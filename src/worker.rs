//! Background worker.
//!
//! Everything expensive (network, disk, crypto, Argon2) happens here, on a
//! dedicated OS thread running a tokio multi-thread runtime. The GTK main
//! thread only exchanges messages over `async-channel`, so the UI can never stall.

use crate::crypto::{self, VaultKeys};
use crate::settings::{BackendKind, ConnectionProfile, Settings};
use crate::storage::{
	nfs::NfsBackend, s3::S3Backend, sftp::SftpBackend, smb::SmbBackend, RawObject, RemoteEntry,
	StorageBackend,
};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub enum Command {
	Connect {
		profile: ConnectionProfile,
		secret_key: String,
		password: Option<String>,
	},
	Disconnect,
	/// `prefix` is the *real* (possibly encrypted) key prefix, "" for root.
	List {
		prefix: String,
	},
	Upload {
		paths: Vec<PathBuf>,
		dest_prefix: String,
	},
	/// Create an empty folder named `name` under the real prefix `prefix`.
	CreateFolder {
		prefix: String,
		name: String,
	},
	Download {
		items: Vec<RemoteEntry>,
		dest: PathBuf,
	},
	Delete {
		items: Vec<RemoteEntry>,
	},
	Move {
		items: Vec<RemoteEntry>,
		dest_prefix: String,
	},
	CancelTransfers,
	SetSettings(Settings),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransferKind {
	Upload,
	Download,
}

/// Live progress of one in-flight file (for the transfer details dialog).
#[derive(Clone, Debug)]
pub struct FileProgress {
	pub name: String,
	pub kind: TransferKind,
	pub done: u64,
	pub total: u64,
	/// Smoothed speed in bytes/second, measured worker-side over >= 1s
	/// windows of the file's own transfer timeline.
	pub speed_bps: f64,
}

#[derive(Debug)]
pub enum Event {
	Connected {
		label: String,
		e2ee: bool,
	},
	ConnectFailed(String),
	Listed {
		prefix: String,
		entries: Vec<RemoteEntry>,
	},
	ListFailed(String),
	TransferStarted {
		total_files: u64,
		total_bytes: u64,
		files: Vec<FileProgress>,
	},
	TransferExtended {
		total_files: u64,
		total_bytes: u64,
		added: Vec<FileProgress>,
	},
	TransferProgress {
		done_files: u64,
		failed_files: u64,
		bytes_done: u64,
		files: Vec<FileProgress>,
		/// Set when this event marks one file as finished: (kind, name, success).
		finished: Option<(TransferKind, String, bool)>,
	},
	TransferFinished {
		uploaded: u64,
		downloaded: u64,
		failed: u64,
		errors: Vec<String>,
	},
	Deleted {
		count: u64,
	},
	Moved {
		count: u64,
	},
	FolderCreated,
	Toast(String),
}

/// Spawn the worker thread. Returns the command sender and event receiver
/// used by the UI.
pub fn spawn() -> (
	async_channel::Sender<Command>,
	async_channel::Receiver<Event>,
) {
	let (cmd_tx, cmd_rx) = async_channel::unbounded::<Command>();
	let (ev_tx, ev_rx) = async_channel::unbounded::<Event>();
	std::thread::Builder::new()
		.name("rse-worker".into())
		.spawn(move || {
			let rt = tokio::runtime::Builder::new_multi_thread()
				.enable_all()
				.build()
				.expect("tokio runtime");
			rt.block_on(dispatch(cmd_rx, ev_tx));
		})
		.expect("spawn worker thread");
	(cmd_tx, ev_rx)
}

/// A live connection. The backend sits behind a lock so it can be swapped
/// out by the reconnect logic while transfers hold clones of the session.
#[derive(Clone)]
struct Session {
	keys: Option<Arc<VaultKeys>>,
	conn: Arc<Conn>,
}

struct Conn {
	profile: ConnectionProfile,
	secret: String,
	backend: tokio::sync::RwLock<Arc<dyn StorageBackend>>,
	/// Serializes reconnect attempts: one task rebuilds, the rest wait.
	reconnect: tokio::sync::Mutex<()>,
	generation: AtomicU64,
	ev: async_channel::Sender<Event>,
}

impl Session {
	async fn backend(&self) -> Arc<dyn StorageBackend> {
		self.conn.backend.read().await.clone()
	}

	/// Called between retries. If the backend is unreachable (e.g. the network
	/// changed), rebuild it from the stored credentials, waiting with backoff
	/// until connectivity returns or the transfer is cancelled.
	async fn wait_until_healthy(&self, cancel: &CancellationToken) {
		let check = |b: Arc<dyn StorageBackend>| async move {
			tokio::time::timeout(Duration::from_secs(10), b.health_check())
				.await
				.map(|r| r.is_ok())
				.unwrap_or(false)
		};
		if check(self.backend().await).await {
			return;
		}

		let generation = self.conn.generation.load(Ordering::Relaxed);
		let _guard = self.conn.reconnect.lock().await;
		if self.conn.generation.load(Ordering::Relaxed) != generation {
			return; // another task already reconnected while we waited
		}
		let _ = self
			.conn
			.ev
			.send(Event::Toast("Connection lost - reconnecting...".into()))
			.await;

		let mut delay = Duration::from_secs(1);
		for _ in 0..8 {
			if cancel.is_cancelled() {
				return;
			}
			match connect_backend(&self.conn.profile, &self.conn.secret).await {
				Ok(backend) => {
					*self.conn.backend.write().await = backend;
					self.conn.generation.fetch_add(1, Ordering::Relaxed);
					let _ = self.conn.ev.send(Event::Toast("Reconnected".into())).await;
					return;
				}
				Err(_) => {
					tokio::select! {
							_ = cancel.cancelled() => return,
							_ = tokio::time::sleep(delay) => {}
					}
					delay = (delay * 2).min(Duration::from_secs(15));
				}
			}
		}
		// Attempts exhausted (~1.5 min): give up for now. The per-file retry
		// loop re-enters here on its next attempt, extending the window.
	}
}

async fn connect_backend(
	profile: &ConnectionProfile,
	secret: &str,
) -> Result<Arc<dyn StorageBackend>> {
	Ok(match profile.kind {
		BackendKind::S3 => Arc::new(
			S3Backend::connect(
				&profile.endpoint,
				&profile.access_key_id,
				secret,
				&profile.bucket,
			)
			.await?,
		),
		BackendKind::Sftp => Arc::new(SftpBackend::connect(profile, secret).await?),
		BackendKind::Nfs => Arc::new(NfsBackend::connect(profile).await?),
		BackendKind::Smb => Arc::new(SmbBackend::connect(profile, secret).await?),
	})
}

async fn dispatch(cmd_rx: async_channel::Receiver<Command>, ev: async_channel::Sender<Event>) {
	let mut session: Option<Session> = None;
	let mut settings = Settings::load();
	let hub = TransferHub::new(ev.clone());

	while let Ok(cmd) = cmd_rx.recv().await {
		match cmd {
			Command::SetSettings(s) => settings = s,

			Command::Disconnect => {
				hub.cancel_all();
				session = None;
			}

			Command::CancelTransfers => hub.cancel_all(),

			Command::Connect {
				profile,
				secret_key,
				password,
			} => match connect(&profile, &secret_key, password.as_deref(), ev.clone()).await {
				Ok(s) => {
					let e2ee = s.keys.is_some();
					session = Some(s);
					let label = match profile.kind {
						BackendKind::S3 => profile.bucket.clone(),
						BackendKind::Sftp => format!("{}@{}", profile.username, profile.host),
						BackendKind::Nfs => format!("{}:{}", profile.host, profile.root_path),
						BackendKind::Smb => format!("{}/{}", profile.host, profile.share),
					};
					let _ = ev.send(Event::Connected { label, e2ee }).await;
				}
				Err(e) => {
					let _ = ev.send(Event::ConnectFailed(format!("{e:#}"))).await;
				}
			},

			Command::List { prefix } => {
				let Some(s) = session.clone() else { continue };
				let ev = ev.clone();
				tokio::spawn(async move {
					let mut result = list(&s, &prefix).await;
					if result.is_err() {
						// The session may have died since the last operation
						// (e.g. server-side timeout): heal it and retry once.
						s.wait_until_healthy(&CancellationToken::new()).await;
						result = list(&s, &prefix).await;
					}
					match result {
						Ok(entries) => {
							let _ = ev.send(Event::Listed { prefix, entries }).await;
						}
						Err(e) => {
							let _ = ev.send(Event::ListFailed(format!("{e:#}"))).await;
						}
					}
				});
			}

			Command::Upload { paths, dest_prefix } => {
				let Some(s) = session.clone() else { continue };
				let (hub, st) = (hub.clone(), settings.clone());
				tokio::spawn(async move { run_upload(hub, s, paths, dest_prefix, st).await });
			}

			Command::Download { items, dest } => {
				let Some(s) = session.clone() else { continue };
				let (hub, st) = (hub.clone(), settings.clone());
				tokio::spawn(async move { run_download(hub, s, items, dest, st).await });
			}

			Command::CreateFolder { prefix, name } => {
				let Some(s) = session.clone() else { continue };
				let ev = ev.clone();
				tokio::spawn(async move {
					let mut result = create_folder(&s, &prefix, &name).await;
					if result.is_err() {
						s.wait_until_healthy(&CancellationToken::new()).await;
						result = create_folder(&s, &prefix, &name).await;
					}
					match result {
						Ok(()) => {
							let _ = ev.send(Event::FolderCreated).await;
						}
						Err(e) => {
							let _ = ev
								.send(Event::Toast(format!("Creating folder failed: {e:#}")))
								.await;
						}
					}
				});
			}
			Command::Delete { items } => {
				let Some(s) = session.clone() else { continue };
				let ev = ev.clone();
				tokio::spawn(async move {
					let mut result = run_delete(&s, items.clone()).await;
					if result.is_err() {
						s.wait_until_healthy(&CancellationToken::new()).await;
						result = run_delete(&s, items).await;
					}
					match result {
						Ok(n) => {
							let _ = ev.send(Event::Deleted { count: n }).await;
						}
						Err(e) => {
							let _ = ev.send(Event::Toast(format!("Delete failed: {e:#}"))).await;
						}
					}
				});
			}

			Command::Move { items, dest_prefix } => {
				let Some(s) = session.clone() else { continue };
				let ev = ev.clone();
				tokio::spawn(async move {
					let mut result = run_move(&s, items.clone(), &dest_prefix).await;
					if result.is_err() {
						s.wait_until_healthy(&CancellationToken::new()).await;
						result = run_move(&s, items, &dest_prefix).await;
					}
					match result {
						Ok(n) => {
							let _ = ev.send(Event::Moved { count: n }).await;
						}
						Err(e) => {
							let _ = ev.send(Event::Toast(format!("Move failed: {e:#}"))).await;
						}
					}
				});
			}
		}
	}
}

async fn connect(
	profile: &ConnectionProfile,
	secret: &str,
	password: Option<&str>,
	ev: async_channel::Sender<Event>,
) -> Result<Session> {
	let backend = connect_backend(profile, secret).await?;

	let keys = if profile.e2ee {
		let password = password
			.filter(|p| !p.is_empty())
			.ok_or_else(|| anyhow!("an encryption password is required when E2EE is enabled"))?
			.to_string();

		match backend.get_vault().await? {
			Some(blob) => {
				let vault: crypto::VaultFile =
					serde_json::from_slice(&blob).context("the vault metadata is corrupted")?;
				let keys = tokio::task::spawn_blocking(move || crypto::open_vault(&vault, &password))
					.await
					.map_err(|e| anyhow!("{e}"))??;
				Some(Arc::new(keys))
			}
			None => {
				// First connection with E2EE: initialise the vault.
				let (vault, keys) = tokio::task::spawn_blocking(move || crypto::create_vault(&password))
					.await
					.map_err(|e| anyhow!("{e}"))??;
				backend
					.put_vault(serde_json::to_vec(&vault)?)
					.await
					.context("storing vault metadata")?;
				Some(Arc::new(keys))
			}
		}
	} else {
		None
	};

	Ok(Session {
		keys,
		conn: Arc::new(Conn {
			profile: profile.clone(),
			secret: secret.to_string(),
			backend: tokio::sync::RwLock::new(backend),
			reconnect: tokio::sync::Mutex::new(()),
			generation: AtomicU64::new(0),
			ev,
		}),
	})
}

async fn list(s: &Session, prefix: &str) -> Result<Vec<RemoteEntry>> {
	let raw = s.backend().await.list(prefix).await?;
	let mut entries: Vec<RemoteEntry> = raw
		.into_iter()
		.filter(|o| o.key.trim_end_matches('/').rsplit('/').next() != Some(crypto::VAULT_KEY))
		.map(|o| raw_to_entry(o, s.keys.as_deref()))
		.collect();
	entries.sort_by(|a, b| {
		b.is_dir
			.cmp(&a.is_dir)
			.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
	});
	Ok(entries)
}

fn raw_to_entry(o: RawObject, keys: Option<&VaultKeys>) -> RemoteEntry {
	let trimmed = o.key.trim_end_matches('/');
	let raw_name = trimmed.rsplit('/').next().unwrap_or(trimmed).to_string();
	let (name, encrypted) = match keys {
		Some(k) => match crypto::decrypt_name(k, &raw_name) {
			Ok(n) => (n, Some(true)),
			Err(_) => (raw_name, Some(false)), // foreign / unencrypted item
		},
		None => (raw_name, None),
	};
	RemoteEntry {
		key: o.key,
		name,
		is_dir: o.is_prefix,
		size: o.size,
		modified: o.modified,
		encrypted,
	}
}

struct Progress {
	ev: async_channel::Sender<Event>,
	uploaded: AtomicU64,
	downloaded: AtomicU64,
	failed: AtomicU64,
	bytes: AtomicU64,
	start: Instant,
	/// Milliseconds (since `start`) of the last emitted byte-progress event.
	last_emit: AtomicU64,
	active: StdMutex<HashMap<(TransferKind, String), FileTrack>>,
}

struct FileTrack {
	done: u64,
	total: u64,
	speed_bps: f64,
	window_start: Instant,
	window_bytes: u64,
}

impl Progress {
	fn new(ev: async_channel::Sender<Event>) -> Arc<Self> {
		Arc::new(Self {
			ev,
			uploaded: AtomicU64::new(0),
			downloaded: AtomicU64::new(0),
			failed: AtomicU64::new(0),
			bytes: AtomicU64::new(0),
			start: Instant::now(),
			last_emit: AtomicU64::new(0),
			active: StdMutex::new(HashMap::new()),
		})
	}

	fn done_files(&self) -> u64 {
		self.uploaded.load(Ordering::Relaxed) + self.downloaded.load(Ordering::Relaxed)
	}

	fn file_start(&self, kind: TransferKind, name: &str, total: u64) {
		self.active.lock().unwrap().insert(
			(kind, name.to_string()),
			FileTrack {
				done: 0,
				total,
				speed_bps: 0.0,
				window_start: Instant::now(),
				window_bytes: 0,
			},
		);
	}

	fn snapshot(&self) -> Vec<FileProgress> {
		let map = self.active.lock().unwrap();
		let mut v: Vec<FileProgress> = map
			.iter()
			.map(|((kind, name), t)| FileProgress {
				name: name.clone(),
				kind: *kind,
				done: t.done,
				total: t.total,
				speed_bps: t.speed_bps,
			})
			.collect();
		// Stable row order: group by kind, then name.
		v.sort_by(|a, b| (a.kind as u8, a.name.as_str()).cmp(&(b.kind as u8, b.name.as_str())));
		v
	}

	async fn file_done(&self, kind: TransferKind, name: &str, ok: bool) {
		self
			.active
			.lock()
			.unwrap()
			.remove(&(kind, name.to_string()));
		if ok {
			match kind {
				TransferKind::Upload => self.uploaded.fetch_add(1, Ordering::Relaxed),
				TransferKind::Download => self.downloaded.fetch_add(1, Ordering::Relaxed),
			};
		} else {
			self.failed.fetch_add(1, Ordering::Relaxed);
		}
		let _ = self
			.ev
			.send(Event::TransferProgress {
				done_files: self.done_files(),
				failed_files: self.failed.load(Ordering::Relaxed),
				bytes_done: self.bytes.load(Ordering::Relaxed),
				files: self.snapshot(),
				finished: Some((kind, name.to_string(), ok)),
			})
			.await;
	}

	/// Record transferred bytes and emit a progress event, throttled to at
	/// most ~10 events/second.
	fn tick(&self, kind: TransferKind, current: &str, n: u64) {
		self.bytes.fetch_add(n, Ordering::Relaxed);
		if let Some(entry) = self
			.active
			.lock()
			.unwrap()
			.get_mut(&(kind, current.to_string()))
		{
			entry.done += n;
			entry.window_bytes += n;
			let elapsed = entry.window_start.elapsed().as_secs_f64();
			if elapsed >= 1.0 {
				let instant_bps = entry.window_bytes as f64 / elapsed;
				entry.speed_bps = if entry.speed_bps == 0.0 {
					instant_bps
				} else {
					entry.speed_bps * 0.5 + instant_bps * 0.5
				};
				entry.window_start = Instant::now();
				entry.window_bytes = 0;
			}
		}
		let now = self.start.elapsed().as_millis() as u64;
		let last = self.last_emit.load(Ordering::Relaxed);
		if now.saturating_sub(last) >= 100
			&& self
				.last_emit
				.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
				.is_ok()
		{
			let _ = self.ev.send_blocking(Event::TransferProgress {
				done_files: self.done_files(),
				failed_files: self.failed.load(Ordering::Relaxed),
				bytes_done: self.bytes.load(Ordering::Relaxed),
				files: self.snapshot(),
				finished: None,
			});
		}
	}

	fn file_resume(&self, kind: TransferKind, name: &str, total: u64, already_done: u64) {
		self.active.lock().unwrap().insert(
			(kind, name.to_string()),
			FileTrack {
				done: already_done,
				total,
				speed_bps: 0.0,
				window_start: Instant::now(),
				window_bytes: 0,
			},
		);
	}
}

struct BatchState {
	open: bool,
	outstanding: u64,
	total_files: u64,
	total_bytes: u64,
	progress: Arc<Progress>,
	errors: Arc<tokio::sync::Mutex<Vec<String>>>,
	upload_sem: Arc<Semaphore>,
	download_sem: Arc<Semaphore>,
	cancel: CancellationToken,
}

/// Handles handed to a file task when its files are admitted to the batch.
struct Admission {
	progress: Arc<Progress>,
	errors: Arc<tokio::sync::Mutex<Vec<String>>>,
	upload_sem: Arc<Semaphore>,
	download_sem: Arc<Semaphore>,
	cancel: CancellationToken,
	fresh: bool,
	total_files: u64,
	total_bytes: u64,
}

/// Owns the single live transfer batch. Uploads and downloads share it, so
/// dropping more files while a transfer runs extends the same batch (and the
/// same progress bar) instead of starting a competing one.
struct TransferHub {
	ev: async_channel::Sender<Event>,
	state: StdMutex<BatchState>,
}

impl TransferHub {
	fn new(ev: async_channel::Sender<Event>) -> Arc<Self> {
		let state = BatchState {
			open: false,
			outstanding: 0,
			total_files: 0,
			total_bytes: 0,
			progress: Progress::new(ev.clone()),
			errors: Arc::new(tokio::sync::Mutex::new(Vec::new())),
			upload_sem: Arc::new(Semaphore::new(1)),
			download_sem: Arc::new(Semaphore::new(1)),
			cancel: CancellationToken::new(),
		};
		Arc::new(Self {
			ev,
			state: StdMutex::new(state),
		})
	}

	fn cancel_all(&self) {
		self.state.lock().unwrap().cancel.cancel();
	}

	/// Register `count` files (`bytes` total) into the running batch, opening a
	/// fresh one if none is live. The fresh/extend decision and the outstanding
	/// bump happen under one lock, so a late merge can never race the drain.
	fn admit(&self, settings: &Settings, count: u64, bytes: u64) -> Admission {
		let mut st = self.state.lock().unwrap();
		let fresh = !st.open;
		if fresh {
			st.open = true;
			st.outstanding = 0;
			st.total_files = 0;
			st.total_bytes = 0;
			st.progress = Progress::new(self.ev.clone());
			st.errors = Arc::new(tokio::sync::Mutex::new(Vec::new()));
			st.upload_sem = Arc::new(Semaphore::new(settings.upload_parallelism.max(1)));
			st.download_sem = Arc::new(Semaphore::new(settings.download_parallelism.max(1)));
			st.cancel = CancellationToken::new();
		}
		st.outstanding += count;
		st.total_files += count;
		st.total_bytes += bytes;
		Admission {
			progress: st.progress.clone(),
			errors: st.errors.clone(),
			upload_sem: st.upload_sem.clone(),
			download_sem: st.download_sem.clone(),
			cancel: st.cancel.clone(),
			fresh,
			total_files: st.total_files,
			total_bytes: st.total_bytes,
		}
	}

	/// One file task finished. Emits `TransferFinished` when the batch drains.
	async fn task_done(&self) {
		let finished = {
			let mut st = self.state.lock().unwrap();
			st.outstanding = st.outstanding.saturating_sub(1);
			if st.open && st.outstanding == 0 {
				st.open = false;
				Some((st.progress.clone(), st.errors.clone()))
			} else {
				None
			}
		};
		if let Some((progress, errors)) = finished {
			let mut errs = errors.lock().await.clone();
			errs.truncate(20);
			let _ = self
				.ev
				.send(Event::TransferFinished {
					uploaded: progress.uploaded.load(Ordering::Relaxed),
					downloaded: progress.downloaded.load(Ordering::Relaxed),
					failed: progress.failed.load(Ordering::Relaxed),
					errors: errs,
				})
				.await;
		}
	}
}

/// Expand dropped paths into (local file, remote-relative display path, size).
fn expand_paths(paths: &[PathBuf]) -> Vec<(PathBuf, String, u64)> {
	let mut out = Vec::new();
	for path in paths {
		if path.is_dir() {
			let base = path.parent().unwrap_or(path);
			for entry in walkdir::WalkDir::new(path).into_iter().flatten() {
				if entry.file_type().is_file() {
					if let Ok(rel) = entry.path().strip_prefix(base) {
						let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
						out.push((entry.path().to_path_buf(), path_to_key(rel), size));
					}
				}
			}
		} else if path.is_file() {
			let name = path
				.file_name()
				.map(|n| n.to_string_lossy().into_owned())
				.unwrap_or_default();
			let size = path.metadata().map(|m| m.len()).unwrap_or(0);
			out.push((path.clone(), name, size));
		}
	}
	out
}

fn path_to_key(rel: &std::path::Path) -> String {
	rel
		.components()
		.map(|c| c.as_os_str().to_string_lossy().into_owned())
		.collect::<Vec<_>>()
		.join("/")
}

async fn run_upload(
	hub: Arc<TransferHub>,
	s: Session,
	paths: Vec<PathBuf>,
	dest_prefix: String,
	st: Settings,
) {
	let ev = hub.ev.clone();
	let files = tokio::task::spawn_blocking(move || expand_paths(&paths))
		.await
		.unwrap_or_default();
	if files.is_empty() {
		let _ = ev.send(Event::Toast("Nothing to upload".into())).await;
		return;
	}
	let total_bytes: u64 = files.iter().map(|(_, _, size)| *size).sum();
	let roster: Vec<FileProgress> = files
		.iter()
		.map(|(_, rel, size)| FileProgress {
			name: rel.clone(),
			kind: TransferKind::Upload,
			done: 0,
			total: *size,
			speed_bps: 0.0,
		})
		.collect();

	let a = hub.admit(&st, files.len() as u64, total_bytes);
	let _ = ev
		.send(if a.fresh {
			Event::TransferStarted {
				total_files: a.total_files,
				total_bytes: a.total_bytes,
				files: roster,
			}
		} else {
			Event::TransferExtended {
				total_files: a.total_files,
				total_bytes: a.total_bytes,
				added: roster,
			}
		})
		.await;

	for (path, rel, _size) in files {
		let (s, st, sem, progress, errors, cancel, hub) = (
			s.clone(),
			st.clone(),
			a.upload_sem.clone(),
			a.progress.clone(),
			a.errors.clone(),
			a.cancel.clone(),
			hub.clone(),
		);
		let dest_prefix = dest_prefix.clone();
		tokio::spawn(async move {
			let _permit = sem.acquire_owned().await.ok();
			if !cancel.is_cancelled() {
				match upload_one(&s, &st, &path, &dest_prefix, &rel, &progress, &cancel).await {
					Ok(()) => progress.file_done(TransferKind::Upload, &rel, true).await,
					Err(e) => {
						if !cancel.is_cancelled() {
							errors.lock().await.push(format!("{rel}: {e:#}"));
						}
						progress.file_done(TransferKind::Upload, &rel, false).await;
					}
				}
			}
			hub.task_done().await;
		});
	}
}

async fn upload_one(
	s: &Session,
	st: &Settings,
	path: &PathBuf,
	dest_prefix: &str,
	rel: &str,
	progress: &Progress,
	cancel: &CancellationToken,
) -> Result<()> {
	let key = match s.keys.as_deref() {
		Some(k) => format!("{dest_prefix}{}", crypto::encrypt_path(k, rel)?),
		None => format!("{dest_prefix}{rel}"),
	};

	let plain_len = tokio::fs::metadata(path).await?.len();
	let threshold = st.multipart_threshold_mib * 1024 * 1024;

	let mut attempt = 0u32;
	loop {
		if cancel.is_cancelled() {
			return Err(anyhow!("cancelled"));
		}
		progress.file_start(TransferKind::Upload, rel, plain_len);
		let result = async {
			let backend = s.backend().await;
			backend.prepare_parents(&key).await?;
			if plain_len <= threshold {
				upload_small(s, &backend, path, &key, rel, plain_len, progress).await
			} else {
				upload_multipart(s, &backend, st, path, &key, rel, progress, cancel).await
			}
		}
		.await;
		match result {
			Ok(()) => return Ok(()),
			Err(_) if attempt < st.retries && !cancel.is_cancelled() => {
				attempt += 1;
				s.wait_until_healthy(cancel).await;
				tokio::time::sleep(Duration::from_millis(400 * (1 << attempt.min(4)))).await;
			}
			Err(e) => return Err(e),
		}
	}
}

async fn upload_small(
	s: &Session,
	backend: &Arc<dyn StorageBackend>,
	path: &PathBuf,
	key: &str,
	name: &str,
	plain_len: u64,
	progress: &Progress,
) -> Result<()> {
	let data = tokio::fs::read(path).await.context("reading local file")?;
	let body = match s.keys.as_deref() {
		Some(k) => crypto::encrypt_bytes(k, &data)?,
		None => data,
	};
	backend.put(key, body).await?;
	progress.tick(TransferKind::Upload, name, plain_len);
	Ok(())
}

async fn upload_multipart(
	s: &Session,
	backend: &Arc<dyn StorageBackend>,
	st: &Settings,
	path: &PathBuf,
	key: &str,
	name: &str,
	progress: &Progress,
	cancel: &CancellationToken,
) -> Result<()> {
	let part_size = (st.part_size_mib.max(5) * 1024 * 1024) as usize;
	let mp = backend.create_multipart(key).await?;

	let result: Result<()> = async {
		let mut file = tokio::fs::File::open(path)
			.await
			.context("opening local file")?;
		let file_len = file.metadata().await?.len();
		let mut encryptor = s.keys.as_deref().map(crypto::Encryptor::new);

		let mut part_buf: Vec<u8> = Vec::with_capacity(part_size + crypto::CIPHER_CHUNK);
		if let Some(enc) = &encryptor {
			part_buf.extend_from_slice(&enc.header());
		}

		let mut etags = Vec::new();
		let mut part_number = 1i32;
		let mut read_total: u64 = 0;
		let mut chunk = vec![0u8; crypto::CHUNK];

		loop {
			if cancel.is_cancelled() {
				return Err(anyhow!("cancelled"));
			}
			// Fill one plaintext chunk (read_exact semantics, tolerant of EOF).
			let mut filled = 0usize;
			while filled < chunk.len() {
				let n = file.read(&mut chunk[filled..]).await?;
				if n == 0 {
					break;
				}
				filled += n;
			}
			read_total += filled as u64;
			let last = read_total >= file_len || filled < chunk.len();

			match &mut encryptor {
				Some(enc) => part_buf.extend(enc.seal_chunk(&chunk[..filled], last)?),
				None => part_buf.extend_from_slice(&chunk[..filled]),
			}
			progress.tick(TransferKind::Upload, name, filled as u64);

			if part_buf.len() >= part_size || last {
				let data = std::mem::take(&mut part_buf);
				let etag = backend.upload_part(&mp, part_number, data).await?;
				etags.push((part_number, etag));
				part_number += 1;
			}
			if last {
				break;
			}
		}
		backend.complete_multipart(&mp, etags).await
	}
	.await;

	if result.is_err() {
		let _ = backend.abort_multipart(&mp).await;
	}
	result
}

async fn run_download(
	hub: Arc<TransferHub>,
	s: Session,
	items: Vec<RemoteEntry>,
	dest: PathBuf,
	st: Settings,
) {
	let ev = hub.ev.clone();
	// Short-lived token just for the recursive-listing heal path below; the
	// real per-file cancel comes from admit().
	let precancel = CancellationToken::new();

	let mut targets: Vec<(String, String, u64)> = Vec::new();
	for item in &items {
		if item.is_dir {
			let mut listing = s.backend().await.list_recursive(&item.key).await;
			if listing.is_err() {
				s.wait_until_healthy(&precancel).await;
				listing = s.backend().await.list_recursive(&item.key).await;
			}
			match listing {
				Ok(objs) => {
					let parent = parent_prefix(&item.key);
					for o in objs {
						let rel_raw = o.key.strip_prefix(&parent).unwrap_or(&o.key).to_string();
						let rel = display_rel(&s, &rel_raw);
						targets.push((o.key, rel, o.size));
					}
				}
				Err(e) => {
					let _ = ev
						.send(Event::Toast(format!("Listing {} failed: {e:#}", item.name)))
						.await;
				}
			}
		} else {
			targets.push((item.key.clone(), item.name.clone(), item.size));
		}
	}
	if targets.is_empty() {
		let _ = ev.send(Event::Toast("Nothing to download".into())).await;
		return;
	}

	let total_bytes: u64 = targets.iter().map(|(_, _, s)| *s).sum();
	let roster: Vec<FileProgress> = targets
		.iter()
		.map(|(_, rel, size)| FileProgress {
			name: rel.clone(),
			kind: TransferKind::Download,
			done: 0,
			total: *size,
			speed_bps: 0.0,
		})
		.collect();

	let a = hub.admit(&st, targets.len() as u64, total_bytes);
	let _ = ev
		.send(if a.fresh {
			Event::TransferStarted {
				total_files: a.total_files,
				total_bytes: a.total_bytes,
				files: roster,
			}
		} else {
			Event::TransferExtended {
				total_files: a.total_files,
				total_bytes: a.total_bytes,
				added: roster,
			}
		})
		.await;

	for (key, rel, size) in targets {
		let (s, st, sem, progress, errors, cancel, dest, hub) = (
			s.clone(),
			st.clone(),
			a.download_sem.clone(),
			a.progress.clone(),
			a.errors.clone(),
			a.cancel.clone(),
			dest.clone(),
			hub.clone(),
		);
		tokio::spawn(async move {
			let _permit = sem.acquire_owned().await.ok();
			if !cancel.is_cancelled() {
				let out_path = dest.join(sanitize_rel(&rel));
				let mut attempt = 0u32;
				let result = loop {
					match download_one(&s, &key, &rel, size, &out_path, &progress, &cancel).await {
						Ok(()) => break Ok(()),
						Err(_) if attempt < st.retries && !cancel.is_cancelled() => {
							attempt += 1;
							s.wait_until_healthy(&cancel).await;
							tokio::time::sleep(Duration::from_millis(400 * (1 << attempt.min(4)))).await;
						}
						Err(e) => break Err(e),
					}
				};
				match result {
					Ok(()) => progress.file_done(TransferKind::Download, &rel, true).await,
					Err(e) => {
						// Gave up (or cancelled): don't leave a stray .rse-part.
						let _ = tokio::fs::remove_file(part_path(&out_path)).await;
						if !cancel.is_cancelled() {
							errors.lock().await.push(format!("{rel}: {e:#}"));
						}
						progress
							.file_done(TransferKind::Download, &rel, false)
							.await;
					}
				}
			}
			hub.task_done().await;
		});
	}
}

/// A read that makes no progress for two minutes means the connection is
/// silently dead; turn it into an error so the retry/reconnect path runs.
async fn read_or_stall<T>(fut: impl std::future::Future<Output = std::io::Result<T>>) -> Result<T> {
	tokio::time::timeout(Duration::from_secs(120), fut)
		.await
		.map_err(|_| anyhow!("download stalled - connection appears dead"))?
		.map_err(Into::into)
}

fn part_path(out_path: &std::path::Path) -> PathBuf {
	let tmp_name = format!(
		"{}.rse-part",
		out_path
			.file_name()
			.and_then(|n| n.to_str())
			.unwrap_or("download")
	);
	out_path.with_file_name(tmp_name)
}

async fn download_one(
	s: &Session,
	key: &str,
	name: &str,
	expected_len: u64,
	out_path: &PathBuf,
	progress: &Progress,
	cancel: &CancellationToken,
) -> Result<()> {
	if cancel.is_cancelled() {
		return Err(anyhow!("cancelled"));
	}
	if let Some(parent) = out_path.parent() {
		tokio::fs::create_dir_all(parent).await?;
	}
	let tmp = part_path(out_path);
	let encrypted = s.keys.is_some();

	// How much is already on disk (plaintext bytes)?
	let mut done_plain: u64 = tokio::fs::metadata(&tmp)
		.await
		.map(|m| m.len())
		.unwrap_or(0);

	// Encrypted resume only lands on a whole-chunk boundary; drop any
	// half-written trailing chunk so we never resume mid-frame.
	if encrypted && done_plain > 0 {
		let whole = done_plain - (done_plain % crypto::CHUNK as u64);
		if whole != done_plain {
			let f = tokio::fs::OpenOptions::new().write(true).open(&tmp).await?;
			f.set_len(whole).await?;
			done_plain = whole;
		}
	}

	// Plaintext size, for the completion check and the progress row total.
	let plaintext_total = if encrypted {
		let (n_chunks, _last) = crypto::chunk_layout(expected_len)?;
		expected_len
			.saturating_sub(crypto::HEADER_LEN as u64)
			.saturating_sub(n_chunks * crypto::TAG as u64)
	} else {
		expected_len
	};

	// Already complete (e.g. crashed between flush and rename): just finalize.
	if done_plain > 0 && done_plain >= plaintext_total {
		if let Ok(m) = tokio::fs::metadata(&tmp).await {
			if m.len() > plaintext_total {
				let f = tokio::fs::OpenOptions::new().write(true).open(&tmp).await?;
				f.set_len(plaintext_total).await?;
			}
		}
		tokio::fs::rename(&tmp, out_path).await?;
		return Ok(());
	}

	// Ciphertext offset to resume the network read from.
	let cipher_off = if encrypted {
		let completed = done_plain / crypto::CHUNK as u64;
		crypto::HEADER_LEN as u64 + completed * crypto::CIPHER_CHUNK as u64
	} else {
		done_plain
	};

	let (_len, mut reader) = if done_plain > 0 {
		s.backend().await.get_range(key, cipher_off).await?
	} else {
		s.backend().await.get_stream(key).await?
	};

	let mut file = tokio::fs::OpenOptions::new()
		.create(true)
		.write(true)
		.append(true)
		.open(&tmp)
		.await?;

	if done_plain > 0 {
		progress.file_resume(TransferKind::Download, name, plaintext_total, done_plain);
	} else {
		progress.file_start(TransferKind::Download, name, plaintext_total);
	}

	let result: Result<()> = async {
		match s.keys.as_deref() {
			None => {
				let mut buf = vec![0u8; 256 * 1024];
				loop {
					let n = tokio::select! {
						biased;
						_ = cancel.cancelled() => return Err(anyhow!("cancelled")),
						r = read_or_stall(reader.read(&mut buf)) => r?,
					};
					if n == 0 {
						break;
					}
					file.write_all(&buf[..n]).await?;
					progress.tick(TransferKind::Download, name, n as u64);
				}
				file.flush().await?;
			}
			Some(keys) => {
				let (n_chunks, last_len) = crypto::chunk_layout(expected_len)?;
				let completed = done_plain / crypto::CHUNK as u64;

				// The file nonce lives in the 12-byte header. When resuming we
				// skipped it, so fetch just those bytes to rebuild the decryptor.
				let mut header = [0u8; crypto::HEADER_LEN];
				if completed == 0 {
					read_or_stall(reader.read_exact(&mut header))
						.await
						.context("reading header")?;
				} else {
					let (_h, mut h_reader) = s.backend().await.get_range(key, 0).await?;
					read_or_stall(h_reader.read_exact(&mut header))
						.await
						.context("reading header")?;
				}
				let mut dec = crypto::Decryptor::new(keys, &header)?;
				dec.seek_to(completed as u32);

				let mut buf = vec![0u8; crypto::CIPHER_CHUNK];
				for i in completed..n_chunks {
					let last = i == n_chunks - 1;
					let clen = if last { last_len } else { crypto::CIPHER_CHUNK };
					tokio::select! {
						biased;
						_ = cancel.cancelled() => return Err(anyhow!("cancelled")),
						r = read_or_stall(reader.read_exact(&mut buf[..clen])) => {
							r.context("reading chunk")?;
						}
					}
					let plain = dec.open_chunk(&buf[..clen], last)?;
					file.write_all(&plain).await?;
					progress.tick(TransferKind::Download, name, plain.len() as u64);
				}
				file.flush().await?;
			}
		}
		Ok(())
	}
	.await;

	drop(file);
	if result.is_ok() {
		tokio::fs::rename(&tmp, out_path).await?;
	}
	// On failure the .rse-part is deliberately left in place so the next
	// attempt resumes from it. The caller removes it only when it gives up.
	result
}

/// "a/b/c/" -> "a/b/"; "x/" -> ""
fn parent_prefix(prefix: &str) -> String {
	let trimmed = prefix.trim_end_matches('/');
	match trimmed.rfind('/') {
		Some(i) => trimmed[..=i].to_string(),
		None => String::new(),
	}
}

fn display_rel(s: &Session, raw_rel: &str) -> String {
	match s.keys.as_deref() {
		Some(k) => crypto::decrypt_path(k, raw_rel).unwrap_or_else(|_| raw_rel.to_string()),
		None => raw_rel.to_string(),
	}
}

/// Prevent path traversal from hostile object keys ("../../etc/passwd").
fn sanitize_rel(rel: &str) -> PathBuf {
	rel
		.split('/')
		.filter(|s| !s.is_empty() && *s != "." && *s != "..")
		.collect()
}

/// Create an empty directory. Object stores have no directories, so a
/// zero-byte marker object with a trailing-slash key stands in - it groups
/// into a common prefix in listings. Filesystem-like backends get a real
/// directory via `prepare_parents`.
async fn create_folder(s: &Session, prefix: &str, name: &str) -> Result<()> {
	let segment = match &s.keys {
		Some(k) => crypto::encrypt_name(k, name)?,
		None => name.to_string(),
	};
	let key = format!("{prefix}{segment}/");
	let backend = s.backend().await;
	if s.conn.profile.kind == BackendKind::S3 {
		backend.put(&key, Vec::new()).await
	} else {
		// Creating the parents of "<key>x" creates <key> itself.
		backend.prepare_parents(&format!("{key}x")).await
	}
}

async fn run_delete(s: &Session, items: Vec<RemoteEntry>) -> Result<u64> {
	let mut keys = Vec::new();
	for item in items {
		if item.is_dir {
			for o in s.backend().await.list_recursive(&item.key).await? {
				keys.push(o.key);
			}
			keys.push(item.key); // folder marker object, if one exists
		} else {
			keys.push(item.key);
		}
	}
	let n = keys.len() as u64;
	s.backend().await.delete(keys).await?;
	Ok(n)
}

async fn run_move(s: &Session, items: Vec<RemoteEntry>, dest_prefix: &str) -> Result<u64> {
	let backend = s.backend().await;
	let mut moved = 0u64;
	for item in items {
		// The item keeps its own (encrypted) leaf segment; only the parent
		// prefix changes, so we never touch names or file contents.
		let trimmed = item.key.trim_end_matches('/');
		let leaf = trimmed.rsplit('/').next().unwrap_or(trimmed);
		if item.is_dir {
			let from = if item.key.ends_with('/') {
				item.key.clone()
			} else {
				format!("{}/", item.key)
			};
			let to = format!("{dest_prefix}{leaf}/");
			// Same place, or moving a folder into itself/a descendant: skip.
			if to == from || dest_prefix.starts_with(&from) {
				continue;
			}
			backend.rename(&from, &to).await?;
		} else {
			let to = format!("{dest_prefix}{leaf}");
			if to == item.key {
				continue;
			}
			backend.rename(&item.key, &to).await?;
		}
		moved += 1;
	}
	Ok(moved)
}
