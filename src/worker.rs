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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferKind {
	Upload,
	Download,
}

/// Live progress of one in-flight file (for the transfer details dialog).
#[derive(Clone, Debug)]
pub struct FileProgress {
	pub name: String,
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
	/// `files` is the full batch roster (also the still-queued ones), in
	/// processing order, with `done = 0`.
	TransferStarted {
		kind: TransferKind,
		total_files: u64,
		total_bytes: u64,
		files: Vec<FileProgress>,
	},
	TransferProgress {
		done_files: u64,
		failed_files: u64,
		bytes_done: u64,
		files: Vec<FileProgress>,
		/// Set when this event marks one file as finished: (name, success).
		finished: Option<(String, bool)>,
	},
	TransferFinished {
		kind: TransferKind,
		done: u64,
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
	let mut cancel = CancellationToken::new();

	while let Ok(cmd) = cmd_rx.recv().await {
		match cmd {
			Command::SetSettings(s) => settings = s,

			Command::Disconnect => {
				cancel.cancel();
				session = None;
			}

			Command::CancelTransfers => cancel.cancel(),

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
				cancel = CancellationToken::new();
				let (ev, st, tok) = (ev.clone(), settings.clone(), cancel.clone());
				tokio::spawn(async move { run_upload(s, paths, dest_prefix, st, ev, tok).await });
			}

			Command::Download { items, dest } => {
				let Some(s) = session.clone() else { continue };
				cancel = CancellationToken::new();
				let (ev, st, tok) = (ev.clone(), settings.clone(), cancel.clone());
				tokio::spawn(async move { run_download(s, items, dest, st, ev, tok).await });
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
	done: AtomicU64,
	failed: AtomicU64,
	bytes: AtomicU64,
	start: Instant,
	/// Milliseconds (since `start`) of the last emitted byte-progress event.
	last_emit: AtomicU64,
	/// Currently in-flight files.
	active: StdMutex<HashMap<String, FileTrack>>,
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
			done: AtomicU64::new(0),
			failed: AtomicU64::new(0),
			bytes: AtomicU64::new(0),
			start: Instant::now(),
			last_emit: AtomicU64::new(0),
			active: StdMutex::new(HashMap::new()),
		})
	}

	fn file_start(&self, name: &str, total: u64) {
		self.active.lock().unwrap().insert(
			name.to_string(),
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
			.map(|(name, t)| FileProgress {
				name: name.clone(),
				done: t.done,
				total: t.total,
				speed_bps: t.speed_bps,
			})
			.collect();
		v.sort_by(|a, b| a.name.cmp(&b.name)); // stable row order in the UI
		v
	}
	async fn file_done(&self, name: &str, ok: bool) {
		self.active.lock().unwrap().remove(name);
		if ok {
			self.done.fetch_add(1, Ordering::Relaxed);
		} else {
			self.failed.fetch_add(1, Ordering::Relaxed);
		}
		let _ = self
			.ev
			.send(Event::TransferProgress {
				done_files: self.done.load(Ordering::Relaxed),
				failed_files: self.failed.load(Ordering::Relaxed),
				bytes_done: self.bytes.load(Ordering::Relaxed),
				files: self.snapshot(),
				finished: Some((name.to_string(), ok)),
			})
			.await;
	}
	/// Record transferred bytes and emit a progress event, throttled to at
	/// most ~10 events/second so large files show a live progress bar without
	/// flooding the UI channel.
	fn tick(&self, current: &str, n: u64) {
		self.bytes.fetch_add(n, Ordering::Relaxed);
		if let Some(entry) = self.active.lock().unwrap().get_mut(current) {
			entry.done += n;
			entry.window_bytes += n;
			// Chunk arrivals are bursty; averaging over at least a second
			// gives a rate that sums correctly across parallel files.
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
			// Unbounded channel: send_blocking never actually blocks.
			let _ = self.ev.send_blocking(Event::TransferProgress {
				done_files: self.done.load(Ordering::Relaxed),
				failed_files: self.failed.load(Ordering::Relaxed),
				bytes_done: self.bytes.load(Ordering::Relaxed),
				files: self.snapshot(),
				finished: None,
			});
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
	s: Session,
	paths: Vec<PathBuf>,
	dest_prefix: String,
	st: Settings,
	ev: async_channel::Sender<Event>,
	cancel: CancellationToken,
) {
	// Directory walking and metadata scans are blocking I/O - keep them off
	// the async workers.
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
			done: 0,
			total: *size,
			speed_bps: 0.0,
		})
		.collect();
	let _ = ev
		.send(Event::TransferStarted {
			kind: TransferKind::Upload,
			total_files: files.len() as u64,
			total_bytes,
			files: roster,
		})
		.await;

	let progress = Progress::new(ev.clone());
	let sem = Arc::new(Semaphore::new(st.upload_parallelism.max(1)));
	let errors = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
	let mut handles = Vec::with_capacity(files.len());

	for (path, rel, _size) in files {
		let (s, st, sem, progress, errors, cancel) = (
			s.clone(),
			st.clone(),
			sem.clone(),
			progress.clone(),
			errors.clone(),
			cancel.clone(),
		);
		let dest_prefix = dest_prefix.clone();
		handles.push(tokio::spawn(async move {
			let _permit = sem.acquire_owned().await.ok();
			if cancel.is_cancelled() {
				return;
			}
			let result = upload_one(&s, &st, &path, &dest_prefix, &rel, &progress, &cancel).await;
			match result {
				Ok(()) => progress.file_done(&rel, true).await,
				Err(e) => {
					if !cancel.is_cancelled() {
						errors.lock().await.push(format!("{rel}: {e:#}"));
					}
					progress.file_done(&rel, false).await;
				}
			}
		}));
	}
	for h in handles {
		let _ = h.await;
	}

	let mut errs = errors.lock().await.clone();
	errs.truncate(20); // don't flood the UI with 5000 identical errors
	let _ = ev
		.send(Event::TransferFinished {
			kind: TransferKind::Upload,
			done: progress.done.load(Ordering::Relaxed),
			failed: progress.failed.load(Ordering::Relaxed),
			errors: errs,
		})
		.await;
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
		progress.file_start(rel, plain_len); // (re)sets the per-file tracker on retries
																			 // Snapshot the backend for the whole attempt: an SFTP multipart write
																			 // must stay on the instance that holds its file handle, even if a
																			 // reconnect swaps the session backend mid-transfer.
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
	progress.tick(name, plain_len);
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
			progress.tick(name, filled as u64);

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
	s: Session,
	items: Vec<RemoteEntry>,
	dest: PathBuf,
	st: Settings,
	ev: async_channel::Sender<Event>,
	cancel: CancellationToken,
) {
	// Resolve folders into concrete (key, relative display path) targets.
	let mut targets: Vec<(String, String, u64)> = Vec::new(); // (key, rel display path, cipher size)
	for item in &items {
		if item.is_dir {
			let mut listing = s.backend().await.list_recursive(&item.key).await;
			if listing.is_err() {
				s.wait_until_healthy(&cancel).await;
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
			done: 0,
			total: *size,
			speed_bps: 0.0,
		})
		.collect();
	let _ = ev
		.send(Event::TransferStarted {
			kind: TransferKind::Download,
			total_files: targets.len() as u64,
			total_bytes,
			files: roster,
		})
		.await;

	let progress = Progress::new(ev.clone());
	let sem = Arc::new(Semaphore::new(st.download_parallelism.max(1)));
	let errors = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));
	let mut handles = Vec::with_capacity(targets.len());

	for (key, rel, size) in targets {
		let (s, st, sem, progress, errors, cancel, dest) = (
			s.clone(),
			st.clone(),
			sem.clone(),
			progress.clone(),
			errors.clone(),
			cancel.clone(),
			dest.clone(),
		);
		handles.push(tokio::spawn(async move {
			let _permit = sem.acquire_owned().await.ok();
			if cancel.is_cancelled() {
				return;
			}
			let out_path = dest.join(sanitize_rel(&rel));
			let mut attempt = 0u32;
			let result = loop {
				progress.file_start(&rel, size); // (re)sets the per-file tracker on retries
				let r = download_one(&s, &key, &rel, &out_path, &progress).await;
				match r {
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
				Ok(()) => progress.file_done(&rel, true).await,
				Err(e) => {
					if !cancel.is_cancelled() {
						errors.lock().await.push(format!("{rel}: {e:#}"));
					}
					progress.file_done(&rel, false).await;
				}
			}
		}));
	}
	for h in handles {
		let _ = h.await;
	}

	let mut errs = errors.lock().await.clone();
	errs.truncate(20);
	let _ = ev
		.send(Event::TransferFinished {
			kind: TransferKind::Download,
			done: progress.done.load(Ordering::Relaxed),
			failed: progress.failed.load(Ordering::Relaxed),
			errors: errs,
		})
		.await;
}

/// A read that makes no progress for two minutes means the connection is
/// silently dead; turn it into an error so the retry/reconnect path runs.
async fn read_or_stall<T>(fut: impl std::future::Future<Output = std::io::Result<T>>) -> Result<T> {
	tokio::time::timeout(Duration::from_secs(120), fut)
		.await
		.map_err(|_| anyhow!("download stalled - connection appears dead"))?
		.map_err(Into::into)
}

async fn download_one(
	s: &Session,
	key: &str,
	name: &str,
	out_path: &PathBuf,
	progress: &Progress,
) -> Result<()> {
	if let Some(parent) = out_path.parent() {
		tokio::fs::create_dir_all(parent).await?;
	}
	let (len, mut reader) = s.backend().await.get_stream(key).await?;
	let tmp_name = format!(
		"{}.rse-part",
		out_path
			.file_name()
			.and_then(|n| n.to_str())
			.unwrap_or("download")
	);
	let tmp = out_path.with_file_name(tmp_name);
	let mut file = tokio::fs::File::create(&tmp).await?;

	let result: Result<()> = async {
		match s.keys.as_deref() {
			None => {
				// Manual copy loop so the progress bar moves *during* the
				// download instead of jumping to 100% at the end.
				let mut buf = vec![0u8; 256 * 1024];
				loop {
					let n = read_or_stall(reader.read(&mut buf)).await?;
					if n == 0 {
						break;
					}
					file.write_all(&buf[..n]).await?;
					progress.tick(name, n as u64);
				}
				file.flush().await?;
			}
			Some(keys) => {
				let (n_chunks, last_len) = crypto::chunk_layout(len)?;
				let mut header = [0u8; crypto::HEADER_LEN];
				read_or_stall(reader.read_exact(&mut header))
					.await
					.context("reading header")?;
				let mut dec = crypto::Decryptor::new(keys, &header)?;
				let mut buf = vec![0u8; crypto::CIPHER_CHUNK];
				for i in 0..n_chunks {
					let last = i == n_chunks - 1;
					let clen = if last { last_len } else { crypto::CIPHER_CHUNK };
					read_or_stall(reader.read_exact(&mut buf[..clen]))
						.await
						.context("reading chunk")?;
					let plain = dec.open_chunk(&buf[..clen], last)?;
					file.write_all(&plain).await?;
					progress.tick(name, plain.len() as u64);
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
	} else {
		let _ = tokio::fs::remove_file(&tmp).await;
	}
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
