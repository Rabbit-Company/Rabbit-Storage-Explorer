//! Background worker.
//!
//! Everything expensive (network, disk, crypto, Argon2) happens here, on a
//! dedicated OS thread running a tokio multi-thread runtime. The GTK main
//! thread only exchanges messages over `async-channel`, so the UI can never stall.

use crate::crypto::{self, VaultKeys};
use crate::dir_view;
use crate::manifest;
use crate::manifest_store::{FlushReason, ManifestStore};
use crate::settings::{BackendKind, ConnectionProfile, Settings};
use crate::storage::ProgressSink;
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
	Rename {
		key: String,
		is_dir: bool,
		old_name: String,
		new_name: String,
		encrypted: bool,
	},
	CalculateSize {
		key: String,
		name: String,
		encrypted: bool,
	},
	FolderInfo {
		key: String,
		name: String,
	},
	CancelTransfers,
	CancelFile {
		id: u64,
	},
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
	pub id: u64,
	pub name: String,
	pub kind: TransferKind,
	pub done: u64,
	pub total: u64,
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
		finished: Option<(u64, bool)>,
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
	Renamed,
	SizeCalculated {
		plaintext: u64,
		encrypted: u64,
	},
	FolderCreated,
	Toast(String),
	FolderInfo(FolderInfo),
}

/// One file's sizes for the folder Info modal.
#[derive(Clone, Debug)]
pub struct FileInfo {
	/// Path relative to the inspected folder (real, decrypted names).
	pub rel_path: String,
	pub plaintext: u64,
	pub encrypted: u64,
}

/// Full breakdown of an encrypted folder, for the Info modal.
#[derive(Clone, Debug)]
pub struct FolderInfo {
	pub name: String,
	pub file_count: u64,
	pub folder_count: u64,
	pub plaintext_total: u64,
	pub encrypted_total: u64,
	/// Unix-millis of the last cached size computation, if any.
	pub computed: Option<i64>,
	/// Per-file rows (already sorted largest-first), capped for the UI.
	pub files: Vec<FileInfo>,
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
	store: ManifestStore,
}

struct Conn {
	profile: ConnectionProfile,
	secret: String,
	backend: tokio::sync::RwLock<Arc<dyn StorageBackend>>,
	/// Serializes reconnect attempts: one task rebuilds, the rest wait.
	reconnect: tokio::sync::Mutex<()>,
	generation: AtomicU64,
	/// Fixed reconnect/retry delay in milliseconds; updated live on SetSettings.
	reconnect_interval_ms: AtomicU64,
	ev: async_channel::Sender<Event>,
}

impl Session {
	async fn backend(&self) -> Arc<dyn StorageBackend> {
		self.conn.backend.read().await.clone()
	}

	fn reconnect_delay(&self) -> Duration {
		Duration::from_millis(
			self
				.conn
				.reconnect_interval_ms
				.load(Ordering::Relaxed)
				.max(200),
		)
	}

	/// Called between retries.
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

		loop {
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
						_ = tokio::time::sleep(self.reconnect_delay()) => {}
					}
				}
			}
		}
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

/// Periodically flush dirty manifests, and do a final forced flush when stopped
/// (disconnect / reconnect / app close). No-op for non-E2EE sessions.
fn spawn_flush_timer(s: Session) -> CancellationToken {
	let token = CancellationToken::new();
	let stop = token.clone();
	tokio::spawn(async move {
		let Some(keys) = s.keys.clone() else { return };
		loop {
			tokio::select! {
				_ = stop.cancelled() => {
					let backend = s.backend().await;
					let _ = s.store.flush(&backend, &keys, FlushReason::Forced).await;
					return;
				}
				_ = tokio::time::sleep(s.store.interval()) => {
					let backend = s.backend().await;
					let _ = s.store.flush(&backend, &keys, FlushReason::Timer).await;
				}
			}
		}
	});
	token
}

async fn dispatch(cmd_rx: async_channel::Receiver<Command>, ev: async_channel::Sender<Event>) {
	let mut session: Option<Session> = None;
	let mut manifest_timer: Option<CancellationToken> = None;
	let mut settings = Settings::load();
	let hub = TransferHub::new(ev.clone());

	while let Ok(cmd) = cmd_rx.recv().await {
		match cmd {
			Command::SetSettings(s) => {
				if let Some(sess) = &session {
					sess
						.conn
						.reconnect_interval_ms
						.store(s.reconnect_interval_secs.max(1) * 1000, Ordering::Relaxed);
					sess
						.store
						.set_interval(std::time::Duration::from_secs(s.manifest_flush_secs.max(1)));
				}
				settings = s;
			}

			Command::Disconnect => {
				if let Some(t) = manifest_timer.take() {
					t.cancel();
				}
				hub.cancel_all();
				session = None;
			}

			Command::CancelTransfers => hub.cancel_all(),
			Command::CancelFile { id } => hub.cancel_file(id),

			Command::Connect {
				profile,
				secret_key,
				password,
			} => match connect(
				&profile,
				&secret_key,
				password.as_deref(),
				settings.reconnect_interval_secs.max(1) * 1000,
				ev.clone(),
			)
			.await
			{
				Ok(s) => {
					if let Some(t) = manifest_timer.take() {
						t.cancel();
					}
					let e2ee = s.keys.is_some();
					session = Some(s);
					if let Some(sess) = &session {
						manifest_timer = Some(spawn_flush_timer(sess.clone()));
					}
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

			Command::Rename {
				key,
				is_dir,
				old_name,
				new_name,
				encrypted,
			} => {
				let Some(s) = session.clone() else { continue };
				let ev = ev.clone();
				tokio::spawn(async move {
					let mut result = run_rename(&s, &key, is_dir, &old_name, &new_name, encrypted).await;
					if result.is_err() {
						s.wait_until_healthy(&CancellationToken::new()).await;
						result = run_rename(&s, &key, is_dir, &old_name, &new_name, encrypted).await;
					}
					match result {
						Ok(()) => {
							let _ = ev.send(Event::Renamed).await;
						}
						Err(e) => {
							let _ = ev.send(Event::Toast(format!("Rename failed: {e:#}"))).await;
						}
					}
				});
			}

			Command::CalculateSize {
				key,
				name,
				encrypted,
			} => {
				let Some(s) = session.clone() else { continue };
				let ev = ev.clone();
				tokio::spawn(async move {
					let mut result = run_calculate_size(&s, &key, &name, encrypted).await;
					if result.is_err() {
						s.wait_until_healthy(&CancellationToken::new()).await;
						result = run_calculate_size(&s, &key, &name, encrypted).await;
					}
					match result {
						Ok((plaintext, encrypted)) => {
							let _ = ev
								.send(Event::SizeCalculated {
									plaintext,
									encrypted,
								})
								.await;
						}
						Err(e) => {
							let _ = ev
								.send(Event::Toast(format!(
									"Size calculation for \"{name}\" failed: {e:#}"
								)))
								.await;
						}
					}
				});
			}

			Command::FolderInfo { key, name } => {
				let Some(s) = session.clone() else { continue };
				let ev = ev.clone();
				tokio::spawn(async move {
					let mut result = collect_folder_info(&s, &key, &name).await;
					if result.is_err() {
						s.wait_until_healthy(&CancellationToken::new()).await;
						result = collect_folder_info(&s, &key, &name).await;
					}
					match result {
						Ok(info) => {
							let _ = ev.send(Event::FolderInfo(info)).await;
						}
						Err(e) => {
							let _ = ev
								.send(Event::Toast(format!("Reading folder info failed: {e:#}")))
								.await;
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
	reconnect_interval_ms: u64,
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
		store: ManifestStore::new(std::time::Duration::from_secs(10)),
		conn: Arc::new(Conn {
			profile: profile.clone(),
			secret: secret.to_string(),
			backend: tokio::sync::RwLock::new(backend),
			reconnect: tokio::sync::Mutex::new(()),
			generation: AtomicU64::new(0),
			reconnect_interval_ms: AtomicU64::new(reconnect_interval_ms),
			ev,
		}),
	})
}

async fn list(s: &Session, prefix: &str) -> Result<Vec<RemoteEntry>> {
	let backend = s.backend().await;
	let raw: Vec<RawObject> = backend
		.list(prefix)
		.await?
		.into_iter()
		.filter(|o| {
			let leaf = o.key.trim_end_matches('/').rsplit('/').next().unwrap_or("");
			leaf != crypto::VAULT_KEY // vault metadata is never a user entry
		})
		.collect();

	match s.keys.as_deref() {
		Some(keys) => {
			// One manifest read (buffered) resolves every hash-named entry in the
			// directory to its real name + plaintext size, hides `.rse`, and
			// surfaces orphans.
			let manifest = s.store.load(&backend, keys, prefix).await?;
			let listing = dir_view::build_listing(raw, &manifest);
			if listing.orphan_count > 0 {
				let _ = s
					.conn
					.ev
					.send(Event::Toast(format!(
						"{} item(s) here lost their names (interrupted upload); re-upload to restore",
						listing.orphan_count
					)))
					.await;
			}
			Ok(listing.entries)
		}
		None => {
			let mut entries: Vec<RemoteEntry> = raw.into_iter().map(|o| raw_to_entry(o, None)).collect();
			entries.sort_by(|a, b| {
				b.is_dir
					.cmp(&a.is_dir)
					.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
			});
			Ok(entries)
		}
	}
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
	active: StdMutex<HashMap<u64, FileTrack>>,
}

struct FileTrack {
	kind: TransferKind,
	name: String,
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

	fn file_start(&self, id: u64, kind: TransferKind, name: &str, total: u64) {
		self.active.lock().unwrap().insert(
			id,
			FileTrack {
				kind,
				name: name.to_string(),
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
			.map(|(id, t)| FileProgress {
				id: *id,
				name: t.name.clone(),
				kind: t.kind,
				done: t.done,
				total: t.total,
				speed_bps: t.speed_bps,
			})
			.collect();
		v.sort_by_key(|f| f.id);
		v
	}

	async fn file_done(&self, id: u64, kind: TransferKind, ok: bool) {
		self.active.lock().unwrap().remove(&id);
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
				finished: Some((id, ok)),
			})
			.await;
	}

	/// Record transferred bytes and emit a progress event, throttled to at
	/// most ~10 events/second.
	fn tick(&self, id: u64, n: u64) {
		self.bytes.fetch_add(n, Ordering::Relaxed);
		if let Some(entry) = self.active.lock().unwrap().get_mut(&id) {
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

	fn file_resume(&self, id: u64, kind: TransferKind, name: &str, total: u64, already_done: u64) {
		self.active.lock().unwrap().insert(
			id,
			FileTrack {
				kind,
				name: name.to_string(),
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
	file_cancels: StdMutex<HashMap<u64, CancellationToken>>,
	next_id: AtomicU64,
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
			file_cancels: StdMutex::new(HashMap::new()),
			next_id: AtomicU64::new(0),
		})
	}

	fn next_id(&self) -> u64 {
		self.next_id.fetch_add(1, Ordering::Relaxed)
	}

	fn register_file(&self, id: u64, parent: &CancellationToken) -> CancellationToken {
		let token = parent.child_token();
		self.file_cancels.lock().unwrap().insert(id, token.clone());
		token
	}

	fn cancel_file(&self, id: u64) {
		if let Some(t) = self.file_cancels.lock().unwrap().get(&id) {
			t.cancel();
		}
	}

	fn cancel_all(&self) {
		self.state.lock().unwrap().cancel.cancel();
	}

	fn unregister_file(&self, id: u64) {
		self.file_cancels.lock().unwrap().remove(&id);
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
			self.file_cancels.lock().unwrap().clear();
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

/// On-wire (ciphertext) length of a `plain`-byte file: a header plus one AEAD
/// tag per CHUNK-sized piece. Matches the inverse math in `download_one`.
fn wire_len(plain: u64) -> u64 {
	let chunk = crypto::CHUNK as u64;
	let n_chunks = ((plain + chunk - 1) / chunk).max(1);
	crypto::HEADER_LEN as u64 + plain + n_chunks * crypto::TAG as u64
}

/// After a file lands, record it (and any parent folders created by its relative
/// path) in the buffered manifests. Non-fatal: the bytes are already uploaded, so
/// a manifest hiccup just leaves a recoverable orphan.
async fn record_upload(s: &Session, dest_prefix: &str, rel: &str, plaintext_size: u64) {
	let Some(keys) = s.keys.as_deref() else {
		return;
	};
	let backend = s.backend().await;
	let segments: Vec<&str> = rel.split('/').filter(|x| !x.is_empty()).collect();
	let mut prefix = dest_prefix.to_string();
	for (i, seg) in segments.iter().enumerate() {
		let Ok(enc) = crypto::encrypt_name(keys, seg) else {
			return;
		};
		let hash = manifest::hash_entry(&enc);
		let last = i + 1 == segments.len();
		let (enc_c, seg_c) = (enc.clone(), seg.to_string());
		let res = if last {
			s.store
				.edit(&backend, keys, &prefix, move |m| {
					m.upsert_file(&enc_c, &seg_c, plaintext_size)
				})
				.await
		} else {
			s.store
				.edit(&backend, keys, &prefix, move |m| {
					m.upsert_folder(&enc_c, &seg_c)
				})
				.await
		};
		if res.is_err() {
			return;
		}
		if !last {
			prefix = format!("{prefix}{hash}/");
		}
	}
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

	let items: Vec<(u64, PathBuf, String, u64)> = files
		.into_iter()
		.map(|(path, rel, size)| (hub.next_id(), path, rel, size))
		.collect();

	// Encrypted files that will use the multipart path are credited in wire
	// (ciphertext) bytes, so their displayed total must be wire-sized too.
	let threshold = st.multipart_threshold_mib * 1024 * 1024;
	let encrypted = s.keys.is_some();
	let meter = |plain: u64| -> u64 {
		if encrypted && plain > threshold {
			wire_len(plain)
		} else {
			plain
		}
	};

	let total_bytes: u64 = items.iter().map(|(_, _, _, size)| meter(*size)).sum();
	let roster: Vec<FileProgress> = items
		.iter()
		.map(|(id, _, rel, size)| FileProgress {
			id: *id,
			name: rel.clone(),
			kind: TransferKind::Upload,
			done: 0,
			total: meter(*size),
			speed_bps: 0.0,
		})
		.collect();

	let a = hub.admit(&st, items.len() as u64, total_bytes);
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

	let mut task_handles = Vec::new();
	for (id, path, rel, size) in items {
		let file_cancel = hub.register_file(id, &a.cancel);
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
		task_handles.push(tokio::spawn(async move {
			let _permit = sem.acquire_owned().await.ok();
			if !file_cancel.is_cancelled() {
				match upload_one(
					&s,
					&st,
					&path,
					&dest_prefix,
					id,
					&rel,
					&progress,
					&file_cancel,
				)
				.await
				{
					Ok(()) => {
						record_upload(&s, &dest_prefix, &rel, size).await;
						progress.file_done(id, TransferKind::Upload, true).await
					}
					Err(e) => {
						if !file_cancel.is_cancelled() {
							errors.lock().await.push(format!("{rel}: {e:#}"));
						}
						progress.file_done(id, TransferKind::Upload, false).await;
					}
				}
			} else if !cancel.is_cancelled() {
				// Per-file cancel while queued: settle the row. Batch cancel skips this.
				progress.file_done(id, TransferKind::Upload, false).await;
			}
			hub.unregister_file(id);
			hub.task_done().await;
		}));
	}

	if let Some(keys) = s.keys.clone() {
		let (s2, handles) = (s.clone(), std::mem::take(&mut task_handles));
		tokio::spawn(async move {
			for h in handles {
				let _ = h.await;
			}
			let backend = s2.backend().await;
			let _ = s2.store.flush(&backend, &keys, FlushReason::Forced).await;
		});
	}
}

async fn upload_one(
	s: &Session,
	st: &Settings,
	path: &PathBuf,
	dest_prefix: &str,
	id: u64,
	rel: &str,
	progress: &Arc<Progress>,
	cancel: &CancellationToken,
) -> Result<()> {
	let key = match s.keys.as_deref() {
		Some(k) => format!("{dest_prefix}{}", dir_view::on_disk_path(k, rel)?),
		None => format!("{dest_prefix}{rel}"),
	};

	let plain_len = tokio::fs::metadata(path).await?.len();
	let threshold = st.multipart_threshold_mib * 1024 * 1024;

	let mut attempt = 0u32;
	loop {
		if cancel.is_cancelled() {
			return Err(anyhow!("cancelled"));
		}
		progress.file_start(id, TransferKind::Upload, rel, plain_len);
		let result = async {
			let backend = s.backend().await;
			backend.prepare_parents(&key).await?;
			if plain_len <= threshold {
				upload_small(s, &backend, path, &key, id, plain_len, progress).await
			} else {
				upload_multipart(s, &backend, st, path, &key, id, progress, cancel).await
			}
		}
		.await;
		match result {
			Ok(()) => return Ok(()),
			Err(_) if attempt < st.retries && !cancel.is_cancelled() => {
				attempt += 1;
				s.wait_until_healthy(cancel).await;
				tokio::time::sleep(s.reconnect_delay()).await;
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
	id: u64,
	plain_len: u64,
	progress: &Arc<Progress>,
) -> Result<()> {
	let data = tokio::fs::read(path).await.context("reading local file")?;
	let body = match s.keys.as_deref() {
		Some(k) => crypto::encrypt_bytes(k, &data)?,
		None => data,
	};
	backend.put(key, body).await?;
	progress.tick(id, plain_len);
	Ok(())
}

async fn upload_multipart(
	s: &Session,
	backend: &Arc<dyn StorageBackend>,
	st: &Settings,
	path: &PathBuf,
	key: &str,
	id: u64,
	progress: &Arc<Progress>,
	cancel: &CancellationToken,
) -> Result<()> {
	const S3_MIN_PART: usize = 5 * 1024 * 1024;

	let part_size = (st.part_size_mib.max(5) * 1024 * 1024) as usize;
	let mp = backend.create_multipart(key).await?;

	let sink: ProgressSink = {
		let progress = progress.clone();
		std::sync::Arc::new(move |n| progress.tick(id, n))
	};

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

			if part_buf.len() >= part_size || last {
				let data = std::mem::take(&mut part_buf);
				if !last && data.len() < S3_MIN_PART {
					return Err(anyhow!(
						"internal: multipart part {part_number} is {} bytes, \
						 below the 5 MiB minimum",
						data.len()
					));
				}
				let etag = backend
					.upload_part(&mp, part_number, data, Some(sink.clone()))
					.await?;
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
						if o.key.ends_with('/') {
							continue;
						}
						let leaf = o.key.rsplit('/').find(|s| !s.is_empty()).unwrap_or("");
						if manifest::is_manifest_key(leaf) {
							continue;
						}
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

	let items: Vec<(u64, String, String, u64)> = targets
		.into_iter()
		.map(|(key, rel, size)| (hub.next_id(), key, rel, size))
		.collect();
	let total_bytes: u64 = items.iter().map(|(_, _, _, s)| *s).sum();
	let roster: Vec<FileProgress> = items
		.iter()
		.map(|(id, _, rel, size)| FileProgress {
			id: *id,
			name: rel.clone(),
			kind: TransferKind::Download,
			done: 0,
			total: *size,
			speed_bps: 0.0,
		})
		.collect();

	let a = hub.admit(&st, items.len() as u64, total_bytes);
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

	for (id, key, rel, size) in items {
		let file_cancel = hub.register_file(id, &a.cancel);
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
			if !file_cancel.is_cancelled() {
				let out_path = dest.join(sanitize_rel(&rel));
				let mut attempt = 0u32;
				let result = loop {
					match download_one(&s, &key, id, &rel, size, &out_path, &progress, &file_cancel).await {
						Ok(()) => break Ok(()),
						Err(_) if attempt < st.retries && !file_cancel.is_cancelled() => {
							attempt += 1;
							s.wait_until_healthy(&file_cancel).await;
							tokio::time::sleep(Duration::from_millis(400 * (1 << attempt.min(4)))).await;
						}
						Err(e) => break Err(e),
					}
				};
				match result {
					Ok(()) => progress.file_done(id, TransferKind::Download, true).await,
					Err(e) => {
						let _ = tokio::fs::remove_file(part_path(&out_path)).await;
						if !file_cancel.is_cancelled() {
							errors.lock().await.push(format!("{rel}: {e:#}"));
						}
						progress.file_done(id, TransferKind::Download, false).await;
					}
				}
			} else if !cancel.is_cancelled() {
				progress.file_done(id, TransferKind::Download, false).await;
			}
			hub.unregister_file(id);
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
	id: u64,
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

	let cipher_len = if encrypted {
		crypto::encrypted_size(expected_len)
	} else {
		expected_len
	};

	// Plaintext size, for the completion check and the progress row total.
	// (For plain files the on-disk size is the plaintext size; for encrypted
	// files the caller passes the manifest plaintext size directly.)
	let plaintext_total = expected_len;

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
		progress.file_resume(
			id,
			TransferKind::Download,
			name,
			plaintext_total,
			done_plain,
		);
	} else {
		progress.file_start(id, TransferKind::Download, name, plaintext_total);
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
					progress.tick(id, n as u64);
				}
				file.flush().await?;
			}
			Some(keys) => {
				let (n_chunks, last_len) = crypto::chunk_layout(cipher_len)?;
				let completed = done_plain / crypto::CHUNK as u64;

				// The file nonce lives in the 12-byte header. When resuming we
				// skipped it, so fetch just those bytes to rebuild the decryptor.
				let mut header = [0u8; crypto::HEADER_LEN];
				if completed == 0 {
					read_or_stall(reader.read_exact(&mut header))
						.await
						.context("reading header")?;
				} else {
					let header_bytes = s
						.backend()
						.await
						.read_header(key, crypto::HEADER_LEN)
						.await
						.context("reading header")?;
					if header_bytes.len() < crypto::HEADER_LEN {
						return Err(anyhow!("encrypted file too short to contain a header"));
					}
					header.copy_from_slice(&header_bytes[..crypto::HEADER_LEN]);
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
					progress.tick(id, plain.len() as u64);
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

async fn create_folder(s: &Session, prefix: &str, name: &str) -> Result<()> {
	let (segment, enc) = match &s.keys {
		Some(k) => {
			let enc = crypto::encrypt_name(k, name)?;
			(manifest::hash_entry(&enc), Some(enc))
		}
		None => (name.to_string(), None),
	};
	let key = format!("{prefix}{segment}/");
	let backend = s.backend().await;
	if s.conn.profile.kind == BackendKind::S3 {
		backend.put(&key, Vec::new()).await?;
	} else {
		backend.prepare_parents(&format!("{key}x")).await?;
	}
	if let (Some(keys), Some(enc)) = (s.keys.as_deref(), enc) {
		let (enc_c, name_c) = (enc, name.to_string());
		s.store
			.edit(&backend, keys, prefix, move |m| {
				m.upsert_folder(&enc_c, &name_c)
			})
			.await?;
		s.store.flush(&backend, keys, FlushReason::Forced).await?;
	}
	Ok(())
}

async fn run_delete(s: &Session, items: Vec<RemoteEntry>) -> Result<u64> {
	let mut keys = Vec::new();
	for item in items.clone() {
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

	if let Some(keys) = s.keys.as_deref() {
		let backend = s.backend().await;
		for item in &items {
			// parent prefix of item.key, and the item's encrypted leaf name
			let parent = parent_prefix(&item.key);
			if let Ok(enc) = crypto::encrypt_name(keys, &item.name) {
				let enc_c = enc.clone();
				let _ = s
					.store
					.edit(&backend, keys, &parent, move |m| {
						m.remove(&enc_c);
					})
					.await;
			}
			// If a whole folder was deleted, forget its buffered manifest too.
			if item.is_dir {
				s.store.forget(item.key.trim_end_matches('/')).await;
			}
		}
		let _ = s.store.flush(&backend, keys, FlushReason::Forced).await;
	}

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

		if let Some(keys) = s.keys.as_deref() {
			let src_parent = parent_prefix(&item.key);
			if let Ok(enc) = crypto::encrypt_name(keys, &item.name) {
				// A move preserves the name, so the encrypted segment (and thus the
				// on-disk hash) is identical in source and destination: take the
				// record out of the source manifest and re-insert it into the dest.
				// The take/insert helpers hold the store lock internally, so nothing
				// non-Send has to cross an await point.
				if let Ok(Some(entry)) = s.store.take_entry(&backend, keys, &src_parent, &enc).await {
					let _ = s
						.store
						.insert_entry(&backend, keys, dest_prefix, &enc, entry)
						.await;
				}
			}
		}
	}

	if let Some(keys) = s.keys.as_deref() {
		let backend = s.backend().await;
		let _ = s.store.flush(&backend, keys, FlushReason::Forced).await;
	}

	Ok(moved)
}

/// Rename one entry in place. Only the leaf segment changes; the parent prefix
/// and (for folders) the whole subtree move with it via the backend's `rename`.
async fn run_rename(
	s: &Session,
	key: &str,
	is_dir: bool,
	old_name: &str,
	new_name: &str,
	encrypted: bool,
) -> Result<()> {
	if new_name.trim().is_empty() || new_name.contains('/') {
		return Err(anyhow!("invalid name"));
	}
	let backend = s.backend().await;
	let parent = parent_prefix(key);

	// Only a genuine E2EE item (hash-named + in the manifest) goes through the
	// hashing/manifest path. A foreign or plaintext object - even inside an E2EE
	// session - is renamed in place, keeping its literal on-disk name.
	match (encrypted, s.keys.as_deref()) {
		(true, Some(keys)) => {
			// On-disk names are hash_entry(encrypt_name(..)); the real name lives
			// in the parent's manifest. So a rename = move the object(s) from the
			// old hash to the new hash, then re-key the manifest entry.
			let old_enc = crypto::encrypt_name(keys, old_name)?;
			let new_enc = crypto::encrypt_name(keys, new_name)?;
			let new_hash = manifest::hash_entry(&new_enc);
			if manifest::hash_entry(&old_enc) == new_hash {
				return Ok(()); // same encrypted name -> nothing to do
			}

			// Collision guard: refuse if the target name already exists here.
			let existing = s.store.load(&backend, keys, &parent).await?;
			if existing.name_for(&new_hash).is_some() {
				return Err(anyhow!("an item named \"{new_name}\" already exists here"));
			}

			let (from, to) = if is_dir {
				let from = if key.ends_with('/') {
					key.to_string()
				} else {
					format!("{key}/")
				};
				(from, format!("{parent}{new_hash}/"))
			} else {
				// Use the authoritative on-disk key as the source rather than
				// reconstructing it, so the move always targets the real object.
				(key.to_string(), format!("{parent}{new_hash}"))
			};
			backend.rename(&from, &to).await?;

			// A renamed folder's buffered child manifest now lives under a new
			// prefix; forget the stale buffered copy so it isn't flushed back.
			if is_dir {
				s.store.forget(from.trim_end_matches('/')).await;
			}

			let (oe, ne, nn) = (old_enc, new_enc, new_name.to_string());
			s.store
				.edit(&backend, keys, &parent, move |m| {
					m.rename_entry(&oe, &ne, &nn);
				})
				.await?;
			s.store.flush(&backend, keys, FlushReason::Forced).await?;
			Ok(())
		}
		_ => {
			// Plaintext rename: no E2EE, or a foreign object in an E2EE session.
			// The on-disk name is literal, so just move the key; no manifest.
			let new_segment = new_name.to_string();
			if is_dir {
				let from = if key.ends_with('/') {
					key.to_string()
				} else {
					format!("{key}/")
				};
				let to = format!("{parent}{new_segment}/");
				if to == from {
					return Ok(());
				}
				backend.rename(&from, &to).await?;
			} else {
				let to = format!("{parent}{new_segment}");
				if to == key {
					return Ok(());
				}
				backend.rename(key, &to).await?;
			}
			Ok(())
		}
	}
}

/// Recursively total the bytes under a folder. Returns `(plaintext, encrypted)`.
///
/// `encrypted` is the sum of on-disk object sizes. `plaintext` is the logical
/// size: for an E2EE session each encrypted object's plaintext size is derived
/// from its ciphertext length; without E2EE the two totals are equal.
async fn run_calculate_size(
	s: &Session,
	key: &str,
	name: &str,
	encrypted: bool,
) -> Result<(u64, u64)> {
	let backend = s.backend().await;
	let objects = backend.list_recursive(key).await?;
	let mut enc_total = 0u64;
	let mut plaintext = 0u64;
	for o in &objects {
		// Skip per-directory `.rse` manifests and the vault: they're metadata,
		// not user data, and would otherwise inflate both totals.
		let leaf = o.key.trim_end_matches('/').rsplit('/').next().unwrap_or("");
		if manifest::is_manifest_key(leaf) || leaf == crypto::VAULT_KEY {
			continue;
		}
		enc_total = enc_total.saturating_add(o.size);
		plaintext = plaintext.saturating_add(match s.keys.as_deref() {
			// Ciphertext -> plaintext size, inverse of `crypto::encrypted_size`.
			Some(_) => plaintext_of_ciphertext(o.size),
			None => o.size,
		});
	}

	// Cache the roll-up on this folder's entry, which lives in the *parent*
	// directory's manifest, so future listings show the size instantly. Only
	// genuine E2EE folders have a manifest entry to write into.
	if encrypted {
		if let Some(keys) = s.keys.as_deref() {
			let parent = parent_prefix(key);
			if let Ok(enc) = crypto::encrypt_name(keys, name) {
				let now_ms = std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.map(|d| d.as_millis() as i64)
					.unwrap_or(0);
				let (enc_c, p, e) = (enc, plaintext, enc_total);
				let _ = s
					.store
					.edit(&backend, keys, &parent, move |m| {
						m.set_folder_size(&enc_c, p, e, now_ms);
					})
					.await;
				let _ = s.store.flush(&backend, keys, FlushReason::Forced).await;
			}
		}
	}

	Ok((plaintext, enc_total))
}

/// Walk an encrypted folder, reading each directory's `.rse` manifest and raw
/// listing, to build a full breakdown for the Info modal: per-file plaintext and
/// ciphertext sizes with real relative paths, totals, counts, and the folder's
/// last cached-size timestamp.
async fn collect_folder_info(s: &Session, key: &str, name: &str) -> Result<FolderInfo> {
	let backend = s.backend().await;
	let keys = s
		.keys
		.as_deref()
		.ok_or_else(|| anyhow!("folder info is only available for encrypted folders"))?;

	let root = format!("{}/", key.trim_end_matches('/'));
	let mut files: Vec<FileInfo> = Vec::new();
	let mut folder_count = 0u64;
	let mut plaintext_total = 0u64;
	let mut encrypted_total = 0u64;

	// (backend dir prefix, human relative path so far)
	let mut stack: Vec<(String, String)> = vec![(root.clone(), String::new())];
	while let Some((dir, rel_base)) = stack.pop() {
		let manifest = s.store.load(&backend, keys, &dir).await.unwrap_or_default();
		let raw = backend.list(&dir).await?;

		for o in &raw {
			let leaf = o.key.trim_end_matches('/').rsplit('/').next().unwrap_or("");
			if manifest::is_manifest_key(leaf) || leaf == crypto::VAULT_KEY {
				continue;
			}
			if o.is_prefix {
				// A subfolder: recurse. Its real name comes from this manifest.
				folder_count += 1;
				let sub_name = manifest.name_for(leaf).unwrap_or(leaf).to_string();
				let sub_rel = if rel_base.is_empty() {
					sub_name
				} else {
					format!("{rel_base}/{sub_name}")
				};
				stack.push((format!("{dir}{leaf}/"), sub_rel));
			} else {
				// A file: plaintext size from the manifest, ciphertext from disk.
				let plaintext = manifest
					.files
					.get(leaf)
					.map(|f| f.size)
					.unwrap_or_else(|| plaintext_of_ciphertext(o.size));
				let fname = manifest.name_for(leaf).unwrap_or(leaf).to_string();
				let rel_path = if rel_base.is_empty() {
					fname
				} else {
					format!("{rel_base}/{fname}")
				};
				plaintext_total = plaintext_total.saturating_add(plaintext);
				encrypted_total = encrypted_total.saturating_add(o.size);
				files.push(FileInfo {
					rel_path,
					plaintext,
					encrypted: o.size,
				});
			}
		}
	}

	// The cached-size timestamp lives on this folder's entry in its *parent*
	// manifest.
	let parent = parent_prefix(key);
	let computed = {
		let parent_manifest = s.store.load(&backend, keys, &parent).await.ok();
		parent_manifest.and_then(|m| {
			crypto::encrypt_name(keys, name).ok().and_then(|enc| {
				m.folders
					.get(&manifest::hash_entry(&enc))
					.and_then(|f| f.computed)
			})
		})
	};

	let file_count = files.len() as u64;
	files.sort_by(|a, b| b.encrypted.cmp(&a.encrypted));

	Ok(FolderInfo {
		name: name.to_string(),
		file_count,
		folder_count,
		plaintext_total,
		encrypted_total,
		computed,
		files,
	})
}

/// Inverse of `crypto::encrypted_size`: recover a file's plaintext length from
/// its on-disk ciphertext length. Header + one Poly1305 tag per 1 MiB chunk are
/// overhead; subtract them. Returns 0 if the size is too small to be a valid
/// encrypted object (e.g. a folder marker), which contributes nothing.
fn plaintext_of_ciphertext(cipher_len: u64) -> u64 {
	let header = crypto::HEADER_LEN as u64;
	let tag = crypto::TAG as u64;
	let chunk = crypto::CHUNK as u64;
	let Some(body) = cipher_len.checked_sub(header) else {
		return 0;
	};
	if body < tag {
		return 0;
	}
	// body = plaintext + chunks*tag, where chunks = ceil(plaintext/chunk),
	// and an empty file still has one (empty) chunk. Compute chunk count from
	// the ciphertext body, then strip that many tags.
	let cipher_chunk = chunk + tag; // full encrypted chunk
	let full_chunks = body / cipher_chunk;
	let remainder = body % cipher_chunk; // last (possibly partial) chunk incl. its tag
	let chunks = full_chunks + if remainder > 0 { 1 } else { 0 };
	body.saturating_sub(chunks.max(1) * tag)
}
