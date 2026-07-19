//! SFTP backend over SSH (russh + russh-sftp). Maps the app's key/prefix model
//! onto a remote directory tree:
//!
//! * keys are `/`-separated paths relative to the configured root directory
//! * "folders" (keys with a trailing `/`) are real directories
//!
//! Host keys are verified trust-on-first-use: the first connection records the
//! server's fingerprint in `known_hosts.json` in the app config dir; later
//! connections fail loudly on mismatch - checked *before* any credentials are
//! sent. Auth is password-based, or public key when a key path is configured
//! (the stored secret is then used as the key passphrase).

use super::{MultipartUpload, RawObject, Reader, StorageBackend};
use crate::settings::{self, ConnectionProfile};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{OpenFlags, StatusCode};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

struct HostKeyRecorder {
	observed: Arc<StdMutex<Option<String>>>,
}

impl russh::client::Handler for HostKeyRecorder {
	type Error = russh::Error;

	async fn check_server_key(
		&mut self,
		server_public_key: &russh::keys::ssh_key::PublicKey,
	) -> Result<bool, Self::Error> {
		let fp = server_public_key
			.fingerprint(Default::default())
			.to_string();
		*self.observed.lock().unwrap() = Some(fp);
		// Accept the handshake; trust decisions happen in `connect()` *before*
		// any authentication data is sent.
		Ok(true)
	}
}

pub struct SftpBackend {
	sftp: SftpSession,
	/// Canonicalized remote root, no trailing slash.
	root: String,
	/// Keeps the SSH connection alive for the lifetime of the backend.
	_session: russh::client::Handle<HostKeyRecorder>,
	/// In-flight "multipart" uploads: id -> open remote file handle.
	uploads: Mutex<HashMap<String, russh_sftp::client::fs::File>>,
	upload_seq: AtomicU64,
	/// Directories already created this session (saves round-trips).
	known_dirs: Mutex<HashSet<String>>,
}

impl SftpBackend {
	pub async fn connect(profile: &ConnectionProfile, secret: &str) -> Result<Self> {
		let mut config = russh::client::Config::default();
		// Detect dead connections (e.g. after a Wi-Fi switch) within ~30s so
		// pending operations fail and the worker can reconnect, instead of
		// hanging on a silently broken TCP stream.
		config.keepalive_interval = Some(std::time::Duration::from_secs(10));
		config.keepalive_max = 3;
		let config = Arc::new(config);
		let observed = Arc::new(StdMutex::new(None));
		let handler = HostKeyRecorder {
			observed: observed.clone(),
		};

		let mut session =
			russh::client::connect(config, (profile.host.as_str(), profile.port), handler)
				.await
				.with_context(|| format!("SSH connection to {}:{} failed", profile.host, profile.port))?;

		let fingerprint = observed
			.lock()
			.unwrap()
			.clone()
			.ok_or_else(|| anyhow!("server presented no host key"))?;
		let host_id = format!("{}:{}", profile.host, profile.port);
		match settings::known_host(&host_id) {
			Some(known) if known != fingerprint => bail!(
				"SSH host key mismatch for {host_id}!\n  stored: {known}\n  now:    {fingerprint}\n\
                 If the server's key legitimately changed, remove this host from known_hosts.json \
                 in the app config directory."
			),
			Some(_) => {}
			None => settings::remember_host(&host_id, &fingerprint),
		}

		let authenticated = if profile.key_path.trim().is_empty() {
			session
				.authenticate_password(&profile.username, secret)
				.await
				.context("password authentication failed")?
				.success()
		} else {
			let passphrase = if secret.is_empty() {
				None
			} else {
				Some(secret)
			};
			let key = load_secret_key(expand_tilde(profile.key_path.trim()), passphrase)
				.with_context(|| format!("loading private key {}", profile.key_path))?;
			let hash_alg = session.best_supported_rsa_hash().await?.flatten();
			session
				.authenticate_publickey(
					&profile.username,
					PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
				)
				.await
				.context("public key authentication failed")?
				.success()
		};
		if !authenticated {
			bail!(
				"SSH authentication failed for {}@{}",
				profile.username,
				profile.host
			);
		}

		let channel = session.channel_open_session().await?;
		channel
			.request_subsystem(true, "sftp")
			.await
			.context("server has no SFTP subsystem")?;
		let sftp = SftpSession::new(channel.into_stream())
			.await
			.context("starting SFTP session")?;

		let root_input = if profile.root_path.trim().is_empty() {
			"."
		} else {
			profile.root_path.trim()
		};
		let root = sftp
			.canonicalize(root_input)
			.await
			.with_context(|| format!("remote directory \"{root_input}\" not found"))?;

		// Trimming the trailing slash from "/" would leave an empty string,
		// making every path lookup query "" instead of the filesystem root.
		let root = match root.trim_end_matches('/') {
			"" => "/".to_string(),
			trimmed => trimmed.to_string(),
		};

		Ok(Self {
			sftp,
			root,
			_session: session,
			uploads: Mutex::new(HashMap::new()),
			upload_seq: AtomicU64::new(0),
			known_dirs: Mutex::new(HashSet::new()),
		})
	}

	/// Absolute remote path for one of our keys ("" -> root).
	fn full(&self, key: &str) -> String {
		let k = key.trim_end_matches('/');
		if k.is_empty() {
			self.root.clone()
		} else if self.root == "/" {
			format!("/{k}")
		} else {
			format!("{}/{}", self.root, k)
		}
	}

	async fn list_inner(&self, prefix: &str) -> Result<Vec<RawObject>> {
		let dir = self.full(prefix);
		let mut out = Vec::new();
		for entry in self
			.sftp
			.read_dir(&dir)
			.await
			.context("listing remote directory")?
		{
			let name = entry.file_name();
			if name == "." || name == ".." {
				continue;
			}
			let meta = entry.metadata();
			let modified = meta.mtime.map(|t| t as i64);
			if entry.file_type().is_dir() {
				out.push(RawObject {
					key: format!("{prefix}{name}/"),
					size: 0,
					modified,
					is_prefix: true,
				});
			} else {
				out.push(RawObject {
					key: format!("{prefix}{name}"),
					size: meta.size.unwrap_or(0),
					modified,
					is_prefix: false,
				});
			}
		}
		Ok(out)
	}

	fn rmdir_recursive<'a>(
		&'a self,
		path: String,
	) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
		Box::pin(async move {
			for entry in self.sftp.read_dir(&path).await? {
				let name = entry.file_name();
				if name == "." || name == ".." {
					continue;
				}
				let child = format!("{path}/{name}");
				if entry.file_type().is_dir() {
					self.rmdir_recursive(child).await?;
				} else {
					tolerate_missing(self.sftp.remove_file(&child).await)?;
				}
			}
			tolerate_missing(self.sftp.remove_dir(&path).await)?;
			Ok(())
		})
	}
}

/// SFTP requests on a dead connection can hang until TCP gives up. Cap every
/// operation so a silent failure becomes an error the retry/reconnect path
/// can act on. Generous limits: only a truly stuck request ever hits them.
async fn with_timeout<T>(
	secs: u64,
	fut: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
	tokio::time::timeout(std::time::Duration::from_secs(secs), fut)
		.await
		.map_err(|_| anyhow!("operation timed out - connection appears dead"))?
}

/// Ignore "no such file" errors (e.g. double deletes), propagate the rest.
fn tolerate_missing(r: std::result::Result<(), SftpError>) -> Result<()> {
	match r {
		Ok(()) => Ok(()),
		Err(SftpError::Status(s)) if matches!(s.status_code, StatusCode::NoSuchFile) => Ok(()),
		Err(e) => Err(e.into()),
	}
}

fn expand_tilde(path: &str) -> std::path::PathBuf {
	if let Some(rest) = path.strip_prefix("~/") {
		if let Ok(home) = std::env::var("HOME") {
			return std::path::Path::new(&home).join(rest);
		}
	}
	std::path::PathBuf::from(path)
}

#[async_trait]
impl StorageBackend for SftpBackend {
	async fn health_check(&self) -> Result<()> {
		self
			.sftp
			.metadata(&self.root)
			.await
			.context("connection check failed")?;
		Ok(())
	}

	async fn list(&self, prefix: &str) -> Result<Vec<RawObject>> {
		with_timeout(60, self.list_inner(prefix)).await
	}

	async fn list_recursive(&self, prefix: &str) -> Result<Vec<RawObject>> {
		// Iterative BFS; returns files only (mirrors S3 semantics).
		let mut files = Vec::new();
		let mut queue = vec![prefix.to_string()];
		while let Some(p) = queue.pop() {
			for obj in self.list(&p).await? {
				if obj.is_prefix {
					queue.push(obj.key);
				} else {
					files.push(obj);
				}
			}
		}
		Ok(files)
	}

	async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
		with_timeout(300, async {
			match self
				.sftp
				.open_with_flags(self.full(key), OpenFlags::READ)
				.await
			{
				Ok(mut file) => {
					let mut buf = Vec::new();
					file
						.read_to_end(&mut buf)
						.await
						.context("reading remote file")?;
					Ok(Some(buf))
				}
				Err(SftpError::Status(s)) if matches!(s.status_code, StatusCode::NoSuchFile) => Ok(None),
				Err(e) => Err(anyhow!("open failed: {e}")),
			}
		})
		.await
	}

	async fn get_stream(&self, key: &str) -> Result<(u64, Reader)> {
		with_timeout(60, async {
			let full = self.full(key);
			let file = self
				.sftp
				.open_with_flags(&full, OpenFlags::READ)
				.await
				.with_context(|| format!("download failed: {key}"))?;
			let len = file.metadata().await.ok().and_then(|m| m.size).unwrap_or(0);
			Ok((len, Box::pin(file) as Reader))
		})
		.await
	}

	async fn put(&self, key: &str, data: Vec<u8>) -> Result<()> {
		with_timeout(600, async {
			let mut file = self
				.sftp
				.open_with_flags(
					self.full(key),
					OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
				)
				.await
				.with_context(|| format!("upload failed: {key}"))?;
			file.write_all(&data).await?;
			file.shutdown().await?; // closes the remote handle
			Ok(())
		})
		.await
	}

	async fn prepare_parents(&self, key: &str) -> Result<()> {
		with_timeout(120, async {
			let segments: Vec<&str> = key.trim_end_matches('/').split('/').collect();
			if segments.len() <= 1 {
				return Ok(());
			}
			let mut partial = String::new();
			for seg in &segments[..segments.len() - 1] {
				if !partial.is_empty() {
					partial.push('/');
				}
				partial.push_str(seg);
				{
					let known = self.known_dirs.lock().await;
					if known.contains(&partial) {
						continue;
					}
				}
				let full = self.full(&partial);
				// Create; tolerate "already exists" style failures, then verify.
				if self.sftp.create_dir(&full).await.is_err() {
					let meta = self
						.sftp
						.metadata(&full)
						.await
						.with_context(|| format!("cannot create remote directory {partial}"))?;
					if !meta.file_type().is_dir() {
						bail!("remote path {partial} exists and is not a directory");
					}
				}
				self.known_dirs.lock().await.insert(partial.clone());
			}
			Ok(())
		})
		.await
	}

	async fn create_multipart(&self, key: &str) -> Result<MultipartUpload> {
		with_timeout(60, async {
			let file = self
				.sftp
				.open_with_flags(
					self.full(key),
					OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
				)
				.await
				.with_context(|| format!("upload failed: {key}"))?;
			let id = format!("sftp-{}", self.upload_seq.fetch_add(1, Ordering::Relaxed));
			self.uploads.lock().await.insert(id.clone(), file);
			Ok(MultipartUpload {
				upload_id: id,
				key: key.to_string(),
			})
		})
		.await
	}

	async fn upload_part(
		&self,
		mp: &MultipartUpload,
		_part_number: i32,
		data: Vec<u8>,
	) -> Result<String> {
		// Parts for one file always arrive in order from a single task, so a
		// sequential append is correct. Take the handle out of the map while
		// writing so other files' parts aren't blocked.
		let mut file = self
			.uploads
			.lock()
			.await
			.remove(&mp.upload_id)
			.ok_or_else(|| anyhow!("unknown upload id"))?;
		let result = with_timeout(600, async {
			file.write_all(&data).await.map_err(Into::into)
		})
		.await;
		self.uploads.lock().await.insert(mp.upload_id.clone(), file);
		result.context("writing remote file")?;
		Ok(String::new()) // SFTP has no ETags
	}

	async fn complete_multipart(
		&self,
		mp: &MultipartUpload,
		_etags: Vec<(i32, String)>,
	) -> Result<()> {
		if let Some(mut file) = self.uploads.lock().await.remove(&mp.upload_id) {
			with_timeout(60, async {
				file.flush().await?;
				file.shutdown().await?;
				Ok(())
			})
			.await?;
		}
		Ok(())
	}

	async fn abort_multipart(&self, mp: &MultipartUpload) -> Result<()> {
		if let Some(file) = self.uploads.lock().await.remove(&mp.upload_id) {
			drop(file);
			tolerate_missing(self.sftp.remove_file(self.full(&mp.key)).await)?;
		}
		Ok(())
	}

	async fn delete(&self, keys: Vec<String>) -> Result<()> {
		for key in keys {
			let full = self.full(&key);
			if key.ends_with('/') {
				// Directory: remove recursively (handles nested subdirectories).
				match self.sftp.metadata(&full).await {
					Ok(_) => self.rmdir_recursive(full).await?,
					Err(_) => {} // already gone
				}
			} else {
				tolerate_missing(self.sftp.remove_file(&full).await)?;
			}
		}
		Ok(())
	}
}
