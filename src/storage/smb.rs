//! SMB 2/3 backend (pure Rust, `smb2` crate). Uses compound and pipelined
//! requests for throughput. Directory/metadata operations require `&mut`
//! access to the client and are serialized behind a mutex, but file readers
//! and writers own their own connection handle - actual data transfer runs
//! concurrently across parallel tasks without holding that lock.

use super::{ChannelReader, MultipartUpload, RawObject, Reader, StorageBackend};
use crate::settings::ConnectionProfile;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use smb2::pack::FileTime;
use smb2::{ClientConfig, ErrorKind, FileWriter, SmbClient, Tree};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

const STREAM_CHUNK: u64 = 256 * 1024;
const WRITE_CHUNK: usize = 256 * 1024;

pub struct SmbBackend {
	/// Client and share tree; `&mut` operations (listing, stat, delete, mkdir)
	/// serialize here. File streams do not hold this lock while transferring.
	inner: Mutex<(SmbClient, Tree)>,
	/// Path prefix inside the share ("" or "dir/sub"), forward slashes.
	base: String,
	/// In-flight uploads: id -> open writer (sequential appends).
	uploads: Mutex<HashMap<String, FileWriter>>,
	upload_seq: AtomicU64,
	known_dirs: Mutex<HashSet<String>>,
}

impl SmbBackend {
	pub async fn connect(profile: &ConnectionProfile, password: &str) -> Result<Self> {
		if profile.share.trim().is_empty() {
			bail!("an SMB share name is required");
		}
		let config = ClientConfig {
			addr: format!("{}:{}", profile.host.trim(), profile.port),
			timeout: Duration::from_secs(15),
			username: profile.username.trim().to_string(),
			password: password.to_string(),
			domain: profile.domain.trim().to_string(),
			auto_reconnect: true,
			compression: true,
			dfs_enabled: true,
			dfs_target_overrides: HashMap::new(),
		};
		let mut client = tokio::time::timeout(Duration::from_secs(20), SmbClient::connect(config))
			.await
			.map_err(|_| anyhow!("SMB connection timed out"))?
			.with_context(|| format!("connecting to {} failed", profile.host.trim()))?;
		let mut tree = client
			.connect_share(profile.share.trim())
			.await
			.with_context(|| format!("connecting to share \"{}\" failed", profile.share.trim()))?;

		let base = profile.root_path.trim().trim_matches('/').to_string();
		if !base.is_empty() {
			let info = client
				.stat(&mut tree, &base)
				.await
				.with_context(|| format!("remote directory \"{base}\" not accessible"))?;
			if !info.is_directory {
				bail!("remote path \"{base}\" is not a directory");
			}
		}

		Ok(Self {
			inner: Mutex::new((client, tree)),
			base,
			uploads: Mutex::new(HashMap::new()),
			upload_seq: AtomicU64::new(0),
			known_dirs: Mutex::new(HashSet::new()),
		})
	}

	/// Share-relative path for one of our keys, forward slashes.
	fn full(&self, key: &str) -> String {
		let k = key.trim_end_matches('/');
		match (self.base.is_empty(), k.is_empty()) {
			(true, true) => String::new(),
			(true, false) => k.to_string(),
			(false, true) => self.base.clone(),
			(false, false) => format!("{}/{}", self.base, k),
		}
	}

	fn not_found(e: &smb2::Error) -> bool {
		e.kind() == ErrorKind::NotFound
	}

	fn epoch(t: FileTime) -> Option<i64> {
		if t.0 == 0 {
			None
		} else {
			Some((t.0 / 10_000_000) as i64 - 11_644_473_600)
		}
	}
}

#[async_trait]
impl StorageBackend for SmbBackend {
	async fn health_check(&self) -> Result<()> {
		let (client, tree) = &mut *self.inner.lock().await;
		client
			.fs_info(tree)
			.await
			.context("connection check failed")?;
		Ok(())
	}

	async fn list(&self, prefix: &str) -> Result<Vec<RawObject>> {
		let dir = self.full(prefix);
		let (client, tree) = &mut *self.inner.lock().await;
		let entries = client
			.list_directory(tree, &dir)
			.await
			.context("listing remote directory failed")?;
		let mut out = Vec::new();
		for e in entries {
			if e.name == "." || e.name == ".." {
				continue;
			}
			if e.is_directory {
				out.push(RawObject {
					key: format!("{prefix}{}/", e.name),
					size: 0,
					modified: Self::epoch(e.modified),
					is_prefix: true,
				});
			} else {
				out.push(RawObject {
					key: format!("{prefix}{}", e.name),
					size: e.size,
					modified: Self::epoch(e.modified),
					is_prefix: false,
				});
			}
		}
		Ok(out)
	}

	async fn list_recursive(&self, prefix: &str) -> Result<Vec<RawObject>> {
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
		let path = self.full(key);
		// Open under the lock; transfer outside it on the reader's own connection.
		let reader = {
			let (client, tree) = &mut *self.inner.lock().await;
			match client.open_file_reader(tree, &path).await {
				Ok(r) => r,
				Err(e) if Self::not_found(&e) => return Ok(None),
				Err(e) => return Err(anyhow!("SMB open failed: {e}")),
			}
		};
		let size = reader.size();
		let mut out = Vec::with_capacity(size as usize);
		let mut offset = 0u64;
		while offset < size {
			let len = STREAM_CHUNK.min(size - offset);
			let chunk = reader
				.read_at(offset, len)
				.await
				.context("SMB read failed")?;
			if chunk.is_empty() {
				break;
			}
			offset += chunk.len() as u64;
			out.extend_from_slice(&chunk);
		}
		reader.close().await.ok();
		Ok(Some(out))
	}

	async fn get_stream(&self, key: &str) -> Result<(u64, Reader)> {
		let path = self.full(key);
		let reader = {
			let (client, tree) = &mut *self.inner.lock().await;
			client
				.open_file_reader(tree, &path)
				.await
				.with_context(|| format!("download failed: {key}"))?
		};
		let len = reader.size();
		let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Vec<u8>>>(4);
		tokio::spawn(async move {
			let mut offset = 0u64;
			while offset < len {
				let want = STREAM_CHUNK.min(len - offset);
				match reader.read_at(offset, want).await {
					Ok(chunk) if chunk.is_empty() => break,
					Ok(chunk) => {
						offset += chunk.len() as u64;
						if tx.send(Ok(chunk)).await.is_err() {
							break; // reader side dropped
						}
					}
					Err(e) => {
						let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
						break;
					}
				}
			}
			reader.close().await.ok();
		});
		Ok((len, Box::pin(ChannelReader::new(rx))))
	}

	async fn put(&self, key: &str, data: Vec<u8>) -> Result<()> {
		let path = self.full(key);
		let mut writer = {
			let (client, tree) = &mut *self.inner.lock().await;
			client
				.create_file_writer(tree, &path)
				.await
				.with_context(|| format!("upload failed: {key}"))?
		};
		for chunk in data.chunks(WRITE_CHUNK) {
			writer
				.write_chunk(chunk)
				.await
				.context("SMB write failed")?;
		}
		writer.finish().await.context("SMB close failed")?;
		Ok(())
	}

	async fn prepare_parents(&self, key: &str) -> Result<()> {
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
			if self.known_dirs.lock().await.contains(&partial) {
				continue;
			}
			let full = self.full(&partial);
			{
				let mut guard = self.inner.lock().await;
				let (client, tree) = &mut *guard;
				match client.create_directory(tree, &full).await {
					Ok(()) => {}
					Err(e) if e.kind() == ErrorKind::AlreadyExists => {
						let info = client
							.stat(tree, &full)
							.await
							.with_context(|| format!("cannot create remote directory {partial}"))?;
						if !info.is_directory {
							bail!("remote path {partial} exists and is not a directory");
						}
					}
					Err(e) => return Err(anyhow!("cannot create remote directory {partial}: {e}")),
				}
			}
			self.known_dirs.lock().await.insert(partial.clone());
		}
		Ok(())
	}

	async fn create_multipart(&self, key: &str) -> Result<MultipartUpload> {
		let path = self.full(key);
		let writer = {
			let (client, tree) = &mut *self.inner.lock().await;
			client
				.create_file_writer(tree, &path)
				.await
				.with_context(|| format!("upload failed: {key}"))?
		};
		let id = format!("smb-{}", self.upload_seq.fetch_add(1, Ordering::Relaxed));
		self.uploads.lock().await.insert(id.clone(), writer);
		Ok(MultipartUpload {
			upload_id: id,
			key: key.to_string(),
		})
	}

	async fn upload_part(
		&self,
		mp: &MultipartUpload,
		_part_number: i32,
		data: Vec<u8>,
	) -> Result<String> {
		let mut writer = self
			.uploads
			.lock()
			.await
			.remove(&mp.upload_id)
			.ok_or_else(|| anyhow!("unknown upload id"))?;
		let mut result = Ok(());
		for chunk in data.chunks(WRITE_CHUNK) {
			if let Err(e) = writer.write_chunk(chunk).await {
				result = Err(anyhow!("SMB write failed: {e}"));
				break;
			}
		}
		match result {
			Ok(()) => {
				self
					.uploads
					.lock()
					.await
					.insert(mp.upload_id.clone(), writer);
				Ok(String::new())
			}
			Err(e) => Err(e),
		}
	}

	async fn complete_multipart(
		&self,
		mp: &MultipartUpload,
		_etags: Vec<(i32, String)>,
	) -> Result<()> {
		if let Some(writer) = self.uploads.lock().await.remove(&mp.upload_id) {
			writer.finish().await.context("SMB close failed")?;
		}
		Ok(())
	}

	async fn abort_multipart(&self, mp: &MultipartUpload) -> Result<()> {
		if self.uploads.lock().await.remove(&mp.upload_id).is_some() {
			let path = self.full(&mp.key);
			let (client, tree) = &mut *self.inner.lock().await;
			match client.delete_file(tree, &path).await {
				Ok(()) => {}
				Err(e) if Self::not_found(&e) => {}
				Err(e) => return Err(anyhow!("SMB delete failed: {e}")),
			}
		}
		Ok(())
	}

	async fn delete(&self, keys: Vec<String>) -> Result<()> {
		for key in keys {
			if key.ends_with('/') {
				// delete_directory only removes empty directories, so walk the
				// tree, delete files as encountered, then remove directories
				// deepest-first.
				let mut dirs = vec![key.clone()];
				let mut order = Vec::new();
				while let Some(d) = dirs.pop() {
					order.push(d.clone());
					for obj in self.list(&d).await? {
						if obj.is_prefix {
							dirs.push(obj.key);
						} else {
							let path = self.full(&obj.key);
							let (client, tree) = &mut *self.inner.lock().await;
							match client.delete_file(tree, &path).await {
								Ok(()) => {}
								Err(e) if Self::not_found(&e) => {}
								Err(e) => return Err(anyhow!("SMB delete failed: {e}")),
							}
						}
					}
				}
				for d in order.into_iter().rev() {
					let path = self.full(&d);
					{
						let mut guard = self.inner.lock().await;
						let (client, tree) = &mut *guard;
						match client.delete_directory(tree, &path).await {
							Ok(()) => {}
							Err(e) if Self::not_found(&e) => {}
							Err(e) => return Err(anyhow!("SMB rmdir failed: {e}")),
						}
					}
					self.known_dirs.lock().await.remove(d.trim_matches('/'));
				}
			} else {
				let path = self.full(&key);
				let (client, tree) = &mut *self.inner.lock().await;
				match client.delete_file(tree, &path).await {
					Ok(()) => {}
					Err(e) if Self::not_found(&e) => {}
					Err(e) => return Err(anyhow!("SMB delete failed: {e}")),
				}
			}
		}
		Ok(())
	}

	async fn get_range(&self, key: &str, offset: u64) -> Result<(u64, Reader)> {
		let path = self.full(key);
		let reader = {
			let (client, tree) = &mut *self.inner.lock().await;
			client
				.open_file_reader(tree, &path)
				.await
				.with_context(|| format!("download failed: {key}"))?
		};
		let len = reader.size();
		let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Vec<u8>>>(4);
		tokio::spawn(async move {
			let mut off = offset.min(len);
			while off < len {
				let want = STREAM_CHUNK.min(len - off);
				match reader.read_at(off, want).await {
					Ok(chunk) if chunk.is_empty() => break,
					Ok(chunk) => {
						off += chunk.len() as u64;
						if tx.send(Ok(chunk)).await.is_err() {
							break;
						}
					}
					Err(e) => {
						let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
						break;
					}
				}
			}
			reader.close().await.ok();
		});
		Ok((len, Box::pin(ChannelReader::new(rx))))
	}
}
