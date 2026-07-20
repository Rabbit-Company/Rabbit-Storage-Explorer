//! Storage abstraction. S3-compatible object stores and SFTP today; the trait
//! that SFTP, WebDAV, GCS... backends can be added without touching the UI or
//! the transfer engine.

pub mod nfs;
pub mod s3;
pub mod sftp;
pub mod smb;

use anyhow::Result;
use async_trait::async_trait;

/// A boxed async byte stream, backend-neutral (S3 body, SFTP file handle...).
pub type Reader = std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>;

/// Adapts an mpsc channel of chunks into an `AsyncRead`. Lets backends whose
/// native reads are pull-based RPC (NFS) or blocking FFI (SMB) stream files
/// through a pump task while still reporting mid-stream errors - an error
/// arriving on the channel surfaces as a read error instead of a silent EOF.
pub struct ChannelReader {
	rx: tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>,
	buf: Vec<u8>,
	pos: usize,
}

impl ChannelReader {
	pub fn new(rx: tokio::sync::mpsc::Receiver<std::io::Result<Vec<u8>>>) -> Self {
		Self {
			rx,
			buf: Vec::new(),
			pos: 0,
		}
	}
}

impl tokio::io::AsyncRead for ChannelReader {
	fn poll_read(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		out: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		use std::task::Poll;
		loop {
			if self.pos < self.buf.len() {
				let n = (self.buf.len() - self.pos).min(out.remaining());
				let pos = self.pos;
				out.put_slice(&self.buf[pos..pos + n]);
				self.pos += n;
				return Poll::Ready(Ok(()));
			}
			match self.rx.poll_recv(cx) {
				Poll::Ready(Some(Ok(chunk))) => {
					self.buf = chunk;
					self.pos = 0;
				}
				Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
				Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
				Poll::Pending => return Poll::Pending,
			}
		}
	}
}

/// A raw listing entry as the backend sees it (keys may be encrypted).
#[derive(Clone, Debug)]
pub struct RawObject {
	pub key: String,
	pub size: u64,
	/// Unix epoch seconds.
	pub modified: Option<i64>,
	/// True for a common prefix ("folder").
	pub is_prefix: bool,
}

/// An entry as shown in the UI: `key` is the real remote key/prefix,
/// `name` is the (decrypted) display name.
#[derive(Clone, Debug)]
pub struct RemoteEntry {
	pub key: String,
	pub name: String,
	pub is_dir: bool,
	pub size: u64,
	pub modified: Option<i64>,
	/// `Some(true)` = E2EE-encrypted, `Some(false)` = foreign/unencrypted item
	/// in an encrypted session, `None` = session without E2EE.
	pub encrypted: Option<bool>,
}

pub struct MultipartUpload {
	pub upload_id: String,
	pub key: String,
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
	/// Cheap connectivity probe, used to decide whether a reconnect is needed.
	async fn health_check(&self) -> Result<()>;

	/// Shallow listing of one "directory" level.
	async fn list(&self, prefix: &str) -> Result<Vec<RawObject>>;
	/// Recursive listing of every object under a prefix.
	async fn list_recursive(&self, prefix: &str) -> Result<Vec<RawObject>>;

	/// Fetch a whole (small) object. `Ok(None)` if the key does not exist.
	async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
	/// Open an object for streaming: returns (content_length, reader).
	async fn get_stream(&self, key: &str) -> Result<(u64, Reader)>;

	/// Upload a whole (small) object.
	async fn put(&self, key: &str, data: Vec<u8>) -> Result<()>;

	/// Fetch the E2EE vault metadata for this connection.
	///
	/// Default: the `.rse-vault` object at the session root. That is correct
	/// for backends whose root *is* the storage unit (S3 bucket, NFS export,
	/// SMB directory). SFTP overrides this: its root is just a movable browse
	/// path inside a per-account namespace, so the vault is anchored to the
	/// account (home directory) instead.
	async fn get_vault(&self) -> Result<Option<Vec<u8>>> {
		self.get(crate::crypto::VAULT_KEY).await
	}

	/// Store the E2EE vault metadata. See [`StorageBackend::get_vault`].
	async fn put_vault(&self, data: Vec<u8>) -> Result<()> {
		self.put(crate::crypto::VAULT_KEY, data).await
	}

	/// Ensure parent "directories" of `key` exist. No-op for object stores;
	/// SFTP creates the directory chain.
	async fn prepare_parents(&self, _key: &str) -> Result<()> {
		Ok(())
	}

	async fn create_multipart(&self, key: &str) -> Result<MultipartUpload>;
	/// Returns the part's ETag.
	async fn upload_part(
		&self,
		mp: &MultipartUpload,
		part_number: i32,
		data: Vec<u8>,
	) -> Result<String>;
	async fn complete_multipart(&self, mp: &MultipartUpload, etags: Vec<(i32, String)>)
		-> Result<()>;
	async fn abort_multipart(&self, mp: &MultipartUpload) -> Result<()>;

	/// Delete up to 1000 keys per call is handled internally; any number accepted.
	async fn delete(&self, keys: Vec<String>) -> Result<()>;

	/// Move/rename one object or an entire subtree (a trailing `/` on both
	/// `from` and `to` denotes a directory). Real keys, not display names.
	///
	/// Default: server-agnostic copy-then-delete. Backends with a native,
	/// server-side rename should override this for an instant move.
	async fn rename(&self, from: &str, to: &str) -> Result<()> {
		if from.ends_with('/') {
			// Make sure the destination directory exists even if it's empty.
			self.prepare_parents(&format!("{to}x")).await?;
			for o in self.list_recursive(from).await? {
				let suffix = o.key.strip_prefix(from).unwrap_or(&o.key);
				let new_key = format!("{to}{suffix}");
				if let Some(data) = self.get(&o.key).await? {
					self.prepare_parents(&new_key).await?;
					self.put(&new_key, data).await?;
				}
			}
		} else if let Some(data) = self.get(from).await? {
			self.prepare_parents(to).await?;
			self.put(to, data).await?;
		}
		// Remove the source. For a trailing-slash key the filesystem backends'
		// `delete` walks and removes the whole subtree (including now-empty dirs).
		self.delete(vec![from.to_string()]).await?;
		Ok(())
	}
}
