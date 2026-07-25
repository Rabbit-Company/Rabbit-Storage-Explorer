//! NFSv3 backend (pure Rust, `nfs3_client`). Speaks the MOUNT and NFS RPC
//! programs directly over TCP with AUTH_UNIX credentials - no kernel mount
//! and no root privileges required.

use super::{ChannelReader, MultipartUpload, RawObject, Reader, StorageBackend};
use crate::settings::ConnectionProfile;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use nfs3_client::nfs3_types::nfs3::{
	createhow3, diropargs3, fattr3, filename3, ftype3, nfs_fh3, nfsstat3, sattr3, stable_how,
};
use nfs3_client::nfs3_types::nfs3::{
	COMMIT3args, CREATE3args, GETATTR3args, LOOKUP3args, MKDIR3args, Nfs3Option, Nfs3Result,
	READ3args, READDIRPLUS3args, REMOVE3args, RMDIR3args, SETATTR3args, WRITE3args,
};
use nfs3_client::nfs3_types::rpc::{auth_unix, opaque_auth};
use nfs3_client::nfs3_types::xdr_codec::Opaque;
use nfs3_client::tokio::{TokioConnector, TokioIo};
use nfs3_client::{Nfs3Connection, Nfs3ConnectionBuilder};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

type Conn = Nfs3Connection<TokioIo<TcpStream>>;

const READ_CHUNK: u32 = 256 * 1024;
const WRITE_CHUNK: usize = 256 * 1024;

pub struct NfsBackend {
	conn: std::sync::Arc<Mutex<Conn>>,
	root: nfs_fh3,
	/// Resolved directory handles: relative dir path ("" = root) -> handle.
	dir_cache: Mutex<HashMap<String, nfs_fh3>>,
	/// In-flight appends: upload id -> (file handle, next offset, key).
	uploads: Mutex<HashMap<String, (nfs_fh3, u64, String)>>,
	upload_seq: AtomicU64,
}

impl NfsBackend {
	pub async fn connect(profile: &ConnectionProfile) -> Result<Self> {
		let export = profile.root_path.trim();
		if export.is_empty() {
			bail!("an NFS export path is required (e.g. /srv/nfs/share)");
		}
		let auth = auth_unix {
			stamp: 0,
			machinename: Opaque::owned(b"rabbit-storage-explorer".to_vec()),
			uid: profile.nfs_uid,
			gid: profile.nfs_gid,
			gids: Vec::new(),
		};
		let mut builder = Nfs3ConnectionBuilder::new(TokioConnector, profile.host.clone(), export)
			.connect_from_privileged_port(profile.nfs_privileged_port)
			.credential(opaque_auth::auth_unix(&auth));
		if profile.port != 0 {
			builder = builder.nfs3_port(profile.port);
		}
		let conn = tokio::time::timeout(std::time::Duration::from_secs(20), builder.mount())
			.await
			.map_err(|_| anyhow!("NFS mount timed out"))?
			.with_context(|| format!("mounting {}:{export} failed", profile.host))?;
		let root = conn.root_nfs_fh3();
		Ok(Self {
			conn: std::sync::Arc::new(Mutex::new(conn)),
			root,
			dir_cache: Mutex::new(HashMap::new()),
			uploads: Mutex::new(HashMap::new()),
			upload_seq: AtomicU64::new(0),
		})
	}

	fn name<'a>(s: &'a str) -> filename3<'a> {
		filename3(Opaque::borrowed(s.as_bytes()))
	}

	/// LOOKUP one name in a directory. `Ok(None)` when it does not exist.
	async fn lookup(
		conn: &mut Conn,
		dir: &nfs_fh3,
		name: &str,
	) -> Result<Option<(nfs_fh3, Option<fattr3>)>> {
		let res = conn
			.nfs3_client
			.lookup(&LOOKUP3args {
				what: diropargs3 {
					dir: dir.clone(),
					name: Self::name(name),
				},
			})
			.await
			.context("NFS lookup failed")?;
		match res {
			Nfs3Result::Ok(ok) => {
				let attrs = match ok.obj_attributes {
					Nfs3Option::Some(a) => Some(a),
					Nfs3Option::None => None,
				};
				Ok(Some((ok.object, attrs)))
			}
			Nfs3Result::Err((nfsstat3::NFS3ERR_NOENT, _)) => Ok(None),
			Nfs3Result::Err((stat, _)) => Err(anyhow!("NFS lookup error: {stat:?}")),
		}
	}

	/// Resolve a relative directory path to a handle, via the cache.
	async fn resolve_dir(&self, path: &str) -> Result<nfs_fh3> {
		let path = path.trim_matches('/');
		if path.is_empty() {
			return Ok(self.root.clone());
		}
		if let Some(fh) = self.dir_cache.lock().await.get(path) {
			return Ok(fh.clone());
		}
		let mut conn = self.conn.lock().await;
		let mut fh = self.root.clone();
		let mut walked = String::new();
		for seg in path.split('/') {
			if !walked.is_empty() {
				walked.push('/');
			}
			walked.push_str(seg);
			fh = match Self::lookup(&mut conn, &fh, seg).await? {
				Some((fh, _)) => fh,
				None => bail!("remote directory {walked} not found"),
			};
			self
				.dir_cache
				.lock()
				.await
				.insert(walked.clone(), fh.clone());
		}
		Ok(fh)
	}

	/// Split a key into its parent directory handle and final name.
	async fn resolve_parent<'k>(&self, key: &'k str) -> Result<(nfs_fh3, &'k str)> {
		let key = key.trim_end_matches('/');
		match key.rsplit_once('/') {
			Some((dir, name)) => Ok((self.resolve_dir(dir).await?, name)),
			None => Ok((self.root.clone(), key)),
		}
	}

	/// Look up a file's handle and size; `Ok(None)` when missing.
	async fn file_handle(&self, key: &str) -> Result<Option<(nfs_fh3, u64)>> {
		let (dir, name) = self.resolve_parent(key).await?;
		let mut conn = self.conn.lock().await;
		match Self::lookup(&mut conn, &dir, name).await? {
			Some((fh, attrs)) => {
				let size = attrs.map(|a| a.size).unwrap_or(0);
				Ok(Some((fh, size)))
			}
			None => Ok(None),
		}
	}

	/// Open (create or truncate) a file for writing; returns its handle.
	async fn create_truncated(&self, key: &str) -> Result<nfs_fh3> {
		let (dir, name) = self.resolve_parent(key).await?;
		let mut conn = self.conn.lock().await;
		if let Some((fh, _)) = Self::lookup(&mut conn, &dir, name).await? {
			// Existing file: truncate to zero.
			let res = conn
				.nfs3_client
				.setattr(&SETATTR3args {
					object: fh.clone(),
					new_attributes: sattr3 {
						size: Nfs3Option::Some(0),
						..Default::default()
					},
					guard: Nfs3Option::None,
				})
				.await
				.context("NFS truncate failed")?;
			if let Nfs3Result::Err((stat, _)) = res {
				bail!("NFS truncate error: {stat:?}");
			}
			return Ok(fh);
		}
		let res = conn
			.nfs3_client
			.create(&CREATE3args {
				where_: diropargs3 {
					dir: dir.clone(),
					name: Self::name(name),
				},
				how: createhow3::UNCHECKED(sattr3::default()),
			})
			.await
			.context("NFS create failed")?;
		if let Nfs3Result::Err((stat, _)) = res {
			bail!("NFS create error: {stat:?}");
		}
		// Not all servers return the new handle in CREATE; a LOOKUP always works.
		match Self::lookup(&mut conn, &dir, name).await? {
			Some((fh, _)) => Ok(fh),
			None => bail!("NFS create succeeded but file not found"),
		}
	}

	/// Write a buffer at an offset, honouring short writes. UNSTABLE writes;
	/// callers COMMIT when the file is complete.
	async fn write_at(&self, fh: &nfs_fh3, mut offset: u64, data: &[u8]) -> Result<u64> {
		for chunk in data.chunks(WRITE_CHUNK) {
			let mut written = 0usize;
			while written < chunk.len() {
				let part = &chunk[written..];
				let mut conn = self.conn.lock().await;
				let res = conn
					.nfs3_client
					.write(&WRITE3args {
						file: fh.clone(),
						offset,
						count: part.len() as u32,
						stable: stable_how::UNSTABLE,
						data: Opaque::borrowed(part),
					})
					.await
					.context("NFS write failed")?;
				match res {
					Nfs3Result::Ok(ok) => {
						if ok.count == 0 {
							bail!("NFS server accepted zero bytes");
						}
						written += ok.count as usize;
						offset += u64::from(ok.count);
					}
					Nfs3Result::Err((stat, _)) => bail!("NFS write error: {stat:?}"),
				}
			}
		}
		Ok(offset)
	}

	async fn commit(&self, fh: &nfs_fh3) -> Result<()> {
		let mut conn = self.conn.lock().await;
		let res = conn
			.nfs3_client
			.commit(&COMMIT3args {
				file: fh.clone(),
				offset: 0,
				count: 0,
			})
			.await
			.context("NFS commit failed")?;
		if let Nfs3Result::Err((stat, _)) = res {
			bail!("NFS commit error: {stat:?}");
		}
		Ok(())
	}

	async fn remove_entry(&self, dir: &nfs_fh3, name: &str, is_dir: bool) -> Result<()> {
		let mut conn = self.conn.lock().await;
		let args = diropargs3 {
			dir: dir.clone(),
			name: Self::name(name),
		};
		let stat = if is_dir {
			match conn
				.nfs3_client
				.rmdir(&RMDIR3args { object: args })
				.await
				.context("NFS rmdir failed")?
			{
				Nfs3Result::Ok(_) => return Ok(()),
				Nfs3Result::Err((s, _)) => s,
			}
		} else {
			match conn
				.nfs3_client
				.remove(&REMOVE3args { object: args })
				.await
				.context("NFS remove failed")?
			{
				Nfs3Result::Ok(_) => return Ok(()),
				Nfs3Result::Err((s, _)) => s,
			}
		};
		if stat == nfsstat3::NFS3ERR_NOENT {
			Ok(()) // already gone
		} else {
			Err(anyhow!("NFS delete error: {stat:?}"))
		}
	}

	async fn list_dir(&self, prefix: &str) -> Result<Vec<RawObject>> {
		let dir = self.resolve_dir(prefix).await?;
		let mut out = Vec::new();
		let mut cookie = 0u64;
		let mut cookieverf = nfs3_client::nfs3_types::nfs3::cookieverf3::default();
		loop {
			let mut conn = self.conn.lock().await;
			let res = conn
				.nfs3_client
				.readdirplus(&READDIRPLUS3args {
					dir: dir.clone(),
					cookie,
					cookieverf,
					dircount: 65536,
					maxcount: 1 << 20,
				})
				.await
				.context("listing remote directory failed")?;
			let ok = match res {
				Nfs3Result::Ok(ok) => ok,
				Nfs3Result::Err((stat, _)) => bail!("NFS readdir error: {stat:?}"),
			};
			cookieverf = ok.cookieverf;
			let entries = ok.reply.entries.0;
			if entries.is_empty() {
				break;
			}
			for e in &entries {
				cookie = e.cookie;
				let name = String::from_utf8_lossy(e.name.0.as_ref()).into_owned();
				if name == "." || name == ".." {
					continue;
				}
				let attrs = match &e.name_attributes {
					Nfs3Option::Some(a) => Some(a),
					Nfs3Option::None => None,
				};
				let is_dir = attrs.map(|a| a.type_ == ftype3::NF3DIR).unwrap_or(false);
				if is_dir {
					out.push(RawObject {
						key: format!("{prefix}{name}/"),
						size: 0,
						modified: attrs.map(|a| i64::from(a.mtime.seconds)),
						is_prefix: true,
					});
				} else {
					out.push(RawObject {
						key: format!("{prefix}{name}"),
						size: attrs.map(|a| a.size).unwrap_or(0),
						modified: attrs.map(|a| i64::from(a.mtime.seconds)),
						is_prefix: false,
					});
				}
			}
			if ok.reply.eof {
				break;
			}
		}
		Ok(out)
	}
}

#[async_trait]
impl StorageBackend for NfsBackend {
	async fn health_check(&self) -> Result<()> {
		let mut conn = self.conn.lock().await;
		let res = conn
			.nfs3_client
			.getattr(&GETATTR3args {
				object: self.root.clone(),
			})
			.await
			.context("connection check failed")?;
		if let Nfs3Result::Err((stat, _)) = res {
			bail!("NFS getattr error: {stat:?}");
		}
		Ok(())
	}

	async fn list(&self, prefix: &str) -> Result<Vec<RawObject>> {
		self.list_dir(prefix).await
	}

	async fn list_recursive(&self, prefix: &str) -> Result<Vec<RawObject>> {
		let mut files = Vec::new();
		let mut queue = vec![prefix.to_string()];
		while let Some(p) = queue.pop() {
			for obj in self.list_dir(&p).await? {
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
		let Some((fh, size)) = self.file_handle(key).await? else {
			return Ok(None);
		};
		let mut out = Vec::with_capacity(size as usize);
		let mut offset = 0u64;
		loop {
			let mut conn = self.conn.lock().await;
			let res = conn
				.nfs3_client
				.read(&READ3args {
					file: fh.clone(),
					offset,
					count: READ_CHUNK,
				})
				.await
				.context("NFS read failed")?;
			match res {
				Nfs3Result::Ok(ok) => {
					offset += ok.count as u64;
					out.extend_from_slice(ok.data.as_ref());
					if ok.eof {
						break;
					}
				}
				Nfs3Result::Err((stat, _)) => bail!("NFS read error: {stat:?}"),
			}
		}
		Ok(Some(out))
	}

	async fn get_stream(&self, key: &str) -> Result<(u64, Reader)> {
		let Some((fh, size)) = self.file_handle(key).await? else {
			bail!("download failed: {key} not found");
		};
		let (tx, rx) = tokio::sync::mpsc::channel::<std::io::Result<Vec<u8>>>(4);
		let conn_arc = self.conn.clone();
		tokio::spawn(async move {
			let mut offset = 0u64;
			loop {
				let chunk = {
					let mut conn = conn_arc.lock().await;
					conn
						.nfs3_client
						.read(&READ3args {
							file: fh.clone(),
							offset,
							count: READ_CHUNK,
						})
						.await
				};
				let result = match chunk {
					Ok(Nfs3Result::Ok(ok)) => {
						offset += ok.count as u64;
						let eof = ok.eof;
						let data = ok.data.to_vec();
						if tx.send(Ok(data)).await.is_err() {
							return; // reader dropped
						}
						if eof {
							return;
						}
						continue;
					}
					Ok(Nfs3Result::Err((stat, _))) => {
						Err(std::io::Error::other(format!("NFS read error: {stat:?}")))
					}
					Err(e) => Err(std::io::Error::other(format!("NFS read failed: {e}"))),
				};
				let _ = tx.send(result).await;
				return;
			}
		});
		Ok((size, Box::pin(ChannelReader::new(rx))))
	}

	async fn put(&self, key: &str, data: Vec<u8>) -> Result<()> {
		let fh = self.create_truncated(key).await?;
		self.write_at(&fh, 0, &data).await?;
		self.commit(&fh).await
	}

	async fn prepare_parents(&self, key: &str) -> Result<()> {
		let segments: Vec<&str> = key.trim_end_matches('/').split('/').collect();
		if segments.len() <= 1 {
			return Ok(());
		}
		let mut fh = self.root.clone();
		let mut walked = String::new();
		for seg in &segments[..segments.len() - 1] {
			if !walked.is_empty() {
				walked.push('/');
			}
			walked.push_str(seg);
			if let Some(cached) = self.dir_cache.lock().await.get(&walked) {
				fh = cached.clone();
				continue;
			}
			let mut conn = self.conn.lock().await;
			fh = match Self::lookup(&mut conn, &fh, seg).await? {
				Some((existing, _)) => existing,
				None => {
					let res = conn
						.nfs3_client
						.mkdir(&MKDIR3args {
							where_: diropargs3 {
								dir: fh.clone(),
								name: Self::name(seg),
							},
							attributes: sattr3::default(),
						})
						.await
						.context("NFS mkdir failed")?;
					match res {
						Nfs3Result::Ok(_) | Nfs3Result::Err((nfsstat3::NFS3ERR_EXIST, _)) => {}
						Nfs3Result::Err((stat, _)) => bail!("NFS mkdir error: {stat:?}"),
					}
					match Self::lookup(&mut conn, &fh, seg).await? {
						Some((new_fh, _)) => new_fh,
						None => bail!("cannot create remote directory {walked}"),
					}
				}
			};
			drop(conn);
			self
				.dir_cache
				.lock()
				.await
				.insert(walked.clone(), fh.clone());
		}
		Ok(())
	}

	async fn create_multipart(&self, key: &str) -> Result<MultipartUpload> {
		let fh = self.create_truncated(key).await?;
		let id = format!("nfs-{}", self.upload_seq.fetch_add(1, Ordering::Relaxed));
		self
			.uploads
			.lock()
			.await
			.insert(id.clone(), (fh, 0, key.to_string()));
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
		let (fh, offset, key) = self
			.uploads
			.lock()
			.await
			.remove(&mp.upload_id)
			.ok_or_else(|| anyhow!("unknown upload id"))?;
		let result = self.write_at(&fh, offset, &data).await;
		match result {
			Ok(new_offset) => {
				self
					.uploads
					.lock()
					.await
					.insert(mp.upload_id.clone(), (fh, new_offset, key));
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
		if let Some((fh, _, _)) = self.uploads.lock().await.remove(&mp.upload_id) {
			self.commit(&fh).await?;
		}
		Ok(())
	}

	async fn abort_multipart(&self, mp: &MultipartUpload) -> Result<()> {
		if self.uploads.lock().await.remove(&mp.upload_id).is_some() {
			let (dir, name) = self.resolve_parent(&mp.key).await?;
			let _ = self.remove_entry(&dir, name, false).await;
		}
		Ok(())
	}

	async fn delete(&self, keys: Vec<String>) -> Result<()> {
		for key in keys {
			if key.ends_with('/') {
				// Depth-first: collect the directory tree, delete files as we
				// walk, then remove directories deepest-first.
				let mut dirs = vec![key.clone()];
				let mut order = Vec::new();
				while let Some(d) = dirs.pop() {
					order.push(d.clone());
					for obj in self.list_dir(&d).await? {
						if obj.is_prefix {
							dirs.push(obj.key);
						} else {
							let (dirfh, name) = self.resolve_parent(&obj.key).await?;
							self.remove_entry(&dirfh, name, false).await?;
						}
					}
				}
				for d in order.into_iter().rev() {
					let (dirfh, name) = self.resolve_parent(&d).await?;
					self.remove_entry(&dirfh, name, true).await?;
					self.dir_cache.lock().await.remove(d.trim_matches('/'));
				}
			} else {
				let (dir, name) = self.resolve_parent(&key).await?;
				self.remove_entry(&dir, name, false).await?;
			}
		}
		Ok(())
	}
}
