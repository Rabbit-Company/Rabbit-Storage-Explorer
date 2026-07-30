//! S3-compatible backend: AWS S3, MinIO, and other S3-compatible object stores.

use crate::storage::ProgressSink;

use super::{MultipartUpload, RawObject, Reader, StorageBackend};
use crate::ratelimit::RateLimiter;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use aws_config::timeout::TimeoutConfig;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, Delete, ObjectIdentifier};
use aws_sdk_s3::Client;
use aws_smithy_types::body::SdkBody;
use aws_smithy_types::byte_stream::ByteStream;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

pub struct S3Backend {
	client: Client,
	bucket: String,
}

struct PacedBody {
	rx: tokio::sync::mpsc::Receiver<Bytes>,
	remaining: u64,
}

impl PacedBody {
	fn new(data: Bytes, limiter: Arc<RateLimiter>) -> Self {
		let total = data.len() as u64;
		let (tx, rx) = tokio::sync::mpsc::channel(4);
		tokio::spawn(async move {
			const CHUNK: usize = 64 * 1024;
			let mut off = 0usize;
			while off < data.len() {
				let end = (off + CHUNK).min(data.len());
				limiter.acquire((end - off) as u64).await;
				if tx.send(data.slice(off..end)).await.is_err() {
					break; // body dropped (upload cancelled/aborted)
				}
				off = end;
			}
		});
		Self {
			rx,
			remaining: total,
		}
	}
}

impl Body for PacedBody {
	type Data = Bytes;
	type Error = std::convert::Infallible;

	fn poll_frame(
		self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
		let this = self.get_mut();
		match this.rx.poll_recv(cx) {
			Poll::Ready(Some(chunk)) => {
				this.remaining = this.remaining.saturating_sub(chunk.len() as u64);
				Poll::Ready(Some(Ok(Frame::data(chunk))))
			}
			Poll::Ready(None) => Poll::Ready(None),
			Poll::Pending => Poll::Pending,
		}
	}

	fn is_end_stream(&self) -> bool {
		self.remaining == 0
	}

	fn size_hint(&self) -> SizeHint {
		SizeHint::with_exact(self.remaining)
	}
}

fn throttled_bytestream(data: Vec<u8>, limiter: Option<Arc<RateLimiter>>) -> ByteStream {
	match limiter {
		Some(l) if !l.is_unlimited() => {
			let data = Bytes::from(data);
			ByteStream::new(SdkBody::retryable(move || {
				SdkBody::from_body_1_x(PacedBody::new(data.clone(), l.clone()))
			}))
		}
		_ => ByteStream::from(data),
	}
}

/// AWS requires the CopyObject source (`bucket/key`) to be URL-encoded.
fn encode_copy_source(bucket: &str, key: &str) -> String {
	let mut out = String::with_capacity(bucket.len() + 1 + key.len());
	out.push_str(bucket);
	out.push('/');
	for b in key.bytes() {
		match b {
			b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
				out.push(b as char)
			}
			_ => out.push_str(&format!("%{b:02X}")),
		}
	}
	out
}

impl S3Backend {
	pub async fn connect(
		endpoint: &str,
		access_key: &str,
		secret_key: &str,
		bucket: &str,
	) -> Result<Self> {
		let creds = Credentials::new(
			access_key,
			secret_key,
			None,
			None,
			"rabbit-storage-explorer",
		);
		let base = aws_config::defaults(BehaviorVersion::latest())
			.region(Region::new("auto")) // accepted by most S3-compatible providers
			.credentials_provider(creds)
			.endpoint_url(endpoint)
			// Fail fast on a dead network instead of hanging; no overall
			// operation timeout so long transfers are unaffected.
			.timeout_config(
				TimeoutConfig::builder()
					.connect_timeout(std::time::Duration::from_secs(15))
					.build(),
			)
			.load()
			.await;
		let conf = aws_sdk_s3::config::Builder::from(&base)
			.force_path_style(true) // safest default across S3-compatible providers
			.build();
		let client = Client::from_conf(conf);

		client
			.head_bucket()
			.bucket(bucket)
			.send()
			.await
			.with_context(|| {
				format!("cannot access bucket \"{bucket}\" - check endpoint, credentials and bucket name")
			})?;

		Ok(Self {
			client,
			bucket: bucket.to_string(),
		})
	}

	async fn list_inner(&self, prefix: &str, delimited: bool) -> Result<Vec<RawObject>> {
		let mut out = Vec::new();
		let mut token: Option<String> = None;
		loop {
			let mut req = self
				.client
				.list_objects_v2()
				.bucket(&self.bucket)
				.prefix(prefix);
			if delimited {
				req = req.delimiter("/");
			}
			if let Some(t) = &token {
				req = req.continuation_token(t);
			}
			let resp = req.send().await.context("listing objects failed")?;

			for cp in resp.common_prefixes() {
				if let Some(p) = cp.prefix() {
					out.push(RawObject {
						key: p.to_string(),
						size: 0,
						modified: None,
						is_prefix: true,
					});
				}
			}
			for obj in resp.contents() {
				let Some(key) = obj.key() else { continue };
				// The delimited listing includes the prefix "marker" object itself
				// when folders were created explicitly; skip it.
				if key == prefix {
					continue;
				}
				out.push(RawObject {
					key: key.to_string(),
					size: obj.size().unwrap_or(0).max(0) as u64,
					modified: obj.last_modified().map(|d| d.secs()),
					is_prefix: false,
				});
			}

			if resp.is_truncated() == Some(true) {
				token = resp.next_continuation_token().map(str::to_string);
				if token.is_none() {
					break;
				}
			} else {
				break;
			}
		}
		Ok(out)
	}

	async fn copy_one(&self, from: &str, to: &str) -> Result<()> {
		self
			.client
			.copy_object()
			.bucket(&self.bucket)
			.copy_source(encode_copy_source(&self.bucket, from))
			.key(to)
			.send()
			.await
			.with_context(|| format!("copy failed: {from} -> {to}"))?;
		Ok(())
	}
}

#[async_trait]
impl StorageBackend for S3Backend {
	async fn health_check(&self) -> Result<()> {
		self
			.client
			.head_bucket()
			.bucket(&self.bucket)
			.send()
			.await?;
		Ok(())
	}

	async fn list(&self, prefix: &str) -> Result<Vec<RawObject>> {
		self.list_inner(prefix, true).await
	}

	async fn list_recursive(&self, prefix: &str) -> Result<Vec<RawObject>> {
		self.list_inner(prefix, false).await
	}

	async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
		match self
			.client
			.get_object()
			.bucket(&self.bucket)
			.key(key)
			.send()
			.await
		{
			Ok(out) => {
				let data = out.body.collect().await.context("reading object body")?;
				Ok(Some(data.into_bytes().to_vec()))
			}
			Err(err) => {
				let service = err.into_service_error();
				if service.is_no_such_key() {
					Ok(None)
				} else {
					Err(anyhow!("get failed: {service}"))
				}
			}
		}
	}

	async fn get_stream(&self, key: &str) -> Result<(u64, Reader)> {
		let out = self
			.client
			.get_object()
			.bucket(&self.bucket)
			.key(key)
			.send()
			.await
			.with_context(|| format!("download failed: {key}"))?;
		let len = out.content_length().unwrap_or(0).max(0) as u64;
		Ok((len, Box::pin(out.body.into_async_read())))
	}

	async fn put(&self, key: &str, data: Vec<u8>) -> Result<()> {
		self
			.client
			.put_object()
			.bucket(&self.bucket)
			.key(key)
			.body(ByteStream::from(data))
			.send()
			.await
			.with_context(|| format!("upload failed: {key}"))?;
		Ok(())
	}

	async fn put_throttled(
		&self,
		key: &str,
		data: Vec<u8>,
		limiter: Option<Arc<RateLimiter>>,
	) -> Result<()> {
		self
			.client
			.put_object()
			.bucket(&self.bucket)
			.key(key)
			.body(throttled_bytestream(data, limiter))
			.send()
			.await
			.with_context(|| format!("upload failed: {key}"))?;
		Ok(())
	}

	async fn create_multipart(&self, key: &str) -> Result<MultipartUpload> {
		let out = self
			.client
			.create_multipart_upload()
			.bucket(&self.bucket)
			.key(key)
			.send()
			.await
			.context("starting multipart upload")?;
		Ok(MultipartUpload {
			upload_id: out
				.upload_id()
				.ok_or_else(|| anyhow!("no upload id"))?
				.to_string(),
			key: key.to_string(),
		})
	}

	async fn upload_part(
		&self,
		mp: &MultipartUpload,
		part_number: i32,
		data: Vec<u8>,
		on_bytes: Option<ProgressSink>,
		limiter: Option<Arc<RateLimiter>>,
	) -> Result<String> {
		let len = data.len() as u64;
		let out = self
			.client
			.upload_part()
			.bucket(&self.bucket)
			.key(&mp.key)
			.upload_id(&mp.upload_id)
			.part_number(part_number)
			.body(throttled_bytestream(data, limiter))
			.send()
			.await
			.with_context(|| format!("uploading part {part_number}"))?;

		if let Some(cb) = on_bytes {
			cb(len);
		}
		Ok(out.e_tag().unwrap_or_default().to_string())
	}

	async fn complete_multipart(
		&self,
		mp: &MultipartUpload,
		etags: Vec<(i32, String)>,
	) -> Result<()> {
		let parts: Vec<CompletedPart> = etags
			.into_iter()
			.map(|(n, tag)| CompletedPart::builder().part_number(n).e_tag(tag).build())
			.collect();
		self
			.client
			.complete_multipart_upload()
			.bucket(&self.bucket)
			.key(&mp.key)
			.upload_id(&mp.upload_id)
			.multipart_upload(
				CompletedMultipartUpload::builder()
					.set_parts(Some(parts))
					.build(),
			)
			.send()
			.await
			.context("completing multipart upload")?;
		Ok(())
	}

	async fn abort_multipart(&self, mp: &MultipartUpload) -> Result<()> {
		self
			.client
			.abort_multipart_upload()
			.bucket(&self.bucket)
			.key(&mp.key)
			.upload_id(&mp.upload_id)
			.send()
			.await
			.context("aborting multipart upload")?;
		Ok(())
	}

	async fn delete(&self, keys: Vec<String>) -> Result<()> {
		for batch in keys.chunks(1000) {
			let ids: Result<Vec<ObjectIdentifier>> = batch
				.iter()
				.map(|k| {
					ObjectIdentifier::builder()
						.key(k)
						.build()
						.map_err(Into::into)
				})
				.collect();
			self
				.client
				.delete_objects()
				.bucket(&self.bucket)
				.delete(
					Delete::builder()
						.set_objects(Some(ids?))
						.build()
						.context("building delete request")?,
				)
				.send()
				.await
				.context("delete failed")?;
		}
		Ok(())
	}

	async fn rename(&self, from: &str, to: &str) -> Result<()> {
		if from.ends_with('/') {
			// Directory: copy every object under `from` to the swapped prefix,
			// plus the folder marker itself, then delete all the originals.
			let mut old_keys = Vec::new();
			for o in self.list_recursive(from).await? {
				let suffix = o.key.strip_prefix(from).unwrap_or(&o.key);
				self.copy_one(&o.key, &format!("{to}{suffix}")).await?;
				old_keys.push(o.key);
			}
			if self.get(from).await?.is_some() {
				self.copy_one(from, to).await?; // preserve an explicit empty-folder marker
			}
			old_keys.push(from.to_string());
			self.delete(old_keys).await?;
		} else {
			self.copy_one(from, to).await?;
			self.delete(vec![from.to_string()]).await?;
		}
		Ok(())
	}

	async fn get_range(&self, key: &str, offset: u64) -> Result<(u64, Reader)> {
		if offset == 0 {
			return self.get_stream(key).await;
		}
		let out = self
			.client
			.get_object()
			.bucket(&self.bucket)
			.key(key)
			.range(format!("bytes={offset}-"))
			.send()
			.await
			.with_context(|| format!("ranged download failed: {key}"))?;
		// A 206 reports only the remaining length; add back the offset.
		let remaining = out.content_length().unwrap_or(0).max(0) as u64;
		let total = offset + remaining;
		let body = out.body.into_async_read();
		Ok((total, Box::pin(body)))
	}

	async fn read_header(&self, key: &str, len: usize) -> Result<Vec<u8>> {
		let end = (len as u64).saturating_sub(1);
		let out = self
			.client
			.get_object()
			.bucket(&self.bucket)
			.key(key)
			.range(format!("bytes=0-{end}"))
			.send()
			.await
			.with_context(|| format!("reading header: {key}"))?;
		let data = out.body.collect().await.context("reading header body")?;
		Ok(data.into_bytes().to_vec())
	}
}
