//! S3-compatible backend: AWS S3, MinIO, and other S3-compatible object stores.

use super::{MultipartUpload, RawObject, Reader, StorageBackend};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use aws_config::timeout::TimeoutConfig;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, Delete, ObjectIdentifier};
use aws_sdk_s3::Client;
use aws_smithy_types::byte_stream::ByteStream;

pub struct S3Backend {
	client: Client,
	bucket: String,
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
	) -> Result<String> {
		let out = self
			.client
			.upload_part()
			.bucket(&self.bucket)
			.key(&mp.key)
			.upload_id(&mp.upload_id)
			.part_number(part_number)
			.body(ByteStream::from(data))
			.send()
			.await
			.with_context(|| format!("uploading part {part_number}"))?;
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
}
