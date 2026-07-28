//! In-memory buffering and flush scheduling for per-directory `.rse` manifests.
//!
//! Manifests are held in memory and written back to the backend lazily, to keep
//! request volume (and thus cost) low during bulk transfers. A directory is
//! marked *dirty* whenever its manifest changes (a file lands, a folder is
//! created, an entry is deleted or renamed, a folder size is recomputed). Dirty
//! directories are flushed when any trigger fires:
//!
//! * the flush interval has elapsed since the directory last changed, AND the
//!   manifest actually differs from what was last written (idempotent changes
//!   never cause a write);
//! * a transfer batch completed;
//! * a create / delete / rename operation completed;
//! * the app is shutting down (final drain).
//!
//! Single-writer model: exactly one app instance manages an encrypted bucket, so
//! there is no cross-client race and a plain last-write-wins put is safe. The
//! only durability gap is a crash between a file landing and the next flush; such
//! orphans are surfaced on listing (see `manifest::Manifest::orphans`) and healed
//! by re-upload, so the buffering trades a small, recoverable staleness window
//! for far fewer writes.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::crypto::VaultKeys;
use crate::manifest::{Manifest, MANIFEST_KEY};
use crate::storage::StorageBackend;

/// Why a flush is happening. Timer flushes respect the per-directory quiet
/// interval and the fingerprint dedup; forced flushes (batch/op/shutdown) write
/// every dirty directory whose content differs from the last write immediately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushReason {
	/// Periodic tick; only directories quiet for >= interval are written.
	Timer,
	/// A batch or discrete operation finished, or the app is closing.
	Forced,
}

/// Per-directory buffered state.
struct DirState {
	manifest: Manifest,
	/// Fingerprint of the manifest as last written to the backend. `None` means
	/// nothing has been written yet (directory is new this session).
	written_fingerprint: Option<u64>,
	/// When this directory's manifest last changed in memory.
	last_change: Instant,
	dirty: bool,
}

/// Decides which directories a flush should write. Pure and clock-injectable so
/// the trigger logic is testable without real time or I/O.
pub struct FlushPlan;

impl FlushPlan {
	/// Given each dirty directory's (fingerprint, last-written-fingerprint,
	/// seconds-since-last-change), return those that should be written now.
	///
	/// A directory is written when its current fingerprint differs from what was
	/// last written (so idempotent edits are skipped) AND either the flush is
	/// forced, or it has been quiet for at least `interval`.
	pub fn select<'a>(
		reason: FlushReason,
		interval: Duration,
		candidates: impl IntoIterator<Item = FlushCandidate<'a>>,
	) -> Vec<&'a str> {
		candidates
			.into_iter()
			.filter(|c| {
				let changed = Some(c.fingerprint) != c.written_fingerprint;
				let quiet_enough = reason == FlushReason::Forced || c.since_change >= interval;
				changed && quiet_enough
			})
			.map(|c| c.dir)
			.collect()
	}
}

/// One directory's inputs to [`FlushPlan::select`].
pub struct FlushCandidate<'a> {
	pub dir: &'a str,
	pub fingerprint: u64,
	pub written_fingerprint: Option<u64>,
	pub since_change: Duration,
}

/// Owns every buffered directory manifest for the current session and performs
/// the actual backend reads/writes. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct ManifestStore {
	inner: Arc<tokio::sync::Mutex<HashMap<String, DirState>>>,
	/// Flush interval in milliseconds, shared across clones so a live settings
	/// change reaches the timer task without re-creating the store.
	interval_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl ManifestStore {
	pub fn new(interval: Duration) -> Self {
		Self {
			inner: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
			interval_ms: Arc::new(std::sync::atomic::AtomicU64::new(
				interval.as_millis() as u64
			)),
		}
	}

	/// Update the flush interval live (from SetSettings). Takes `&self` because
	/// the value is shared; every clone sees the change.
	pub fn set_interval(&self, interval: Duration) {
		self.interval_ms.store(
			interval.as_millis() as u64,
			std::sync::atomic::Ordering::Relaxed,
		);
	}

	/// Current flush interval, for the timer task's sleep.
	pub fn interval(&self) -> Duration {
		Duration::from_millis(
			self
				.interval_ms
				.load(std::sync::atomic::Ordering::Relaxed)
				.max(1),
		)
	}

	/// Directory key for a `.rse` object: the browse prefix (may be "").
	/// Manifests are keyed by their containing directory prefix.
	fn manifest_object_key(dir: &str) -> String {
		if dir.is_empty() {
			MANIFEST_KEY.to_string()
		} else {
			format!("{dir}{MANIFEST_KEY}")
		}
	}

	/// Load a directory's manifest into the buffer, fetching+decrypting from the
	/// backend if not already present. Returns a clone for read use.
	pub async fn load(
		&self,
		backend: &Arc<dyn StorageBackend>,
		keys: &VaultKeys,
		dir: &str,
	) -> Result<Manifest> {
		{
			let map = self.inner.lock().await;
			if let Some(state) = map.get(dir) {
				return Ok(state.manifest.clone());
			}
		}
		// Fetch outside the lock (network), then insert if still absent.
		let obj_key = Self::manifest_object_key(dir);
		let fetched = backend.get(&obj_key).await?;
		let manifest = match fetched {
			Some(blob) => Manifest::decrypt(keys, &blob)?,
			None => Manifest::default(),
		};
		let fp = manifest.fingerprint().ok();

		let mut map = self.inner.lock().await;
		let state = map.entry(dir.to_string()).or_insert_with(|| DirState {
			manifest: manifest.clone(),
			// A freshly loaded manifest is already "written" (it came from the
			// backend), so its current fingerprint is the written one - no
			// spurious flush until something actually changes it.
			written_fingerprint: fp,
			last_change: Instant::now(),
			dirty: false,
		});
		Ok(state.manifest.clone())
	}

	/// Mutate a directory's buffered manifest and mark it dirty. The manifest is
	/// loaded first if necessary. `f` receives the live manifest to edit.
	pub async fn edit(
		&self,
		backend: &Arc<dyn StorageBackend>,
		keys: &VaultKeys,
		dir: &str,
		f: impl FnOnce(&mut Manifest),
	) -> Result<()> {
		// Ensure it's buffered.
		self.load(backend, keys, dir).await?;
		let mut map = self.inner.lock().await;
		if let Some(state) = map.get_mut(dir) {
			f(&mut state.manifest);
			state.last_change = Instant::now();
			state.dirty = true;
		}
		Ok(())
	}

	/// Flush dirty directories per the trigger rules. Returns the number written.
	pub async fn flush(
		&self,
		backend: &Arc<dyn StorageBackend>,
		keys: &VaultKeys,
		reason: FlushReason,
	) -> Result<usize> {
		// Phase 1: under the lock, decide what to write and snapshot the blobs.
		let to_write: Vec<(String, Vec<u8>, u64)> = {
			let map = self.inner.lock().await;
			let candidates: Vec<(String, u64, Option<u64>, Duration)> = map
				.iter()
				.filter(|(_, s)| s.dirty)
				.filter_map(|(dir, s)| {
					s.manifest.fingerprint().ok().map(|fp| {
						(
							dir.clone(),
							fp,
							s.written_fingerprint,
							s.last_change.elapsed(),
						)
					})
				})
				.collect();

			let chosen: Vec<&str> = FlushPlan::select(
				reason,
				self.interval(),
				candidates
					.iter()
					.map(|(dir, fp, wfp, since)| FlushCandidate {
						dir: dir.as_str(),
						fingerprint: *fp,
						written_fingerprint: *wfp,
						since_change: *since,
					}),
			);

			let chosen: std::collections::HashSet<&str> = chosen.into_iter().collect();
			let mut out = Vec::new();
			for (dir, fp, _wfp, _since) in &candidates {
				if chosen.contains(dir.as_str()) {
					if let Some(state) = map.get(dir) {
						// Encrypt while holding the lock is cheap (small blob) and
						// keeps the snapshot consistent with the fingerprint.
						if let Ok(blob) = state.manifest.encrypt(keys) {
							out.push((dir.clone(), blob, *fp));
						}
					}
				}
			}
			out
		};

		// Phase 2: perform the network writes without holding the lock.
		let mut written = 0usize;
		for (dir, blob, fp) in to_write {
			let obj_key = Self::manifest_object_key(&dir);
			backend.put(&obj_key, blob).await?;
			// Phase 3: record the write. If the manifest changed again during the
			// network put, leave it dirty (fingerprint won't match) so the next flush picks it up.
			let mut map = self.inner.lock().await;
			if let Some(state) = map.get_mut(&dir) {
				state.written_fingerprint = Some(fp);
				if state.manifest.fingerprint().ok() == Some(fp) {
					state.dirty = false;
				}
			}
			written += 1;
		}
		Ok(written)
	}

	/// Drop a directory from the buffer (e.g. after it's deleted). Does not touch the backend.
	pub async fn forget(&self, dir: &str) {
		self.inner.lock().await.remove(dir);
	}

	/// Remove an entry from one directory's buffered manifest and return it, so
	/// the caller can insert it elsewhere. Marks the source dirty. Loads the directory first if needed.
	pub async fn take_entry(
		&self,
		backend: &Arc<dyn StorageBackend>,
		keys: &VaultKeys,
		dir: &str,
		encrypted_segment: &str,
	) -> Result<Option<crate::manifest::Entry>> {
		self.load(backend, keys, dir).await?;
		let mut map = self.inner.lock().await;
		let taken = map.get_mut(dir).and_then(|state| {
			let e = state.manifest.take_entry(encrypted_segment);
			if e.is_some() {
				state.last_change = std::time::Instant::now();
				state.dirty = true;
			}
			e
		});
		Ok(taken)
	}

	/// Insert a record (from `take_entry`) into a directory's buffered manifest. Marks it dirty.
	pub async fn insert_entry(
		&self,
		backend: &Arc<dyn StorageBackend>,
		keys: &VaultKeys,
		dir: &str,
		encrypted_segment: &str,
		entry: crate::manifest::Entry,
	) -> Result<()> {
		self
			.edit(backend, keys, dir, move |m| {
				m.insert_entry(encrypted_segment, entry)
			})
			.await
	}

	#[cfg(test)]
	#[allow(unused)]
	async fn is_dirty(&self, dir: &str) -> bool {
		self
			.inner
			.lock()
			.await
			.get(dir)
			.map(|s| s.dirty)
			.unwrap_or(false)
	}
}
