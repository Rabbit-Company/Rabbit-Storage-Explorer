//! Per-directory encrypted metadata manifest (`.rse`).
//!
//! Design (E2EE directories only):
//! * Every file and folder in an encrypted directory is stored on the backend
//!   under an *opaque* name: uppercase-hex `SHA-256(encrypted_segment)`, 64
//!   chars, well under every filesystem's 255-char limit. The real (plaintext)
//!   name never appears on disk.
//! * A single `.rse` object per directory maps each on-disk hash back to its
//!   real name and plaintext size, plus optional cached recursive folder sizes.
//!   Listing a directory is therefore one manifest read, not one read per entry.
//! * The manifest is serialized to JSON and then encrypted as a whole with the
//!   content key (via `crypto::encrypt_bytes`), so the backend only ever sees
//!   ciphertext for the metadata too.
//!
//! Why the on-disk name hashes the *ciphertext* (not a random id): it stays
//! deterministic, so `hash_entry(encrypt_name(path))` yields the exact on-disk
//! name without reading the manifest. Existence checks, overwrites and path
//! resolution remain O(1) and stateless - the manifest is needed only for the
//! hash -> real-name *display* direction. (Single-writer model: exactly one app
//! instance manages an encrypted bucket at a time, so manifest writes never race.)
//!
//! Concurrency / durability: the manifest is buffered in memory and flushed on a
//! timer (only when it differs from the last write), on batch completion, and on
//! create/delete/rename. A crash mid-batch can leave hash-named objects with no
//! manifest entry; those are surfaced on listing as "unrecovered" entries rather
//! than hidden, and re-uploading (deterministic hash) self-heals them.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::crypto::{self, VaultKeys};

/// Reserved object name holding a directory's encrypted metadata. base32hex
/// (the encrypted-name alphabet) never emits `.`, so a `.rse` entry can never
/// collide with a real hashed name.
pub const MANIFEST_KEY: &str = ".rse";

/// Current on-disk manifest schema version.
pub const MANIFEST_VERSION: u32 = 1;

/// Metadata for one file in a directory.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
	/// Real (plaintext) file name.
	pub name: String,
	/// Unencrypted file size in bytes.
	pub size: u64,
	/// Unknown/future fields are preserved verbatim so a newer writer's data
	/// survives an older reader (forward compatibility).
	#[serde(flatten)]
	pub extra: BTreeMap<String, serde_json::Value>,
}

/// Metadata for one subfolder in a directory. The recursive-size fields are
/// `None` until the user explicitly runs "calculate size"; the app shows the
/// cached value (with its timestamp) and lets the user recompute.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FolderEntry {
	/// Real (plaintext) folder name.
	pub name: String,
	/// Cached sum of unencrypted sizes under this folder, or `None`.
	pub size: Option<u64>,
	/// Cached sum of encrypted (on-wire) sizes under this folder, or `None`.
	pub esize: Option<u64>,
	/// Unix-millis timestamp of the last size computation, or `None`.
	pub computed: Option<i64>,
	#[serde(flatten)]
	pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Entry {
	File(FileEntry),
	Folder(FolderEntry),
}

/// A directory's decrypted manifest. Keys of both maps are the on-disk names
/// (uppercase-hex `SHA-256` of the encrypted segment).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
	pub version: u32,
	#[serde(default)]
	pub files: BTreeMap<String, FileEntry>,
	#[serde(default)]
	pub folders: BTreeMap<String, FolderEntry>,
	#[serde(flatten)]
	pub extra: BTreeMap<String, serde_json::Value>,
}

impl Default for Manifest {
	fn default() -> Self {
		Self {
			version: MANIFEST_VERSION,
			files: BTreeMap::new(),
			folders: BTreeMap::new(),
			extra: BTreeMap::new(),
		}
	}
}

/// The on-disk name for an encrypted segment: uppercase-hex `SHA-256`.
/// Deterministic, so the same encrypted name always maps to the same entry -
/// which is what keeps lookups O(1) without reading the manifest.
pub fn hash_entry(encrypted_segment: &str) -> String {
	use std::fmt::Write;
	let digest = Sha256::digest(encrypted_segment.as_bytes());
	let mut out = String::with_capacity(digest.len() * 2);
	for b in digest {
		let _ = write!(out, "{b:02X}");
	}
	out
}

/// True if an on-disk name is the reserved manifest object (must be hidden from
/// listings and never treated as a user file).
pub fn is_manifest_key(on_disk_name: &str) -> bool {
	on_disk_name == MANIFEST_KEY || on_disk_name.trim_end_matches('/') == MANIFEST_KEY
}

impl Manifest {
	/// Decrypt and parse a `.rse` blob fetched from a backend.
	pub fn decrypt(keys: &VaultKeys, blob: &[u8]) -> Result<Self> {
		let json = crypto::decrypt_bytes(keys, blob).context("decrypting directory manifest")?;
		let manifest: Manifest = serde_json::from_slice(&json).context("parsing directory manifest")?;
		Ok(manifest)
	}

	/// Serialize and encrypt this manifest into a `.rse` blob to upload.
	pub fn encrypt(&self, keys: &VaultKeys) -> Result<Vec<u8>> {
		let json = serde_json::to_vec(self).context("serializing directory manifest")?;
		crypto::encrypt_bytes(keys, &json).context("encrypting directory manifest")
	}

	/// Record (or overwrite) a file, keyed by the hash of its encrypted name.
	pub fn upsert_file(&mut self, encrypted_segment: &str, name: &str, size: u64) {
		self.files.insert(
			hash_entry(encrypted_segment),
			FileEntry {
				name: name.to_string(),
				size,
				extra: BTreeMap::new(),
			},
		);
	}

	/// Record (or overwrite) a folder, preserving any existing cached sizes.
	pub fn upsert_folder(&mut self, encrypted_segment: &str, name: &str) {
		let key = hash_entry(encrypted_segment);
		match self.folders.get_mut(&key) {
			Some(existing) => existing.name = name.to_string(),
			None => {
				self.folders.insert(
					key,
					FolderEntry {
						name: name.to_string(),
						size: None,
						esize: None,
						computed: None,
						extra: BTreeMap::new(),
					},
				);
			}
		}
	}

	/// Store a computed recursive size roll-up on a folder entry. Timestamp is
	/// Unix-millis. No-op if the folder isn't present (caller should upsert first).
	pub fn set_folder_size(
		&mut self,
		encrypted_segment: &str,
		plaintext_total: u64,
		encrypted_total: u64,
		computed_ms: i64,
	) {
		if let Some(folder) = self.folders.get_mut(&hash_entry(encrypted_segment)) {
			folder.size = Some(plaintext_total);
			folder.esize = Some(encrypted_total);
			folder.computed = Some(computed_ms);
		}
	}

	/// Remove an entry (file or folder) by its encrypted name. Returns true if
	/// something was removed.
	pub fn remove(&mut self, encrypted_segment: &str) -> bool {
		let key = hash_entry(encrypted_segment);
		self.files.remove(&key).is_some() | self.folders.remove(&key).is_some()
	}

	/// Look up the real name for an on-disk hash (file or folder).
	pub fn name_for(&self, on_disk_name: &str) -> Option<&str> {
		self
			.files
			.get(on_disk_name)
			.map(|f| f.name.as_str())
			.or_else(|| self.folders.get(on_disk_name).map(|f| f.name.as_str()))
	}

	/// A stable fingerprint of the manifest's serialized form, used by the flush
	/// scheduler to skip writes when nothing changed since the last flush.
	pub fn fingerprint(&self) -> Result<u64> {
		let json = serde_json::to_vec(self).context("fingerprinting manifest")?;
		// FNV-1a: cheap, deterministic, no external dep. Collisions here only
		// risk a skipped redundant write, never correctness of stored data.
		let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
		for b in json {
			hash ^= b as u64;
			hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
		}
		Ok(hash)
	}

	/// Rename an entry in place: re-key its record from the old encrypted name to
	/// the new one and update the stored display name, preserving size (files) or
	/// cached recursive sizes (folders). Returns false if the old entry was absent.
	///
	/// This is the *only* manifest change a rename needs in the entry's parent
	/// directory. For a folder the backend also moves the subtree, but the child
	/// manifests inside it are unaffected (their leaf hashes don't change), so no
	/// deeper manifest edits are required.
	///
	/// Precondition: the caller must ensure `new_name` isn't already taken in this
	/// directory. If it is, this silently overwrites that entry (last-writer-wins),
	/// matching the backend object clobber - so the worker checks for a name
	/// collision before calling rename.
	pub fn rename_entry(&mut self, old_encrypted: &str, new_encrypted: &str, new_name: &str) -> bool {
		let old_key = hash_entry(old_encrypted);
		let new_key = hash_entry(new_encrypted);
		if let Some(mut f) = self.files.remove(&old_key) {
			f.name = new_name.to_string();
			self.files.insert(new_key, f);
			true
		} else if let Some(mut d) = self.folders.remove(&old_key) {
			d.name = new_name.to_string();
			self.folders.insert(new_key, d);
			true
		} else {
			false
		}
	}

	/// Remove and return a file's record (for moving it to another directory).
	pub fn take_file(&mut self, encrypted_segment: &str) -> Option<FileEntry> {
		self.files.remove(&hash_entry(encrypted_segment))
	}

	/// Remove and return a folder's record (for moving it to another directory).
	pub fn take_folder(&mut self, encrypted_segment: &str) -> Option<FolderEntry> {
		self.folders.remove(&hash_entry(encrypted_segment))
	}

	/// Insert a file record under its encrypted name (destination side of a move).
	/// The name is unchanged by a move, so the hash key matches the source's.
	pub fn insert_file_entry(&mut self, encrypted_segment: &str, entry: FileEntry) {
		self.files.insert(hash_entry(encrypted_segment), entry);
	}

	/// Insert a folder record under its encrypted name (destination side of a move).
	pub fn insert_folder_entry(&mut self, encrypted_segment: &str, entry: FolderEntry) {
		self.folders.insert(hash_entry(encrypted_segment), entry);
	}

	/// Take a file or folder record out by encrypted name, whichever is present.
	pub fn take_entry(&mut self, encrypted_segment: &str) -> Option<Entry> {
		if let Some(f) = self.take_file(encrypted_segment) {
			Some(Entry::File(f))
		} else {
			self.take_folder(encrypted_segment).map(Entry::Folder)
		}
	}

	/// Insert a previously taken record under an encrypted name.
	pub fn insert_entry(&mut self, encrypted_segment: &str, entry: Entry) {
		match entry {
			Entry::File(f) => self.insert_file_entry(encrypted_segment, f),
			Entry::Folder(d) => self.insert_folder_entry(encrypted_segment, d),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::derive_keys;

	fn keys() -> VaultKeys {
		derive_keys("hunter2", b"0123456789abcdef").unwrap()
	}

	#[test]
	fn hash_entry_is_64_upper_hex() {
		let h = hash_entry("SOMEBASE32HEXCIPHERTEXT");
		assert_eq!(h.len(), 64);
		assert!(h
			.chars()
			.all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c)));
		// Deterministic: same input -> same on-disk name (this is what preserves
		// O(1) lookup without reading the manifest).
		assert_eq!(h, hash_entry("SOMEBASE32HEXCIPHERTEXT"));
		assert_ne!(h, hash_entry("DIFFERENT"));
	}

	#[test]
	fn manifest_key_never_collides_with_a_hash() {
		// A hashed name is [0-9A-F] only, so it can never equal ".rse" and can
		// never contain '.'; the two namespaces are cleanly partitioned.
		let h = hash_entry("anything");
		assert!(!is_manifest_key(&h));
		assert!(!h.contains('.'));
		assert!(is_manifest_key(MANIFEST_KEY));
		assert!(is_manifest_key(".rse/")); // folder-style trailing slash
	}

	#[test]
	fn encrypt_decrypt_roundtrip() {
		let k = keys();
		let mut m = Manifest::default();
		m.upsert_file("ENCNAME1", "movie.mkv", 2_346_645_648);
		m.upsert_folder("ENCFOLDER1", "Holiday Photos");

		let blob = m.encrypt(&k).unwrap();
		let back = Manifest::decrypt(&k, &blob).unwrap();
		assert_eq!(back, m);
		// Wrong key must fail to decrypt, not return garbage.
		let other = derive_keys("different", b"0123456789abcdef").unwrap();
		assert!(Manifest::decrypt(&other, &blob).is_err());
	}

	#[test]
	fn upsert_and_lookup() {
		let mut m = Manifest::default();
		m.upsert_file("ENC_A", "a.txt", 10);
		m.upsert_folder("ENC_B", "subdir");

		assert_eq!(m.name_for(&hash_entry("ENC_A")), Some("a.txt"));
		assert_eq!(m.name_for(&hash_entry("ENC_B")), Some("subdir"));
		assert_eq!(m.name_for("nonexistent"), None);

		// Re-upserting a file overwrites name/size.
		m.upsert_file("ENC_A", "a-renamed.txt", 20);
		assert_eq!(m.name_for(&hash_entry("ENC_A")), Some("a-renamed.txt"));
		assert_eq!(m.files[&hash_entry("ENC_A")].size, 20);
	}

	#[test]
	fn folder_size_is_cached_and_preserved() {
		let mut m = Manifest::default();
		m.upsert_folder("ENC_F", "big");
		// Null until computed.
		let f = &m.folders[&hash_entry("ENC_F")];
		assert!(f.size.is_none() && f.esize.is_none() && f.computed.is_none());

		m.set_folder_size("ENC_F", 1000, 1100, 1_785_179_569_512);
		let f = &m.folders[&hash_entry("ENC_F")];
		assert_eq!(f.size, Some(1000));
		assert_eq!(f.esize, Some(1100));
		assert_eq!(f.computed, Some(1_785_179_569_512));

		// Re-upserting the folder (e.g. on a fresh listing) must NOT wipe the
		// cached size - only the name is refreshed.
		m.upsert_folder("ENC_F", "big");
		let f = &m.folders[&hash_entry("ENC_F")];
		assert_eq!(f.size, Some(1000));
	}

	#[test]
	fn remove_entries() {
		let mut m = Manifest::default();
		m.upsert_file("ENC_A", "a", 1);
		m.upsert_folder("ENC_B", "b");
		assert!(m.remove("ENC_A"));
		assert!(m.remove("ENC_B"));
		assert!(!m.remove("ENC_A")); // already gone
		assert!(m.files.is_empty() && m.folders.is_empty());
	}

	#[test]
	fn forward_compat_extra_fields_survive() {
		// Simulate a future writer that added fields at every level, then make
		// sure an older reader round-trips them without loss.
		let future = serde_json::json!({
			"version": 1,
			"newtoplevel": {"experimental": true},
			"files": {
				hash_entry("ENC_A"): {
					"name": "a.txt",
					"size": 10,
					"mtime": 1785179569
				}
			},
			"folders": {
				hash_entry("ENC_B"): {
					"name": "b",
					"size": null, "esize": null, "computed": null,
					"tags": ["archive"]
				}
			}
		});
		let bytes = serde_json::to_vec(&future).unwrap();
		let m: Manifest = serde_json::from_slice(&bytes).unwrap();

		// Known fields parsed correctly...
		assert_eq!(m.files[&hash_entry("ENC_A")].name, "a.txt");
		// ...and unknown fields preserved on re-serialize.
		let reser = serde_json::to_value(&m).unwrap();
		assert_eq!(reser["newtoplevel"]["experimental"], true);
		assert_eq!(reser["files"][hash_entry("ENC_A")]["mtime"], 1785179569);
		assert_eq!(reser["folders"][hash_entry("ENC_B")]["tags"][0], "archive");
	}

	#[test]
	fn fingerprint_tracks_changes() {
		// The flush scheduler writes only when the fingerprint changes, so equal
		// content must fingerprint equal and any change must differ.
		let mut m = Manifest::default();
		let fp0 = m.fingerprint().unwrap();

		m.upsert_file("ENC_A", "a", 1);
		let fp1 = m.fingerprint().unwrap();
		assert_ne!(fp0, fp1);

		// Idempotent upsert -> identical manifest -> identical fingerprint
		// (this is what prevents redundant timer writes).
		let mut m2 = Manifest::default();
		m2.upsert_file("ENC_A", "a", 1);
		assert_eq!(m.fingerprint().unwrap(), m2.fingerprint().unwrap());

		m.upsert_file("ENC_A", "a", 2); // size change
		assert_ne!(fp1, m.fingerprint().unwrap());
	}

	#[test]
	fn rename_file_preserves_size_and_rekeys() {
		let mut m = Manifest::default();
		m.upsert_file("ENC_a.txt", "a.txt", 4096);
		// Rename a.txt -> b.txt: old hash gone, new hash present, size kept, name updated.
		assert!(m.rename_entry("ENC_a.txt", "ENC_b.txt", "b.txt"));
		assert_eq!(m.name_for(&hash_entry("ENC_a.txt")), None);
		let e = &m.files[&hash_entry("ENC_b.txt")];
		assert_eq!(e.name, "b.txt");
		assert_eq!(e.size, 4096);
		// Renaming something absent is a no-op returning false.
		assert!(!m.rename_entry("ENC_missing", "ENC_x", "x"));
	}

	#[test]
	fn rename_folder_preserves_cached_sizes() {
		let mut m = Manifest::default();
		m.upsert_folder("ENC_photos", "photos");
		m.set_folder_size("ENC_photos", 10_000, 11_000, 1_785_000_000_000);
		// Rename photos -> pics: cached recursive sizes must survive the re-key.
		assert!(m.rename_entry("ENC_photos", "ENC_pics", "pics"));
		assert!(m.folders.get(&hash_entry("ENC_photos")).is_none());
		let f = &m.folders[&hash_entry("ENC_pics")];
		assert_eq!(f.name, "pics");
		assert_eq!(f.size, Some(10_000));
		assert_eq!(f.esize, Some(11_000));
		assert_eq!(f.computed, Some(1_785_000_000_000));
	}

	#[test]
	fn move_file_between_manifests() {
		let mut src = Manifest::default();
		let mut dest = Manifest::default();
		src.upsert_file("ENC_clip.mkv", "clip.mkv", 9_999);

		// Take from source, insert into destination under the same encrypted name
		// (a move keeps the name, hence the same hash).
		let entry = src.take_file("ENC_clip.mkv").expect("present in source");
		assert_eq!(entry.size, 9_999);
		dest.insert_file_entry("ENC_clip.mkv", entry);

		assert!(src.files.is_empty());
		assert_eq!(dest.name_for(&hash_entry("ENC_clip.mkv")), Some("clip.mkv"));
		assert_eq!(dest.files[&hash_entry("ENC_clip.mkv")].size, 9_999);
	}

	#[test]
	fn move_folder_between_manifests_keeps_cache() {
		let mut src = Manifest::default();
		let mut dest = Manifest::default();
		src.upsert_folder("ENC_docs", "docs");
		src.set_folder_size("ENC_docs", 500, 550, 1_785_000_000_001);

		let entry = src.take_folder("ENC_docs").expect("present");
		dest.insert_folder_entry("ENC_docs", entry);

		assert!(src.folders.is_empty());
		let f = &dest.folders[&hash_entry("ENC_docs")];
		assert_eq!(f.name, "docs");
		assert_eq!(f.size, Some(500)); // cached size travels with the move
	}

	#[test]
	fn take_entry_dispatches_file_or_folder() {
		let mut m = Manifest::default();
		m.upsert_file("EF", "f.txt", 42);
		m.upsert_folder("ED", "d");
		m.set_folder_size("ED", 7, 8, 9);

		match m.take_entry("EF") {
			Some(Entry::File(f)) => {
				assert_eq!(f.name, "f.txt");
				assert_eq!(f.size, 42);
			}
			_ => panic!("expected a file"),
		}
		match m.take_entry("ED") {
			Some(Entry::Folder(d)) => {
				assert_eq!(d.name, "d");
				assert_eq!(d.size, Some(7)); // cached sizes ride along
			}
			_ => panic!("expected a folder"),
		}
		assert!(m.take_entry("EF").is_none()); // already taken
		assert!(m.files.is_empty() && m.folders.is_empty());
	}

	#[test]
	fn take_then_insert_is_lossless_across_manifests() {
		let mut src = Manifest::default();
		let mut dest = Manifest::default();
		src.upsert_folder("ED", "docs");
		src.set_folder_size("ED", 500, 550, 1_785_000_000_002);

		let taken = src.take_entry("ED").expect("present");
		dest.insert_entry("ED", taken);

		assert!(src.folders.is_empty());
		let f = &dest.folders[&hash_entry("ED")];
		assert_eq!(f.name, "docs");
		assert_eq!(f.size, Some(500));
		assert_eq!(f.esize, Some(550));
		assert_eq!(f.computed, Some(1_785_000_000_002));
	}
}
