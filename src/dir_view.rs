//! Manifest-aware directory naming and listing (worker layer).
//!
//! In an E2EE session every on-disk name is `hash_entry(encrypt_name(segment))`
//! - a 64-char uppercase-hex SHA-256 - and the real name/size live in the
//! directory's `.rse` manifest. This module holds the two pure pieces the worker
//! needs around that:
//!
//! * [`on_disk_segment`] / [`on_disk_path`]: the *forward* (deterministic) map
//!   from a logical name/path to its on-disk hash form. Used for writes (where
//!   does this upload go?) and navigation (what prefix is this folder?). No
//!   manifest needed - the map is deterministic, preserving O(1) lookup.
//! * [`build_listing`]: the *reverse* map for display - given the raw backend
//!   entries of a directory and its decrypted manifest, produce user-facing
//!   entries with real names and plaintext sizes, hide the `.rse` object, and
//!   surface orphans (hash-named objects with no manifest record) instead of
//!   dropping them.
//!
//! Backends stay name-agnostic: they only ever see keys.

use anyhow::Result;

use crate::crypto::{self, VaultKeys};
use crate::manifest::{hash_entry, is_manifest_key, Manifest};
use crate::storage::{RawObject, RemoteEntry};

/// The on-disk name for one logical path segment in an encrypted session:
/// `SHA-256(encrypt_name(segment))`, uppercase hex. Deterministic.
pub fn on_disk_segment(keys: &VaultKeys, name: &str) -> Result<String> {
	let encrypted = crypto::encrypt_name(keys, name)?;
	Ok(hash_entry(&encrypted))
}

/// Map a whole `/`-separated logical path to its on-disk hash path, preserving a
/// trailing slash (folder marker). Empty segments (e.g. a leading/trailing `/`)
/// pass through unchanged so prefixes compose correctly.
pub fn on_disk_path(keys: &VaultKeys, path: &str) -> Result<String> {
	let mut out = Vec::new();
	for seg in path.split('/') {
		out.push(if seg.is_empty() {
			String::new()
		} else {
			on_disk_segment(keys, seg)?
		});
	}
	Ok(out.join("/"))
}

/// The parent directory prefix of an on-disk key, including its trailing slash
/// (or `""` for a root-level entry). Handles both files (`a/b/HASH`) and folders
/// (`a/b/HASH/`); the folder marker is trimmed before finding the parent.
///
/// Composition guarantee: `parent_prefix(&format!("{dest}{hash}/")) == dest`, so
/// the worker can recover a directory from any child key it built.
#[allow(unused)]
pub fn parent_prefix(key: &str) -> String {
	let trimmed = key.trim_end_matches('/');
	match trimmed.rfind('/') {
		Some(idx) => trimmed[..=idx].to_string(),
		None => String::new(),
	}
}

/// True if a name has the shape of an on-disk hash entry: exactly 64 uppercase
/// hex chars. Lets the listing tell "ours but orphaned" (hash-shaped, absent
/// from the manifest) apart from "foreign" (some other tool's plaintext name).
fn looks_like_hash(name: &str) -> bool {
	name.len() == 64
		&& name
			.bytes()
			.all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

/// How a single raw entry was classified against the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
	/// Hash-named and present in the manifest: a normal encrypted item.
	Known,
	/// Hash-named but absent from the manifest: an orphan from an interrupted
	/// upload. Surfaced so the user can see, delete, or (once rename exists)
	/// re-associate it - never silently hidden.
	Orphan,
	/// Not hash-shaped: a foreign object written by another tool.
	Foreign,
}

/// A user-facing directory listing produced from raw entries + the manifest.
pub struct DirListing {
	pub entries: Vec<RemoteEntry>,
	/// Number of orphaned (hash-named, unrecorded) items in `entries`.
	pub orphan_count: usize,
}

/// Extract the leaf (last path segment) of a raw key, trimming a trailing slash.
fn leaf_of(key: &str) -> &str {
	let trimmed = key.trim_end_matches('/');
	trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// Build the display listing for one encrypted directory.
///
/// `raw` is the backend's shallow listing of the directory; `manifest` is that
/// directory's decrypted `.rse` (use `Manifest::default()` if the directory has
/// none yet). The `.rse` object itself is dropped. Files show their manifest
/// plaintext size; folders show their cached recursive size if one was computed,
/// else 0.
pub fn build_listing(raw: Vec<RawObject>, manifest: &Manifest) -> DirListing {
	let mut entries = Vec::with_capacity(raw.len());
	let mut orphan_count = 0;

	for o in raw {
		let leaf = leaf_of(&o.key);
		if is_manifest_key(leaf) {
			continue; // never show the manifest object
		}

		let kind = if manifest.name_for(leaf).is_some() {
			EntryKind::Known
		} else if looks_like_hash(leaf) {
			EntryKind::Orphan
		} else {
			EntryKind::Foreign
		};

		let (name, size, encrypted) = match kind {
			EntryKind::Known => {
				let name = manifest.name_for(leaf).unwrap_or(leaf).to_string();
				// Under the single-writer model a hash lives in exactly one of
				// files/folders and the backend's is_prefix agrees with it, so the
				// size lookup below matches. If a corrupted manifest ever disagreed,
				// we degrade to 0 / raw size rather than panicking.
				let size = if o.is_prefix {
					manifest.folders.get(leaf).and_then(|f| f.size).unwrap_or(0)
				} else {
					manifest.files.get(leaf).map(|f| f.size).unwrap_or(o.size)
				};
				(name, size, Some(true))
			}
			EntryKind::Orphan => {
				orphan_count += 1;
				// Show the hash so the item is actionable; mark as not-cleanly-
				// encrypted so the UI can badge it distinctly from a known item.
				(
					format!("[unrecovered] {}", &leaf[..16.min(leaf.len())]),
					o.size,
					Some(false),
				)
			}
			EntryKind::Foreign => (leaf.to_string(), o.size, Some(false)),
		};

		entries.push(RemoteEntry {
			key: o.key,
			name,
			is_dir: o.is_prefix,
			size,
			modified: o.modified,
			encrypted,
		});
	}

	entries.sort_by(|a, b| {
		b.is_dir
			.cmp(&a.is_dir)
			.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
	});

	DirListing {
		entries,
		orphan_count,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::derive_keys;
	use crate::manifest::MANIFEST_KEY;

	fn keys() -> VaultKeys {
		derive_keys("hunter2", b"0123456789abcdef").unwrap()
	}

	fn raw_file(key: &str, size: u64) -> RawObject {
		RawObject {
			key: key.to_string(),
			size,
			modified: Some(1000),
			is_prefix: false,
		}
	}
	fn raw_dir(key: &str) -> RawObject {
		RawObject {
			key: key.to_string(),
			size: 0,
			modified: Some(1000),
			is_prefix: true,
		}
	}

	#[test]
	fn on_disk_naming_is_deterministic_and_hashed() {
		let k = keys();
		let a = on_disk_segment(&k, "vacation.jpg").unwrap();
		let b = on_disk_segment(&k, "vacation.jpg").unwrap();
		assert_eq!(a, b); // deterministic -> O(1) lookup
		assert!(looks_like_hash(&a));
		let enc = crypto::encrypt_name(&k, "vacation.jpg").unwrap();
		assert_eq!(a, hash_entry(&enc));
	}

	#[test]
	fn on_disk_path_preserves_structure_and_trailing_slash() {
		let k = keys();
		let p = on_disk_path(&k, "photos/2024/summer/").unwrap();
		let segs: Vec<&str> = p.split('/').collect();
		// three hashed segments + a trailing empty from the final slash
		assert_eq!(segs.len(), 4);
		assert!(looks_like_hash(segs[0]) && looks_like_hash(segs[1]) && looks_like_hash(segs[2]));
		assert_eq!(segs[3], "");
		assert!(p.ends_with('/'));
	}

	#[test]
	fn listing_resolves_names_and_plaintext_sizes() {
		let k = keys();
		let mut m = Manifest::default();
		// A file: encrypted name -> hash on disk, real name + plaintext size in manifest.
		let enc_file = crypto::encrypt_name(&k, "movie.mkv").unwrap();
		let file_hash = hash_entry(&enc_file);
		m.upsert_file(&enc_file, "movie.mkv", 5_000_000_000);
		// A folder with a computed recursive size.
		let enc_dir = crypto::encrypt_name(&k, "Holiday").unwrap();
		let dir_hash = hash_entry(&enc_dir);
		m.upsert_folder(&enc_dir, "Holiday");
		m.set_folder_size(&enc_dir, 9_000, 9_500, 1_785_000_000_000);

		let raw = vec![
			raw_file(
				&format!("prefix/{file_hash}"),
				4_999_999_000, /* ciphertext-ish */
			),
			raw_dir(&format!("prefix/{dir_hash}/")),
			raw_file(&format!("prefix/{MANIFEST_KEY}"), 200), // must be hidden
		];
		let listing = build_listing(raw, &m);

		assert_eq!(listing.orphan_count, 0);
		assert_eq!(listing.entries.len(), 2); // .rse hidden

		// Folder sorts before file; check both resolved correctly.
		let folder = &listing.entries[0];
		assert!(folder.is_dir);
		assert_eq!(folder.name, "Holiday");
		assert_eq!(folder.size, 9_000); // cached plaintext recursive size
		assert_eq!(folder.encrypted, Some(true));

		let file = &listing.entries[1];
		assert!(!file.is_dir);
		assert_eq!(file.name, "movie.mkv");
		assert_eq!(file.size, 5_000_000_000); // manifest plaintext size, not raw
		assert_eq!(file.encrypted, Some(true));
	}

	#[test]
	fn listing_surfaces_orphans() {
		let k = keys();
		let m = Manifest::default(); // empty: nothing is recorded

		let orphan_hash = hash_entry(&crypto::encrypt_name(&k, "lost.txt").unwrap());
		let raw = vec![raw_file(&format!("d/{orphan_hash}"), 123)];
		let listing = build_listing(raw, &m);

		assert_eq!(listing.orphan_count, 1);
		assert_eq!(listing.entries.len(), 1);
		let e = &listing.entries[0];
		assert!(e.name.starts_with("[unrecovered]"));
		assert_eq!(e.encrypted, Some(false)); // badged distinctly from a known item
		assert!(e.key.ends_with(&orphan_hash));
	}

	#[test]
	fn listing_distinguishes_foreign_from_orphan() {
		let m = Manifest::default();
		// A foreign object written by another tool: not hash-shaped.
		let raw = vec![raw_file("d/some-other-tool.bin", 42)];
		let listing = build_listing(raw, &m);

		assert_eq!(listing.orphan_count, 0); // foreign, not orphan
		assert_eq!(listing.entries[0].name, "some-other-tool.bin");
		assert_eq!(listing.entries[0].encrypted, Some(false));
	}

	#[test]
	fn parent_prefix_handles_files_folders_and_root() {
		assert_eq!(parent_prefix("dir/sub/ABC"), "dir/sub/");
		assert_eq!(parent_prefix("dir/sub/ABC/"), "dir/sub/"); // folder marker trimmed
		assert_eq!(parent_prefix("ABC"), ""); // file at root
		assert_eq!(parent_prefix("ABC/"), ""); // folder at root
		assert_eq!(parent_prefix(""), "");
	}

	#[test]
	fn parent_prefix_composes_with_dest() {
		// The property the worker relies on when recording uploads / moves.
		let dest = "photos/2024/";
		let hash = "A".repeat(64);
		assert_eq!(parent_prefix(&format!("{dest}{hash}/")), dest);
		assert_eq!(parent_prefix(&format!("{dest}{hash}")), dest);
	}

	#[test]
	fn manifest_object_is_always_hidden() {
		let m = Manifest::default();
		let raw = vec![
			raw_file(MANIFEST_KEY, 100),
			raw_file(&format!("d/{MANIFEST_KEY}"), 100),
		];
		let listing = build_listing(raw, &m);
		assert!(listing.entries.is_empty());
	}
}
