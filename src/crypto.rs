//! End-to-end encryption.
//!
//! Design:
//! * Password -> Argon2id (random 16-byte salt, stored in the bucket) -> 32-byte master key.
//! * HKDF-SHA256 splits the master key into a content key (XChaCha20-Poly1305)
//!   and a filename key (AES-256-SIV, deterministic so lookups/listings work).
//! * File format: `"RSE1" || file_prefix(20)` header (24 bytes total), then 1 MiB
//!   plaintext chunks, each sealed with XChaCha20-Poly1305 using
//!   nonce = file_prefix || u32_be(counter). The final chunk sets the counter's
//!   high bit, which makes truncation attacks detectable.
//! * Filenames: each path segment is AES-SIV encrypted and base32hex encoded.
//!   Deterministic by design - equal names encrypt to equal ciphertexts so that
//!   prefix listing and navigation still work. (Trade-off: an observer can see
//!   that two objects share a name/folder, but not what the name is.)

use aes_siv::{siv::Aes256Siv, KeyInit as AesSivKeyInit};
use anyhow::{anyhow, bail, Context, Result};
use argon2::Argon2;
use chacha20poly1305::{
	aead::{Aead, KeyInit as ChaChaKeyInit},
	XChaCha20Poly1305, XNonce,
};
use data_encoding::BASE32HEX_NOPAD;
use hkdf::Hkdf;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAGIC: &[u8; 4] = b"RSE1";
pub const PREFIX_LEN: usize = 20; // per-file random nonce prefix
pub const HEADER_LEN: usize = MAGIC.len() + PREFIX_LEN; // magic(4) + prefix(20) = 24
pub const CHUNK: usize = 1 << 20; // 1 MiB plaintext per chunk
pub const TAG: usize = 16; // Poly1305 tag
pub const CIPHER_CHUNK: usize = CHUNK + TAG;
const LAST_FLAG: u32 = 0x8000_0000;
const CANARY: &[u8] = b"rse canary v1";
const NAME_HEADER: &[u8] = b"rse-name-v1";

/// Key material derived from the user's password. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKeys {
	content: [u8; 32],
	name: [u8; 64],
}

pub fn derive_keys(password: &str, salt: &[u8]) -> Result<VaultKeys> {
	let mut master = [0u8; 32];
	Argon2::default() // Argon2id, OWASP-recommended defaults (19 MiB, t=2, p=1)
		.hash_password_into(password.as_bytes(), salt, &mut master)
		.map_err(|e| anyhow!("key derivation failed: {e}"))?;

	let hk = Hkdf::<Sha256>::new(None, &master);
	let mut keys = VaultKeys {
		content: [0; 32],
		name: [0; 64],
	};
	hk.expand(b"rse/content/v1", &mut keys.content)
		.map_err(|e| anyhow!("hkdf: {e}"))?;
	hk.expand(b"rse/names/v1", &mut keys.name)
		.map_err(|e| anyhow!("hkdf: {e}"))?;
	master.zeroize();
	Ok(keys)
}

pub struct Encryptor {
	cipher: XChaCha20Poly1305,
	prefix: [u8; PREFIX_LEN],
	counter: u32,
}

impl Encryptor {
	pub fn new(keys: &VaultKeys) -> Self {
		let cipher = XChaCha20Poly1305::new_from_slice(&keys.content).expect("32-byte key");
		let mut prefix = [0u8; PREFIX_LEN];
		rand::rng().fill_bytes(&mut prefix);
		Self {
			cipher,
			prefix,
			counter: 0,
		}
	}

	/// The 24-byte header that must precede all ciphertext chunks.
	pub fn header(&self) -> [u8; HEADER_LEN] {
		let mut h = [0u8; HEADER_LEN];
		h[..MAGIC.len()].copy_from_slice(MAGIC);
		h[MAGIC.len()..].copy_from_slice(&self.prefix);
		h
	}

	/// Seal one chunk (must be called in order; `last` on the final chunk).
	pub fn seal_chunk(&mut self, plaintext: &[u8], last: bool) -> Result<Vec<u8>> {
		let nonce = XNonce::from(chunk_nonce(&self.prefix, self.counter, last));
		self.counter = self
			.counter
			.checked_add(1)
			.ok_or_else(|| anyhow!("file too large (chunk counter overflow)"))?;
		self
			.cipher
			.encrypt(&nonce, plaintext)
			.map_err(|_| anyhow!("encryption failed"))
	}
}

pub struct Decryptor {
	cipher: XChaCha20Poly1305,
	prefix: [u8; PREFIX_LEN],
	counter: u32,
}

impl Decryptor {
	pub fn new(keys: &VaultKeys, header: &[u8]) -> Result<Self> {
		if header.len() < HEADER_LEN || &header[..MAGIC.len()] != MAGIC {
			bail!("not a Rabbit Storage Explorer encrypted file (bad header)");
		}
		let cipher = XChaCha20Poly1305::new_from_slice(&keys.content).expect("32-byte key");
		let mut prefix = [0u8; PREFIX_LEN];
		prefix.copy_from_slice(&header[MAGIC.len()..HEADER_LEN]);
		Ok(Self {
			cipher,
			prefix,
			counter: 0,
		})
	}

	pub fn open_chunk(&mut self, ciphertext: &[u8], last: bool) -> Result<Vec<u8>> {
		let nonce = XNonce::from(chunk_nonce(&self.prefix, self.counter, last));
		self.counter = self
			.counter
			.checked_add(1)
			.ok_or_else(|| anyhow!("file too large (chunk counter overflow)"))?;

		self
			.cipher
			.decrypt(&nonce, ciphertext)
			.map_err(|_| anyhow!("decryption failed - wrong password or corrupted data"))
	}

	pub fn seek_to(&mut self, index: u32) {
		self.counter = index;
	}
}

fn chunk_nonce(prefix: &[u8; PREFIX_LEN], counter: u32, last: bool) -> [u8; 24] {
	let mut nonce = [0u8; 24];
	nonce[..PREFIX_LEN].copy_from_slice(prefix);
	let c = if last { counter | LAST_FLAG } else { counter };
	nonce[PREFIX_LEN..].copy_from_slice(&c.to_be_bytes());
	nonce
}

/// Size of the ciphertext for a plaintext of `plain` bytes.
pub fn encrypted_size(plain: u64) -> u64 {
	let chunks = if plain == 0 {
		1
	} else {
		plain.div_ceil(CHUNK as u64)
	};
	HEADER_LEN as u64 + plain + chunks * TAG as u64
}

/// Given a total ciphertext length, the number of chunks and last-chunk length.
pub fn chunk_layout(cipher_len: u64) -> Result<(u64, usize)> {
	let body = cipher_len
		.checked_sub(HEADER_LEN as u64)
		.ok_or_else(|| anyhow!("encrypted file too short"))?;
	if body < TAG as u64 {
		bail!("encrypted file too short");
	}
	let n = body.div_ceil(CIPHER_CHUNK as u64).max(1);
	let last = (body - (n - 1) * CIPHER_CHUNK as u64) as usize;
	if last < TAG {
		bail!("encrypted file has invalid chunk framing");
	}
	Ok((n, last))
}

/// One-shot helpers for small buffers (canary, small files).
pub fn encrypt_bytes(keys: &VaultKeys, data: &[u8]) -> Result<Vec<u8>> {
	let mut enc = Encryptor::new(keys);
	let mut out = Vec::with_capacity(encrypted_size(data.len() as u64) as usize);
	out.extend_from_slice(&enc.header());
	let mut chunks = data.chunks(CHUNK).peekable();
	if data.is_empty() {
		out.extend(enc.seal_chunk(&[], true)?);
	}
	while let Some(chunk) = chunks.next() {
		let last = chunks.peek().is_none();
		out.extend(enc.seal_chunk(chunk, last)?);
	}
	Ok(out)
}

pub fn decrypt_bytes(keys: &VaultKeys, blob: &[u8]) -> Result<Vec<u8>> {
	let (n, last_len) = chunk_layout(blob.len() as u64)?;
	let mut dec = Decryptor::new(keys, blob)?;
	let mut out = Vec::new();
	let mut off = HEADER_LEN;
	for i in 0..n {
		let last = i == n - 1;
		let len = if last { last_len } else { CIPHER_CHUNK };
		out.extend(dec.open_chunk(&blob[off..off + len], last)?);
		off += len;
	}
	Ok(out)
}

pub fn encrypt_name(keys: &VaultKeys, name: &str) -> Result<String> {
	let mut siv = Aes256Siv::new_from_slice(&keys.name).map_err(|_| anyhow!("bad name key"))?;
	let ct = siv
		.encrypt([NAME_HEADER], name.as_bytes())
		.map_err(|_| anyhow!("name encryption failed"))?;
	Ok(BASE32HEX_NOPAD.encode(&ct))
}

pub fn decrypt_name(keys: &VaultKeys, encoded: &str) -> Result<String> {
	let ct = BASE32HEX_NOPAD
		.decode(encoded.as_bytes())
		.context("not an encrypted name")?;
	let mut siv = Aes256Siv::new_from_slice(&keys.name).map_err(|_| anyhow!("bad name key"))?;
	let pt = siv
		.decrypt([NAME_HEADER], &ct)
		.map_err(|_| anyhow!("name decryption failed"))?;
	String::from_utf8(pt).context("decrypted name is not UTF-8")
}

/// Encrypt every segment of a `/`-separated key path. Trailing `/` preserved.
pub fn encrypt_path(keys: &VaultKeys, path: &str) -> Result<String> {
	map_segments(path, |s| encrypt_name(keys, s))
}

pub fn decrypt_path(keys: &VaultKeys, path: &str) -> Result<String> {
	map_segments(path, |s| decrypt_name(keys, s))
}

fn map_segments(path: &str, f: impl Fn(&str) -> Result<String>) -> Result<String> {
	let mut out = Vec::new();
	for seg in path.split('/') {
		out.push(if seg.is_empty() {
			String::new()
		} else {
			f(seg)?
		});
	}
	Ok(out.join("/"))
}

pub const VAULT_KEY: &str = ".rse-vault";

#[derive(Serialize, Deserialize)]
pub struct VaultFile {
	pub version: u32,
	pub salt: String,   // base64
	pub canary: String, // base64, encrypted CANARY - lets us verify the password on connect
}

pub fn create_vault(password: &str) -> Result<(VaultFile, VaultKeys)> {
	use base64::Engine;
	let mut salt = [0u8; 16];
	rand::rng().fill_bytes(&mut salt);
	let keys = derive_keys(password, &salt)?;
	let canary = encrypt_bytes(&keys, CANARY)?;
	let b64 = base64::engine::general_purpose::STANDARD;
	Ok((
		VaultFile {
			version: 1,
			salt: b64.encode(salt),
			canary: b64.encode(canary),
		},
		keys,
	))
}

pub fn open_vault(vault: &VaultFile, password: &str) -> Result<VaultKeys> {
	use base64::Engine;
	let b64 = base64::engine::general_purpose::STANDARD;
	let salt = b64.decode(&vault.salt).context("vault salt corrupted")?;
	let canary = b64
		.decode(&vault.canary)
		.context("vault canary corrupted")?;
	let keys = derive_keys(password, &salt)?;
	let plain = decrypt_bytes(&keys, &canary)
		.map_err(|_| anyhow!("wrong encryption password for this bucket"))?;
	if plain != CANARY {
		bail!("wrong encryption password for this bucket");
	}
	Ok(keys)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn keys() -> VaultKeys {
		derive_keys("hunter2", b"0123456789abcdef").unwrap()
	}

	#[test]
	fn roundtrip_bytes() {
		let k = keys();
		for len in [0usize, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 7] {
			let data = vec![0xAB; len];
			let ct = encrypt_bytes(&k, &data).unwrap();
			assert_eq!(ct.len() as u64, encrypted_size(len as u64));
			assert_eq!(decrypt_bytes(&k, &ct).unwrap(), data);
		}
	}

	#[test]
	fn truncation_detected() {
		let k = keys();
		let ct = encrypt_bytes(&k, &vec![7u8; 2 * CHUNK]).unwrap();
		// Drop the last chunk entirely: remaining data decrypts but last-flag check fails.
		let truncated = &ct[..HEADER_LEN + CIPHER_CHUNK];
		assert!(decrypt_bytes(&k, truncated).is_err());
	}

	#[test]
	fn roundtrip_names() {
		let k = keys();
		let n = encrypt_name(&k, "häppy file (1).svg").unwrap();
		assert!(!n.contains('/'));
		assert_eq!(decrypt_name(&k, &n).unwrap(), "häppy file (1).svg");
		// deterministic
		assert_eq!(n, encrypt_name(&k, "häppy file (1).svg").unwrap());
	}

	#[test]
	fn vault_roundtrip() {
		let (vf, _) = create_vault("pw").unwrap();
		assert!(open_vault(&vf, "pw").is_ok());
		assert!(open_vault(&vf, "wrong").is_err());
	}

	#[test]
	fn header_size_matches_format() {
		// magic(4) + prefix(20) = 24. If this changes, the wire format changed;
		// worker resume math and encrypted_size all key off HEADER_LEN.
		assert_eq!(HEADER_LEN, 24);
		assert_eq!(HEADER_LEN, MAGIC.len() + PREFIX_LEN);

		let enc = Encryptor::new(&keys());
		let h = enc.header();
		assert_eq!(h.len(), HEADER_LEN);
		assert_eq!(&h[..MAGIC.len()], MAGIC);
	}

	#[test]
	fn header_roundtrips_into_decryptor() {
		let k = keys();
		let enc = Encryptor::new(&k);
		let header = enc.header();
		// A decryptor built from just the 24-byte header must accept it and
		// recover the same nonce prefix the encryptor is using.
		assert!(Decryptor::new(&k, &header).is_ok());
		// A truncated or magic-less header must be rejected.
		assert!(Decryptor::new(&k, &header[..HEADER_LEN - 1]).is_err());
		let mut bad = header;
		bad[0] ^= 0xFF;
		assert!(Decryptor::new(&k, &bad).is_err());
	}

	#[test]
	fn prefix_is_random_per_file() {
		// Two encryptors under the same key must not share a nonce prefix;
		// this is the whole point of widening to 160 random bits.
		let k = keys();
		let a = Encryptor::new(&k).header();
		let b = Encryptor::new(&k).header();
		assert_ne!(a, b);
	}

	#[test]
	fn resume_from_chunk_boundary() {
		// Simulate an interrupted download: decrypt the first whole chunk, then
		// rebuild the decryptor from the header alone, seek past what we have,
		// and finish. The concatenation must equal the original plaintext.
		let k = keys();
		let plain = vec![0x5Au8; 3 * CHUNK + 123];
		let ct = encrypt_bytes(&k, &plain).unwrap();
		let (n_chunks, last_len) = chunk_layout(ct.len() as u64).unwrap();
		assert!(n_chunks >= 2);

		// First pass: open only the first chunk (what "already on disk" covers).
		let mut first = Decryptor::new(&k, &ct).unwrap();
		let done_chunks = 1u32;
		let mut recovered = first
			.open_chunk(&ct[HEADER_LEN..HEADER_LEN + CIPHER_CHUNK], false)
			.unwrap();

		// Second pass: fresh decryptor from the header, seek to the boundary.
		let mut resumed = Decryptor::new(&k, &ct).unwrap();
		resumed.seek_to(done_chunks);
		let mut off = HEADER_LEN + done_chunks as usize * CIPHER_CHUNK;
		for i in done_chunks as u64..n_chunks {
			let last = i == n_chunks - 1;
			let len = if last { last_len } else { CIPHER_CHUNK };
			recovered.extend(resumed.open_chunk(&ct[off..off + len], last).unwrap());
			off += len;
		}

		assert_eq!(recovered, plain);
	}

	#[test]
	fn resume_wrong_boundary_fails() {
		// Seeking to the wrong chunk index yields the wrong nonce, so the AEAD
		// tag check must fail rather than returning garbage plaintext.
		let k = keys();
		let ct = encrypt_bytes(&k, &vec![1u8; 2 * CHUNK]).unwrap();
		let mut dec = Decryptor::new(&k, &ct).unwrap();
		dec.seek_to(1); // should be 0 for the first chunk
		assert!(dec
			.open_chunk(&ct[HEADER_LEN..HEADER_LEN + CIPHER_CHUNK], false)
			.is_err());
	}
}
