//! App settings and the saved connection profile.
//! Settings live in `$XDG_CONFIG_HOME/rabbit-storage-explorer/`; secrets live in
//! the OS keychain (Secret Service / macOS Keychain / Windows Credential Manager).

use gtk::glib;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub const KEYRING_SERVICE: &str = "rabbit-storage-explorer";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
	/// Concurrent object uploads. Thousands of small files are latency-bound,
	/// so parallelism matters far more than bandwidth.
	pub upload_parallelism: usize,
	/// Concurrent object downloads.
	pub download_parallelism: usize,
	/// Files larger than this (MiB) use multipart upload.
	pub multipart_threshold_mib: u64,
	/// Multipart part size (MiB). The S3 minimum is 5 MiB.
	pub part_size_mib: u64,
	/// Retries per object before it is reported as failed.
	pub retries: u32,
	/// Fixed delay between reconnect/retry attempts after the connection
	/// drops (seconds). A short value resumes transfers quickly once the
	/// network returns.
	pub reconnect_interval_secs: u64,
}

impl Default for Settings {
	fn default() -> Self {
		Self {
			upload_parallelism: 12,
			download_parallelism: 6,
			multipart_threshold_mib: 64,
			part_size_mib: 16,
			retries: 500_000,
			reconnect_interval_secs: 3,
		}
	}
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
	#[default]
	S3,
	Sftp,
	Nfs,
	Smb,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionProfile {
	pub name: String,
	pub kind: BackendKind,
	/// Full endpoint URL, e.g. `https://s3.example.com`
	pub endpoint: String,
	pub bucket: String,
	pub access_key_id: String,
	pub host: String,
	pub port: u16,
	pub username: String,
	/// Path to a private key file; empty = password authentication.
	pub key_path: String,
	/// SFTP: remote start directory (empty = home). NFS: export path.
	/// SMB: directory inside the share (empty = share root).
	pub root_path: String,
	/// SMB share name.
	pub share: String,
	/// SMB domain / workgroup (optional).
	pub domain: String,
	/// NFS: bind the client socket to a privileged port (0–1023). Most NFS
	/// servers require it, but it needs privileges the Flatpak sandbox lacks.
	/// Turn it off there (the server must allow non-privileged clients).
	pub nfs_privileged_port: bool,
	/// NFS AUTH_UNIX identity.
	pub nfs_uid: u32,
	pub nfs_gid: u32,
	/// End-to-end encryption enabled for this connection.
	pub e2ee: bool,
}

impl Default for ConnectionProfile {
	fn default() -> Self {
		Self {
			name: String::new(),
			kind: BackendKind::S3,
			endpoint: String::new(),
			bucket: String::new(),
			access_key_id: String::new(),
			host: String::new(),
			port: 22,
			username: String::new(),
			key_path: String::new(),
			root_path: String::new(),
			share: String::new(),
			domain: String::new(),
			nfs_privileged_port: true,
			nfs_uid: 1000,
			nfs_gid: 1000,
			e2ee: false,
		}
	}
}

pub fn config_dir() -> PathBuf {
	glib::user_config_dir().join("rabbit-storage-explorer")
}

fn read_json<T: for<'d> Deserialize<'d> + Default>(file: &str) -> T {
	let path = config_dir().join(file);
	fs::read_to_string(path)
		.ok()
		.and_then(|s| serde_json::from_str(&s).ok())
		.unwrap_or_default()
}

fn write_json<T: Serialize>(file: &str, value: &T) {
	let dir = config_dir();
	let _ = fs::create_dir_all(&dir);
	if let Ok(s) = serde_json::to_string_pretty(value) {
		let _ = fs::write(dir.join(file), s);
	}
}

impl Settings {
	pub fn load() -> Self {
		read_json("settings.json")
	}
	pub fn save(&self) {
		write_json("settings.json", self);
	}
}

impl ConnectionProfile {
	/// All saved connections. Transparently migrates the old single-profile
	/// format (`profile.json`) from earlier versions.
	pub fn load_all() -> Vec<ConnectionProfile> {
		let mut list: Vec<ConnectionProfile> = read_json("profiles.json");
		if list.is_empty() {
			let legacy: ConnectionProfile = read_json("profile.json");
			if !legacy.endpoint.is_empty() {
				list.push(legacy);
				Self::save_all(&list);
				let _ = fs::remove_file(config_dir().join("profile.json"));
			}
		}
		list
	}

	pub fn save_all(list: &[ConnectionProfile]) {
		write_json("profiles.json", &list);
	}

	/// Insert or replace (matched by name).
	pub fn upsert(profile: &ConnectionProfile) {
		let mut list = Self::load_all();
		match list.iter_mut().find(|p| p.name == profile.name) {
			Some(slot) => *slot = profile.clone(),
			None => list.push(profile.clone()),
		}
		Self::save_all(&list);
	}

	/// Remove a profile and its keychain secret.
	pub fn remove(name: &str) {
		let mut list = Self::load_all();
		list.retain(|p| p.name != name);
		Self::save_all(&list);
		delete_secret(name);
	}
}

/// Store the S3 secret access key in the OS keychain. Best-effort: on headless
/// systems without a Secret Service this fails and the user re-types the key.
pub fn store_secret(profile_name: &str, secret: &str) -> anyhow::Result<()> {
	let entry = keyring::Entry::new(KEYRING_SERVICE, profile_name)?;
	entry.set_password(secret)?;
	Ok(())
}

pub fn load_secret(profile_name: &str) -> Option<String> {
	keyring::Entry::new(KEYRING_SERVICE, profile_name)
		.ok()?
		.get_password()
		.ok()
}

pub fn delete_secret(profile_name: &str) {
	if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, profile_name) {
		let _ = entry.delete_credential();
	}
}

pub fn known_host(host_id: &str) -> Option<String> {
	let mut map: HashMap<String, String> = read_json("known_hosts.json");
	map.remove(host_id)
}

pub fn remember_host(host_id: &str, fingerprint: &str) {
	let mut map: HashMap<String, String> = read_json("known_hosts.json");
	map.insert(host_id.to_string(), fingerprint.to_string());
	write_json("known_hosts.json", &map);
}
