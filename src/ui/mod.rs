pub mod browser_page;
pub mod connection_page;
pub mod settings_dialog;
pub mod transfer_item;
pub mod window;

use gtk::glib;

pub fn human_size(bytes: u64) -> String {
	const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
	let mut v = bytes as f64;
	let mut u = 0;
	while v >= 1024.0 && u < UNITS.len() - 1 {
		v /= 1024.0;
		u += 1;
	}
	if u == 0 {
		format!("{bytes} B")
	} else {
		format!("{v:.1} {}", UNITS[u])
	}
}

pub fn human_time(epoch: Option<i64>) -> String {
	epoch
		.and_then(|s| glib::DateTime::from_unix_local(s).ok())
		.and_then(|d| d.format("%Y-%m-%d %H:%M").ok())
		.map(|g| g.to_string())
		.unwrap_or_default()
}

pub fn human_eta(seconds: f64) -> String {
	if !seconds.is_finite() || seconds <= 0.0 {
		return "-".to_string();
	}
	let s = seconds.round() as u64;
	if s >= 3600 {
		format!("{}h {}m", s / 3600, (s % 3600) / 60)
	} else if s >= 60 {
		format!("{}m {}s", s / 60, s % 60)
	} else {
		format!("{s}s")
	}
}
