//! Settings dialog (Adw PreferencesDialog): transfer parallelism, multipart
//! thresholds and retry counts. Values are collected when the dialog closes.

use crate::settings::Settings;
use adw::prelude::*;

pub fn present(
	parent: &adw::ApplicationWindow,
	current: &Settings,
	on_save: impl Fn(Settings) + 'static,
) {
	let transfers = adw::PreferencesGroup::builder().title("Transfers").build();

	let up = spin_row(
		"Parallel uploads",
		"Concurrent objects sent at once",
		1.0,
		64.0,
		current.upload_parallelism as f64,
	);
	let down = spin_row(
		"Parallel downloads",
		"Concurrent objects fetched at once",
		1.0,
		64.0,
		current.download_parallelism as f64,
	);
	let retries = spin_row(
		"Retries per file",
		"Failed transfers are retried at the reconnect interval below",
		0.0,
		1_000_000.0,
		current.retries as f64,
	);
	let reconnect = spin_row(
		"Reconnect interval (seconds)",
		"How often to retry after the connection drops",
		1.0,
		600.0,
		current.reconnect_interval_secs as f64,
	);
	let flush = spin_row(
		"Manifest flush interval (seconds)",
		"How often encrypted directory metadata is saved back",
		1.0,
		300.0,
		current.manifest_flush_secs as f64,
	);
	transfers.add(&up);
	transfers.add(&down);
	transfers.add(&retries);
	transfers.add(&reconnect);
	transfers.add(&flush);

	let large = adw::PreferencesGroup::builder()
		.title("Large files")
		.build();
	let threshold = spin_row(
		"Multipart threshold (MiB)",
		"Files larger than this use multipart upload",
		5.0,
		4096.0,
		current.multipart_threshold_mib as f64,
	);
	let part = spin_row(
		"Part size (MiB)",
		"S3 requires at least 5 MiB per part",
		5.0,
		512.0,
		current.part_size_mib as f64,
	);
	large.add(&threshold);
	large.add(&part);

	let page = adw::PreferencesPage::new();
	page.add(&transfers);
	page.add(&large);

	let dialog = adw::PreferencesDialog::new();
	dialog.set_title("Settings");
	dialog.add(&page);

	dialog.connect_closed(move |_| {
		on_save(Settings {
			upload_parallelism: up.value() as usize,
			download_parallelism: down.value() as usize,
			retries: retries.value() as u32,
			multipart_threshold_mib: threshold.value() as u64,
			part_size_mib: part.value() as u64,
			reconnect_interval_secs: reconnect.value() as u64,
			manifest_flush_secs: flush.value() as u64,
		});
	});

	dialog.present(Some(parent));
}

fn spin_row(title: &str, subtitle: &str, min: f64, max: f64, value: f64) -> adw::SpinRow {
	let row = adw::SpinRow::with_range(min, max, 1.0);
	row.set_title(title);
	row.set_subtitle(subtitle);
	row.set_value(value);
	row
}
