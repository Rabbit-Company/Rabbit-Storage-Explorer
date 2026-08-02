//! Main application window. Owns the worker channels: commands go out from
//! widget callbacks, events come back into a single `spawn_future_local` loop
//! that updates the UI. No other thread ever touches a widget.

use super::browser_page::BrowserPage;
use super::connection_page::ConnectionPage;
use super::settings_dialog;
use crate::settings::Settings;
use crate::ui::{human_size, human_time};
use crate::worker::{self, Command, Event, FolderInfo};
use adw::prelude::*;
use gtk::glib;
use std::cell::RefCell;
use std::rc::Rc;

pub fn build(app: &adw::Application) {
	let (cmd, events) = worker::spawn();
	let settings_state = Rc::new(RefCell::new(Settings::load()));

	let window = adw::ApplicationWindow::builder()
		.application(app)
		.title("Rabbit Storage Explorer")
		.default_width(1000)
		.default_height(700)
		.build();

	let title = adw::WindowTitle::new("Rabbit Storage Explorer", "");
	let header = adw::HeaderBar::new();
	header.set_title_widget(Some(&title));

	let btn_disconnect = gtk::Button::from_icon_name("network-offline-symbolic");
	btn_disconnect.set_tooltip_text(Some("Disconnect"));
	btn_disconnect.set_visible(false);
	header.pack_start(&btn_disconnect);

	let btn_settings = gtk::Button::from_icon_name("emblem-system-symbolic");
	btn_settings.set_tooltip_text(Some("Settings"));
	header.pack_end(&btn_settings);

	let stack = gtk::Stack::new();
	stack.set_transition_type(gtk::StackTransitionType::Crossfade);

	let toasts = adw::ToastOverlay::new();

	let connection = ConnectionPage::new(cmd.clone(), &window, &toasts);
	let browser = BrowserPage::new(cmd.clone(), &window);
	stack.add_named(&connection.root, Some("connect"));
	stack.add_named(&browser.root, Some("browser"));

	let toolbar_view = adw::ToolbarView::new();
	toolbar_view.add_top_bar(&header);
	toolbar_view.set_content(Some(&stack));

	toasts.set_child(Some(&toolbar_view));
	window.set_content(Some(&toasts));

	{
		let window = window.clone();
		let cmd = cmd.clone();
		let state = settings_state.clone();
		btn_settings.connect_clicked(move |_| {
			let cmd = cmd.clone();
			let state = state.clone();
			let current = state.borrow().clone();
			settings_dialog::present(&window, &current, move |new| {
				new.save();
				let _ = cmd.send_blocking(Command::SetSettings(new.clone()));
				*state.borrow_mut() = new;
			});
		});
	}

	{
		let cmd = cmd.clone();
		let stack = stack.clone();
		let title = title.clone();
		let connection = connection.clone();
		btn_disconnect.connect_clicked(move |btn| {
			let _ = cmd.send_blocking(Command::Disconnect);
			title.set_subtitle("");
			btn.set_visible(false);
			connection.reset();
			stack.set_visible_child_name("connect");
		});
	}

	{
		let browser = browser.clone();
		let connection = connection.clone();
		let toasts = toasts.clone();
		let stack = stack.clone();
		let title = title.clone();
		let btn_disconnect = btn_disconnect.clone();
		let window = window.clone();
		glib::spawn_future_local(async move {
			let toast = |msg: &str| toasts.add_toast(adw::Toast::new(msg));
			while let Ok(ev) = events.recv().await {
				match ev {
					Event::Connected { label, e2ee } => {
						connection.set_busy(false);
						title.set_subtitle(&if e2ee {
							format!("{label} · encrypted")
						} else {
							label
						});
						btn_disconnect.set_visible(true);
						stack.set_visible_child_name("browser");
						browser.reset_to_root();
					}
					Event::ConnectFailed(msg) => {
						connection.set_busy(false);
						toast(&msg);
					}
					Event::Listed { prefix, entries } => browser.set_listing(&prefix, entries),
					Event::ListFailed(msg) => {
						browser.listing_failed();
						toast(&msg);
					}
					Event::TransferStarted {
						total_files,
						total_bytes,
						files,
					} => {
						browser.transfer_started(total_files, total_bytes, files);
					}
					Event::TransferExtended {
						total_files,
						total_bytes,
						added,
					} => {
						browser.transfer_extended(total_files, total_bytes, added);
					}
					Event::TransferProgress {
						done_files,
						failed_files,
						bytes_done,
						files,
						finished,
					} => {
						browser.transfer_progress(done_files, failed_files, bytes_done, files, finished);
					}
					Event::TransferFinished {
						uploaded,
						downloaded,
						failed,
						errors,
					} => {
						browser.transfer_finished();
						let mut parts = Vec::new();
						if uploaded > 0 {
							parts.push(format!("Uploaded {uploaded} file(s)"));
						}
						if downloaded > 0 {
							parts.push(format!("Downloaded {downloaded} file(s)"));
						}
						if parts.is_empty() {
							parts.push("Transfer complete".to_string());
						}
						let mut msg = parts.join(" · ");
						if failed > 0 {
							msg.push_str(&format!(" · {failed} failed"));
						}
						toast(&msg);
						if let Some(first) = errors.first() {
							toast(first);
						}
					}
					Event::FolderCreated => {
						toast("Folder created");
						browser.request_list();
					}
					Event::Deleted { count } => {
						toast(&format!("Deleted {count} object(s)"));
						browser.request_list();
					}
					Event::Moved { count } => {
						toast(&format!("Moved {count} item(s)"));
						browser.request_list();
					}
					Event::Renamed => {
						browser.request_list();
					}
					Event::SizeCalculated {
						plaintext,
						encrypted,
					} => {
						toast(&format!(
							"Size: {} ({} on disk)",
							human_size(plaintext),
							human_size(encrypted),
						));
						browser.request_list();
					}
					Event::FolderInfo(info) => {
						present_folder_info(&window, info);
					}
					Event::Toast(msg) => toast(&msg),
				}
			}
		});
	}

	window.present();
}

/// Present the encrypted-folder Info modal: a hero with the two size totals and
/// the encryption overhead, a meta line (counts + last computed), and a
/// scrollable, largest-first list of every file with its plaintext/encrypted sizes.
fn present_folder_info(parent: &adw::ApplicationWindow, info: FolderInfo) {
	let overhead = info.encrypted_total.saturating_sub(info.plaintext_total);
	let overhead_pct = if info.plaintext_total > 0 {
		(overhead as f64 / info.plaintext_total as f64) * 100.0
	} else {
		0.0
	};

	// hero: two stat cards + an overhead badge
	let hero = gtk::Box::new(gtk::Orientation::Horizontal, 12);
	hero.set_homogeneous(true);
	hero.add_css_class("info-hero");

	hero.append(&stat_card(
		"Unencrypted",
		&human_size(info.plaintext_total),
		"changes-allow-symbolic",
	));
	hero.append(&stat_card(
		"Encrypted (on disk)",
		&human_size(info.encrypted_total),
		"channel-secure-symbolic",
	));
	hero.append(&overhead_card(overhead_pct, &human_size(overhead)));

	// meta line
	let meta_text = {
		let when = match info.computed {
			Some(ms) => format!("size last calculated {}", human_time(Some(ms / 1000))),
			None => "size not yet calculated".to_string(),
		};
		format!(
			"{} file(s) · {} folder(s) · {when}",
			info.file_count, info.folder_count
		)
	};
	let meta = gtk::Label::new(Some(&meta_text));
	meta.set_xalign(0.0);
	meta.add_css_class("dim-label");
	meta.add_css_class("caption");
	meta.set_margin_top(4);
	meta.set_margin_bottom(4);

	// per-file list
	let list = gtk::ListBox::new();
	list.add_css_class("boxed-list");
	list.set_selection_mode(gtk::SelectionMode::None);

	const MAX_ROWS: usize = 500;
	for f in info.files.iter().take(MAX_ROWS) {
		let row = adw::ActionRow::builder()
			.title(glib::markup_escape_text(&f.rel_path))
			.subtitle(format!(
				"{} → {} on disk",
				human_size(f.plaintext),
				human_size(f.encrypted)
			))
			.build();
		row.add_prefix(&gtk::Image::from_icon_name("text-x-generic-symbolic"));
		list.append(&row);
	}
	if info.files.len() > MAX_ROWS {
		let more = adw::ActionRow::builder()
			.title(format!(
				"… and {} more file(s)",
				info.files.len() - MAX_ROWS
			))
			.build();
		more.add_css_class("dim-label");
		list.append(&more);
	}
	if info.files.is_empty() {
		let empty = adw::ActionRow::builder()
			.title("This folder contains no files.")
			.build();
		empty.add_css_class("dim-label");
		list.append(&empty);
	}

	let scroller = gtk::ScrolledWindow::new();
	scroller.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
	scroller.set_vexpand(true);
	scroller.set_child(Some(&list));

	// assemble
	let content = gtk::Box::new(gtk::Orientation::Vertical, 12);
	content.set_margin_top(16);
	content.set_margin_bottom(16);
	content.set_margin_start(16);
	content.set_margin_end(16);
	content.append(&hero);
	content.append(&meta);
	content.append(&scroller);

	let header = adw::HeaderBar::new();
	header.set_title_widget(Some(&adw::WindowTitle::new("Folder info", &info.name)));
	let toolbar = adw::ToolbarView::new();
	toolbar.add_top_bar(&header);
	toolbar.set_content(Some(&content));

	let dialog = adw::Dialog::new();
	dialog.set_title(&format!("Info · {}", info.name));
	dialog.set_content_width(640);
	dialog.set_content_height(680);
	dialog.set_child(Some(&toolbar));
	dialog.present(Some(parent));
}

/// A labelled stat card for the info hero (title on top, big value below).
fn stat_card(title: &str, value: &str, icon: &str) -> gtk::Box {
	let card = gtk::Box::new(gtk::Orientation::Vertical, 2);
	card.add_css_class("card");
	card.add_css_class("info-card");
	card.set_valign(gtk::Align::Fill);

	let top = gtk::Box::new(gtk::Orientation::Horizontal, 6);
	let img = gtk::Image::from_icon_name(icon);
	img.add_css_class("dim-label");
	let t = gtk::Label::new(Some(title));
	t.set_xalign(0.0);
	t.add_css_class("caption");
	t.add_css_class("dim-label");
	top.append(&img);
	top.append(&t);

	let v = gtk::Label::new(Some(value));
	v.set_xalign(0.0);
	v.add_css_class("title-2");
	v.set_wrap(true);

	card.append(&top);
	card.append(&v);
	card
}

/// The overhead card: highlights how much extra storage encryption costs.
fn overhead_card(pct: f64, bytes: &str) -> gtk::Box {
	let card = gtk::Box::new(gtk::Orientation::Vertical, 2);
	card.add_css_class("card");
	card.add_css_class("info-card");
	card.add_css_class("info-card-accent");
	card.set_valign(gtk::Align::Fill);

	let t = gtk::Label::new(Some("Encryption overhead"));
	t.set_xalign(0.0);
	t.add_css_class("caption");
	t.add_css_class("dim-label");

	let v = gtk::Label::new(Some(&format!("+{pct:.2}%")));
	v.set_xalign(0.0);
	v.add_css_class("title-2");

	let sub = gtk::Label::new(Some(&format!("+{bytes}")));
	sub.set_xalign(0.0);
	sub.add_css_class("caption");
	sub.add_css_class("dim-label");

	card.append(&t);
	card.append(&v);
	card.append(&sub);
	card
}
