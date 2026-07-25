//! Main application window. Owns the worker channels: commands go out from
//! widget callbacks, events come back into a single `spawn_future_local` loop
//! that updates the UI. No other thread ever touches a widget.

use super::browser_page::BrowserPage;
use super::connection_page::ConnectionPage;
use super::settings_dialog;
use crate::settings::Settings;
use crate::worker::{self, Command, Event};
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

	let connection = ConnectionPage::new(cmd.clone(), &window);
	let browser = BrowserPage::new(cmd.clone(), &window);
	stack.add_named(&connection.root, Some("connect"));
	stack.add_named(&browser.root, Some("browser"));

	let toolbar_view = adw::ToolbarView::new();
	toolbar_view.add_top_bar(&header);
	toolbar_view.set_content(Some(&stack));

	let toasts = adw::ToastOverlay::new();
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
					Event::Toast(msg) => toast(&msg),
				}
			}
		});
	}

	window.present();
}
