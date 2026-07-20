//! Bucket browser: virtualized object list (ColumnView), breadcrumb navigation,
//! drag-and-drop uploads, selection actions and the transfer status bar.

use super::{human_eta, human_size, human_time};
use crate::storage::RemoteEntry;
use crate::worker::{Command, FileProgress};
use adw::prelude::*;
use gtk::{gdk, gio, glib};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

#[derive(Clone, Copy, PartialEq)]
enum ItemState {
	Queued,
	Active,
	Done,
	Failed,
}

/// One row in the transfers dialog. Stored in a persistent `gio::ListStore`
/// and updated in place, so the dialog's scroll position survives updates.
#[derive(Clone)]
struct TransferItem {
	name: String,
	total: u64,
	done: u64,
	state: ItemState,
	/// Bytes/second, measured by the worker.
	speed_bps: f64,
}

pub struct BrowserPage {
	weak_self: std::rc::Weak<BrowserPage>,
	pub root: gtk::Widget,
	cmd: async_channel::Sender<Command>,
	window: glib::WeakRef<adw::ApplicationWindow>,

	store: gio::ListStore,
	selection: gtk::MultiSelection,
	entries: RefCell<Vec<RemoteEntry>>,
	/// Breadcrumb stack: (display name, real full prefix). Root is ("", "").
	path: RefCell<Vec<(String, String)>>,
	breadcrumbs: gtk::Box,
	search: gtk::SearchEntry,
	empty: adw::StatusPage,
	list_scroll: gtk::ScrolledWindow,

	drop_reveal: gtk::Revealer,
	loading: gtk::Spinner,
	/// Bumped on every listing request; lets slow/stale responses be told apart.
	list_generation: Cell<u64>,
	list_pending: Cell<bool>,

	bar: gtk::Revealer,
	bar_progress: gtk::ProgressBar,
	total_files: Cell<u64>,
	total_bytes: Cell<u64>,
	/// Rows of the transfers dialog; persists across dialog open/close.
	transfer_store: gio::ListStore,
	/// name -> position in `transfer_store`.
	transfer_index: RefCell<HashMap<String, u32>>,
	bytes_done: Cell<u64>,
	/// Sum of the active files' speeds, bytes/second.
	global_speed_bps: Cell<f64>,
	/// Stat labels of the open transfers dialog, if any.
	stats_widgets: RefCell<Option<StatsWidgets>>,
}

struct StatsWidgets {
	speed: gtk::Label,
	transferred: gtk::Label,
	eta: gtk::Label,
}

impl BrowserPage {
	pub fn new(cmd: async_channel::Sender<Command>, window: &adw::ApplicationWindow) -> Rc<Self> {
		let store = gio::ListStore::new::<glib::BoxedAnyObject>();

		let toolbar = gtk::Box::new(gtk::Orientation::Horizontal, 6);
		toolbar.set_margin_start(8);
		toolbar.set_margin_end(8);
		toolbar.set_margin_top(6);
		toolbar.set_margin_bottom(6);

		let btn_upload = gtk::MenuButton::new();
		btn_upload.set_icon_name("document-send-symbolic");
		btn_upload.set_tooltip_text(Some("Upload"));
		btn_upload.add_css_class("flat");

		let mi_files = menu_row("document-send-symbolic", "Files…");
		let mi_folders = menu_row("folder-symbolic", "Folders…");
		let upload_menu = gtk::Box::new(gtk::Orientation::Vertical, 0);
		upload_menu.append(&mi_files);
		upload_menu.append(&mi_folders);
		let upload_popover = gtk::Popover::new();
		upload_popover.set_child(Some(&upload_menu));
		btn_upload.set_popover(Some(&upload_popover));

		let btn_new_folder = icon_button("folder-new-symbolic", "New folder");
		let btn_download = icon_button("folder-download-symbolic", "Download selected");
		let btn_delete = icon_button("user-trash-symbolic", "Delete selected");
		let btn_refresh = icon_button("view-refresh-symbolic", "Refresh");
		let search = gtk::SearchEntry::new();
		search.set_placeholder_text(Some("Filter by name"));
		search.set_hexpand(true);

		toolbar.append(&btn_upload);
		for b in [&btn_new_folder, &btn_download, &btn_delete, &btn_refresh] {
			toolbar.append(b);
		}
		toolbar.append(&search);

		let breadcrumbs = gtk::Box::new(gtk::Orientation::Horizontal, 2);
		breadcrumbs.add_css_class("breadcrumbs");
		breadcrumbs.set_margin_start(10);
		breadcrumbs.set_margin_bottom(4);

		let view = gtk::ColumnView::new(None::<gtk::MultiSelection>);
		view.set_vexpand(true);
		view.add_css_class("data-table");

		let ctx_page: Rc<RefCell<std::rc::Weak<BrowserPage>>> =
			Rc::new(RefCell::new(std::rc::Weak::new()));

		let name_col = name_column(ctx_page.clone());
		name_col.set_sorter(Some(&entry_sorter(|a, b| {
			a.name.to_lowercase().cmp(&b.name.to_lowercase())
		})));
		let size_col = text_column("Size", 100, |e| {
			if e.is_dir {
				String::new()
			} else {
				human_size(e.size)
			}
		});
		size_col.set_sorter(Some(&entry_sorter(|a, b| a.size.cmp(&b.size))));
		let modified_col = text_column("Modified", 160, |e| human_time(e.modified));
		modified_col.set_sorter(Some(&entry_sorter(|a, b| a.modified.cmp(&b.modified))));

		view.append_column(&name_col);
		view.append_column(&size_col);
		view.append_column(&modified_col);

		// Clicking column headers sorts; the view's aggregate sorter drives the
		// sort model. Sorting happens in the model, so the backing store stays
		// in insertion order and selection positions always match what's shown.
		let sort_model = gtk::SortListModel::new(Some(store.clone()), view.sorter());
		let selection = gtk::MultiSelection::new(Some(sort_model));
		view.set_model(Some(&selection));
		view.sort_by_column(Some(&name_col), gtk::SortType::Ascending);

		let list_scroll = gtk::ScrolledWindow::builder()
			.child(&view)
			.vexpand(true)
			.build();

		let empty = adw::StatusPage::builder()
			.icon_name("folder-open-symbolic")
			.title("Empty folder")
			.description("Drop files anywhere in this window to upload them here")
			.build();
		empty.set_visible(false);
		empty.set_vexpand(true);

		// Just a full-width bar and a cancel button; no shifting labels.
		// Clicking the bar opens the per-file details dialog.
		let bar_progress = gtk::ProgressBar::new();
		bar_progress.set_hexpand(true);
		bar_progress.set_valign(gtk::Align::Center);
		bar_progress.set_tooltip_text(Some("Click for per-file progress"));
		let btn_cancel = gtk::Button::with_label("Cancel");
		btn_cancel.add_css_class("destructive-action");

		let bar_box = gtk::Box::new(gtk::Orientation::Horizontal, 12);
		bar_box.set_margin_start(10);
		bar_box.set_margin_end(10);
		bar_box.set_margin_top(6);
		bar_box.set_margin_bottom(6);
		bar_box.append(&bar_progress);
		bar_box.append(&btn_cancel);
		let bar = gtk::Revealer::builder()
			.transition_type(gtk::RevealerTransitionType::SlideUp)
			.child(&bar_box)
			.build();

		let drop_status = adw::StatusPage::builder()
			.icon_name("document-send-symbolic")
			.title("Drop to upload")
			.build();
		drop_status.add_css_class("drop-overlay");
		let drop_reveal = gtk::Revealer::builder()
			.transition_type(gtk::RevealerTransitionType::Crossfade)
			.child(&drop_status)
			.can_target(false)
			.build();

		let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
		content.append(&toolbar);
		content.append(&breadcrumbs);
		content.append(&list_scroll);
		content.append(&empty);
		content.append(&bar);

		let loading = gtk::Spinner::new();
		loading.set_size_request(32, 32);
		loading.set_halign(gtk::Align::Center);
		loading.set_valign(gtk::Align::Center);
		loading.set_can_target(false);
		loading.set_visible(false);

		let overlay = gtk::Overlay::new();
		overlay.set_child(Some(&content));
		overlay.add_overlay(&loading);
		overlay.add_overlay(&drop_reveal);

		let weak_window = glib::WeakRef::new();
		weak_window.set(Some(window));

		let root: gtk::Widget = overlay.clone().upcast();
		let page = Rc::new_cyclic(|weak| Self {
			weak_self: weak.clone(),
			root,
			cmd,
			window: weak_window,
			store,
			selection,
			entries: RefCell::new(Vec::new()),
			path: RefCell::new(vec![(String::new(), String::new())]),
			breadcrumbs,
			search,
			empty,
			list_scroll,
			drop_reveal,
			loading,
			list_generation: Cell::new(0),
			list_pending: Cell::new(false),
			bar,
			bar_progress,
			total_files: Cell::new(0),
			total_bytes: Cell::new(0),
			transfer_store: gio::ListStore::new::<glib::BoxedAnyObject>(),
			transfer_index: RefCell::new(HashMap::new()),
			bytes_done: Cell::new(0),
			global_speed_bps: Cell::new(0.0),
			stats_widgets: RefCell::new(None),
		});

		*ctx_page.borrow_mut() = Rc::downgrade(&page);

		// Row activation (double-click / Enter): enter folders.
		let p = page.clone();
		view.connect_activate(move |_, pos| {
			let Some(obj) = p.selection.item(pos).and_downcast::<glib::BoxedAnyObject>() else {
				return;
			};
			let e = obj.borrow::<RemoteEntry>().clone();
			if e.is_dir {
				p.search.set_text(""); // a filter from the old folder would hide the new one's contents
				p.path.borrow_mut().push((e.name.clone(), e.key.clone()));
				p.request_list();
			}
		});

		let p = page.clone();
		let pop = upload_popover.clone();
		mi_files.connect_clicked(move |_| {
			pop.popdown();
			p.pick_files_and_upload();
		});
		let p = page.clone();
		let pop = upload_popover.clone();
		mi_folders.connect_clicked(move |_| {
			pop.popdown();
			p.pick_folders_and_upload();
		});
		let p = page.clone();
		btn_refresh.connect_clicked(move |_| p.request_list());
		let p = page.clone();
		btn_new_folder.connect_clicked(move |_| p.new_folder_dialog());
		let p = page.clone();
		btn_download.connect_clicked(move |_| p.download_selected());
		let p = page.clone();
		btn_delete.connect_clicked(move |_| p.confirm_delete_selected());
		let key = gtk::EventControllerKey::new();
		let p = page.clone();
		key.connect_key_pressed(move |_, keyval, _, _| {
			if keyval == gdk::Key::Delete || keyval == gdk::Key::KP_Delete {
				p.confirm_delete_selected();
				glib::Propagation::Stop
			} else {
				glib::Propagation::Proceed
			}
		});
		view.add_controller(key);
		let p = page.clone();
		btn_cancel.connect_clicked(move |_| {
			let _ = p.cmd.send_blocking(Command::CancelTransfers);
		});
		let click = gtk::GestureClick::new();
		let p = page.clone();
		click.connect_released(move |_, _, _, _| p.show_transfers_dialog());
		page.bar_progress.add_controller(click);
		let p = page.clone();
		page
			.search
			.connect_search_changed(move |_| p.rebuild_store());

		let target = gtk::DropTarget::new(gdk::FileList::static_type(), gdk::DragAction::COPY);
		let p = page.clone();
		target.connect_enter(move |_, _, _| {
			p.drop_reveal.set_reveal_child(true);
			gdk::DragAction::COPY
		});
		let p = page.clone();
		target.connect_leave(move |_| p.drop_reveal.set_reveal_child(false));
		let p = page.clone();
		target.connect_drop(move |_, value, _, _| {
			p.drop_reveal.set_reveal_child(false);
			if let Ok(list) = value.get::<gdk::FileList>() {
				let paths: Vec<PathBuf> = list.files().iter().filter_map(|f| f.path()).collect();
				if !paths.is_empty() {
					let _ = p.cmd.send_blocking(Command::Upload {
						paths,
						dest_prefix: p.current_prefix(),
					});
					return true;
				}
			}
			false
		});
		overlay.add_controller(target);

		page.rebuild_breadcrumbs();
		page
	}

	pub fn current_prefix(&self) -> String {
		self
			.path
			.borrow()
			.last()
			.map(|(_, real)| real.clone())
			.unwrap_or_default()
	}

	pub fn reset_to_root(&self) {
		self.search.set_text("");
		*self.path.borrow_mut() = vec![(String::new(), String::new())];
		self.entries.borrow_mut().clear();
		self.rebuild_store();
		self.request_list();
	}

	pub fn request_list(&self) {
		let generation = self.list_generation.get() + 1;
		self.list_generation.set(generation);
		self.list_pending.set(true);
		let _ = self.cmd.send_blocking(Command::List {
			prefix: self.current_prefix(),
		});
		self.rebuild_breadcrumbs();

		// Show the spinner only if the listing takes a moment - instant
		// responses shouldn't flicker.
		let weak = self.weak_self.clone();
		glib::timeout_add_local_once(std::time::Duration::from_millis(150), move || {
			if let Some(p) = weak.upgrade() {
				if p.list_pending.get() && p.list_generation.get() == generation {
					p.loading.set_visible(true);
					p.loading.set_spinning(true);
				}
			}
		});
	}

	fn finish_loading(&self) {
		self.list_pending.set(false);
		self.loading.set_spinning(false);
		self.loading.set_visible(false);
	}

	/// Called from the event loop when a listing request failed.
	pub fn listing_failed(&self) {
		self.finish_loading();
	}

	/// Called from the event loop when a listing arrives.
	pub fn set_listing(&self, prefix: &str, entries: Vec<RemoteEntry>) {
		if prefix != self.current_prefix() {
			return; // stale response from an earlier navigation
		}
		self.finish_loading();
		*self.entries.borrow_mut() = entries;
		self.rebuild_store();
	}

	fn filtered(&self) -> Vec<RemoteEntry> {
		let needle = self.search.text().to_lowercase();
		self
			.entries
			.borrow()
			.iter()
			.filter(|e| needle.is_empty() || e.name.to_lowercase().contains(&needle))
			.cloned()
			.collect()
	}

	fn rebuild_store(&self) {
		let filtered = self.filtered();
		let has_items = !filtered.is_empty();
		self.store.remove_all();
		for e in filtered {
			self.store.append(&glib::BoxedAnyObject::new(e));
		}
		self.empty.set_visible(!has_items);
		self.list_scroll.set_visible(has_items);
	}

	fn rebuild_breadcrumbs(&self) {
		while let Some(child) = self.breadcrumbs.first_child() {
			self.breadcrumbs.remove(&child);
		}
		let path = self.path.borrow().clone();
		let last = path.len() - 1;
		for (i, (display, _)) in path.iter().enumerate() {
			if i > 0 {
				self.breadcrumbs.append(&gtk::Label::new(Some("›")));
			}
			let btn = gtk::Button::with_label(if i == 0 { "Bucket" } else { display });
			btn.add_css_class("flat");
			if i == last {
				btn.add_css_class("heading");
			}
			let weak = self.weak_self.clone();
			btn.connect_clicked(move |_| {
				if let Some(p) = weak.upgrade() {
					p.search.set_text("");
					p.path.borrow_mut().truncate(i + 1);
					p.request_list();
				}
			});

			let real_prefix = self.path.borrow()[i].1.clone();
			let drop = gtk::DropTarget::new(String::static_type(), gdk::DragAction::MOVE);
			let weak = self.weak_self.clone();
			drop.connect_drop(move |_, value, _, _| {
				let Ok(key) = value.get::<String>() else {
					return false;
				};
				if let Some(p) = weak.upgrade() {
					p.perform_move(&key, real_prefix.clone());
					return true;
				}
				false
			});
			btn.add_controller(drop);

			self.breadcrumbs.append(&btn);
		}
	}

	fn selected(&self) -> Vec<RemoteEntry> {
		let mut out = Vec::new();
		for i in 0..self.selection.n_items() {
			if self.selection.is_selected(i) {
				if let Some(obj) = self
					.selection
					.item(i)
					.and_downcast::<glib::BoxedAnyObject>()
				{
					out.push(obj.borrow::<RemoteEntry>().clone());
				}
			}
		}
		out
	}

	fn pick_files_and_upload(&self) {
		let Some(window) = self.window.upgrade() else {
			return;
		};
		let Some(p) = self.weak_self.upgrade() else {
			return;
		};
		let dialog = gtk::FileDialog::new();
		dialog.open_multiple(Some(&window), gio::Cancellable::NONE, move |res| {
			if let Ok(model) = res {
				let mut paths = Vec::new();
				for i in 0..model.n_items() {
					if let Some(file) = model.item(i).and_downcast::<gio::File>() {
						if let Some(path) = file.path() {
							paths.push(path);
						}
					}
				}
				if !paths.is_empty() {
					let _ = p.cmd.send_blocking(Command::Upload {
						paths,
						dest_prefix: p.current_prefix(),
					});
				}
			}
		});
	}

	/// Pick one or more local folders; everything inside uploads recursively,
	/// preserving the folder structure under the current remote directory.
	fn pick_folders_and_upload(&self) {
		let Some(window) = self.window.upgrade() else {
			return;
		};
		let Some(p) = self.weak_self.upgrade() else {
			return;
		};
		let dialog = gtk::FileDialog::new();
		dialog.select_multiple_folders(Some(&window), gio::Cancellable::NONE, move |res| {
			if let Ok(model) = res {
				let mut paths = Vec::new();
				for i in 0..model.n_items() {
					if let Some(file) = model.item(i).and_downcast::<gio::File>() {
						if let Some(path) = file.path() {
							paths.push(path);
						}
					}
				}
				if !paths.is_empty() {
					let _ = p.cmd.send_blocking(Command::Upload {
						paths,
						dest_prefix: p.current_prefix(),
					});
				}
			}
		});
	}

	fn new_folder_dialog(&self) {
		let Some(window) = self.window.upgrade() else {
			return;
		};
		let Some(p) = self.weak_self.upgrade() else {
			return;
		};

		let entry = adw::EntryRow::builder().title("Folder name").build();
		let list = gtk::ListBox::new();
		list.add_css_class("boxed-list");
		list.append(&entry);

		let dialog = adw::AlertDialog::new(Some("New folder"), None);
		dialog.set_extra_child(Some(&list));
		dialog.add_response("cancel", "Cancel");
		dialog.add_response("create", "Create");
		dialog.set_response_appearance("create", adw::ResponseAppearance::Suggested);
		dialog.set_default_response(Some("create"));
		dialog.set_close_response("cancel");

		// Live-validate: Create stays disabled until the name is usable.
		let valid = |name: &str| !name.is_empty() && !name.contains('/') && name != "." && name != "..";
		dialog.set_response_enabled("create", false);
		let d = dialog.clone();
		entry.connect_changed(move |e| {
			d.set_response_enabled("create", valid(e.text().trim()));
		});

		let e = entry.clone();
		dialog.connect_response(Some("create"), move |_, _| {
			let name = e.text().trim().to_string();
			if valid(&name) {
				let _ = p.cmd.send_blocking(Command::CreateFolder {
					prefix: p.current_prefix(),
					name,
				});
			}
		});
		dialog.present(Some(&window));
	}

	fn download_selected(&self) {
		self.download_items(self.selected());
	}

	fn download_items(&self, items: Vec<RemoteEntry>) {
		if items.is_empty() {
			return;
		}
		let Some(window) = self.window.upgrade() else {
			return;
		};
		let Some(p) = self.weak_self.upgrade() else {
			return;
		};
		let dialog = gtk::FileDialog::new();
		dialog.set_title("Choose download destination");
		dialog.select_folder(Some(&window), gio::Cancellable::NONE, move |res| {
			if let Ok(folder) = res {
				if let Some(dest) = folder.path() {
					let _ = p.cmd.send_blocking(Command::Download {
						items: items.clone(),
						dest,
					});
				}
			}
		});
	}

	fn confirm_delete_selected(&self) {
		self.confirm_delete_items(self.selected());
	}

	fn confirm_delete_items(&self, items: Vec<RemoteEntry>) {
		if items.is_empty() {
			return;
		}
		let Some(window) = self.window.upgrade() else {
			return;
		};
		let dialog = adw::AlertDialog::new(
			Some("Delete objects?"),
			Some(&format!(
				"{} item(s) will be permanently deleted from the bucket.",
				items.len()
			)),
		);
		dialog.add_response("cancel", "Cancel");
		dialog.add_response("delete", "Delete");
		dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
		dialog.set_default_response(Some("cancel"));
		let Some(p) = self.weak_self.upgrade() else {
			return;
		};
		dialog.connect_response(Some("delete"), move |_, _| {
			let _ = p.cmd.send_blocking(Command::Delete {
				items: items.clone(),
			});
		});
		dialog.present(Some(&window));
	}

	fn show_row_menu(&self, entry: RemoteEntry, anchor: &impl IsA<gtk::Widget>, x: f64, y: f64) {
		let btn_dl = menu_row("folder-download-symbolic", "Download");
		let btn_del = menu_row("user-trash-symbolic", "Delete");
		let menu = gtk::Box::new(gtk::Orientation::Vertical, 0);
		menu.append(&btn_dl);
		menu.append(&btn_del);

		let popover = gtk::Popover::new();
		popover.set_child(Some(&menu));
		popover.set_parent(anchor);
		popover.set_pointing_to(Some(&gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
		popover.connect_closed(|pop| pop.unparent());

		let p = self.weak_self.clone();
		let e = entry.clone();
		let pop = popover.clone();
		btn_dl.connect_clicked(move |_| {
			pop.popdown();
			if let Some(p) = p.upgrade() {
				p.download_items(vec![e.clone()]);
			}
		});
		let p = self.weak_self.clone();
		let pop = popover.clone();
		btn_del.connect_clicked(move |_| {
			pop.popdown();
			if let Some(p) = p.upgrade() {
				p.confirm_delete_items(vec![entry.clone()]);
			}
		});

		popover.popup();
	}

	fn entry_by_key(&self, key: &str) -> Option<RemoteEntry> {
		self.entries.borrow().iter().find(|e| e.key == key).cloned()
	}

	/// Move the dragged row (or the whole selection, if the dragged row is part
	/// of a multi-selection) into `dest_prefix`.
	fn perform_move(&self, dragged_key: &str, dest_prefix: String) {
		let sel = self.selected();
		let mut items = if sel.len() > 1 && sel.iter().any(|e| e.key == dragged_key) {
			sel
		} else if let Some(e) = self.entry_by_key(dragged_key) {
			vec![e]
		} else {
			return;
		};
		// Never move the destination folder into itself.
		let dest = dest_prefix.trim_end_matches('/').to_string();
		items.retain(|e| e.key.trim_end_matches('/') != dest);
		if items.is_empty() {
			return;
		}
		let _ = self.cmd.send_blocking(Command::Move { items, dest_prefix });
	}

	pub fn transfer_started(&self, total_files: u64, total_bytes: u64, files: Vec<FileProgress>) {
		self.total_files.set(total_files);
		self.total_bytes.set(total_bytes);
		self.bytes_done.set(0);
		self.global_speed_bps.set(0.0);
		self.bar_progress.set_fraction(0.0);

		self.transfer_store.remove_all();
		let mut index = self.transfer_index.borrow_mut();
		index.clear();
		for (i, f) in files.into_iter().enumerate() {
			index.insert(f.name.clone(), i as u32);
			self
				.transfer_store
				.append(&glib::BoxedAnyObject::new(TransferItem {
					name: f.name,
					total: f.total,
					done: 0,
					state: ItemState::Queued,
					speed_bps: 0.0,
				}));
		}
		self.update_stats_widgets();
		self.bar.set_reveal_child(true);
	}

	pub fn transfer_progress(
		&self,
		done: u64,
		failed: u64,
		bytes: u64,
		files: Vec<FileProgress>,
		finished: Option<(String, bool)>,
	) {
		let total_f = self.total_files.get().max(1);
		let total_b = self.total_bytes.get();
		let fraction = if total_b > 0 {
			(bytes as f64 / total_b as f64).clamp(0.0, 1.0)
		} else {
			((done + failed) as f64 / total_f as f64).clamp(0.0, 1.0)
		};
		self.bar_progress.set_fraction(fraction);
		self.bytes_done.set(bytes);
		self
			.global_speed_bps
			.set(files.iter().map(|f| f.speed_bps).sum());
		self.update_stats_widgets();

		for f in files {
			self.update_transfer_item(&f.name, |item| {
				item.done = f.done;
				item.speed_bps = f.speed_bps;
				item.state = ItemState::Active;
			});
		}
		if let Some((name, ok)) = finished {
			self.update_transfer_item(&name, |item| {
				item.state = if ok {
					ItemState::Done
				} else {
					ItemState::Failed
				};
				if ok {
					item.done = item.total;
				}
				item.speed_bps = 0.0;
			});
		}
	}

	pub fn transfer_finished(&self) {
		self.bar.set_reveal_child(false);
		self.transfer_store.remove_all();
		self.transfer_index.borrow_mut().clear();
		self.global_speed_bps.set(0.0);
		self.update_stats_widgets();
		self.request_list();
	}

	fn update_stats_widgets(&self) {
		let Some(w) = &*self.stats_widgets.borrow() else {
			return;
		};
		let speed = self.global_speed_bps.get();
		w.speed.set_text(&if speed > 0.0 {
			format!("{:.1} Mbps", speed * 8.0 / 1_000_000.0)
		} else {
			"-".to_string()
		});
		w.transferred.set_text(&format!(
			"{} / {}",
			human_size(self.bytes_done.get()),
			human_size(self.total_bytes.get())
		));
		let remaining = self.total_bytes.get().saturating_sub(self.bytes_done.get());
		w.eta.set_text(&if speed > 0.0 && remaining > 0 {
			human_eta(remaining as f64 / speed)
		} else {
			"-".to_string()
		});
	}

	/// Replace one row's data in place. The splice keeps the row position, so
	/// an open dialog updates without losing the user's scroll position.
	fn update_transfer_item(&self, name: &str, apply: impl FnOnce(&mut TransferItem)) {
		let Some(pos) = self.transfer_index.borrow().get(name).copied() else {
			return;
		};
		let Some(obj) = self
			.transfer_store
			.item(pos)
			.and_downcast::<glib::BoxedAnyObject>()
		else {
			return;
		};
		let mut item = obj.borrow::<TransferItem>().clone();
		apply(&mut item);
		self
			.transfer_store
			.splice(pos, 1, &[glib::BoxedAnyObject::new(item)]);
	}

	fn show_transfers_dialog(&self) {
		let Some(window) = self.window.upgrade() else {
			return;
		};

		let factory = gtk::SignalListItemFactory::new();
		factory.connect_setup(|_, item| {
			let item = item.downcast_ref::<gtk::ListItem>().unwrap();
			let status = gtk::Label::new(None);
			status.set_xalign(0.0);
			status.add_css_class("caption");
			status.add_css_class("numeric");
			let name = gtk::Label::new(None);
			name.set_xalign(0.0);
			name.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
			let bar = gtk::ProgressBar::new();
			bar.set_show_text(true);
			let row = gtk::Box::new(gtk::Orientation::Vertical, 4);
			row.set_margin_start(14);
			row.set_margin_end(14);
			row.set_margin_top(8);
			row.set_margin_bottom(8);
			row.append(&status);
			row.append(&name);
			row.append(&bar);
			item.set_child(Some(&row));
		});
		factory.connect_bind(|_, item| {
			let item = item.downcast_ref::<gtk::ListItem>().unwrap();
			let Some(obj) = item.item().and_downcast::<glib::BoxedAnyObject>() else {
				return;
			};
			let data = obj.borrow::<TransferItem>();
			let row = item.child().and_downcast::<gtk::Box>().unwrap();
			let status = row.first_child().and_downcast::<gtk::Label>().unwrap();
			let name = status.next_sibling().and_downcast::<gtk::Label>().unwrap();
			let bar = row.last_child().and_downcast::<gtk::ProgressBar>().unwrap();

			name.set_text(&data.name);
			name.set_tooltip_text(Some(&data.name));

			for class in ["dim-label", "success", "error"] {
				status.remove_css_class(class);
			}
			match data.state {
				ItemState::Queued => {
					status.set_text("Waiting");
					status.add_css_class("dim-label");
					bar.set_fraction(0.0);
					bar.set_text(Some(""));
				}
				ItemState::Active => {
					if data.speed_bps > 0.0 {
						let mut text = format!("{:.1} Mbps", data.speed_bps * 8.0 / 1_000_000.0);
						if data.total > data.done {
							let eta = (data.total - data.done) as f64 / data.speed_bps;
							text.push_str(&format!(" · {} left", human_eta(eta)));
						}
						status.set_text(&text);
					} else {
						status.set_text("..."); // first second: no full window measured yet
					}
					let fraction = if data.total > 0 {
						(data.done as f64 / data.total as f64).clamp(0.0, 1.0)
					} else {
						0.0
					};
					bar.set_fraction(fraction);
					bar.set_text(Some(&format!(
						"{} / {}  ({:.0}%)",
						human_size(data.done),
						human_size(data.total),
						fraction * 100.0
					)));
				}
				ItemState::Done => {
					status.set_text("Done");
					status.add_css_class("success");
					bar.set_fraction(1.0);
					bar.set_text(Some(&human_size(data.total)));
				}
				ItemState::Failed => {
					status.set_text("Failed");
					status.add_css_class("error");
					bar.set_text(Some(""));
				}
			}
		});

		let selection = gtk::NoSelection::new(Some(self.transfer_store.clone()));
		let view = gtk::ListView::new(Some(selection), Some(factory));
		view.set_vexpand(true);

		let scroller = gtk::ScrolledWindow::builder()
			.hscrollbar_policy(gtk::PolicyType::Never)
			.vexpand(true)
			.child(&view)
			.build();

		let empty_note = gtk::Label::new(Some("No active transfers"));
		empty_note.add_css_class("dim-label");
		empty_note.set_halign(gtk::Align::Center);
		empty_note.set_valign(gtk::Align::Center);
		empty_note.set_visible(self.transfer_store.n_items() == 0);
		let note = empty_note.clone();
		self
			.transfer_store
			.connect_items_changed(move |store, _, _, _| {
				note.set_visible(store.n_items() == 0);
			});

		let overlay = gtk::Overlay::new();
		overlay.set_child(Some(&scroller));
		overlay.add_overlay(&empty_note);

		let stat = |title: &str| -> (gtk::Box, gtk::Label) {
			let caption = gtk::Label::new(Some(title));
			caption.add_css_class("caption");
			caption.add_css_class("dim-label");
			let value = gtk::Label::new(Some("-"));
			value.add_css_class("title-4");
			value.add_css_class("numeric");
			let block = gtk::Box::new(gtk::Orientation::Vertical, 2);
			block.set_hexpand(true);
			block.append(&caption);
			block.append(&value);
			(block, value)
		};
		let (b_speed, speed) = stat("Total speed");
		let (b_transferred, transferred) = stat("Transferred");
		let (b_eta, eta) = stat("Time left");
		let stats_box = gtk::Box::new(gtk::Orientation::Horizontal, 12);
		stats_box.set_margin_start(18);
		stats_box.set_margin_end(18);
		stats_box.set_margin_top(10);
		stats_box.set_margin_bottom(10);
		stats_box.append(&b_speed);
		stats_box.append(&b_transferred);
		stats_box.append(&b_eta);

		let content = gtk::Box::new(gtk::Orientation::Vertical, 0);
		content.append(&stats_box);
		content.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
		content.append(&overlay);

		let header = adw::HeaderBar::new();
		header.set_title_widget(Some(&adw::WindowTitle::new("Transfers", "")));
		let toolbar = adw::ToolbarView::new();
		toolbar.add_top_bar(&header);
		toolbar.set_content(Some(&content));

		*self.stats_widgets.borrow_mut() = Some(StatsWidgets {
			speed,
			transferred,
			eta,
		});
		let weak = self.weak_self.clone();

		let dialog = adw::Dialog::new();
		dialog.set_title("Transfers");
		dialog.set_content_width(680);
		dialog.set_content_height(620);
		dialog.set_child(Some(&toolbar));
		dialog.connect_closed(move |_| {
			if let Some(p) = weak.upgrade() {
				*p.stats_widgets.borrow_mut() = None;
			}
		});
		self.update_stats_widgets();
		dialog.present(Some(&window));
	}
}

/// Column sorter over `RemoteEntry` values. Directories group before files;
/// within each group the provided comparator applies. (With descending order
/// GTK inverts the whole comparison, so the groups swap too - standard
/// ColumnView behaviour.)
fn entry_sorter(
	cmp: impl Fn(&RemoteEntry, &RemoteEntry) -> std::cmp::Ordering + 'static,
) -> gtk::CustomSorter {
	gtk::CustomSorter::new(move |a, b| {
		let (Some(a), Some(b)) = (
			a.downcast_ref::<glib::BoxedAnyObject>(),
			b.downcast_ref::<glib::BoxedAnyObject>(),
		) else {
			return gtk::Ordering::Equal;
		};
		let a = a.borrow::<RemoteEntry>();
		let b = b.borrow::<RemoteEntry>();
		b.is_dir.cmp(&a.is_dir).then_with(|| cmp(&a, &b)).into()
	})
}

/// A flat button with a left-aligned icon + label, for use inside popovers.
fn menu_row(icon: &str, label: &str) -> gtk::Button {
	let content = gtk::Box::new(gtk::Orientation::Horizontal, 10);
	content.append(&gtk::Image::from_icon_name(icon));
	let l = gtk::Label::new(Some(label));
	l.set_xalign(0.0);
	l.set_hexpand(true);
	content.append(&l);
	let b = gtk::Button::new();
	b.set_child(Some(&content));
	b.add_css_class("flat");
	b
}

fn icon_button(icon: &str, tooltip: &str) -> gtk::Button {
	let b = gtk::Button::from_icon_name(icon);
	b.set_tooltip_text(Some(tooltip));
	b.add_css_class("flat");
	b
}

fn name_column(ctx: Rc<RefCell<std::rc::Weak<BrowserPage>>>) -> gtk::ColumnViewColumn {
	let factory = gtk::SignalListItemFactory::new();
	factory.connect_setup(move |_, item| {
		let item = item.downcast_ref::<gtk::ListItem>().unwrap();
		let hbox = gtk::Box::new(gtk::Orientation::Horizontal, 8);
		let icon = gtk::Image::new();
		let label = gtk::Label::new(None);
		label.set_xalign(0.0);
		label.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
		hbox.append(&icon);
		hbox.append(&label);

		// Right-click context menu.
		let gesture = gtk::GestureClick::new();
		gesture.set_button(gdk::BUTTON_SECONDARY);
		let ctx_menu = ctx.clone();
		let item_menu = item.downgrade();
		let hbox_menu = hbox.downgrade();
		gesture.connect_pressed(move |g, _, x, y| {
			g.set_state(gtk::EventSequenceState::Claimed);
			let (Some(item), Some(hbox)) = (item_menu.upgrade(), hbox_menu.upgrade()) else {
				return;
			};
			let Some(obj) = item.item().and_downcast::<glib::BoxedAnyObject>() else {
				return;
			};
			let entry = obj.borrow::<RemoteEntry>().clone();
			if let Some(page) = ctx_menu.borrow().upgrade() {
				page.show_row_menu(entry, &hbox, x, y);
			}
		});
		hbox.add_controller(gesture);

		// Drag source: carries the dragged row's real key.
		let drag = gtk::DragSource::new();
		drag.set_actions(gdk::DragAction::MOVE);
		let item_drag = item.downgrade();
		drag.connect_prepare(move |_, _, _| {
			let item = item_drag.upgrade()?;
			let obj = item.item().and_downcast::<glib::BoxedAnyObject>()?;
			let key = obj.borrow::<RemoteEntry>().key.clone();
			Some(gdk::ContentProvider::for_value(&key.to_value()))
		});
		let hbox_icon = hbox.downgrade();
		drag.connect_drag_begin(move |src, _| {
			if let Some(h) = hbox_icon.upgrade() {
				let paintable = gtk::WidgetPaintable::new(Some(&h));
				src.set_icon(Some(&paintable), 0, 0);
			}
		});
		hbox.add_controller(drag);

		// Drop target: only folders accept, and only internal key payloads.
		let drop = gtk::DropTarget::new(String::static_type(), gdk::DragAction::MOVE);
		let item_accept = item.downgrade();
		drop.connect_accept(move |_, _| {
			item_accept
				.upgrade()
				.and_then(|i| i.item().and_downcast::<glib::BoxedAnyObject>())
				.map(|o| o.borrow::<RemoteEntry>().is_dir)
				.unwrap_or(false)
		});
		let hbox_enter = hbox.downgrade();
		drop.connect_enter(move |_, _, _| {
			if let Some(h) = hbox_enter.upgrade() {
				h.add_css_class("drop-into");
			}
			gdk::DragAction::MOVE
		});
		let hbox_leave = hbox.downgrade();
		drop.connect_leave(move |_| {
			if let Some(h) = hbox_leave.upgrade() {
				h.remove_css_class("drop-into");
			}
		});
		let ctx_drop = ctx.clone();
		let item_drop = item.downgrade();
		let hbox_drop = hbox.downgrade();
		drop.connect_drop(move |_, value, _, _| {
			if let Some(h) = hbox_drop.upgrade() {
				h.remove_css_class("drop-into");
			}
			let Ok(key) = value.get::<String>() else {
				return false;
			};
			let (Some(item), Some(page)) = (item_drop.upgrade(), ctx_drop.borrow().upgrade()) else {
				return false;
			};
			let Some(obj) = item.item().and_downcast::<glib::BoxedAnyObject>() else {
				return false;
			};
			let dest = obj.borrow::<RemoteEntry>();
			if !dest.is_dir || dest.key == key {
				return false;
			}
			page.perform_move(&key, dest.key.clone());
			true
		});
		hbox.add_controller(drop);

		item.set_child(Some(&hbox));
	});
	factory.connect_bind(|_, item| {
		let item = item.downcast_ref::<gtk::ListItem>().unwrap();
		let Some(obj) = item.item().and_downcast::<glib::BoxedAnyObject>() else {
			return;
		};
		let entry = obj.borrow::<RemoteEntry>();
		let hbox = item.child().and_downcast::<gtk::Box>().unwrap();
		let icon = hbox.first_child().and_downcast::<gtk::Image>().unwrap();
		let label = hbox.last_child().and_downcast::<gtk::Label>().unwrap();
		let lower = entry.name.to_lowercase();
		icon.set_icon_name(Some(if entry.is_dir {
			"folder-symbolic"
		} else if [".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif"]
			.iter()
			.any(|x| lower.ends_with(x))
		{
			"image-x-generic-symbolic"
		} else {
			"text-x-generic-symbolic"
		}));
		icon.remove_css_class("icon-encrypted");
		icon.remove_css_class("icon-unencrypted");
		match entry.encrypted {
			Some(true) => icon.add_css_class("icon-encrypted"),
			Some(false) => icon.add_css_class("icon-unencrypted"),
			None => {}
		}
		label.set_text(&entry.name);
	});
	gtk::ColumnViewColumn::builder()
		.title("Name")
		.factory(&factory)
		.expand(true)
		.build()
}

fn text_column(
	title: &str,
	width: i32,
	text: impl Fn(&RemoteEntry) -> String + 'static,
) -> gtk::ColumnViewColumn {
	let factory = gtk::SignalListItemFactory::new();
	factory.connect_setup(|_, item| {
		let item = item.downcast_ref::<gtk::ListItem>().unwrap();
		let label = gtk::Label::new(None);
		label.set_xalign(0.0);
		label.add_css_class("dim-label");
		label.add_css_class("numeric");
		item.set_child(Some(&label));
	});
	factory.connect_bind(move |_, item| {
		let item = item.downcast_ref::<gtk::ListItem>().unwrap();
		let Some(obj) = item.item().and_downcast::<glib::BoxedAnyObject>() else {
			return;
		};
		let entry = obj.borrow::<RemoteEntry>();
		let label = item.child().and_downcast::<gtk::Label>().unwrap();
		label.set_text(&text(&entry));
	});
	gtk::ColumnViewColumn::builder()
		.title(title)
		.factory(&factory)
		.fixed_width(width)
		.build()
}
