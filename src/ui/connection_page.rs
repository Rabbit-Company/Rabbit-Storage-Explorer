//! Connection manager. Two views inside one page:
//!
//! * **list** - saved connections; click to connect (E2EE profiles prompt for
//!   the encryption password), with per-row edit and delete.
//! * **form** - add or edit a connection.

use crate::settings::{self, BackendKind, ConnectionProfile};
use crate::worker::Command;
use adw::prelude::*;
use gtk::glib;
use std::cell::RefCell;
use std::rc::Rc;

pub struct ConnectionPage {
	weak_self: std::rc::Weak<ConnectionPage>,
	pub root: gtk::Widget,
	cmd: async_channel::Sender<Command>,
	window: glib::WeakRef<adw::ApplicationWindow>,

	stack: gtk::Stack,
	profiles_list: gtk::ListBox,
	list_empty_note: gtk::Label,
	spinner_list: gtk::Spinner,
	spinner_form: gtk::Spinner,

	// form
	editing: RefCell<Option<String>>, // original name when editing
	form_title: gtk::Label,
	kind_combo: adw::ComboRow,
	name: adw::EntryRow,
	// S3
	s3_group: adw::PreferencesGroup,
	endpoint: adw::EntryRow,
	bucket: adw::EntryRow,
	access_key: adw::EntryRow,
	// SFTP
	net_group: adw::PreferencesGroup,
	host: adw::EntryRow,
	port: adw::SpinRow,
	username: adw::EntryRow,
	root_path: adw::EntryRow,
	sftp_group: adw::PreferencesGroup,
	key_path: adw::EntryRow,
	nfs_privileged_port: adw::SwitchRow,
	nfs_group: adw::PreferencesGroup,
	nfs_uid: adw::SpinRow,
	nfs_gid: adw::SpinRow,
	smb_group: adw::PreferencesGroup,
	share: adw::EntryRow,
	domain: adw::EntryRow,
	// shared
	secret_key: adw::PasswordEntryRow,
	e2ee: adw::SwitchRow,
	password: adw::PasswordEntryRow,
	remember: adw::SwitchRow,
	connect_btn: gtk::Button,
}

impl ConnectionPage {
	pub fn new(cmd: async_channel::Sender<Command>, window: &adw::ApplicationWindow) -> Rc<Self> {
		// Header and the action button stay pinned; only the connection list
		// in the middle scrolls when the window is small.
		let list_title = gtk::Label::new(Some("Connections"));
		list_title.add_css_class("title-1");
		let list_desc = gtk::Label::new(Some("Pick a saved connection or add a new one"));
		list_desc.add_css_class("dim-label");
		let list_header = gtk::Box::new(gtk::Orientation::Vertical, 6);
		list_header.set_margin_top(24);
		list_header.append(&list_title);
		list_header.append(&list_desc);

		let profiles_list = gtk::ListBox::new();
		profiles_list.add_css_class("boxed-list");
		profiles_list.set_selection_mode(gtk::SelectionMode::None);

		let list_empty_note = gtk::Label::new(Some("No saved connections yet."));
		list_empty_note.add_css_class("dim-label");

		let list_middle = gtk::Box::new(gtk::Orientation::Vertical, 12);
		list_middle.set_margin_top(4);
		list_middle.set_margin_bottom(4);
		list_middle.append(&profiles_list);
		list_middle.append(&list_empty_note);
		let list_scroller = gtk::ScrolledWindow::builder()
			.hscrollbar_policy(gtk::PolicyType::Never)
			.vexpand(true)
			.child(&list_middle)
			.build();

		let btn_add = gtk::Button::with_label("Add connection");
		btn_add.add_css_class("suggested-action");
		btn_add.add_css_class("pill");
		btn_add.set_halign(gtk::Align::Center);
		let spinner_list = gtk::Spinner::new();
		spinner_list.set_halign(gtk::Align::Center);
		let list_bottom = gtk::Box::new(gtk::Orientation::Vertical, 8);
		list_bottom.set_margin_bottom(24);
		list_bottom.append(&btn_add);
		list_bottom.append(&spinner_list);

		let list_box = gtk::Box::new(gtk::Orientation::Vertical, 18);
		list_box.set_margin_start(12);
		list_box.set_margin_end(12);
		list_box.append(&list_header);
		list_box.append(&list_scroller);
		list_box.append(&list_bottom);
		let list_page = adw::Clamp::builder()
			.maximum_size(560)
			.child(&list_box)
			.build();

		let form_title = gtk::Label::new(Some("Add connection"));
		form_title.add_css_class("title-1");
		let form_desc = gtk::Label::new(Some(
			"S3-compatible object storage, NFS, SMB or an SSH server (SFTP)",
		));
		form_desc.add_css_class("dim-label");
		let form_header = gtk::Box::new(gtk::Orientation::Vertical, 6);
		form_header.set_margin_top(24);
		form_header.append(&form_title);
		form_header.append(&form_desc);

		let common_group = adw::PreferencesGroup::new();
		let kind_combo = adw::ComboRow::builder()
			.title("Type")
			.model(&gtk::StringList::new(&[
				"S3-compatible storage",
				"SFTP (SSH)",
				"NFS",
				"SMB / Windows share",
			]))
			.build();
		let name = adw::EntryRow::builder().title("Connection name").build();
		common_group.add(&kind_combo);
		common_group.add(&name);

		let s3_group = adw::PreferencesGroup::builder().title("S3 details").build();
		let endpoint = adw::EntryRow::builder()
			.title("Endpoint URL  (https://s3.example.com)")
			.build();
		let bucket = adw::EntryRow::builder().title("Bucket").build();
		let access_key = adw::EntryRow::builder().title("Access key ID").build();
		s3_group.add(&endpoint);
		s3_group.add(&bucket);
		s3_group.add(&access_key);

		let net_group = adw::PreferencesGroup::builder()
			.title("Server details")
			.build();
		let host = adw::EntryRow::builder().title("Host").build();
		let port = adw::SpinRow::with_range(0.0, 65535.0, 1.0);
		port.set_title("Port");
		port.set_value(22.0);
		let username = adw::EntryRow::builder().title("Username").build();
		let root_path = adw::EntryRow::builder()
			.title("Remote directory  (optional)")
			.build();
		net_group.add(&host);
		net_group.add(&port);
		net_group.add(&username);
		net_group.add(&root_path);

		let sftp_group = adw::PreferencesGroup::new();
		let key_path = adw::EntryRow::builder()
			.title("Private key path  (optional - leave empty for password login)")
			.build();
		sftp_group.add(&key_path);

		let nfs_group = adw::PreferencesGroup::new();
		let nfs_uid = adw::SpinRow::with_range(0.0, u32::MAX as f64, 1.0);
		nfs_uid.set_title("UID");
		nfs_uid.set_subtitle("Unix user id used for NFS AUTH_UNIX access");
		nfs_uid.set_value(1000.0);
		let nfs_gid = adw::SpinRow::with_range(0.0, u32::MAX as f64, 1.0);
		nfs_gid.set_title("GID");
		nfs_gid.set_value(1000.0);
		nfs_group.add(&nfs_uid);
		nfs_group.add(&nfs_gid);
		let nfs_privileged_port = adw::SwitchRow::builder()
			.title("Connect from a privileged port")
			.subtitle(
				"Required by most NFS servers. Turn off inside Flatpak or other \
				 sandboxes that can't bind ports below 1024 (the server must accept \
				 non-privileged clients).",
			)
			.active(true)
			.build();
		nfs_group.add(&nfs_privileged_port);

		let smb_group = adw::PreferencesGroup::new();
		let share = adw::EntryRow::builder().title("Share name").build();
		let domain = adw::EntryRow::builder()
			.title("Domain / workgroup  (optional)")
			.build();
		smb_group.add(&share);
		smb_group.add(&domain);

		// shared credential + options
		let cred_group = adw::PreferencesGroup::new();
		let secret_key = adw::PasswordEntryRow::builder()
			.title("Secret access key")
			.build();
		let remember = adw::SwitchRow::builder()
			.title("Remember this connection")
			.subtitle("The secret is stored in your system keychain")
			.active(true)
			.build();
		cred_group.add(&secret_key);
		cred_group.add(&remember);

		let enc_group = adw::PreferencesGroup::builder()
			.title("End-to-end encryption")
			.build();
		let e2ee = adw::SwitchRow::builder()
			.title("Encrypt files and names")
			.subtitle("Files are encrypted on your machine before upload; only you hold the key")
			.build();
		let password = adw::PasswordEntryRow::builder()
			.title("Encryption password")
			.build();
		password.set_sensitive(false);
		e2ee.connect_active_notify(glib::clone!(
			#[weak]
			password,
			move |row| password.set_sensitive(row.is_active())
		));
		enc_group.add(&e2ee);
		enc_group.add(&password);

		let btn_back = gtk::Button::with_label("Back");
		btn_back.add_css_class("pill");
		let connect_btn = gtk::Button::with_label("Connect");
		connect_btn.add_css_class("suggested-action");
		connect_btn.add_css_class("pill");
		let spinner_form = gtk::Spinner::new();
		spinner_form.set_valign(gtk::Align::Center);
		let btn_row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
		btn_row.set_halign(gtk::Align::Center);
		btn_row.append(&btn_back);
		btn_row.append(&connect_btn);
		btn_row.append(&spinner_form);

		// Header and buttons pinned; the field groups scroll in the middle.
		let form_fields = gtk::Box::new(gtk::Orientation::Vertical, 18);
		form_fields.set_margin_top(4);
		form_fields.set_margin_bottom(4);
		form_fields.append(&common_group);
		form_fields.append(&s3_group);
		form_fields.append(&net_group);
		form_fields.append(&smb_group);
		form_fields.append(&sftp_group);
		form_fields.append(&nfs_group);
		form_fields.append(&cred_group);
		form_fields.append(&enc_group);
		let form_scroller = gtk::ScrolledWindow::builder()
			.hscrollbar_policy(gtk::PolicyType::Never)
			.vexpand(true)
			.child(&form_fields)
			.build();

		btn_row.set_margin_bottom(24);

		let form_box = gtk::Box::new(gtk::Orientation::Vertical, 18);
		form_box.set_margin_start(12);
		form_box.set_margin_end(12);
		form_box.append(&form_header);
		form_box.append(&form_scroller);
		form_box.append(&btn_row);
		let form_page = adw::Clamp::builder()
			.maximum_size(560)
			.child(&form_box)
			.build();

		let stack = gtk::Stack::new();
		stack.set_transition_type(gtk::StackTransitionType::SlideLeftRight);
		stack.add_named(&list_page, Some("list"));
		stack.add_named(&form_page, Some("form"));

		let weak_window = glib::WeakRef::new();
		weak_window.set(Some(window));

		let root: gtk::Widget = stack.clone().upcast();
		let page = Rc::new_cyclic(|weak| Self {
			weak_self: weak.clone(),
			root,
			cmd,
			window: weak_window,
			stack,
			profiles_list,
			list_empty_note,
			spinner_list,
			spinner_form,
			editing: RefCell::new(None),
			form_title,
			kind_combo,
			name,
			s3_group,
			endpoint,
			bucket,
			access_key,
			net_group,
			host,
			port,
			username,
			root_path,
			sftp_group,
			key_path,
			nfs_privileged_port,
			nfs_group,
			nfs_uid,
			nfs_gid,
			smb_group,
			share,
			domain,
			secret_key,
			e2ee,
			password,
			remember,
			connect_btn,
		});

		let p = page.clone();
		page
			.kind_combo
			.connect_selected_notify(move |_| p.update_kind_ui());
		let p = page.clone();
		btn_add.connect_clicked(move |_| {
			p.fill_form(None);
			p.stack.set_visible_child_name("form");
		});
		let p = page.clone();
		btn_back.connect_clicked(move |_| p.show_start_view());
		let p = page.clone();
		page
			.connect_btn
			.connect_clicked(move |_| p.connect_from_form());

		page.reset();
		page
	}

	fn selected_kind(&self) -> BackendKind {
		match self.kind_combo.selected() {
			0 => BackendKind::S3,
			1 => BackendKind::Sftp,
			2 => BackendKind::Nfs,
			_ => BackendKind::Smb,
		}
	}

	fn kind_index(kind: BackendKind) -> u32 {
		match kind {
			BackendKind::S3 => 0,
			BackendKind::Sftp => 1,
			BackendKind::Nfs => 2,
			BackendKind::Smb => 3,
		}
	}

	fn update_kind_ui(&self) {
		let kind = self.selected_kind();
		self.s3_group.set_visible(kind == BackendKind::S3);
		self.net_group.set_visible(kind != BackendKind::S3);
		self.sftp_group.set_visible(kind == BackendKind::Sftp);
		self.nfs_group.set_visible(kind == BackendKind::Nfs);
		self.smb_group.set_visible(kind == BackendKind::Smb);
		// NFSv3 with AUTH_UNIX has neither usernames nor passwords.
		self
			.username
			.set_visible(kind == BackendKind::Sftp || kind == BackendKind::Smb);
		self.secret_key.set_visible(kind != BackendKind::Nfs);
		self.secret_key.set_title(match kind {
			BackendKind::S3 => "Secret access key",
			BackendKind::Sftp => "Password or key passphrase",
			BackendKind::Smb => "Password",
			BackendKind::Nfs => "",
		});
		self.root_path.set_title(match kind {
			BackendKind::Sftp => "Remote directory  (optional - defaults to the home directory)",
			BackendKind::Nfs => "Export path  (required, e.g. /srv/nfs/share)",
			BackendKind::Smb => "Directory inside the share  (optional)",
			BackendKind::S3 => "",
		});
		self.port.set_subtitle(if kind == BackendKind::Nfs {
			"0 = automatic (portmapper)"
		} else {
			""
		});
		let default_port = match kind {
			BackendKind::Sftp => 22.0,
			BackendKind::Smb => 445.0,
			BackendKind::Nfs => 0.0,
			BackendKind::S3 => self.port.value(),
		};
		self.port.set_value(default_port);
	}

	/// Refresh the saved-connections list and show the appropriate view.
	pub fn reset(&self) {
		self.rebuild_profile_rows();
		self.show_start_view();
	}

	fn show_start_view(&self) {
		let has_profiles = !ConnectionProfile::load_all().is_empty();
		self.rebuild_profile_rows();
		self
			.stack
			.set_visible_child_name(if has_profiles { "list" } else { "form" });
		if !has_profiles {
			self.fill_form(None);
		}
	}

	fn rebuild_profile_rows(&self) {
		while let Some(child) = self.profiles_list.first_child() {
			self.profiles_list.remove(&child);
		}
		let profiles = ConnectionProfile::load_all();
		self.list_empty_note.set_visible(profiles.is_empty());
		self.profiles_list.set_visible(!profiles.is_empty());

		for profile in profiles {
			let subtitle = match profile.kind {
				BackendKind::S3 => format!("{} · {}", profile.bucket, profile.endpoint),
				BackendKind::Sftp => format!(
					"{}@{}:{} · {}",
					profile.username,
					profile.host,
					profile.port,
					if profile.root_path.is_empty() {
						"~"
					} else {
						&profile.root_path
					}
				),
				BackendKind::Nfs => format!("{}:{}", profile.host, profile.root_path),
				BackendKind::Smb => format!("{}@{}/{}", profile.username, profile.host, profile.share),
			};
			let row = adw::ActionRow::builder()
				.title(&profile.name)
				.subtitle(subtitle)
				.activatable(true)
				.build();
			row.add_prefix(&gtk::Image::from_icon_name(if profile.e2ee {
				"channel-secure-symbolic"
			} else {
				match profile.kind {
					BackendKind::S3 => "network-server-symbolic",
					BackendKind::Sftp => "utilities-terminal-symbolic",
					BackendKind::Nfs => "folder-remote-symbolic",
					BackendKind::Smb => "network-workgroup-symbolic",
				}
			}));

			let btn_edit = gtk::Button::from_icon_name("document-edit-symbolic");
			btn_edit.set_tooltip_text(Some("Edit"));
			btn_edit.add_css_class("flat");
			btn_edit.set_valign(gtk::Align::Center);
			let weak = self.weak_self.clone();
			let prof = profile.clone();
			btn_edit.connect_clicked(move |_| {
				if let Some(p) = weak.upgrade() {
					p.fill_form(Some(&prof));
					p.stack.set_visible_child_name("form");
				}
			});

			let btn_delete = gtk::Button::from_icon_name("user-trash-symbolic");
			btn_delete.set_tooltip_text(Some("Delete connection"));
			btn_delete.add_css_class("flat");
			btn_delete.set_valign(gtk::Align::Center);
			let weak = self.weak_self.clone();
			let name = profile.name.clone();
			btn_delete.connect_clicked(move |_| {
				if let Some(p) = weak.upgrade() {
					p.confirm_delete(&name);
				}
			});

			row.add_suffix(&btn_edit);
			row.add_suffix(&btn_delete);
			row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));

			let weak = self.weak_self.clone();
			let prof = profile.clone();
			row.connect_activated(move |_| {
				if let Some(p) = weak.upgrade() {
					p.connect_saved(&prof);
				}
			});
			self.profiles_list.append(&row);
		}
	}

	fn confirm_delete(&self, name: &str) {
		let Some(window) = self.window.upgrade() else {
			return;
		};
		let dialog = adw::AlertDialog::new(
			Some("Delete connection?"),
			Some(&format!(
				"“{name}” and its stored secret will be removed. Nothing on the server is deleted."
			)),
		);
		dialog.add_response("cancel", "Cancel");
		dialog.add_response("delete", "Delete");
		dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
		dialog.set_default_response(Some("cancel"));
		let weak = self.weak_self.clone();
		let name = name.to_string();
		dialog.connect_response(Some("delete"), move |_, _| {
			ConnectionProfile::remove(&name);
			if let Some(p) = weak.upgrade() {
				p.rebuild_profile_rows();
			}
		});
		dialog.present(Some(&window));
	}

	/// Connect to a saved profile: fetch the secret from the keychain and, for
	/// E2EE profiles, prompt for the encryption password.
	fn connect_saved(&self, profile: &ConnectionProfile) {
		// NFS has no secret; connect (or prompt for the E2EE password) directly.
		if profile.kind == BackendKind::Nfs {
			if profile.e2ee {
				self.prompt_password(profile.clone(), String::new());
			} else {
				self.send_connect(profile.clone(), String::new(), None);
			}
			return;
		}
		let Some(secret) = settings::load_secret(&profile.name) else {
			// Keychain has no entry (different machine, keyring unavailable...):
			// fall back to the form so the user can re-enter the secret.
			self.fill_form(Some(profile));
			self.stack.set_visible_child_name("form");
			self.secret_key.grab_focus();
			return;
		};
		if profile.e2ee {
			self.prompt_password(profile.clone(), secret);
		} else {
			self.send_connect(profile.clone(), secret, None);
		}
	}

	fn prompt_password(&self, profile: ConnectionProfile, secret: String) {
		let Some(window) = self.window.upgrade() else {
			return;
		};
		let entry = adw::PasswordEntryRow::builder()
			.title("Encryption password")
			.build();
		let list = gtk::ListBox::new();
		list.add_css_class("boxed-list");
		list.append(&entry);

		let dialog = adw::AlertDialog::new(
			Some("Unlock encrypted storage"),
			Some(&format!(
				"Enter the encryption password for “{}”.",
				profile.name
			)),
		);
		dialog.set_extra_child(Some(&list));
		dialog.add_response("cancel", "Cancel");
		dialog.add_response("connect", "Connect");
		dialog.set_response_appearance("connect", adw::ResponseAppearance::Suggested);
		dialog.set_default_response(Some("connect"));

		let weak = self.weak_self.clone();
		dialog.connect_response(Some("connect"), move |_, _| {
			let password = entry.text().to_string();
			if password.is_empty() {
				return;
			}
			if let Some(p) = weak.upgrade() {
				p.send_connect(profile.clone(), secret.clone(), Some(password));
			}
		});
		dialog.present(Some(&window));
	}

	/// Connect using the form contents (add / edit path).
	fn connect_from_form(&self) {
		let kind = self.selected_kind();
		let profile = ConnectionProfile {
			name: nonempty_or(&self.name.text(), "default"),
			kind,
			endpoint: self
				.endpoint
				.text()
				.trim()
				.trim_end_matches('/')
				.to_string(),
			bucket: self.bucket.text().trim().to_string(),
			access_key_id: self.access_key.text().trim().to_string(),
			host: self.host.text().trim().to_string(),
			port: self.port.value() as u16,
			username: self.username.text().trim().to_string(),
			key_path: self.key_path.text().trim().to_string(),
			root_path: self.root_path.text().trim().to_string(),
			share: self.share.text().trim().to_string(),
			domain: self.domain.text().trim().to_string(),
			nfs_privileged_port: self.nfs_privileged_port.is_active(),
			nfs_uid: self.nfs_uid.value() as u32,
			nfs_gid: self.nfs_gid.value() as u32,
			e2ee: self.e2ee.is_active(),
		};
		let secret = self.secret_key.text().to_string();

		// Required fields per backend type. For SFTP with a key file the
		// secret (passphrase) may legitimately be empty.
		let mut required: Vec<(&String, gtk::Widget)> = Vec::new();
		match kind {
			BackendKind::S3 => {
				required.push((&profile.endpoint, self.endpoint.clone().upcast()));
				required.push((&profile.bucket, self.bucket.clone().upcast()));
				required.push((&profile.access_key_id, self.access_key.clone().upcast()));
				required.push((&secret, self.secret_key.clone().upcast()));
			}
			BackendKind::Sftp => {
				required.push((&profile.host, self.host.clone().upcast()));
				required.push((&profile.username, self.username.clone().upcast()));
				if profile.key_path.is_empty() {
					required.push((&secret, self.secret_key.clone().upcast()));
				}
			}
			BackendKind::Nfs => {
				required.push((&profile.host, self.host.clone().upcast()));
				required.push((&profile.root_path, self.root_path.clone().upcast()));
			}
			BackendKind::Smb => {
				required.push((&profile.host, self.host.clone().upcast()));
				required.push((&profile.share, self.share.clone().upcast()));
				required.push((&profile.username, self.username.clone().upcast()));
				required.push((&secret, self.secret_key.clone().upcast()));
			}
		}
		for (val, row) in required {
			if val.is_empty() {
				row.grab_focus();
				return;
			}
		}

		let password = if profile.e2ee {
			let p = self.password.text().to_string();
			if p.is_empty() {
				self.password.grab_focus();
				return;
			}
			Some(p)
		} else {
			None
		};

		if self.remember.is_active() {
			// If this was an edit that renamed the profile, drop the old entry.
			if let Some(old) = self.editing.borrow().as_deref() {
				if old != profile.name {
					ConnectionProfile::remove(old);
				}
			}
			ConnectionProfile::upsert(&profile);
			if let Err(e) = settings::store_secret(&profile.name, &secret) {
				eprintln!("keychain unavailable, secret not saved: {e:#}");
			}
		}
		self.send_connect(profile, secret, password);
	}

	fn send_connect(&self, profile: ConnectionProfile, secret: String, password: Option<String>) {
		self.set_busy(true);
		let _ = self.cmd.send_blocking(Command::Connect {
			profile,
			secret_key: secret,
			password,
		});
	}

	fn fill_form(&self, profile: Option<&ConnectionProfile>) {
		*self.editing.borrow_mut() = profile.map(|p| p.name.clone());
		self.form_title.set_text(if profile.is_some() {
			"Edit connection"
		} else {
			"Add connection"
		});
		let blank = ConnectionProfile::default();
		let p = profile.unwrap_or(&blank);
		self.kind_combo.set_selected(Self::kind_index(p.kind));
		self.name.set_text(&p.name);
		self.endpoint.set_text(&p.endpoint);
		self.bucket.set_text(&p.bucket);
		self.access_key.set_text(&p.access_key_id);
		self.host.set_text(&p.host);
		self.username.set_text(&p.username);
		self.key_path.set_text(&p.key_path);
		self.root_path.set_text(&p.root_path);
		self.share.set_text(&p.share);
		self.domain.set_text(&p.domain);
		self.nfs_privileged_port.set_active(p.nfs_privileged_port);
		self.nfs_uid.set_value(p.nfs_uid as f64);
		self.nfs_gid.set_value(p.nfs_gid as f64);
		self.e2ee.set_active(p.e2ee);
		self.password.set_text("");
		self.secret_key.set_text(
			&profile
				.and_then(|p| settings::load_secret(&p.name))
				.unwrap_or_default(),
		);
		self.update_kind_ui();
		self.port.set_value(p.port as f64);
	}

	pub fn set_busy(&self, busy: bool) {
		self.connect_btn.set_sensitive(!busy);
		self.profiles_list.set_sensitive(!busy);
		self.spinner_form.set_spinning(busy);
		self.spinner_list.set_spinning(busy);
	}
}

fn nonempty_or(s: &str, fallback: &str) -> String {
	let t = s.trim();
	if t.is_empty() {
		fallback.to_string()
	} else {
		t.to_string()
	}
}
