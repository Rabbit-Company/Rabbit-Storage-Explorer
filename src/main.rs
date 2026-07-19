mod crypto;
mod settings;
mod storage;
mod ui;
mod worker;

use adw::prelude::*;
use gtk::{gdk, glib};

const APP_ID: &str = "com.rabbit_company.RabbitStorageExplorer";

fn main() -> glib::ExitCode {
	let app = adw::Application::builder().application_id(APP_ID).build();
	app.connect_startup(|_| load_css());
	app.connect_activate(ui::window::build);
	app.run()
}

fn load_css() {
	let provider = gtk::CssProvider::new();
	provider.load_from_data(include_str!("style.css"));
	if let Some(display) = gdk::Display::default() {
		gtk::style_context_add_provider_for_display(
			&display,
			&provider,
			gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
		);
	}
}
