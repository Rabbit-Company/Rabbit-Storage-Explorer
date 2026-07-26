use gtk::glib;
use gtk::prelude::*;
use gtk::subclass::prelude::*;

use crate::worker::TransferKind;

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum ItemState {
	#[default]
	Queued,
	Active,
	Done,
	Failed,
	Cancelled,
}

mod imp {
	use super::*;
	use std::cell::{Cell, RefCell};
	use std::sync::OnceLock;

	pub struct TransferItem {
		pub id: Cell<u64>,
		pub kind: Cell<TransferKind>,
		pub name: RefCell<String>,
		pub total: Cell<u64>,
		pub done: Cell<u64>,
		pub state: Cell<ItemState>,
		pub speed_bps: Cell<f64>,
	}

	impl Default for TransferItem {
		fn default() -> Self {
			Self {
				id: Cell::new(0),
				kind: Cell::new(TransferKind::Upload),
				name: RefCell::new(String::new()),
				total: Cell::new(0),
				done: Cell::new(0),
				state: Cell::new(ItemState::Queued),
				speed_bps: Cell::new(0.0),
			}
		}
	}

	#[glib::object_subclass]
	impl ObjectSubclass for TransferItem {
		const NAME: &'static str = "RseTransferItem";
		type Type = super::TransferItem;
	}

	impl ObjectImpl for TransferItem {
		fn signals() -> &'static [glib::subclass::Signal] {
			static SIGNALS: OnceLock<Vec<glib::subclass::Signal>> = OnceLock::new();
			SIGNALS.get_or_init(|| vec![glib::subclass::Signal::builder("changed").build()])
		}
	}
}

glib::wrapper! {
	pub struct TransferItem(ObjectSubclass<imp::TransferItem>);
}

impl TransferItem {
	pub fn new(id: u64, kind: TransferKind, name: &str, total: u64) -> Self {
		let obj: Self = glib::Object::new();
		let imp = obj.imp();
		imp.id.set(id);
		imp.kind.set(kind);
		imp.name.replace(name.to_string());
		imp.total.set(total);
		obj
	}

	pub fn id(&self) -> u64 {
		self.imp().id.get()
	}
	pub fn kind(&self) -> TransferKind {
		self.imp().kind.get()
	}
	pub fn name(&self) -> String {
		self.imp().name.borrow().clone()
	}
	pub fn total(&self) -> u64 {
		self.imp().total.get()
	}
	pub fn done(&self) -> u64 {
		self.imp().done.get()
	}
	pub fn state(&self) -> ItemState {
		self.imp().state.get()
	}
	pub fn speed_bps(&self) -> f64 {
		self.imp().speed_bps.get()
	}

	fn emit_changed(&self) {
		self.emit_by_name::<()>("changed", &[]);
	}

	pub fn connect_changed<F: Fn(&Self) + 'static>(&self, f: F) -> glib::SignalHandlerId {
		self.connect_local("changed", false, move |vals| {
			let obj = vals[0].get::<Self>().unwrap();
			f(&obj);
			None
		})
	}

	/// Live progress. Ignored once the user has cancelled this row.
	pub fn set_active(&self, done: u64, speed_bps: f64) {
		let imp = self.imp();
		if imp.state.get() == ItemState::Cancelled {
			return;
		}
		imp.done.set(done);
		imp.speed_bps.set(speed_bps);
		imp.state.set(ItemState::Active);
		self.emit_changed();
	}

	/// Final outcome from the worker. Ignored if already cancelled.
	pub fn set_finished(&self, ok: bool) {
		let imp = self.imp();
		if imp.state.get() == ItemState::Cancelled {
			return;
		}
		imp.state.set(if ok {
			ItemState::Done
		} else {
			ItemState::Failed
		});
		if ok {
			imp.done.set(imp.total.get());
		}
		imp.speed_bps.set(0.0);
		self.emit_changed();
	}

	/// User pressed cancel. Sticky — later worker updates won't override it.
	pub fn set_cancelled(&self) {
		let imp = self.imp();
		imp.state.set(ItemState::Cancelled);
		imp.speed_bps.set(0.0);
		self.emit_changed();
	}
}
