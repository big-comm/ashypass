// The fields of `AppEvent` variants and the public `subscribe` API are part of
// the bus surface even when not yet consumed by every view. Suppress the
// "never read" lint here so the foundation stays warning-free as views migrate
// over from the legacy callback wiring.
#![allow(dead_code)]

//! In-process event bus for cross-cutting UI signals.
//!
//! Historically, components reached into shared state via `Rc<RefCell<...>>`
//! and registered per-callsite callbacks (e.g. `set_lock_callback`,
//! `set_warning_callback`). That couples the emitter to every listener and
//! makes the wiring hard to read. The bus inverts the dependency: emitters
//! call `bus.emit(event)`, listeners call `bus.subscribe(closure)`, and they
//! never need to know about each other.
//!
//! `glib 0.20` removed `MainContext::channel`, and we don't want to pull in
//! `async-channel` just for in-thread fan-out, so this is a synchronous
//! single-threaded bus. All GTK callbacks run on the main loop already, so
//! synchronous dispatch is fine — and it keeps reasoning simple: when `emit`
//! returns, every subscriber has run.
//!
//! Subscribers are stored as `Rc<dyn Fn>` so the bus can clone the list
//! before iterating; that lets a subscriber call back into the bus during
//! dispatch (e.g. emit a follow-up event) without panicking on `RefCell`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// Application-wide signals. Add a variant here when a new emitter needs to
/// notify multiple views; do NOT add per-component callback fields to
/// `AppState`.
#[derive(Debug, Clone)]
pub enum AppEvent {
    /// Vault data mutated (add / update / delete / restore / attachment, …).
    /// Views should refresh whatever they show from the vault.
    VaultChanged,
    /// Session auto-locked due to inactivity. Views must hide secrets.
    SessionLocked,
    /// Session is about to lock — `seconds_left` is the countdown.
    SessionWarning { seconds_left: u64 },
    /// A WebDAV sync push completed successfully.
    SyncCompleted { filename: String },
    /// A WebDAV sync push failed; the payload is a human-readable reason.
    SyncFailed(String),
    /// A remote conflict was detected during a sync attempt.
    SyncConflict {
        local_generation: u64,
        remote_generation: u64,
    },
}

type Subscriber = Rc<dyn Fn(&AppEvent)>;

/// Handle identifying one registration, for `unsubscribe`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionId(u64);

#[derive(Default)]
pub struct EventBus {
    subs: RefCell<Vec<(SubscriptionId, Subscriber)>>,
    next_id: Cell<u64>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a listener for every event.
    ///
    /// Long-lived views can ignore the returned id — the bus lives as long as
    /// the application. Anything shorter-lived than the bus (a dialog, a
    /// transient view) must keep the id and `unsubscribe` when it goes away,
    /// otherwise every re-open leaks another subscriber onto the dispatch list.
    /// Subscribers that outlive their widgets should hold weak references.
    #[must_use = "short-lived subscribers must unsubscribe; bind to `_` if the listener is permanent"]
    pub fn subscribe<F>(&self, f: F) -> SubscriptionId
    where
        F: Fn(&AppEvent) + 'static,
    {
        let id = SubscriptionId(self.next_id.get());
        self.next_id.set(self.next_id.get() + 1);
        self.subs.borrow_mut().push((id, Rc::new(f)));
        id
    }

    /// Remove a previously registered listener. Safe to call during dispatch
    /// (the running `emit` iterates a snapshot) and safe to call twice.
    pub fn unsubscribe(&self, id: SubscriptionId) {
        self.subs.borrow_mut().retain(|(sub_id, _)| *sub_id != id);
    }

    /// Dispatch synchronously to all current subscribers. The list is cloned
    /// first so re-entrant `emit`, `subscribe` and `unsubscribe` calls from
    /// within a handler are safe.
    pub fn emit(&self, event: AppEvent) {
        let snapshot: Vec<Subscriber> = self
            .subs
            .borrow()
            .iter()
            .map(|(_, sub)| sub.clone())
            .collect();
        for s in snapshot {
            s(&event);
        }
    }

    #[cfg(test)]
    pub fn subscriber_count(&self) -> usize {
        self.subs.borrow().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn delivers_to_all_subscribers_in_order() {
        let bus = EventBus::new();
        let log = Rc::new(RefCell::new(Vec::<&'static str>::new()));
        {
            let log = log.clone();
            let _ = bus.subscribe(move |e| {
                if matches!(e, AppEvent::VaultChanged) {
                    log.borrow_mut().push("a");
                }
            });
        }
        {
            let log = log.clone();
            let _ = bus.subscribe(move |e| {
                if matches!(e, AppEvent::VaultChanged) {
                    log.borrow_mut().push("b");
                }
            });
        }
        bus.emit(AppEvent::VaultChanged);
        assert_eq!(&*log.borrow(), &["a", "b"]);
    }

    #[test]
    fn snapshot_lets_handler_subscribe_more() {
        let bus = Rc::new(EventBus::new());
        let calls = Rc::new(Cell::new(0));
        {
            let bus_outer = bus.clone();
            let calls = calls.clone();
            let _ = bus.subscribe(move |_| {
                let calls = calls.clone();
                let _ = bus_outer.subscribe(move |_| {
                    calls.set(calls.get() + 1);
                });
            });
        }
        // First emit: the late subscription happens but is not visible to the
        // current dispatch (we iterate the pre-emit snapshot).
        bus.emit(AppEvent::VaultChanged);
        assert_eq!(calls.get(), 0);
        // Second emit: both the original and the late-added subscriber run.
        bus.emit(AppEvent::VaultChanged);
        // The original subscriber appends another late subscriber on every
        // emit, so we expect 1 from the first late subscriber added.
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn unsubscribe_removes_only_that_listener() {
        let bus = EventBus::new();
        let a = Rc::new(Cell::new(0));
        let b = Rc::new(Cell::new(0));
        let id_a = {
            let a = a.clone();
            bus.subscribe(move |_| a.set(a.get() + 1))
        };
        let _id_b = {
            let b = b.clone();
            bus.subscribe(move |_| b.set(b.get() + 1))
        };

        bus.emit(AppEvent::VaultChanged);
        assert_eq!((a.get(), b.get()), (1, 1));

        bus.unsubscribe(id_a);
        assert_eq!(bus.subscriber_count(), 1);
        bus.emit(AppEvent::VaultChanged);
        assert_eq!((a.get(), b.get()), (1, 2));

        // Idempotent: unsubscribing twice is not an error.
        bus.unsubscribe(id_a);
        assert_eq!(bus.subscriber_count(), 1);
    }

    #[test]
    fn unsubscribe_during_dispatch_takes_effect_next_emit() {
        let bus = Rc::new(EventBus::new());
        let calls = Rc::new(Cell::new(0));
        let id: Rc<RefCell<Option<SubscriptionId>>> = Rc::new(RefCell::new(None));
        let new_id = {
            let calls = calls.clone();
            let bus_inner = bus.clone();
            let id = id.clone();
            bus.subscribe(move |_| {
                calls.set(calls.get() + 1);
                if let Some(self_id) = *id.borrow() {
                    bus_inner.unsubscribe(self_id);
                }
            })
        };
        *id.borrow_mut() = Some(new_id);

        bus.emit(AppEvent::VaultChanged);
        assert_eq!(calls.get(), 1);
        bus.emit(AppEvent::VaultChanged);
        assert_eq!(calls.get(), 1, "listener removed itself during dispatch");
    }

    #[test]
    fn payload_round_trips() {
        let bus = EventBus::new();
        let seen = Rc::new(RefCell::new(Vec::<String>::new()));
        {
            let seen = seen.clone();
            let _ = bus.subscribe(move |e| {
                if let AppEvent::SyncCompleted { filename } = e {
                    seen.borrow_mut().push(filename.clone());
                }
            });
        }
        bus.emit(AppEvent::SyncCompleted {
            filename: "snap-1.ashy".into(),
        });
        bus.emit(AppEvent::VaultChanged); // should be ignored
        bus.emit(AppEvent::SyncCompleted {
            filename: "snap-2.ashy".into(),
        });
        assert_eq!(
            &*seen.borrow(),
            &["snap-1.ashy", "snap-2.ashy"].map(String::from)
        );
    }
}
