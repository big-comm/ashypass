//! Auto-lock session manager.
//!
//! Replaces `core/auth.py:SessionManager`. Uses `glib::timeout_add_seconds_local`.

use ashypass_core::config::SESSION_TIMEOUT_SECONDS;
use glib::SourceId;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

/// Warn this long before locking. WCAG's timing guidance asks for at least
/// 20 seconds to react; shorter timeouts warn for half their length.
const WARNING_SECONDS: u64 = 20;

/// An open form holds auto-lock off, but not forever: an unattended machine
/// with an entry dialog open must still lock. The cap is generous for real
/// editing and scales with the user's own timeout.
const MIN_INHIBIT_CAP_SECONDS: u64 = 10 * 60;
const INHIBIT_CAP_MULTIPLIER: u64 = 3;

pub fn inhibit_cap_seconds(timeout_seconds: u64) -> u64 {
    timeout_seconds
        .saturating_mul(INHIBIT_CAP_MULTIPLIER)
        .max(MIN_INHIBIT_CAP_SECONDS)
}

pub fn warning_delay_seconds(timeout_seconds: u64) -> u64 {
    let warning = WARNING_SECONDS.min(timeout_seconds / 2);
    timeout_seconds.saturating_sub(warning).max(1)
}

pub struct SessionManager {
    pub timeout_seconds: u64,
    authenticated: bool,
    last_activity: Instant,
    timeout_id: Option<SourceId>,
    warning_id: Option<SourceId>,
    lock_callback: Option<Rc<dyn Fn()>>,
    warning_callback: Option<Rc<dyn Fn(u64)>>,
    /// Outstanding `inhibit` calls. While non-zero the lock timer re-arms
    /// instead of locking. See `SessionManager::inhibit`.
    inhibitors: usize,
    /// When the first outstanding inhibitor was taken.
    inhibited_since: Option<Instant>,
}

impl Default for SessionManager {
    fn default() -> Self {
        Self {
            timeout_seconds: SESSION_TIMEOUT_SECONDS,
            authenticated: false,
            last_activity: Instant::now(),
            timeout_id: None,
            warning_id: None,
            lock_callback: None,
            warning_callback: None,
            inhibitors: 0,
            inhibited_since: None,
        }
    }
}

impl SessionManager {
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn set_lock_callback(&mut self, cb: Rc<dyn Fn()>) {
        self.lock_callback = Some(cb);
    }

    pub fn set_warning_callback(&mut self, cb: Rc<dyn Fn(u64)>) {
        self.warning_callback = Some(cb);
    }

    pub fn on_activity(this: &Rc<RefCell<Self>>) {
        if this.borrow().authenticated {
            Self::reset_timeout(this);
        }
    }

    /// Suspend auto-lock while the user is in the middle of something that
    /// would be destroyed by locking — editing an entry, above all. Idle time
    /// spent staring at a half-filled form is not idle time.
    ///
    /// Inhibiting does not stop the clock: when the timer fires it is simply
    /// re-armed instead of locking, so the vault locks as soon as the last
    /// inhibitor is released and the remaining idle time elapses. Every
    /// `inhibit` must be paired with exactly one `release`.
    pub fn inhibit(this: &Rc<RefCell<Self>>) {
        let mut s = this.borrow_mut();
        if s.inhibitors == 0 {
            s.inhibited_since = Some(Instant::now());
        }
        s.inhibitors += 1;
    }

    pub fn release(this: &Rc<RefCell<Self>>) {
        {
            let mut s = this.borrow_mut();
            s.inhibitors = s.inhibitors.saturating_sub(1);
            if s.inhibitors == 0 {
                s.inhibited_since = None;
            }
            if s.inhibitors > 0 || !s.authenticated {
                return;
            }
        }
        // Last inhibitor gone: restart the idle countdown from now rather than
        // locking immediately on whatever time passed while the form was open.
        Self::reset_timeout(this);
    }

    pub fn login(this: &Rc<RefCell<Self>>) {
        this.borrow_mut().authenticated = true;
        Self::reset_timeout(this);
    }

    pub fn logout(this: &Rc<RefCell<Self>>) {
        let cb = {
            let mut s = this.borrow_mut();
            s.authenticated = false;
            s.cancel_timers();
            s.lock_callback.clone()
        };
        if let Some(cb) = cb {
            cb();
        }
    }

    /// Record that the vault is locked without running the lock callback.
    ///
    /// Used by paths that lock the vault directly (the toolbar button, the
    /// sidebar item): without this the session would stay "authenticated", so
    /// the idle timer would keep running against a locked vault and
    /// type-to-search would still think the vault was open.
    pub fn mark_locked(this: &Rc<RefCell<Self>>) {
        let mut s = this.borrow_mut();
        s.authenticated = false;
        s.cancel_timers();
    }

    /// An inhibitor is active and has not yet exceeded its cap.
    fn is_held_off(&self) -> bool {
        let cap = inhibit_cap_seconds(self.timeout_seconds);
        self.inhibitors > 0
            && self
                .inhibited_since
                .is_some_and(|since| since.elapsed().as_secs() + WARNING_SECONDS < cap)
    }

    fn cancel_timers(&mut self) {
        if let Some(id) = self.timeout_id.take() {
            id.remove();
        }
        if let Some(id) = self.warning_id.take() {
            id.remove();
        }
    }

    pub fn remaining(&self) -> u64 {
        if !self.authenticated {
            return 0;
        }
        let elapsed = self.last_activity.elapsed().as_secs();
        self.timeout_seconds.saturating_sub(elapsed)
    }

    fn reset_timeout(this: &Rc<RefCell<Self>>) {
        {
            let mut s = this.borrow_mut();
            s.last_activity = Instant::now();
            s.cancel_timers();
        }

        let timeout_secs = this.borrow().timeout_seconds;
        let warn_delay = warning_delay_seconds(timeout_secs);

        let this_warn = this.clone();
        let warn_id = glib::timeout_add_seconds_local(warn_delay as u32, move || {
            let cb = {
                let mut s = this_warn.borrow_mut();
                s.warning_id = None;
                // No point warning about a lock that is being held off —
                // unless the hold is about to run out.
                if s.is_held_off() {
                    None
                } else {
                    s.warning_callback.clone()
                }
            };
            if let Some(cb) = cb {
                let remaining = this_warn.borrow().remaining();
                if remaining > 0 {
                    cb(remaining);
                }
            }
            glib::ControlFlow::Break
        });

        let this_lock = this.clone();
        let lock_id = glib::timeout_add_seconds_local(timeout_secs as u32, move || {
            let inhibited = {
                let mut s = this_lock.borrow_mut();
                s.timeout_id = None;
                s.is_held_off()
            };
            if inhibited {
                SessionManager::reset_timeout(&this_lock);
            } else {
                SessionManager::logout(&this_lock);
            }
            glib::ControlFlow::Break
        });

        let mut s = this.borrow_mut();
        s.warning_id = Some(warn_id);
        s.timeout_id = Some(lock_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inhibition_is_capped_but_generous() {
        assert_eq!(inhibit_cap_seconds(30), MIN_INHIBIT_CAP_SECONDS);
        assert_eq!(inhibit_cap_seconds(3600), 3 * 3600);
    }

    #[test]
    fn warning_leaves_time_to_react_without_firing_at_once() {
        assert_eq!(warning_delay_seconds(300), 280);
        assert_eq!(warning_delay_seconds(30), 15);
        assert_eq!(warning_delay_seconds(15), 8);
        assert!(warning_delay_seconds(1) >= 1);
    }
}
