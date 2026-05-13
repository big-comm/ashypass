//! Auto-lock session manager.
//!
//! Replaces `core/auth.py:SessionManager`. Uses `glib::timeout_add_seconds_local`.

use ashypass_core::config::SESSION_TIMEOUT_SECONDS;
use glib::SourceId;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

const WARNING_SECONDS: u64 = 10;

pub struct SessionManager {
    pub timeout_seconds: u64,
    authenticated: bool,
    last_activity: Instant,
    timeout_id: Option<SourceId>,
    warning_id: Option<SourceId>,
    lock_callback: Option<Rc<dyn Fn()>>,
    warning_callback: Option<Rc<dyn Fn(u64)>>,
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
        let warn_delay = timeout_secs.saturating_sub(WARNING_SECONDS).max(1);

        let this_warn = this.clone();
        let warn_id = glib::timeout_add_seconds_local(warn_delay as u32, move || {
            let cb = {
                let mut s = this_warn.borrow_mut();
                s.warning_id = None;
                s.warning_callback.clone()
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
            this_lock.borrow_mut().timeout_id = None;
            SessionManager::logout(&this_lock);
            glib::ControlFlow::Break
        });

        let mut s = this.borrow_mut();
        s.warning_id = Some(warn_id);
        s.timeout_id = Some(lock_id);
    }
}
