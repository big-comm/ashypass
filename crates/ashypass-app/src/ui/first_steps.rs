//! First run: a short welcome after the vault is created, then a "First
//! steps" card above the password list.
//!
//! The welcome is three screens and asks for nothing but one check: that
//! the master password is written down. Everything optional (the browser,
//! a phone, verification codes, a PIN) waits in the card, where each step
//! opens the place that does it and is ticked off once done. The card can
//! be hidden, and comes back from the main menu.

use crate::tr;
use adw::prelude::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

/// The steps of the card, in the order shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Backup,
    Passwords,
    Browser,
    Sync,
    Codes,
    Pin,
}

const STEPS: [Step; 6] = [
    Step::Backup,
    Step::Passwords,
    Step::Browser,
    Step::Sync,
    Step::Codes,
    Step::Pin,
];

impl Step {
    fn title(self) -> &'static str {
        match self {
            Step::Backup => tr!("Make a backup"),
            Step::Passwords => tr!("Bring or add your passwords"),
            Step::Browser => tr!("Fill passwords in the browser"),
            Step::Sync => tr!("Use them on your phone or another computer"),
            Step::Codes => tr!("Keep verification codes (2FA)"),
            Step::Pin => tr!("Unlock with a PIN"),
        }
    }

    fn subtitle(self) -> &'static str {
        match self {
            Step::Backup => tr!(
                "Important: if this computer breaks, a backup is the only way to get everything back"
            ),
            Step::Passwords => tr!("Import from a browser or another app, or add them one by one"),
            Step::Browser => tr!("Install the Ashy Pass extension and connect it"),
            Step::Sync => tr!("Through an encrypted folder in your cloud or on a drive"),
            Step::Codes => tr!("The six-digit codes sites ask for after the password"),
            Step::Pin => tr!("Quicker than the master password on this computer"),
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Step::Backup => "document-save-symbolic",
            Step::Passwords => "dialog-password-symbolic",
            Step::Browser => "web-browser-symbolic",
            Step::Sync => "emblem-synchronizing-symbolic",
            Step::Codes => "security-high-symbolic",
            Step::Pin => "system-lock-screen-symbolic",
        }
    }
}

/// Which steps are done, read by the window from the vault and settings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Progress {
    pub backup: bool,
    pub passwords: bool,
    pub browser: bool,
    pub sync: bool,
    pub codes: bool,
    pub pin: bool,
}

impl Progress {
    pub fn done(&self, step: Step) -> bool {
        match step {
            Step::Backup => self.backup,
            Step::Passwords => self.passwords,
            Step::Browser => self.browser,
            Step::Sync => self.sync,
            Step::Codes => self.codes,
            Step::Pin => self.pin,
        }
    }

    pub fn count(&self) -> usize {
        STEPS.iter().filter(|step| self.done(**step)).count()
    }

    pub fn all_done(&self) -> bool {
        self.count() == STEPS.len()
    }
}

type StepCallback = Box<dyn Fn(Step)>;
type Callback = Box<dyn Fn()>;

/// The card: a collapsible list of the steps with their state.
pub struct FirstStepsCard {
    pub root: gtk::ListBox,
    expander: adw::ExpanderRow,
    rows: Vec<(Step, adw::ActionRow, gtk::Image)>,
    on_step: Rc<RefCell<Option<StepCallback>>>,
    on_hide: Rc<RefCell<Option<Callback>>>,
    /// Whether the vault had passwords at the last update: the card opens
    /// itself over an empty vault and folds away once passwords arrive.
    had_passwords: Cell<Option<bool>>,
}

impl FirstStepsCard {
    pub fn new() -> Self {
        let root = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::None)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(12)
            .margin_end(12)
            .visible(false)
            .build();
        root.add_css_class("boxed-list");
        let expander = adw::ExpanderRow::builder()
            .title(tr!("First steps"))
            .build();
        let hide = gtk::Button::builder()
            .icon_name("window-close-symbolic")
            .tooltip_text(tr!("Hide first steps"))
            .valign(gtk::Align::Center)
            .build();
        hide.add_css_class("flat");
        hide.update_property(&[gtk::accessible::Property::Label(tr!("Hide first steps"))]);
        expander.add_suffix(&hide);
        root.append(&expander);

        let on_step: Rc<RefCell<Option<StepCallback>>> = Rc::new(RefCell::new(None));
        let on_hide: Rc<RefCell<Option<Callback>>> = Rc::new(RefCell::new(None));
        let mut rows = Vec::new();
        for step in STEPS {
            let row = adw::ActionRow::builder()
                .title(step.title())
                .subtitle(step.subtitle())
                .activatable(true)
                .build();
            let icon = gtk::Image::from_icon_name(step.icon());
            icon.set_accessible_role(gtk::AccessibleRole::Presentation);
            row.add_prefix(&icon);
            row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
            {
                let on_step = on_step.clone();
                row.connect_activated(move |_| {
                    if let Some(run) = on_step.borrow().as_ref() {
                        run(step);
                    }
                });
            }
            expander.add_row(&row);
            rows.push((step, row, icon));
        }
        {
            let on_hide = on_hide.clone();
            hide.connect_clicked(move |_| {
                if let Some(run) = on_hide.borrow().as_ref() {
                    run();
                }
            });
        }
        Self {
            root,
            expander,
            rows,
            on_step,
            on_hide,
            had_passwords: Cell::new(None),
        }
    }

    pub fn set_on_step(&self, run: impl Fn(Step) + 'static) {
        *self.on_step.borrow_mut() = Some(Box::new(run));
    }

    pub fn set_on_hide(&self, run: impl Fn() + 'static) {
        *self.on_hide.borrow_mut() = Some(Box::new(run));
    }

    pub fn set_expanded(&self, expanded: bool) {
        self.expander.set_expanded(expanded);
    }

    pub fn update(&self, progress: &Progress) {
        if self.had_passwords.replace(Some(progress.passwords)) != Some(progress.passwords) {
            self.expander.set_expanded(!progress.passwords);
        }
        self.expander.set_subtitle(
            &tr!("{done} of {total} done")
                .replace("{done}", &progress.count().to_string())
                .replace("{total}", &STEPS.len().to_string()),
        );
        for (step, row, icon) in &self.rows {
            let done = progress.done(*step);
            icon.set_icon_name(Some(if done {
                "object-select-symbolic"
            } else {
                step.icon()
            }));
            if done {
                icon.add_css_class("success");
                icon.remove_css_class("warning");
            } else {
                icon.remove_css_class("success");
                // The one step that protects everything else stands out.
                if *step == Step::Backup {
                    icon.add_css_class("warning");
                }
            }
            row.upcast_ref::<gtk::Widget>().update_property(&[
                gtk::accessible::Property::Description(if done {
                    tr!("Done")
                } else {
                    tr!("Not done yet")
                }),
            ]);
        }
    }
}

/// The welcome after creating a vault: what the vault is (and that the
/// master password cannot be recovered), where passwords kept elsewhere
/// come from, and the reminder to make a backup. `on_import` runs when the
/// person chooses to import now; the welcome closes first.
pub fn show_welcome(parent: &impl IsA<gtk::Widget>, on_import: impl Fn() + 'static) {
    let dialog = big_gtk_kit::dialog::Dialog::builder(Some(parent))
        .title(tr!("Welcome to Ashy Pass"))
        .content_width(480)
        .content_height(540)
        .build();
    let header = adw::HeaderBar::new();
    let back = gtk::Button::builder()
        .icon_name("go-previous-symbolic")
        .tooltip_text(tr!("Back"))
        .visible(false)
        .build();
    back.update_property(&[gtk::accessible::Property::Label(tr!("Back"))]);
    header.pack_start(&back);
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);

    let stack = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::SlideLeftRight)
        .vexpand(true)
        .build();

    // 1. The vault, and the one thing that cannot be undone.
    let (vault_page, vault_actions) = welcome_page(
        "ashypass",
        tr!("Your vault is ready"),
        tr!("Everything you keep in Ashy Pass stays in an encrypted vault on this computer. Only your master password opens it, and Ashy Pass cannot recover it if it is lost."),
        None,
        tr!("Step 1 of 3"),
    );
    let written =
        gtk::CheckButton::with_label(tr!("I wrote my master password down somewhere safe"));
    written.set_halign(gtk::Align::Center);
    vault_actions.append(&written);
    let next_1 = pill(tr!("Continue"), true);
    next_1.set_sensitive(false);
    vault_actions.append(&next_1);
    stack.add_named(&vault_page, Some("vault"));

    // 2. Passwords kept elsewhere.
    let (import_page, import_actions) = welcome_page(
        "dialog-password-symbolic",
        tr!("Do you keep passwords somewhere else?"),
        tr!("Bring them from a browser (Chrome, Edge, Brave, Firefox) or another password manager (Bitwarden, 1Password, KeePass)."),
        Some(tr!("In Chrome: Settings → Autofill and passwords → Google Password Manager → Settings → Export passwords. After importing, delete the exported file: it is not protected.")),
        tr!("Step 2 of 3"),
    );
    let import = pill(tr!("Import passwords…"), true);
    let skip_import = pill(tr!("Not now"), false);
    import_actions.append(&import);
    import_actions.append(&skip_import);
    stack.add_named(&import_page, Some("import"));

    // 3. The backup, once there is something in the vault.
    let (backup_page, backup_actions) = welcome_page(
        "drive-removable-media-symbolic",
        tr!("Remember the backup"),
        tr!("Once your passwords are in, make a backup in Backups and keep it off this computer, on a USB drive for example. If this computer breaks or is lost, it is the only way to get them back."),
        Some(tr!("The other steps — the browser, your phone, verification codes — wait in First steps, above your passwords.")),
        tr!("Step 3 of 3"),
    );
    let finish = pill(tr!("Start using Ashy Pass"), true);
    backup_actions.append(&finish);
    stack.add_named(&backup_page, Some("backup"));

    toolbar.set_content(Some(&stack));
    dialog.set_child(Some(&toolbar));

    let go = {
        let stack = stack.downgrade();
        let back = back.downgrade();
        move |page: &str| {
            if let (Some(stack), Some(back)) = (stack.upgrade(), back.upgrade()) {
                stack.set_visible_child_name(page);
                back.set_visible(page != "vault");
            }
        }
    };
    {
        let next_1 = next_1.downgrade();
        written.connect_toggled(move |check| {
            if let Some(next_1) = next_1.upgrade() {
                next_1.set_sensitive(check.is_active());
            }
        });
    }
    {
        let go = go.clone();
        next_1.connect_clicked(move |_| go("import"));
    }
    {
        let go = go.clone();
        skip_import.connect_clicked(move |_| go("backup"));
    }
    {
        let stack_weak = stack.downgrade();
        let go = go.clone();
        back.connect_clicked(move |_| {
            let Some(stack) = stack_weak.upgrade() else {
                return;
            };
            match stack.visible_child_name().as_deref() {
                Some("backup") => go("import"),
                _ => go("vault"),
            }
        });
    }
    {
        let dialog_weak = dialog.downgrade();
        finish.connect_clicked(move |_| {
            if let Some(dialog) = dialog_weak.upgrade() {
                dialog.close();
            }
        });
    }
    {
        let dialog_weak = dialog.downgrade();
        import.connect_clicked(move |_| {
            if let Some(dialog) = dialog_weak.upgrade() {
                dialog.close();
            }
            on_import();
        });
    }
    dialog.set_default_widget(Some(&next_1));
    dialog.present();
}

/// One screen of the welcome: icon, title, text, an optional note, the
/// step count, and a box for its buttons (returned).
fn welcome_page(
    icon: &str,
    title: &str,
    body: &str,
    note: Option<&str>,
    step: &str,
) -> (gtk::Widget, gtk::Box) {
    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(14)
        .valign(gtk::Align::Center)
        .margin_top(18)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    let image = gtk::Image::builder().icon_name(icon).pixel_size(72).build();
    image.set_accessible_role(gtk::AccessibleRole::Presentation);
    content.append(&image);
    let title_label = gtk::Label::builder()
        .label(title)
        .wrap(true)
        .justify(gtk::Justification::Center)
        .build();
    title_label.add_css_class("title-2");
    title_label.set_accessible_role(gtk::AccessibleRole::Heading);
    content.append(&title_label);
    let body_label = gtk::Label::builder()
        .label(body)
        .wrap(true)
        .justify(gtk::Justification::Center)
        .build();
    content.append(&body_label);
    if let Some(note) = note {
        let note_label = gtk::Label::builder()
            .label(note)
            .wrap(true)
            .xalign(0.0)
            .build();
        note_label.add_css_class("caption");
        note_label.add_css_class("ashy-note");
        content.append(&note_label);
    }
    let actions = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(10)
        .margin_top(8)
        .halign(gtk::Align::Center)
        .build();
    content.append(&actions);
    let step_label = gtk::Label::new(Some(step));
    step_label.add_css_class("caption");
    step_label.add_css_class("dim-label");
    content.append(&step_label);
    let clamp = adw::Clamp::builder()
        .maximum_size(420)
        .child(&content)
        .build();
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .child(&clamp)
        .build();
    (scrolled.upcast(), actions)
}

fn pill(label: &str, suggested: bool) -> gtk::Button {
    let button = gtk::Button::builder()
        .label(label)
        .width_request(260)
        .build();
    button.add_css_class("pill");
    if suggested {
        button.add_css_class("suggested-action");
    } else {
        button.add_css_class("flat");
    }
    button
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_counts_the_steps_done() {
        let mut progress = Progress::default();
        assert_eq!(progress.count(), 0);
        progress.backup = true;
        progress.codes = true;
        assert_eq!(progress.count(), 2);
        assert!(!progress.all_done());
        let all = Progress {
            backup: true,
            passwords: true,
            browser: true,
            sync: true,
            codes: true,
            pin: true,
        };
        assert!(all.all_done());
    }
}
