//! Add / edit an access.
//!
//! Four fields up front — name, user or e-mail, password, site — and the rest
//! (folder, notes, tags, verification code, attachments) in a second section.
//! Errors appear next to the field they belong to and keep everything the
//! user typed; a failure to *save* is reported as such ("nothing was saved"),
//! never as a mistake in the form. Editing a password says plainly that only
//! the copy kept in Ashy Pass changes, not the password on the site.

use crate::session::SessionManager;
use crate::state::SharedState;
use crate::tr;
use crate::ui::generator_view::{GeneratorPanel, PanelMode};
use crate::ui::widgets::describe;
use adw::prelude::*;
use ashypass_core::db::vault::{NewEntry, PasswordEntry, UpdateEntry};
use ashypass_core::totp::{generate_totp, parse_otpauth, Algorithm};
use gtk::{gio, glib};
use std::cell::RefCell;
use std::rc::Rc;
use zeroize::Zeroizing;

type SavedCallback = Box<dyn Fn(i64)>;
type RenderSlot = Rc<RefCell<Option<Rc<dyn Fn()>>>>;

pub struct EntryFormOptions {
    pub entry: Option<PasswordEntry>,
    pub prefill_password: Option<Zeroizing<String>>,
    pub prefill_folder: Option<String>,
    pub on_saved: Option<SavedCallback>,
}

/// What the verification-code field holds after validation.
#[derive(Debug, PartialEq, Eq)]
pub struct TotpInput {
    pub secret: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
    /// Issuer / label from an otpauth URI, to fill an empty name or user.
    pub issuer: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TotpInputError {
    /// The user typed the 6–8 digit code shown by another app, not the key.
    LooksLikeOneTimeCode,
    Invalid(String),
}

/// Validate what the user pasted into the verification-code field: an
/// `otpauth://` URI or a Base32 setup key. A bare 6–8 digit number is the
/// temporary code, not the key, and gets its own explanation.
pub fn parse_totp_input(
    input: &str,
    algorithm: &str,
    digits: u8,
    period: u32,
) -> Result<TotpInput, TotpInputError> {
    let trimmed = input.trim();
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    if (6..=8).contains(&compact.len()) && compact.chars().all(|c| c.is_ascii_digit()) {
        return Err(TotpInputError::LooksLikeOneTimeCode);
    }
    let parsed = if trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        let uri = parse_otpauth(trimmed).map_err(|e| TotpInputError::Invalid(e.to_string()))?;
        TotpInput {
            secret: uri.secret,
            algorithm: uri.algorithm.as_str().to_string(),
            digits: uri.digits,
            period: uri.period,
            issuer: Some(uri.issuer).filter(|s| !s.is_empty()),
            label: Some(uri.label).filter(|s| !s.is_empty()),
        }
    } else {
        TotpInput {
            secret: compact.to_ascii_uppercase(),
            algorithm: algorithm.to_string(),
            digits,
            period,
            issuer: None,
            label: None,
        }
    };
    if !(6..=8).contains(&parsed.digits) || parsed.period == 0 {
        return Err(TotpInputError::Invalid(
            "unsupported code length or period".into(),
        ));
    }
    let algo = Algorithm::parse(&parsed.algorithm).unwrap_or(Algorithm::Sha1);
    generate_totp(&parsed.secret, algo, parsed.digits, parsed.period, 0)
        .map_err(|e| TotpInputError::Invalid(e.to_string()))?;
    Ok(parsed)
}

pub fn totp_error_message(error: &TotpInputError) -> String {
    match error {
        TotpInputError::LooksLikeOneTimeCode => tr!(
            "This looks like a temporary code. Paste the setup key (letters and numbers) or the otpauth:// link shown by the site instead."
        )
        .to_string(),
        TotpInputError::Invalid(_) => tr!(
            "This setup key is not valid. Copy it again from the site's two-step verification settings."
        )
        .to_string(),
    }
}

fn field_error_label() -> gtk::Label {
    let label = gtk::Label::builder()
        .xalign(0.0)
        .wrap(true)
        .visible(false)
        .margin_start(12)
        .margin_end(12)
        .build();
    label.add_css_class("error");
    label.add_css_class("caption");
    label
}

fn set_field_error(row: &impl IsA<gtk::Widget>, label: &gtk::Label, message: Option<&str>) {
    match message {
        Some(text) => {
            label.set_label(text);
            label.set_visible(true);
            row.add_css_class("error");
        }
        None => {
            label.set_visible(false);
            row.remove_css_class("error");
        }
    }
}

pub fn present(
    state: &SharedState,
    toast: &adw::ToastOverlay,
    parent: &impl IsA<gtk::Widget>,
    options: EntryFormOptions,
) {
    if !state.vault.borrow().is_unlocked() {
        return;
    }
    let EntryFormOptions {
        entry,
        prefill_password,
        prefill_folder,
        on_saved,
    } = options;
    let is_edit = entry.is_some();
    let original_password: Zeroizing<String> = Zeroizing::new(
        entry
            .as_ref()
            .and_then(|e| e.password.clone())
            .unwrap_or_default(),
    );

    let dialog = adw::Dialog::builder()
        .title(if is_edit {
            tr!("Edit password")
        } else {
            tr!("Add password")
        })
        .content_width(560)
        .content_height(640)
        .build();

    let header = adw::HeaderBar::builder()
        .show_start_title_buttons(false)
        .show_end_title_buttons(false)
        .build();
    let cancel_button = gtk::Button::with_label(tr!("Cancel"));
    header.pack_start(&cancel_button);
    let save_button = gtk::Button::with_label(tr!("Save to vault"));
    save_button.add_css_class("suggested-action");
    header.pack_end(&save_button);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);

    let save_banner = adw::Banner::builder().revealed(false).build();
    toolbar.add_top_bar(&save_banner);

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(12)
        .margin_end(12)
        .build();

    // ---- Main fields --------------------------------------------------
    let main_group = adw::PreferencesGroup::new();
    let title_row = adw::EntryRow::builder().title(tr!("Name")).build();
    let username_row = adw::EntryRow::builder()
        .title(tr!("User or e-mail (optional)"))
        .build();
    let password_row = adw::PasswordEntryRow::builder()
        .title(tr!("Password"))
        .build();
    let generate_button = gtk::Button::builder()
        .label(tr!("Generate password"))
        .valign(gtk::Align::Center)
        .build();
    generate_button.add_css_class("flat");
    password_row.add_suffix(&generate_button);
    let url_row = adw::EntryRow::builder()
        .title(tr!("Website (optional)"))
        .input_purpose(gtk::InputPurpose::Url)
        .build();
    main_group.add(&title_row);
    main_group.add(&username_row);
    main_group.add(&password_row);
    main_group.add(&url_row);
    content.append(&main_group);

    let title_error = field_error_label();
    let password_error = field_error_label();
    content.append(&title_error);
    content.append(&password_error);
    describe(&title_row, &title_error);
    describe(&password_row, &password_error);

    let password_note = gtk::Label::builder()
        .label(tr!(
            "This only updates the copy kept in Ashy Pass. To change your password, change it on the site as well."
        ))
        .wrap(true)
        .xalign(0.0)
        .visible(false)
        .build();
    password_note.add_css_class("caption");
    password_note.add_css_class("ashy-note");
    content.append(&password_note);
    describe(&password_row, &password_note);

    if let Some(e) = entry.as_ref() {
        title_row.set_text(&e.title);
        username_row.set_text(e.username.as_deref().unwrap_or(""));
        password_row.set_text(&original_password);
        url_row.set_text(e.url.as_deref().unwrap_or(""));
    }
    if let Some(prefill) = prefill_password.as_ref() {
        password_row.set_text(prefill);
    }

    // ---- More options ------------------------------------------------
    let more_group = adw::PreferencesGroup::builder()
        .title(tr!("More options"))
        .build();

    let existing_folders = state.vault.borrow().categories().unwrap_or_default();
    let current_folder = entry
        .as_ref()
        .and_then(|e| e.category.clone())
        .or(prefill_folder)
        .filter(|s| !s.trim().is_empty());
    let mut folder_items: Vec<String> = vec![tr!("No folder").to_string()];
    folder_items.extend(existing_folders.iter().cloned());
    if let Some(folder) = current_folder.as_ref() {
        if !existing_folders.iter().any(|f| f == folder) {
            folder_items.push(folder.clone());
        }
    }
    let new_folder_label = tr!("New folder…").to_string();
    folder_items.push(new_folder_label.clone());
    let folder_model =
        gtk::StringList::new(&folder_items.iter().map(String::as_str).collect::<Vec<_>>());
    let folder_row = adw::ComboRow::builder()
        .title(tr!("Folder"))
        .model(&folder_model)
        .build();
    let selected_folder = current_folder
        .as_ref()
        .and_then(|f| folder_items.iter().position(|item| item == f))
        .unwrap_or(0);
    folder_row.set_selected(selected_folder as u32);
    let new_folder_row = adw::EntryRow::builder()
        .title(tr!("New folder name"))
        .visible(false)
        .build();
    {
        let new_folder_row = new_folder_row.clone();
        let last = (folder_items.len() - 1) as u32;
        folder_row.connect_selected_notify(move |row| {
            let creating = row.selected() == last;
            new_folder_row.set_visible(creating);
            if creating {
                new_folder_row.grab_focus();
            }
        });
    }
    more_group.add(&folder_row);
    more_group.add(&new_folder_row);

    let tags_row = adw::EntryRow::builder()
        .title(tr!("Tags (separated by commas)"))
        .build();
    if let Some(eid) = entry.as_ref().map(|e| e.id) {
        let current = state.vault.borrow().tags_of(eid).unwrap_or_default();
        tags_row.set_text(&current.join(", "));
    }
    let existing_tags: Vec<String> = state
        .vault
        .borrow()
        .all_tags()
        .unwrap_or_default()
        .into_iter()
        .map(|(name, _count)| name)
        .collect();
    if let Some(picker) = build_value_picker(&existing_tags, tr!("Add an existing tag"), {
        let target = tags_row.clone();
        move |value| append_tag(&target, value)
    }) {
        tags_row.add_suffix(&picker);
    }
    more_group.add(&tags_row);
    content.append(&more_group);

    let notes_group = adw::PreferencesGroup::builder()
        .title(tr!("Notes (optional)"))
        .build();
    let notes_view = gtk::TextView::builder()
        .wrap_mode(gtk::WrapMode::WordChar)
        .accepts_tab(false)
        .top_margin(10)
        .bottom_margin(10)
        .left_margin(12)
        .right_margin(12)
        .height_request(96)
        .build();
    notes_view.add_css_class("ashy-notes");
    notes_view.update_property(&[gtk::accessible::Property::Label(tr!("Notes"))]);
    if let Some(notes) = entry.as_ref().and_then(|e| e.notes.as_deref()) {
        notes_view.buffer().set_text(notes);
    }
    let notes_frame = gtk::Frame::builder().child(&notes_view).build();
    notes_frame.add_css_class("view");
    notes_group.add(&notes_frame);
    content.append(&notes_group);

    // ---- Verification code -------------------------------------------
    let totp_group = adw::PreferencesGroup::new();
    let totp_expander = adw::ExpanderRow::builder()
        .title(tr!("Verification code (optional)"))
        .subtitle(tr!(
            "Paste the setup key or otpauth:// link from the site's two-step verification settings"
        ))
        .build();
    let totp_row = adw::PasswordEntryRow::builder()
        .title(tr!("Setup key"))
        .build();
    let algo_model = gtk::StringList::new(&["SHA1", "SHA256", "SHA512"]);
    let algo_row = adw::ComboRow::builder()
        .title(tr!("Algorithm"))
        .model(&algo_model)
        .build();
    let digits_row = adw::SpinRow::builder()
        .title(tr!("Digits"))
        .adjustment(&gtk::Adjustment::new(6.0, 6.0, 8.0, 1.0, 1.0, 0.0))
        .build();
    let period_row = adw::SpinRow::builder()
        .title(tr!("New code every (seconds)"))
        .adjustment(&gtk::Adjustment::new(30.0, 15.0, 120.0, 15.0, 15.0, 0.0))
        .build();
    totp_expander.add_row(&totp_row);
    totp_expander.add_row(&algo_row);
    totp_expander.add_row(&digits_row);
    totp_expander.add_row(&period_row);
    // Read the site's QR code instead of copying the key by hand.
    let qr_status = gtk::Label::builder()
        .xalign(0.0)
        .wrap(true)
        .visible(false)
        .margin_top(6)
        .build();
    qr_status.set_accessible_role(gtk::AccessibleRole::Status);
    let qr_buttons = {
        let totp_row = totp_row.clone();
        let qr_status = qr_status.clone();
        crate::ui::qr_scan::scan_buttons(move |result| {
            qr_status.set_label(crate::ui::qr_scan::message_for(&result));
            qr_status.set_visible(true);
            if let crate::ui::qr_scan::ScanResult::Otpauth(uri) = result {
                qr_status.remove_css_class("error");
                totp_row.set_text(&uri);
            } else {
                qr_status.add_css_class("error");
            }
        })
    };
    let qr_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(12)
        .margin_end(12)
        .build();
    qr_box.append(&qr_buttons);
    qr_box.append(&qr_status);
    let qr_row = gtk::ListBoxRow::builder()
        .activatable(false)
        .selectable(false)
        .child(&qr_box)
        .build();
    totp_expander.add_row(&qr_row);
    totp_group.add(&totp_expander);
    let totp_error = field_error_label();
    describe(&totp_row, &totp_error);
    content.append(&totp_group);
    content.append(&totp_error);
    if let Some(e) = entry.as_ref() {
        if let Some(secret) = e.totp_secret.as_deref() {
            totp_row.set_text(secret);
            totp_expander.set_expanded(true);
        }
        algo_row.set_selected(match e.totp_algorithm.as_str() {
            "SHA256" => 1,
            "SHA512" => 2,
            _ => 0,
        });
        digits_row.set_value(e.totp_digits as f64);
        period_row.set_value(e.totp_period as f64);
    }

    // ---- Attachments (existing entries only) --------------------------
    if let Some(eid) = entry.as_ref().map(|e| e.id) {
        let (group, render_slot) = build_attachments_group(state, toast, eid);
        content.append(&group);
        // Break the closure/slot cycle when the form closes.
        dialog.connect_closed(move |_| {
            render_slot.borrow_mut().take();
        });
    }

    let clamp = adw::Clamp::builder()
        .maximum_size(600)
        .child(&content)
        .build();
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&clamp)
        .build();
    toolbar.set_content(Some(&scrolled));
    dialog.set_child(Some(&toolbar));
    dialog.set_default_widget(Some(&save_button));
    dialog.set_focus(Some(&title_row));

    // The note about the site appears as soon as the stored password differs.
    if is_edit {
        let note = password_note.clone();
        let original = original_password.clone();
        password_row.connect_changed(move |row| {
            note.set_visible(row.text().as_str() != original.as_str());
        });
        password_note.set_visible(password_row.text().as_str() != original_password.as_str());
    }
    {
        let title_error = title_error.clone();
        title_row.connect_changed(move |row| set_field_error(row, &title_error, None));
    }
    {
        let password_error = password_error.clone();
        password_row.connect_changed(move |row| set_field_error(row, &password_error, None));
    }
    {
        let totp_error = totp_error.clone();
        totp_row.connect_changed(move |row| set_field_error(row, &totp_error, None));
    }

    // "Generate password": the embedded generator hands its value straight
    // to the field — no detour through the clipboard.
    {
        let state = state.clone();
        let toast = toast.clone();
        let password_row = password_row.clone();
        generate_button.connect_clicked(move |button| {
            present_embedded_generator(&state, &toast, button, {
                let password_row = password_row.clone();
                move |value| {
                    password_row.set_text(&value);
                }
            });
        });
    }

    {
        let dialog = dialog.clone();
        cancel_button.connect_clicked(move |_| {
            dialog.close();
        });
    }

    let entry_id = entry.as_ref().map(|e| e.id);
    let on_saved: Rc<Option<SavedCallback>> = Rc::new(on_saved);
    {
        let state = state.clone();
        let toast = toast.clone();
        let dialog_cl = dialog.clone();
        let save_banner = save_banner.clone();
        save_button.connect_clicked(move |_| {
            save_banner.set_revealed(false);
            if !state.vault.borrow().is_unlocked() {
                save_banner.set_title(tr!(
                    "The vault is locked. Nothing was saved — unlock it and try again."
                ));
                save_banner.set_revealed(true);
                return;
            }

            let mut title = title_row.text().trim().to_string();
            let password = Zeroizing::new(password_row.text().to_string());
            let mut username = trim_to_opt(&username_row.text());
            let url = trim_to_opt(&url_row.text());
            let notes = {
                let buffer = notes_view.buffer();
                let text = buffer
                    .text(&buffer.start_iter(), &buffer.end_iter(), false)
                    .to_string();
                Some(text.trim().to_string()).filter(|s| !s.is_empty())
            };

            // Verification code first: an otpauth link can fill the name.
            let totp_text = totp_row.text().trim().to_string();
            let totp = if totp_text.is_empty() {
                None
            } else {
                let algo = match algo_row.selected() {
                    1 => "SHA256",
                    2 => "SHA512",
                    _ => "SHA1",
                };
                match parse_totp_input(
                    &totp_text,
                    algo,
                    digits_row.value() as u8,
                    period_row.value() as u32,
                ) {
                    Ok(parsed) => Some(parsed),
                    Err(error) => {
                        totp_expander.set_expanded(true);
                        set_field_error(&totp_row, &totp_error, Some(&totp_error_message(&error)));
                        return;
                    }
                }
            };
            if let Some(parsed) = totp.as_ref() {
                if title.is_empty() {
                    if let Some(name) = parsed.issuer.clone().or(parsed.label.clone()) {
                        title = name;
                        title_row.set_text(&title);
                    }
                }
                if username.is_none() && parsed.issuer.is_some() {
                    username = parsed.label.clone();
                }
            }

            let mut invalid = false;
            if title.is_empty() {
                set_field_error(
                    &title_row,
                    &title_error,
                    Some(tr!("Give this access a name, for example the site or app.")),
                );
                invalid = true;
            }
            if password.is_empty() && totp.is_none() {
                set_field_error(
                    &password_row,
                    &password_error,
                    Some(tr!("Enter the password, or add a verification code below.")),
                );
                invalid = true;
            }
            if invalid {
                return;
            }

            let category = if folder_row.selected() as usize == folder_items.len() - 1 {
                trim_to_opt(&new_folder_row.text())
            } else if folder_row.selected() == 0 {
                None
            } else {
                folder_items
                    .get(folder_row.selected() as usize)
                    .cloned()
                    .filter(|s| !s.trim().is_empty())
            };
            let tag_list: Vec<String> = tags_row
                .text()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let (totp_secret, algorithm, digits, period) = match totp {
                Some(t) => (Some(t.secret), t.algorithm, t.digits, t.period),
                None => (None, "SHA1".to_string(), 6, 30),
            };

            let result = if let Some(id) = entry_id {
                state
                    .vault
                    .borrow()
                    .update(
                        id,
                        UpdateEntry {
                            title: Some(title),
                            username: Some(username.unwrap_or_default()),
                            password: Some(password.to_string()),
                            notes: Some(notes),
                            url: Some(url),
                            totp_secret: Some(totp_secret),
                            totp_algorithm: Some(algorithm),
                            totp_digits: Some(digits),
                            totp_period: Some(period),
                            category: Some(category),
                        },
                    )
                    .map(|_| id)
            } else {
                state.vault.borrow().add(NewEntry {
                    title,
                    username,
                    password: password.to_string(),
                    url,
                    notes,
                    totp_secret,
                    totp_algorithm: Some(algorithm),
                    totp_digits: Some(digits),
                    totp_period: Some(period),
                    category,
                })
            };

            match result {
                Ok(id) => {
                    if let Err(e) = state.vault.borrow().set_tags(id, &tag_list) {
                        log::warn!("could not save tags: {e}");
                        toast.add_toast(
                            adw::Toast::builder()
                                .title(tr!("Saved, but the tags could not be updated"))
                                .timeout(5)
                                .build(),
                        );
                    } else {
                        toast.add_toast(
                            adw::Toast::builder()
                                .title(if entry_id.is_some() {
                                    tr!("Changes saved to the vault")
                                } else {
                                    tr!("Saved to the vault")
                                })
                                .timeout(3)
                                .build(),
                        );
                    }
                    SessionManager::on_activity(&state.session);
                    if let Some(cb) = on_saved.as_ref() {
                        cb(id);
                    }
                    dialog_cl.close();
                }
                Err(e) => {
                    log::error!("saving entry failed: {e}");
                    save_banner.set_title(&format!(
                        "{} ({e})",
                        tr!("Could not save. Nothing was changed in the vault")
                    ));
                    save_banner.set_revealed(true);
                }
            }
        });
    }

    // Hold off auto-lock while the form is open (capped in SessionManager),
    // and close the form if the vault locks anyway.
    SessionManager::inhibit(&state.session);
    {
        let state_cl = state.clone();
        dialog.connect_closed(move |_| {
            SessionManager::release(&state_cl.session);
        });
    }
    state.track_sensitive_dialog(&dialog);
    dialog.present(Some(parent));
}

/// The generator inside the entry form, with "Use this password" as its
/// main action.
fn present_embedded_generator<F>(
    state: &SharedState,
    toast: &adw::ToastOverlay,
    parent: &impl IsA<gtk::Widget>,
    use_value: F,
) where
    F: Fn(String) + 'static,
{
    let dialog = adw::Dialog::builder()
        .title(tr!("Generate password"))
        .content_width(520)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let panel = GeneratorPanel::new(state.clone(), toast.clone(), PanelMode::Embedded);
    {
        let dialog = dialog.clone();
        panel.set_on_primary(Box::new(move |value| {
            use_value(value);
            dialog.close();
        }));
    }
    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .margin_top(12)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    content.append(&panel.root);
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .propagate_natural_height(true)
        .child(&content)
        .build();
    toolbar.set_content(Some(&scrolled));
    dialog.set_child(Some(&toolbar));
    // The panel's handlers hold it weakly; keep it alive for as long as the
    // dialog is open, or every button would silently do nothing.
    let keep_alive = RefCell::new(Some(panel));
    dialog.connect_closed(move |_| {
        keep_alive.borrow_mut().take();
    });
    state.track_sensitive_dialog(&dialog);
    dialog.present(Some(parent));
}

fn build_attachments_group(
    state: &SharedState,
    toast: &adw::ToastOverlay,
    eid: i64,
) -> (adw::PreferencesGroup, RenderSlot) {
    let group = adw::PreferencesGroup::builder()
        .title(tr!("Attachments"))
        .description(tr!("Files are encrypted and stored inside the vault."))
        .build();
    let add_button = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text(tr!("Add file"))
        .valign(gtk::Align::Center)
        .build();
    add_button.add_css_class("flat");
    add_button.update_property(&[gtk::accessible::Property::Label(tr!("Add file"))]);
    group.set_header_suffix(Some(&add_button));

    let render: RenderSlot = Rc::new(RefCell::new(None));
    let rows: Rc<RefCell<Vec<gtk::Widget>>> = Rc::new(RefCell::new(Vec::new()));
    let render_fn: Rc<dyn Fn()> = Rc::new({
        let group = group.clone();
        let state = state.clone();
        let toast = toast.clone();
        let render = render.clone();
        let rows = rows.clone();
        move || {
            for child in rows.borrow_mut().drain(..) {
                group.remove(&child);
            }
            let attachments = state
                .vault
                .borrow()
                .list_attachments(eid)
                .unwrap_or_default();
            if attachments.is_empty() {
                let row = adw::ActionRow::builder()
                    .title(tr!("No attachments"))
                    .build();
                row.add_css_class("dim-label");
                group.add(&row);
                rows.borrow_mut().push(row.upcast());
                return;
            }
            for att in attachments {
                let row = adw::ActionRow::builder()
                    .title(glib::markup_escape_text(&att.filename).as_str())
                    .subtitle(format!(
                        "{} · {}",
                        crate::ui::vault_view::human_size(att.size_bytes),
                        att.mime_type
                            .as_deref()
                            .unwrap_or("application/octet-stream")
                    ))
                    .build();
                let save = gtk::Button::builder()
                    .icon_name("document-save-symbolic")
                    .tooltip_text(tr!("Save a copy…"))
                    .valign(gtk::Align::Center)
                    .build();
                save.add_css_class("flat");
                save.update_property(&[gtk::accessible::Property::Label(tr!("Save a copy…"))]);
                {
                    let state = state.clone();
                    let toast = toast.clone();
                    let filename = att.filename.clone();
                    let att_id = att.id;
                    save.connect_clicked(move |button| {
                        crate::ui::vault_view::save_attachment_copy(
                            &state, &toast, button, att_id, &filename,
                        );
                    });
                }
                row.add_suffix(&save);
                let delete = gtk::Button::builder()
                    .icon_name("user-trash-symbolic")
                    .tooltip_text(tr!("Remove attachment"))
                    .valign(gtk::Align::Center)
                    .build();
                delete.add_css_class("flat");
                delete
                    .update_property(&[gtk::accessible::Property::Label(tr!("Remove attachment"))]);
                {
                    let state = state.clone();
                    let toast = toast.clone();
                    let render = render.clone();
                    let filename = att.filename.clone();
                    let att_id = att.id;
                    delete.connect_clicked(move |button| {
                        let confirm = adw::AlertDialog::builder()
                            .heading(tr!("Remove attachment?"))
                            .body(format!(
                                "{} “{filename}”",
                                tr!("This permanently removes the file")
                            ))
                            .close_response("cancel")
                            .default_response("cancel")
                            .build();
                        confirm.add_response("cancel", tr!("Cancel"));
                        confirm.add_response("remove", tr!("Remove"));
                        confirm.set_response_appearance(
                            "remove",
                            adw::ResponseAppearance::Destructive,
                        );
                        state.track_sensitive_dialog(&confirm);
                        let state = state.clone();
                        let toast = toast.clone();
                        let render = render.clone();
                        confirm.connect_response(None, move |_, response| {
                            if response != "remove" {
                                return;
                            }
                            match state.vault.borrow().delete_attachment(att_id) {
                                Ok(_) => toast.add_toast(
                                    adw::Toast::builder()
                                        .title(tr!("Attachment removed"))
                                        .timeout(3)
                                        .build(),
                                ),
                                Err(e) => toast.add_toast(
                                    adw::Toast::builder()
                                        .title(format!(
                                            "{}: {e}",
                                            tr!("Could not remove the attachment")
                                        ))
                                        .timeout(5)
                                        .build(),
                                ),
                            }
                            if let Some(r) = render.borrow().as_ref() {
                                r();
                            }
                        });
                        confirm.present(Some(button));
                    });
                }
                row.add_suffix(&delete);
                group.add(&row);
                rows.borrow_mut().push(row.upcast());
            }
        }
    });
    *render.borrow_mut() = Some(render_fn.clone());
    render_fn();

    {
        let state = state.clone();
        let toast = toast.clone();
        let render = render.clone();
        add_button.connect_clicked(move |button| {
            let parent = button.root().and_then(|r| r.downcast::<gtk::Window>().ok());
            let dialog = gtk::FileDialog::builder()
                .title(tr!("Add attachment"))
                .modal(true)
                .build();
            let state = state.clone();
            let toast = toast.clone();
            let render = render.clone();
            dialog.open(parent.as_ref(), None::<&gio::Cancellable>, move |result| {
                let Ok(file) = result else { return };
                let Some(path) = file.path() else { return };
                let data = match std::fs::read(&path) {
                    Ok(d) => d,
                    Err(e) => {
                        toast.add_toast(
                            adw::Toast::builder()
                                .title(format!("{}: {e}", tr!("Could not read the file")))
                                .timeout(5)
                                .build(),
                        );
                        return;
                    }
                };
                let filename = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("attachment")
                    .to_string();
                let mime = crate::ui::vault_view::mime_guess_from_ext(&filename);
                let added =
                    state
                        .vault
                        .borrow()
                        .add_attachment(eid, &filename, mime.as_deref(), &data);
                match added {
                    Ok(_) => {
                        toast.add_toast(
                            adw::Toast::builder()
                                .title(tr!("Attachment added"))
                                .timeout(3)
                                .build(),
                        );
                        if let Some(r) = render.borrow().as_ref() {
                            r();
                        }
                    }
                    Err(e) => toast.add_toast(
                        adw::Toast::builder()
                            .title(format!("{}: {e}", tr!("Could not add the attachment")))
                            .timeout(5)
                            .build(),
                    ),
                }
            });
        });
    }
    (group, render)
}

/// Suffix menu listing `values`, calling `pick` with the chosen one. `None`
/// when there is nothing to offer, so a fresh vault does not grow a dead
/// button. Values travel as action targets, so quotes or parentheses in a
/// name cannot break the menu model.
fn build_value_picker<F>(values: &[String], tooltip: &str, pick: F) -> Option<gtk::MenuButton>
where
    F: Fn(&str) + 'static,
{
    let values: Vec<String> = values
        .iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    if values.is_empty() {
        return None;
    }
    let button = gtk::MenuButton::builder()
        .icon_name("view-list-symbolic")
        .tooltip_text(tooltip)
        .valign(gtk::Align::Center)
        .build();
    button.add_css_class("flat");
    button.update_property(&[gtk::accessible::Property::Label(tooltip)]);
    let action = gio::SimpleAction::new("pick", Some(glib::VariantTy::STRING));
    action.connect_activate(move |_, target| {
        if let Some(value) = target.and_then(|t| t.str()) {
            pick(value);
        }
    });
    let group = gio::SimpleActionGroup::new();
    group.add_action(&action);
    let menu = gio::Menu::new();
    for value in &values {
        let item = gio::MenuItem::new(Some(value), None);
        item.set_action_and_target_value(Some("picker.pick"), Some(&value.to_variant()));
        menu.append_item(&item);
    }
    button.insert_action_group("picker", Some(&group));
    button.set_menu_model(Some(&menu));
    Some(button)
}

/// Append `tag` to a comma-separated tag entry, skipping duplicates.
fn append_tag(entry: &adw::EntryRow, tag: &str) {
    let mut tags: Vec<String> = entry
        .text()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if tags
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(tag))
    {
        return;
    }
    tags.push(tag.to_string());
    entry.set_text(&tags.join(", "));
    entry.set_position(-1);
}

fn trim_to_opt(s: &glib::GString) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_one_time_code_is_not_a_setup_key() {
        assert_eq!(
            parse_totp_input("482193", "SHA1", 6, 30),
            Err(TotpInputError::LooksLikeOneTimeCode)
        );
        assert_eq!(
            parse_totp_input("482 193", "SHA1", 6, 30),
            Err(TotpInputError::LooksLikeOneTimeCode)
        );
    }

    #[test]
    fn base32_keys_are_normalised() {
        let parsed = parse_totp_input("jbsw y3dp ehpk 3pxp", "SHA1", 6, 30).unwrap();
        assert_eq!(parsed.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(parsed.digits, 6);
    }

    #[test]
    fn otpauth_parameters_win_over_the_form() {
        let parsed = parse_totp_input(
            "otpauth://totp/Example:ana@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60",
            "SHA1",
            6,
            30,
        )
        .unwrap();
        assert_eq!(parsed.algorithm, "SHA256");
        assert_eq!(parsed.digits, 8);
        assert_eq!(parsed.period, 60);
        assert_eq!(parsed.issuer.as_deref(), Some("Example"));
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(matches!(
            parse_totp_input("not a key!", "SHA1", 6, 30),
            Err(TotpInputError::Invalid(_))
        ));
    }
}
