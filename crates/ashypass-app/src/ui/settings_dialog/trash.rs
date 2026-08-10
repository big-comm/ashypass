//! `settings_dialog` — trash section.

use super::*;

// ---------------------------------------------------------------------------
// Trash
// ---------------------------------------------------------------------------

pub(super) fn populate_trash(
    page: &adw::PreferencesPage,
    state: SharedState,
    settings: Rc<RefCell<Settings>>,
    toast: adw::ToastOverlay,
) {
    // Retention setting
    let retention_group = adw::PreferencesGroup::builder()
        .title(tr!("Retention"))
        .description(tr!(
            "Deleted entries stay in the trash for this many days, then are \
             permanently removed on next app start. Set 0 to bypass the trash."
        ))
        .build();
    let retention_row = adw::SpinRow::with_range(0.0, 365.0, 1.0);
    retention_row.set_title(tr!("Keep deleted entries for (days)"));
    retention_row.set_value(settings.borrow().trash_retention_days as f64);
    {
        let settings = settings.clone();
        retention_row.connect_value_notify(move |row| {
            settings.borrow_mut().trash_retention_days = row.value() as u32;
            save_settings(&settings.borrow());
        });
    }
    retention_group.add(&retention_row);
    page.add(&retention_group);

    // Listing
    let list_group = adw::PreferencesGroup::builder()
        .title(tr!("Trashed entries"))
        .build();
    page.add(&list_group);

    let list_holder = Rc::new(RefCell::new(list_group.clone()));
    let trash_rows: Rc<RefCell<Vec<gtk::Widget>>> = Rc::new(RefCell::new(Vec::new()));
    // Self-referential render closure: stored in a RefCell so button handlers
    // built during rendering can re-invoke it once it's installed.
    let render_slot: RenderSlot = Rc::new(RefCell::new(None));
    let render: Rc<dyn Fn()> = {
        let state = state.clone();
        let holder = list_holder.clone();
        let toast = toast.clone();
        let render_slot = render_slot.clone();
        let trash_rows = trash_rows.clone();
        Rc::new(move || {
            let group = holder.borrow().clone();
            for row in trash_rows.borrow_mut().drain(..) {
                group.remove(&row);
            }
            let entries = match state.vault.borrow().list_trash() {
                Ok(v) => v,
                Err(e) => {
                    let row = adw::ActionRow::builder().title(format!("{e}")).build();
                    group.add(&row);
                    trash_rows.borrow_mut().push(row.upcast());
                    return;
                }
            };
            if entries.is_empty() {
                let row = adw::ActionRow::builder()
                    .title(tr!("Trash is empty."))
                    .build();
                group.add(&row);
                trash_rows.borrow_mut().push(row.upcast());
                return;
            }
            for t in entries {
                let when = chrono::DateTime::<chrono::Utc>::from_timestamp(t.deleted_at, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                    .unwrap_or_default();
                let row = adw::ActionRow::builder()
                    .title(&t.title)
                    .subtitle(format!(
                        "{} — {}",
                        t.username.as_deref().unwrap_or(""),
                        when
                    ))
                    .build();

                let restore_btn = gtk::Button::builder()
                    .icon_name("edit-undo-symbolic")
                    .tooltip_text(tr!("Restore"))
                    .valign(gtk::Align::Center)
                    .build();
                restore_btn.add_css_class("flat");
                let purge_btn = gtk::Button::builder()
                    .icon_name("edit-delete-symbolic")
                    .tooltip_text(tr!("Delete permanently"))
                    .valign(gtk::Align::Center)
                    .build();
                purge_btn.add_css_class("flat");

                {
                    let state = state.clone();
                    let toast = toast.clone();
                    let trash_id = t.trash_id;
                    let render_slot = render_slot.clone();
                    restore_btn.connect_clicked(move |_| {
                        let r = state.vault.borrow().restore_from_trash(trash_id);
                        match r {
                            Ok(Some(_)) => {
                                toast.add_toast(
                                    adw::Toast::builder()
                                        .title(tr!("Entry restored"))
                                        .timeout(3)
                                        .build(),
                                );
                                if let Some(cb) = render_slot.borrow().clone() {
                                    (cb)();
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                toast.add_toast(
                                    adw::Toast::builder()
                                        .title(format!("{e}"))
                                        .timeout(3)
                                        .build(),
                                );
                            }
                        }
                    });
                }
                {
                    let state = state.clone();
                    let toast = toast.clone();
                    let trash_id = t.trash_id;
                    let render_slot = render_slot.clone();
                    purge_btn.connect_clicked(move |_| {
                        let r = state.vault.borrow().delete_from_trash(trash_id);
                        match r {
                            Ok(_) => {
                                toast.add_toast(
                                    adw::Toast::builder()
                                        .title(tr!("Permanently deleted"))
                                        .timeout(3)
                                        .build(),
                                );
                                if let Some(cb) = render_slot.borrow().clone() {
                                    (cb)();
                                }
                            }
                            Err(e) => {
                                toast.add_toast(
                                    adw::Toast::builder()
                                        .title(format!("{e}"))
                                        .timeout(3)
                                        .build(),
                                );
                            }
                        }
                    });
                }

                row.add_suffix(&restore_btn);
                row.add_suffix(&purge_btn);
                group.add(&row);
                trash_rows.borrow_mut().push(row.upcast());
            }
        })
    };
    *render_slot.borrow_mut() = Some(render.clone());
    (render)();

    let action_group = adw::PreferencesGroup::new();
    let refresh_row = adw::ActionRow::builder()
        .title(tr!("Refresh listing"))
        .activatable(true)
        .build();
    {
        let render = render.clone();
        refresh_row.connect_activated(move |_| (render)());
    }
    action_group.add(&refresh_row);

    let empty_row = adw::ActionRow::builder()
        .title(tr!("Empty trash"))
        .subtitle(tr!("Permanently deletes every trashed entry."))
        .activatable(true)
        .build();
    {
        let state = state.clone();
        let toast = toast.clone();
        let render = render.clone();
        empty_row.connect_activated(move |_| match state.vault.borrow().empty_trash() {
            Ok(n) => {
                toast.add_toast(
                    adw::Toast::builder()
                        .title(format!("{} {}", n, tr!("entries removed")))
                        .timeout(3)
                        .build(),
                );
                (render)();
            }
            Err(e) => {
                toast.add_toast(
                    adw::Toast::builder()
                        .title(format!("{e}"))
                        .timeout(3)
                        .build(),
                );
            }
        });
    }
    action_group.add(&empty_row);
    page.add(&action_group);
}
