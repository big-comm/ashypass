//! "Organize folders": create, rename and remove folders.
//!
//! Removing a folder says exactly what happens — the passwords inside stay
//! in the vault and move to "No folder" — and never deletes an entry.

use crate::state::SharedState;
use crate::tr;
use crate::trn;
use adw::prelude::*;
use std::cell::RefCell;
use std::rc::Rc;

type RenderSlot = Rc<RefCell<Option<Rc<dyn Fn()>>>>;

pub fn present(state: &SharedState, toast: &adw::ToastOverlay, parent: &impl IsA<gtk::Widget>) {
    let dialog = adw::Dialog::builder()
        .title(tr!("Organize folders"))
        .content_width(480)
        .content_height(520)
        .build();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let page = adw::PreferencesPage::new();
    let group = adw::PreferencesGroup::builder()
        .description(tr!(
            "Removing a folder keeps its passwords. They move to “No folder”."
        ))
        .build();
    let add = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text(tr!("Create folder"))
        .valign(gtk::Align::Center)
        .build();
    add.add_css_class("flat");
    add.update_property(&[gtk::accessible::Property::Label(tr!("Create folder"))]);
    group.set_header_suffix(Some(&add));
    page.add(&group);
    toolbar.set_content(Some(&page));
    dialog.set_child(Some(&toolbar));

    let rows: Rc<RefCell<Vec<gtk::Widget>>> = Rc::default();
    let render: RenderSlot = Rc::default();
    let render_fn: Rc<dyn Fn()> = Rc::new({
        let state = state.clone();
        let toast = toast.clone();
        let group = group.clone();
        let rows = rows.clone();
        let render = render.clone();
        move || {
            for row in rows.borrow_mut().drain(..) {
                group.remove(&row);
            }
            let counts = state.vault.borrow().folder_counts().unwrap_or_default();
            if counts.is_empty() {
                let row = adw::ActionRow::builder()
                    .title(tr!("No folders yet"))
                    .subtitle(tr!("Use the + button to create one."))
                    .build();
                group.add(&row);
                rows.borrow_mut().push(row.upcast());
                return;
            }
            for (name, count) in counts {
                let row = adw::ActionRow::builder()
                    .title(&name)
                    .subtitle(
                        trn!("{} password", "{} passwords", count)
                            .replace("{}", &count.to_string()),
                    )
                    .use_markup(false)
                    .build();
                row.add_prefix(&gtk::Image::from_icon_name("folder-symbolic"));
                let rename = gtk::Button::builder()
                    .icon_name("document-edit-symbolic")
                    .tooltip_text(tr!("Rename"))
                    .valign(gtk::Align::Center)
                    .build();
                rename.add_css_class("flat");
                rename.update_property(&[gtk::accessible::Property::Label(&format!(
                    "{} {name}",
                    tr!("Rename")
                ))]);
                let remove = gtk::Button::builder()
                    .icon_name("user-trash-symbolic")
                    .tooltip_text(tr!("Remove folder"))
                    .valign(gtk::Align::Center)
                    .build();
                remove.add_css_class("flat");
                remove.update_property(&[gtk::accessible::Property::Label(&format!(
                    "{} {name}",
                    tr!("Remove folder")
                ))]);
                {
                    let state = state.clone();
                    let toast = toast.clone();
                    let render = render.clone();
                    let name = name.clone();
                    rename.connect_clicked(move |button| {
                        ask_name(button, tr!("Rename folder"), &name, tr!("Rename"), {
                            let state = state.clone();
                            let toast = toast.clone();
                            let render = render.clone();
                            let old = name.clone();
                            move |new| {
                                let result = state.vault.borrow().rename_folder(&old, new);
                                let message = match result {
                                    Ok(_) => tr!("Folder renamed").to_string(),
                                    Err(e) => {
                                        format!("{}: {e}", tr!("Could not rename the folder"))
                                    }
                                };
                                toast.add_toast(
                                    adw::Toast::builder().title(message).timeout(3).build(),
                                );
                                if let Some(r) = render.borrow().as_ref() {
                                    r();
                                }
                            }
                        });
                    });
                }
                {
                    let state = state.clone();
                    let toast = toast.clone();
                    let render = render.clone();
                    let name = name.clone();
                    remove.connect_clicked(move |button| {
                        let body = if count == 0 {
                            tr!("The folder is empty.").to_string()
                        } else {
                            trn!(
                                "The {} password in it stays in the vault and moves to “No folder”.",
                                "The {} passwords in it stay in the vault and move to “No folder”.",
                                count
                            )
                            .replace("{}", &count.to_string())
                        };
                        let confirm = adw::AlertDialog::builder()
                            .heading(format!("{} “{name}”?", tr!("Remove folder")))
                            .body(&body)
                            .close_response("cancel")
                            .default_response("cancel")
                            .build();
                        confirm.add_response("cancel", tr!("Cancel"));
                        confirm.add_response("remove", tr!("Remove folder"));
                        confirm
                            .set_response_appearance("remove", adw::ResponseAppearance::Destructive);
                        let state = state.clone();
                        let toast = toast.clone();
                        let render = render.clone();
                        let name = name.clone();
                        confirm.connect_response(None, move |_, response| {
                            if response != "remove" {
                                return;
                            }
                            let message =
                                match state.vault.borrow().remove_folder_keep_entries(&name) {
                                    Ok(_) => tr!("Folder removed. Its passwords were kept.")
                                        .to_string(),
                                    Err(e) => format!(
                                        "{}: {e}",
                                        tr!("Could not remove the folder")
                                    ),
                                };
                            toast.add_toast(
                                adw::Toast::builder().title(message).timeout(4).build(),
                            );
                            if let Some(r) = render.borrow().as_ref() {
                                r();
                            }
                        });
                        confirm.present(Some(button));
                    });
                }
                row.add_suffix(&rename);
                row.add_suffix(&remove);
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
        add.connect_clicked(move |button| {
            let state = state.clone();
            let toast = toast.clone();
            let render = render.clone();
            ask_name(
                button,
                tr!("Create folder"),
                "",
                tr!("Create"),
                move |name| {
                    let message = match state.vault.borrow().create_folder(name) {
                        Ok(true) => tr!("Folder created").to_string(),
                        Ok(false) => tr!("This folder already exists").to_string(),
                        Err(e) => format!("{}: {e}", tr!("Could not create the folder")),
                    };
                    toast.add_toast(adw::Toast::builder().title(message).timeout(3).build());
                    if let Some(r) = render.borrow().as_ref() {
                        r();
                    }
                },
            );
        });
    }

    state.track_sensitive_dialog(&dialog);
    dialog.present(Some(parent));
}

fn ask_name<F>(anchor: &impl IsA<gtk::Widget>, heading: &str, current: &str, action: &str, done: F)
where
    F: Fn(&str) + 'static,
{
    let dialog = adw::AlertDialog::builder()
        .heading(heading)
        .default_response("ok")
        .close_response("cancel")
        .build();
    dialog.add_response("cancel", tr!("Cancel"));
    dialog.add_response("ok", action);
    dialog.set_response_appearance("ok", adw::ResponseAppearance::Suggested);
    let entry = adw::EntryRow::builder()
        .title(tr!("Folder name"))
        .text(current)
        .activates_default(true)
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .build();
    list.add_css_class("boxed-list");
    list.append(&entry);
    dialog.set_extra_child(Some(&list));
    dialog.connect_response(None, move |_, response| {
        if response == "ok" {
            let name = entry.text().trim().to_string();
            if !name.is_empty() {
                done(&name);
            }
        }
    });
    dialog.present(Some(anchor));
}
