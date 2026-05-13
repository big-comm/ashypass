//! Ashy Pass — GTK4/libadwaita password manager (Rust port).

mod clipboard;
mod events;
mod favicons;
mod session;
mod state;
mod ui;

use adw::prelude::*;
use ashypass_core::config::{database_path, ensure_directories, APP_ID, APP_NAME};
use ashypass_core::db::Vault;
use gtk::gio;
use state::{AppState, SharedState};
use std::cell::RefCell;
use std::rc::Rc;

fn main() -> glib::ExitCode {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn,ashypass=debug"),
    )
    .init();

    init_i18n();

    if let Err(e) = ensure_directories() {
        eprintln!("Failed to create application directories: {e}");
        return glib::ExitCode::FAILURE;
    }

    let app = adw::Application::builder()
        .application_id(APP_ID)
        .flags(gio::ApplicationFlags::default())
        .build();

    let state_holder: Rc<RefCell<Option<SharedState>>> = Rc::new(RefCell::new(None));
    let window_holder: Rc<RefCell<Option<ui::MainWindow>>> = Rc::new(RefCell::new(None));

    // app actions
    setup_app_actions(&app);

    {
        let state_holder = state_holder.clone();
        let window_holder = window_holder.clone();
        app.connect_activate(move |app| {
            if window_holder.borrow().is_some() {
                window_holder.borrow().as_ref().unwrap().present();
                return;
            }

            let vault = match Vault::open(database_path()) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Failed to open vault: {e}");
                    app.quit();
                    return;
                }
            };
            // Trash retention: purge anything older than the configured window.
            // 0 days means "never use the trash" — purge everything immediately
            // so the table doesn't accumulate stale rows.
            let s = ashypass_core::settings::Settings::load();
            let retention_secs = (s.trash_retention_days as i64) * 24 * 3600;
            let _ = vault.purge_trash(retention_secs);
            let state = AppState::new(vault);
            *state_holder.borrow_mut() = Some(state.clone());

            let win = ui::MainWindow::new(app, state);
            win.present();
            *window_holder.borrow_mut() = Some(win);
        });
    }

    app.run()
}

fn init_i18n() {
    use gettextrs::{bindtextdomain, setlocale, textdomain, LocaleCategory};
    setlocale(LocaleCategory::LcAll, "");
    let _ = bindtextdomain("ashypass", "/usr/share/locale");
    let _ = textdomain("ashypass");
}

fn setup_app_actions(app: &adw::Application) {
    let quit = gio::SimpleAction::new("quit", None);
    let app_cl = app.clone();
    quit.connect_activate(move |_, _| app_cl.quit());
    app.add_action(&quit);
    app.set_accels_for_action("app.quit", &["<Primary>q"]);

    let about = gio::SimpleAction::new("about", None);
    let app_cl = app.clone();
    about.connect_activate(move |_, _| show_about(&app_cl));
    app.add_action(&about);
}

fn show_about(app: &adw::Application) {
    let parent = app.active_window();
    let about = adw::AboutDialog::builder()
        .application_name(APP_NAME)
        .application_icon("ashypass")
        .version(env!("CARGO_PKG_VERSION"))
        .developer_name("Big Community")
        .license_type(gtk::License::MitX11)
        .comments("Modern password generator and encrypted password vault")
        .website("https://github.com/big-comm")
        .issue_url("https://github.com/big-comm/ashypass/issues")
        .build();
    match parent {
        Some(w) => about.present(Some(&w)),
        None => about.present(None::<&gtk::Widget>),
    }
}
