//! Ashy Pass — GTK4/libadwaita password manager (Rust port).

mod auto_sync;
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
    configure_graphics_backend();

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

            init_css();
            let win = ui::MainWindow::new(app, state);
            win.present();

            // Dev-only preview harnesses, enabled by env var. Designed to
            // exercise dialogs that normally require external setup (a
            // configured Nextcloud server, a token, etc.) so we can iterate
            // on visuals without the full integration. Each harness shows
            // its dialog as soon as the window is on screen and then
            // exits — the value can be a comma-separated list.
            if let Ok(preview) = std::env::var("ASHYPASS_PREVIEW") {
                for kind in preview.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    ui::preview::present(kind, &win.window);
                }
            }

            *window_holder.borrow_mut() = Some(win);
        });
    }

    app.run()
}

fn configure_graphics_backend() {
    if std::env::var_os("GSK_RENDERER").is_some() {
        return;
    }

    // Avoid GTK's Vulkan renderer by default. Some Mesa/Xe stacks can freeze
    // during list redraws with VK_ERROR_OUT_OF_DEVICE_MEMORY.
    std::env::set_var("GSK_RENDERER", "ngl");
}

fn init_i18n() {
    use gettextrs::{bindtextdomain, setlocale, textdomain, LocaleCategory};
    setlocale(LocaleCategory::LcAll, "");
    let locale_dir = app_locale_dir();
    let _ = bindtextdomain("ashypass", &locale_dir);
    let _ = textdomain("ashypass");
}

fn app_locale_dir() -> std::path::PathBuf {
    fn has_catalog(path: &std::path::Path) -> bool {
        path.join("en/LC_MESSAGES/ashypass.mo").is_file()
            || path.join("pt_BR/LC_MESSAGES/ashypass.mo").is_file()
    }

    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors() {
            let candidate = ancestor.join("usr/share/locale");
            if has_catalog(&candidate) {
                return candidate;
            }
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        let candidate = cwd.join("usr/share/locale");
        if has_catalog(&candidate) {
            return candidate;
        }
    }

    std::path::PathBuf::from("/usr/share/locale")
}

fn init_css() {
    let Some(display) = gdk::Display::default() else {
        return;
    };
    let provider = gtk::CssProvider::new();
    provider.load_from_string(
        "
        .sync-provider-badge {
            border-radius: 999px;
            padding: 2px 7px;
            font-weight: 600;
            font-size: 0.82em;
            background: rgba(53, 132, 228, 0.18);
            color: #1c71d8;
        }

        .sync-provider-badge:backdrop {
            background: rgba(53, 132, 228, 0.10);
            color: rgba(28, 113, 216, 0.70);
        }

        .folder-heading-icon {
            color: #62a0ea;
        }

        .folder-heading-icon:backdrop {
            color: rgba(98, 160, 234, 0.70);
        }

        .favorite-active {
            color: #62a0ea;
        }

        .favorite-active:backdrop {
            color: rgba(98, 160, 234, 0.70);
        }

        .favorite-inactive {
            color: rgba(255, 255, 255, 0.58);
        }

        .totp-code {
            font-size: 1.28em;
            font-weight: 700;
            letter-spacing: 1px;
        }
        ",
    );
    gtk::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
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
