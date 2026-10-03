//! Ashy Pass — GTK4/libadwaita password manager (Rust port).

mod auto_sync;
mod clipboard;
mod events;
mod favicons;
mod session;
mod session_watch;
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
            ui::settings_dialog::apply_color_scheme(&state.settings().color_scheme);
            let win = ui::MainWindow::new(app, state.clone());
            session_watch::install(state.clone(), win.lock_handle());
            win.present();
            #[cfg(debug_assertions)]
            run_dev_script(&win);

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

    // Leaving the process must not leave secrets behind: wipe a still-pending
    // clipboard copy and drop the session keys (including the quick-unlock
    // cache) rather than relying on the allocator.
    {
        let state_holder = state_holder.clone();
        app.connect_shutdown(move |_| {
            clipboard::clear_on_exit();
            if let Some(state) = state_holder.borrow().as_ref() {
                state.vault.borrow_mut().full_lock();
            }
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
    add_dev_icon_path(&display);

    let provider = gtk::CssProvider::new();
    provider.load_from_string(BASE_CSS);
    gtk::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    // White text on some accent colours falls short of 4.5:1 (the teal
    // accent gives about 3.8:1). Darken the background of filled accent
    // buttons instead of repainting more of the interface with it. Needs the
    // CSS variables and color-mix() of GTK 4.16+; older GTK keeps the theme.
    if gtk::check_version(4, 16, 0).is_none() {
        let contrast = gtk::CssProvider::new();
        contrast.load_from_string(ACCENT_CONTRAST_CSS);
        gtk::style_context_add_provider_for_display(
            &display,
            &contrast,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}

const BASE_CSS: &str = "
listview.ashy-entry-list {
    background: none;
    padding: 4px 12px 12px 12px;
}
listview.ashy-entry-list > row {
    padding: 0;
    margin: 3px 0;
    border-radius: 12px;
    background-color: @card_bg_color;
    box-shadow: 0 0 0 1px alpha(@card_shade_color, 0.6), 0 1px 2px alpha(@card_shade_color, 0.8);
}
.ashy-entry-row.ashy-open {
    border-radius: 12px;
    background-color: alpha(@accent_bg_color, 0.12);
    box-shadow: inset 0 0 0 2px alpha(@accent_bg_color, 0.45);
}
listview.ashy-entry-list.ashy-compact > row {
    margin: 1px 0;
    border-radius: 8px;
}
listview.ashy-entry-list.ashy-compact .ashy-entry-row {
    padding-top: 3px;
    padding-bottom: 3px;
    min-height: 34px;
}
listview.ashy-entry-list > row:hover {
    background-color: mix(@card_bg_color, @window_fg_color, 0.04);
}
.ashy-entry-row {
    padding: 8px 8px 8px 12px;
    min-height: 44px;
}
button.ashy-row-action {
    padding: 6px 14px;
    font-weight: 600;
    color: @accent_color;
    background-color: alpha(@accent_bg_color, 0.12);
}
button.ashy-row-action:hover {
    background-color: alpha(@accent_bg_color, 0.20);
}
.ashy-favorite {
    color: @warning_color;
}
.ashy-badge {
    border-radius: 999px;
    padding: 2px 8px;
    font-weight: 600;
    color: @accent_color;
    background-color: alpha(@accent_bg_color, 0.14);
}
.ashy-note {
    padding: 10px 12px;
    border-radius: 10px;
    background-color: alpha(@accent_bg_color, 0.08);
}
.ashy-result-card {
    padding: 14px 10px 14px 18px;
}
.ashy-secret-large {
    font-size: 1.55em;
    font-weight: 600;
}
.ashy-code {
    font-size: 1.35em;
    font-weight: 700;
    letter-spacing: 1px;
}
.ashy-code-large {
    font-size: 1.75em;
}
.ashy-code-expiring {
    color: @warning_color;
}
levelbar.ashy-code-timer trough,
levelbar.ashy-code-timer block {
    min-height: 4px;
}
row.ashy-revealed .subtitle {
    font-family: monospace;
}
.ashy-lock-button {
    padding: 8px 12px;
}
row.ashy-nav-separator {
    min-height: 0;
    padding-top: 6px;
    padding-bottom: 6px;
    background: none;
}
button.ashy-source-card {
    padding: 0;
}
textview.ashy-notes, textview.ashy-notes text {
    background: none;
}
";

const ACCENT_CONTRAST_CSS: &str = "
button.suggested-action,
button.suggested-action:checked,
splitbutton.suggested-action > button,
splitbutton.suggested-action > menubutton > button {
    background-color: color-mix(in srgb, var(--accent-bg-color) 80%, black);
}
";

/// In a development checkout the app icon is not installed yet; let the icon
/// theme find it in the repository's `usr/share/icons`.
fn add_dev_icon_path(display: &gdk::Display) {
    let theme = gtk::IconTheme::for_display(display);
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        candidates.extend(exe.ancestors().map(|a| a.join("usr/share/icons")));
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("usr/share/icons"));
    }
    if let Some(dir) = candidates
        .into_iter()
        .find(|dir| dir.join("hicolor/scalable/apps/ashypass.svg").is_file())
    {
        theme.add_search_path(dir);
    }
}

/// Development harness: `ASHYPASS_DEV_SCRIPT="unlock:pw;seed;page:vault;shot:/tmp/a.png;quit"`.
/// Debug builds only, and only when both XDG data and config directories
/// point into /tmp — it creates entries and must never meet a real vault.
#[cfg(debug_assertions)]
fn run_dev_script(window: &ui::MainWindow) {
    let Ok(script) = std::env::var("ASHYPASS_DEV_SCRIPT") else {
        return;
    };
    let safe = ["XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"]
        .iter()
        .all(|var| std::env::var(var).is_ok_and(|v| v.starts_with("/tmp/")));
    if !safe {
        eprintln!("ASHYPASS_DEV_SCRIPT refused: XDG_DATA_HOME, XDG_CONFIG_HOME and XDG_CACHE_HOME must be under /tmp");
        return;
    }
    let steps: std::collections::VecDeque<String> = script
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let dev = Rc::new(window.dev());
    let steps = Rc::new(RefCell::new(steps));
    fn next(
        dev: Rc<ui::window::DevHandle>,
        steps: Rc<RefCell<std::collections::VecDeque<String>>>,
    ) {
        let Some(step) = steps.borrow_mut().pop_front() else {
            return;
        };
        let mut delay = 350;
        let (cmd, arg) = step.split_once(':').unwrap_or((step.as_str(), ""));
        match cmd {
            "wait" => delay = arg.parse().unwrap_or(500),
            "seed" => dev_seed(&dev.state()),
            "shot" => dev_screenshot(&dev.window(), arg),
            "quit" => {
                if let Some(app) = dev.window().application() {
                    app.quit();
                }
                return;
            }
            _ => dev.run_step(&step),
        }
        glib::timeout_add_local_once(std::time::Duration::from_millis(delay), move || {
            next(dev, steps)
        });
    }
    glib::timeout_add_local_once(std::time::Duration::from_millis(800), move || {
        next(dev, steps)
    });
}

#[cfg(debug_assertions)]
fn dev_seed(state: &SharedState) {
    use ashypass_core::db::vault::NewEntry;
    let vault = state.vault.borrow();
    if !vault.is_unlocked() || vault.list(None).map(|l| !l.is_empty()).unwrap_or(true) {
        return;
    }
    type Sample<'a> = (
        &'a str,
        &'a str,
        &'a str,
        Option<&'a str>,
        Option<&'a str>,
        bool,
    );
    let samples: &[Sample] = &[
        (
            "GitHub",
            "dev@example.com",
            "https://github.com",
            Some("Trabalho"),
            Some("JBSWY3DPEHPK3PXP"),
            true,
        ),
        (
            "Nextcloud",
            "ana",
            "https://nextcloud.com",
            Some("Trabalho"),
            Some("KRSXG5CTMVRXEZLU"),
            false,
        ),
        (
            "Wikipedia",
            "ana.souza",
            "https://www.wikipedia.org",
            None,
            None,
            false,
        ),
        (
            "Loja de exemplo",
            "cliente@example.com",
            "https://loja.example.com/conta/login",
            Some("Compras"),
            None,
            true,
        ),
        (
            "Servidor de testes",
            "root",
            "192.168.0.10",
            Some("Trabalho"),
            None,
            false,
        ),
        (
            "Mozilla",
            "ana@example.com",
            "https://accounts.firefox.com",
            Some("Pessoal"),
            Some("GEZDGNBVGY3TQOJQ"),
            false,
        ),
        (
            "GitLab",
            "ana",
            "https://gitlab.com",
            Some("Trabalho"),
            None,
            false,
        ),
        (
            "Debian Wiki",
            "ana",
            "https://wiki.debian.org",
            Some("Pessoal"),
            None,
            false,
        ),
    ];
    for (title, user, url, folder, totp, favorite) in samples {
        let id = vault.add(NewEntry {
            title: title.to_string(),
            username: Some(user.to_string()),
            password: ashypass_core::generator::generate_password(
                &ashypass_core::generator::PasswordConfig::default(),
            )
            .unwrap_or_default(),
            url: Some(url.to_string()),
            notes: (*title == "Servidor de testes")
                .then(|| "Acesso SSH apenas pela VPN.\nPorta 2222.".to_string()),
            totp_secret: totp.map(str::to_string),
            totp_algorithm: None,
            totp_digits: None,
            totp_period: None,
            category: folder.map(str::to_string),
        });
        if let (Ok(id), true) = (id, *favorite) {
            let _ = vault.set_favorite(id, true);
        }
    }
    drop(vault);
    state.events.emit(events::AppEvent::VaultChanged);
}

#[cfg(debug_assertions)]
fn dev_screenshot(window: &adw::ApplicationWindow, path: &str) {
    let width = window.width();
    let height = window.height();
    let paintable = gtk::WidgetPaintable::new(Some(window));
    let snapshot = gtk::Snapshot::new();
    paintable.snapshot(&snapshot, width as f64, height as f64);
    let Some(node) = snapshot.to_node() else {
        eprintln!("dev screenshot: nothing to render");
        return;
    };
    let Some(renderer) = window.renderer() else {
        eprintln!("dev screenshot: no renderer");
        return;
    };
    let texture = renderer.render_texture(
        &node,
        Some(&gtk::graphene::Rect::new(
            0.0,
            0.0,
            width as f32,
            height as f32,
        )),
    );
    match texture.save_to_png(path) {
        Ok(()) => eprintln!("dev screenshot: {path}"),
        Err(e) => eprintln!("dev screenshot failed: {e}"),
    }
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
        .version(ashypass_core::config::APP_VERSION)
        .developer_name("Big Community")
        .license_type(gtk::License::MitX11)
        .comments(tr!(
            "Modern password generator and encrypted password vault"
        ))
        .website("https://github.com/big-comm")
        .issue_url("https://github.com/big-comm/ashypass/issues")
        .build();
    match parent {
        Some(w) => about.present(Some(&w)),
        None => about.present(None::<&gtk::Widget>),
    }
}
