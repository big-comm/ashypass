//! Ashy Pass — terminal companion.
//!
//! Reuses the same on-disk vault as the GTK app (`~/.local/share/ashypass/passwords.db`)
//! and the same Secret Service item, so configuring keyring unlock in the GUI
//! makes the CLI password-less too. When no stored master is available we
//! prompt on stdin with echo turned off.

use anyhow::{anyhow, bail, Context, Result};
use ashypass_core::db::vault::{NewEntry, PasswordEntry, Vault};
use ashypass_core::generator::{
    generate_passphrase, generate_password, generate_pin, PasswordConfig,
};
use ashypass_core::totp::{generate_totp, Algorithm};
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "ashypass-cli",
    about = "Ashy Pass — terminal companion",
    version
)]
struct Cli {
    /// Override the vault database path. Defaults to the GUI's location.
    #[arg(long, global = true)]
    db: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// List entries (no decrypted secrets).
    List(ListArgs),
    /// Show one entry, including the decrypted password and live TOTP code.
    Show(ShowArgs),
    /// Print the current TOTP code for an entry.
    Totp(ShowArgs),
    /// Generate a password.
    Gen(GenArgs),
    /// Create a new entry (prompts for fields).
    Add(AddArgs),
    /// External drive encryption (LUKS2).
    Drives {
        #[command(subcommand)]
        action: DrivesAction,
    },
}

#[derive(Subcommand, Debug)]
enum DrivesAction {
    /// List removable / hotplug block devices that are candidates for encryption.
    List {
        /// Include non-removable disks (use with care — the system disk will appear).
        #[arg(long)]
        all: bool,
    },
    /// Show the LUKS header metadata of an encrypted device.
    Info {
        /// Block device, e.g. /dev/sda.
        device: std::path::PathBuf,
        /// Emit the full LUKS2 JSON metadata (includes Argon2id keyslot
        /// parameters and digest tuning that the human-readable view omits).
        #[arg(long)]
        json: bool,
    },
    /// **Destructive.** Encrypt a block device with LUKS2.
    Format {
        device: std::path::PathBuf,
        /// User-visible label written to the LUKS2 header and the filesystem.
        #[arg(long)]
        label: Option<String>,
        /// Filesystem to create on top of the opened mapping.
        #[arg(long, default_value = "ext4")]
        filesystem: String,
        /// Pre-format wipe strategy.
        ///
        /// `encrypted-zero` (default, recommended) — fills the device with
        /// AES-encrypted zeros at line rate.
        /// `secure-discard` — SSD/NVMe TRIM secure-erase.
        /// `random` — single pass of /dev/urandom (slow).
        /// `none` — skip; prior plaintext outside LUKS sectors may survive.
        #[arg(long, default_value = "encrypted-zero", conflicts_with = "quick")]
        wipe: String,
        /// Shortcut for `--wipe none`: just writes the LUKS header and
        /// filesystem, instant. Equivalent to Linux Mint's "encrypt with
        /// LUKS" tool. **Forensic residue from prior writes will survive
        /// outside the LUKS data region.**
        #[arg(long)]
        quick: bool,
        /// Forward TRIM commands through the mapping. Off by default; leaks
        /// free-space patterns to the underlying device.
        #[arg(long)]
        allow_discards: bool,
        /// Skip the interactive "type the device path" guard. Required by
        /// scripts; never use it interactively.
        #[arg(long)]
        i_understand_this_erases_everything: bool,
    },
    /// Open an encrypted device and expose it under /dev/mapper.
    Unlock {
        device: std::path::PathBuf,
        /// Label used to derive the mapper name (must match the label used
        /// at format time, or be supplied via --mapper-name).
        #[arg(long)]
        label: Option<String>,
        /// Explicit mapper name; overrides the label-derived default.
        #[arg(long)]
        mapper_name: Option<String>,
        /// Forward TRIM through the mapping.
        #[arg(long)]
        allow_discards: bool,
    },
    /// Close an open mapping.
    Lock {
        /// Mapper name (e.g. `ashypass_vault`) or full /dev/mapper/... path.
        mapper: String,
    },
    /// Enrol a FIDO2 security token (Yubikey, Nitrokey, etc.) so the drive
    /// can be unlocked by tap/touch in addition to (or instead of) a
    /// passphrase. Calls `systemd-cryptenroll --fido2-device=auto`.
    EnrollFido2 {
        device: std::path::PathBuf,
        /// Require the FIDO2 PIN at unlock time (typically yes).
        #[arg(long, default_value_t = true)]
        require_pin: bool,
        /// Require user-presence (touch the token) at unlock time.
        #[arg(long, default_value_t = true)]
        require_presence: bool,
    },
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Only show entries whose category equals this (case-sensitive).
    #[arg(long)]
    category: Option<String>,
    /// Only show entries carrying this tag.
    #[arg(long)]
    tag: Option<String>,
    /// Substring filter on title/username/url.
    #[arg(long)]
    search: Option<String>,
}

#[derive(Args, Debug)]
struct ShowArgs {
    /// Numeric id or exact title.
    selector: String,
}

#[derive(Args, Debug)]
struct GenArgs {
    /// Length in characters (ignored for --passphrase / --pin).
    #[arg(long, default_value_t = 20)]
    length: usize,
    /// Generate a 4-word passphrase instead.
    #[arg(long)]
    passphrase: bool,
    /// Generate a numeric PIN instead.
    #[arg(long)]
    pin: bool,
    /// PIN length when --pin is used.
    #[arg(long, default_value_t = 6)]
    pin_length: usize,
}

#[derive(Args, Debug)]
struct AddArgs {
    /// Entry title.
    title: String,
    /// Username (optional).
    #[arg(long)]
    username: Option<String>,
    /// URL (optional).
    #[arg(long)]
    url: Option<String>,
    /// Category (optional).
    #[arg(long)]
    category: Option<String>,
    /// Read the password from stdin instead of prompting interactively.
    #[arg(long)]
    password_stdin: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let db_path = cli.db.unwrap_or_else(ashypass_core::config::database_path);

    match cli.command {
        Command::Gen(a) => run_gen(a),
        Command::Drives { action } => run_drives(action),
        cmd => {
            let mut vault = Vault::open(&db_path).context("opening vault")?;
            unlock_vault(&mut vault)?;
            match cmd {
                Command::List(a) => run_list(&vault, a),
                Command::Show(a) => run_show(&vault, a, false),
                Command::Totp(a) => run_show(&vault, a, true),
                Command::Add(a) => run_add(&vault, a),
                Command::Gen(_) | Command::Drives { .. } => unreachable!(),
            }
        }
    }
}

fn run_drives(action: DrivesAction) -> Result<()> {
    use ashypass_drives::detect::{human_size, list_all, list_removable};
    use ashypass_drives::fs::Filesystem;
    use ashypass_drives::pipeline::{
        encrypt_new_drive, mapper_name_for, unlock_existing, EncryptRequest, Progress,
    };
    use ashypass_drives::runner::{auto_runner, CommandSpec};
    use ashypass_drives::safety;
    use ashypass_drives::wipe::WipeMode;

    let parse_fs = |s: &str| -> Result<Filesystem> {
        match s {
            "ext4" => Ok(Filesystem::Ext4),
            "btrfs" => Ok(Filesystem::Btrfs),
            "xfs" => Ok(Filesystem::Xfs),
            other => Err(anyhow!("unknown filesystem: {other}")),
        }
    };
    let parse_wipe = |s: &str| -> Result<WipeMode> {
        match s {
            "encrypted-zero" => Ok(WipeMode::EncryptedZero),
            "secure-discard" => Ok(WipeMode::SecureDiscard),
            "random" => Ok(WipeMode::Random),
            "none" => Ok(WipeMode::None),
            other => Err(anyhow!("unknown wipe mode: {other}")),
        }
    };

    match action {
        DrivesAction::List { all } => {
            let drives = if all { list_all() } else { list_removable() }
                .map_err(|e| anyhow!("listing drives: {e}"))?;
            if drives.is_empty() {
                println!("No removable drives detected.");
                if !all {
                    println!("(Re-run with --all to include fixed disks.)");
                }
                return Ok(());
            }
            println!(
                "{:<12} {:>10} {:<5} {:<20} {:<24} FLAGS",
                "DEVICE", "SIZE", "BUS", "VENDOR", "MODEL"
            );
            for d in drives {
                let mut flags = Vec::new();
                if d.removable {
                    flags.push("removable");
                }
                if d.hotplug {
                    flags.push("hotplug");
                }
                if d.read_only {
                    flags.push("ro");
                }
                if !d.partitions.is_empty() {
                    flags.push("partitioned");
                }
                println!(
                    "{:<12} {:>10} {:<5} {:<20} {:<24} {}",
                    d.path,
                    human_size(d.size_bytes),
                    d.transport.as_deref().unwrap_or("-"),
                    d.vendor.as_deref().unwrap_or("-"),
                    d.model.as_deref().unwrap_or("-"),
                    flags.join(",")
                );
                for p in d.partitions {
                    println!(
                        "  └─ {:<8} {:>10}  {}  {}",
                        p.name,
                        human_size(p.size_bytes),
                        p.fstype.as_deref().unwrap_or("-"),
                        p.mountpoint.as_deref().unwrap_or("(not mounted)")
                    );
                }
            }
            Ok(())
        }

        DrivesAction::Info { device, json } => {
            let runner = auto_runner();
            let mut spec = CommandSpec::new("cryptsetup").arg("luksDump");
            if json {
                spec = spec.arg("--dump-json-metadata");
            }
            spec = spec.arg(device.to_string_lossy().into_owned());
            let out = runner
                .run(spec)
                .map_err(|e| anyhow!("luksDump failed: {e}"))?;
            print!("{}", String::from_utf8_lossy(&out.stdout));
            Ok(())
        }

        DrivesAction::Format {
            device,
            label,
            filesystem,
            wipe,
            quick,
            allow_discards,
            i_understand_this_erases_everything,
        } => {
            let filesystem = parse_fs(&filesystem)?;
            let wipe_mode = if quick {
                eprintln!(
                    "  ℹ --quick: skipping the pre-format wipe. Prior plaintext\n\
                     \x20   outside the LUKS data region may remain recoverable."
                );
                WipeMode::None
            } else {
                parse_wipe(&wipe)?
            };
            let label = label.unwrap_or_else(|| "ashypass".into());

            // Safety pre-flight before we collect a passphrase, so we fail
            // fast and the user doesn't waste a prompt typing on a device
            // that was always going to be refused.
            let report = safety::inspect(&device, safety::SafetyPolicy::default())
                .map_err(|e| anyhow!("safety check failed: {e}"))?;

            print_device_block(&device, &report);

            if !report.allow_destructive {
                bail!(
                    "Refusing to format: {}",
                    report.reasons.join("; ")
                );
            }

            if !i_understand_this_erases_everything {
                let expected = device.to_string_lossy().to_string();
                eprintln!();
                eprintln!(
                    "  ⚠ This will PERMANENTLY ERASE everything on {expected}."
                );
                eprintln!(
                    "    To confirm, type the device path exactly (case-sensitive):"
                );
                eprint!("    > ");
                use std::io::Write as _;
                std::io::stderr().flush().ok();
                let mut typed = String::new();
                std::io::stdin().read_line(&mut typed)?;
                if typed.trim() != expected {
                    bail!("confirmation mismatch — aborted");
                }
            }

            let passphrase = prompt_new_passphrase()?;

            eprintln!();
            eprintln!("Starting encryption pipeline…");
            let runner = auto_runner();
            let mut bar = ProgressBar::new();
            let outcome = encrypt_new_drive(
                runner.as_ref(),
                &EncryptRequest {
                    device: device.clone(),
                    label: label.clone(),
                    filesystem,
                    wipe_mode,
                    allow_discards,
                },
                &passphrase,
                |progress| match progress {
                    Progress::Started(step) => {
                        eprintln!("  → {}", step_label(step));
                        bar.reset();
                    }
                    Progress::Finished(step) => {
                        bar.finish_if_active();
                        eprintln!("    ✓ {} done", step_label(step));
                    }
                    Progress::Wiping { copied, total } => {
                        bar.render(copied, total);
                    }
                },
            )
            .map_err(|e| anyhow!("encryption failed: {e}"))?;

            eprintln!();
            println!("Encrypted successfully.");
            println!("  device:        {}", outcome.canonical_device.display());
            println!("  label:         {label}");
            println!("  mapper name:   {}", mapper_name_for(&label));
            println!();
            println!("Unlock again with:");
            println!(
                "  ashypass-cli drives unlock {} --label {}",
                device.display(),
                label
            );
            Ok(())
        }

        DrivesAction::Unlock {
            device,
            label,
            mapper_name,
            allow_discards,
        } => {
            let mapper = mapper_name
                .unwrap_or_else(|| mapper_name_for(label.as_deref().unwrap_or("ashypass")));
            let passphrase = prompt_passphrase("LUKS passphrase: ")?;
            let runner = auto_runner();
            let mapped = unlock_existing(
                runner.as_ref(),
                &device,
                mapper.trim_start_matches("ashypass_"),
                &passphrase,
                allow_discards,
            )
            .map_err(|e| anyhow!("unlock failed: {e}"))?;
            println!("Unlocked at {}", mapped.display());
            Ok(())
        }

        DrivesAction::Lock { mapper } => {
            let mapper = mapper.trim_start_matches("/dev/mapper/");
            let runner = auto_runner();
            ashypass_drives::luks::luks_close(runner.as_ref(), mapper)
                .map_err(|e| anyhow!("close failed: {e}"))?;
            println!("Closed mapping {mapper}");
            Ok(())
        }

        DrivesAction::EnrollFido2 {
            device,
            require_pin,
            require_presence,
        } => {
            eprintln!(
                "Enrolling FIDO2 token on {}. You will be prompted on your token \
                 (touch / PIN as required).",
                device.display()
            );
            let passphrase = prompt_passphrase("Current LUKS passphrase: ")?;
            let runner = auto_runner();
            ashypass_drives::luks::enroll_fido2(
                runner.as_ref(),
                &device,
                &passphrase,
                require_pin,
                require_presence,
            )
            .map_err(|e| anyhow!("enrollment failed: {e}"))?;
            println!("FIDO2 keyslot added.");
            Ok(())
        }
    }
}

fn step_label(step: ashypass_drives::pipeline::Step) -> &'static str {
    use ashypass_drives::pipeline::Step::*;
    match step {
        Safety => "safety check",
        Wipe => "wiping device (this may take a while)",
        LuksFormat => "writing LUKS2 header",
        LuksOpen => "opening encrypted mapping",
        MkFs => "creating filesystem",
        LuksClose => "closing mapping",
    }
}

fn print_device_block(device: &std::path::Path, report: &ashypass_drives::safety::SafetyReport) {
    use ashypass_drives::detect::human_size;
    eprintln!();
    eprintln!("Device:       {}", device.display());
    eprintln!("Canonical:    {}", report.canonical_path.display());
    if let Some(v) = report.vendor.as_deref() {
        eprintln!("Vendor:       {v}");
    }
    if let Some(m) = report.model.as_deref() {
        eprintln!("Model:        {m}");
    }
    if let Some(s) = report.serial.as_deref() {
        eprintln!("Serial:       {s}");
    }
    eprintln!("Size:         {}", human_size(report.size_bytes));
    if !report.allow_destructive {
        eprintln!();
        eprintln!("Safety refused:");
        for r in &report.reasons {
            eprintln!("  • {r}");
        }
    }
}

fn prompt_passphrase(label: &str) -> Result<ashypass_drives::passphrase::Passphrase> {
    let s = rpassword::prompt_password(label)?;
    Ok(ashypass_drives::passphrase::Passphrase::from_string_zeroizing(s))
}

fn prompt_new_passphrase() -> Result<ashypass_drives::passphrase::Passphrase> {
    let first = rpassword::prompt_password("New LUKS passphrase: ")?;
    if first.is_empty() {
        bail!("empty passphrase rejected");
    }
    if first.len() < 8 {
        bail!("passphrase must be at least 8 characters");
    }
    let second = rpassword::prompt_password("Repeat passphrase: ")?;
    if first != second {
        bail!("passphrases do not match");
    }
    drop(second);
    Ok(ashypass_drives::passphrase::Passphrase::from_string_zeroizing(first))
}

fn unlock_vault(vault: &mut Vault) -> Result<()> {
    if !vault.has_master_password().unwrap_or(false) {
        bail!("vault is uninitialised — open the GUI once to create the master password");
    }

    // Try keyring first; fall back to TTY prompt if nothing is stored or it
    // doesn't match (which indicates the user rotated the master).
    if let Ok(Some(stored)) = ashypass_core::keyring::load_master() {
        if vault.unlock(&stored).is_ok() {
            return Ok(());
        }
    }

    let password =
        rpassword::prompt_password("Master password: ").context("reading password from tty")?;
    vault.unlock(&password).map_err(|e| anyhow!("{e}"))?;
    Ok(())
}

fn run_gen(a: GenArgs) -> Result<()> {
    let pw = if a.passphrase {
        generate_passphrase(4, "-", true, true)
    } else if a.pin {
        generate_pin(a.pin_length)
    } else {
        let cfg = PasswordConfig {
            length: a.length,
            ..Default::default()
        };
        generate_password(&cfg).map_err(|e| anyhow!("{e}"))?
    };
    println!("{pw}");
    Ok(())
}

fn run_list(vault: &Vault, a: ListArgs) -> Result<()> {
    let mut entries = if let Some(t) = a.tag.as_deref() {
        vault.entries_with_tag(t).map_err(|e| anyhow!("{e}"))?
    } else {
        vault
            .list(a.search.as_deref())
            .map_err(|e| anyhow!("{e}"))?
    };
    if let Some(c) = a.category.as_deref() {
        entries.retain(|e| e.category.as_deref() == Some(c));
    }
    if entries.is_empty() {
        println!("(no entries)");
        return Ok(());
    }
    // Column widths sized to the longest visible value.
    let title_w = entries
        .iter()
        .map(|e| e.title.len())
        .max()
        .unwrap_or(5)
        .max(5);
    let user_w = entries
        .iter()
        .map(|e| e.username.as_deref().unwrap_or("").len())
        .max()
        .unwrap_or(8)
        .max(8);
    let cat_w = entries
        .iter()
        .map(|e| e.category.as_deref().unwrap_or("").len())
        .max()
        .unwrap_or(8)
        .max(8);
    println!(
        "{:>5}  {:<title_w$}  {:<user_w$}  {:<cat_w$}  TOTP",
        "ID", "TITLE", "USERNAME", "CATEGORY"
    );
    for e in entries {
        println!(
            "{:>5}  {:<title_w$}  {:<user_w$}  {:<cat_w$}  {}",
            e.id,
            e.title,
            e.username.as_deref().unwrap_or(""),
            e.category.as_deref().unwrap_or(""),
            if e.has_totp { "yes" } else { "" }
        );
    }
    Ok(())
}

fn run_show(vault: &Vault, a: ShowArgs, totp_only: bool) -> Result<()> {
    let entry = find_entry(vault, &a.selector)?;
    let full = vault
        .get(entry.id)
        .map_err(|e| anyhow!("{e}"))?
        .ok_or_else(|| anyhow!("entry {} not found", entry.id))?;

    if totp_only {
        let code = compute_totp(&full)?;
        println!("{code}");
        return Ok(());
    }

    println!("ID:        {}", full.id);
    println!("Title:     {}", full.title);
    if let Some(u) = full.username.as_deref() {
        println!("Username:  {u}");
    }
    if let Some(u) = full.url.as_deref() {
        println!("URL:       {u}");
    }
    if let Some(c) = full.category.as_deref() {
        println!("Category:  {c}");
    }
    let tags = vault.tags_of(full.id).unwrap_or_default();
    if !tags.is_empty() {
        println!("Tags:      {}", tags.join(", "));
    }
    if let Some(p) = full.password.as_deref() {
        println!("Password:  {p}");
    }
    if full.has_totp {
        if let Ok(code) = compute_totp(&full) {
            println!("TOTP:      {code}");
        }
    }
    if let Some(n) = full.notes.as_deref() {
        println!("Notes:     {n}");
    }
    Ok(())
}

fn run_add(vault: &Vault, a: AddArgs) -> Result<()> {
    let password = if a.password_stdin {
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).context("read stdin")?;
        buf.trim_end_matches('\n').to_string()
    } else {
        rpassword::prompt_password("Password: ").context("read tty")?
    };
    if password.is_empty() {
        bail!("password cannot be empty");
    }
    let id = vault
        .add(NewEntry {
            title: a.title,
            username: a.username,
            password,
            url: a.url,
            category: a.category,
            ..Default::default()
        })
        .map_err(|e| anyhow!("{e}"))?;
    println!("created entry id={id}");
    Ok(())
}

fn compute_totp(e: &PasswordEntry) -> Result<String> {
    let secret = e
        .totp_secret
        .as_deref()
        .ok_or_else(|| anyhow!("entry has no TOTP secret"))?;
    let algo = Algorithm::parse(&e.totp_algorithm).map_err(|err| anyhow!("{err}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    generate_totp(secret, algo, e.totp_digits, e.totp_period, now).map_err(|e| anyhow!("{e}"))
}

/// Accept either a numeric id or an exact title match.
fn find_entry(vault: &Vault, sel: &str) -> Result<PasswordEntry> {
    if let Ok(id) = sel.parse::<i64>() {
        if let Some(e) = vault.get(id).map_err(|e| anyhow!("{e}"))? {
            return Ok(e);
        }
    }
    let entries = vault.list(None).map_err(|e| anyhow!("{e}"))?;
    let matches: Vec<PasswordEntry> = entries.into_iter().filter(|e| e.title == sel).collect();
    match matches.len() {
        0 => bail!("no entry matches {sel:?}"),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => bail!("{n} entries match {sel:?} — pass the numeric id instead"),
    }
}

/// Query the controlling terminal's column count via `TIOCGWINSZ` on
/// stderr (where we render). Falls back to 80 when stderr is not a TTY or
/// the ioctl fails.
fn term_cols() -> usize {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ only reads, ws is a valid mutable winsize.
    let rc = unsafe { libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if rc == 0 && ws.ws_col > 0 {
        ws.ws_col as usize
    } else {
        80
    }
}

/// dysk-style progress bar for the wipe step.
///
/// Renders a single line using Unicode block characters for smooth 1/8-cell
/// partial fill. The bar adapts to the terminal width on every render so
/// it never wraps — wrapping defeats the `\r` overwrite and turns the
/// progress display into a scrollback waterfall.
struct ProgressBar {
    started_at: Option<std::time::Instant>,
    last_render: Option<std::time::Instant>,
    last_copied: u64,
    last_bps: f64,
    active: bool,
}

impl ProgressBar {
    const BLOCKS: [&'static str; 9] = ["", "▏", "▎", "▍", "▌", "▋", "▊", "▉", "█"];

    fn new() -> Self {
        Self {
            started_at: None,
            last_render: None,
            last_copied: 0,
            last_bps: 0.0,
            active: false,
        }
    }

    fn reset(&mut self) {
        self.started_at = None;
        self.last_render = None;
        self.last_copied = 0;
        self.last_bps = 0.0;
        self.active = false;
    }

    fn render(&mut self, copied: u64, total: u64) {
        use std::io::Write as _;
        let now = std::time::Instant::now();
        if self.started_at.is_none() {
            self.started_at = Some(now);
        }
        // Throttle: at most 1 render per 100 ms.
        if let Some(prev) = self.last_render {
            if now.duration_since(prev).as_millis() < 100 && copied < total {
                return;
            }
        }

        // Throughput via exponential moving average — smooth out jitter.
        if let Some(prev) = self.last_render {
            let dt = now.duration_since(prev).as_secs_f64().max(0.001);
            let inst_bps = (copied.saturating_sub(self.last_copied)) as f64 / dt;
            self.last_bps = if self.last_bps == 0.0 {
                inst_bps
            } else {
                0.7 * self.last_bps + 0.3 * inst_bps
            };
        }
        self.last_render = Some(now);
        self.last_copied = copied;
        self.active = true;

        let ratio = if total == 0 {
            0.0
        } else {
            (copied as f64 / total as f64).clamp(0.0, 1.0)
        };
        let pct = ratio * 100.0;
        let eta = if self.last_bps > 1.0 {
            let remaining = total.saturating_sub(copied) as f64 / self.last_bps;
            human_duration(remaining)
        } else {
            "—".into()
        };

        // Build the right-hand text first so we know how much room the bar
        // can occupy without wrapping.
        let text = format!(
            "  {pct:5.1}%  {c}/{t}  {r}/s  ETA {eta}",
            pct = pct,
            c = human_size(copied),
            t = human_size(total),
            r = human_size(self.last_bps as u64),
            eta = eta,
        );

        let cols = term_cols();
        let indent = 2;
        // Conservative bar sizing — better to under-fill than to wrap. The
        // wrap is disastrous (it scroll-spams the terminal), while a too-small
        // bar is merely ugly. We cap at 28 chars regardless of how wide the
        // terminal reports itself, since wider bars don't add information.
        let bar_width = cols
            .saturating_sub(indent)
            .saturating_sub(text.chars().count())
            .saturating_sub(4)
            .clamp(6, 28);

        let filled_eighths = (ratio * (bar_width as f64) * 8.0).round() as usize;
        let full_blocks = filled_eighths / 8;
        let partial = filled_eighths % 8;
        let mut bar = String::with_capacity(bar_width * 4);
        bar.push_str(&"█".repeat(full_blocks.min(bar_width)));
        if full_blocks < bar_width {
            bar.push_str(Self::BLOCKS[partial]);
            bar.push_str(&"░".repeat(bar_width.saturating_sub(full_blocks + 1)));
        }

        // \r\x1b[2K — clear the current physical line before drawing.
        eprint!(
            "\r\x1b[2K{pad}\x1b[36m{bar}\x1b[0m{text}",
            pad = " ".repeat(indent),
            bar = bar,
            text = text,
        );
        let _ = std::io::stderr().flush();
    }

    fn finish_if_active(&mut self) {
        if self.active {
            // Newline so the next status line doesn't get overwritten.
            eprintln!();
            self.active = false;
        }
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn human_duration(seconds: f64) -> String {
    let s = seconds as u64;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}
