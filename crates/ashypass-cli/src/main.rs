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
        cmd => {
            let mut vault = Vault::open(&db_path).context("opening vault")?;
            unlock_vault(&mut vault)?;
            match cmd {
                Command::List(a) => run_list(&vault, a),
                Command::Show(a) => run_show(&vault, a, false),
                Command::Totp(a) => run_show(&vault, a, true),
                Command::Add(a) => run_add(&vault, a),
                Command::Gen(_) => unreachable!(),
            }
        }
    }
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
