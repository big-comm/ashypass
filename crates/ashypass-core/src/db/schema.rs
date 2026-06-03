//! Schema definitions and bootstrap.

pub const CREATE_MASTER: &str = r#"
CREATE TABLE IF NOT EXISTS master (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash   TEXT    NOT NULL,
    salt            TEXT    NOT NULL,
    crypto_version  INTEGER NOT NULL DEFAULT 2,
    created_at      INTEGER NOT NULL
)
"#;

pub const CREATE_PASSWORDS: &str = r#"
CREATE TABLE IF NOT EXISTS passwords (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    title                  TEXT    NOT NULL,
    username               TEXT,
    password_encrypted     BLOB    NOT NULL,
    notes_encrypted        BLOB,
    url                    TEXT,
    totp_secret_encrypted  BLOB,
    totp_algorithm         TEXT    DEFAULT 'SHA1',
    totp_digits            INTEGER DEFAULT 6,
    totp_period            INTEGER DEFAULT 30,
    category               TEXT,
    favorite               INTEGER DEFAULT 0,
    created_at             INTEGER NOT NULL,
    updated_at             INTEGER NOT NULL,
    last_accessed          INTEGER
)
"#;

pub const CREATE_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS idx_passwords_title ON passwords(title)",
    "CREATE INDEX IF NOT EXISTS idx_passwords_username ON passwords(username)",
    "CREATE INDEX IF NOT EXISTS idx_passwords_url ON passwords(url)",
    "CREATE INDEX IF NOT EXISTS idx_passwords_category_title ON passwords(category, title)",
    "CREATE INDEX IF NOT EXISTS idx_passwords_favorite_title ON passwords(favorite, title)",
];

pub const CREATE_SEARCH_META: &str = r#"
CREATE TABLE IF NOT EXISTS search_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
)
"#;

const FTS_READY_KEY: &str = "passwords_fts_trigram_v1";

const CREATE_PASSWORDS_FTS: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS passwords_fts USING fts5(
    title,
    username,
    url,
    content='passwords',
    content_rowid='id',
    tokenize='trigram'
);

CREATE TRIGGER IF NOT EXISTS passwords_fts_ai AFTER INSERT ON passwords BEGIN
    INSERT INTO passwords_fts(rowid, title, username, url)
    VALUES (new.id, new.title, coalesce(new.username, ''), coalesce(new.url, ''));
END;

CREATE TRIGGER IF NOT EXISTS passwords_fts_ad AFTER DELETE ON passwords BEGIN
    INSERT INTO passwords_fts(passwords_fts, rowid, title, username, url)
    VALUES ('delete', old.id, old.title, coalesce(old.username, ''), coalesce(old.url, ''));
END;

CREATE TRIGGER IF NOT EXISTS passwords_fts_au AFTER UPDATE OF title, username, url ON passwords BEGIN
    INSERT INTO passwords_fts(passwords_fts, rowid, title, username, url)
    VALUES ('delete', old.id, old.title, coalesce(old.username, ''), coalesce(old.url, ''));
    INSERT INTO passwords_fts(rowid, title, username, url)
    VALUES (new.id, new.title, coalesce(new.username, ''), coalesce(new.url, ''));
END;
"#;

pub const CREATE_PASSWORDS_HISTORY: &str = r#"
CREATE TABLE IF NOT EXISTS passwords_history (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id               INTEGER NOT NULL,
    password_encrypted     BLOB    NOT NULL,
    changed_at             INTEGER NOT NULL,
    FOREIGN KEY (entry_id) REFERENCES passwords(id) ON DELETE CASCADE
)
"#;

pub const CREATE_HISTORY_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_history_entry ON passwords_history(entry_id, changed_at DESC)";

/// Soft-deleted entries: the full encrypted row is preserved so `restore`
/// brings it back identically. `deleted_at` is the timestamp the user trashed
/// it; rows older than the retention window are pruned by `vault.purge_trash`.
pub const CREATE_PASSWORDS_TRASH: &str = r#"
CREATE TABLE IF NOT EXISTS passwords_trash (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    original_id            INTEGER NOT NULL,
    title                  TEXT    NOT NULL,
    username               TEXT,
    password_encrypted     BLOB    NOT NULL,
    notes_encrypted        BLOB,
    url                    TEXT,
    totp_secret_encrypted  BLOB,
    totp_algorithm         TEXT,
    totp_digits            INTEGER,
    totp_period            INTEGER,
    category               TEXT,
    favorite               INTEGER,
    created_at             INTEGER,
    updated_at             INTEGER,
    deleted_at             INTEGER NOT NULL
)
"#;

pub const CREATE_TRASH_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_trash_deleted_at ON passwords_trash(deleted_at)";

/// Tag catalog: free-form labels users assign to entries. Decoupled from
/// `category` (which is single-valued) so an entry can carry several tags.
pub const CREATE_TAGS: &str = r#"
CREATE TABLE IF NOT EXISTS tags (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT    NOT NULL UNIQUE COLLATE NOCASE
)
"#;

pub const CREATE_ENTRY_TAGS: &str = r#"
CREATE TABLE IF NOT EXISTS entry_tags (
    entry_id INTEGER NOT NULL,
    tag_id   INTEGER NOT NULL,
    PRIMARY KEY (entry_id, tag_id),
    FOREIGN KEY (entry_id) REFERENCES passwords(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id)   REFERENCES tags(id)      ON DELETE CASCADE
)
"#;

pub const CREATE_ENTRY_TAGS_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_entry_tags_tag ON entry_tags(tag_id)";

/// Local folder catalog. Existing entries still store their folder name in
/// `passwords.category`; this table lets users create empty folders and gives
/// sync a stable local catalog to mirror to providers like Nextcloud.
pub const CREATE_FOLDERS: &str = r#"
CREATE TABLE IF NOT EXISTS folders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
)
"#;

/// Encrypted file attachments. The blob is the standard `aes_gcm_v2` envelope
/// (version byte + nonce + AES-GCM ciphertext). `size_bytes` is the plaintext
/// length, kept for UI display without needing to decrypt.
pub const CREATE_ATTACHMENTS: &str = r#"
CREATE TABLE IF NOT EXISTS attachments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id    INTEGER NOT NULL,
    filename    TEXT    NOT NULL,
    mime_type   TEXT,
    ciphertext  BLOB    NOT NULL,
    size_bytes  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (entry_id) REFERENCES passwords(id) ON DELETE CASCADE
)
"#;

pub const CREATE_ATTACHMENTS_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_attachments_entry ON attachments(entry_id)";

/// Sync bookkeeping for the remote-backup conflict detector. The single-row
/// design (id = 1) is enforced by CHECK; we initialise the row inside
/// `initialize()` so callers can update unconditionally.
///
/// * `generation`              — bumped on every vault mutation.
/// * `last_synced_generation`  — local generation at the last successful push.
/// * `last_synced_at`          — wall-clock timestamp of that push.
/// * `last_remote_generation`  — highest generation observed remotely at the
///   last successful sync. A remote generation greater than this without a
///   matching local bump means another device wrote between our syncs.
pub const CREATE_SYNC_META: &str = r#"
CREATE TABLE IF NOT EXISTS sync_meta (
    id                       INTEGER PRIMARY KEY CHECK (id = 1),
    generation               INTEGER NOT NULL DEFAULT 0,
    last_synced_generation   INTEGER NOT NULL DEFAULT 0,
    last_synced_at           INTEGER,
    last_remote_generation   INTEGER NOT NULL DEFAULT 0
)
"#;

/// Per-entry mapping to a Nextcloud Passwords resource. One row per local
/// entry that has been pushed to or pulled from Nextcloud at least once. The
/// reverse direction (UUID → local id) is enforced via the UNIQUE constraint.
///
/// * `local_updated_at_snapshot`  — `passwords.updated_at` at the last sync,
///   so we can tell whether the local side changed since.
/// * `remote_edited_snapshot`     — `password.edited` (server-side) at the
///   last sync; lets us see whether the remote changed since.
/// * `remote_revision_snapshot`   — server `revision`; a quick equality check
///   when the timestamps look stale.
///
/// Soft-deleted local entries lose the row via `ON DELETE CASCADE`. For
/// remote deletes we keep a tombstone in `nextcloud_tombstones`.
pub const CREATE_NEXTCLOUD_MAPPING: &str = r#"
CREATE TABLE IF NOT EXISTS nextcloud_mapping (
    entry_id                    INTEGER PRIMARY KEY,
    nc_uuid                     TEXT    NOT NULL UNIQUE,
    last_synced_at              INTEGER NOT NULL,
    local_updated_at_snapshot   INTEGER NOT NULL,
    remote_edited_snapshot      INTEGER NOT NULL,
    remote_revision_snapshot    TEXT    NOT NULL,
    FOREIGN KEY (entry_id) REFERENCES passwords(id) ON DELETE CASCADE
)
"#;

/// Maps local folder names to Nextcloud Passwords folder UUIDs. Folder names
/// remain user-facing local labels; UUIDs are provider state.
pub const CREATE_NEXTCLOUD_FOLDER_MAPPING: &str = r#"
CREATE TABLE IF NOT EXISTS nextcloud_folder_mapping (
    local_name                 TEXT PRIMARY KEY COLLATE NOCASE,
    nc_uuid                    TEXT    NOT NULL UNIQUE,
    last_synced_at             INTEGER NOT NULL,
    remote_edited_snapshot     INTEGER NOT NULL,
    remote_revision_snapshot   TEXT    NOT NULL
)
"#;

/// Records UUIDs we have deleted locally so the next sync push deletes them
/// remotely (and ignores any remote-pull that re-creates them with the same
/// UUID until the tombstone is cleared). Each row is removed once we've
/// successfully told the server to delete the matching UUID.
pub const CREATE_NEXTCLOUD_TOMBSTONES: &str = r#"
CREATE TABLE IF NOT EXISTS nextcloud_tombstones (
    nc_uuid     TEXT PRIMARY KEY,
    deleted_at  INTEGER NOT NULL
)
"#;

pub fn initialize(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute(CREATE_MASTER, [])?;
    conn.execute(CREATE_PASSWORDS, [])?;
    conn.execute(CREATE_PASSWORDS_HISTORY, [])?;
    conn.execute(CREATE_HISTORY_INDEX, [])?;
    conn.execute(CREATE_PASSWORDS_TRASH, [])?;
    conn.execute(CREATE_TRASH_INDEX, [])?;
    conn.execute(CREATE_TAGS, [])?;
    conn.execute(CREATE_ENTRY_TAGS, [])?;
    conn.execute(CREATE_ENTRY_TAGS_INDEX, [])?;
    conn.execute(CREATE_FOLDERS, [])?;
    conn.execute(CREATE_ATTACHMENTS, [])?;
    conn.execute(CREATE_ATTACHMENTS_INDEX, [])?;
    conn.execute(CREATE_SYNC_META, [])?;
    conn.execute(
        "INSERT OR IGNORE INTO sync_meta (id, generation, last_synced_generation, last_remote_generation)
         VALUES (1, 0, 0, 0)",
        [],
    )?;
    conn.execute(CREATE_NEXTCLOUD_MAPPING, [])?;
    conn.execute(CREATE_NEXTCLOUD_FOLDER_MAPPING, [])?;
    conn.execute(CREATE_NEXTCLOUD_TOMBSTONES, [])?;
    for s in CREATE_INDEXES {
        conn.execute(s, [])?;
    }
    conn.execute(CREATE_SEARCH_META, [])?;
    let _ = initialize_password_search(conn);
    Ok(())
}

fn initialize_password_search(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(CREATE_PASSWORDS_FTS)?;

    let ready: Option<String> = conn
        .query_row(
            "SELECT value FROM search_meta WHERE key = ?",
            [FTS_READY_KEY],
            |r| r.get(0),
        )
        .ok();
    if ready.as_deref() != Some("1") {
        conn.execute(
            "INSERT INTO passwords_fts(passwords_fts) VALUES ('rebuild')",
            [],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO search_meta (key, value) VALUES (?, '1')",
            [FTS_READY_KEY],
        )?;
    }
    Ok(())
}
