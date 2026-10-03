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

pub const CREATE_PASSWORDS_HISTORY_TRASH: &str = r#"
CREATE TABLE IF NOT EXISTS passwords_history_trash (
    original_history_id    INTEGER NOT NULL UNIQUE,
    trash_id               INTEGER NOT NULL,
    password_encrypted     BLOB    NOT NULL,
    changed_at             INTEGER NOT NULL,
    FOREIGN KEY (trash_id) REFERENCES passwords_trash(id) ON DELETE CASCADE
)
"#;

pub const CREATE_ATTACHMENTS_TRASH: &str = r#"
CREATE TABLE IF NOT EXISTS attachments_trash (
    original_attachment_id INTEGER NOT NULL UNIQUE,
    trash_id               INTEGER NOT NULL,
    filename               TEXT    NOT NULL,
    mime_type              TEXT,
    ciphertext             BLOB    NOT NULL,
    size_bytes             INTEGER NOT NULL,
    created_at             INTEGER NOT NULL,
    FOREIGN KEY (trash_id) REFERENCES passwords_trash(id) ON DELETE CASCADE
)
"#;

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

/// Vault key verifier. See `db::key_check`. Additive: builds that predate it
/// simply ignore the table.
pub const CREATE_KEY_CHECK: &str = r#"
CREATE TABLE IF NOT EXISTS key_check (
    id    INTEGER PRIMARY KEY CHECK (id = 1),
    blob  BLOB    NOT NULL,
    salt  TEXT    NOT NULL
)
"#;

/// Columns introduced after the initial Python release. Each statement fails
/// harmlessly ("duplicate column") on databases that already have it.
pub const LEGACY_COLUMN_ALTERS: &[&str] = &[
    "ALTER TABLE master ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1",
    "ALTER TABLE passwords ADD COLUMN totp_secret_encrypted BLOB",
    "ALTER TABLE passwords ADD COLUMN totp_algorithm TEXT DEFAULT 'SHA1'",
    "ALTER TABLE passwords ADD COLUMN totp_digits INTEGER DEFAULT 6",
    "ALTER TABLE passwords ADD COLUMN totp_period INTEGER DEFAULT 30",
    "ALTER TABLE passwords ADD COLUMN category TEXT",
    "ALTER TABLE passwords ADD COLUMN favorite INTEGER DEFAULT 0",
];

const SEED_SYNC_META: &str =
    "INSERT OR IGNORE INTO sync_meta (id, generation, last_synced_generation, last_remote_generation)
     VALUES (1, 0, 0, 0)";

/// Every idempotent setup statement run after the core tables exist and the
/// legacy columns were added, in order. Adding a statement here automatically
/// changes `setup_version()`, so existing databases re-run setup once.
const SETUP_STATEMENTS: &[&str] = &[
    CREATE_PASSWORDS_HISTORY,
    CREATE_HISTORY_INDEX,
    CREATE_PASSWORDS_TRASH,
    CREATE_TRASH_INDEX,
    CREATE_PASSWORDS_HISTORY_TRASH,
    CREATE_ATTACHMENTS_TRASH,
    CREATE_TAGS,
    CREATE_ENTRY_TAGS,
    CREATE_ENTRY_TAGS_INDEX,
    CREATE_FOLDERS,
    CREATE_ATTACHMENTS,
    CREATE_ATTACHMENTS_INDEX,
    CREATE_SYNC_META,
    SEED_SYNC_META,
    CREATE_NEXTCLOUD_MAPPING,
    CREATE_NEXTCLOUD_FOLDER_MAPPING,
    CREATE_NEXTCLOUD_TOMBSTONES,
    CREATE_KEY_CHECK,
    CREATE_SEARCH_META,
];

/// Bump when setup gains a *data* step that is not visible in the DDL text
/// above (the DDL itself is fingerprinted automatically).
const SETUP_DATA_REVISION: u32 = 1;

/// Value stored in `PRAGMA user_version` once full setup has completed on a
/// database. Derived from the text of every setup statement, so any schema
/// change made by a later build forces setup to run again. Always positive
/// and non-zero (0 is SQLite's default for a never-marked file).
pub fn setup_version() -> i32 {
    let mut hash: u32 = 0x811c_9dc5;
    let mut feed = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0100_0193);
    };
    feed(CREATE_MASTER.as_bytes());
    feed(CREATE_PASSWORDS.as_bytes());
    for statement in LEGACY_COLUMN_ALTERS
        .iter()
        .chain(SETUP_STATEMENTS)
        .chain(CREATE_INDEXES)
    {
        feed(statement.as_bytes());
    }
    feed(CREATE_PASSWORDS_FTS.as_bytes());
    feed(FTS_READY_KEY.as_bytes());
    feed(&SETUP_DATA_REVISION.to_le_bytes());
    ((hash & 0x7fff_ffff) | 1) as i32
}

/// Tables full setup guarantees. Checked on the fast open path as a guard
/// against a file whose `user_version` claims more than it holds.
const REQUIRED_TABLES: &[&str] = &[
    "master",
    "passwords",
    "passwords_history",
    "passwords_trash",
    "passwords_history_trash",
    "attachments_trash",
    "tags",
    "entry_tags",
    "folders",
    "attachments",
    "sync_meta",
    "nextcloud_mapping",
    "nextcloud_folder_mapping",
    "nextcloud_tombstones",
    "key_check",
    "search_meta",
    "passwords_fts",
];

pub fn required_tables_present(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    let mut stmt = conn
        .prepare_cached("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")?;
    for table in REQUIRED_TABLES {
        let count: i64 = stmt.query_row([table], |r| r.get(0))?;
        if count != 1 {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Add the columns from `LEGACY_COLUMN_ALTERS` that are missing.
pub fn add_legacy_columns(conn: &rusqlite::Connection) {
    for sql in LEGACY_COLUMN_ALTERS {
        // Ignore "duplicate column" — the cheapest way is to attempt and swallow.
        let _ = conn.execute(sql, []);
    }
}

pub fn initialize(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    initialize_reporting_search(conn).map(|_| ())
}

/// Full idempotent setup. Returns whether the full-text search index is
/// available; when it is not (SQLite built without FTS5), setup should be
/// retried on the next open, as it always was.
pub fn initialize_reporting_search(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    conn.execute(CREATE_MASTER, [])?;
    conn.execute(CREATE_PASSWORDS, [])?;
    // Python-era databases may lack columns the indexes below refer to.
    add_legacy_columns(conn);
    for statement in SETUP_STATEMENTS.iter().chain(CREATE_INDEXES) {
        conn.execute(statement, [])?;
    }
    migrate_orphaned_trash_children(conn)?;
    Ok(initialize_password_search(conn).is_ok())
}

/// True when trash-related history or attachment rows exist whose entry is
/// gone. Read-only, so it is cheap to run on every open.
pub fn has_orphaned_trash_children(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS (
             SELECT 1 FROM passwords_history h
               JOIN passwords_trash t ON t.original_id = h.entry_id
               LEFT JOIN passwords p ON p.id = h.entry_id
              WHERE p.id IS NULL)
         OR EXISTS (
             SELECT 1 FROM attachments a
               JOIN passwords_trash t ON t.original_id = a.entry_id
               LEFT JOIN passwords p ON p.id = a.entry_id
              WHERE p.id IS NULL)
         OR EXISTS (
             SELECT 1 FROM passwords_history
              WHERE id IN (SELECT original_history_id FROM passwords_history_trash))
         OR EXISTS (
             SELECT 1 FROM attachments
              WHERE id IN (SELECT original_attachment_id FROM attachments_trash))",
        [],
        |r| r.get(0),
    )
}

/// Older builds left history and attachments orphaned when foreign keys were
/// disabled. Move those rows under the matching trash record before enabling
/// strict enforcement. The migration is additive and transactional.
pub fn migrate_orphaned_trash_children(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(
        r#"
        INSERT OR IGNORE INTO passwords_history_trash
            (original_history_id, trash_id, password_encrypted, changed_at)
        SELECT h.id, t.id, h.password_encrypted, h.changed_at
          FROM passwords_history h
          JOIN passwords_trash t ON t.original_id = h.entry_id
          LEFT JOIN passwords p ON p.id = h.entry_id
         WHERE p.id IS NULL;

        DELETE FROM passwords_history
         WHERE id IN (SELECT original_history_id FROM passwords_history_trash);

        INSERT OR IGNORE INTO attachments_trash
            (original_attachment_id, trash_id, filename, mime_type,
             ciphertext, size_bytes, created_at)
        SELECT a.id, t.id, a.filename, a.mime_type,
               a.ciphertext, a.size_bytes, a.created_at
          FROM attachments a
          JOIN passwords_trash t ON t.original_id = a.entry_id
          LEFT JOIN passwords p ON p.id = a.entry_id
         WHERE p.id IS NULL;

        DELETE FROM attachments
         WHERE id IN (SELECT original_attachment_id FROM attachments_trash);
        "#,
    )?;
    tx.commit()
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
