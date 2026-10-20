//! Bidirectional sync engines.
//!
//! Distinct from `backup` (one-way snapshot upload via WebDAV): this module
//! reconciles state against external password managers that expose a CRUD
//! API. Today the only backend is the Nextcloud Passwords app.

pub mod folder;
pub mod folder_account;
pub mod folder_cloud;
pub mod nextcloud_engine;
pub mod nextcloud_passwords;
pub mod pairing;

pub use nextcloud_engine::{
    is_sync_running, ConflictResolution, NextcloudSyncPhase, NextcloudSyncProgress, SyncReport,
    SyncStats,
};
pub use nextcloud_passwords::{NcConfig, NcPassword, NextcloudPasswordsClient};
