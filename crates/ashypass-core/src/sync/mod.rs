//! Bidirectional sync engines.
//!
//! Distinct from `backup` (one-way snapshot upload via WebDAV): this module
//! reconciles state against external password managers that expose a CRUD
//! API. Today the only backend is the Nextcloud Passwords app.

pub mod nextcloud_passwords;
pub mod nextcloud_engine;

pub use nextcloud_engine::{ConflictResolution, SyncReport, SyncStats};
pub use nextcloud_passwords::{NcConfig, NcPassword, NextcloudPasswordsClient};
