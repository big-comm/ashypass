//! Google Drive backup, REST-only (no Google SDK).
//!
//! OAuth 2.0 PKCE loopback flow + multipart upload to a per-app folder
//! created under the user's Drive root via the `drive.file` scope.

pub mod drive;
pub(crate) mod files;
pub mod oauth;
pub mod restore;
pub mod sync;
pub mod webdav;

pub use drive::{BackupService, DriveFile};
pub use files::MAX_DOWNLOAD_BYTES;
pub use oauth::{ClientCredentials, Token};
pub use restore::{
    restore_db_snapshot, restore_db_snapshot_with, validate_backup, BackupInfo, BackupKind,
    RestoreOutcome,
};
pub use sync::{plan_push, push, PushOutcome, SyncAction, SyncPlan};
pub use webdav::{WebdavConfig, WebdavFile, WebdavService};
