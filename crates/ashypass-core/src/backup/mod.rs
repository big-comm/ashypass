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

/// Write `bytes` to `path` owner-only (0600) through a temporary file and a
/// rename, so a failed write never leaves the destination truncated and an
/// existing file's looser permissions are not kept.
pub fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> crate::Result<()> {
    files::write_private_replacing(path, bytes)
}
