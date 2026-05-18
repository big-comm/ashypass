//! Google Drive backup, REST-only (no Google SDK).
//!
//! OAuth 2.0 PKCE loopback flow + multipart upload to a per-app folder
//! created under the user's Drive root via the `drive.file` scope.

pub mod drive;
pub mod oauth;
pub mod sync;
pub mod webdav;

pub use drive::{BackupService, DriveFile};
pub use oauth::{ClientCredentials, Token};
pub use sync::{plan_push, push, PushOutcome, SyncAction, SyncPlan};
pub use webdav::{WebdavConfig, WebdavFile, WebdavService};
