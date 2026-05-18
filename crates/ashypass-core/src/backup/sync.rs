//! Incremental sync + conflict detection on top of WebDAV.
//!
//! The vault carries a monotonic `generation` counter that is bumped on every
//! mutation (see `Vault::notify_change`). Each successful upload is named
//! `ashypass-{gen:010}-{unix_ts}.ashy` so the generation can be recovered from
//! the filename without downloading the file. Lexicographic order over the
//! zero-padded generation matches numeric order, which makes "latest" cheap.
//!
//! ## Flow
//!
//! 1. **Plan** — `plan_push(vault, &webdav)` performs a PROPFIND and returns a
//!    [`SyncPlan`] describing what should happen:
//!    * `NoChanges` — local generation matches what was last uploaded; nothing
//!      to do.
//!    * `Ready` — local has progressed since the last upload AND no other
//!      device has uploaded in the meantime.
//!    * `Conflict` — remote contains a snapshot with a higher generation than
//!      the one we recorded at the last successful sync. Caller must decide
//!      whether to overwrite (force push) or pull first.
//!
//! 2. **Execute** — `push(vault, &webdav, master_password, force)` uploads a
//!    fresh encrypted snapshot and updates `sync_meta`. The export reuses the
//!    existing `.ashy` format (Argon2id + AES-GCM keyed on the vault master).
//!
//! Conflict detection is best-effort: a malicious or misbehaving remote that
//! removes snapshots can mask a conflict, but as long as snapshots accumulate
//! the generation embedded in the filename is reliable.

use crate::backup::webdav::{WebdavFile, WebdavService};
use crate::db::vault::Vault;
use crate::importers::ashy;
use crate::{Error, Result};
use std::path::Path;

/// Snapshot filename prefix. Matches `ashypass-{gen:010}-{ts}.ashy`.
const SNAPSHOT_PREFIX: &str = "ashypass-";
const SNAPSHOT_SUFFIX: &str = ".ashy";

#[derive(Debug, Clone)]
pub struct SyncPlan {
    pub local_generation: u64,
    pub last_synced_generation: u64,
    pub remote_max_generation: u64,
    pub action: SyncAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAction {
    NoChanges,
    Ready,
    /// Another device uploaded after our last sync. The contained value is the
    /// remote generation we did not author.
    Conflict {
        unseen_remote_generation: u64,
    },
}

/// Inspect remote state and decide what to do next, without uploading.
pub fn plan_push(vault: &Vault, webdav: &WebdavService) -> Result<SyncPlan> {
    let local = vault.current_generation()?;
    let last_synced = vault.last_synced_generation()?;

    // List remote snapshots. A 404 (folder absent) is treated as "no remote
    // history yet" — caller can then push the first snapshot freely.
    let files = match webdav.list_backups() {
        Ok(v) => v,
        Err(e) => {
            // The webdav layer normalises 404 to an empty list already, so
            // anything reaching here is a real failure.
            return Err(e);
        }
    };

    let remote_max = remote_max_generation(&files);

    let action = if remote_max > last_synced {
        SyncAction::Conflict {
            unseen_remote_generation: remote_max,
        }
    } else if local <= last_synced {
        SyncAction::NoChanges
    } else {
        SyncAction::Ready
    };

    Ok(SyncPlan {
        local_generation: local,
        last_synced_generation: last_synced,
        remote_max_generation: remote_max,
        action,
    })
}

/// Push a fresh encrypted snapshot of the vault. With `force = false` this
/// refuses to clobber an unseen remote snapshot; with `force = true` it ignores
/// the conflict and uploads anyway.
///
/// `master_password` is the export password — for `.ashy` snapshots we reuse
/// the user's master so a single secret restores the whole chain.
pub fn push(
    vault: &Vault,
    webdav: &WebdavService,
    master_password: &str,
    force: bool,
) -> Result<PushOutcome> {
    let plan = plan_push(vault, webdav)?;

    if !force {
        match &plan.action {
            SyncAction::NoChanges => {
                return Ok(PushOutcome::Skipped(plan));
            }
            SyncAction::Conflict { .. } => {
                return Ok(PushOutcome::Conflict(plan));
            }
            SyncAction::Ready => {}
        }
    }

    webdav.ensure_folder()?;

    let local = plan.local_generation;
    let ts = chrono::Utc::now().timestamp();
    let name = snapshot_filename(local, ts);

    // Encrypt to a temp file before uploading so a half-written upload never
    // overwrites the previous snapshot.
    let tmp = tempfile_path(&name)?;
    ashy::export_vault(vault, &tmp, master_password)?;
    let upload_result = webdav.upload(&tmp, &name);
    let _ = std::fs::remove_file(&tmp);
    upload_result?;

    // After a forced push the local generation is now authoritative; record
    // both sides as equal so the next sync starts from a clean slate.
    let remote_after_push = local.max(plan.remote_max_generation);
    vault.mark_synced(local, remote_after_push, ts)?;

    Ok(PushOutcome::Uploaded {
        plan,
        filename: name,
    })
}

#[derive(Debug, Clone)]
pub enum PushOutcome {
    /// Nothing to upload — local has not advanced since the last sync.
    Skipped(SyncPlan),
    /// Refused to upload because another device wrote in the meantime. Caller
    /// can re-run with `force = true` after resolving manually.
    Conflict(SyncPlan),
    /// New snapshot was successfully stored on the remote.
    Uploaded { plan: SyncPlan, filename: String },
}

/// Find the snapshot with the highest embedded generation. Files that don't
/// match the expected naming scheme are ignored — this is what lets the
/// detector coexist with manually placed `.ashy` files in the same folder.
fn remote_max_generation(files: &[WebdavFile]) -> u64 {
    files
        .iter()
        .filter_map(|f| parse_generation(&f.name))
        .max()
        .unwrap_or(0)
}

pub(crate) fn parse_generation(name: &str) -> Option<u64> {
    let rest = name.strip_prefix(SNAPSHOT_PREFIX)?;
    let rest = rest.strip_suffix(SNAPSHOT_SUFFIX)?;
    // Pattern: `{gen:010}-{ts}`. We only need the part before the first `-`.
    let gen_str = rest.split('-').next()?;
    gen_str.parse::<u64>().ok()
}

fn snapshot_filename(generation: u64, unix_ts: i64) -> String {
    format!("{SNAPSHOT_PREFIX}{generation:010}-{unix_ts}{SNAPSHOT_SUFFIX}")
}

fn tempfile_path(filename: &str) -> Result<std::path::PathBuf> {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    Ok(dir.join(format!("ashypass-sync-{pid}-{ts}-{filename}")))
}

/// Convenience: download the latest snapshot's bytes into `dest` so the caller
/// can offer the user a "Pull" action when a conflict is detected.
pub fn download_latest(
    webdav: &WebdavService,
    dest: impl AsRef<Path>,
) -> Result<Option<WebdavFile>> {
    let mut files = webdav.list_backups()?;
    files.retain(|f| parse_generation(&f.name).is_some());
    files.sort_by_key(|f| parse_generation(&f.name).unwrap_or(0));
    let Some(latest) = files.pop() else {
        return Ok(None);
    };
    webdav.download(&latest.href, dest)?;
    Ok(Some(latest))
}

/// Remove all but the `keep` most recent snapshots. Useful to bound storage
/// growth on the remote; callers typically expose this as "Keep last N
/// snapshots" in the UI.
pub fn prune(webdav: &WebdavService, keep: usize) -> Result<usize> {
    if keep == 0 {
        return Err(Error::Other("refusing to prune to zero snapshots".into()));
    }
    let mut files: Vec<WebdavFile> = webdav
        .list_backups()?
        .into_iter()
        .filter(|f| parse_generation(&f.name).is_some())
        .collect();
    if files.len() <= keep {
        return Ok(0);
    }
    files.sort_by_key(|f| parse_generation(&f.name).unwrap_or(0));
    let drop_count = files.len() - keep;
    let mut removed = 0;
    for f in files.iter().take(drop_count) {
        if webdav.delete(&f.href).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_well_formed_name() {
        assert_eq!(
            parse_generation("ashypass-0000000042-1700000000.ashy"),
            Some(42)
        );
    }

    #[test]
    fn rejects_unrelated_files() {
        assert_eq!(parse_generation("vault.ashy"), None);
        assert_eq!(parse_generation("ashypass-notanumber-12.ashy"), None);
        assert_eq!(parse_generation("ashypass-7.txt"), None);
    }

    #[test]
    fn snapshot_name_roundtrips() {
        let n = snapshot_filename(99, 1_700_000_000);
        assert_eq!(parse_generation(&n), Some(99));
        // Zero-padding gives stable lexicographic sort.
        let a = snapshot_filename(2, 0);
        let b = snapshot_filename(10, 0);
        assert!(a < b, "{a} should sort before {b}");
    }

    #[test]
    fn max_generation_ignores_garbage() {
        let files = vec![
            WebdavFile {
                name: "ashypass-0000000005-1.ashy".into(),
                href: "/x/a".into(),
                modified: "".into(),
                size: 1,
            },
            WebdavFile {
                name: "random.ashy".into(),
                href: "/x/r".into(),
                modified: "".into(),
                size: 1,
            },
            WebdavFile {
                name: "ashypass-0000000017-2.ashy".into(),
                href: "/x/b".into(),
                modified: "".into(),
                size: 1,
            },
        ];
        assert_eq!(remote_max_generation(&files), 17);
    }
}
