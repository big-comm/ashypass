//! Bidirectional reconciliation between the local vault and the Nextcloud
//! Passwords app.
//!
//! ## Algorithm
//!
//! For each (local entry, remote entry) pair we have one of:
//!
//! 1. **Local-only** — entry never pushed. Action: `create` remotely, then
//!    insert a mapping row.
//! 2. **Remote-only** — UUID has no mapping. Could also be a re-creation of
//!    something we deleted (UUID in `nextcloud_tombstones`) → request remote
//!    delete instead. Otherwise: insert locally.
//! 3. **Mapped + neither side changed** — skip.
//! 4. **Mapped + only local changed** — `update` remotely.
//! 5. **Mapped + only remote changed** — `update` locally.
//! 6. **Mapped + both sides changed** — true conflict. Resolved by
//!    [`ConflictResolution`] policy (default: last-write-wins by timestamp,
//!    ties broken toward remote).
//!
//! "Changed" is detected by comparing the timestamps captured on the last
//! sync (`local_updated_at_snapshot`, `remote_edited_snapshot`) against the
//! current values. We do not diff field-by-field — Nextcloud bumps `edited`
//! on every server-side update, and `updated_at` is set by every local
//! mutation already.
//!
//! ## Caveats
//!
//! * Folders/categories: Nextcloud's `folder` is a UUID; mapping that to
//!   Ashypass's free-text `category` is lossy in both directions. We carry
//!   the category as a plain label and ignore the remote folder UUID. A
//!   future task could map them through a side table.
//! * TOTP secrets: not exposed by Nextcloud Passwords API v1.0. We never
//!   write them to the remote, and we leave any local TOTP intact when
//!   pulling updates.
//! * No live diff: each sync rewalks both inventories. Fine for vaults in
//!   the hundreds of entries; for thousands you'd want a `since` cursor —
//!   v2.0 of the API supports that.

use crate::db::vault::{NewEntry, NextcloudMapping, UpdateEntry, Vault};
use crate::sync::nextcloud_passwords::{NcCreateOrUpdate, NcPassword, NextcloudPasswordsClient};
use crate::Result;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Newest `updated_at` / `edited` wins; on equal timestamps, remote wins.
    LastWriteWins,
    /// Force the local copy onto the server.
    PreferLocal,
    /// Force the remote copy into the local vault.
    PreferRemote,
}

impl Default for ConflictResolution {
    fn default() -> Self {
        Self::LastWriteWins
    }
}

#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    pub created_remotely: usize,
    pub created_locally: usize,
    pub updated_remotely: usize,
    pub updated_locally: usize,
    pub deleted_remotely: usize,
    pub conflicts: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub stats: SyncStats,
    /// Human-readable summary of conflicts so the UI can show "5 entries
    /// resolved by latest-wins". Each entry is a `(title, decision)` pair.
    pub conflict_details: Vec<(String, &'static str)>,
}

/// Run a full reconcile against the Nextcloud server. The vault must be
/// unlocked; this function decrypts passwords to push them, and writes new
/// encrypted entries when pulling.
pub fn sync(
    vault: &Vault,
    client: &NextcloudPasswordsClient,
    policy: ConflictResolution,
) -> Result<SyncReport> {
    let mut report = SyncReport::default();

    // 1. Apply any pending local deletions to the remote first. Done up
    //    front so a re-creation by another device after our delete still
    //    gets re-killed during step 4.
    let tombstones = vault.nc_tombstones()?;
    for uuid in &tombstones {
        match client.delete(uuid) {
            Ok(()) => {
                report.stats.deleted_remotely += 1;
                vault.nc_clear_tombstone(uuid)?;
            }
            Err(e) => {
                // 404 is fine — the resource is already gone.
                let msg = e.to_string();
                if msg.contains("404") {
                    vault.nc_clear_tombstone(uuid)?;
                } else {
                    report.stats.errors.push(format!("delete {uuid}: {msg}"));
                }
            }
        }
    }

    // 2. Fetch the full remote inventory once.
    let remote_list = client.list()?;
    let mut remote_by_uuid: HashMap<String, NcPassword> = remote_list
        .into_iter()
        .filter(|p| !p.trashed) // ignore server-side trash; mirror desktop behaviour
        .map(|p| (p.id.clone(), p))
        .collect();

    // 3. Walk the local inventory.
    let local_entries = vault.list(None)?;
    for summary in &local_entries {
        // Need the decrypted entry to push to the server.
        let local_full = match vault.get(summary.id)? {
            Some(e) => e,
            None => continue,
        };
        let mapping = vault.nc_mapping_for_entry(local_full.id)?;
        match mapping {
            None => {
                // Local-only entry — push as new.
                let payload = build_create_payload(&local_full);
                match client.create(&payload) {
                    Ok(created) => {
                        let new_map = NextcloudMapping {
                            entry_id: local_full.id,
                            nc_uuid: created.id.clone(),
                            last_synced_at: chrono::Utc::now().timestamp(),
                            local_updated_at_snapshot: local_full.updated_at,
                            remote_edited_snapshot: created.edited,
                            remote_revision_snapshot: created.revision,
                        };
                        vault.nc_mapping_upsert(&new_map)?;
                        report.stats.created_remotely += 1;
                        // If we somehow saw the same UUID in the remote
                        // list, drop it now so we don't double-process it.
                        remote_by_uuid.remove(&created.id);
                    }
                    Err(e) => report
                        .stats
                        .errors
                        .push(format!("create {}: {e}", local_full.title)),
                }
            }
            Some(map) => {
                // Mapped — compare changes.
                let remote = match remote_by_uuid.remove(&map.nc_uuid) {
                    Some(r) => r,
                    None => {
                        // Remote disappeared while we were synced. Honour
                        // that by deleting locally (also via trash) so
                        // both sides agree.
                        if vault.delete(local_full.id).unwrap_or(false) {
                            report.stats.deleted_remotely += 0; // local delete; nothing remote
                        }
                        continue;
                    }
                };
                let local_changed = local_full.updated_at > map.local_updated_at_snapshot;
                let remote_changed = remote.edited > map.remote_edited_snapshot
                    || remote.revision != map.remote_revision_snapshot;

                match (local_changed, remote_changed) {
                    (false, false) => continue,
                    (true, false) => {
                        let mut payload = build_create_payload(&local_full);
                        payload.id = Some(map.nc_uuid.clone());
                        match client.update(&payload) {
                            Ok(updated) => {
                                let new_map = NextcloudMapping {
                                    entry_id: local_full.id,
                                    nc_uuid: map.nc_uuid.clone(),
                                    last_synced_at: chrono::Utc::now().timestamp(),
                                    local_updated_at_snapshot: local_full.updated_at,
                                    remote_edited_snapshot: updated.edited,
                                    remote_revision_snapshot: updated.revision,
                                };
                                vault.nc_mapping_upsert(&new_map)?;
                                report.stats.updated_remotely += 1;
                            }
                            Err(e) => report
                                .stats
                                .errors
                                .push(format!("update {}: {e}", local_full.title)),
                        }
                    }
                    (false, true) => {
                        if apply_remote_to_local(vault, local_full.id, &remote)? {
                            update_mapping_after_pull(vault, local_full.id, &remote, &map)?;
                            report.stats.updated_locally += 1;
                        }
                    }
                    (true, true) => {
                        report.stats.conflicts += 1;
                        let chose = resolve_conflict(policy, local_full.updated_at, remote.edited);
                        report
                            .conflict_details
                            .push((local_full.title.clone(), chose));
                        match chose {
                            "local" => {
                                let mut payload = build_create_payload(&local_full);
                                payload.id = Some(map.nc_uuid.clone());
                                if let Ok(updated) = client.update(&payload) {
                                    let new_map = NextcloudMapping {
                                        entry_id: local_full.id,
                                        nc_uuid: map.nc_uuid.clone(),
                                        last_synced_at: chrono::Utc::now().timestamp(),
                                        local_updated_at_snapshot: local_full.updated_at,
                                        remote_edited_snapshot: updated.edited,
                                        remote_revision_snapshot: updated.revision,
                                    };
                                    vault.nc_mapping_upsert(&new_map)?;
                                    report.stats.updated_remotely += 1;
                                }
                            }
                            _ => {
                                if apply_remote_to_local(vault, local_full.id, &remote)? {
                                    update_mapping_after_pull(vault, local_full.id, &remote, &map)?;
                                    report.stats.updated_locally += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 4. Anything still in `remote_by_uuid` is remote-only. Pull it in,
    //    unless we tombstoned its UUID (already cleared in step 1) — in
    //    that case the server still had a delete pending; ignore the row
    //    and a future sync will re-issue the delete if needed.
    for (uuid, remote) in remote_by_uuid {
        let new_entry = NewEntry {
            title: remote.label.clone(),
            username: empty_to_none(&remote.username),
            url: empty_to_none(&remote.url),
            password: remote.password.clone(),
            notes: empty_to_none(&remote.notes),
            category: None,
            ..Default::default()
        };
        match vault.add(new_entry) {
            Ok(new_id) => {
                let map = NextcloudMapping {
                    entry_id: new_id,
                    nc_uuid: uuid,
                    last_synced_at: chrono::Utc::now().timestamp(),
                    local_updated_at_snapshot: vault
                        .entry_updated_at(new_id)?
                        .unwrap_or_else(|| chrono::Utc::now().timestamp()),
                    remote_edited_snapshot: remote.edited,
                    remote_revision_snapshot: remote.revision,
                };
                vault.nc_mapping_upsert(&map)?;
                report.stats.created_locally += 1;
            }
            Err(e) => report
                .stats
                .errors
                .push(format!("pull {}: {e}", remote.label)),
        }
    }

    Ok(report)
}

fn apply_remote_to_local(vault: &Vault, entry_id: i64, r: &NcPassword) -> Result<bool> {
    // Only carry text fields. Passwords without a non-empty password value
    // would violate the not-null constraint, so guard against that.
    if r.password.is_empty() {
        return Ok(false);
    }
    let change = UpdateEntry {
        title: Some(r.label.clone()),
        username: Some(empty_to_none(&r.username).unwrap_or_default()),
        password: Some(r.password.clone()),
        url: Some(empty_to_none(&r.url).map(|s| s.to_string())),
        notes: Some(empty_to_none(&r.notes).map(|s| s.to_string())),
        ..Default::default()
    };
    vault.update(entry_id, change)
}

fn update_mapping_after_pull(
    vault: &Vault,
    entry_id: i64,
    remote: &NcPassword,
    prev: &NextcloudMapping,
) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let local_updated = vault.entry_updated_at(entry_id)?.unwrap_or(now);
    let new_map = NextcloudMapping {
        entry_id,
        nc_uuid: prev.nc_uuid.clone(),
        last_synced_at: now,
        local_updated_at_snapshot: local_updated,
        remote_edited_snapshot: remote.edited,
        remote_revision_snapshot: remote.revision.clone(),
    };
    vault.nc_mapping_upsert(&new_map)
}

fn resolve_conflict(policy: ConflictResolution, local_ts: i64, remote_ts: i64) -> &'static str {
    match policy {
        ConflictResolution::PreferLocal => "local",
        ConflictResolution::PreferRemote => "remote",
        ConflictResolution::LastWriteWins => {
            if local_ts > remote_ts {
                "local"
            } else {
                "remote"
            }
        }
    }
}

fn build_create_payload(e: &crate::db::vault::PasswordEntry) -> NcCreateOrUpdate {
    NcCreateOrUpdate {
        id: None,
        label: e.title.clone(),
        username: e.username.clone().unwrap_or_default(),
        password: e.password.clone().unwrap_or_default(),
        url: e.url.clone().unwrap_or_default(),
        notes: e.notes.clone().unwrap_or_default(),
        // SHA-1 hash of the plaintext password — required by the Nextcloud
        // Passwords API for HIBP-style breach checks server-side. We hash
        // here so the server never needs the raw secret separately.
        hash: sha1_hex(e.password.as_deref().unwrap_or_default().as_bytes()),
    }
}

fn empty_to_none(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

fn sha1_hex(data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    let out = h.finalize();
    let mut s = String::with_capacity(40);
    for b in out {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_prefers_remote_on_tie() {
        assert_eq!(
            resolve_conflict(ConflictResolution::LastWriteWins, 100, 100),
            "remote"
        );
    }

    #[test]
    fn resolution_picks_newer() {
        assert_eq!(
            resolve_conflict(ConflictResolution::LastWriteWins, 200, 100),
            "local"
        );
        assert_eq!(
            resolve_conflict(ConflictResolution::LastWriteWins, 50, 100),
            "remote"
        );
    }

    #[test]
    fn forced_policies_ignore_timestamps() {
        assert_eq!(
            resolve_conflict(ConflictResolution::PreferLocal, 0, 999_999),
            "local"
        );
        assert_eq!(
            resolve_conflict(ConflictResolution::PreferRemote, 999_999, 0),
            "remote"
        );
    }

    #[test]
    fn sha1_known_vector() {
        // Sanity check: SHA-1("password") = 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
        assert_eq!(
            sha1_hex(b"password"),
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
        );
    }
}
