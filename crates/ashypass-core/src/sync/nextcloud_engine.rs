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
//! * Folders/categories: Nextcloud's `folder` is a UUID; AshyPass keeps a
//!   side-table mapping between local category names and remote folder UUIDs
//!   so local folders and remote folders reconcile together.
//! * TOTP secrets: not exposed by Nextcloud Passwords API v1.0. We never
//!   write them to the remote, and we leave any local TOTP intact when
//!   pulling updates.
//! * No live diff: each sync rewalks both inventories. Fine for vaults in
//!   the hundreds of entries; for thousands you'd want a `since` cursor —
//!   v2.0 of the API supports that.

use crate::db::vault::{NewEntry, NextcloudFolderMapping, NextcloudMapping, UpdateEntry, Vault};
use crate::sync::nextcloud_passwords::{
    NcCreateOrUpdate, NcFolder, NcFolderCreate, NcPassword, NextcloudPasswordsClient,
};
use crate::Result;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictResolution {
    /// Newest `updated_at` / `edited` wins; on equal timestamps, remote wins.
    #[default]
    LastWriteWins,
    /// Force the local copy onto the server.
    PreferLocal,
    /// Force the remote copy into the local vault.
    PreferRemote,
}

#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    pub created_remotely: usize,
    pub created_locally: usize,
    pub updated_remotely: usize,
    pub updated_locally: usize,
    pub deleted_remotely: usize,
    pub skipped_passwordless: usize,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextcloudSyncPhase {
    Preparing,
    ApplyingDeletes,
    FetchingRemote,
    SyncingFolders,
    SyncingLocal,
    PullingRemote,
    Finishing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NextcloudSyncProgress {
    pub phase: NextcloudSyncPhase,
    pub current: usize,
    pub total: usize,
}

impl NextcloudSyncProgress {
    fn new(phase: NextcloudSyncPhase, current: usize, total: usize) -> Self {
        Self {
            phase,
            current,
            total,
        }
    }
}

/// Run a full reconcile against the Nextcloud server. The vault must be
/// unlocked; this function decrypts passwords to push them, and writes new
/// encrypted entries when pulling.
pub fn sync(
    vault: &Vault,
    client: &NextcloudPasswordsClient,
    policy: ConflictResolution,
) -> Result<SyncReport> {
    sync_with_progress(vault, client, policy, |_| {})
}

pub fn sync_with_progress<F>(
    vault: &Vault,
    client: &NextcloudPasswordsClient,
    policy: ConflictResolution,
    mut progress: F,
) -> Result<SyncReport>
where
    F: FnMut(NextcloudSyncProgress),
{
    let mut report = SyncReport::default();
    progress(NextcloudSyncProgress::new(
        NextcloudSyncPhase::Preparing,
        0,
        0,
    ));
    let mut folders = FolderResolver::new(vault, client)?;

    // 1. Apply any pending local deletions to the remote first. Done up
    //    front so a re-creation by another device after our delete still
    //    gets re-killed during step 4.
    let tombstones = vault.nc_tombstones()?;
    progress(NextcloudSyncProgress::new(
        NextcloudSyncPhase::ApplyingDeletes,
        0,
        tombstones.len(),
    ));
    for (idx, uuid) in tombstones.iter().enumerate() {
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
        progress(NextcloudSyncProgress::new(
            NextcloudSyncPhase::ApplyingDeletes,
            idx + 1,
            tombstones.len(),
        ));
    }

    // 2. Fetch the full remote inventory once.
    progress(NextcloudSyncProgress::new(
        NextcloudSyncPhase::FetchingRemote,
        0,
        0,
    ));
    let remote_list = client.list()?;
    let mut remote_by_uuid: HashMap<String, NcPassword> = remote_list
        .into_iter()
        .filter(|p| !p.trashed) // ignore server-side trash; mirror desktop behaviour
        .map(|p| (p.id.clone(), p))
        .collect();

    // Mirror local empty folders too. Entry sync below also calls this for
    // every categorized password, but that would miss folders with no entries.
    let local_folders = vault.categories()?;
    progress(NextcloudSyncProgress::new(
        NextcloudSyncPhase::SyncingFolders,
        0,
        local_folders.len(),
    ));
    for (idx, local_folder) in local_folders.iter().enumerate() {
        folders.remote_uuid_for_local_category(Some(local_folder))?;
        progress(NextcloudSyncProgress::new(
            NextcloudSyncPhase::SyncingFolders,
            idx + 1,
            local_folders.len(),
        ));
    }

    // 3. Walk the local inventory.
    let local_entries = vault.list(None)?;
    progress(NextcloudSyncProgress::new(
        NextcloudSyncPhase::SyncingLocal,
        0,
        local_entries.len(),
    ));
    for (idx, summary) in local_entries.iter().enumerate() {
        // Need the decrypted entry to push to the server.
        let local_full = match vault.get(summary.id)? {
            Some(e) => e,
            None => {
                progress(NextcloudSyncProgress::new(
                    NextcloudSyncPhase::SyncingLocal,
                    idx + 1,
                    local_entries.len(),
                ));
                continue;
            }
        };
        let mapping = vault.nc_mapping_for_entry(local_full.id)?;
        match mapping {
            None => {
                // Local-only entry — push as new.
                if is_passwordless(&local_full) {
                    report.stats.skipped_passwordless += 1;
                    progress(NextcloudSyncProgress::new(
                        NextcloudSyncPhase::SyncingLocal,
                        idx + 1,
                        local_entries.len(),
                    ));
                    continue;
                }
                let payload = build_create_payload(
                    &local_full,
                    folders.remote_uuid_for_local_category(local_full.category.as_deref())?,
                );
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
                        // Remote disappeared. If the local entry changed after
                        // the last sync, do not silently discard that edit:
                        // preserve it by creating a fresh remote item unless
                        // the caller explicitly prefers remote state.
                        let local_changed = local_full.updated_at > map.local_updated_at_snapshot;
                        if local_changed && policy != ConflictResolution::PreferRemote {
                            if is_passwordless(&local_full) {
                                report.stats.skipped_passwordless += 1;
                                progress(NextcloudSyncProgress::new(
                                    NextcloudSyncPhase::SyncingLocal,
                                    idx + 1,
                                    local_entries.len(),
                                ));
                                continue;
                            }
                            report.stats.conflicts += 1;
                            report
                                .conflict_details
                                .push((local_full.title.clone(), "local"));
                            let payload = build_create_payload(
                                &local_full,
                                folders.remote_uuid_for_local_category(
                                    local_full.category.as_deref(),
                                )?,
                            );
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
                                }
                                Err(e) => report
                                    .stats
                                    .errors
                                    .push(format!("recreate {}: {e}", local_full.title)),
                            }
                        } else if let Err(e) = vault.delete(local_full.id) {
                            report
                                .stats
                                .errors
                                .push(format!("delete local {}: {e}", local_full.title));
                        }
                        continue;
                    }
                };
                let local_changed = local_full.updated_at > map.local_updated_at_snapshot;
                let remote_changed = remote.edited > map.remote_edited_snapshot
                    || remote.revision != map.remote_revision_snapshot;
                let remote_category = folders.local_category_for_remote_uuid(&remote.folder)?;
                let category_changed =
                    !same_category(local_full.category.as_deref(), remote_category.as_deref());

                match (local_changed, remote_changed) {
                    (false, false) => {
                        if category_changed
                            && apply_remote_to_local(
                                vault,
                                local_full.id,
                                &remote,
                                remote_category,
                            )?
                        {
                            update_mapping_after_pull(vault, local_full.id, &remote, &map)?;
                            report.stats.updated_locally += 1;
                        }
                    }
                    (true, false) => {
                        if is_passwordless(&local_full) {
                            report.stats.skipped_passwordless += 1;
                            progress(NextcloudSyncProgress::new(
                                NextcloudSyncPhase::SyncingLocal,
                                idx + 1,
                                local_entries.len(),
                            ));
                            continue;
                        }
                        let mut payload = build_create_payload(
                            &local_full,
                            folders
                                .remote_uuid_for_local_category(local_full.category.as_deref())?,
                        );
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
                        if apply_remote_to_local(vault, local_full.id, &remote, remote_category)? {
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
                                if is_passwordless(&local_full) {
                                    report.stats.skipped_passwordless += 1;
                                    progress(NextcloudSyncProgress::new(
                                        NextcloudSyncPhase::SyncingLocal,
                                        idx + 1,
                                        local_entries.len(),
                                    ));
                                    continue;
                                }
                                let mut payload = build_create_payload(
                                    &local_full,
                                    folders.remote_uuid_for_local_category(
                                        local_full.category.as_deref(),
                                    )?,
                                );
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
                                if apply_remote_to_local(
                                    vault,
                                    local_full.id,
                                    &remote,
                                    remote_category,
                                )? {
                                    update_mapping_after_pull(vault, local_full.id, &remote, &map)?;
                                    report.stats.updated_locally += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
        progress(NextcloudSyncProgress::new(
            NextcloudSyncPhase::SyncingLocal,
            idx + 1,
            local_entries.len(),
        ));
    }

    // 4. Anything still in `remote_by_uuid` is remote-only. Pull it in,
    //    unless we tombstoned its UUID (already cleared in step 1) — in
    //    that case the server still had a delete pending; ignore the row
    //    and a future sync will re-issue the delete if needed.
    let remote_remaining = remote_by_uuid.len();
    progress(NextcloudSyncProgress::new(
        NextcloudSyncPhase::PullingRemote,
        0,
        remote_remaining,
    ));
    for (idx, (uuid, remote)) in remote_by_uuid.into_iter().enumerate() {
        let category = folders.local_category_for_remote_uuid(&remote.folder)?;
        let new_entry = NewEntry {
            title: remote.label.clone(),
            username: empty_to_none(&remote.username),
            url: empty_to_none(&remote.url),
            password: remote.password.clone(),
            notes: empty_to_none(&remote.notes),
            category,
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
        progress(NextcloudSyncProgress::new(
            NextcloudSyncPhase::PullingRemote,
            idx + 1,
            remote_remaining,
        ));
    }

    progress(NextcloudSyncProgress::new(
        NextcloudSyncPhase::Finishing,
        1,
        1,
    ));
    Ok(report)
}

struct FolderResolver<'a> {
    vault: &'a Vault,
    client: &'a NextcloudPasswordsClient,
    remote_by_uuid: HashMap<String, NcFolder>,
    remote_uuid_by_label: HashMap<String, String>,
}

impl<'a> FolderResolver<'a> {
    fn new(vault: &'a Vault, client: &'a NextcloudPasswordsClient) -> Result<Self> {
        let mut remote_by_uuid = HashMap::new();
        let mut remote_uuid_by_label = HashMap::new();
        for folder in client
            .list_folders()?
            .into_iter()
            .filter(|f| !f.id.is_empty() && !f.label.trim().is_empty())
            .filter(|f| !f.trashed && !f.hidden)
        {
            let key = folder_key(&folder.label);
            remote_uuid_by_label
                .entry(key)
                .or_insert_with(|| folder.id.clone());
            vault.create_folder(&folder.label)?;
            vault.nc_folder_mapping_upsert(&NextcloudFolderMapping {
                local_name: folder.label.clone(),
                nc_uuid: folder.id.clone(),
                last_synced_at: chrono::Utc::now().timestamp(),
                remote_edited_snapshot: folder.edited,
                remote_revision_snapshot: folder.revision.clone(),
            })?;
            remote_by_uuid.insert(folder.id.clone(), folder);
        }
        Ok(Self {
            vault,
            client,
            remote_by_uuid,
            remote_uuid_by_label,
        })
    }

    fn remote_uuid_for_local_category(&mut self, category: Option<&str>) -> Result<String> {
        let Some(local_name) = category.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(String::new());
        };
        if let Some(mapping) = self.vault.nc_folder_mapping_for_name(local_name)? {
            return Ok(mapping.nc_uuid);
        }
        if let Some(uuid) = self
            .remote_uuid_by_label
            .get(&folder_key(local_name))
            .cloned()
        {
            let folder = self
                .remote_by_uuid
                .get(&uuid)
                .cloned()
                .unwrap_or_else(|| NcFolder {
                    id: uuid.clone(),
                    label: local_name.to_string(),
                    ..Default::default()
                });
            self.upsert_local_mapping(local_name, &folder)?;
            return Ok(uuid);
        }

        let created = self.client.create_folder(&NcFolderCreate {
            label: local_name.to_string(),
            parent: String::new(),
        })?;
        if created.id.is_empty() {
            return Err(crate::Error::Other(format!(
                "nextcloud folder create returned no id for {local_name}"
            )));
        }
        let folder = NcFolder {
            label: if created.label.is_empty() {
                local_name.to_string()
            } else {
                created.label
            },
            ..created
        };
        self.upsert_local_mapping(local_name, &folder)?;
        self.remote_uuid_by_label
            .insert(folder_key(local_name), folder.id.clone());
        self.remote_by_uuid
            .insert(folder.id.clone(), folder.clone());
        Ok(folder.id)
    }

    fn local_category_for_remote_uuid(&mut self, uuid: &str) -> Result<Option<String>> {
        if uuid.trim().is_empty() {
            return Ok(None);
        }
        if let Some(mapping) = self.vault.nc_folder_mapping_for_uuid(uuid)? {
            return Ok(Some(mapping.local_name));
        }
        let Some(folder) = self.remote_by_uuid.get(uuid).cloned() else {
            return Ok(None);
        };
        self.upsert_local_mapping(&folder.label, &folder)?;
        Ok(Some(folder.label))
    }

    fn upsert_local_mapping(&self, local_name: &str, folder: &NcFolder) -> Result<()> {
        self.vault.create_folder(local_name)?;
        self.vault
            .nc_folder_mapping_upsert(&NextcloudFolderMapping {
                local_name: local_name.to_string(),
                nc_uuid: folder.id.clone(),
                last_synced_at: chrono::Utc::now().timestamp(),
                remote_edited_snapshot: folder.edited,
                remote_revision_snapshot: folder.revision.clone(),
            })
    }
}

fn apply_remote_to_local(
    vault: &Vault,
    entry_id: i64,
    r: &NcPassword,
    category: Option<String>,
) -> Result<bool> {
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
        category: Some(category),
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

fn build_create_payload(e: &crate::db::vault::PasswordEntry, folder: String) -> NcCreateOrUpdate {
    NcCreateOrUpdate {
        id: None,
        label: e.title.clone(),
        username: e.username.clone().unwrap_or_default(),
        password: e.password.clone().unwrap_or_default(),
        url: e.url.clone().unwrap_or_default(),
        notes: e.notes.clone().unwrap_or_default(),
        folder,
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

fn is_passwordless(entry: &crate::db::vault::PasswordEntry) -> bool {
    entry
        .password
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .is_empty()
}

fn same_category(left: Option<&str>, right: Option<&str>) -> bool {
    normalize_category(left) == normalize_category(right)
}

fn normalize_category(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn folder_key(name: &str) -> String {
    name.trim().to_lowercase()
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

    #[test]
    fn same_category_treats_blank_as_none() {
        assert!(same_category(None, Some("")));
        assert!(same_category(Some(" Work "), Some("Work")));
        assert!(!same_category(Some("Work"), Some("Personal")));
    }

    #[test]
    fn passwordless_detects_blank_passwords() {
        let entry = crate::db::vault::PasswordEntry {
            id: 0,
            title: String::new(),
            username: None,
            url: None,
            password: Some("  ".into()),
            notes: None,
            totp_secret: None,
            totp_algorithm: "SHA1".into(),
            totp_digits: 6,
            totp_period: 30,
            has_totp: false,
            category: None,
            favorite: false,
            created_at: 0,
            updated_at: 0,
            last_accessed: None,
        };
        assert!(is_passwordless(&entry));
    }
}
