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
//!   so local folders and remote folders reconcile together. Local folder
//!   renames and removals are queued in `nextcloud_folder_ops`: a rename is
//!   pushed as a folder update, a removal deletes the remote folder only once
//!   no password is left in it.
//! * TOTP secrets: not exposed by Nextcloud Passwords API v1.0. We never
//!   write them to the remote, and we leave any local TOTP intact when
//!   pulling updates.
//! * No live diff: each sync rewalks both inventories. Fine for vaults in
//!   the hundreds of entries; for thousands you'd want a `since` cursor —
//!   v2.0 of the API supports that.

use crate::db::vault::{
    NewEntry, NextcloudFolderMapping, NextcloudFolderOp, NextcloudMapping, PasswordEntry,
    UpdateEntry, Vault,
};
use crate::sync::nextcloud_passwords::{
    NcCreateOrUpdate, NcFolder, NcFolderCreate, NcFolderUpdate, NcPassword,
    NextcloudPasswordsClient,
};
use crate::Result;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// UUID of the Nextcloud Passwords base (root) folder.
const BASE_FOLDER_UUID: &str = "00000000-0000-0000-0000-000000000000";

/// Process-wide flag: two reconciles running at once (auto-sync plus a manual
/// "Sync now") would both push the same local-only entries and duplicate
/// them remotely, or race on the mapping table.
static SYNC_RUNNING: AtomicBool = AtomicBool::new(false);

struct SyncGuard;

impl SyncGuard {
    fn acquire() -> Result<Self> {
        SYNC_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| SyncGuard)
            .map_err(|_| crate::Error::Other("sync already running".into()))
    }
}

impl Drop for SyncGuard {
    fn drop(&mut self) {
        SYNC_RUNNING.store(false, Ordering::Release);
    }
}

/// Deletions the user confirmed for the next sync (see `Error::MassDelete`).
static MASS_DELETE_APPROVED: AtomicUsize = AtomicUsize::new(0);

/// Allow the next sync to delete up to `count` entries locally (they go to
/// Deleted items) after the user confirmed they were deleted on the server.
pub fn approve_mass_delete(count: usize) {
    MASS_DELETE_APPROVED.store(count, Ordering::Release);
}

/// True while a Nextcloud reconcile is in progress in this process.
pub fn is_sync_running() -> bool {
    SYNC_RUNNING.load(Ordering::Acquire)
}

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
    pub deleted_locally: usize,
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
    let _guard = SyncGuard::acquire()?;
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
    // Deletes that failed this round: their tombstone stays, and the remote
    // copy must not be pulled back in as a "new" remote item in step 4.
    let mut pending_deletes: HashSet<String> = HashSet::new();
    for (idx, uuid) in tombstones.iter().enumerate() {
        match client.delete_if_exists(uuid) {
            Ok(true) => {
                report.stats.deleted_remotely += 1;
                vault.nc_clear_tombstone(uuid)?;
            }
            // HTTP 404 — the resource is already gone.
            Ok(false) => vault.nc_clear_tombstone(uuid)?,
            Err(e) => {
                report.stats.errors.push(format!("delete {uuid}: {e}"));
                pending_deletes.insert(uuid.clone());
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
    // Remote folder of every live password, kept current as we push, so a
    // locally removed folder is only deleted remotely once it is empty.
    let mut remote_folder_of: HashMap<String, String> = remote_list
        .iter()
        .filter(|p| !p.trashed)
        .map(|p| (p.id.clone(), p.folder.clone()))
        .collect();
    let mut remote_by_uuid: HashMap<String, NcPassword> = remote_list
        .into_iter()
        .filter(|p| !p.trashed) // ignore server-side trash; mirror desktop behaviour
        .map(|p| (p.id.clone(), p))
        .collect();

    // A mapped entry missing from the server is treated as a remote delete
    // and removed locally. If *every* mapped entry is missing, that is far
    // more likely a different account, a wiped server or a truncated listing
    // than the user deleting everything elsewhere — refuse rather than empty
    // the local vault.
    let mut mappings: HashMap<i64, NextcloudMapping> = vault
        .nc_all_mappings()?
        .into_iter()
        .map(|m| (m.entry_id, m))
        .collect();
    let mapped_uuids: Vec<String> = mappings.values().map(|m| m.nc_uuid.clone()).collect();
    if all_mappings_vanished(&mapped_uuids, &remote_by_uuid) {
        return Err(crate::Error::Other(format!(
            "none of the {} entries previously synced exist on the server; \
             refusing to delete them locally (signed in to a different account?)",
            mapped_uuids.len()
        )));
    }
    // Same reasoning for a large share of them: a partial listing would
    // otherwise delete everything it left out. Checked before any local
    // delete and before folder changes are pushed.
    let would_delete = vault
        .list(None)?
        .iter()
        .filter(|summary| {
            mappings.get(&summary.id).is_some_and(|map| {
                !remote_by_uuid.contains_key(&map.nc_uuid)
                    && !keeps_local_copy(policy, summary.updated_at, map)
            })
        })
        .count();
    // An approval covers one sync, and only up to the count the user saw.
    let approved = MASS_DELETE_APPROVED.swap(0, Ordering::AcqRel);
    if too_many_local_deletes(would_delete, mappings.len()) && would_delete > approved {
        return Err(crate::Error::MassDelete {
            count: would_delete,
            mapped: mappings.len(),
        });
    }

    drop_pending_deletes(&mut remote_by_uuid, &pending_deletes);
    // Remote items no local entry is mapped to yet. After a sign-out (which
    // forgets the mappings) or on a first sync against a server that already
    // holds the same passwords, identical entries are linked instead of
    // being created again on both sides.
    let mapped_set: HashSet<String> = mapped_uuids.into_iter().collect();

    // Folders: push local renames, then take in remote folders that are new
    // or were renamed on the server.
    progress(NextcloudSyncProgress::new(
        NextcloudSyncPhase::SyncingFolders,
        0,
        0,
    ));
    folders.push_renames(&mut report)?;
    folders.reconcile_remote()?;

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

    // 3. Walk the local inventory. Listed after the folder step, which may
    //    have renamed local folders.
    let local_entries = vault.list(None)?;
    progress(NextcloudSyncProgress::new(
        NextcloudSyncPhase::SyncingLocal,
        0,
        local_entries.len(),
    ));
    for (idx, summary) in local_entries.iter().enumerate() {
        let mapping = mappings.remove(&summary.id);
        // Skip the decryption for mapped entries nobody touched: the summary
        // row carries everything needed to tell.
        if let Some(map) = mapping.as_ref() {
            if let Some(remote) = remote_by_uuid.get(&map.nc_uuid) {
                let remote_category = resolve_category(
                    summary.category.as_deref(),
                    &folders.local_category_for_remote_uuid(&remote.folder)?,
                );
                let category_changed =
                    !same_category(summary.category.as_deref(), remote_category.as_deref());
                let leaving_folder = folders.is_pending_delete(&remote.folder);
                if !needs_full_entry(
                    summary.updated_at,
                    map,
                    remote,
                    category_changed,
                    leaving_folder,
                ) {
                    remote_by_uuid.remove(&map.nc_uuid);
                    progress(NextcloudSyncProgress::new(
                        NextcloudSyncPhase::SyncingLocal,
                        idx + 1,
                        local_entries.len(),
                    ));
                    continue;
                }
            }
        }
        // Need the decrypted entry to push to the server.
        let local_full = match vault.get_without_touch(summary.id)? {
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
                if let Some(uuid) = find_adoptable(&local_full, &remote_by_uuid, &mapped_set) {
                    let remote = remote_by_uuid
                        .remove(&uuid)
                        .expect("adoptable uuid comes from the map");
                    vault.nc_mapping_upsert(&NextcloudMapping {
                        entry_id: local_full.id,
                        nc_uuid: uuid,
                        last_synced_at: chrono::Utc::now().timestamp(),
                        // One second behind: the local copy counts as changed,
                        // so its folder (not compared above) is sent to the
                        // server instead of being replaced by the remote one.
                        local_updated_at_snapshot: local_full.updated_at - 1,
                        remote_edited_snapshot: remote.edited,
                        remote_revision_snapshot: remote.revision,
                    })?;
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
                        remote_folder_of.insert(created.id.clone(), payload.folder.clone());
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
                        if keeps_local_copy(policy, local_full.updated_at, &map) {
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
                                    remote_folder_of.insert(created.id, payload.folder);
                                }
                                Err(e) => report
                                    .stats
                                    .errors
                                    .push(format!("recreate {}: {e}", local_full.title)),
                            }
                        } else {
                            match vault.delete(local_full.id) {
                                Ok(true) => {
                                    // The server already dropped it: a
                                    // tombstone would only make the next
                                    // sync delete it remotely again.
                                    vault.nc_clear_tombstone(&map.nc_uuid)?;
                                    report.stats.deleted_locally += 1;
                                }
                                Ok(false) => {}
                                Err(e) => report
                                    .stats
                                    .errors
                                    .push(format!("delete local {}: {e}", local_full.title)),
                            }
                        }
                        progress(NextcloudSyncProgress::new(
                            NextcloudSyncPhase::SyncingLocal,
                            idx + 1,
                            local_entries.len(),
                        ));
                        continue;
                    }
                };
                let remote_changed = remote_changed(&map, &remote);
                // An entry still in a folder removed locally is moved out of
                // it, so the remote folder can be deleted once empty.
                let leaving_folder = !remote_changed && folders.is_pending_delete(&remote.folder);
                let local_changed = local_full.updated_at > map.local_updated_at_snapshot;
                let local_changed = local_changed || leaving_folder;
                let remote_category = resolve_category(
                    local_full.category.as_deref(),
                    &folders.local_category_for_remote_uuid(&remote.folder)?,
                );
                let category_changed =
                    !same_category(local_full.category.as_deref(), remote_category.as_deref());

                match (local_changed, remote_changed) {
                    (false, false) => {
                        if category_changed {
                            if let Some(written) =
                                apply_remote_to_local(vault, &local_full, &remote, remote_category)?
                            {
                                update_mapping_after_pull(vault, written, &remote, &map)?;
                                report.stats.updated_locally += 1;
                            }
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
                        let payload = build_update_payload(
                            &local_full,
                            folders
                                .remote_uuid_for_local_category(local_full.category.as_deref())?,
                            &map.nc_uuid,
                        );
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
                                remote_folder_of.insert(map.nc_uuid.clone(), payload.folder);
                            }
                            Err(e) => report
                                .stats
                                .errors
                                .push(format!("update {}: {e}", local_full.title)),
                        }
                    }
                    (false, true) => {
                        if let Some(written) =
                            apply_remote_to_local(vault, &local_full, &remote, remote_category)?
                        {
                            update_mapping_after_pull(vault, written, &remote, &map)?;
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
                                let payload = build_update_payload(
                                    &local_full,
                                    folders.remote_uuid_for_local_category(
                                        local_full.category.as_deref(),
                                    )?,
                                    &map.nc_uuid,
                                );
                                match client.update(&payload) {
                                    Ok(updated) => {
                                        // The remote password was overwritten:
                                        // keep it in the local history. Only
                                        // now that the server took ours.
                                        if remote.password
                                            != local_full.password.as_deref().unwrap_or("")
                                        {
                                            vault.append_password_history(
                                                local_full.id,
                                                &remote.password,
                                                Some(remote.edited).filter(|t| *t > 0),
                                            )?;
                                        }
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
                                        remote_folder_of
                                            .insert(map.nc_uuid.clone(), payload.folder);
                                    }
                                    Err(error) => report.stats.errors.push(format!(
                                        "conflict update {}: {error}",
                                        local_full.title
                                    )),
                                }
                            }
                            _ => {
                                // `Vault::update` moves the losing local
                                // password into the password history.
                                if let Some(written) = apply_remote_to_local(
                                    vault,
                                    &local_full,
                                    &remote,
                                    remote_category,
                                )? {
                                    update_mapping_after_pull(vault, written, &remote, &map)?;
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
        let category = resolve_category(
            None,
            &folders.local_category_for_remote_uuid(&remote.folder)?,
        );
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

    // 5. Folders removed locally: delete them remotely once the entries
    //    above have been moved out.
    folders.apply_deletes(&remote_folder_of, &mut report)?;

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
    /// Live remote folders in server order.
    remote_folders: Vec<NcFolder>,
    remote_by_uuid: HashMap<String, NcFolder>,
    remote_uuid_by_label: HashMap<String, String>,
    /// Remote folders whose local folder was renamed: uuid → new label.
    pending_renames: HashMap<String, String>,
    /// Remote folders whose local folder was removed: uuid → old label.
    pending_deletes: HashMap<String, String>,
}

impl<'a> FolderResolver<'a> {
    /// Read the remote folders and the queued local folder changes. Writes
    /// nothing besides dropping queued changes that no longer apply.
    fn new(vault: &'a Vault, client: &'a NextcloudPasswordsClient) -> Result<Self> {
        let remote_folders: Vec<NcFolder> = client
            .list_folders()?
            .into_iter()
            .filter(|f| !f.id.is_empty() && !f.label.trim().is_empty())
            .filter(|f| !f.trashed && !f.hidden)
            .collect();

        let mut pending_renames = HashMap::new();
        let mut pending_deletes = HashMap::new();
        for op in vault.nc_folder_ops()? {
            let mapping = vault.nc_folder_mapping_for_uuid(op.nc_uuid())?;
            match op {
                // Still current only while the mapping carries the new name:
                // an older build may have re-mapped the folder since.
                NextcloudFolderOp::Rename { nc_uuid, label }
                    if mapping
                        .as_ref()
                        .is_some_and(|m| folder_key(&m.local_name) == folder_key(&label)) =>
                {
                    pending_renames.insert(nc_uuid, label);
                }
                // A folder mapped again (re-created locally, or pulled back
                // by an older build) is wanted after all.
                NextcloudFolderOp::Delete { nc_uuid, label } if mapping.is_none() => {
                    pending_deletes.insert(nc_uuid, label);
                }
                stale => vault.nc_clear_folder_op(stale.nc_uuid())?,
            }
        }

        let mut remote_by_uuid = HashMap::new();
        let mut remote_uuid_by_label = HashMap::new();
        for folder in &remote_folders {
            if !pending_deletes.contains_key(&folder.id) {
                remote_uuid_by_label
                    .entry(folder_key(&folder.label))
                    .or_insert_with(|| folder.id.clone());
            }
            remote_by_uuid.insert(folder.id.clone(), folder.clone());
        }
        Ok(Self {
            vault,
            client,
            remote_folders,
            remote_by_uuid,
            remote_uuid_by_label,
            pending_renames,
            pending_deletes,
        })
    }

    /// True for a remote folder whose local folder was removed and that is
    /// waiting to be deleted remotely.
    fn is_pending_delete(&self, uuid: &str) -> bool {
        self.pending_deletes.contains_key(uuid.trim())
    }

    /// Send local folder renames to the server. A failed rename stays queued
    /// and is retried on the next sync.
    fn push_renames(&mut self, report: &mut SyncReport) -> Result<()> {
        let mut renames: Vec<(String, String)> = self.pending_renames.drain().collect();
        renames.sort();
        for (uuid, label) in renames {
            let Some(folder) = self.remote_by_uuid.get(&uuid).cloned() else {
                // Gone remotely: forget it, and let the local folder be
                // created again remotely like any new folder.
                self.vault.nc_folder_mapping_delete(&uuid)?;
                self.vault.nc_clear_folder_op(&uuid)?;
                continue;
            };
            let result = if folder.label == label {
                Ok(folder.clone())
            } else {
                self.client.update_folder(&NcFolderUpdate {
                    id: uuid.clone(),
                    label: label.clone(),
                    parent: folder.parent.clone(),
                })
            };
            match result {
                Ok(updated) => {
                    let renamed = NcFolder {
                        id: uuid.clone(),
                        label: label.clone(),
                        parent: folder.parent.clone(),
                        revision: if updated.revision.is_empty() {
                            folder.revision.clone()
                        } else {
                            updated.revision
                        },
                        edited: updated.edited.max(folder.edited),
                        ..folder.clone()
                    };
                    self.vault
                        .nc_folder_mapping_upsert(&NextcloudFolderMapping {
                            local_name: label.clone(),
                            nc_uuid: uuid.clone(),
                            last_synced_at: chrono::Utc::now().timestamp(),
                            remote_edited_snapshot: renamed.edited,
                            remote_revision_snapshot: renamed.revision.clone(),
                        })?;
                    self.vault.nc_clear_folder_op(&uuid)?;
                    let old_key = folder_key(&folder.label);
                    if self.remote_uuid_by_label.get(&old_key) == Some(&uuid) {
                        self.remote_uuid_by_label.remove(&old_key);
                    }
                    self.remote_uuid_by_label
                        .entry(folder_key(&label))
                        .or_insert_with(|| uuid.clone());
                    if let Some(entry) = self.remote_folders.iter_mut().find(|f| f.id == uuid) {
                        *entry = renamed.clone();
                    }
                    self.remote_by_uuid.insert(uuid, renamed);
                }
                Err(e) => {
                    report
                        .stats
                        .errors
                        .push(format!("rename folder {label}: {e}"));
                    self.pending_renames.insert(uuid, label);
                }
            }
        }
        Ok(())
    }

    /// Take in remote folders: map new ones, follow renames made on the
    /// server, refresh changed snapshots. Unchanged folders cause no write,
    /// and a folder removed locally is not brought back.
    fn reconcile_remote(&mut self) -> Result<()> {
        for folder in &self.remote_folders {
            if self.pending_deletes.contains_key(&folder.id)
                || self.pending_renames.contains_key(&folder.id)
            {
                continue;
            }
            let fresh = NextcloudFolderMapping {
                local_name: folder.label.clone(),
                nc_uuid: folder.id.clone(),
                last_synced_at: chrono::Utc::now().timestamp(),
                remote_edited_snapshot: folder.edited,
                remote_revision_snapshot: folder.revision.clone(),
            };
            match self.vault.nc_folder_mapping_for_uuid(&folder.id)? {
                Some(mapping) => match folder_mapping_change(&mapping, folder) {
                    FolderMappingChange::None => {}
                    FolderMappingChange::Snapshot => self.vault.nc_folder_mapping_upsert(&fresh)?,
                    FolderMappingChange::Renamed => {
                        if !self.vault.nc_apply_remote_folder_rename(&fresh)? {
                            log::warn!(
                                "nextcloud folder renamed to {:?}, which another folder already uses",
                                folder.label
                            );
                        }
                    }
                },
                None => {
                    // Two remote folders with the same name: keep the one
                    // already mapped instead of swapping them every sync.
                    if self
                        .vault
                        .nc_folder_mapping_for_name(&folder.label)?
                        .is_some()
                    {
                        continue;
                    }
                    self.vault.create_folder(&folder.label)?;
                    self.vault.nc_folder_mapping_upsert(&fresh)?;
                }
            }
        }
        Ok(())
    }

    /// Delete remote folders whose local folder was removed, once no live
    /// password and no subfolder is left in them. Anything still inside
    /// keeps the change queued for a later sync.
    fn apply_deletes(
        &mut self,
        remote_folder_of: &HashMap<String, String>,
        report: &mut SyncReport,
    ) -> Result<()> {
        let mut deletes: Vec<(String, String)> = self.pending_deletes.drain().collect();
        deletes.sort();
        for (uuid, label) in deletes {
            if !self.remote_by_uuid.contains_key(&uuid) {
                // Already gone (or trashed / hidden): nothing left to do.
                self.vault.nc_clear_folder_op(&uuid)?;
                continue;
            }
            let has_passwords = remote_folder_of.values().any(|f| *f == uuid);
            let has_subfolders = self.remote_folders.iter().any(|f| f.parent == uuid);
            if has_passwords || has_subfolders {
                self.pending_deletes.insert(uuid, label);
                continue;
            }
            match self.client.delete_folder_if_exists(&uuid) {
                Ok(_) => self.vault.nc_clear_folder_op(&uuid)?,
                Err(e) => {
                    report
                        .stats
                        .errors
                        .push(format!("delete folder {label}: {e}"));
                    self.pending_deletes.insert(uuid, label);
                }
            }
        }
        Ok(())
    }

    fn remote_uuid_for_local_category(&mut self, category: Option<&str>) -> Result<String> {
        let Some(local_name) = category.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(String::new());
        };
        if let Some(mapping) = self.vault.nc_folder_mapping_for_name(local_name)? {
            // A folder deleted on the server leaves a stale mapping; using it
            // would make every push of this entry fail.
            if self.remote_by_uuid.contains_key(&mapping.nc_uuid) {
                return Ok(mapping.nc_uuid);
            }
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

    fn local_category_for_remote_uuid(&mut self, uuid: &str) -> Result<RemoteFolder> {
        let uuid = uuid.trim();
        if uuid.is_empty() || uuid == BASE_FOLDER_UUID {
            return Ok(RemoteFolder::Root);
        }
        if self.pending_deletes.contains_key(uuid) {
            // Removed locally: its entries live outside any folder now.
            return Ok(RemoteFolder::Root);
        }
        if let Some(mapping) = self.vault.nc_folder_mapping_for_uuid(uuid)? {
            return Ok(RemoteFolder::Known(mapping.local_name));
        }
        let Some(folder) = self.remote_by_uuid.get(uuid).cloned() else {
            // Trashed, hidden, or otherwise unknown remote folder.
            return Ok(RemoteFolder::Unresolvable);
        };
        if self
            .vault
            .nc_folder_mapping_for_name(&folder.label)?
            .is_none()
        {
            self.upsert_local_mapping(&folder.label, &folder)?;
        }
        Ok(RemoteFolder::Known(folder.label))
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

/// What a known remote folder needs locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FolderMappingChange {
    /// Same name, same revision: no write at all.
    None,
    /// Same name, newer server state: refresh the stored snapshot.
    Snapshot,
    /// Renamed on the server.
    Renamed,
}

fn folder_mapping_change(
    mapping: &NextcloudFolderMapping,
    remote: &NcFolder,
) -> FolderMappingChange {
    if mapping.local_name != remote.label {
        FolderMappingChange::Renamed
    } else if mapping.remote_revision_snapshot != remote.revision
        || mapping.remote_edited_snapshot != remote.edited
    {
        FolderMappingChange::Snapshot
    } else {
        FolderMappingChange::None
    }
}

/// Where a remote password's folder maps locally.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RemoteFolder {
    /// No folder / the base folder.
    Root,
    Known(String),
    /// A folder we cannot see (trashed, hidden, deleted).
    Unresolvable,
}

/// Category to apply locally. An unresolvable remote folder keeps the local
/// category instead of clearing it.
fn resolve_category(local: Option<&str>, remote: &RemoteFolder) -> Option<String> {
    match remote {
        RemoteFolder::Root => None,
        RemoteFolder::Known(name) => Some(name.clone()),
        RemoteFolder::Unresolvable => local.map(ToOwned::to_owned),
    }
}

/// Whether the remote item changed since the last sync. The revision UUID
/// changes on every server-side edit, so it is authoritative when known;
/// `edited` is only a fallback (shallow create/update responses report
/// `edited = 0`, which would otherwise look like a change on the next sync).
fn remote_changed(map: &NextcloudMapping, remote: &NcPassword) -> bool {
    if !map.remote_revision_snapshot.is_empty() && !remote.revision.is_empty() {
        remote.revision != map.remote_revision_snapshot
    } else {
        remote.edited > map.remote_edited_snapshot
    }
}

fn drop_pending_deletes<V>(remote: &mut HashMap<String, V>, pending: &HashSet<String>) {
    remote.retain(|uuid, _| !pending.contains(uuid));
}

/// Build the local update for a remote item. The password is only touched
/// when the remote has a different, non-empty one: an empty remote password
/// never wipes the local secret, and an unchanged one does not add a
/// duplicate history row.
fn remote_update(local: &PasswordEntry, r: &NcPassword, category: Option<String>) -> UpdateEntry {
    let local_password = local.password.as_deref().unwrap_or_default();
    UpdateEntry {
        title: Some(r.label.clone()),
        username: Some(empty_to_none(&r.username).unwrap_or_default()),
        password: (!r.password.is_empty() && r.password != local_password)
            .then(|| r.password.clone()),
        url: Some(empty_to_none(&r.url)),
        notes: Some(empty_to_none(&r.notes)),
        category: Some(category),
        ..Default::default()
    }
}

/// Apply a remote item to the local entry. Returns the `updated_at` written
/// when the mapping should be advanced to the remote state (also for empty-password remote
/// items, which would otherwise be re-applied on every sync).
///
/// Returns false and writes nothing when the entry was edited (or deleted)
/// locally after `local` was read: that edit wins for now, and the next sync
/// sees it as a local change.
fn apply_remote_to_local(
    vault: &Vault,
    local: &PasswordEntry,
    r: &NcPassword,
    category: Option<String>,
) -> Result<Option<i64>> {
    vault.update_if_unchanged(
        local.id,
        local.updated_at,
        remote_update(local, r, category),
    )
}

/// Whether a mapped entry has to be decrypted and looked at closely. An
/// entry unchanged on both sides, already in the right folder and not
/// leaving a folder removed locally needs nothing.
fn needs_full_entry(
    local_updated_at: i64,
    map: &NextcloudMapping,
    remote: &NcPassword,
    category_changed: bool,
    leaving_folder: bool,
) -> bool {
    local_updated_at > map.local_updated_at_snapshot
        || remote_changed(map, remote)
        || category_changed
        || leaving_folder
}

/// For a mapped entry missing remotely: keep the local copy (and send it
/// again) instead of deleting it, because it was edited since the last sync.
fn keeps_local_copy(
    policy: ConflictResolution,
    local_updated_at: i64,
    map: &NextcloudMapping,
) -> bool {
    local_updated_at > map.local_updated_at_snapshot && policy != ConflictResolution::PreferRemote
}

/// Fewest local deletions one sync may make before the guard below applies.
const MASS_DELETE_FLOOR: usize = 10;

/// True when one sync would delete more than `max(10, 20% of mapped)`
/// entries locally — far more likely an incomplete server listing than the
/// user deleting that much on another device.
fn too_many_local_deletes(would_delete: usize, mapped: usize) -> bool {
    would_delete > MASS_DELETE_FLOOR && would_delete * 5 > mapped
}

/// `written` is the `updated_at` the pull itself wrote. It is recorded as
/// is, not re-read: re-reading could pick up a local edit made right after
/// the pull, which would then never count as a local change.
fn update_mapping_after_pull(
    vault: &Vault,
    written: i64,
    remote: &NcPassword,
    prev: &NextcloudMapping,
) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let local_updated = written;
    let new_map = NextcloudMapping {
        entry_id: prev.entry_id,
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

/// Payload for `password/update`. "No folder" is sent as the base folder:
/// an omitted folder would leave the password where it was on the server,
/// and the next sync would pull the old folder back.
fn build_update_payload(
    e: &crate::db::vault::PasswordEntry,
    folder: String,
    nc_uuid: &str,
) -> NcCreateOrUpdate {
    let folder = if folder.is_empty() {
        BASE_FOLDER_UUID.to_string()
    } else {
        folder
    };
    NcCreateOrUpdate {
        id: Some(nc_uuid.to_string()),
        ..build_create_payload(e, folder)
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

/// True when there are mapped entries and none of them is present remotely.
fn all_mappings_vanished<V>(mapped_uuids: &[String], remote: &HashMap<String, V>) -> bool {
    !mapped_uuids.is_empty() && mapped_uuids.iter().all(|u| !remote.contains_key(u))
}

/// An unmapped remote item with the same name, user, address and password
/// as `local`: the same entry, already on both sides.
fn find_adoptable(
    local: &PasswordEntry,
    remote_by_uuid: &HashMap<String, NcPassword>,
    mapped: &HashSet<String>,
) -> Option<String> {
    let text = |value: Option<&str>| value.unwrap_or("").trim().to_string();
    let user = text(local.username.as_deref());
    let url = text(local.url.as_deref());
    let mut candidates: Vec<&String> = remote_by_uuid
        .iter()
        .filter(|(uuid, remote)| {
            !mapped.contains(*uuid)
                && remote.label.trim() == local.title.trim()
                && remote.username.trim() == user
                && remote.url.trim() == url
                && local.password.as_deref() == Some(remote.password.as_str())
                // Notes too: adopting would otherwise let the next edit on
                // either side silently replace the other side's notes.
                && remote.notes.trim() == text(local.notes.as_deref())
        })
        .map(|(uuid, _)| uuid)
        .collect();
    // Deterministic choice when the server itself holds duplicates.
    candidates.sort();
    candidates.first().map(|uuid| (*uuid).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vanished_guard_trips_only_when_every_mapping_is_gone() {
        let mapped = vec!["a".to_string(), "b".to_string()];
        let mut remote: HashMap<String, ()> = HashMap::new();
        assert!(all_mappings_vanished(&mapped, &remote));
        remote.insert("b".into(), ());
        assert!(!all_mappings_vanished(&mapped, &remote));
        assert!(!all_mappings_vanished(&[], &HashMap::<String, ()>::new()));
    }

    fn mapping(revision: &str, edited: i64) -> NextcloudMapping {
        NextcloudMapping {
            entry_id: 1,
            nc_uuid: "u".into(),
            last_synced_at: 0,
            local_updated_at_snapshot: 0,
            remote_edited_snapshot: edited,
            remote_revision_snapshot: revision.into(),
        }
    }

    fn remote(revision: &str, edited: i64, password: &str) -> NcPassword {
        NcPassword {
            id: "u".into(),
            label: "Remote".into(),
            password: password.into(),
            revision: revision.into(),
            edited,
            ..Default::default()
        }
    }

    fn local_entry(password: &str, category: Option<&str>) -> PasswordEntry {
        PasswordEntry {
            id: 1,
            title: "Local".into(),
            username: None,
            url: None,
            password: Some(password.into()),
            notes: None,
            totp_secret: None,
            totp_algorithm: "SHA1".into(),
            totp_digits: 6,
            totp_period: 30,
            has_totp: false,
            category: category.map(Into::into),
            favorite: false,
            created_at: 0,
            updated_at: 0,
            last_accessed: None,
        }
    }

    #[test]
    fn identical_unmapped_remote_items_are_adopted_not_duplicated() {
        let local = local_entry("secret", None);
        let mut same = remote("r1", 1, "secret");
        same.id = "b".into();
        same.label = "Local".into();
        let mut other = same.clone();
        other.id = "a".into();
        other.password = "different".into();
        let mut remotes: HashMap<String, NcPassword> = HashMap::new();
        remotes.insert(same.id.clone(), same.clone());
        remotes.insert(other.id.clone(), other);
        let none = HashSet::new();
        assert_eq!(find_adoptable(&local, &remotes, &none), Some("b".into()));
        // Already linked to another local entry: not adopted twice.
        let mapped: HashSet<String> = ["b".to_string()].into();
        assert_eq!(find_adoptable(&local, &remotes, &mapped), None);
        // Different notes: kept apart rather than one side's notes lost.
        let mut with_notes = local_entry("secret", None);
        with_notes.notes = Some("recovery codes".into());
        assert_eq!(find_adoptable(&with_notes, &remotes, &none), None);
        // A different user name is a different account.
        let mut with_user = local_entry("secret", None);
        with_user.username = Some("ana".into());
        assert_eq!(find_adoptable(&with_user, &remotes, &none), None);
    }

    #[test]
    fn shallow_snapshot_with_zero_edited_is_not_a_phantom_change() {
        // After a shallow create response we stored revision r1, edited 0.
        let map = mapping("r1", 0);
        assert!(!remote_changed(&map, &remote("r1", 1_700_000_000, "p")));
        assert!(remote_changed(&map, &remote("r2", 1_700_000_000, "p")));
        // Without a revision, fall back to the timestamp.
        let legacy = mapping("", 100);
        assert!(!remote_changed(&legacy, &remote("", 100, "p")));
        assert!(remote_changed(&legacy, &remote("", 101, "p")));
    }

    #[test]
    fn unresolvable_remote_folder_keeps_local_category() {
        assert_eq!(
            resolve_category(Some("Work"), &RemoteFolder::Unresolvable),
            Some("Work".into())
        );
        assert_eq!(resolve_category(Some("Work"), &RemoteFolder::Root), None);
        assert_eq!(
            resolve_category(None, &RemoteFolder::Known("Home".into())),
            Some("Home".into())
        );
        assert_eq!(resolve_category(None, &RemoteFolder::Unresolvable), None);
    }

    #[test]
    fn failed_remote_deletes_are_not_pulled_back() {
        let mut remote_items: HashMap<String, ()> =
            [("gone".to_string(), ()), ("keep".to_string(), ())].into();
        let pending: HashSet<String> = ["gone".to_string()].into();
        drop_pending_deletes(&mut remote_items, &pending);
        assert!(!remote_items.contains_key("gone"));
        assert!(remote_items.contains_key("keep"));
    }

    #[test]
    fn remote_update_never_wipes_or_duplicates_passwords() {
        let local = local_entry("secret", Some("Work"));
        let empty = remote_update(&local, &remote("r", 1, ""), Some("Work".into()));
        assert_eq!(empty.password, None);
        assert_eq!(empty.title.as_deref(), Some("Remote"));
        let same = remote_update(&local, &remote("r", 1, "secret"), None);
        assert_eq!(same.password, None);
        let changed = remote_update(&local, &remote("r", 1, "new"), None);
        assert_eq!(changed.password.as_deref(), Some("new"));
    }

    #[test]
    fn empty_remote_password_advances_mapping_and_keeps_local_secret() {
        let (_directory, vault) = crate::importers::report::tests::test_vault();
        let id = vault
            .add(NewEntry {
                title: "Local".into(),
                password: "secret".into(),
                ..NewEntry::default()
            })
            .unwrap();
        let local = vault.get_without_touch(id).unwrap().unwrap();
        assert!(
            apply_remote_to_local(&vault, &local, &remote("r", 1, ""), None)
                .unwrap()
                .is_some()
        );
        let after = vault.get_without_touch(id).unwrap().unwrap();
        assert_eq!(after.password.as_deref(), Some("secret"));
        assert_eq!(after.title, "Remote");
        assert!(vault.password_history(id).unwrap().is_empty());

        // A winning remote password moves the local one into history.
        apply_remote_to_local(&vault, &after, &remote("r2", 2, "remote-pw"), None).unwrap();
        let history = vault.password_history(id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].password, "secret");
    }

    #[test]
    fn a_pull_never_overwrites_a_newer_local_edit() {
        let (_directory, vault) = crate::importers::report::tests::test_vault();
        let id = vault
            .add(NewEntry {
                title: "Local".into(),
                password: "secret".into(),
                ..NewEntry::default()
            })
            .unwrap();
        // The sync read the entry, then the user edited it.
        let mut stale = vault.get_without_touch(id).unwrap().unwrap();
        stale.updated_at -= 1;
        assert!(
            apply_remote_to_local(&vault, &stale, &remote("r", 1, "remote-pw"), None)
                .unwrap()
                .is_none()
        );
        let after = vault.get_without_touch(id).unwrap().unwrap();
        assert_eq!(after.title, "Local");
        assert_eq!(after.password.as_deref(), Some("secret"));
        assert!(vault.password_history(id).unwrap().is_empty());
    }

    #[test]
    fn mass_delete_guard_allows_small_and_proportionate_deletes() {
        // Up to 10 always passes.
        assert!(!too_many_local_deletes(0, 0));
        assert!(!too_many_local_deletes(10, 10));
        // Above 10, only up to 20% of the mapped entries.
        assert!(too_many_local_deletes(11, 20));
        assert!(!too_many_local_deletes(11, 55));
        assert!(!too_many_local_deletes(20, 100));
        assert!(too_many_local_deletes(21, 100));
        assert!(too_many_local_deletes(500, 1000));
    }

    #[test]
    fn update_payload_sends_the_base_folder_for_no_folder() {
        let entry = local_entry("secret", None);
        let payload = build_update_payload(&entry, String::new(), "uuid-1");
        assert_eq!(payload.id.as_deref(), Some("uuid-1"));
        assert_eq!(payload.folder, BASE_FOLDER_UUID);
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains(&format!(r#""folder":"{BASE_FOLDER_UUID}""#)));
        let in_folder = build_update_payload(&entry, "f1".into(), "uuid-1");
        assert_eq!(in_folder.folder, "f1");
        // Creating still leaves the folder to the server default.
        assert!(build_create_payload(&entry, String::new())
            .folder
            .is_empty());
    }

    #[test]
    fn untouched_entries_are_not_decrypted() {
        let mut map = mapping("r1", 10);
        map.local_updated_at_snapshot = 100;
        let same = remote("r1", 10, "p");
        assert!(!needs_full_entry(100, &map, &same, false, false));
        assert!(needs_full_entry(101, &map, &same, false, false));
        assert!(needs_full_entry(
            100,
            &map,
            &remote("r2", 10, "p"),
            false,
            false
        ));
        assert!(needs_full_entry(100, &map, &same, true, false));
        assert!(needs_full_entry(100, &map, &same, false, true));
    }

    #[test]
    fn deleted_remote_entries_keep_recent_local_edits() {
        let mut map = mapping("r1", 10);
        map.local_updated_at_snapshot = 100;
        assert!(!keeps_local_copy(
            ConflictResolution::LastWriteWins,
            100,
            &map
        ));
        assert!(keeps_local_copy(
            ConflictResolution::LastWriteWins,
            101,
            &map
        ));
        assert!(!keeps_local_copy(
            ConflictResolution::PreferRemote,
            101,
            &map
        ));
    }

    #[test]
    fn unchanged_remote_folders_cause_no_write() {
        let mapping = NextcloudFolderMapping {
            local_name: "Work".into(),
            nc_uuid: "f1".into(),
            last_synced_at: 0,
            remote_edited_snapshot: 5,
            remote_revision_snapshot: "r1".into(),
        };
        let folder = |label: &str, revision: &str, edited: i64| NcFolder {
            id: "f1".into(),
            label: label.into(),
            revision: revision.into(),
            edited,
            ..Default::default()
        };
        assert_eq!(
            folder_mapping_change(&mapping, &folder("Work", "r1", 5)),
            FolderMappingChange::None
        );
        assert_eq!(
            folder_mapping_change(&mapping, &folder("Work", "r2", 6)),
            FolderMappingChange::Snapshot
        );
        assert_eq!(
            folder_mapping_change(&mapping, &folder("Office", "r2", 6)),
            FolderMappingChange::Renamed
        );
    }

    #[test]
    fn only_one_sync_runs_at_a_time() {
        let first = SyncGuard::acquire().unwrap();
        assert!(is_sync_running());
        let error = SyncGuard::acquire().err().unwrap();
        assert!(error.to_string().contains("sync already running"));
        drop(first);
        assert!(!is_sync_running());
        drop(SyncGuard::acquire().unwrap());
    }

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
