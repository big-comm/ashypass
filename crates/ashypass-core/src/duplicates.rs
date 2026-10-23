//! Duplicate items already in the vault (left by old imports, or by two
//! syncs at once): logins of the same site and account, and items holding
//! the same two-step code. Merging keeps one item, moves what only the
//! others had into it, and sends the others to the trash.

use crate::db::vault::{UpdateEntry, Vault, ITEM_LOGIN};
use crate::url_match::{registrable_domain, url_host};
use crate::{Error, Result};
use std::collections::HashMap;

/// Why the items of a group are the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicateReason {
    /// Same site (registrable domain) and account.
    SameLogin,
    /// Same two-step verification secret.
    SameCode,
}

#[derive(Debug, Clone)]
pub struct DuplicateMember {
    pub id: i64,
    pub title: String,
    pub username: String,
    pub url: String,
    pub updated_at: i64,
    /// Its password differs from the suggested item's.
    pub password_differs: bool,
}

#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    pub reason: DuplicateReason,
    /// What they share, to show: `github.com · ana` or the code's title.
    pub label: String,
    /// Newest first; the first is the suggested one to keep.
    pub members: Vec<DuplicateMember>,
}

/// Base32 is case-insensitive; spaces, dashes and padding are decoration.
fn normalize_secret(secret: &str) -> String {
    secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .collect::<String>()
        .to_ascii_uppercase()
}

/// The site part of a login's key: its registrable domain (`github.com`
/// for `https://gist.github.com/x`), else its host, else its title.
fn site_of(url: &str, title: &str) -> String {
    match url_host(url) {
        Some(host) => {
            let host = host.trim_start_matches("www.").to_string();
            registrable_domain(&host).unwrap_or(host)
        }
        None => format!("\u{0}{}", title.trim().to_lowercase()),
    }
}

/// Every group of two or more duplicate items.
pub fn find_duplicates(vault: &Vault) -> Result<Vec<DuplicateGroup>> {
    let list = vault.list(None)?;
    // Full entries: passwords and codes are needed to compare.
    let mut full = HashMap::new();
    for summary in &list {
        if let Some(entry) = vault.get_without_touch(summary.id)? {
            full.insert(summary.id, entry);
        }
    }
    let mut by_login: HashMap<(String, String), Vec<i64>> = HashMap::new();
    let mut by_code: HashMap<String, Vec<i64>> = HashMap::new();
    for summary in &list {
        let Some(e) = full.get(&summary.id) else {
            continue;
        };
        if e.item_type == ITEM_LOGIN {
            let user = e.username.clone().unwrap_or_default().trim().to_lowercase();
            let site = site_of(e.url.as_deref().unwrap_or(""), &e.title);
            // A login with neither site nor account says too little to be
            // called a duplicate of another.
            if !(user.is_empty() && site.starts_with('\u{0}')) {
                by_login.entry((site, user)).or_default().push(e.id);
            }
        }
        if let Some(secret) = e.totp_secret.as_deref().filter(|s| !s.trim().is_empty()) {
            by_code
                .entry(normalize_secret(secret))
                .or_default()
                .push(e.id);
        }
    }

    let group = |reason, label: String, mut ids: Vec<i64>| -> DuplicateGroup {
        ids.sort_by_key(|id| std::cmp::Reverse(full[id].updated_at));
        let keep_password = full[&ids[0]].password.clone().unwrap_or_default();
        DuplicateGroup {
            reason,
            label,
            members: ids
                .iter()
                .map(|id| {
                    let e = &full[id];
                    DuplicateMember {
                        id: *id,
                        title: e.title.clone(),
                        username: e.username.clone().unwrap_or_default(),
                        url: e.url.clone().unwrap_or_default(),
                        updated_at: e.updated_at,
                        password_differs: e.password.clone().unwrap_or_default() != keep_password,
                    }
                })
                .collect(),
        }
    };

    let mut groups = Vec::new();
    let mut login_sets: Vec<Vec<i64>> = Vec::new();
    for ((site, user), ids) in by_login.into_iter().filter(|(_, ids)| ids.len() > 1) {
        let site = site.trim_start_matches('\u{0}').to_string();
        let label = if user.is_empty() {
            site
        } else {
            format!("{site} · {user}")
        };
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        login_sets.push(sorted);
        groups.push(group(DuplicateReason::SameLogin, label, ids));
    }
    for (_, ids) in by_code.into_iter().filter(|(_, ids)| ids.len() > 1) {
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        // Already shown as the same login.
        if login_sets.contains(&sorted) {
            continue;
        }
        let label = full[&ids[0]].title.clone();
        groups.push(group(DuplicateReason::SameCode, label, ids));
    }
    groups.sort_by_key(|g| g.label.to_lowercase());
    Ok(groups)
}

/// Keep `keep`, bring into it what only the `others` had, and move the
/// `others` to the trash (they can be restored from there):
/// - a two-step code it lacks, notes it does not already contain, other
///   websites, groups (tags), the favorite mark;
/// - another password goes to its password history, so none is lost.
pub fn merge_duplicates(vault: &Vault, keep: i64, others: &[i64]) -> Result<()> {
    let kept = vault
        .get_without_touch(keep)?
        .ok_or_else(|| Error::InvalidInput("the item to keep is gone".into()))?;
    let mut others_full = Vec::new();
    for id in others.iter().copied().filter(|id| *id != keep) {
        others_full.push(
            vault
                .get_without_touch(id)?
                .ok_or_else(|| Error::InvalidInput("an item to merge is gone".into()))?,
        );
    }
    // No outer transaction (the steps open their own). The order makes an
    // interruption harmless: the kept item is complete before any other one
    // goes to the trash.
    {
        let mut change = UpdateEntry::default();
        let kept_password = kept.password.clone().unwrap_or_default();
        let mut notes = kept.notes.clone().unwrap_or_default();
        let mut totp = kept.totp_secret.clone().filter(|s| !s.trim().is_empty());
        let mut url = kept.url.clone().unwrap_or_default();
        let mut extra: serde_json::Value = kept
            .extra
            .as_deref()
            .and_then(|e| serde_json::from_str(e).ok())
            .unwrap_or_else(|| serde_json::json!({}));
        let mut urls: Vec<String> = extra["urls"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|u| u.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let mut tags = vault.tags_of(keep)?;
        let mut favorite = kept.favorite;
        let mut extra_changed = false;
        for other in &others_full {
            if let Some(password) = other.password.as_deref() {
                if !password.is_empty() && password != kept_password {
                    vault.append_password_history(keep, password, Some(other.updated_at))?;
                }
            }
            if totp.is_none() {
                if let Some(secret) = other.totp_secret.clone().filter(|s| !s.trim().is_empty()) {
                    change.totp_secret = Some(Some(secret.clone()));
                    change.totp_algorithm = Some(other.totp_algorithm.clone());
                    change.totp_digits = Some(other.totp_digits);
                    change.totp_period = Some(other.totp_period);
                    totp = Some(secret);
                }
            }
            if let Some(other_notes) = other
                .notes
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
            {
                if !notes.contains(other_notes) {
                    if !notes.is_empty() {
                        notes.push_str("\n\n");
                    }
                    notes.push_str(other_notes);
                    change.notes = Some(Some(notes.clone()));
                }
            }
            let mut other_urls: Vec<String> = other.url.clone().into_iter().collect();
            if let Some(o) = other
                .extra
                .as_deref()
                .and_then(|e| serde_json::from_str::<serde_json::Value>(e).ok())
            {
                for u in o["urls"].as_array().into_iter().flatten() {
                    if let Some(u) = u.as_str() {
                        other_urls.push(u.to_string());
                    }
                }
            }
            for u in other_urls
                .into_iter()
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty())
            {
                if url.is_empty() {
                    url = u.clone();
                    change.url = Some(Some(u));
                } else if u != url && !urls.contains(&u) {
                    urls.push(u);
                    extra_changed = true;
                }
            }
            for tag in vault.tags_of(other.id)? {
                if !tags.iter().any(|t| t.eq_ignore_ascii_case(&tag)) {
                    tags.push(tag);
                }
            }
            favorite |= other.favorite;
        }
        if extra_changed {
            extra["urls"] = serde_json::json!(urls);
            change.extra = Some(Some(extra.to_string()));
        }
        vault.update(keep, change)?;
        vault.set_tags(keep, &tags)?;
        if favorite != kept.favorite {
            vault.set_favorite(keep, favorite)?;
        }
        for other in &others_full {
            vault.delete(other.id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::vault::NewEntry;

    fn vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::open(dir.path().join("v.db")).unwrap();
        v.set_master_password("correct horse battery").unwrap();
        (dir, v)
    }

    fn login(v: &Vault, title: &str, user: &str, url: &str, password: &str) -> i64 {
        v.add(NewEntry {
            title: title.into(),
            username: Some(user.into()),
            url: Some(url.into()),
            password: password.into(),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn same_site_and_account_are_grouped_newest_first() {
        let (_d, v) = vault();
        let a = login(&v, "GitHub", "Ana", "https://github.com/login", "old");
        let b = login(&v, "github.com", "ana", "gist.github.com", "new");
        login(&v, "GitHub", "bob", "https://github.com", "x"); // another account
        login(&v, "Pages", "ana", "https://ana.github.io", "y"); // another site
        v.update(
            b,
            UpdateEntry {
                notes: Some(Some("touch".into())),
                ..Default::default()
            },
        )
        .unwrap();
        let groups = find_duplicates(&v).unwrap();
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(g.reason, DuplicateReason::SameLogin);
        assert_eq!(g.label, "github.com · ana");
        assert_eq!(g.members.iter().map(|m| m.id).collect::<Vec<_>>(), [b, a]);
        assert!(!g.members[0].password_differs && g.members[1].password_differs);
    }

    #[test]
    fn same_code_under_other_names_is_a_group() {
        let (_d, v) = vault();
        let with_code = |title: &str| {
            v.add(NewEntry {
                title: title.into(),
                totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
                ..Default::default()
            })
            .unwrap()
        };
        with_code("GitHub");
        with_code("github 2FA");
        let groups = find_duplicates(&v).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].reason, DuplicateReason::SameCode);
    }

    #[test]
    fn merging_keeps_everything_and_trashes_the_rest() {
        let (_d, v) = vault();
        let keep = login(&v, "GitHub", "ana", "https://github.com", "current");
        let other = v
            .add(NewEntry {
                title: "github".into(),
                username: Some("ana".into()),
                url: Some("https://gist.github.com".into()),
                password: "older".into(),
                notes: Some("recovery codes in the drawer".into()),
                totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
                ..Default::default()
            })
            .unwrap();
        v.set_tags(other, &["Work".into()]).unwrap();
        v.set_favorite(other, true).unwrap();

        merge_duplicates(&v, keep, &[other]).unwrap();
        let kept = v.get_without_touch(keep).unwrap().unwrap();
        assert_eq!(kept.password.as_deref(), Some("current"));
        assert_eq!(kept.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(kept.notes.as_deref(), Some("recovery codes in the drawer"));
        assert!(kept.extra.as_deref().unwrap().contains("gist.github.com"));
        assert!(kept.favorite);
        assert_eq!(v.tags_of(keep).unwrap(), ["Work"]);
        // The other password is in the history, the other item in the trash.
        let history = v.password_history(keep).unwrap();
        assert!(history.iter().any(|h| h.password == "older"));
        assert!(v.get_without_touch(other).unwrap().is_none());
        assert_eq!(v.list_trash().unwrap().len(), 1);
        assert!(find_duplicates(&v).unwrap().is_empty());
    }
}
