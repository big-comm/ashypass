//! Vault audit — duplicate / weak / old / non-TOTP / breached passwords.
//!
//! `run(vault, opts)` walks every decrypted entry, classifies it, and returns
//! a `Report`. Network checks (HIBP) are opt-in and run synchronously — the UI
//! is expected to call this from a worker thread.

use crate::db::{vault::PasswordEntry, vault::Vault};
use crate::hibp;
use crate::strength;
use crate::Result;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Default)]
pub struct AuditOptions {
    pub check_hibp: bool,
    /// Entries older than this (seconds since epoch) count as "old".
    pub older_than_secs: i64,
    /// Strength score (0..=4) at or below this counts as "weak".
    pub weak_threshold: u8,
}

impl AuditOptions {
    pub fn defaults() -> Self {
        Self {
            check_hibp: false,
            older_than_secs: 365 * 24 * 3600,
            weak_threshold: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    Weak,
    Duplicate,
    Old,
    Breached,
    MissingTotp,
}

#[derive(Debug, Clone)]
pub struct EntryFinding {
    pub entry_id: i64,
    pub title: String,
    pub kinds: Vec<IssueKind>,
    pub strength_score: u8,
    pub strength_label: &'static str,
    pub breached_count: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub total_entries: usize,
    pub findings: Vec<EntryFinding>,
    pub duplicate_groups: usize,
    pub network_errors: Vec<String>,
}

impl Report {
    pub fn count(&self, kind: IssueKind) -> usize {
        self.findings
            .iter()
            .filter(|f| f.kinds.contains(&kind))
            .count()
    }
}

pub fn run(vault: &Vault, opts: AuditOptions) -> Result<Report> {
    let summaries = vault.list(None)?;
    let mut decrypted: Vec<PasswordEntry> = Vec::with_capacity(summaries.len());
    for s in &summaries {
        if let Some(e) = vault.get(s.id)? {
            decrypted.push(e);
        }
    }

    let now = chrono::Utc::now().timestamp();
    let mut dup_groups: HashMap<String, Vec<i64>> = HashMap::new();
    for e in &decrypted {
        if let Some(p) = e.password.as_deref() {
            if !p.is_empty() {
                dup_groups.entry(p.to_string()).or_default().push(e.id);
            }
        }
    }
    let dup_ids: std::collections::HashSet<i64> = dup_groups
        .values()
        .filter(|v| v.len() > 1)
        .flat_map(|v| v.iter().copied())
        .collect();
    let duplicate_groups = dup_groups.values().filter(|v| v.len() > 1).count();

    let mut breaches: HashMap<i64, u64> = HashMap::new();
    let mut network_errors: Vec<String> = Vec::new();
    if opts.check_hibp {
        let passwords: Vec<&str> = decrypted
            .iter()
            .map(|e| e.password.as_deref().unwrap_or(""))
            .collect();
        match hibp::check_many(&passwords) {
            Ok(statuses) => {
                for (entry, status) in decrypted.iter().zip(statuses.iter()) {
                    if let hibp::BreachStatus::Found { count } = status {
                        breaches.insert(entry.id, *count);
                    }
                }
            }
            Err(e) => network_errors.push(format!("HIBP: {e}")),
        }
    }

    let mut findings: Vec<EntryFinding> = Vec::new();
    for e in &decrypted {
        let mut kinds: Vec<IssueKind> = Vec::new();

        let password = e.password.as_deref().unwrap_or("");
        let strength = strength::estimate(password, &collect_user_inputs(e));
        if strength.score <= opts.weak_threshold {
            kinds.push(IssueKind::Weak);
        }

        if dup_ids.contains(&e.id) {
            kinds.push(IssueKind::Duplicate);
        }

        if now - e.updated_at > opts.older_than_secs {
            kinds.push(IssueKind::Old);
        }

        if !e.has_totp {
            kinds.push(IssueKind::MissingTotp);
        }

        let breached_count = breaches.get(&e.id).copied();
        if breached_count.is_some() {
            kinds.push(IssueKind::Breached);
        }

        if !kinds.is_empty() {
            findings.push(EntryFinding {
                entry_id: e.id,
                title: e.title.clone(),
                kinds,
                strength_score: strength.score,
                strength_label: strength.label,
                breached_count,
            });
        }
    }

    findings.sort_by(|a, b| {
        b.kinds
            .len()
            .cmp(&a.kinds.len())
            .then(a.title.cmp(&b.title))
    });

    Ok(Report {
        total_entries: summaries.len(),
        findings,
        duplicate_groups,
        network_errors,
    })
}

fn collect_user_inputs(e: &PasswordEntry) -> Vec<&str> {
    let mut v: Vec<&str> = Vec::new();
    v.push(&e.title);
    if let Some(u) = e.username.as_deref() {
        if !u.is_empty() {
            v.push(u);
        }
    }
    if let Some(u) = e.url.as_deref() {
        if !u.is_empty() {
            v.push(u);
        }
    }
    v
}
