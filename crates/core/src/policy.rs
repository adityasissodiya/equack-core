//! Policy model and authorization epochs (M3).
//!
//! - Policy events live in the SAME DAG as data ops.
//! - Build auth *epochs* by scanning the SAME total order (topo + tie).
//! - Deny-wins: a data op applies iff there exists a valid epoch for the author
//!   whose role permits the action and whose scope INTERSECTS the resource tags.
//! - Epochs are keyed by total-order positions [start_idx, end_idx).
//! - Optional HLC windows (nbf/naf) restrict validity further at check time.
//!
//! M4 will add VC/issuer validation; here Grants/Revoke are ground truth.

use std::collections::{BTreeMap, BTreeSet};

use crate::crypto::PublicKeyBytes;       // <- import from crypto (public)
use crate::dag::Dag;
use crate::hlc::Hlc;
use crate::op::{OpId, Payload};

pub type TagSet = BTreeSet<String>;

/// Actions derived from data ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action { SetField, SetAdd, SetRem }

/// Permission entry bound to a role.
#[derive(Debug, Clone)]
pub struct Permission {
    pub action: Action,
    pub required_tags: TagSet,
}

fn empty_tags() -> TagSet { TagSet::new() }

/// Role → permissions table (simple “editor”).
static EDITOR_PERMS: once_cell::sync::Lazy<Vec<Permission>> = once_cell::sync::Lazy::new(|| {
    vec![
        Permission { action: Action::SetField, required_tags: empty_tags() },
        Permission { action: Action::SetAdd,   required_tags: empty_tags() },
        Permission { action: Action::SetRem,   required_tags: empty_tags() },
    ]
});

fn role_perms(role: &str) -> &'static [Permission] {
    match role { "editor" => &EDITOR_PERMS, _ => &[] }
}

/// Static resource tags for (obj,field). Keep deterministic.
///  ("o","x")->{"hv"}, ("o","s")->{"mech"}; else empty.
pub fn tags_for(obj: &str, field: &str) -> TagSet {
    let mut t = TagSet::new();
    match (obj, field) {
        ("o", "x") => { t.insert("hv".to_string()); }
        ("o", "s") => { t.insert("mech".to_string()); }
        _ => {}
    }
    t
}

/// Parse Data key into (action, obj, field, elem_opt, resource_tags).
pub fn derive_action_and_tags(key: &str) -> Option<(Action, String, String, Option<String>, TagSet)> {
    if let Some(rest) = key.strip_prefix("mv:") {
        let mut it = rest.split(':');
        let obj = it.next()?.to_string();
        let field = it.next()?.to_string();
        let tags = tags_for(&obj, &field);
        return Some((Action::SetField, obj, field, None, tags));
    }
    if let Some(rest) = key.strip_prefix("set+:") {
        let mut it = rest.split(':');
        let obj = it.next()?.to_string();
        let field = it.next()?.to_string();
        let elem = it.next()?.to_string();
        let tags = tags_for(&obj, &field);
        return Some((Action::SetAdd, obj, field, Some(elem), tags));
    }
    if let Some(rest) = key.strip_prefix("set-:") {
        let mut it = rest.split(':');
        let obj = it.next()?.to_string();
        let field = it.next()?.to_string();
        let elem = it.next()?.to_string();
        let tags = tags_for(&obj, &field);
        return Some((Action::SetRem, obj, field, Some(elem), tags));
    }
    None
}

/// One authorization epoch entry for (subject, role, scope).
#[derive(Debug, Clone)]
pub struct Epoch {
    pub scope: TagSet,
    pub start_pos: usize,        // inclusive
    pub end_pos: Option<usize>,  // exclusive; None=open
    pub not_before: Option<Hlc>,
    pub not_after: Option<Hlc>,
}

/// Authorization index over the deterministic total order.
#[derive(Default)]
pub struct EpochIndex {
    entries: BTreeMap<(PublicKeyBytes, String), Vec<Epoch>>,
}

impl EpochIndex {
    fn push_epoch(&mut self, subject: PublicKeyBytes, role: String, e: Epoch) {
        self.entries.entry((subject, role)).or_default().push(e);
    }
    fn close_epochs_intersecting_scope(
        &mut self,
        subject: &PublicKeyBytes,
        role: &str,
        revoke_scope: &TagSet,
        at_pos: usize,
    ) {
        if let Some(v) = self.entries.get_mut(&(*subject, role.to_string())) {
            for ep in v.iter_mut() {
                if ep.end_pos.is_none() && !ep.scope.is_disjoint(revoke_scope) {
                    ep.end_pos = Some(at_pos);
                }
            }
        }
    }
}

/// Build authorization epochs by scanning policy events in topo order.
pub fn build_auth_epochs(dag: &Dag, topo: &[OpId]) -> EpochIndex {
    let mut idx = EpochIndex::default();
    for (pos, id) in topo.iter().enumerate() {
        let Some(op) = dag.get(id) else { continue; };
        match &op.header.payload {
            Payload::Grant { subject_pk, role, scope_tags, not_before, not_after } => {
                let mut scope = TagSet::new();
                for s in scope_tags { scope.insert(s.clone()); }
                idx.push_epoch(*subject_pk, role.clone(), Epoch {
                    scope,
                    start_pos: pos,
                    end_pos: None,
                    not_before: Some(*not_before),
                    not_after: *not_after,
                });
            }
            Payload::Revoke { subject_pk, role, scope_tags, .. } => {
                let mut scope = TagSet::new();
                for s in scope_tags { scope.insert(s.clone()); }
                idx.close_epochs_intersecting_scope(subject_pk, role, &scope, pos);
            }
            _ => {}
        }
    }
    idx
}

/// Check permission at a given *position* and HLC (deny-wins).
pub fn is_permitted_at_pos(
    idx: &EpochIndex,
    author: &PublicKeyBytes,
    action: Action,
    resource_tags: &TagSet,
    pos_idx: usize,
    at_hlc: Hlc,
) -> bool {
    for ((subj, role), epochs) in idx.entries.iter() {
        if subj != author { continue; }
        // Role permits action?
        let mut ok = false;
        for p in role_perms(role) {
            if p.action == action && p.required_tags.is_subset(resource_tags) {
                ok = true; break;
            }
        }
        if !ok { continue; }

        // Epoch covers pos and intersects scope (and passes HLC guards).
        for ep in epochs {
            if pos_idx < ep.start_pos { continue; }
            if let Some(end) = ep.end_pos { if pos_idx >= end { continue; } }
            if ep.scope.is_disjoint(resource_tags) { continue; }
            if let Some(nbf) = ep.not_before { if at_hlc < nbf { continue; } }
            if let Some(naf) = ep.not_after  { if at_hlc >= naf { continue; } }
            return true;
        }
    }
    false
}
