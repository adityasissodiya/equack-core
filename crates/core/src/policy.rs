//! Policy model and authorization epochs.
//!
//! M3 semantics recap:
//! - Policy events live in the SAME DAG as data ops.
//! - Build auth *epochs* by scanning the SAME total order (topo + tie).
//! - Deny-wins: a data op applies iff there exists a valid epoch for the author
//!   whose role permits the action and whose scope INTERSECTS the resource tags.
//! - Epochs are keyed by total-order positions [start_idx, end_idx).
//!
//! M4 transition note:
//! - `Grant` no longer carries role/scope/time; it references a VC by `cred_hash`.
//! - In M4 proper, epochs come from **verified VCs** plus intersection with `Revoke`.
//! - This file keeps the *public API stable* for replay (`derive_action_and_tags`,
//!   `build_auth_epochs`, `is_permitted_at_pos`) so other modules compile.
//! - Until VC verification is wired in, `build_auth_epochs` produces **no epochs**
//!   (pure deny at the gate). This will be replaced in the next patch when we add
//!   `vc.rs / trust.rs / status.rs` and the VC-backed epoch builder.

//! Policy model and authorization epochs (M4).
//!
//! - Policy events live in the SAME DAG as data ops.
//! - Deterministic total order (topo + tie) is the only source of truth.
//! - Grants reference a VC (`cred_hash`); we build epochs only from **verified VCs**.
//! - Revokes intersect/close epochs (deny-wins).
//!
//! Scope semantics: INTERSECTS. Role→permission table is static (“editor”).
//!
//! Filesystem inputs (deterministic, offline):
//!   - `trust/issuers.toml` (issuer -> ed25519 key, hex)
//!   - `trust/status/<list>.bin` (little-endian bitstring)

//! Policy model and authorization epochs (M4).
//! Grants reference a VC; only verified VCs create epochs. Revokes close epochs.

//! Policy model and authorization epochs (M4-ready).
//!
//! - Policy events live in the SAME DAG as data ops.
//! - We now form authorization epochs from VC-backed grants:
//!     * First pass: collect & verify JWT credentials from `Credential` ops
//!       (verify Ed25519 signature using the op author's public key).
//!     * Second pass: for each `Grant{cred_hash}`, look up the verified VC,
//!       and open an epoch with (role, scope, nbf/exp) from the VC claims.
//!     * `Revoke` still closes any open epochs that INTERSECT the revoke scope.
//! - Deny-wins check uses epochs keyed by total-order positions and HLC guards.

use std::collections::{BTreeMap, BTreeSet};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use blake3::Hasher;
use ed25519_dalek::Signature;
use serde_json::Value;

use crate::crypto::{vk_from_bytes, PublicKeyBytes};
use crate::dag::Dag;
use crate::hlc::Hlc;
use crate::op::{OpId, Payload};
use crate::trust::TrustStore;
use crate::status::StatusCache;
use crate::vc::verify_vc;

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

    // If you ever need to inspect entries, use a collected view to avoid lifetime gymnastics.
    #[allow(dead_code)]
    fn entries_for_subject(&self, subject: &PublicKeyBytes) -> Vec<(&String, &Vec<Epoch>)> {
        self.entries
            .iter()
            .filter(|((s, _), _)| s == subject)
            .map(|((_s, r), v)| (r, v))
            .collect()
    }
}

/// Minimal verified VC bundle extracted from a Credential.
#[derive(Debug, Clone)]
struct VerifiedClaims {
    subject_pk: PublicKeyBytes,
    role: String,
    scope: TagSet,
    nbf_ms: u64,
    exp_ms: u64,
}

/// Build authorization epochs by scanning policy events in topo order.
/// M4 path:
///   1) Collect & verify JWTs from `Credential` ops (EdDSA, key = op.author_pk).
///   2) When encountering `Grant{cred_hash}`, look up verified claims and open an epoch.
///   3) `Revoke` closes open epochs in intersecting scope.
pub fn build_auth_epochs(dag: &Dag, topo: &[OpId]) -> EpochIndex {
    // ---- Pass 1: collect verified credentials (cred_hash -> claims)
    let mut vc_index: BTreeMap<[u8; 32], VerifiedClaims> = BTreeMap::new();

    for id in topo {
        let Some(op) = dag.get(id) else { continue; };
        if let Payload::Credential { cred_bytes, .. } = &op.header.payload {
            if let Some(vc) = verify_credential_compact_jwt(cred_bytes, op.header.author_pk) {
                let mut h = Hasher::new();
                h.update(cred_bytes);
                let cred_hash: [u8; 32] = h.finalize().into();
                vc_index.insert(cred_hash, vc);
            }
        }
    }

    // ---- Pass 2: build epochs from grants/revokes
    let mut idx = EpochIndex::default();

    for (pos, id) in topo.iter().enumerate() {
        let Some(op) = dag.get(id) else { continue; };
        match &op.header.payload {
            Payload::Grant { subject_pk, cred_hash } => {
                if let Some(vc) = vc_index.get(cred_hash) {
                    // Subject must match VC.claims.sub_pk
                    if &vc.subject_pk != subject_pk {
                        continue;
                    }
                    idx.push_epoch(*subject_pk, vc.role.clone(), Epoch {
                        scope: vc.scope.clone(),
                        start_pos: pos,
                        end_pos: None,
                        not_before: Some(Hlc::new(vc.nbf_ms, 0)),
                        not_after: Some(Hlc::new(vc.exp_ms, 0)),
                    });
                }
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

// --------------------
// Helpers (JWT verify)

fn verify_credential_compact_jwt(compact: &[u8], issuer_pk_bytes: PublicKeyBytes) -> Option<VerifiedClaims> {
    // Split into header.payload.signature
    let s = core::str::from_utf8(compact).ok()?;
    let mut parts = s.split('.');
    let (h_b64, p_b64, sig_b64) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) => (h, p, s),
        _ => return None,
    };
    if parts.next().is_some() { return None; }

    let header_bytes = URL_SAFE_NO_PAD.decode(h_b64.as_bytes()).ok()?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(p_b64.as_bytes()).ok()?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64.as_bytes()).ok()?;
    if sig_bytes.len() != 64 { return None; }

    // Parse JSON
    let header: Value = serde_json::from_slice(&header_bytes).ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;

    // alg must be EdDSA
    let alg = header.get("alg")?.as_str()?;
    if alg != "EdDSA" { return None; }

    // Verify signature using issuer = author_pk of the Credential op
    let vk = vk_from_bytes(&issuer_pk_bytes).ok()?;
    let signing_input = [h_b64.as_bytes(), b".", p_b64.as_bytes()].concat();
    let sig = Signature::from_slice(&sig_bytes).ok()?;
    if vk.verify_strict(&signing_input, &sig).is_err() {
        return None;
    }

    // Extract required claims
    let role = payload.get("role")?.as_str()?.to_string();
    let nbf_ms = payload.get("nbf")?.as_u64()?;
    let exp_ms = payload.get("exp")?.as_u64()?;
    let sub_pk_hex = payload.get("sub_pk")?.as_str()?;
    let scope_arr = payload.get("scope")?.as_array()?;

    let subject_pk = hex32(sub_pk_hex)?;
    let mut scope = TagSet::new();
    for t in scope_arr {
        scope.insert(t.as_str()?.to_string());
    }

    Some(VerifiedClaims { subject_pk, role, scope, nbf_ms, exp_ms })
}

fn hex32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 { return None; }
    let mut out = [0u8; 32];
    let b = hex.as_bytes();
    for i in 0..32 {
        out[i] = (hex_nibble(b[2*i])? << 4) | hex_nibble(b[2*i + 1])?;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn build_auth_epochs_with(
    dag: &Dag,
    topo: &[OpId],
    trust: &TrustStore,
    status: &mut StatusCache,
) -> EpochIndex {
    // 1) verify credentials once, index by cred_hash
    let mut vc_index: BTreeMap<[u8;32], VerifiedClaims> = BTreeMap::new();
    for id in topo {
        if let Some(op) = dag.get(id) {
            if let Payload::Credential { cred_bytes, .. } = &op.header.payload {
                if let Ok(vc) = verify_vc(cred_bytes, trust, status) {
                    vc_index.insert(vc.cred_hash, VerifiedClaims {
                        subject_pk: vc.subject_pk,
                        role: vc.role,
                        scope: vc.scope_tags,
                        nbf_ms: vc.nbf_ms,
                        exp_ms: vc.exp_ms,
                    });
                }
            }
        }
    }

    // 2) build epochs: only Grant{cred_hash} referencing a verified VC counts
    let mut idx = EpochIndex::default();
    for (pos, id) in topo.iter().enumerate() {
        let Some(op) = dag.get(id) else { continue; };
        match &op.header.payload {
            Payload::Grant { subject_pk, cred_hash } => {
                if let Some(vc) = vc_index.get(cred_hash) {
                    if &vc.subject_pk != subject_pk { continue; }
                    idx.push_epoch(*subject_pk, vc.role.clone(), Epoch {
                        scope: vc.scope.clone(),
                        start_pos: pos,
                        end_pos: None,
                        not_before: Some(Hlc::new(vc.nbf_ms, 0)),
                        not_after:  Some(Hlc::new(vc.exp_ms, 0)),
                    });
                }
            }
            Payload::Revoke { subject_pk, role, scope_tags, .. } => {
                let mut s = TagSet::new(); for t in scope_tags { s.insert(t.clone()); }
                idx.close_epochs_intersecting_scope(subject_pk, role, &s, pos);
            }
            _ => {}
        }
    }
    idx
}