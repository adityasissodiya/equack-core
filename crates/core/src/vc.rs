//! Verifiable Credential (JWT-VC) verification (M4).
//!
//! - Only compact JWS with `alg=EdDSA` (Ed25519).
//! - We hash the EXACT compact bytes for `cred_hash` (blake3 over ASCII).
//! - We extract claims and validate signature against pinned issuer key.
//! - Revocation checked via local StatusCache if `status` present.
//!
//! Time handling:
//!   We *parse* `nbf`/`exp` (ms since epoch) but do not consult wall-clock here.
//!   Replay checks an op's HLC against `[nbf, exp)` when gating.

use core::str;
use std::collections::BTreeSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use blake3::Hasher;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
// crates/core/src/vc.rs
use serde::{Deserialize, Serialize};

use crate::crypto::PublicKeyBytes;
use crate::status::StatusCache;
use crate::trust::TrustStore;

/// VC wire format used in ops (frozen for M4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VcFormat {
    Jwt,
}

#[derive(Debug)]
pub enum VcError {
    BadFormat,
    BadBase64,
    BadJson,
    BadAlg,
    MissingField(&'static str),
    BadKeyHex,
    BadSig,
    UnknownIssuer(String),
    Revoked,
}

#[derive(Debug, Clone)]
pub struct VerifiedVc {
    pub cred_id: String,
    pub cred_hash: [u8; 32],
    pub issuer: String,
    pub subject_pk: PublicKeyBytes,
    pub role: String,
    pub scope_tags: BTreeSet<String>,
    pub nbf_ms: u64,
    pub exp_ms: u64,
    pub status_list_id: Option<String>,
    pub status_index: Option<u32>,
}

pub fn blake3_hash32(v: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(v);
    h.finalize().into()
}

/// Verify a compact JWT VC using the trust store and local status lists.
/// On success returns a `VerifiedVc` with extracted claims.
pub fn verify_vc(
    compact_jwt: &[u8],
    trust: &TrustStore,
    status: &mut StatusCache,
) -> Result<VerifiedVc, VcError> {
    // split into 3 parts
    let s = str::from_utf8(compact_jwt).map_err(|_| VcError::BadFormat)?;
    let mut parts = s.split('.');
    let (h_b64, p_b64, sig_b64) = match (parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s)) => (h, p, s),
        _ => return Err(VcError::BadFormat),
    };
    if parts.next().is_some() { return Err(VcError::BadFormat); }

    let header_bytes = URL_SAFE_NO_PAD.decode(h_b64.as_bytes()).map_err(|_| VcError::BadBase64)?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(p_b64.as_bytes()).map_err(|_| VcError::BadBase64)?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64.as_bytes()).map_err(|_| VcError::BadBase64)?;
    if sig_bytes.len() != 64 { return Err(VcError::BadSig); }

    let header: Value = serde_json::from_slice(&header_bytes).map_err(|_| VcError::BadJson)?;
    let payload: Value = serde_json::from_slice(&payload_bytes).map_err(|_| VcError::BadJson)?;

    let alg = header.get("alg").and_then(|v| v.as_str()).ok_or(VcError::MissingField("alg"))?;
    if alg != "EdDSA" { return Err(VcError::BadAlg); }

    // required claims
    let iss = payload.get("iss").and_then(|v| v.as_str()).ok_or(VcError::MissingField("iss"))?;
    let jti = payload.get("jti").and_then(|v| v.as_str()).ok_or(VcError::MissingField("jti"))?;
    let role = payload.get("role").and_then(|v| v.as_str()).ok_or(VcError::MissingField("role"))?;
    let sub_pk_hex = payload.get("sub_pk").and_then(|v| v.as_str()).ok_or(VcError::MissingField("sub_pk"))?;
    let nbf = payload.get("nbf").and_then(|v| v.as_u64()).ok_or(VcError::MissingField("nbf"))?;
    let exp = payload.get("exp").and_then(|v| v.as_u64()).ok_or(VcError::MissingField("exp"))?;
    let scope = payload.get("scope").and_then(|v| v.as_array()).ok_or(VcError::MissingField("scope"))?;

    let mut scope_tags: BTreeSet<String> = BTreeSet::new();
    for t in scope {
        let s = t.as_str().ok_or(VcError::BadJson)?;
        scope_tags.insert(s.to_string());
    }

    // issuer key
    let vk: &VerifyingKey = trust.get(iss).ok_or_else(|| VcError::UnknownIssuer(iss.to_string()))?;

    // signature over "header.payload"
    let signing_input = [h_b64.as_bytes(), b".", p_b64.as_bytes()].concat();
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| VcError::BadSig)?;
    vk.verify_strict(&signing_input, &sig).map_err(|_| VcError::BadSig)?;

    // parse subject_pk
    let subject_pk = {
        let hex = sub_pk_hex.trim();
        if hex.len() != 64 { return Err(VcError::BadKeyHex); }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = (hex_nibble(hex.as_bytes()[2*i])? << 4) | hex_nibble(hex.as_bytes()[2*i+1])?;
        }
        out
    };

    // optional status
    let (status_id, status_index) = if let Some(st) = payload.get("status") {
        let id = st.get("id").and_then(|v| v.as_str()).ok_or(VcError::BadJson)?;
        let idx = st.get("index").and_then(|v| v.as_u64()).ok_or(VcError::BadJson)?;
        let revoked = status.is_revoked(id, idx as u32);
        if revoked { return Err(VcError::Revoked); }
        (Some(id.to_string()), Some(idx as u32))
    } else {
        (None, None)
    };

    let cred_hash = blake3_hash32(compact_jwt);

    Ok(VerifiedVc {
        cred_id: jti.to_string(),
        cred_hash,
        issuer: iss.to_string(),
        subject_pk,
        role: role.to_string(),
        scope_tags,
        nbf_ms: nbf,
        exp_ms: exp,
        status_list_id: status_id,
        status_index,
    })
}

fn hex_nibble(b: u8) -> Result<u8, VcError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(VcError::BadKeyHex),
    }
}
