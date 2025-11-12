//! Operation definition: header (hashed), signature, and derived op_id.
//!
//! M4 change summary:
//! - Payload::Data remains EXACTLY as in M1/M2 (schema & bytes unchanged).
//! - Add `Payload::Credential` to carry a VC on the log (JWT compact bytes).
//! - Change `Payload::Grant` to reference a VC by `cred_hash` and `subject_pk`.
//!   Role/scope/time now come from the VC (verified during M4 policy build).
//! - `Payload::Revoke` remains as in M3 (explicit deny).

use serde::{Deserialize, Serialize};

use crate::crypto::{
    self, hash_with_domain, sig_from_slice, vk_from_bytes, PublicKeyBytes, OP_HASH_DOMAIN,
};
use crate::hlc::Hlc;
use crate::serialize::canonical_cbor;

pub type OpId = [u8; 32];

/// Credential formats we support on the log.
/// M4 freezes to JWT (compact JWS, Ed25519, alg=EdDSA). JSON-LD is out of scope.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CredentialFormat {
    Jwt,
}

/// The part we hash & sign (no sig/op_id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpHeader {
    /// Some older/externally-produced CBOR may omit `parents` when empty.
    /// Accept that by defaulting to [] on deserialization (serialization unchanged).
    pub parents: Vec<OpId>,
    /// Older CBOR may omit `hlc`; accept and default to zero to keep legacy files readable.
    #[serde(default)]
    pub hlc: Hlc,
    pub author_pk: PublicKeyBytes,
    pub payload: Payload,
}

/// Payload variants.
///
/// IMPORTANT: Do NOT change the CBOR preimage structure or op_id domain.
/// `Data` must remain exactly as in M1/M2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload {
    /// M1/M2 data op (naming convention interprets semantics in replay/policy).
    Data { key: String, value: Vec<u8> },

    /// M4: Carry a verifiable credential on the log (JWT compact bytes).
    /// - `cred_id`: application-level identifier (e.g., jti)
    /// - `cred_bytes`: the EXACT compact JWT bytes (ASCII) as received
    /// - `format`: must be `Jwt` in M4
    Credential {
        cred_id: String,
        cred_bytes: Vec<u8>,
        format: CredentialFormat,
    },

    /// M4: Grant references a credential by its hash.
    /// - `cred_hash` = blake3 over EXACT compact JWT bytes (header.payload.signature)
    /// - `subject_pk`: the intended subject of the grant (authorizing identity)
    ///
    /// Role, scope, nbf/exp are derived from the verified VC; not embedded here.
    Grant {
        subject_pk: PublicKeyBytes,
        cred_hash: [u8; 32],
    },

    /// M3/M4: explicit deny event. Still supported and intersected with VC epochs.
    Revoke {
        subject_pk: PublicKeyBytes,
        role: String,
        scope_tags: Vec<String>,
        at: Hlc,
    },

    #[serde(other)]
    _Reserved,
}

/// Full op = header + signature + derived id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Op {
    pub header: OpHeader,
    pub sig: Vec<u8>, // store as Vec<u8> for serde friendliness
    pub op_id: OpId,
}

impl Op {
    /// Create + sign a new op.
    pub fn new(
        parents: Vec<OpId>,
        hlc: Hlc,
        author_vk_bytes: PublicKeyBytes,
        payload: Payload,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let header = OpHeader {
            parents,
            hlc,
            author_pk: author_vk_bytes,
            payload,
        };
        let header_bytes = canonical_cbor(&header);
        let op_id = hash_with_domain(OP_HASH_DOMAIN, &header_bytes);
        let sig = crypto::sign_hash(&op_id, signing_key).to_bytes().to_vec();
        Self { header, sig, op_id }
    }

    /// Verify: re-hash header, id must match, then verify signature under author_pk.
    pub fn verify(&self) -> bool {
        let header_bytes = canonical_cbor(&self.header);
        let expect = hash_with_domain(OP_HASH_DOMAIN, &header_bytes);
        if expect != self.op_id {
            return false;
        }
        let vk = match vk_from_bytes(&self.header.author_pk) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let sig = match sig_from_slice(&self.sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        crypto::verify_hash(&self.op_id, &sig, &vk)
    }

    pub fn author_pk(&self) -> PublicKeyBytes {
        self.header.author_pk
    }
    pub fn hlc(&self) -> Hlc {
        self.header.hlc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_keypair, vk_to_bytes};

    #[test]
    fn op_id_stable_and_signature_valid_for_data() {
        let (sk, vk) = generate_keypair();
        let vk_bytes = vk_to_bytes(&vk);

        let op1 = Op::new(
            vec![],
            Hlc::new(100, 1),
            vk_bytes,
            Payload::Data {
                key: "k".into(),
                value: b"v".to_vec(),
            },
            &sk,
        );
        assert!(op1.verify());

        let op2 = Op::new(
            vec![],
            Hlc::new(100, 1),
            vk_bytes,
            Payload::Data {
                key: "k".into(),
                value: b"v".to_vec(),
            },
            &sk,
        );
        assert_eq!(op1.op_id, op2.op_id);

        // Tamper payload ⇒ verify must fail
        let mut tampered = op1.clone();
        if let Payload::Data { ref mut value, .. } = tampered.header.payload {
            value.push(0);
        }
        assert!(!tampered.verify());
    }
}
