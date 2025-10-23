//! Operation definition: header (hashed), signature, and derived op_id.

use serde::{Deserialize, Serialize};

use crate::crypto::{
    self, hash_with_domain, sig_from_slice, vk_from_bytes, OP_HASH_DOMAIN, PublicKeyBytes,
};
use crate::hlc::Hlc;
use crate::serialize::canonical_cbor;

pub type OpId = [u8; 32];

/// The part we hash & sign (no sig/op_id).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpHeader {
    pub parents: Vec<OpId>,
    pub hlc: Hlc,
    pub author_pk: PublicKeyBytes,
    pub payload: Payload,
}

/// Minimal payload variants for M1. Extend later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload {
    Data { key: String, value: Vec<u8> },
    #[serde(other)]
    _Reserved,
}

/// Full op = header + signature + derived id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Op {
    pub header: OpHeader,
    pub sig: Vec<u8>,   // store as Vec<u8> for serde friendliness
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
        let header = OpHeader { parents, hlc, author_pk: author_vk_bytes, payload };
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

    pub fn author_pk(&self) -> PublicKeyBytes { self.header.author_pk }
    pub fn hlc(&self) -> Hlc { self.header.hlc }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_keypair, vk_to_bytes};

    #[test]
    fn op_id_stable_and_signature_valid() {
        let (sk, vk) = generate_keypair();
        let vk_bytes = vk_to_bytes(&vk);

        let op1 = Op::new(vec![], Hlc::new(100, 1), vk_bytes, Payload::Data { key: "k".into(), value: b"v".to_vec() }, &sk);
        assert!(op1.verify());

        let op2 = Op::new(vec![], Hlc::new(100, 1), vk_bytes, Payload::Data { key: "k".into(), value: b"v".to_vec() }, &sk);
        assert_eq!(op1.op_id, op2.op_id);

        // Tamper payload ⇒ verify must fail
        let mut tampered = op1.clone();
        if let Payload::Data { ref mut value, .. } = tampered.header.payload {
            value.push(0);
        }
        assert!(!tampered.verify());
    }
}
