//use anyhow::{anyhow, Result};
use anyhow::Result;
use ecac_core::serialize::canonical_cbor;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::types::{Announce, FetchMissing, RpcFrame, SignedAnnounce};

/// Encode any wire value to canonical CBOR bytes.
pub fn to_cbor_announce(a: &Announce) -> Vec<u8> {
    canonical_cbor(a)
}
pub fn to_cbor_signed_announce(sa: &SignedAnnounce) -> Vec<u8> {
    canonical_cbor(sa)
}
pub fn to_cbor_fetch(req: &FetchMissing) -> Vec<u8> {
    canonical_cbor(req)
}
pub fn to_cbor_frame(f: &RpcFrame) -> Vec<u8> {
    canonical_cbor(f)
}

/// Decode helpers.
pub fn from_cbor_announce(b: &[u8]) -> Result<Announce> {
    Ok(serde_cbor::from_slice(b)?)
}
pub fn from_cbor_signed_announce(b: &[u8]) -> Result<SignedAnnounce> {
    Ok(serde_cbor::from_slice(b)?)
}
pub fn from_cbor_fetch(b: &[u8]) -> Result<FetchMissing> {
    Ok(serde_cbor::from_slice(b)?)
}
pub fn from_cbor_frame(b: &[u8]) -> Result<RpcFrame> {
    Ok(serde_cbor::from_slice(b)?)
}

/// Produce a SignedAnnounce using the provided ed25519 signing key.
/// Signature = Ed25519 over canonical CBOR bytes of `announce`.
pub fn sign_announce(announce: Announce, sk: &SigningKey) -> SignedAnnounce {
    let vk = sk.verifying_key();
    let bytes = to_cbor_announce(&announce);
    //let sig = sk.sign(&blake3::hash(&bytes).as_bytes()); // sign a fixed 32-byte digest
    let digest = blake3::hash(&bytes);
    let sig = sk.sign(digest.as_bytes()); // sign the 32-byte digest as bytes
    SignedAnnounce {
        announce,
        sig: sig.to_bytes().to_vec(),
        vk: vk.to_bytes(),
    }
}

/// Verify a SignedAnnounce: (re-encode announce -> blake3) then ed25519 verify.
pub fn verify_signed_announce(sa: &SignedAnnounce) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&sa.vk) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&sa.sig) else {
        return false;
    };
    let bytes = to_cbor_announce(&sa.announce);
    // let h = *blake3::hash(&bytes).as_bytes();
    // vk.verify(&h, &sig).is_ok()
    let digest = blake3::hash(&bytes);
    vk.verify(digest.as_bytes(), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Announce, FetchMissing, RpcFrame};
    use ecac_core::op::OpId;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn opid(x: u8) -> OpId {
        [x; 32]
    }

    #[test]
    fn announce_roundtrip_and_verify() {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);

        let a = Announce {
            node_id: [7u8; 32],
            topo_watermark: 123,
            head_ids: vec![opid(1), opid(2)],
            bloom16: [0b0000_1111, 0b1010_0000],
        };
        let sa = sign_announce(a.clone(), &sk);
        assert!(verify_signed_announce(&sa));

        // Deterministic encode (struct-only CBOR) → equal bytes for equal inputs
        let sa2 = sign_announce(a, &sk);
        assert_eq!(to_cbor_signed_announce(&sa), to_cbor_signed_announce(&sa2));
        assert!(verify_signed_announce(&sa2));
    }

    #[test]
    fn rpc_frames_roundtrip() {
        let op = RpcFrame::OpBytes(vec![1, 2, 3, 4]);
        let end = RpcFrame::End;

        let b1 = to_cbor_frame(&op);
        let b2 = to_cbor_frame(&end);

        let op2 = from_cbor_frame(&b1).unwrap();
        let end2 = from_cbor_frame(&b2).unwrap();

        assert_eq!(op, op2);
        assert_eq!(end, end2);

        let req = FetchMissing {
            want: vec![opid(9), opid(10)],
        };
        let rb = to_cbor_fetch(&req);
        let req2 = from_cbor_fetch(&rb).unwrap();
        assert_eq!(req, req2);
    }
}
