//! Minimal crypto helpers for M1: BLAKE3 hashing + Ed25519 signing/verifying.

use blake3;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer, Verifier};
use rand::rngs::OsRng;

pub type PublicKeyBytes = [u8; 32];

/// Domain separator for op hashing.
pub const OP_HASH_DOMAIN: &[u8] = b"ECAC_OP_V1";

/// blake3(data) -> 32-byte digest
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Domain-separated hash: blake3(DOMAIN || msg)
pub fn hash_with_domain(domain: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(msg);
    *hasher.finalize().as_bytes()
}

/// Generate a fresh Ed25519 keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// Sign a 32-byte hash.
pub fn sign_hash(hash32: &[u8; 32], sk: &SigningKey) -> Signature {
    sk.sign(hash32)
}

/// Verify a signature over a 32-byte hash.
pub fn verify_hash(hash32: &[u8; 32], sig: &Signature, vk: &VerifyingKey) -> bool {
    vk.verify(hash32, sig).is_ok()
}

/// Convert VerifyingKey -> 32-byte public key bytes.
pub fn vk_to_bytes(vk: &VerifyingKey) -> PublicKeyBytes {
    vk.to_bytes()
}

/// Parse VerifyingKey from 32 bytes.
pub fn vk_from_bytes(bytes: &PublicKeyBytes) -> Result<VerifyingKey, ed25519_dalek::SignatureError> {
    VerifyingKey::from_bytes(bytes)
}

/// Convert Signature -> [u8; 64].
pub fn sig_to_bytes(sig: &Signature) -> [u8; 64] {
    sig.to_bytes()
}

/// Parse Signature from slice (expects 64 bytes).
pub fn sig_from_slice(bytes: &[u8]) -> Result<Signature, ed25519_dalek::ed25519::Error> {
    Signature::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_tamper() {
        let (sk, vk) = generate_keypair();
        let msg = b"hello";
        let h = hash_with_domain(OP_HASH_DOMAIN, msg);
        let sig = sign_hash(&h, &sk);
        assert!(verify_hash(&h, &sig, &vk));

        let mut tampered = h;
        tampered[0] ^= 0x01;
        assert!(!verify_hash(&tampered, &sig, &vk));
    }
}
