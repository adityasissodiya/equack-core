//! Minimal crypto helpers for M1/M4/M9:
//! - BLAKE3 hashing
//! - Ed25519 signing/verifying
//! - XChaCha20-Poly1305 encrypt/decrypt for confidential values (M9)

use blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};

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

/// Domain separator for AEAD AAD derivation.
/// M9: aad = blake3(
///     "ECAC_AAD"
///     || author_pk
///     || hlc_physical_ms
///     || hlc_logical
///     || parents
///     || obj
///     || field
/// )
pub const ENC_AAD_DOMAIN: &[u8] = b"ECAC_AAD";

/// Derive the AEAD AAD for a given op header + (obj, field).
/// Callers should pass this as `aad` into encrypt/decrypt.
pub fn derive_enc_aad(
    author_pk: &[u8; 32],
    hlc_physical_ms: u64,
    hlc_logical: u64,
    parents: &[[u8; 32]],
    obj: &str,
    field: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ENC_AAD_DOMAIN);
    hasher.update(author_pk);
    hasher.update(&hlc_physical_ms.to_be_bytes());
    hasher.update(&hlc_logical.to_be_bytes());
    for p in parents {
        hasher.update(p);
    }
    hasher.update(obj.as_bytes());
    hasher.update(field.as_bytes());
    *hasher.finalize().as_bytes()
}

/// M9: encrypted value envelope (EncV1).
///
/// Cipher: XChaCha20-Poly1305
///  - key: 32 bytes (handled by caller / keyring)
///  - nonce: 24 bytes
///  - tag: 16 bytes
///
/// We separate `aead_tag` from `ct` for a stable on-wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncV1 {
    /// Logical tag for this field (e.g., "hv", "mech", "confidential").
    pub tag: String,
    /// Key version used for this ciphertext.
    pub key_version: u32,
    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: [u8; 24],
    /// Authentication tag (16 bytes).
    pub aead_tag: [u8; 16],
    /// Ciphertext bytes.
    pub ct: Vec<u8>,
}

/// Encrypt plaintext into an EncV1 envelope using XChaCha20-Poly1305.
///
/// - `tag`: logical tag (policy-level; not the AEAD tag)
/// - `key_version`: current version for this tag
/// - `key`: 32-byte symmetric key
/// - `plaintext`: bytes to encrypt
/// - `aad`: additional authenticated data
pub fn encrypt_value(
    tag: &str,
    key_version: u32,
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> EncV1 {
    let key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut buf = plaintext.to_vec();

    let auth_tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(&nonce), aad, &mut buf)
        .expect("encryption failure");

    let mut tag_bytes = [0u8; 16];
    tag_bytes.copy_from_slice(auth_tag.as_slice());

    EncV1 {
        tag: tag.to_string(),
        key_version,
        nonce,
        aead_tag: tag_bytes,
        ct: buf,
    }
}

/// Decrypt an EncV1 envelope with the given key and AAD.
/// Returns None on any failure (wrong key, bad AAD, tampering).
pub fn decrypt_value(key: &[u8; 32], enc: &EncV1, aad: &[u8]) -> Option<Vec<u8>> {
    let key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(key);

    let mut buf = enc.ct.clone();
    let nonce = XNonce::from_slice(&enc.nonce);
    let auth_tag = chacha20poly1305::Tag::from_slice(&enc.aead_tag);

    if cipher
        .decrypt_in_place_detached(nonce, aad, &mut buf, auth_tag)
        .is_err()
    {
        return None;
    }
    Some(buf)
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
pub fn vk_from_bytes(
    bytes: &PublicKeyBytes,
) -> Result<VerifyingKey, ed25519_dalek::SignatureError> {
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
    #[test]
    fn enc_dec_roundtrip_and_tamper() {
        // Fixed key for test determinism.
        let key: [u8; 32] = [7u8; 32];
        let author_pk: [u8; 32] = [1u8; 32];
        let hlc_physical_ms: u64 = 0;
        let hlc_logical: u64 = 0;
        // No parents in this synthetic test.
        let parents: &[[u8; 32]] = &[];
        let aad = derive_enc_aad(&author_pk, hlc_physical_ms, hlc_logical, parents, "o", "x");

        let pt = b"secret bytes";

        let enc = encrypt_value("hv", 1, &key, pt, &aad);
        let dec = decrypt_value(&key, &enc, &aad).expect("decrypt ok");
        assert_eq!(dec, pt);

        // Wrong key ⇒ fail.
        let wrong_key: [u8; 32] = [3u8; 32];
        assert!(decrypt_value(&wrong_key, &enc, &aad).is_none());

        // Tamper ciphertext ⇒ fail.
        let mut enc_ct_tampered = enc.clone();
        if !enc_ct_tampered.ct.is_empty() {
            enc_ct_tampered.ct[0] ^= 0x01;
        }
        assert!(decrypt_value(&key, &enc_ct_tampered, &aad).is_none());

        // Tamper tag ⇒ fail.
        let mut enc_tag_tampered = enc;
        enc_tag_tampered.aead_tag[0] ^= 0x01;
        assert!(decrypt_value(&key, &enc_tag_tampered, &aad).is_none());
    }
}
