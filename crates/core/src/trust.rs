//! Trust store loader for issuer public keys (M4).
//!
//! File: `trust/issuers.toml`
//! ```toml
//! [issuers]
//! oem-issuer-1 = "f1e2d3...<64 hex chars ed25519 verifying key>"
//! another-issuer = "ab12..."
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;

#[derive(Debug)]
pub enum TrustError {
    Io(std::io::Error),
    Utf8(std::str::Utf8Error),
    Toml(toml::de::Error),
    BadKeyHex(String),
    BadKeyLen(usize),
    Dalek(ed25519_dalek::SignatureError),
}

impl From<std::io::Error> for TrustError { fn from(e: std::io::Error) -> Self { TrustError::Io(e) } }
impl From<std::str::Utf8Error> for TrustError { fn from(e: std::str::Utf8Error) -> Self { TrustError::Utf8(e) } }
impl From<toml::de::Error> for TrustError { fn from(e: toml::de::Error) -> Self { TrustError::Toml(e) } }
impl From<ed25519_dalek::SignatureError> for TrustError { fn from(e: ed25519_dalek::SignatureError) -> Self { TrustError::Dalek(e) } }

#[derive(Deserialize)]
struct IssuersToml {
    issuers: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct TrustStore {
    pub issuers: HashMap<String, VerifyingKey>,
}

impl TrustStore {
    /// Load `trust/issuers.toml` from a directory.
    pub fn load_from_dir<P: AsRef<Path>>(dir: P) -> Result<Self, TrustError> {
        let mut p = PathBuf::from(dir.as_ref());
        p.push("issuers.toml");
        let bytes = fs::read(&p)?;
        let s = std::str::from_utf8(&bytes)?;
        let parsed: IssuersToml = toml::from_str(s)?;

        let mut map = HashMap::new();
        for (iss, hexstr) in parsed.issuers.into_iter() {
            let key_bytes = hex_to_bytes(&hexstr).map_err(|_| TrustError::BadKeyHex(iss.clone()))?;
            if key_bytes.len() != 32 {
                return Err(TrustError::BadKeyLen(key_bytes.len()));
            }
            // Borrow the slice for conversion to avoid moving `key_bytes`.
            let arr: [u8; 32] = <[u8; 32]>::try_from(key_bytes.as_slice())
                .map_err(|_| TrustError::BadKeyLen(key_bytes.len()))?;
            let vk = VerifyingKey::from_bytes(&arr)?;
            map.insert(iss, vk);
        }
        Ok(Self { issuers: map })
    }

    pub fn get(&self, issuer: &str) -> Option<&VerifyingKey> {
        self.issuers.get(issuer)
    }

    /// Build a trust store in-memory with a single issuer (handy for tests).
    pub fn from_single(issuer_id: &str, vk: ed25519_dalek::VerifyingKey) -> Self {
        let mut m = std::collections::HashMap::new();
        m.insert(issuer_id.to_string(), vk);
        Self { issuers: m }
    }
    
}

// ---- helpers

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim();
    if s.len() % 2 != 0 { return Err(()); }
    let mut out = Vec::with_capacity(s.len()/2);
    let b = s.as_bytes();
    for i in (0..s.len()).step_by(2) {
        out.push(nibble(b[i])? << 4 | nibble(b[i+1])?);
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}
