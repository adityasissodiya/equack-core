//! Local revocation/status lists (M4).
//!
//! Files live under `trust/status/<list_id>.bin` as a little-endian bitstring.
//! Bit `index` set → credential revoked. Missing files mean "not revoked".

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub enum StatusError {
    Io(std::io::Error),
}

impl From<std::io::Error> for StatusError { fn from(e: std::io::Error) -> Self { StatusError::Io(e) } }

#[derive(Debug, Default, Clone)]
pub struct StatusCache {
    base_dir: PathBuf,
    cache: HashMap<String, Vec<u8>>,
}

impl StatusCache {
    pub fn load_from_dir<P: AsRef<Path>>(dir: P) -> Self {
        let base = PathBuf::from(dir.as_ref());
        // dir should be `.../trust/status`
        Self { base_dir: base, cache: HashMap::new() }
    }

    fn load_list(&mut self, list_id: &str) -> Option<&[u8]> {
        if !self.cache.contains_key(list_id) {
            let mut p = self.base_dir.clone();
            p.push(format!("{list_id}.bin"));
            if let Ok(bytes) = fs::read(p) {
                self.cache.insert(list_id.to_string(), bytes);
            } else {
                // cache empty vector to avoid repeated fs lookups
                self.cache.insert(list_id.to_string(), Vec::new());
            }
        }
        self.cache.get(list_id).map(|v| v.as_slice())
    }

    /// Little-endian bit check: LSB=bit0.
    pub fn is_revoked(&mut self, list_id: &str, index: u32) -> bool {
        let Some(bytes) = self.load_list(list_id) else { return false; };
        let i = index as usize / 8;
        let b = index as usize % 8;
        if i >= bytes.len() { return false; }
        (bytes[i] & (1u8 << b)) != 0
    }

    /// Empty in-memory cache (no revocations).
    pub fn empty() -> Self {
        Self { base_dir: std::path::PathBuf::new(), cache: std::collections::HashMap::new() }
    }

    /// Build an in-memory cache from `(list_id, bytes)` pairs (for tests).
    pub fn from_map<I: IntoIterator<Item = (String, Vec<u8>)>>(lists: I) -> Self {
        let mut cache = std::collections::HashMap::new();
        for (id, bytes) in lists {
            cache.insert(id, bytes);
        }
        Self { base_dir: std::path::PathBuf::new(), cache }
    }
}
