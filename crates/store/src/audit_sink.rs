#![cfg(feature = "audit")]

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use getrandom::getrandom;
use std::{
    env, fs,
    path::Path,
    sync::{Arc, Mutex},
};

use crate::audit::AuditWriter;
use ecac_core::audit::AuditEvent;
use ecac_core::audit_hook::AuditHook;

/// File-backed audit hook that appends to the store audit log.
pub struct StoreAuditHook {
    inner: Arc<Mutex<AuditWriter>>,
}

impl StoreAuditHook {
    /// Back-compat: open with explicit key + node_id (used by tests).
    pub fn open(dir: &Path, sk: SigningKey, node_id: [u8; 32]) -> Result<Self> {
        fs::create_dir_all(dir).ok();
        let writer = AuditWriter::open(dir, sk, node_id)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(writer)),
        })
    }

    /// Open using ECAC_AUDIT_DIR or default ".audit".
    pub fn open_default() -> Result<Self> {
        let dir = env::var("ECAC_AUDIT_DIR").unwrap_or_else(|_| ".audit".to_string());
        Self::open_dir(Path::new(&dir))
    }

    /// Open and bootstrap key / node_id material under `dir`.
    pub fn open_dir(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).ok();

        // signing key (32 bytes)
        let sk_path = dir.join("node_sk.bin");
        let sk = if sk_path.exists() {
            let b = fs::read(&sk_path).context("read node_sk.bin")?;
            let arr: [u8; 32] = b
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("node_sk.bin must be 32 bytes"))?;
            SigningKey::from_bytes(&arr)
        } else {
            let mut bytes = [0u8; 32];
            getrandom(&mut bytes)?;
            fs::write(&sk_path, &bytes)?;
            SigningKey::from_bytes(&bytes)
        };

        // node id (32 bytes) — reuse if present, else generate
        let id_path = dir.join("node_id.bin");
        let node_id = if id_path.exists() {
            let b = fs::read(&id_path).context("read node_id.bin")?;
            let mut id = [0u8; 32];
            anyhow::ensure!(b.len() == 32, "node_id.bin must be 32 bytes");
            id.copy_from_slice(&b);
            id
        } else {
            let mut id = [0u8; 32];
            getrandom(&mut id)?;
            id
        };

        let writer = AuditWriter::open(dir, sk, node_id)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(writer)),
        })
    }
}

impl AuditHook for StoreAuditHook {
    fn on_event(&mut self, e: AuditEvent) {
        if let Ok(mut w) = self.inner.lock() {
            let _ = w.append(e);
        }
    }
}
