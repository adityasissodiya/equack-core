#![cfg(feature = "audit")]

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ecac_core::audit::AuditEvent;
use ecac_core::crypto::{hash_with_domain, sig_from_slice, sign_hash, verify_hash};
use ecac_core::serialize::canonical_cbor;

const DOMAIN: &[u8] = b"ECAC_AUDIT_V1";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct EntryPreimage {
    seq: u64,
    ts_monotonic: u64,
    prev_hash: [u8; 32],
    event: AuditEvent,
    node_id: [u8; 32],
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct Entry {
    seq: u64,
    ts_monotonic: u64,
    prev_hash: [u8; 32],
    event: AuditEvent,
    node_id: [u8; 32],
    signature: Vec<u8>,
}

fn preimage_bytes(e: &Entry) -> Vec<u8> {
    canonical_cbor(&EntryPreimage {
        seq: e.seq, ts_monotonic: e.ts_monotonic, prev_hash: e.prev_hash,
        event: e.event.clone(), node_id: e.node_id,
    })
}
fn entry_hash(e: &Entry) -> [u8; 32] { hash_with_domain(DOMAIN, &preimage_bytes(e)) }

fn seg0(dir: &Path) -> PathBuf { dir.join("audit").join("segment-0000.log") }

/// Append-only audit writer (single segment for now).
pub struct AuditWriter {
    file: File,
    seq: u64,
    prev_hash: [u8; 32],
    node_sk: SigningKey,
    node_id: [u8; 32],
}

impl AuditWriter {
    pub fn open(db_dir: &Path, node_sk: SigningKey, node_id: [u8; 32]) -> Result<Self> {
        let ad = db_dir.join("audit");
        fs::create_dir_all(&ad)?;
        let p = seg0(db_dir);
        let file = OpenOptions::new().create(true).read(true).append(true).open(&p)
            .with_context(|| format!("open {}", p.display()))?;
        let mut s = Self { file, seq: 0, prev_hash: [0;32], node_sk, node_id };
        s.recover()?;
        Ok(s)
    }

    fn recover(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut pos = 0u64;
        loop {
            let mut l = [0u8; 4];
            match self.file.read_exact(&mut l) {
                Ok(()) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let n = u32::from_le_bytes(l) as usize;
            let mut buf = vec![0u8; n];
            if let Err(e) = self.file.read_exact(&mut buf) {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    // truncate partial tail
                    self.file.set_len(pos)?;
                    break;
                }
                return Err(e.into());
            }
            pos += 4 + n as u64;
            let e: Entry = serde_cbor::from_slice(&buf)?;
            self.seq = e.seq;
            self.prev_hash = entry_hash(&e);
        }
        self.file.seek(SeekFrom::End(0))?;
        Ok(())
    }

    pub fn append(&mut self, event: AuditEvent) -> Result<u64> {
        let next = self.seq + 1;
        let mut e = Entry {
            seq: next,
            ts_monotonic: next, // deterministic counter
            prev_hash: self.prev_hash,
            event,
            node_id: self.node_id,
            signature: Vec::new(),
        };
        let h = entry_hash(&e);
        e.signature = sign_hash(&h, &self.node_sk).to_bytes().to_vec();
        let bytes = canonical_cbor(&e);
        self.file.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.file.write_all(&bytes)?;
        self.file.sync_all()?;
        self.seq = next;
        self.prev_hash = h;
        Ok(next)
    }
}

/// Verifier for the single-segment log.
pub struct AuditReader { file: File }

impl AuditReader {
    pub fn open(db_dir: &Path) -> Result<Self> {
        let p = seg0(db_dir);
        Ok(Self { file: OpenOptions::new().read(true).open(&p)
            .with_context(|| format!("open {}", p.display()))? })
    }

    pub fn verify_all(&mut self, node_vk: &VerifyingKey) -> Result<(u64, bool)> {
        self.file.seek(SeekFrom::Start(0))?;
        let mut prev = [0u8;32];
        let mut expect = 1u64;
        let mut count = 0u64;
        let mut truncated = false;

        loop {
            let mut l = [0u8;4];
            match self.file.read_exact(&mut l) {
                Ok(()) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let n = u32::from_le_bytes(l) as usize;
            let mut buf = vec![0u8; n];
            if let Err(e) = self.file.read_exact(&mut buf) {
                if e.kind() == std::io::ErrorKind::UnexpectedEof { truncated = true; break; }
                return Err(e.into());
            }
            let e: Entry = serde_cbor::from_slice(&buf)?;
            if e.seq != expect { return Err(anyhow!("seq gap at {}, got {}", expect, e.seq)); }
            if e.prev_hash != prev { return Err(anyhow!("prev_hash mismatch at seq {}", e.seq)); }
            let h = entry_hash(&e);
            let sig = sig_from_slice(&e.signature).map_err(|_| anyhow!("bad sig at seq {}", e.seq))?;
            if !verify_hash(&h, &sig, node_vk) { return Err(anyhow!("signature verify failed at seq {}", e.seq)); }
            prev = h; expect += 1; count += 1;
        }
        Ok((count, truncated))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecac_core::crypto::{generate_keypair, hash_bytes};
    use ecac_core::audit::{AppliedReason, SkipReason};
    use tempfile::tempdir;

    #[test]
    fn basic_roundtrip_and_verify() {
        let (sk, vk) = generate_keypair();
        let node_id = hash_bytes(&vk.to_bytes());
        let dir = tempdir().unwrap();

        let mut w = AuditWriter::open(dir.path(), sk, node_id).unwrap();
        w.append(AuditEvent::IngestedOp { op_id: [1;32], author_pk: [2;32], parents: vec![], verified_sig: true }).unwrap();
               w.append(AuditEvent::AppliedOp  { op_id: [1;32], topo_idx: 0, reason: AppliedReason::Authorized }).unwrap();
               w.append(AuditEvent::SkippedOp  { op_id: [3;32], topo_idx: 1, reason: SkipReason::DenyWins }).unwrap();

        let mut r = AuditReader::open(dir.path()).unwrap();
        let (cnt, trunc) = r.verify_all(&vk).unwrap();
        assert_eq!(cnt, 3);
        assert!(!trunc);
    }
}
