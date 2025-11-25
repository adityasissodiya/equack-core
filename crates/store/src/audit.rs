// crates/store/src/audit.rs
#![cfg(feature = "audit")]

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    //time::Instant,
};

use anyhow::{anyhow, Context, Result};
use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use ecac_core::audit::AuditEvent;

// ---- wire types -------------------------------------------------------------

const DOMAIN: &[u8] = b"ECAC_AUDIT_V1";
const SEG_PREFIX: &str = "segment-";
const INDEX_FILE: &str = "index.json";
const NODE_PK_FILE: &str = "node_pk.bin";
const NODE_ID_FILE: &str = "node_id.bin";

fn canonical_cbor<T: serde::Serialize>(v: &T) -> Vec<u8> {
        // serde_cbor 0.11 doesn't expose a "canonical" toggle. For our struct-only
        // payloads this is deterministic (field order is definition order).
        serde_cbor::to_vec(v).expect("CBOR serialize")
    }
     
#[derive(Serialize)]
struct EntryNoSig<'a> {
    seq: u64,
    ts_monotonic: u64,
    prev_hash: [u8; 32],
    #[serde(borrow)]
    event: &'a AuditEvent,
    node_id: [u8; 32],
}

#[derive(Clone)]
struct Entry {
    seq: u64,
    ts_monotonic: u64,
    prev_hash: [u8; 32],
    event: AuditEvent,
    node_id: [u8; 32],
    signature: [u8; 64],
}

// Wire adapter to avoid serde on [u8; 64].
#[derive(Serialize, Deserialize, Clone)]
struct EntryWire {
    seq: u64,
    ts_monotonic: u64,
    prev_hash: [u8; 32],
    event: AuditEvent,
    node_id: [u8; 32],
    signature: Vec<u8>,
}

impl From<&Entry> for EntryWire {
    fn from(e: &Entry) -> Self {
        Self {
            seq: e.seq,
            ts_monotonic: e.ts_monotonic,
            prev_hash: e.prev_hash,
            event: e.event.clone(),
            node_id: e.node_id,
            signature: e.signature.to_vec(),
        }
    }
}

impl TryFrom<EntryWire> for Entry {
    type Error = anyhow::Error;
    fn try_from(w: EntryWire) -> Result<Self> {
        let sig: [u8; 64] = w
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("signature length must be 64"))?;
        Ok(Self {
            seq: w.seq,
            ts_monotonic: w.ts_monotonic,
            prev_hash: w.prev_hash,
            event: w.event,
            node_id: w.node_id,
            signature: sig,
        })
    }
}


#[derive(Serialize, Deserialize, Default, Clone)]
struct Index {
    segments: Vec<IndexSeg>,
}
#[derive(Serialize, Deserialize, Clone)]
struct IndexSeg {
    segment_id: u32,
    path: String,
    first_seq: u64,
    last_seq: u64,
    first_hash: [u8; 32],
    last_hash: [u8; 32],
}

// ---- helpers ----------------------------------------------------------------

fn hash_preimage(pre: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN);
    h.update(pre);
    h.finalize().into()
}

fn u32_be(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

fn read_u32_be(r: &mut File) -> std::io::Result<Option<u32>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => Ok(Some(u32::from_be_bytes(len))),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

fn atomic_write_json(path: &Path, v: &impl Serialize) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(v)?)?;
    fs::rename(tmp, path)?;
    Ok(())
}

// ---- writer -----------------------------------------------------------------

pub struct AuditWriter {
    dir: PathBuf,
    sk: SigningKey,
    vk: VerifyingKey,
    node_id: [u8; 32],

    seg_id: u32,
    file: File,
    seq: u64,
    prev_hash: [u8; 32],
    ts_counter: u64,
    bytes_in_seg: u64,
    rotate_bytes: u64,
    index: Index,
}

impl AuditWriter {
    /// `dir` must already be the audit directory (no extra "audit" appended here).
    /// Writes `node_pk.bin` and `node_id.bin` once, creates/updates `index.json`,
    /// and starts at a fresh segment `segment-00000001.log` unless one exists.
    pub fn open(dir: &Path, sk: SigningKey, node_id: [u8; 32]) -> Result<Self> {
        fs::create_dir_all(dir).ok();

        let vk = sk.verifying_key();
        // Persist node pk/id for verifiers.
        let pk_bytes = vk.to_bytes();
        let pk_path = dir.join(NODE_PK_FILE);
        let id_path = dir.join(NODE_ID_FILE);
        if !pk_path.exists() {
            fs::write(&pk_path, &pk_bytes)?;
        }
        if !id_path.exists() {
            fs::write(&id_path, &node_id)?;
        }

        // Rotation threshold (MiB), default 8
        let rotate_bytes = std::env::var("ECAC_AUDIT_ROTATE_MB")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(8)
            * 1024
            * 1024;

        // Load or create index
        let index_path = dir.join(INDEX_FILE);
        let mut index: Index = if index_path.exists() {
            let b = fs::read(&index_path)?;
            serde_json::from_slice(&b)?
        } else {
            Index::default()
        };

        // If index has segments, resume last; else create first.
        let (seg_id, mut file, mut seq, mut prev_hash, mut bytes_in_seg, _first_hash) =
            if let Some(last) = index.segments.last() {
                let p = dir.join(&last.path);
                let mut f = OpenOptions::new().read(true).write(true).open(&p)?;
                // Seek to end and pick up last_seq/last_hash from index
                let len = f.metadata()?.len();
                f.seek(SeekFrom::End(0))?;
                (
                    last.segment_id,
                    f,
                    last.last_seq,
                    last.last_hash,
                    len,
                    last.first_hash,
                )
            } else {
                let seg_id = 1u32;
                let p = dir.join(format!("{SEG_PREFIX}{seg_id:08}.log"));
                let f = OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .open(&p)?;
                // First segment starts with prev_hash = 0
                let first_hash = [0u8; 32];
                index.segments.push(IndexSeg {
                    segment_id: seg_id,
                    path: p.file_name().unwrap().to_string_lossy().to_string(),
                    first_seq: 0,
                    last_seq: 0,
                    first_hash,
                    last_hash: first_hash,
                });
                (seg_id, f, 0, first_hash, 0, first_hash)
            };

        // Ensure index on disk
        atomic_write_json(&index_path, &index)?;

        Ok(Self {
            dir: dir.to_path_buf(),
            sk,
            vk,
            node_id,
            seg_id,
            file,
            seq,
            prev_hash,
            ts_counter: 0,
            bytes_in_seg,
            rotate_bytes,
            index,
        })
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join(INDEX_FILE)
    }
    fn seg_path(&self, seg_id: u32) -> PathBuf {
        self.dir.join(format!("{SEG_PREFIX}{seg_id:08}.log"))
    }

    fn roll_segment(&mut self) -> Result<()> {
        // Update index last_hash for previous segment is already maintained during append.

        self.seg_id += 1;
        let p = self.seg_path(self.seg_id);
        self.file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&p)?;
        self.bytes_in_seg = 0;

        // New segment inherits prev_hash; first_seq will be set at next append.
        self.index.segments.push(IndexSeg {
            segment_id: self.seg_id,
            path: p.file_name().unwrap().to_string_lossy().to_string(),
            first_seq: 0,
            last_seq: 0,
            first_hash: self.prev_hash,
            last_hash: self.prev_hash,
        });
        atomic_write_json(&self.index_path(), &self.index)?;
        Ok(())
    }

    /// Append one event; returns the sequence number.
    pub fn append(&mut self, event: AuditEvent) -> Result<u64> {
        // Rotation?
        if self.bytes_in_seg >= self.rotate_bytes && self.rotate_bytes > 0 {
            self.roll_segment()?;
        }

        let seq = self.seq + 1;
        let ts_monotonic = self.ts_counter + 1;

        let pre = EntryNoSig {
            seq,
            ts_monotonic,
            prev_hash: self.prev_hash,
            event: &event,
            node_id: self.node_id,
        };
        let pre_bytes = canonical_cbor(&pre);
        let entry_hash = hash_preimage(&pre_bytes);

        let sig: Signature = self.sk.sign(&entry_hash);
        let entry = Entry {
            seq,
            ts_monotonic,
            prev_hash: self.prev_hash,
            event,
            node_id: self.node_id,
            signature: sig.to_bytes(),
        };
                // Write canonical CBOR of the wire representation
        let wire = EntryWire::from(&entry);
        let bytes = canonical_cbor(&wire);

        let len = bytes.len() as u32;
        self.file.write_all(&u32_be(len))?;
        self.file.write_all(&bytes)?;
        self.file.flush()?;
        // fsync for correctness (we can relax later)
        self.file.sync_data()?;

        self.bytes_in_seg += 4 + len as u64;
        self.seq = seq;
        self.ts_counter = ts_monotonic;
        self.prev_hash = entry_hash;

        // Update index (first_seq lazily set at first write to segment)
        if let Some(last) = self.index.segments.last_mut() {
            if last.first_seq == 0 {
                last.first_seq = seq;
                last.first_hash = entry_hash; // first entry's hash in this segment
            }
            last.last_seq = seq;
            last.last_hash = entry_hash;
        }
        atomic_write_json(&self.index_path(), &self.index)?;

        Ok(seq)
    }
}

// ---- reader & verifier ------------------------------------------------------

#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("I/O error at {path} @offset {offset}: {source}")]
    Io {
        path: String,
        offset: u64,
        #[source]
        source: std::io::Error,
    },
    #[error("truncated record at {path} @offset {offset}")]
    Truncated { path: String, offset: u64 },

    #[error("sequence gap at {path}: expected {expected}, found {found}")]
    SeqGap { path: String, expected: u64, found: u64 },

    #[error("prev_hash mismatch at seq {seq} in {path}")]
    PrevHash { path: String, seq: u64 },

    #[error("signature invalid at seq {seq} in {path}")]
    BadSig { path: String, seq: u64 },

    #[error("node_id mismatch inside entry at seq {seq} in {path}")]
    BadNodeId { path: String, seq: u64 },
}

pub struct AuditReader {
    dir: PathBuf,
    vk: VerifyingKey,
    node_id: [u8; 32],
    index: Index,
}

impl AuditReader {
    pub fn open(dir: &Path) -> Result<Self> {
        let pk = fs::read(dir.join(NODE_PK_FILE)).context("read node_pk.bin")?;
        let node_id = {
            let mut arr = [0u8; 32];
            let disk = fs::read(dir.join(NODE_ID_FILE)).context("read node_id.bin")?;
            anyhow::ensure!(disk.len() == 32, "node_id.bin must be 32 bytes");
            arr.copy_from_slice(&disk);
            arr
        };
        let vk = VerifyingKey::from_bytes(&pk.try_into().map_err(|_| anyhow!("bad pk len"))?)
            .context("verifying key")?;
        let index: Index = {
            let p = dir.join(INDEX_FILE);
            if p.exists() {
                serde_json::from_slice(&fs::read(p)?)?
            } else {
                Index::default()
            }
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            vk,
            node_id,
            index,
        })
    }

    pub fn verify(&self) -> std::result::Result<(), VerifyError> {
        // If index missing, accept empty.
        if self.index.segments.is_empty() {
            return Ok(());
        }

        let mut expect_seq: u64 = 1;
        let mut prev_hash: [u8; 32] = [0; 32];

        for seg in &self.index.segments {
            let path = self.dir.join(&seg.path);
            let mut f = OpenOptions::new()
                .read(true)
                .open(&path)
                .map_err(|e| VerifyError::Io {
                    path: path.display().to_string(),
                    offset: 0,
                    source: e,
                })?;

            let mut offset = 0u64;
            loop {
                let len = match read_u32_be(&mut f) {
                    Ok(Some(n)) => n as usize,
                    Ok(None) => break, // EOF exactly at boundary
                    Err(e) => {
                        return Err(VerifyError::Io {
                            path: path.display().to_string(),
                            offset,
                            source: e,
                        })
                    }
                };
                offset += 4;

                let mut buf = vec![0u8; len];
                if let Err(e) = f.read_exact(&mut buf) {
                    return Err(if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        VerifyError::Truncated {
                            path: path.display().to_string(),
                            offset,
                        }
                    } else {
                        VerifyError::Io {
                            path: path.display().to_string(),
                            offset,
                            source: e,
                        }
                    });
                }
                                let wire: EntryWire =
                                    serde_cbor::from_slice(&buf).map_err(|_| VerifyError::Truncated {
                                        path: path.display().to_string(),
                                        offset,
                                    })?;
                                let entry: Entry = wire.try_into().map_err(|_| VerifyError::Truncated {
                                    path: path.display().to_string(),
                                    offset,
                                })?;
                // Seq continuity
                if entry.seq != expect_seq {
                    return Err(VerifyError::SeqGap {
                        path: path.display().to_string(),
                        expected: expect_seq,
                        found: entry.seq,
                    });
                }

                // node_id matches local
                if entry.node_id != self.node_id {
                    return Err(VerifyError::BadNodeId {
                        path: path.display().to_string(),
                        seq: entry.seq,
                    });
                }

                // Prev hash link
                if entry.prev_hash != prev_hash {
                    return Err(VerifyError::PrevHash {
                        path: path.display().to_string(),
                        seq: entry.seq,
                    });
                }

                // Signature over preimage
                let pre = EntryNoSig {
                    seq: entry.seq,
                    ts_monotonic: entry.ts_monotonic,
                    prev_hash: entry.prev_hash,
                    event: &entry.event,
                    node_id: entry.node_id,
                };
                let pre_bytes = canonical_cbor(&pre);
                let h = hash_preimage(&pre_bytes);
                let sig = Signature::from_bytes(&entry.signature);
                if self.vk.verify(&h, &sig).is_err() {
                    return Err(VerifyError::BadSig {
                        path: path.display().to_string(),
                        seq: entry.seq,
                    });
                }

                // Advance
                prev_hash = h;
                expect_seq += 1;
                offset += len as u64;
            }
        }

        Ok(())
    }
}
