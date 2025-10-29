use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBWithThreadMode, IteratorMode, MultiThreaded,
    Options, WriteBatch, WriteOptions,
};
use serde::{Deserialize, Serialize};

use ecac_core::crypto::PublicKeyBytes;
use ecac_core::crypto::{hash_with_domain, OP_HASH_DOMAIN};
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::serialize::canonical_cbor;
use ecac_core::state::State;
//use ecac_core::op::OpHeader;
//use ed25519_dalek::Signature;

type Db = DBWithThreadMode<MultiThreaded>;

const CF_OPS: &str = "ops";
const CF_EDGES: &str = "edges";
const CF_BY_AUTHOR: &str = "by_author";
const CF_VC_RAW: &str = "vc_raw";
const CF_VC_VERIFIED: &str = "vc_verified";
const CF_CHECKPOINTS: &str = "checkpoints";
const CF_META: &str = "meta";

#[derive(Clone)]
pub struct Store {
    db: Arc<Db>,
    sync_writes: bool,
}

#[derive(Clone, Debug)]
pub struct StoreOptions {
    pub create_if_missing: bool,
    pub sync_writes: bool,
}
impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            create_if_missing: true,
            sync_writes: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EdgeVal {
    parents: Vec<OpId>,
    author_pk: [u8; 32],
    hlc_ms: u64,
    hlc_logical: u32,
    hlc_node: u32,
}

#[derive(Serialize, Deserialize)]
struct CheckpointBlob {
    topo_idx: u64,
    state_digest: [u8; 32],
    state_cbor: Vec<u8>,
}

#[inline]
fn default_hlc() -> Hlc {
    Hlc {
        physical_ms: 0,
        logical: 0,
        node_id: 0,
    }
}

#[derive(Deserialize)]
struct OpFlatCompat {
    #[serde(default)]
    parents: Vec<OpId>,
    #[serde(default = "default_hlc")]
    hlc: Hlc,
    author_pk: PublicKeyBytes,
    payload: Payload,
    sig: Vec<u8>,
    op_id: OpId,
}

/// Build the composite by_author key: (author_pk || hlc_ms || hlc_logical || hlc_node || op_id), big-endian for numeric.
#[inline]
fn composite_author_key(
    author_pk: &[u8; 32],
    hlc_ms: u64,
    hlc_logical: u32,
    hlc_node: u32,
    op_id: &[u8; 32],
) -> Vec<u8> {
    let mut k = Vec::with_capacity(32 + 8 + 4 + 4 + 32);
    k.extend_from_slice(author_pk);
    k.extend_from_slice(&hlc_ms.to_be_bytes());
    k.extend_from_slice(&hlc_logical.to_be_bytes());
    k.extend_from_slice(&hlc_node.to_be_bytes());
    k.extend_from_slice(op_id);
    k
}

impl Store {
    /// Try to finalize any orphan ops that now have all parents present:
    /// writes `edges` and `by_author` rows for them in a single batch.
    fn adopt_ready(&self) -> Result<()> {
        use rocksdb::IteratorMode;
        let it = self.db.iterator_cf(&self.cf(CF_OPS), IteratorMode::Start);
        let mut b = WriteBatch::default();
        let mut writes = 0usize;
        for kv in it {
            let (k, v) = kv?;
            // Skip if edges already present
            if self.db.get_cf(&self.cf(CF_EDGES), k.as_ref())?.is_some() {
                continue;
            }
            let op: Op = serde_cbor::from_slice(&v).context("decode Op")?;
            // Require all parents in `ops`
            // if !op
            //     .header
            //     .parents
            //     .iter()
            //     .all(|p| self.db.get_cf(&self.cf(CF_OPS), p)?.is_some())
            // {
            //     continue;
            // }
            // Require all parents in `ops`
let mut missing = false;
for p in &op.header.parents {
    if self.db.get_cf(&self.cf(CF_OPS), p)?.is_none() {
        missing = true;
        break;
    }
}
if missing {
    continue;
}

            let e = EdgeVal {
                parents: op.header.parents.clone(),
                author_pk: op.header.author_pk,
                hlc_ms: op.header.hlc.physical_ms,
                hlc_logical: op.header.hlc.logical,
                hlc_node: op.header.hlc.node_id,
            };
            b.put_cf(&self.cf(CF_EDGES), &op.op_id, &serde_cbor::to_vec(&e)?);
            let k2 =
                composite_author_key(&e.author_pk, e.hlc_ms, e.hlc_logical, e.hlc_node, &op.op_id);
            b.put_cf(&self.cf(CF_BY_AUTHOR), k2, []);
            writes += 1;
        }
        if writes > 0 {
            self.db.write_opt(b, &self.write_opts())?;
        }
        Ok(())
    }
}

impl Store {
    pub fn open(path: &Path, opts: StoreOptions) -> Result<Self> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(opts.create_if_missing);
        db_opts.create_missing_column_families(true);
        db_opts.set_paranoid_checks(true);
        db_opts.set_allow_concurrent_memtable_write(true);
        db_opts.set_bytes_per_sync(1 << 20);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_OPS, Options::default()),
            ColumnFamilyDescriptor::new(CF_EDGES, Options::default()),
            ColumnFamilyDescriptor::new(CF_BY_AUTHOR, Options::default()),
            ColumnFamilyDescriptor::new(CF_VC_RAW, Options::default()),
            ColumnFamilyDescriptor::new(CF_VC_VERIFIED, Options::default()),
            ColumnFamilyDescriptor::new(CF_CHECKPOINTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];
        let db = Db::open_cf_descriptors(&db_opts, path, cfs)?;
        let this = Self {
            db: Arc::new(db),
            sync_writes: opts.sync_writes,
        };
        // Schema guard
        const SCHEMA: &str = "ecac:v1";
        match this.db.get_cf(&this.cf(CF_META), b"schema_version")? {
            Some(v) if v.as_slice() == SCHEMA.as_bytes() => {}
            None => {
                this.put_meta_once("schema_version", SCHEMA.as_bytes())?;
            }
            Some(_) => anyhow::bail!("unknown schema_version; expected {}", SCHEMA),
        }
        // First boot (or after crash) adoption pass to finalize any now-satisfied orphans
        this.adopt_ready()?;
        Ok(this)
    }

    fn write_opts(&self) -> WriteOptions {
        let mut w = WriteOptions::default();
        w.set_sync(self.sync_writes);
        w.disable_wal(false);
        w
    }

    fn cf(&self, name: &str) -> Arc<BoundColumnFamily<'_>> {
        self.db.cf_handle(name).expect("missing column family")
    }

    fn put_meta_once(&self, key: &str, val: &[u8]) -> Result<()> {
        if self.db.get_cf(&self.cf(CF_META), key.as_bytes())?.is_none() {
            let mut b = WriteBatch::default();
            b.put_cf(&self.cf(CF_META), key.as_bytes(), val);
            self.db.write_opt(b, &self.write_opts())?;
        }
        Ok(())
    }

    pub fn has_op(&self, op_id: &[u8; 32]) -> Result<bool> {
        Ok(self.db.get_cf(&self.cf(CF_OPS), op_id)?.is_some())
    }
    pub fn get_op_bytes(&self, op_id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.db.get_cf(&self.cf(CF_OPS), op_id)?)
    }

    /// Store an op given its exact canonical CBOR bytes.
/// Validates: op_id = H(OP_HASH_DOMAIN || canonical_cbor(header)), signature under author_pk.
pub fn put_op_cbor(&self, op_cbor: &[u8]) -> Result<[u8;32]> {
    // Decode as Op; accept legacy flat encoding for compatibility.
    let op: Op = match serde_cbor::from_slice::<Op>(op_cbor) {
        Ok(op) => op,
        Err(_) => {
            let f: OpFlatCompat = serde_cbor::from_slice(op_cbor)
                .map_err(|e| anyhow!("decode Op CBOR: {}", e))?;
            Op {
                header: ecac_core::op::OpHeader {
                    parents: f.parents,
                    hlc: f.hlc,
                    author_pk: f.author_pk,
                    payload: f.payload,
                },
                sig: f.sig,
                op_id: f.op_id,
            }
        }
    };

    // Verify id and signature
    let header_bytes = canonical_cbor(&op.header);
    let expect = hash_with_domain(OP_HASH_DOMAIN, &header_bytes);
    if expect != op.op_id {
        return Err(anyhow!("op_id mismatch (header hash != embedded op_id)"));
    }
    if !op.verify() {
        return Err(anyhow!("invalid signature for op {}", hex::encode(op.op_id)));
    }

    // Parents-present check (no '?' inside an Iterator<bool>!)
    let mut _all_parents_present = true;
    for p in &op.header.parents {
        if self.db.get_cf(&self.cf(CF_OPS), p)?.is_none() {
            _all_parents_present = false;
            break;
        }
    }
    
    // (You can use all_parents_present as a hint if you later choose to gate indexes.)

    // Build edges metadata
    let e = EdgeVal {
        parents: op.header.parents.clone(),
        author_pk: op.header.author_pk,
        hlc_ms: op.header.hlc.physical_ms,
        hlc_logical: op.header.hlc.logical,
        hlc_node: op.header.hlc.node_id,
    };
    let edges_cbor = serde_cbor::to_vec(&e)?;

    // Atomic batch write
    let mut b = WriteBatch::default();
    b.put_cf(&self.cf(CF_OPS), &op.op_id, op_cbor);      // store EXACT bytes provided
    b.put_cf(&self.cf(CF_EDGES), &op.op_id, &edges_cbor);

    // by_author index (kept simple; whether or not parents are present)
    let mut k = Vec::with_capacity(32 + 8 + 4 + 4 + 32);
    k.extend_from_slice(&e.author_pk);
    k.extend_from_slice(&e.hlc_ms.to_be_bytes());
    k.extend_from_slice(&e.hlc_logical.to_be_bytes());
    k.extend_from_slice(&e.hlc_node.to_be_bytes());
    k.extend_from_slice(&op.op_id);
    b.put_cf(&self.cf(CF_BY_AUTHOR), k, []);

    self.db.write_opt(b, &self.write_opts())?;
    Ok(op.op_id)
}


    pub fn topo_ids(&self) -> Result<Vec<[u8; 32]>> {
        // Build indegree and children map for all nodes whose parents are present.
        let iter = self.db.iterator_cf(&self.cf(CF_EDGES), IteratorMode::Start);
        let mut indeg: BTreeMap<[u8; 32], u32> = BTreeMap::new();
        let mut children: BTreeMap<[u8; 32], Vec<[u8; 32]>> = BTreeMap::new();
        let mut meta: BTreeMap<[u8; 32], Hlc> = BTreeMap::new();

        for kv in iter {
            let (k, v) = kv?;
            if k.len() != 32 {
                continue;
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&k);
            let e: EdgeVal = serde_cbor::from_slice(&v)?;
            // decode the referenced op to compare parents for integrity
            let op_bytes = self
                .db
                .get_cf(&self.cf(CF_OPS), k.as_ref())?
                .ok_or_else(|| {
                    anyhow!(
                        "missing op {} while verifying edges",
                        hex::encode(k.as_ref())
                    )
                })?;
            let op: Op =
                serde_cbor::from_slice(&op_bytes).context("decode Op for edges verification")?;
            if e.parents != op.header.parents {
                return Err(anyhow!(
                    "edges parents mismatch for {}",
                    hex::encode(k.as_ref())
                ));
            }
            // Skip nodes referencing missing parents
            let mut missing = false;
            for p in &e.parents {
                if self.db.get_cf(&self.cf(CF_OPS), p)?.is_none() {
                    missing = true;
                    break;
                }
            }
            if missing {
                continue;
            }
            indeg.entry(id).or_default();
            for p in &e.parents {
                *indeg.entry(*p).or_default() += 0;
                *indeg.entry(id).or_default() += 1;
                children.entry(*p).or_default().push(id);
            }
            meta.insert(
                id,
                Hlc {
                    physical_ms: e.hlc_ms,
                    logical: e.hlc_logical,
                    node_id: e.hlc_node,
                },
            );
        }
        // Ready set ordered by (hlc_ms, hlc_logical, hlc_node, op_id)
        let mut ready: BTreeSet<(u64, u32, u32, [u8; 32])> = BTreeSet::new();
        for (id, deg) in &indeg {
            if *deg == 0 {
                let hlc = *meta.get(id).unwrap_or(&Hlc {
                    physical_ms: 0,
                    logical: 0,
                    node_id: 0,
                });
                ready.insert((hlc.physical_ms, hlc.logical, hlc.node_id, *id));
            }
        }
        let mut out = Vec::with_capacity(indeg.len());
        let mut indeg_mut = indeg;
        while let Some(&(ms, lo, node, id)) = ready.iter().next() {
            ready.remove(&(ms, lo, node, id));
            out.push(id);
            if let Some(ch) = children.get(&id) {
                for c in ch {
                    if let Some(d) = indeg_mut.get_mut(c) {
                        if *d > 0 {
                            *d -= 1;
                            if *d == 0 {
                                let h = *meta.get(c).unwrap_or(&Hlc {
                                    physical_ms: 0,
                                    logical: 0,
                                    node_id: 0,
                                });
                                ready.insert((h.physical_ms, h.logical, h.node_id, *c));
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn load_ops_cbor(&self, ids: &[[u8; 32]]) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let v = self
                .db
                .get_cf(&self.cf(CF_OPS), id)?
                .ok_or_else(|| anyhow!("missing op {}", hex::encode(id)))?;
            out.push(v);
        }
        Ok(out)
    }

    pub fn persist_vc_raw(&self, cred_hash: [u8; 32], jwt: &[u8]) -> Result<()> {
        let mut b = WriteBatch::default();
        b.put_cf(&self.cf(CF_VC_RAW), cred_hash, jwt);

        self.db.write_opt(b, &self.write_opts())?;
        Ok(())
    }
    pub fn persist_vc_verified(&self, cred_hash: [u8; 32], verified_cbor: &[u8]) -> Result<()> {
        let mut b = WriteBatch::default();
        b.put_cf(&self.cf(CF_VC_VERIFIED), cred_hash, verified_cbor);
        self.db.write_opt(b, &self.write_opts())?;
        Ok(())
    }

    pub fn checkpoint_create(&self, state: &State, topo_idx: u64) -> Result<u64> {
        let state_cbor = canonical_cbor(state);
        let state_digest = state.digest();
        let blob = CheckpointBlob {
            topo_idx,
            state_digest,
            state_cbor,
        };
        let id = self.next_checkpoint_id()?;
        let mut b = WriteBatch::default();
        b.put_cf(
            &self.cf(CF_CHECKPOINTS),
            &id.to_be_bytes(),
            serde_cbor::to_vec(&blob)?,
        );
        b.put_cf(&self.cf(CF_META), b"last_checkpoint_id", &id.to_be_bytes());
        self.db.write_opt(b, &self.write_opts())?;
        Ok(id)
    }
    pub fn checkpoint_latest(&self) -> Result<Option<(u64, u64)>> {
        if let Some(b) = self.db.get_cf(&self.cf(CF_META), b"last_checkpoint_id")? {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&b);
            let id = u64::from_be_bytes(arr);
            let (_s, topo) = self.checkpoint_load(id)?;
            Ok(Some((id, topo)))
        } else {
            Ok(None)
        }
    }
    pub fn checkpoint_load(&self, id: u64) -> Result<(State, u64)> {
        let b = self
            .db
            .get_cf(&self.cf(CF_CHECKPOINTS), &id.to_be_bytes())?
            .ok_or_else(|| anyhow!("checkpoint {} not found", id))?;
        let blob: CheckpointBlob = serde_cbor::from_slice(&b)?;
        // verify digest
        let st: State = serde_cbor::from_slice(&blob.state_cbor)?;
        anyhow::ensure!(
            st.digest() == blob.state_digest,
            "checkpoint digest mismatch"
        );
        Ok((st, blob.topo_idx))
    }

    pub fn verify_integrity(&self) -> Result<()> {
        // a) every op decodes and verifies id+sig; b) every edges has an op and parents exist; c) topo covers all ops
        let mut ops_count = 0usize;
        let mut edges_count = 0usize;
        let mut missing_parent = 0usize;
        // verify ops
        let it_ops = self.db.iterator_cf(&self.cf(CF_OPS), IteratorMode::Start);
        for kv in it_ops {
            let (k, v) = kv?;
            let op: Op = serde_cbor::from_slice(&v).context("decode Op")?;
            let header = canonical_cbor(&op.header);
            let expect = hash_with_domain(OP_HASH_DOMAIN, &header);
            if expect != op.op_id || &op.op_id[..] != k.as_ref() {
                return Err(anyhow!("op_id mismatch for {}", hex::encode(k.as_ref())));
            }
            if !op.verify() {
                return Err(anyhow!("signature invalid for {}", hex::encode(k.as_ref())));
            }
            ops_count += 1;
        }
        // verify edges mapping and parent presence; also cross-check edges.parents == op.header.parents
        let it_edges = self.db.iterator_cf(&self.cf(CF_EDGES), IteratorMode::Start);
        for kv in it_edges {
            let (k, v) = kv?;
            if self.db.get_cf(&self.cf(CF_OPS), k.as_ref())?.is_none() {
                return Err(anyhow!("edge without op {}", hex::encode(k.as_ref())));
            }
            let e: EdgeVal = serde_cbor::from_slice(&v)?;
            for p in &e.parents {
                if self.db.get_cf(&self.cf(CF_OPS), p)?.is_none() {
                    missing_parent += 1;
                }
            }
            edges_count += 1;
        }
        if missing_parent > 0 {
            return Err(anyhow!("{} missing parent references", missing_parent));
        }
        let topo = self.topo_ids()?;
        anyhow::ensure!(
            topo.len() == ops_count && ops_count == edges_count,
            "topo/ops/edges mismatch"
        );
        Ok(())
    }

    fn next_checkpoint_id(&self) -> Result<u64> {
        if let Some(b) = self.db.get_cf(&self.cf(CF_META), b"last_checkpoint_id")? {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&b);
            Ok(u64::from_be_bytes(arr) + 1)
        } else {
            Ok(1)
        }
    }
}
