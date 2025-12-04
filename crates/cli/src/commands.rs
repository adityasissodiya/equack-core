use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
#[cfg(feature = "audit")]
use ecac_core::audit::{AuditEvent, SkipReason};
#[cfg(feature = "audit")]
use ecac_core::audit_hook::AuditHook;
use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use ed25519_dalek::SigningKey as EdSigningKey;
use serde_json::json;
use std::path::Path;

// emit SkippedOp etc.
use std::time::{SystemTime, UNIX_EPOCH};

use ecac_core::crypto::{derive_enc_aad, encrypt_value, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{CredentialFormat, Op, Payload};
use ecac_core::policy::tags_for;
use ecac_core::replay::{project_field_for_subject, replay_full};
use ecac_core::serialize::canonical_cbor;
use ecac_core::state::FieldValue;
use ecac_core::status::StatusCache;
use ecac_core::trust::TrustStore;
use ecac_core::trustview::TrustView;
use ecac_core::vc::{blake3_hash32, verify_vc, verify_vc_with_trustview};
use ecac_store::Store;
use serde::{Deserialize, Serialize};

// --- local hex helpers (avoid reaching into main.rs) ---
fn to_hex<T: AsRef<[u8]>>(v: T) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let b = v.as_ref();
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        out.push(HEX[(x >> 4) as usize] as char);
        out.push(HEX[(x & 0x0f) as usize] as char);
    }
    out
}
fn to_hex32(v: &[u8; 32]) -> String {
    to_hex(v)
}

fn bytes_to_display(v: &[u8]) -> String {
    match std::str::from_utf8(v) {
        Ok(s) => s.to_string(),
        Err(_) => to_hex(v),
    }
}

fn hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("bad hex")),
    }
}

fn parse_sk_hex(hex: &str) -> Result<SigningKey> {
    let s = hex.trim();
    if s.len() != 64 {
        return Err(anyhow!("expected 64 hex chars for ed25519 secret key"));
    }
    let b = s.as_bytes();
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = (hex_nibble(b[2 * i])? << 4) | hex_nibble(b[2 * i + 1])?;
    }
    Ok(SigningKey::from_bytes(&key))
}

fn parse_pk_hex(hex: &str) -> Result<[u8; 32]> {
    let s = hex.trim();
    if s.len() != 64 {
        return Err(anyhow!("expected 64 hex chars for ed25519 public key"));
    }
    let b = s.as_bytes();
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = (hex_nibble(b[2 * i])? << 4) | hex_nibble(b[2 * i + 1])?;
    }
    Ok(key)
}

fn parse_sha256_hex(hex: &str) -> Result<[u8; 32]> {
    let s = hex.trim();
    if s.len() != 64 {
        return Err(anyhow!("expected 64 hex chars for SHA-256 value"));
    }
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (hex_nibble(b[2 * i])? << 4) | hex_nibble(b[2 * i + 1])?;
    }
    Ok(out)
}

/// Return a reproducible "now" in ms when the caller opts in.
///
/// Precedence:
///   1) ECAC_TIME_MS (explicit fixed value for tests/pipelines)
///   2) SOURCE_DATE_EPOCH (seconds; multiplied by 1000)
///   3) wall-clock `SystemTime::now()` as a last resort.
///
/// M11 pipelines are expected to set ECAC_TIME_MS or SOURCE_DATE_EPOCH
/// so trust/audit timestamps are bitwise-stable across runs.
fn deterministic_now_ms() -> u64 {
    if let Ok(ms_str) = std::env::var("ECAC_TIME_MS") {
        if let Ok(ms) = ms_str.parse::<u64>() {
            return ms;
        }
    }

    if let Ok(sec_str) = std::env::var("SOURCE_DATE_EPOCH") {
        if let Ok(sec) = sec_str.parse::<u64>() {
            return sec.saturating_mul(1000);
        }
    }

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Serialize, Deserialize)]
struct PersistVerifiedVc {
    cred_id: String,
    issuer: String,
    subject_pk: [u8; 32],
    role: String,
    // IMPORTANT: the field name must be `scope` so CBOR matches
    // `VerifiedVcPersist` in ecac-store.
    scope: Vec<String>,
    nbf_ms: u64,
    exp_ms: u64,
    status_list_id: Option<String>,
    status_index: Option<u32>,
    cred_hash: [u8; 32],
}

#[derive(Serialize)]
struct CliIssuerKeyView {
    algo: String,
    valid_from_ms: u64,
    valid_until_ms: u64,
    activated_at_ms: u64,
    revoked_at_ms: Option<u64>,
    pubkey_hex: String,
}

#[derive(Serialize)]
struct CliStatusListView {
    issuer_id: String,
    list_id: String,
    version: u32,
    num_chunks: usize,
    bitset_sha256_hex: String,
    digest_matches: bool,
}

/// Mint a demo VC + trust config:
///   - Generates an issuer Ed25519 keypair.
///   - Generates a subject Ed25519 keypair.
///   - Writes ./trust/issuers.toml with the issuer VK and schema "standard-v1".
///   - Mints a compact JWT VC (alg=EdDSA) that matches crates/core/src/vc.rs expectations.
///   - Writes the VC to ./vc.jwt.
///   - Prints a JSON blob with issuer, issuer_vk_hex, subject_pk_hex and vc_path.
pub fn cmd_vc_mint_demo() -> Result<()> {
    use rand::rngs::OsRng;

    // 1) Generate issuer keypair
    let mut rng = OsRng;
    let issuer_sk = EdSigningKey::generate(&mut rng);
    let issuer_vk = issuer_sk.verifying_key();
    let issuer_vk_bytes = issuer_vk.to_bytes();

    // 2) Generate subject keypair (we only need PK for VC + grants)
    let subject_sk = EdSigningKey::generate(&mut rng);
    let subject_vk = subject_sk.verifying_key();
    let subject_pk_bytes = subject_vk.to_bytes();

    let issuer_vk_hex = to_hex32(&issuer_vk_bytes);
    let subject_pk_hex = to_hex32(&subject_pk_bytes);
    let issuer_id = "local-issuer-1";

    // 3) Write ./trust/issuers.toml so TrustStore::load_from_dir("./trust") works.
    fs::create_dir_all("./trust")?;
    let issuers_toml = format!(
        "[issuers]\n{iss} = \"{vk}\"\n\n[schemas]\n{iss} = \"standard-v1\"\n",
        iss = issuer_id,
        vk = issuer_vk_hex,
    );
    fs::write("./trust/issuers.toml", issuers_toml)?;

    // 4) Build JWT header + payload in the shape vc.rs expects.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let header = json!({
        "alg": "EdDSA",
        "typ": "JWT",
    });

    let payload = json!({
        "iss": issuer_id,
        "jti": format!("demo-vc-{}", now_ms),
        "role": "confidential_reader",
        "sub_pk": subject_pk_hex,
        "nbf": now_ms,
        "exp": now_ms + 86_400_000u64, // +1 day
        "scope": ["confidential"],
        // no "status" => no revocation checks
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    let sig = issuer_sk.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let compact = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);

    // 5) Persist VC to ./vc.jwt
    let vc_path = "vc.jwt";
    fs::write(vc_path, &compact)?;

    // 6) Emit JSON so scripts can grab subject_pk_hex etc.
    let out = json!({
        "issuer": issuer_id,
        "issuer_vk_hex": issuer_vk_hex,
        "subject_pk_hex": subject_pk_hex,
        "vc_path": vc_path,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

pub fn cmd_vc_verify(vc_path: &str) -> Result<()> {
    let compact = fs::read(vc_path)?;

    // DB path via env ECAC_DB or default ".ecac.db"
    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;

    // Prefer in-band trust (IssuerKey / StatusListChunk ops) when available.
    // If no usable TrustView can be built, fall back to filesystem-backed
    // trust (issuers.toml + trust/status/*.bin) for compatibility.
    let v = match build_trustview_from_store(&store) {
        Ok(tv) if !tv.issuer_keys.is_empty() || !tv.status_lists.is_empty() => {
            verify_vc_with_trustview(&compact, &tv)
                .map_err(|e| anyhow!("VC verify failed (in-band trust): {:?}", e))?
        }
        _ => {
            // By convention, look in ./trust and ./trust/status
            let trust = TrustStore::load_from_dir("./trust")
                .map_err(|e| anyhow!("trust load failed: {:?}", e))?;
            let mut status = StatusCache::load_from_dir("./trust/status");
            verify_vc(&compact, &trust, &mut status)
                .map_err(|e| anyhow!("VC verify failed (filesystem trust): {:?}", e))?
        }
    };

    // 1) Raw compact JWT bytes
    store.persist_vc_raw(v.cred_hash, &compact)?;

    // 2) Slim, stable, serde-friendly verified snapshot
    let pv = PersistVerifiedVc {
        cred_id: v.cred_id.clone(),
        issuer: v.issuer.clone(),
        subject_pk: v.subject_pk,
        role: v.role.clone(),
        // keep iteration order identical to store’s VerifiedVcPersist
        scope: v.scope_tags.iter().cloned().collect(),
        nbf_ms: v.nbf_ms,
        exp_ms: v.exp_ms,
        status_list_id: v.status_list_id.clone(),
        status_index: v.status_index,
        cred_hash: v.cred_hash,
    };

    let verified_cbor = serde_cbor::to_vec(&pv)?;
    store.persist_vc_verified(v.cred_hash, &verified_cbor)?;

    let out = json!({
        "cred_id": v.cred_id,
        "issuer": v.issuer,
        "subject_pk_hex": to_hex32(&v.subject_pk),
        "role": v.role,
        "scope": v.scope_tags.iter().collect::<Vec<_>>(),
        "nbf_ms": v.nbf_ms,
        "exp_ms": v.exp_ms,
        "status_list_id": v.status_list_id,
        "status_index": v.status_index,
        "cred_hash_hex": to_hex32(&v.cred_hash),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Build an in-band `TrustView` from the current store contents.
///
/// This replays only the trust-related payloads (IssuerKey / IssuerKeyRevoke /
/// StatusListChunk) via `TrustView::build_from_dag`. Callers typically prefer
/// in-band verification when this succeeds, and fall back to legacy
/// filesystem-backed trust otherwise.
fn build_trustview_from_store(store: &Store) -> Result<TrustView> {
    let ids = store.topo_ids()?;
    if ids.is_empty() {
        return Ok(TrustView::default());
    }

    let blobs = store.load_ops_cbor(&ids)?;
    let mut dag = Dag::new();
    for (i, b) in blobs.into_iter().enumerate() {
        let op: Op = serde_cbor::from_slice(&b)
            .map_err(|e| anyhow!("decode Op {} from store failed: {e}", i))?;
        dag.insert(op);
    }

    Ok(TrustView::build_from_dag(&dag, &ids))
}

pub fn cmd_vc_attach(
    vc_path: &str,
    issuer_sk_hex: &str,
    admin_sk_hex: &str,
    out_dir_opt: Option<&str>,
) -> Result<()> {
    let compact = fs::read(vc_path)?;

    // Verify first (to extract fields & ensure it's valid).
    let trust =
        TrustStore::load_from_dir("./trust").map_err(|e| anyhow!("trust load failed: {:?}", e))?;
    let mut status = StatusCache::load_from_dir("./trust/status");
    let v = verify_vc(&compact, &trust, &mut status)
        .map_err(|e| anyhow!("VC verify failed: {:?}", e))?;

    let cred_hash = blake3_hash32(&compact);

    // Keys
    let issuer_sk = parse_sk_hex(issuer_sk_hex)?;
    let issuer_pk = vk_to_bytes(&issuer_sk.verifying_key());
    let admin_sk = parse_sk_hex(admin_sk_hex)?;
    let admin_pk = vk_to_bytes(&admin_sk.verifying_key());

    // Build ops
    let cred_op = Op::new(
        vec![],
        Hlc::new(v.nbf_ms, 1),
        issuer_pk,
        Payload::Credential {
            cred_id: v.cred_id.clone(),
            cred_bytes: compact.clone(),
            format: CredentialFormat::Jwt,
        },
        &issuer_sk,
    );

    let grant_op = Op::new(
        vec![cred_op.op_id],
        Hlc::new(v.nbf_ms, 2),
        admin_pk,
        Payload::Grant {
            subject_pk: v.subject_pk,
            cred_hash,
        },
        &admin_sk,
    );

    // Write files (ensure dir exists first).
    let out_dir = out_dir_opt.unwrap_or(".");
    let out_dir_path = PathBuf::from(out_dir);
    fs::create_dir_all(&out_dir_path)?;

    let mut p1 = out_dir_path.clone();
    p1.push("cred.op.cbor");
    let mut p2 = out_dir_path.clone();
    p2.push("grant.op.cbor");

    fs::write(&p1, canonical_cbor(&cred_op))?;
    fs::write(&p2, canonical_cbor(&grant_op))?;

    println!("credential_op_id={}", to_hex32(&cred_op.op_id));
    println!("grant_op_id      ={}", to_hex32(&grant_op.op_id));
    println!("cred_hash        ={}", to_hex32(&cred_hash));
    println!("wrote: {} and {}", p1.display(), p2.display());
    Ok(())
}

pub fn cmd_vc_status_set(list_id: &str, index: u32, value: bool) -> Result<()> {
    // Ensure ./trust/status/ exists
    let mut dir = PathBuf::from("./trust/status");
    fs::create_dir_all(&dir)?;
    dir.push(format!("{list_id}.bin"));

    // Read existing bytes (or start empty)
    let mut bytes = match fs::read(&dir) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };

    // Little-endian bit order: byte = index/8, bit = index%8
    let i = (index / 8) as usize;
    let b = (index % 8) as u8;

    if bytes.len() <= i {
        bytes.resize(i + 1, 0);
    }

    if value {
        bytes[i] |= 1u8 << b;
    } else {
        bytes[i] &= !(1u8 << b);
    }

    fs::write(&dir, &bytes)?;
    println!(
        "status {}[{}] = {}",
        list_id,
        index,
        if value { 1 } else { 0 }
    );
    println!("wrote {}", dir.display());
    Ok(())
}

/// Publish an in-band issuer key (IssuerKey op) into the RocksDB store.
///
/// - ECAC_DB selects the store (default ".ecac.db").
/// - The op is signed by `issuer_sk_hex` and authored by that key.
pub fn cmd_trust_issuer_publish(
    issuer_id: &str,
    key_id: &str,
    algo: &str,
    issuer_sk_hex: &str,
    prev_key_id: Option<&str>,
    valid_from_ms: Option<u64>,
    valid_until_ms: Option<u64>,
) -> Result<()> {
    // Parse issuer SK and derive PK.
    let issuer_sk = parse_sk_hex(issuer_sk_hex)?;
    let issuer_pk = vk_to_bytes(&issuer_sk.verifying_key());

    // Open store via ECAC_DB or default ".ecac.db".
    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;

    // Parents from current DAG heads.
    let parents = store.heads(8).unwrap_or_default();

    // Timestamps (M11-friendly).
    let now_ms = deterministic_now_ms();
    let vf = valid_from_ms.unwrap_or(now_ms);
    // Default validity window: +365 days from "now".
    let default_vu = now_ms
        .checked_add(365 * 24 * 60 * 60 * 1000)
        .unwrap_or(u64::MAX);
    let vu = valid_until_ms.unwrap_or(default_vu);
    if vu <= vf {
        return Err(anyhow!(
            "valid_until_ms ({}) must be > valid_from_ms ({})",
            vu,
            vf
        ));
    }

    let op = Op::new(
        parents,
        Hlc::new(now_ms, 1),
        issuer_pk,
        Payload::IssuerKey {
            issuer_id: issuer_id.to_string(),
            key_id: key_id.to_string(),
            algo: algo.to_string(),
            pubkey: issuer_pk.to_vec(),
            prev_key_id: prev_key_id.map(|s| s.to_string()),
            valid_from_ms: vf,
            valid_until_ms: vu,
        },
        &issuer_sk,
    );

    let bytes = canonical_cbor(&op);
    let id = store.put_op_cbor(&bytes)?;

    println!(
        "issuer_key_op_id={} issuer_id={} key_id={}",
        to_hex32(&id),
        issuer_id,
        key_id
    );
    println!("valid_from_ms={} valid_until_ms={}", vf, vu);
    Ok(())
}

/// Publish an IssuerKeyRevoke op into the store to deactivate a key.
///
/// Semantics:
///   - Identifies the key by (issuer_id, key_id).
///   - The revoke point is the op's HLC physical time; from that point
///     onwards in the total order, the key is considered inactive.
///   - The op is authored and signed by `issuer_sk_hex`; in M10 policy,
///     only principals with the appropriate `issuer_admin` authority
///     should be allowed to emit these ops.
///
/// Environment:
///   - ECAC_DB selects the RocksDB store (default ".ecac.db").
pub fn cmd_trust_issuer_revoke(
    issuer_id: &str,
    key_id: &str,
    reason: &str,
    issuer_sk_hex: &str,
) -> Result<()> {
    // Parse issuer SK and derive PK.
    let issuer_sk = parse_sk_hex(issuer_sk_hex)?;
    let issuer_pk = vk_to_bytes(&issuer_sk.verifying_key());

    // Open store via ECAC_DB or default ".ecac.db".
    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;

    // Parents from current DAG heads (same pattern as other trust ops).
    let parents = store.heads(8).unwrap_or_default();

    // Timestamp: M11-friendly ms, logical=1.
    let now_ms = deterministic_now_ms();
    let hlc = Hlc::new(now_ms, 1);

    let op = Op::new(
        parents,
        hlc,
        issuer_pk,
        Payload::IssuerKeyRevoke {
            issuer_id: issuer_id.to_string(),
            key_id: key_id.to_string(),
            reason: reason.to_string(),
        },
        &issuer_sk,
    );

    let bytes = canonical_cbor(&op);
    let id = store.put_op_cbor(&bytes)?;
    println!(
        "issuer_revoke_op_id={} issuer_id={} key_id={} reason={}",
        to_hex32(&id),
        issuer_id,
        key_id,
        reason
    );
    Ok(())
}

/// Publish a single StatusListChunk op into the store.
///
/// The caller must supply the SHA-256 over the COMPLETE bitset (64 hex chars).
pub fn cmd_trust_status_chunk(
    issuer_id: &str,
    list_id: &str,
    version: u32,
    chunk_index: u32,
    chunk_path: &PathBuf,
    issuer_sk_hex: &str,
    bitset_sha256_hex: Option<&str>,
) -> Result<()> {
    let chunk_bytes = fs::read(chunk_path)
        .map_err(|e| anyhow!("failed to read chunk from {}: {e}", chunk_path.display()))?;

    let bitset_sha256 = match bitset_sha256_hex {
        Some(h) => parse_sha256_hex(h)?,
        None => {
            return Err(anyhow!(
                "bitset_sha256_hex not provided; pass --bitset-sha256-hex <64-hex>"
            ));
        }
    };

    let issuer_sk = parse_sk_hex(issuer_sk_hex)?;
    let issuer_pk = vk_to_bytes(&issuer_sk.verifying_key());

    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;

    let parents = store.heads(8).unwrap_or_default();

    let now_ms = deterministic_now_ms();

    let op = Op::new(
        parents,
        Hlc::new(now_ms, 1),
        issuer_pk,
        Payload::StatusListChunk {
            issuer_id: issuer_id.to_string(),
            list_id: list_id.to_string(),
            version,
            chunk_index,
            bitset_sha256,
            chunk_bytes,
        },
        &issuer_sk,
    );

    let bytes = canonical_cbor(&op);
    let id = store.put_op_cbor(&bytes)?;
    println!(
        "status_list_chunk_op_id={} issuer_id={} list_id={} version={} chunk_index={}",
        to_hex32(&id),
        issuer_id,
        list_id,
        version,
        chunk_index
    );
    Ok(())
}

/// Dump the in-band TrustView derived from the RocksDB log.
///
/// - Source: ECAC_DB (default ".ecac.db") as the op store.
/// - Builds a Dag from all ops, runs TrustView::build_from_dag over topo order.
/// - Prints a deterministic JSON summary:
///     * issuers: issuer_id -> key_id -> {algo, validity, activation, revoked_at, pubkey_hex}
///     * status_lists: list_id -> {issuer_id, version, num_chunks, bitset_sha256_hex, digest_matches}
///     * issuers_digest_hex: blake3 over the issuers map (CBOR-encoded)
///     * status_lists_digest_hex: blake3 over the status_lists map (CBOR-encoded)
pub fn cmd_trust_dump() -> Result<()> {
    // Open store via ECAC_DB or default ".ecac.db".
    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;

    // Load ops in deterministic topo order.
    let ids = store.topo_ids()?;
    let blobs = store.load_ops_cbor(&ids)?;

    // Build DAG.
    let mut dag = Dag::new();
    for b in blobs {
        let op: Op = serde_cbor::from_slice(&b)?;
        dag.insert(op);
    }

    // Build TrustView from in-band trust ops.
    let order = dag.topo_sort();
    let tv = TrustView::build_from_dag(&dag, &order);

    // ---- Summarize issuer keys ----
    let mut issuers: BTreeMap<String, BTreeMap<String, CliIssuerKeyView>> = BTreeMap::new();
    for (issuer_id, by_kid) in tv.issuer_keys.iter() {
        let mut keys_map: BTreeMap<String, CliIssuerKeyView> = BTreeMap::new();
        for (kid, rec) in by_kid.iter() {
            keys_map.insert(
                kid.clone(),
                CliIssuerKeyView {
                    algo: rec.algo.clone(),
                    valid_from_ms: rec.valid_from_ms,
                    valid_until_ms: rec.valid_until_ms,
                    activated_at_ms: rec.activated_at_ms,
                    revoked_at_ms: rec.revoked_at_ms,
                    pubkey_hex: to_hex(&rec.pubkey),
                },
            );
        }
        issuers.insert(issuer_id.clone(), keys_map);
    }

    // ---- Summarize status lists ----
    let mut status_lists: BTreeMap<String, CliStatusListView> = BTreeMap::new();
    for (list_id, sl) in tv.status_lists.iter() {
        status_lists.insert(
            list_id.clone(),
            CliStatusListView {
                issuer_id: sl.issuer_id.clone(),
                list_id: sl.list_id.clone(),
                version: sl.version,
                num_chunks: sl.chunks.len(),
                bitset_sha256_hex: to_hex32(&sl.bitset_sha256),
                digest_matches: sl.digest_matches(),
            },
        );
    }

    // ---- Compute digests over the summaries (deterministic) ----
    let issuers_bytes = serde_cbor::to_vec(&issuers)?;
    let issuers_digest = blake3_hash32(&issuers_bytes);

    let status_bytes = serde_cbor::to_vec(&status_lists)?;
    let status_digest = blake3_hash32(&status_bytes);

    // ---- Emit JSON ----
    let out = json!({
        "issuers": issuers,
        "status_lists": status_lists,
        "issuers_digest_hex": to_hex32(&issuers_digest),
        "status_lists_digest_hex": to_hex32(&status_digest),
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Append a single data op into the RocksDB store.
///
/// Arguments:
///   - kind: currently must be "data".
///   - obj, field: logical object and field identifiers.
///   - value: logical value as UTF-8; stored as raw bytes.
///
/// Environment:
///   - ECAC_DB: path to RocksDB directory (defaults to ".ecac.db").
///   - ECAC_SUBJECT_SK_HEX: 32-byte ed25519 secret key (64 hex chars).
///
/// Behaviour:
///   - Builds a M2/M3-style Payload::Data with key = "mv:<obj>:<field>".
///   - If policy::tags_for(obj, field) contains "confidential":
///       * Loads the current key_version and key bytes for tag="confidential"
///         from the keyring (you must have run `keyrotate confidential`).
///       * Encrypts the UTF-8 bytes into EncV1 using AAD derived from the
///         eventual op header: (author_pk, hlc, parents, obj, field).
///  ///   - Otherwise, stores the UTF-8 bytes as plaintext.
pub fn cmd_write(kind: &str, obj: &str, field: &str, value: &str) -> Result<()> {
    // For now we only support "data" writes.
    if kind != "data" {
        return Err(anyhow!(
            "unsupported write kind '{}'; only 'data' is implemented",
            kind
        ));
    }

    // Open store via ECAC_DB or default ".ecac.db".
    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;

    // Writer identity: ECAC_SUBJECT_SK_HEX (32-byte ed25519 SK hex).
    let sk_hex = std::env::var("ECAC_SUBJECT_SK_HEX")
        .map_err(|_| anyhow!("ECAC_SUBJECT_SK_HEX not set (32-byte ed25519 SK hex)"))?;
    let sk = parse_sk_hex(&sk_hex)?;
    let pk = vk_to_bytes(&sk.verifying_key());

    // Parents: current DAG heads (same pattern as keyrotate/grant-key).
    let parents = store.heads(8).unwrap_or_default();

    // HLC: wall-clock ms, logical=1.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let hlc = Hlc::new(now_ms, 1);

    // IMPORTANT:
    // Match policy::derive_action_and_tags:
    //   mv:<obj>:<field>  => Action::SetField
    let key = format!("mv:{}:{}", obj, field);

    // Start from logical UTF-8 bytes.
    let mut val_bytes = value.as_bytes().to_vec();

    // M9: encrypt-on-write for confidential fields.
    //
    // We treat the presence of the static "confidential" resource tag (as
    // returned by policy::tags_for) as the signal that this field must be
    // encrypted under tag="confidential".
    //
    // This does *not* change behaviour for existing fields until you actually
    // add "confidential" to their tag set in policy.rs.
    let tags = tags_for(obj, field);
    let is_confidential = tags.iter().any(|t| t == "confidential");

    if is_confidential {
        let enc_tag = "confidential";

        // Look up the current key_version for this tag.
        let key_version = store.max_key_version_for_tag(enc_tag)?.ok_or_else(|| {
            anyhow!(
                "no key_version for tag='{}'; run `keyrotate {}` first",
                enc_tag,
                enc_tag
            )
        })?;

        // Fetch the actual 32-byte key.
        let key_bytes = store.get_tag_key(enc_tag, key_version)?.ok_or_else(|| {
            anyhow!(
                "missing key material for tag='{}', version={}",
                enc_tag,
                key_version
            )
        })?;

        // AAD = hash(header fields + (obj, field)), matching the decrypt side.
        let aad = derive_enc_aad(
            &pk,
            hlc.physical_ms,
            hlc.logical as u64,
            &parents,
            obj,
            field,
        );

        let enc = encrypt_value(enc_tag, key_version, &key_bytes, &val_bytes, &aad);
        val_bytes = serde_cbor::to_vec(&enc)?;
    }

    let op = Op::new(
        parents,
        hlc,
        pk,
        Payload::Data {
            key,
            value: val_bytes,
        },
        &sk,
    );

    let bytes = canonical_cbor(&op);
    let id = store.put_op_cbor(&bytes)?;

    println!("write_op_id={}", to_hex32(&id));
    println!("obj={} field={}", obj, field);
    Ok(())
}

/// Emit a KeyGrant op bound to (subject_pk, tag, key_version) and backed by a VC.
/// Requirements:
///  - ECAC_DB selects the RocksDB store (default ".ecac.db").
///  - ECAC_KEYADMIN_SK_HEX is the key admin ed25519 SK (32-byte hex).
///  - ./trust and ./trust/status exist and contain issuer + status metadata.
pub fn cmd_grant_key(subject_pk_hex: &str, tag: &str, version: u32, vc_path: &str) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Parse subject public key.
    let subject_pk = parse_pk_hex(subject_pk_hex)?;

    // Open store (for keyring + DAG heads).
    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;

    // Ensure the keyring actually has a key for (tag, version).
    if store.get_tag_key(tag, version)?.is_none() {
        return Err(anyhow!(
            "no key for tag='{}', version={} in keyring; run keyrotate first",
            tag,
            version
        ));
    }

    // Load and verify the VC, extract cred_hash and subject.
    let compact = fs::read(vc_path)?;
    let trust =
        TrustStore::load_from_dir("./trust").map_err(|e| anyhow!("trust load failed: {:?}", e))?;
    let mut status = StatusCache::load_from_dir("./trust/status");
    let v = verify_vc(&compact, &trust, &mut status)
        .map_err(|e| anyhow!("VC verify failed: {:?}", e))?;

    if v.subject_pk != subject_pk {
        return Err(anyhow!(
            "subject_pk_hex does not match VC subject_pk (VC subject is {})",
            to_hex32(&v.subject_pk)
        ));
    }

    let cred_hash = v.cred_hash;

    // Signer for KeyGrant: ECAC_KEYADMIN_SK_HEX
    let admin_sk_hex = std::env::var("ECAC_KEYADMIN_SK_HEX")
        .map_err(|_| anyhow!("ECAC_KEYADMIN_SK_HEX not set (32-byte ed25519 SK hex)"))?;
    let admin_sk = parse_sk_hex(&admin_sk_hex)?;
    let admin_pk = vk_to_bytes(&admin_sk.verifying_key());

    // Parents: current DAG heads.
    let parents = store.heads(8).unwrap_or_default();

    // HLC
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let hlc = Hlc::new(now_ms, 1);

    let op = Op::new(
        parents,
        hlc,
        admin_pk,
        Payload::KeyGrant {
            subject_pk,
            tag: tag.to_string(),
            key_version: version,
            cred_hash,
        },
        &admin_sk,
    );

    let bytes = canonical_cbor(&op);
    let id = store.put_op_cbor(&bytes)?;

    println!("keygrant_op_id={}", to_hex32(&id));
    println!("subject_pk={}", subject_pk_hex);
    println!("tag={} key_version={}", tag, version);
    println!("cred_hash={}", to_hex32(&cred_hash));
    Ok(())
}

/// Rotate the symmetric key for a given tag:
///  - Compute next key_version = max_version(tag) + 1 (or 1 if none).
///  - Derive key bytes from (db_uuid, tag, version) via blake3 for reproducibility.
///  - Store in keyring CF.
///  - Emit a KeyRotate op signed by ECAC_KEYADMIN_SK_HEX.
pub fn cmd_keyrotate(tag: &str) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Open store via ECAC_DB or default ".ecac.db"
    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;

    // Compute next key_version for this tag.
    let next_version = match store.max_key_version_for_tag(tag)? {
        Some(cur) => cur
            .checked_add(1)
            .ok_or_else(|| anyhow!("key_version overflow"))?,
        None => 1,
    };

    // Derive a 32-byte key from (db_uuid, tag, version) using blake3.
    // This is deterministic per-DB but looks random and is fine for tests/eval.
    let db_uuid = store.db_uuid()?;
    let mut buf = Vec::new();
    buf.extend_from_slice(&db_uuid);
    buf.extend_from_slice(tag.as_bytes());
    buf.extend_from_slice(&next_version.to_be_bytes());
    let key = blake3_hash32(&buf);

    // Persist in keyring.
    store.put_tag_key(tag, next_version, &key)?;

    // Signer for KeyRotate: ECAC_KEYADMIN_SK_HEX
    let admin_sk_hex = std::env::var("ECAC_KEYADMIN_SK_HEX")
        .map_err(|_| anyhow!("ECAC_KEYADMIN_SK_HEX not set (32-byte ed25519 SK hex)"))?;
    let admin_sk = parse_sk_hex(&admin_sk_hex)?;
    let admin_pk = vk_to_bytes(&admin_sk.verifying_key());

    // Use current DAG heads as parents where possible.
    let parents = store.heads(8).unwrap_or_default();

    // HLC: use wall-clock ms, logical=1.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let hlc = Hlc::new(now_ms, 1);

    let op = Op::new(
        parents,
        hlc,
        admin_pk,
        Payload::KeyRotate {
            tag: tag.to_string(),
            new_version: next_version,
            new_key: key.to_vec(),
        },
        &admin_sk,
    );

    let bytes = canonical_cbor(&op);
    let id = store.put_op_cbor(&bytes)?;

    println!("tag={} new_version={}", tag, next_version);
    println!("keyrotate_op_id={}", to_hex32(&id));
    Ok(())
}

#[cfg(feature = "audit")]
pub fn cmd_op_append_audited(db_path: &Path, files: Vec<PathBuf>) -> Result<()> {
    use ecac_store::Store;
    let store = Store::open(db_path, Default::default())?;
    // open default audit sink (respects ECAC_NODE_SK_HEX and ECAC_AUDIT_DIR or <db>/audit)
    let Some(mut sink) = crate::commands::open_audit_sink_default()? else {
        return Err(anyhow::anyhow!(
            "audit sink unavailable: set ECAC_NODE_SK_HEX"
        ));
    };
    for f in files {
        let ops = super::read_ops_cbor(&f)?; // same tolerant reader
        for op in ops {
            let bytes = ecac_core::serialize::canonical_cbor(&op);
            match store.put_op_cbor(&bytes) {
                Ok(id) => eprintln!("appended {}", to_hex32(&id)),
                Err(e) => {
                    // If signature verification failed, log SkippedOp{InvalidSig}
                    // (topo_idx is 0 here; it’s an ingest-time rejection, not part of DAG)
                    let op_id = op.op_id;
                    let reason = SkipReason::InvalidSig;
                    let ev = AuditEvent::SkippedOp {
                        op_id,
                        topo_idx: 0,
                        reason,
                    };
                    sink.on_event(ev);
                    eprintln!("append failed for {}: {e}", to_hex32(&op_id));
                }
            }
        }
    }
    Ok(())
}
// crates/cli/src/commands.rs

#[cfg(feature = "audit")]
pub fn open_audit_sink_default() -> anyhow::Result<Option<ecac_store::StoreAuditHook>> {
    match ecac_store::StoreAuditHook::open_default() {
        Ok(h) => Ok(Some(h)),
        Err(e) => {
            eprintln!("audit: disabled (failed to open default sink: {e})");
            Ok(None)
        }
    }
}

#[cfg(not(feature = "audit"))]
#[allow(dead_code)]
pub fn open_audit_sink_default() -> anyhow::Result<Option<()>> {
    Ok(None)
}

// in crates/cli/src/commands.rs (or a new file)
#[cfg(feature = "audit")]
struct MemAudit(pub Vec<ecac_core::audit::AuditEvent>);

#[cfg(feature = "audit")]
impl ecac_core::audit_hook::AuditHook for MemAudit {
    fn on_event(&mut self, e: ecac_core::audit::AuditEvent) {
        self.0.push(e);
    }
}

// ===== Audit CLI helpers =====

#[cfg(feature = "audit")]
use ecac_store::audit::AuditReader;
#[cfg(feature = "audit")]
use std::io::Read; // fs, Path, Result, Deserialize, Serialize are already imported above

// --- shared local types to read the on-disk audit index/segments ---

#[cfg(feature = "audit")]
#[derive(Deserialize)]
struct CliIndex {
    segments: Vec<CliIndexSeg>,
}

#[cfg(feature = "audit")]
#[derive(Deserialize)]
struct CliIndexSeg {
    // relative path of segment (e.g., "segment-00000001.log")
    path: String,
    // the rest are ignored by the CLI but present in the index file
    #[allow(dead_code)]
    segment_id: Option<u32>,
    #[allow(dead_code)]
    first_seq: Option<u64>,
    #[allow(dead_code)]
    last_seq: Option<u64>,
    #[allow(dead_code)]
    first_hash: Option<[u8; 32]>,
    #[allow(dead_code)]
    last_hash: Option<[u8; 32]>,
}

#[cfg(feature = "audit")]
#[derive(Deserialize, Serialize)]
struct EntryWireCli {
    seq: u64,
    ts_monotonic: u64,
    prev_hash: [u8; 32],
    event: AuditEvent,
    node_id: [u8; 32],
    signature: Vec<u8>,
}

#[cfg(feature = "audit")]
fn read_u32_be(r: &mut impl Read) -> std::io::Result<Option<u32>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => Ok(Some(u32::from_be_bytes(len))),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(feature = "audit")]
fn hex32(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

// ---- audit-verify (chain only) ----

#[cfg(feature = "audit")]
pub fn cmd_audit_verify(dir_opt: Option<&str>) -> Result<()> {
    let dir = dir_opt.unwrap_or(".audit");
    let r = AuditReader::open(Path::new(dir))?;
    r.verify().map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("OK: audit chain verified at {dir}");
    Ok(())
}

// ---- audit-export ----
// Deterministic JSONL: one JSON object per line, stable field order.
// We first verify the chain; if it passes, we stream decode each segment.

#[cfg(feature = "audit")]
pub fn cmd_audit_export(dir_opt: Option<&str>, out_path_opt: Option<&str>) -> Result<()> {
    let dir = dir_opt.unwrap_or(".audit");
    let out_path = out_path_opt.unwrap_or("audit.jsonl");

    // 1) Integrity check.
    let r = AuditReader::open(Path::new(dir))?;
    r.verify().map_err(|e| anyhow::anyhow!("{e}"))?;

    // 2) Load index and iterate segments in order.
    let index_bytes = fs::read(Path::new(dir).join("index.json"))?;
    let index: CliIndex = serde_json::from_slice(&index_bytes)?;

    let mut out = std::fs::File::create(out_path)?;

    for seg in index.segments {
        let path = Path::new(dir).join(seg.path);
        let mut f = std::fs::File::open(&path)?;
        loop {
            let len = match read_u32_be(&mut f)? {
                Some(n) => n as usize,
                None => break, // EOF at boundary
            };
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf)?;
            let entry: EntryWireCli = serde_cbor::from_slice(&buf)
                .map_err(|e| anyhow::anyhow!("CBOR decode failed in {:?}: {e}", path))?;

            // Build a stable export record (byte arrays → hex)
            #[derive(Serialize)]
            struct Jsonl<'a> {
                seq: u64,
                ts_monotonic: u64,
                prev_hash_hex: String,
                node_id_hex: String,
                #[serde(borrow)]
                event: &'a AuditEvent,
                signature_hex: String,
            }
            let j = Jsonl {
                seq: entry.seq,
                ts_monotonic: entry.ts_monotonic,
                prev_hash_hex: hex32(&entry.prev_hash),
                node_id_hex: hex32(&entry.node_id),
                event: &entry.event,
                signature_hex: hex32(&entry.signature),
            };

            serde_json::to_writer(&mut out, &j)?;
            // newline-delimited
            use std::io::Write as _;
            out.write_all(b"\n")?;
        }
    }

    println!("wrote deterministic JSONL to {}", out_path);
    Ok(())
}

// ---- audit-cat ----
// Dump decoded entries (pretty JSON) from either the whole log or a single segment.

#[cfg(feature = "audit")]
pub fn cmd_audit_cat(dir_opt: Option<&str>, segment_opt: Option<&str>) -> Result<()> {
    let dir = dir_opt.unwrap_or(".audit");

    let segments: Vec<String> = if let Some(seg_name) = segment_opt {
        vec![seg_name.to_string()]
    } else {
        let idx = fs::read(Path::new(dir).join("index.json"))?;
        let index: CliIndex = serde_json::from_slice(&idx)?;
        index.segments.into_iter().map(|s| s.path).collect()
    };

    for seg in segments {
        let path = Path::new(dir).join(&seg);
        println!("=== {} ===", path.display());
        let mut f = std::fs::File::open(&path)?;
        let mut _offset: u64 = 0;
        loop {
            let len = match read_u32_be(&mut f)? {
                Some(n) => n as usize,
                None => break,
            };
            _offset += 4;
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf)?;
            let entry: EntryWireCli = serde_cbor::from_slice(&buf)?;
            println!(
                "{{\"seq\":{},\"ts_monotonic\":{},\"prev_hash\":\"{}\",\"node_id\":\"{}\",\"event\":{},\"signature\":\"{}\"}}",
                entry.seq,
                entry.ts_monotonic,
                hex32(&entry.prev_hash),
                hex32(&entry.node_id),
                serde_json::to_string(&entry.event)?,
                hex32(&entry.signature),
            );
            _offset += len as u64;
        }
    }
    Ok(())
}

// ---- helpers: corrupt-sig and make-orphan -----------------------------------

/// Load Op or Vec<Op> from CBOR (compat: also Vec<OpFlatCompat>).
fn load_ops_any(p: &Path) -> Result<Vec<Op>> {
    let data = fs::read(p)?;
    if let Ok(v) = serde_cbor::from_slice::<Vec<Op>>(&data) {
        return Ok(v);
    }
    if let Ok(op) = serde_cbor::from_slice::<Op>(&data) {
        return Ok(vec![op]);
    }
    // Compat path: older flat format
    if let Ok(vf) = serde_cbor::from_slice::<Vec<crate::OpFlatCompat>>(&data) {
        let out = vf
            .into_iter()
            .map(|f| Op {
                header: ecac_core::op::OpHeader {
                    parents: f.parents,
                    hlc: f.hlc,
                    author_pk: f.author_pk,
                    payload: f.payload,
                },
                sig: f.sig,
                op_id: f.op_id,
            })
            .collect();
        return Ok(out);
    }
    if let Ok(f) = serde_cbor::from_slice::<crate::OpFlatCompat>(&data) {
        let op = Op {
            header: ecac_core::op::OpHeader {
                parents: f.parents,
                hlc: f.hlc,
                author_pk: f.author_pk,
                payload: f.payload,
            },
            sig: f.sig,
            op_id: f.op_id,
        };
        return Ok(vec![op]);
    }
    Err(anyhow!("{}: not an Op/Vec<Op> CBOR", p.display()))
}

#[allow(dead_code)]
fn save_ops_vec(p: &Path, ops: &[Op]) -> Result<()> {
    // Some serde_cbor versions require a Sized value; wrap the slice as Vec<Op>.
    // This keeps encoding stable and avoids the `[Op]` unsized error.
    let bytes = serde_cbor::to_vec(&ops.to_vec())?;
    fs::write(p, bytes)?;
    Ok(())
}

/// Flip one bit in the first signature to force verify failure.
pub fn cmd_op_corrupt_sig(input: &str, output: &str) -> Result<()> {
    let in_path = Path::new(input);
    let mut ops = load_ops_any(in_path)?;
    if ops.is_empty() {
        return Err(anyhow!("no ops in {}", input));
    }
    for op in &mut ops {
        if op.sig.is_empty() {
            op.sig = vec![0x00];
        } else {
            op.sig[0] ^= 0x01;
        }
    }
    // Keep structure; write as Vec<Op> to avoid ambiguity
    save_ops_vec(Path::new(output), &ops)?;
    eprintln!("wrote corrupted signatures to {}", output);
    Ok(())
}

/// Append a new op cloned from last payload but with a bogus parent; sign with provided SK.
pub fn cmd_op_make_orphan(base: &str, author_sk_hex: &str, output: &str) -> Result<()> {
    let base_path = Path::new(base);
    let mut ops = load_ops_any(base_path)?;
    if ops.is_empty() {
        return Err(anyhow!("no ops in {}", base));
    }
    let tmpl = ops.last().unwrap().clone();
    let sk = parse_sk_hex(author_sk_hex)?; // function lives in this module
    let author_pk = vk_to_bytes(&sk.verifying_key());
    // All-zeros parent id is guaranteed missing in normal runs.
    let bogus_parent = [0u8; 32];
    // HLC: bump physical by 1ms to keep monotonic.
    let hlc = {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // Keep it deterministic-ish relative to tmpl if clock jumps
        let phys = std::cmp::max(now_ms, tmpl.header.hlc.physical_ms + 1);
        Hlc::new(phys, tmpl.header.hlc.logical)
    };
    let new_op = Op::new(
        vec![bogus_parent],
        hlc,
        author_pk,
        tmpl.header.payload.clone(),
        &sk,
    );
    ops.push(new_op);
    save_ops_vec(Path::new(output), &ops)?;
    eprintln!("appended orphan op → {}", output);
    Ok(())
}

// Mint a minimal, valid single Credential op and write as a one-element Vec<Op> CBOR.
pub fn cmd_op_make_min(author_sk_hex: &str, output: &str) -> Result<()> {
    let sk = parse_sk_hex(author_sk_hex)?;
    let pk = vk_to_bytes(&sk.verifying_key());
    // Minimal credential payload; contents don't matter for signature tests.
    let op = Op::new(
        vec![],         // no parents
        Hlc::new(0, 1), // deterministic HLC
        pk,
        Payload::Credential {
            cred_id: "min-cred".to_string(),
            cred_bytes: vec![1, 2, 3],     // dummy bytes
            format: CredentialFormat::Jwt, // <-- missing field
        },
        &sk,
    );
    // Reuse the stable writer (writes a Vec<Op>)
    save_ops_vec(Path::new(output), &[op])?;
    eprintln!("wrote minimal op to {}", output);
    Ok(())
}

/// Write a minimal Credential + Grant pair into a directory.
/// Files: <out_dir>/cred.op.cbor and <out_dir>/grant.op.cbor
pub fn cmd_op_make_grant(author_sk_hex: &str, admin_sk_hex: &str, out_dir: &Path) -> Result<()> {
    use std::time::{SystemTime, UNIX_EPOCH};

    fs::create_dir_all(out_dir)?;

    // Keys
    let issuer_sk = parse_sk_hex(author_sk_hex)?;
    let issuer_pk = vk_to_bytes(&issuer_sk.verifying_key());
    let admin_sk = parse_sk_hex(admin_sk_hex)?;
    let admin_pk = vk_to_bytes(&admin_sk.verifying_key());

    // Minimal, deterministic-ish timestamps (ms). Use now for readability.
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Minimal credential bytes (doesn't need to be a real JWT for plumbing tests)
    let cred_bytes = b"m8-test-credential".to_vec();
    let cred_hash = blake3_hash32(&cred_bytes);

    // 1) Credential op signed by issuer
    let cred_op = Op::new(
        vec![],
        Hlc::new(now_ms, 1),
        issuer_pk,
        Payload::Credential {
            cred_id: "m8:test:cred".to_string(),
            cred_bytes: cred_bytes.clone(),
            format: CredentialFormat::Jwt,
        },
        &issuer_sk,
    );

    // 2) Grant op signed by admin, points at the credential's hash
    //    For subject_pk, use issuer_pk to keep it self-contained.
    let grant_op = Op::new(
        vec![cred_op.op_id],
        Hlc::new(now_ms, 2),
        admin_pk,
        Payload::Grant {
            subject_pk: issuer_pk,
            cred_hash,
        },
        &admin_sk,
    );

    fs::write(out_dir.join("cred.op.cbor"), canonical_cbor(&cred_op))?;
    fs::write(out_dir.join("grant.op.cbor"), canonical_cbor(&grant_op))?;

    println!("credential_op_id={}", to_hex32(&cred_op.op_id));
    println!("grant_op_id      ={}", to_hex32(&grant_op.op_id));
    println!("cred_hash        ={}", to_hex32(&cred_hash));
    println!(
        "wrote: {} and {}",
        out_dir.join("cred.op.cbor").display(),
        out_dir.join("grant.op.cbor").display()
    );
    Ok(())
}

// ---- audit-verify-full (chain + replay cross-check) ----
// Dag, Op and Store are already imported at the top of this module.

// Replay the store and WRITE decision events to the on-disk audit sink.
// Uses the default sink (respects ECAC_NODE_SK_HEX, writes to .audit).
#[cfg(feature = "audit")]
pub fn cmd_audit_record(db_dir_opt: Option<&str>) -> Result<()> {
    use anyhow::Context;
    let db_dir = db_dir_opt.unwrap_or(".ecac.db");
    let store = Store::open(Path::new(db_dir), Default::default())
        .with_context(|| format!("open store at {}", db_dir))?;
    let ids = store.topo_ids().context("load topo ids")?;
    let blobs = store.load_ops_cbor(&ids).context("load ops cbor")?;

    let mut dag = Dag::default();
    for bytes in blobs {
        let op: Op = serde_cbor::from_slice(&bytes).context("decode Op from store")?;
        dag.insert(op);
    }

    // Open default audit sink (creates .audit/*, requires ECAC_NODE_SK_HEX).
    let Some(mut sink) = open_audit_sink_default()? else {
        return Err(anyhow::anyhow!(
            "audit sink unavailable: set ECAC_NODE_SK_HEX (64 hex) and ensure .audit is writable"
        ));
    };

    let (_state, _digest) = ecac_core::replay::replay_full_with_audit(&dag, &mut sink);
    println!("OK: wrote decision events to the audit sink");
    Ok(())
}
/// Verify audit chain integrity and cross-check replay decisions against the on-disk audit.
/// Order of audit dir selection:
///  1) If ECAC_AUDIT_DIR is set, use it (must contain index.json and node_pk.bin)
///  2) <db_dir>/audit
///  3) .audit
/// If `db_dir_opt` is None, <db_dir> defaults to ".ecac.db".

#[cfg(feature = "audit")]
pub fn cmd_audit_verify_full(db_dir_opt: Option<&str>) -> Result<()> {
    use anyhow::Context;
    use std::io::Read as _;

    let db_dir = db_dir_opt.unwrap_or(".ecac.db");
    // 0) ECAC_AUDIT_DIR override
    let audit_dir: PathBuf = if let Ok(env_dir) = std::env::var("ECAC_AUDIT_DIR") {
        let p = PathBuf::from(env_dir);
        if p.join("index.json").exists() && p.join("node_pk.bin").exists() {
            eprintln!("audit: using ECAC_AUDIT_DIR={}", p.display());
            p
        } else {
            return Err(anyhow::anyhow!(
                "ECAC_AUDIT_DIR='{}' is not a valid audit dir (missing index.json/node_pk.bin)",
                p.display()
            ));
        }
    } else {
        // 1) Prefer <db>/audit; if missing/incomplete, fall back to .audit with a note.
        let primary = Path::new(db_dir).join("audit");
        let fallback = Path::new(".audit");
        if primary.join("index.json").exists() && primary.join("node_pk.bin").exists() {
            primary
        } else if fallback.join("index.json").exists() && fallback.join("node_pk.bin").exists() {
            eprintln!(
                "audit: '{}' missing or incomplete; falling back to {}",
                Path::new(db_dir).join("audit").display(),
                fallback.display()
            );
            fallback.to_path_buf()
        } else {
            return Err(anyhow::anyhow!(
                "no audit log found in '{}' or '{}'",
                Path::new(db_dir).join("audit").display(),
                fallback.display()
            ));
        }
    };

    // 1) Chain integrity.
    let r = AuditReader::open(&audit_dir)?;
    r.verify().map_err(|e| anyhow::anyhow!("{e}"))?;
    eprintln!("audit: chain OK at {}", audit_dir.display());

    // 2) Rebuild DAG from store (parent-first topo IDs) and replay with in-memory audit.
    let store = Store::open(Path::new(db_dir), Default::default())
        .with_context(|| format!("open store at {}", db_dir))?;
    let ids = store.topo_ids().context("load topo ids")?;
    let blobs = store.load_ops_cbor(&ids).context("load ops cbor")?;

    let mut dag = Dag::default();
    for bytes in blobs {
        let op: Op = serde_cbor::from_slice(&bytes).context("decode Op from store")?;
        // If your Dag uses a different API, change this to the right call.
        dag.insert(op);
    }

    let mut mem = MemAudit(Vec::new());
    let (_state, _digest) = ecac_core::replay::replay_full_with_audit(&dag, &mut mem);

    // 3) Stream the on-disk audit decisions.
    let index_bytes = fs::read(audit_dir.join("index.json"))?;
    let index: CliIndex = serde_json::from_slice(&index_bytes)?;
    let mut disk_events: Vec<AuditEvent> = Vec::new();
    for seg in &index.segments {
        let p = audit_dir.join(&seg.path);
        let mut f =
            std::fs::File::open(&p).with_context(|| format!("open segment {}", p.display()))?;
        loop {
            let len = match read_u32_be(&mut f)? {
                Some(n) => n as usize,
                None => break,
            };
            let mut buf = vec![0u8; len];
            f.read_exact(&mut buf)?;
            let entry: EntryWireCli = serde_cbor::from_slice(&buf)
                .with_context(|| format!("decode CBOR in {}", p.display()))?;
            disk_events.push(entry.event);
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    enum Dec {
        Applied {
            op: [u8; 32],
            topo: u64,
            why: &'static str,
        },
        Skipped {
            op: [u8; 32],
            topo: u64,
            why: &'static str,
        },
    }
    fn extract(v: &[AuditEvent]) -> Vec<Dec> {
        use ecac_core::audit::{AppliedReason, SkipReason};
        let mut out = Vec::new();
        for e in v {
            match e {
                AuditEvent::AppliedOp {
                    op_id,
                    topo_idx,
                    reason,
                } => {
                    let why = match reason {
                        AppliedReason::Authorized => "authorized",
                    };
                    out.push(Dec::Applied {
                        op: *op_id,
                        topo: *topo_idx,
                        why,
                    });
                }
                AuditEvent::SkippedOp {
                    op_id,
                    topo_idx,
                    reason,
                } => {
                    let why = match reason {
                        SkipReason::DenyWins => "deny_wins",
                        SkipReason::InvalidSig => "invalid_sig",
                        SkipReason::BadParent => "bad_parent",
                        SkipReason::RevokedCred => "revoked_cred",
                        SkipReason::ExpiredCred => "expired_cred",
                        SkipReason::OutOfScope => "out_of_scope",
                    };
                    out.push(Dec::Skipped {
                        op: *op_id,
                        topo: *topo_idx,
                        why,
                    });
                }
                _ => {}
            }
        }
        out.sort();
        out
    }

    let want = extract(&mem.0);
    let have = extract(&disk_events);
    if want == have {
        println!("OK: replay decisions match audit ({} entries)", want.len());
        return Ok(());
    }

    // Show first mismatch and per-reason counts to debug fast.
    let n = want.len().max(have.len());
    for i in 0..n {
        match (want.get(i), have.get(i)) {
            (Some(a), Some(b)) if a == b => continue,
            (Some(a), Some(b)) => {
                eprintln!("mismatch @ {}:\n  replay: {:?}\n  audit : {:?}", i, a, b);
                break;
            }
            (Some(a), None) => {
                eprintln!("extra in replay @ {}: {:?}", i, a);
                break;
            }
            (None, Some(b)) => {
                eprintln!("missing in replay @ {}: {:?}", i, b);
                break;
            }
            _ => unreachable!(),
        }
    }
    use std::collections::BTreeMap;
    let sum = |src: &[Dec]| -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for d in src {
            match d {
                Dec::Applied { why, .. } | Dec::Skipped { why, .. } => {
                    *m.entry(*why).or_default() += 1;
                }
            }
        }
        m
    };
    eprintln!("replay summary: {:?}", sum(&want));
    eprintln!("audit  summary: {:?}", sum(&have));
    Err(anyhow::anyhow!("audit decisions diverge"))
}

// ---- M9 CLI: show logical field value with key/VC gating --------------------

/// Show the logical value of <obj>.<field> as visible to a given subject.
///
/// Source of truth:
///   - Ops: RocksDB store selected via ECAC_DB or default ".ecac.db".
///   - Keys: keyring CF in the same store.
///   - Grants: KeyGrant ops in the log.
///
/// Behaviour:
///   - If the winning value is plaintext, we print it (UTF-8 or hex).
///   - If the winning value is EncV1, we only decrypt if:
///       * there is a KeyGrant(subject_pk, tag, key_version), AND
///       * the keyring has a key for (tag, key_version), AND
///       * decryption with AAD derived from the op header and logical location
///         (author_pk, hlc, parents, obj, field) via `derive_enc_aad` succeeds.
///   - Otherwise we print "<redacted>".
pub fn cmd_show(obj: &str, field: &str, subject_pk_hex: &str) -> Result<()> {
    // Parse subject PK.
    let subject_pk = parse_pk_hex(subject_pk_hex)?;

    // Open store and load all ops in topo order.
    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;
    let ids = store.topo_ids()?;
    let blobs = store.load_ops_cbor(&ids)?;

    // Build DAG.
    let mut dag = Dag::new();
    for b in blobs {
        let op: Op = serde_cbor::from_slice(&b)?;
        dag.insert(op);
    }

    // Deterministic replay (write policy enforcement in core).
    let (state, _digest) = replay_full(&dag);

    // Resolve field early for error messages and to handle Set separately.
    let Some(fields) = state.objects.get(obj) else {
        println!(r#"{{"error":"object not found","obj":"{}"}}"#, obj);
        return Ok(());
    };
    let Some(fv) = fields.get(field) else {
        println!(
            r#"{{"error":"field not found","obj":"{}","field":"{}"}}"#,
            obj, field
        );
        return Ok(());
    };

    match fv {
        FieldValue::MV(_mv) => {
            // Key lookup closure: (tag, version) -> key bytes from keyring.
            let store_ref = &store;
            let visible = project_field_for_subject(
                &dag,
                &state,
                &subject_pk,
                |tag, ver| match store_ref.get_tag_key(tag, ver) {
                    Ok(Some(k)) => Some(k),
                    _ => None,
                },
                obj,
                field,
            );

            if let Some(v) = visible {
                println!("{}", v);
            } else {
                println!("\"<redacted>\"");
            }
        }
        FieldValue::Set(set) => {
            // Sets are not M9-encrypted; reuse the old deterministic projection.
            let mut elems = Vec::new();
            for (ek, v) in set.iter_present() {
                elems.push(format!(r#"{{"key":"{}","value":"{}"}}"#, ek, to_hex(&v)));
            }
            println!("[{}]", elems.join(","));
        }
    }

    Ok(())
}
