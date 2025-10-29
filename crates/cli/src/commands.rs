use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use serde_json::json;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::hlc::Hlc;
use ecac_core::op::{CredentialFormat, Op, Payload};
use ecac_core::serialize::canonical_cbor;
use ecac_core::status::StatusCache;
use ecac_core::trust::TrustStore;
use ecac_core::vc::{blake3_hash32, verify_vc};
use std::path::Path;
use ecac_store::Store;
use serde::{Serialize, Deserialize};

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

fn to_hex32(arr: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in arr {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[derive(Serialize, Deserialize)]
struct PersistVerifiedVc {
    cred_id: String,
    issuer: String,
    subject_pk: [u8; 32],
    role: String,
    scope_tags: Vec<String>,
    nbf_ms: u64,
    exp_ms: u64,
    status_list_id: Option<String>, // <-- was String
    status_index: Option<u32>,      // <-- was u32
    cred_hash: [u8; 32],
}


pub fn cmd_vc_verify(vc_path: &str) -> Result<()> {
    let compact = fs::read(vc_path)?;
    // By convention, look in ./trust and ./trust/status
    let trust =
        TrustStore::load_from_dir("./trust").map_err(|e| anyhow!("trust load failed: {:?}", e))?;
    let mut status = StatusCache::load_from_dir("./trust/status");

    let v = verify_vc(&compact, &trust, &mut status)
        .map_err(|e| anyhow!("VC verify failed: {:?}", e))?;

//         // Persist VC caches (M5: avoid re-verification on boot)
// {
//     // Allow override via env; falls back to ".ecac.db"
//     let db_dir = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
//     let store = Store::open(Path::new(&db_dir), Default::default())?;

//     // Raw compact JWT bytes
//     store.persist_vc_raw(v.cred_hash, &compact)?;

//     // Verified struct, as CBOR
//     let verified_cbor = serde_cbor::to_vec(&v)?;
//     store.persist_vc_verified(v.cred_hash, &verified_cbor)?;
// }

    // ---- Persist VC caches (optional but sensible) ----
    // DB path via env ECAC_DB or default ".ecac.db"
    let db_path = std::env::var("ECAC_DB").unwrap_or_else(|_| ".ecac.db".to_string());
    let store = Store::open(Path::new(&db_path), Default::default())?;

    // 1) Raw compact JWT bytes
    store.persist_vc_raw(v.cred_hash, &compact)?;

    // 2) Slim, stable, serde-friendly verified snapshot
    let pv = PersistVerifiedVc {
        cred_id: v.cred_id.clone(),
        issuer: v.issuer.clone(),
        subject_pk: v.subject_pk,
        role: v.role.clone(),
        scope_tags: v.scope_tags.iter().cloned().collect(),
        nbf_ms: v.nbf_ms,
        exp_ms: v.exp_ms,
        status_list_id: v.status_list_id.clone(), // now matches Option<String>
        status_index: v.status_index,             // now matches Option<u32>
        cred_hash: v.cred_hash,
    };
        
    let verified_cbor = serde_cbor::to_vec(&pv)?;
    store.persist_vc_verified(v.cred_hash, &verified_cbor)?;
    // ---------------------------------------------------

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
    println!("status {}[{}] = {}", list_id, index, if value { 1 } else { 0 });
    println!("wrote {}", dir.display());
    Ok(())
}