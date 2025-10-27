use std::{env, fs, path::PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use ecac_core::crypto::vk_to_bytes;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::serialize::canonical_cbor;

// --- tiny hex helpers (same style as other examples) ---
fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("bad hex".into()),
    }
}
fn parse_sk_hex(hex: &str) -> Result<SigningKey, String> {
    let s = hex.trim();
    if s.len() != 64 { return Err("expected 64 hex chars for ed25519 secret key".into()); }
    let b = s.as_bytes();
    let mut key = [0u8; 32];
    for i in 0..32 { key[i] = (hex_nibble(b[2*i])? << 4) | hex_nibble(b[2*i+1])?; }
    Ok(SigningKey::from_bytes(&key))
}
fn hex32(arr: &[u8;32]) -> String {
    const HEX: &[u8;16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in arr { s.push(HEX[(b>>4) as usize] as char); s.push(HEX[(b&0x0f) as usize] as char); }
    s
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Args: <SUBJECT_SK_HEX> <PHYS_MS> <KEY> <VALUE> <OUT_OP_PATH>
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 {
        eprintln!("usage: make_write <SUBJECT_SK_HEX> <PHYS_MS> <KEY> <VALUE> <OUT_OP_PATH>");
        std::process::exit(2);
    }

    let subject_sk = parse_sk_hex(&args[0]).map_err(|e| format!("bad subject sk: {e}"))?;
    let phys_ms: u64 = args[1].parse()?;
    let key = args[2].clone();
    let value = args[3].as_bytes().to_vec();
    let out = PathBuf::from(&args[4]);

    let author_pk = vk_to_bytes(&VerifyingKey::from(&subject_sk));
    // Node id can be any u32; pick a constant for determinism.
    let op = Op::new(
        vec![],
        Hlc::new(phys_ms, 7),
        author_pk,
        Payload::Data { key, value },
        &subject_sk,
    );

    fs::write(&out, canonical_cbor(&op))?;
    println!("Wrote {}", out.display());
    println!("op_id={}", hex32(&op.op_id));
    Ok(())
}
