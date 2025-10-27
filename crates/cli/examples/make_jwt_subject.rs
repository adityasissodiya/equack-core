use std::{env, fs, path::PathBuf};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::json;

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
    // Args: <ISSUER_SK_HEX> <SUBJECT_SK_HEX> <OUT_JWT_PATH>
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        eprintln!("usage: make_jwt_subject <ISSUER_SK_HEX> <SUBJECT_SK_HEX> <OUT_JWT_PATH>");
        std::process::exit(2);
    }
    let issuer_sk = parse_sk_hex(&args[0]).map_err(|e| format!("bad issuer sk: {e}"))?;
    let subject_sk = parse_sk_hex(&args[1]).map_err(|e| format!("bad subject sk: {e}"))?;
    let out = PathBuf::from(&args[2]);

    let issuer_vk = VerifyingKey::from(&issuer_sk);
    let subject_vk = VerifyingKey::from(&subject_sk);

    // Claims (same shape as the rest of M4)
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let claims = json!({
        "sub_pk": hex32(&subject_vk.to_bytes()),
        "role": "editor",
        "scope": ["hv"],
        "nbf": 10000u64,
        "exp": 20000u64,
        "iss": "oem-issuer-1",
        "jti": "test-cred-1",
        "status": { "id": "list-0", "index": 1 }
    });
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{header}.{payload}");
    let sig: Signature = issuer_sk.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let compact = format!("{signing_input}.{sig_b64}");

    fs::write(&out, compact.as_bytes())?;

    println!("Wrote {}", out.display());
    println!("issuer_vk_hex  = {}", hex32(&issuer_vk.to_bytes()));
    println!("subject_pk_hex = {}", hex32(&subject_vk.to_bytes()));
    println!("(keep SUBJECT_SK_HEX to sign writes later)");
    Ok(())
}
