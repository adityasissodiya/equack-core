use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::json;
use std::env;
use std::fs;

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
    if s.len() != 64 {
        return Err("need 64 hex chars for ed25519 SK".into());
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Args: <issuer_sk_hex> <out_path>
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() < 2 {
        eprintln!("usage: cargo run -p ecac-cli --example make_jwt -- <issuer_sk_hex> <out_path>");
        std::process::exit(2);
    }
    let issuer_sk = parse_sk_hex(&args[0]).map_err(|e| format!("bad SK: {e}"))?;
    let out_path = &args[1];

    // Subject key (generate fresh for demo)
    let subject_sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let subject_vk = VerifyingKey::from(&subject_sk);

    // Claims (status.index=1 so it won't be revoked if list-0.bin is 0x01)
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","typ":"JWT"}"#);
    let claims = json!({
        "sub_pk": to_hex32(subject_vk.as_bytes()),
        "role": "editor",
        "scope": ["hv"],
        "nbf": 10_000u64,
        "exp": 20_000u64,
        "iss": "oem-issuer-1",
        "jti": "test-cred-1",
        "status": { "id":"list-0", "index": 1u64 }
    });
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{header}.{payload}");

    // Sign (Ed25519 over ASCII of signing_input)
    let sig = issuer_sk.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    let compact = format!("{signing_input}.{sig_b64}");

    fs::create_dir_all(
        std::path::Path::new(out_path)
            .parent()
            .unwrap_or_else(|| ".".as_ref()),
    )?;
    fs::write(out_path, compact.as_bytes())?;

    // Print info to wire up trust store
    let issuer_vk = issuer_sk.verifying_key();
    println!("Wrote {}", out_path);
    println!("issuer_vk_hex = {}", to_hex32(issuer_vk.as_bytes()));
    println!("subject_pk_hex = {}", to_hex32(subject_vk.as_bytes()));
    Ok(())
}
