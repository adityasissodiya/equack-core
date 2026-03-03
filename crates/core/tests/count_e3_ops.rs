//! F1: Programmatically count payload variants in the E3 policy CBOR log.
//!
//! Run with: cargo test -p ecac-core --test count_e3_ops -- --nocapture

use ecac_core::op::{Op, Payload};
use std::path::PathBuf;

/// Locate e3-policy.cbor relative to the workspace root.
fn e3_cbor_path() -> PathBuf {
    // tests run from crate dir; workspace root is ../../..
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // crates/core -> equack-core -> project root
    p.pop(); // crates
    p.pop(); // equack-core
    p.pop(); // project root
    p.push("e3-policy.cbor");
    p
}

#[test]
fn count_e3_payload_variants() {
    let path = e3_cbor_path();
    assert!(path.exists(), "e3-policy.cbor not found at {}", path.display());

    let data = std::fs::read(&path).expect("read e3-policy.cbor");

    // Try Vec<Op> first, then legacy flat format
    let ops: Vec<Op> = serde_cbor::from_slice(&data)
        .expect("decode CBOR Vec<Op> from e3-policy.cbor");

    let mut data_count = 0u64;
    let mut credential_count = 0u64;
    let mut grant_count = 0u64;
    let mut revoke_count = 0u64;
    let mut key_grant_count = 0u64;
    let mut key_rotate_count = 0u64;
    let mut issuer_key_count = 0u64;
    let mut issuer_key_revoke_count = 0u64;
    let mut status_list_chunk_count = 0u64;
    let mut status_pointer_count = 0u64;
    let mut reserved_count = 0u64;

    for op in &ops {
        match &op.header.payload {
            Payload::Data { .. } => data_count += 1,
            Payload::Credential { .. } => credential_count += 1,
            Payload::Grant { .. } => grant_count += 1,
            Payload::Revoke { .. } => revoke_count += 1,
            Payload::KeyGrant { .. } => key_grant_count += 1,
            Payload::KeyRotate { .. } => key_rotate_count += 1,
            Payload::IssuerKey { .. } => issuer_key_count += 1,
            Payload::IssuerKeyRevoke { .. } => issuer_key_revoke_count += 1,
            Payload::StatusListChunk { .. } => status_list_chunk_count += 1,
            Payload::StatusPointer { .. } => status_pointer_count += 1,
            Payload::_Reserved => reserved_count += 1,
        }
    }

    let total = ops.len() as u64;

    println!("=== E3 Policy CBOR Op-Count Breakdown ===");
    println!("Total ops:          {total}");
    println!("  Data:             {data_count}");
    println!("  Credential:       {credential_count}");
    println!("  Grant:            {grant_count}");
    println!("  Revoke:           {revoke_count}");
    println!("  KeyGrant:         {key_grant_count}");
    println!("  KeyRotate:        {key_rotate_count}");
    println!("  IssuerKey:        {issuer_key_count}");
    println!("  IssuerKeyRevoke:  {issuer_key_revoke_count}");
    println!("  StatusListChunk:  {status_list_chunk_count}");
    println!("  StatusPointer:    {status_pointer_count}");
    println!("  _Reserved:        {reserved_count}");

    // Sanity: variant counts must sum to total
    let sum = data_count + credential_count + grant_count + revoke_count
        + key_grant_count + key_rotate_count + issuer_key_count
        + issuer_key_revoke_count + status_list_chunk_count
        + status_pointer_count + reserved_count;
    assert_eq!(sum, total, "variant counts must sum to total");
}
