#![cfg(feature = "audit")]

use ed25519_dalek::SigningKey;
use tempfile::tempdir;
use std::{fs, io::{Read, Write}};
use getrandom::getrandom;
use ecac_core::audit::AuditEvent;

// Minimal helper to make a node key + id.
fn gen_node() -> (SigningKey, [u8; 32]) {
    let mut sk_bytes = [0u8; 32];
    getrandom(&mut sk_bytes).unwrap();
    let sk = SigningKey::from_bytes(&sk_bytes);
    let mut node_id = [0u8; 32];
    getrandom(&mut node_id).unwrap();
    (sk, node_id)
}

// Locate first/second record boundaries in a segment file.
fn read_len_be(buf: &[u8]) -> (usize, usize) {
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    (len, 4 + len)
}

#[test]
fn chain_basic() {
    let tmp = tempdir().unwrap();
    let audit_dir = tmp.path().join("audit");
    let (sk, node_id) = gen_node();

    let mut w = ecac_store::audit::AuditWriter::open(&audit_dir, sk, node_id).unwrap();

    // Append a couple of simple events (use whatever variant your core exposes).
        let e1 = AuditEvent::Checkpoint { checkpoint_id: 0_u64, topo_idx: 0, state_digest: [0u8;32] };
        let e2 = AuditEvent::Checkpoint { checkpoint_id: 1_u64, topo_idx: 1, state_digest: [1u8;32] };

    let s1 = w.append(e1).unwrap();
    let s2 = w.append(e2).unwrap();
    assert_eq!(s1, 1);
    assert_eq!(s2, 2);

    let r = ecac_store::audit::AuditReader::open(&audit_dir).unwrap();
    r.verify().unwrap();
}

#[test]
fn corrupt_byte_reports_precisely() {
    let tmp = tempdir().unwrap();
    let audit_dir = tmp.path().join("audit");
    let (sk, node_id) = gen_node();
    let mut w = ecac_store::audit::AuditWriter::open(&audit_dir, sk, node_id).unwrap();

    // two entries so we can corrupt the second
        w.append(AuditEvent::Checkpoint { checkpoint_id: 0_u64, topo_idx: 0, state_digest: [0;32] }).unwrap();
        w.append(AuditEvent::Checkpoint { checkpoint_id: 1_u64, topo_idx: 1, state_digest: [1;32] }).unwrap();
    // Flip a byte inside the second CBOR blob
    let seg = audit_dir.join("segment-00000001.log");
    let mut bytes = fs::read(&seg).unwrap();
    // first record boundaries
    let (l1, first_total) = read_len_be(&bytes);
    let second_start = first_total;
    // guard
    assert!(bytes.len() > second_start + 4);
    let (l2, _second_total) = read_len_be(&bytes[second_start..]);
    let payload_start = second_start + 4;
    bytes[payload_start + (l2 / 2)] ^= 0xFF; // flip a byte mid-payload
    fs::write(&seg, &bytes).unwrap();

    let r = ecac_store::audit::AuditReader::open(&audit_dir).unwrap();
    let err = r.verify().unwrap_err();
    // Corruption will usually trip signature verification:
    match err {
        ecac_store::audit::VerifyError::BadSig { seq, .. } => assert_eq!(seq, 2),
        // If the CBOR structure breaks, you may see Truncated instead; either is acceptable for now.
        ecac_store::audit::VerifyError::Truncated { .. } => {}
        _ => panic!("unexpected error: {err:?}"),
    }
}

#[test]
fn missing_prev_detects_gap() {
    let tmp = tempdir().unwrap();
    let audit_dir = tmp.path().join("audit");
    let (sk, node_id) = gen_node();
    let mut w = ecac_store::audit::AuditWriter::open(&audit_dir, sk, node_id).unwrap();

        w.append(AuditEvent::Checkpoint { checkpoint_id: 0_u64, topo_idx: 0, state_digest: [0;32] }).unwrap();
        w.append(AuditEvent::Checkpoint { checkpoint_id: 1_u64, topo_idx: 1, state_digest: [1;32] }).unwrap();

    // Remove the first record (len+payload) so file starts at seq=2 while verifier expects 1
    let seg = audit_dir.join("segment-00000001.log");
    let mut bytes = fs::read(&seg).unwrap();
    let (l1, first_total) = read_len_be(&bytes);
    assert!(bytes.len() > first_total);
    bytes.drain(0..first_total);
    fs::write(&seg, &bytes).unwrap();

    let r = ecac_store::audit::AuditReader::open(&audit_dir).unwrap();
    let err = r.verify().unwrap_err();
    match err {
        ecac_store::audit::VerifyError::SeqGap { expected, found, .. } => {
            assert_eq!(expected, 1);
            assert_eq!(found, 2);
        }
        _ => panic!("expected SeqGap, got {err:?}"),
    }
}
