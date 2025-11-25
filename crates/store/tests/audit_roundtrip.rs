#![cfg(feature = "audit")]

use std::path::PathBuf;
use ed25519_dalek::SigningKey;
use ecac_store::audit::{AuditReader, AuditWriter};
use ecac_core::audit::AuditEvent;

fn tmpdir() -> PathBuf {
    let p = std::env::temp_dir().join(format!("ecac-audit-rt-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn audit_roundtrip_one_entry() {
    // fixed privkey bytes (32 bytes)
    let sk_bytes = hex::decode(
        "0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210"
    ).unwrap();
    let sk = SigningKey::from_bytes(&sk_bytes.try_into().unwrap());

    // arbitrary node_id that stays consistent on disk
    let node_id = [0xABu8; 32];
    let dir = tmpdir();

    // writer: open and append a minimal event
    {
        let mut w = AuditWriter::open(&dir, sk, node_id).expect("open writer");
        let ev = AuditEvent::Checkpoint {
            checkpoint_id: 1,
            topo_idx: 1,
            state_digest: [0u8; 32],
        };
        w.append(ev).expect("append");
    }

    // reader: verify the chain
    {
        let r = AuditReader::open(&dir).expect("open reader");
        r.verify().expect("verify ok");
    }
}
