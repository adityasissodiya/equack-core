use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::serialize::canonical_cbor;
use ecac_store::Store;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn tmpdir() -> PathBuf {
    let mut p = std::env::temp_dir();
    // add nanos + a random byte to avoid collisions even within the same test thread
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let rand = (blake3::hash(&nanos.to_le_bytes()).as_bytes()[0]) as u8;
    p.push(format!("ecac_store_test_{}_{}_{}", std::process::id(), nanos, rand));
    std::fs::create_dir_all(&p).unwrap();
    p
}


// fn tmpdir() -> PathBuf {
//     let mut p = std::env::temp_dir();
//     p.push(format!("ecac_store_test_{}", std::process::id()));
//     std::fs::create_dir_all(&p).unwrap();
//     p
// }

#[test]
fn heads_basic_and_missing_parent_filtered() {
    let db = tmpdir();
    let store = Store::open(&db, Default::default()).unwrap();

    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

    // a -> b ; c (independent root)
    let a = Op::new(vec![], Hlc::new(10,1), pk, Payload::Data{key:"k".into(), value:b"a".to_vec()}, &sk);
    let b = Op::new(vec![a.op_id], Hlc::new(11,1), pk, Payload::Data{key:"k".into(), value:b"b".to_vec()}, &sk);
    let c = Op::new(vec![], Hlc::new(12,1), pk, Payload::Data{key:"k".into(), value:b"c".to_vec()}, &sk);

    // orphan d (parent not present)
    let bogus_parent = [0x55u8; 32];
    let d = Op::new(vec![bogus_parent], Hlc::new(13,1), pk, Payload::Data{key:"k".into(), value:b"d".to_vec()}, &sk);

    for op in [&a, &b, &c, &d] {
        let bytes = canonical_cbor(op);
        store.put_op_cbor(&bytes).unwrap();
    }

    let heads = store.heads(10).unwrap();
    // Expected heads: b and c (d excluded due to missing parent; a has child)
    assert!(heads.contains(&b.op_id));
    assert!(heads.contains(&c.op_id));
    assert!(!heads.contains(&a.op_id));
    assert!(!heads.contains(&d.op_id));
}

#[test]
fn recent_bloom_covers_last_n() {
    let db = tmpdir();
    let store = Store::open(&db, Default::default()).unwrap();

    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

    let mut ids = Vec::new();
    for t in 0..20 {
        let op = Op::new(vec![], Hlc::new(100 + t, 1), pk, Payload::Data{key:"k".into(), value:vec![t as u8]}, &sk);
        store.put_op_cbor(&canonical_cbor(&op)).unwrap();
        ids.push(op.op_id);
    }

    let bloom = store.recent_bloom(8).unwrap();

    // Check that each of the last 8 IDs sets all 3 bloom bits used by our hash mapping
    for id in ids.iter().rev().take(8) {
        let h = blake3::hash(id).as_bytes().to_owned();
        let idx = [
            (u16::from_le_bytes([h[0], h[1]]) % 16) as u8,
            (u16::from_le_bytes([h[2], h[3]]) % 16) as u8,
            (u16::from_le_bytes([h[4], h[5]]) % 16) as u8,
        ];
        for i in idx {
            let byte = (i / 8) as usize;
            let bit = i % 8;
            assert!((bloom[byte] & (1u8 << bit)) != 0, "bit {} not set for recent id", i);
        }
    }
}
