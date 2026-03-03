//! Tiny CLI example: build a small DAG, replay, and print deterministic JSON.

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::replay::replay_full;

fn main() {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

    // Build a small history:
    // mv:o:x = "A" ; then concurrent mv:o:x = "B"
    // set+:o:s:e = "v1" ; set-:o:s:e (HB) ; set+:o:s:e = "v2" (HB)
    let a = Op::new(
        vec![],
        Hlc::new(10, 1),
        pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"A".to_vec(),
        },
        &sk,
    );
    let b = Op::new(
        vec![],
        Hlc::new(10, 2),
        pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"B".to_vec(),
        },
        &sk,
    );

    let add1 = Op::new(
        vec![],
        Hlc::new(11, 1),
        pk,
        Payload::Data {
            key: "set+:o:s:e".into(),
            value: b"v1".to_vec(),
        },
        &sk,
    );
    let rem = Op::new(
        vec![add1.op_id],
        Hlc::new(12, 1),
        pk,
        Payload::Data {
            key: "set-:o:s:e".into(),
            value: vec![],
        },
        &sk,
    );
    let add2 = Op::new(
        vec![rem.op_id],
        Hlc::new(13, 1),
        pk,
        Payload::Data {
            key: "set+:o:s:e".into(),
            value: b"v2".to_vec(),
        },
        &sk,
    );

    let mut dag = Dag::new();
    for op in [a, b, add1, rem, add2] {
        dag.insert(op);
    }

    let (state, digest) = replay_full(&dag);
    println!("{}", state.to_deterministic_json_string());
    println!("digest={}", hex(&digest));
}

fn hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &x in bytes {
        out.push(HEX[(x >> 4) as usize] as char);
        out.push(HEX[(x & 0x0f) as usize] as char);
    }
    out
}
