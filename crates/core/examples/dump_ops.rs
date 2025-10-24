use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use std::env;
use std::fs;

fn main() {
    let out = env::args().nth(1).unwrap_or_else(|| "ops.cbor".into());

    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

    // Same small history from m2_replay:
    // two concurrent MV writes, plus OR-Set add -> remove -> add
    let a = Op::new(vec![], Hlc::new(10,1), pk, Payload::Data { key: "mv:o:x".into(), value: b"A".to_vec() }, &sk);
    let b = Op::new(vec![], Hlc::new(10,2), pk, Payload::Data { key: "mv:o:x".into(), value: b"B".to_vec() }, &sk);

    let add1 = Op::new(vec![], Hlc::new(11,1), pk, Payload::Data { key: "set+:o:s:e".into(), value: b"v1".to_vec() }, &sk);
    let rem  = Op::new(vec![add1.op_id], Hlc::new(12,1), pk, Payload::Data { key: "set-:o:s:e".into(), value: vec![] }, &sk);
    let add2 = Op::new(vec![rem.op_id], Hlc::new(13,1), pk, Payload::Data { key: "set+:o:s:e".into(), value: b"v2".to_vec() }, &sk);

    let ops = vec![a, b, add1, rem, add2];

    let bytes = serde_cbor::to_vec(&ops).expect("serialize");
    fs::write(&out, &bytes).expect("write");
    eprintln!("wrote {}", out);
}
