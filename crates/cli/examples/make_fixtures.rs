use std::fs;
use std::path::PathBuf;

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};

fn main() {
    let out_dir = std::env::args().nth(1).unwrap_or_else(|| "fixtures".to_string());
    let mut dir = PathBuf::from(out_dir);
    fs::create_dir_all(&dir).expect("mkdir fixtures");

    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

    // 1) HB chain (MVReg overwrite)
    let a = Op::new(vec![], Hlc::new(10,1), pk, Payload::Data { key: "mv:o:x".into(), value: b"A".to_vec() }, &sk);
    let b = Op::new(vec![a.op_id], Hlc::new(11,1), pk, Payload::Data { key: "mv:o:x".into(), value: b"B".to_vec() }, &sk);
    let c = Op::new(vec![b.op_id], Hlc::new(12,1), pk, Payload::Data { key: "mv:o:x".into(), value: b"C".to_vec() }, &sk);
    let hb_chain = vec![a.clone(), b.clone(), c.clone()];
    let mut path = dir.clone(); path.push("hb_chain.cbor");
    fs::write(&path, serde_cbor::to_vec(&hb_chain).unwrap()).unwrap();

    // 2) Concurrent MVReg writes
    let mv_conc = vec![
        Op::new(vec![], Hlc::new(10,1), pk, Payload::Data { key: "mv:o:x".into(), value: b"A".to_vec() }, &sk),
        Op::new(vec![], Hlc::new(10,2), pk, Payload::Data { key: "mv:o:x".into(), value: b"B".to_vec() }, &sk),
    ];
    let mut path = dir.clone(); path.push("mv_concurrent.cbor");
    fs::write(&path, serde_cbor::to_vec(&mv_conc).unwrap()).unwrap();

    // 3) OR-Set add/remove races
    let add1 = Op::new(vec![], Hlc::new(10,1), pk, Payload::Data { key: "set+:o:s:e".into(), value: b"v1".to_vec() }, &sk);
    let rem_conc = Op::new(vec![], Hlc::new(10,2), pk, Payload::Data { key: "set-:o:s:e".into(), value: vec![] }, &sk);
    let add2 = Op::new(vec![], Hlc::new(11,1), pk, Payload::Data { key: "set+:o:s:e".into(), value: b"v2".to_vec() }, &sk);
    let rem_hb = Op::new(vec![add1.op_id], Hlc::new(12,1), pk, Payload::Data { key: "set-:o:s:e".into(), value: vec![] }, &sk);
    let orset = vec![add1, rem_conc, add2, rem_hb];
    let mut path = dir.clone(); path.push("orset_races.cbor");
    fs::write(&path, serde_cbor::to_vec(&orset).unwrap()).unwrap();

    eprintln!("wrote fixtures to {}", dir.display());
}
