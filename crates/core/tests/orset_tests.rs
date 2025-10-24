use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload, OpId};
use ecac_core::crdt::ORSet;
use ecac_core::crypto::{generate_keypair, vk_to_bytes};

fn hb_of(dag: &Dag) -> impl Fn(&OpId, &OpId) -> bool + '_ {
    move |a: &OpId, b: &OpId| {
        if a == b { return false; }
        let mut stack = vec![*b];
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        while let Some(cur) = stack.pop() {
            if &cur == a { return true; }
            if !seen.insert(cur) { continue; }
            let op = dag.get(&cur).unwrap();
            for p in &op.header.parents { stack.push(*p); }
        }
        false
    }
}

#[test]
fn orset_add_remove_observed() {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

    let add = Op::new(vec![], Hlc::new(10,1), pk, Payload::Data { key: "set+:o:s:elem".into(), value: b"v1".to_vec() }, &sk);
    let rem = Op::new(vec![add.op_id], Hlc::new(11,1), pk, Payload::Data { key: "set-:o:s:elem".into(), value: vec![] }, &sk);

    let mut dag = Dag::new();
    dag.insert(rem.clone());
    dag.insert(add.clone());

    let mut set = ORSet::new();
    set.add("elem".into(), add.op_id, b"v1".to_vec());
    set.remove_with_hb("elem", &rem.op_id, hb_of(&dag));

    // Element should be absent.
    assert!(set.get("elem").map(|e| e.is_present()).unwrap_or(false) == false);
}

#[test]
fn orset_concurrent_add_remove() {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

    let add = Op::new(vec![], Hlc::new(10,1), pk, Payload::Data { key: "set+:o:s:elem".into(), value: b"v1".to_vec() }, &sk);
    let rem = Op::new(vec![], Hlc::new(10,2), pk, Payload::Data { key: "set-:o:s:elem".into(), value: vec![] }, &sk);

    let mut dag = Dag::new();
    dag.insert(add.clone());
    dag.insert(rem.clone());

    let mut set = ORSet::new();
    set.add("elem".into(), add.op_id, b"v1".to_vec());
    set.remove_with_hb("elem", &rem.op_id, hb_of(&dag));

    // Concurrent remove should not kill the add.
    assert!(set.get("elem").unwrap().is_present());
}

#[test]
fn orset_readd() {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

    let add1 = Op::new(vec![], Hlc::new(10,1), pk, Payload::Data { key: "set+:o:s:elem".into(), value: b"v1".to_vec() }, &sk);
    let rem  = Op::new(vec![add1.op_id], Hlc::new(11,1), pk, Payload::Data { key: "set-:o:s:elem".into(), value: vec![] }, &sk);
    let add2 = Op::new(vec![rem.op_id], Hlc::new(12,1), pk, Payload::Data { key: "set+:o:s:elem".into(), value: b"v2".to_vec() }, &sk);

    let mut dag = Dag::new();
    dag.insert(add2.clone());
    dag.insert(rem.clone());
    dag.insert(add1.clone());

    let mut set = ORSet::new();
    set.add("elem".into(), add1.op_id, b"v1".to_vec());
    set.remove_with_hb("elem", &rem.op_id, hb_of(&dag));
    set.add("elem".into(), add2.op_id, b"v2".to_vec());

    // Re-add must make it present again.
    assert!(set.get("elem").unwrap().is_present());
    // Projection must be deterministic (min hash among active tags). Either v1 or v2 depending on hashes.
    let pv = set.get("elem").unwrap().project_value().unwrap();
    assert!(pv == b"v1".to_vec() || pv == b"v2".to_vec());
}
