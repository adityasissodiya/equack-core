use ecac_core::crdt::MVReg;
use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};

/// Build a DAG with two MV writes a -> b (HB), ensure b overwrites a.
#[test]
fn mvreg_hb_overwrite() {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

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
        vec![a.op_id],
        Hlc::new(11, 1),
        pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"B".to_vec(),
        },
        &sk,
    );

    let mut dag = Dag::new();
    dag.insert(b.clone());
    dag.insert(a.clone());

    // Replay via MVReg directly using DAG as HB oracle.
    let mut mv = MVReg::new();
    let hb = |x: &_, y: &_| -> bool {
        // is x ancestor of y?
        let mut stack = vec![*y];
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        while let Some(cur) = stack.pop() {
            if &cur == x {
                return true;
            }
            if !seen.insert(cur) {
                continue;
            }
            let op = dag.get(&cur).unwrap();
            for p in &op.header.parents {
                stack.push(*p);
            }
        }
        false
    };

    mv.apply_put(a.op_id, b"A".to_vec(), hb);
    mv.apply_put(b.op_id, b"B".to_vec(), hb);

    let winners = mv.values();
    assert_eq!(winners, vec![b"B".to_vec()]);
    assert_eq!(mv.project().unwrap(), b"B".to_vec());
}

/// Two concurrent MV writes: both winners remain; projection stable.
#[test]
fn mvreg_concurrent() {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

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

    let mut dag = Dag::new();
    dag.insert(a.clone());
    dag.insert(b.clone());

    let mut mv = MVReg::new();
    let hb = |x: &_, y: &_| -> bool {
        let mut stack = vec![*y];
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        while let Some(cur) = stack.pop() {
            if &cur == x {
                return true;
            }
            if !seen.insert(cur) {
                continue;
            }
            let op = dag.get(&cur).unwrap();
            for p in &op.header.parents {
                stack.push(*p);
            }
        }
        false
    };

    mv.apply_put(a.op_id, b"A".to_vec(), &hb);
    mv.apply_put(b.op_id, b"B".to_vec(), &hb);

    let winners = mv.values();
    assert_eq!(winners.len(), 2);

    // Projection must be one of A or B and stable over runs.
    let p = mv.project().unwrap();
    assert!(p == b"A".to_vec() || p == b"B".to_vec());
}
