use ecac_core::{
    crypto::*,
    dag::Dag,
    hlc::Hlc,
    op::{Op, Payload},
};
use proptest::prelude::*;

fn to_hex(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

proptest! {
  #[test]
  fn topo_is_deterministic_across_insertion_orders(n in 5usize..30) {
    let (sk, vk) = generate_keypair(); let pk = vk_to_bytes(&vk);

    // Build a DAG with edges only to earlier nodes (acyclic).
    let mut ops: Vec<Op> = Vec::new();
    for i in 0..n {
      let parents = if i==0 { vec![] } else {
        let p1 = (i-1) as usize;
        let mut v = vec![ops[p1].op_id];
        if i>2 { v.push(ops[i-2].op_id); }
        v
      };
      let o = Op::new(parents, Hlc::new(100 + i as u64, 1), pk,
                      Payload::Data{ key: format!("k{i}"), value: vec![i as u8] }, &sk);
      assert!(o.verify());
      ops.push(o);
    }

    // Reference topo (sequential insert)
    let mut dag_ref = Dag::new();
    for o in &ops { dag_ref.insert(o.clone()); }
    let ref_order: Vec<String> = dag_ref.topo_sort().iter().map(|id| to_hex(id)).collect();

    // Shuffle insertions 5 times; topo must match reference
    for s in 0..5 {
      let mut dag = Dag::new();
      let mut idxs: Vec<_> = (0..n).collect();
      // cheap shuffle based on seed s
      for i in 0..idxs.len() { let j = ((i + s) * 7 + 3) % idxs.len(); idxs.swap(i,j); }
      for i in idxs { dag.insert(ops[i].clone()); }
      let got: Vec<String> = dag.topo_sort().iter().map(|id| to_hex(id)).collect();
      //prop_assert_eq!(got, ref_order);
      prop_assert_eq!(got.as_slice(), ref_order.as_slice());
    }
  }
}

/// Rigorous topo determinism: build a DAG with concurrent (diamond-shaped)
/// nodes and shuffle insertion order 100 times, asserting the produced
/// linearization (list of op_ids) is identical every time.
#[test]
fn topo_determinism_concurrent_diamond_100_shuffles() {
    use rand::seq::SliceRandom;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

    // Build a diamond DAG with concurrent branches:
    //
    //       root (t=100)
    //      / | \
    //    a1 a2 a3   (t=101, different node_ids -> concurrent)
    //      \ | /
    //      merge    (t=102, parents=[a1,a2,a3])
    //        |
    //       b1      (t=103)
    //      / \
    //    c1  c2     (t=104, concurrent pair)
    //      \ /
    //      tail     (t=105)
    //
    let root = Op::new(
        vec![],
        Hlc::new(100, 1),
        pk,
        Payload::Data { key: "root".into(), value: vec![0] },
        &sk,
    );

    let a1 = Op::new(
        vec![root.op_id],
        Hlc::new(101, 1),
        pk,
        Payload::Data { key: "a1".into(), value: vec![1] },
        &sk,
    );
    let a2 = Op::new(
        vec![root.op_id],
        Hlc::new(101, 2),
        pk,
        Payload::Data { key: "a2".into(), value: vec![2] },
        &sk,
    );
    let a3 = Op::new(
        vec![root.op_id],
        Hlc::new(101, 3),
        pk,
        Payload::Data { key: "a3".into(), value: vec![3] },
        &sk,
    );

    let merge = Op::new(
        vec![a1.op_id, a2.op_id, a3.op_id],
        Hlc::new(102, 1),
        pk,
        Payload::Data { key: "merge".into(), value: vec![4] },
        &sk,
    );

    let b1 = Op::new(
        vec![merge.op_id],
        Hlc::new(103, 1),
        pk,
        Payload::Data { key: "b1".into(), value: vec![5] },
        &sk,
    );

    let c1 = Op::new(
        vec![b1.op_id],
        Hlc::new(104, 1),
        pk,
        Payload::Data { key: "c1".into(), value: vec![6] },
        &sk,
    );
    let c2 = Op::new(
        vec![b1.op_id],
        Hlc::new(104, 2),
        pk,
        Payload::Data { key: "c2".into(), value: vec![7] },
        &sk,
    );

    let tail = Op::new(
        vec![c1.op_id, c2.op_id],
        Hlc::new(105, 1),
        pk,
        Payload::Data { key: "tail".into(), value: vec![8] },
        &sk,
    );

    let all_ops = vec![
        root.clone(),
        a1.clone(),
        a2.clone(),
        a3.clone(),
        merge.clone(),
        b1.clone(),
        c1.clone(),
        c2.clone(),
        tail.clone(),
    ];

    // Build reference topo order from sequential insertion.
    let mut dag_ref = Dag::new();
    for o in &all_ops {
        dag_ref.insert(o.clone());
    }
    let ref_order: Vec<String> = dag_ref.topo_sort().iter().map(|id| to_hex(id)).collect();

    // Shuffle insertion order 100 times; topo must always match reference.
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
    for iteration in 0..100 {
        let mut shuffled = all_ops.clone();
        shuffled.shuffle(&mut rng);

        let mut dag = Dag::new();
        for o in shuffled {
            dag.insert(o);
        }
        let got: Vec<String> = dag.topo_sort().iter().map(|id| to_hex(id)).collect();
        assert_eq!(
            got, ref_order,
            "topo order diverged on shuffle iteration {iteration}"
        );
    }
}
