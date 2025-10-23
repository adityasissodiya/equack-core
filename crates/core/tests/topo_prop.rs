use ecac_core::{crypto::*, hlc::Hlc, op::{Op, Payload}, dag::Dag};
use proptest::prelude::*;

fn to_hex(id: &[u8;32]) -> String { id.iter().map(|b| format!("{:02x}", b)).collect() }

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
