//! Property: incremental apply parity for *arbitrary split points*,
//! and snapshot/restore parity across the split.

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::replay::{apply_incremental, replay_full};
use proptest::prelude::*;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn make_random_ops(seed: u64, n: usize) -> Vec<Op> {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);

    let mut rng = StdRng::seed_from_u64(seed);
    let mut ops: Vec<Op> = Vec::with_capacity(n);

    for i in 0..n {
        // Choose a key kind.
        let kind: u8 = rng.gen_range(0..3);
        let (key, value) = match kind {
            0 => ("mv:o:x".to_string(), vec![rng.gen::<u8>()]),
            1 => ("set+:o:s:e".to_string(), vec![rng.gen::<u8>()]),
            _ => ("set-:o:s:e".to_string(), vec![]),
        };

        let chosen_parents: Vec<[u8; 32]> = if ops.is_empty() {
            vec![]
        } else {
            // Choose up to 2 random parents from existing ops.
            let mut ps = vec![];
            let attempts = rng.gen_range(0..=2);
            for _ in 0..attempts {
                let idx = rng.gen_range(0..ops.len());
                let pid = ops[idx].op_id;
                if !ps.contains(&pid) {
                    ps.push(pid);
                }
            }
            ps
        };

        let hlc = Hlc::new(100 + i as u64, (i as u32) % 3);
        let op = Op::new(chosen_parents, hlc, pk, Payload::Data { key, value }, &sk);
        ops.push(op);
    }
    ops
}

proptest! {
    // Keep bounds modest for runtime.
    #[test]
    fn incremental_parity_any_split(seed in any::<u64>(), n in 2usize..12) {
        let ops = make_random_ops(seed, n);

        // Build final DAG by random insertion order #1.
        let mut dag_full = Dag::new();
        let mut idxs: Vec<usize> = (0..ops.len()).collect();
        let mut rng = StdRng::seed_from_u64(seed ^ 0x00BAD5EEDu64);
        idxs.shuffle(&mut rng);
        for i in idxs { dag_full.insert(ops[i].clone()); }

        // Compute a topo order and pick a random split k (0..=len).
        let topo = dag_full.topo_sort();
        let len = topo.len();
        let mut rng2 = StdRng::seed_from_u64(seed ^ 0x0051_517u64);
        let k = rng2.gen_range(0..=len);

        // Build prefix DAG with the first k topo ops.
        let mut dag_prefix = Dag::new();
        for id in topo.iter().take(k) {
            dag_prefix.insert(dag_full.get(id).unwrap().clone());
        }

        // Incremental apply on prefix.
        let mut state_inc = ecac_core::state::State::new();
        let (_st_a, _d_a) = apply_incremental(&mut state_inc, &dag_prefix);

        // Snapshot/restore at split (exercise checkpoint correctness).
        let snap = state_inc.snapshot_to_cbor();
        let mut state_restored = ecac_core::state::State::restore_from_cbor(&snap).expect("restore");

        // Now extend DAG to full by inserting remaining ops in a different permutation.
        let mut rest_ids: Vec<_> = topo.iter().skip(k).cloned().collect();
        rest_ids.shuffle(&mut rng2);

        for id in rest_ids {
            dag_prefix.insert(dag_full.get(&id).unwrap().clone());
        }

        // Apply suffix incrementally to both states.
        let (_st_b1, d_inc) = apply_incremental(&mut state_inc, &dag_prefix);
        let (_st_b2, d_rest) = apply_incremental(&mut state_restored, &dag_prefix);
        prop_assert_eq!(d_inc, d_rest);

        // Full rebuild on final DAG must match both.
        let (_st_full, d_full) = replay_full(&dag_prefix);
        prop_assert_eq!(d_inc, d_full);
    }
}
