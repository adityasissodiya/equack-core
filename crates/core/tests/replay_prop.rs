//! Property tests for deterministic replay: convergence, idempotence, parity.

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::replay::{apply_incremental, replay_full};
use proptest::prelude::*;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, Rng, SeedableRng}; // <- bring shuffle() into scope

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
    // Use small sizes to keep the test fast.
    #[test]
    fn convergence_and_idempotence(seed in any::<u64>(), n in 1usize..10) {
        let ops = make_random_ops(seed, n);

        // Permute insertion orders and ensure replay digest is identical.
        let mut digests = Vec::new();
        for perm_seed in 0..3u64 {
            let mut dag = Dag::new();

            // Random permutation by shuffling indices with another RNG.
            let mut idxs: Vec<usize> = (0..ops.len()).collect();
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed ^ perm_seed);
            idxs.shuffle(&mut rng);

            for i in idxs {
                dag.insert(ops[i].clone());
            }

            let (state_full, d_full) = replay_full(&dag);

            // Idempotence: applying incrementally on top of fresh state matches full.
            let mut state_inc = ecac_core::state::State::new();
            let (_st1, d1) = apply_incremental(&mut state_inc, &dag);
            let (_st2, d2) = apply_incremental(&mut state_inc, &dag); // re-apply -> no change
            prop_assert_eq!(d1, d2);

            // Full vs incremental parity (single shot).
            prop_assert_eq!(state_full.digest(), state_inc.digest());

            digests.push(d_full);
        }

        // All digests across permutations must be identical.
        for d in digests.windows(2) {
            prop_assert_eq!(d[0], d[1]);
        }
    }
}
