// crates/net/tests/sync_planner.rs
use ecac_core::op::OpId;
use ecac_net::sync::{SyncPlanner, bloom16_maybe_contains};


fn hash_indices(id: &OpId) -> [u8; 3] {
    let h = ecac_core::crypto::hash_bytes(id);
    let i0 = (u16::from_le_bytes([h[0], h[1]]) % 16) as u8;
    let i1 = (u16::from_le_bytes([h[2], h[3]]) % 16) as u8;
    let i2 = (u16::from_le_bytes([h[4], h[5]]) % 16) as u8;
    [i0, i1, i2]
}

fn set_bloom_bits_for(bloom: &mut [u8; 2], id: &OpId) {
    for i in hash_indices(id) {
        let byte = (i / 8) as usize;
        let bit  =  i % 8;
        bloom[byte] |= 1u8 << bit;
    }
}

fn id(x: u8) -> OpId { [x; 32] }

#[test]
fn planner_diff_small_and_parent_first() {
    // DAG:
    //   A -> B -> D
    //   A -> C -> D
    // Local has only A; Remote heads are [D].
    let a = id(1);
    let b = id(2);
    let c = id(3);
    let d = id(4);

    let parents = move |x: &OpId| -> Vec<OpId> {
        match *x {
            x if x == d => vec![b, c],
            x if x == b => vec![a],
            x if x == c => vec![a],
            _ => vec![],
        }
    };

    let have = move |x: &OpId| *x == a;

        let bloom = [0u8; 2]; // no short-circuiting
        let plan = SyncPlanner::plan_with(&[d], bloom, have, parents);
    
        // Boundary is A (already present) so we should fetch only [B,C] then [D].
            assert_eq!(plan.batches.len(), 2);
    let mut bc = plan.batches[0].clone(); bc.sort();
    assert_eq!(bc, vec![b, c]);              // parents layer
    assert_eq!(plan.batches[1], vec![d]);    // child
}

#[test]
fn bloom_short_circuit_skips_knowns() {
        // Local has nothing, but bloom claims B is present → planner should skip B.
        // Choose IDs such that B’s bloom indices do NOT accidentally cover C/D.
        // We’ll deterministically search small byte values until we get disjoint indices.
        let mut b = id(0x10);
        let mut c = id(0x20);
        let mut d = id(0x30);
        let mut tries = 0u32;
        loop {
            let bi = hash_indices(&b);
            let ci = hash_indices(&c);
            let di = hash_indices(&d);
            let covers = |x: [u8;3], y: [u8;3]| -> bool {
                y.iter().all(|yy| x.contains(yy))
            };
            if !covers(bi, ci) && !covers(bi, di) {
                break;
            }
            // Bump IDs deterministically; this loop will terminate quickly for a 16-bit bloom.
            b = id(b[0].wrapping_add(1));
            c = id(c[0].wrapping_add(1));
            d = id(d[0].wrapping_add(1));
            tries += 1;
            assert!(tries < 1000, "failed to find disjoint bloom indices for test");
        }
    
        // Parents: D -> [B, C]
        let parents = move |x: &OpId| -> Vec<OpId> {
            if *x == d { vec![b, c] } else { vec![] }
        };
        let have = |_x: &OpId| false;
    
        // Build a bloom that marks B as present (set exactly its three bits)
        let mut bloom = [0u8; 2];
        set_bloom_bits_for(&mut bloom, &b);
        assert!(bloom16_maybe_contains(bloom, &b));
        // Defensive: make sure C and D are NOT falsely marked present
        assert!(!bloom16_maybe_contains(bloom, &c));
        assert!(!bloom16_maybe_contains(bloom, &d));
        
    //     let b_maybe = bloom16_maybe_contains(local_recent_bloom16, &id);
    // eprintln!("planner: visit id={} have={} bloom_maybe={}",
    //     hex::encode(id), have(&id), b_maybe);

        let plan = SyncPlanner::plan_with(&[d], bloom, have, parents);
    
        // Because bloom hints B as present, we only fetch C first, then D.
        assert_eq!(plan.batches.len(), 2);
        assert_eq!(plan.batches[0], vec![c]); // parents
        assert_eq!(plan.batches[1], vec![d]); // child
}
