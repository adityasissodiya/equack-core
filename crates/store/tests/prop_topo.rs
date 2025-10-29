#![cfg(feature = "prop-topo")]

use ecac_store::Store;
use ecac_core::dag::Dag;
use ecac_core::op::Op;
use ecac_core::replay::replay_full;
use proptest::prelude::*;
use tempfile::TempDir;

proptest! {
    // keep this very small so it’s fast in CI
    #[test]
    fn topo_never_violates_parents(n in 1usize..8) {
        // generate a tiny DAG via in-memory ops (you likely already have helpers to mint valid signed Ops)
        let ops: Vec<Op> = ecac_core::tests::fixtures::random_dag_ops(n);

        // build DB
        let td = TempDir::new().unwrap();
        let dbp = td.path().join("ecac.db");
        let store = Store::open(&dbp, Default::default()).unwrap();

        // append out of order to stress topo
        for op in ops.iter().rev() {
            let bytes = ecac_core::serialize::canonical_cbor(op);
            store.put_op_cbor(&bytes).unwrap();
        }

        // topo order from store must be a valid topological order
        let ids = store.topo_ids().unwrap();
        let set: std::collections::BTreeSet<[u8;32]> = ids.iter().cloned().collect();
        for id in &ids {
            let b = store.get_op_bytes(id).unwrap().unwrap();
            let op: Op = serde_cbor::from_slice(&b).unwrap();
            for p in &op.header.parents {
                assert!(set.contains(p), "child emitted before missing parent");
            }
        }

        // parity: replay_from_store == replay in memory
        let (st_file, dig_file) = {
            let mut dag = Dag::new();
            for op in &ops { dag.insert(op.clone()); }
            replay_full(&dag)
        };
        let cbor = store.load_ops_cbor(&ids).unwrap();
        let mut dag2 = Dag::new();
        for b in cbor { dag2.insert(serde_cbor::from_slice::<Op>(&b).unwrap()); }
        let (st_store, dig_store) = replay_full(&dag2);
        assert_eq!(dig_file, dig_store, "digest mismatch");
        assert_eq!(st_file.to_deterministic_json_string(), st_store.to_deterministic_json_string());
    }
}
