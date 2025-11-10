// crates/net/tests/two_node_sync_minimal.rs
use anyhow::Result;
use libp2p::Multiaddr;
use tokio::task::yield_now;
use tokio::time::{timeout, Duration};
use libp2p::gossipsub::PublishError;

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::replay::replay_full;
use ecac_core::serialize::canonical_cbor;

use ecac_net::transport::Node;
use ecac_net::types::{Announce, SignedAnnounce};

use ecac_store::Store;
use std::sync::Once;

fn init_tracing() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
    });
}

fn loopback_addr() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}

// Poll both swarms in alternating order to avoid bias.
async fn tick_both(a: &mut Node, b: &mut Node) -> Result<bool> {
    let mut progressed = false;
    tokio::select! {
        r = a.poll_once() => { progressed |= r?; }
        r = b.poll_once() => { progressed |= r?; }
    }
    tokio::select! {
        r = b.poll_once() => { progressed |= r?; }
        r = a.poll_once() => { progressed |= r?; }
    }
    yield_now().await;
    Ok(progressed)
}

/// Build a deterministic small DAG of N ops (with some branching) under one keypair.
fn make_ops(n: usize) -> (Vec<Op>, std::collections::HashMap<OpId, Vec<OpId>>) {
    use std::collections::HashMap;
    let (sk, vk) = generate_keypair();
    let vk_bytes = vk_to_bytes(&vk);

    let mut ops: Vec<Op> = Vec::with_capacity(n);
    let mut parents_map: HashMap<OpId, Vec<OpId>> = HashMap::with_capacity(n);

    for i in 0..n {
        // Parent selection: mix chains and occasional two-parent merges, deterministic.
        let parents: Vec<OpId> = if i == 0 {
            vec![]
        } else if i % 5 == 0 && i >= 2 {
            vec![ops[i - 1].op_id, ops[i - 2].op_id]
        } else if i % 7 == 0 && i >= 3 {
            vec![ops[i - 1].op_id, ops[i - 3].op_id]
        } else {
            vec![ops[i - 1].op_id]
        };

        let hlc = Hlc::new(10_000 + i as u64, (i % 4) as u32);
        let payload = Payload::Data {
            key: format!("obj{}.field{}", i % 3, i % 2),
            value: format!("val{}", i).into_bytes(),
        };

        let op = Op::new(parents.clone(), hlc, vk_bytes, payload, &sk);
        parents_map.insert(op.op_id, parents);
        ops.push(op);
    }

    (ops, parents_map)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_node_sync_minimal_converges_parent_first() -> Result<()> {

    init_tracing();
    
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("ecac_net=trace,libp2p_swarm=info,libp2p_request_response=info"),
    )
    .is_test(true)
    .try_init();

    // Generate deterministic DAG
    let n = 60;
    let (ops, parents_map) = make_ops(n);

    // Stores: A preloaded, B empty
    let tmp_a = tempfile::tempdir()?;
    let tmp_b = tempfile::tempdir()?;
    let store_a = Store::open(tmp_a.path(), Default::default())?;
    let store_b = Store::open(tmp_b.path(), Default::default())?;

    for op in &ops {
        let bytes = canonical_cbor(op);
        store_a.put_op_cbor(&bytes)?;
    }

    // Nodes
    let mut a = Node::new("proj")?;
    let mut b = Node::new("proj")?;

    // Provider on A: return exact op bytes for any requested id
    let store_a_clone = store_a.clone();
    let a_pid = a.peer_id;
    a.set_fetch_bytes_provider(move |id: &OpId| {
        eprintln!("[{:?}] provider asked for {}", a_pid, hex::encode(id));
        store_a_clone.get_op_bytes(id).ok().flatten()
    });

    // Planner providers + ingest sink on B
    let store_b_for_have = store_b.clone();
    let parents_map = std::sync::Arc::new(parents_map);
    let parents_map_for_fn = parents_map.clone();
    b.set_sync_providers(
        move |id: &OpId| store_b_for_have.contains(id).unwrap_or(false),
        move |id: &OpId| parents_map_for_fn.get(id).cloned().unwrap_or_default(),
    );
    let store_b_for_put = store_b.clone();
    b.set_ingest_bytes_sink(move |bytes: &[u8]| store_b_for_put.put_op_cbor(bytes));

    // Listen + connect
    a.listen(loopback_addr())?;
    b.listen(loopback_addr())?;

    // Wait for listen addrs
    let a_addr = timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(addr) = a.listen_addr_rx.try_recv() {
                break Ok::<_, anyhow::Error>(addr);
            }
            let _ = tick_both(&mut a, &mut b).await?;
        }
    })
    .await??;

    let b_addr = timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(addr) = b.listen_addr_rx.try_recv() {
                break Ok::<_, anyhow::Error>(addr);
            }
            let _ = tick_both(&mut a, &mut b).await?;
        }
    })
    .await??;

    a.add_peer(b.peer_id, b_addr.clone())?;

    // Make gossip robust: be explicit peers and (re)subscribe (both are idempotent).
a.add_gossip_explicit_peer(b.peer_id);
b.add_gossip_explicit_peer(a.peer_id);
let _ = a.subscribe_announce();
let _ = b.subscribe_announce();

    // Wait until connected both ways
    timeout(Duration::from_secs(20), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            if a.is_connected_to(&b.peer_id) && b.is_connected_to(&a.peer_id) {
                break Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await??;

  // Build Announce from A (heads + bloom from A)
let heads_a = store_a.heads(8)?;
let bloom_a = store_a.recent_bloom(64)?;
let sa = SignedAnnounce {
    announce: Announce {
        node_id: [0u8; 32],
        topo_watermark: 0,
        head_ids: heads_a.clone(),
        bloom16: bloom_a,
    },
    sig: vec![],
    vk: [0u8; 32],
};

// Retry publish until gossipsub accepts (i.e., A sees at least one subscribed peer)
let mut attempts = 0usize;
timeout(Duration::from_secs(10), async {
    loop {
        attempts += 1;

        // Drive both swarms
        let _ = tick_both(&mut a, &mut b).await?;

        // Only attempt publish once we (A) actually see a subscribed peer for the topic
        let subc = a.announce_subscribed_count();
        if subc == 0 {
            if attempts % 10 == 0 {
                eprintln!("[TEST] attempt #{attempts}: still 0 subscribed peers at A; connected(a->b)={}, connected(b->a)={}",
                    a.is_connected_to(&b.peer_id),
                    b.is_connected_to(&a.peer_id)
                );
            }
            continue;
        }

        match a.publish_announce(&sa) {
            Ok(()) | Err(PublishError::Duplicate) => {
                eprintln!("[TEST] publish accepted after {attempts} attempts (A sees {subc} subscribed)");
                break Ok::<_, anyhow::Error>(());
            }
            Err(PublishError::InsufficientPeers) => {
                eprintln!("[TEST] attempt #{attempts}: PublishError::InsufficientPeers (A sees {subc} subscribed)");
                // Keep ticking; gossipsub internal view can lag even after Subscribed
                continue;
            }
            Err(e) => anyhow::bail!("[TEST] unexpected publish error: {:?}", e),
        }
    }
})
.await??;


// Drive both swarms until B has ingested all N ops.
timeout(Duration::from_secs(15), async {
    loop {
        let _ = tick_both(&mut a, &mut b).await?;
        let count_b = store_b.topo_ids()?.len();
        if count_b >= n {
            break Ok::<_, anyhow::Error>(());
        }
    }
})
.await??;


    // Asserts: same op count and heads
    let count_a = store_a.topo_ids()?.len();
    let count_b = store_b.topo_ids()?.len();
    assert_eq!(count_a, n);
    assert_eq!(count_b, n);

    let heads_b = store_b.heads(8)?;
    assert_eq!(heads_a, heads_b, "heads diverged");

    // Deterministic replay equality (digest)
    let ids_a = store_a.topo_ids()?;
    let ids_b = store_b.topo_ids()?;
    let bytes_a = store_a.load_ops_cbor(&ids_a)?;
    let bytes_b = store_b.load_ops_cbor(&ids_b)?;

    let mut dag_a = Dag::new();
    for b in &bytes_a {
        let op: Op = serde_cbor::from_slice(b)?;
        dag_a.insert(op);
    }
    let mut dag_b = Dag::new();
    for b in &bytes_b {
        let op: Op = serde_cbor::from_slice(b)?;
        dag_b.insert(op);
    }

    // A serves bytes from its store
let store_a2 = store_a.clone();
a.set_fetch_bytes_provider(move |id: &OpId| {
    store_a2.get_op_bytes(id).ok().flatten()
});

// B ingests via its store (verifies id+sig; exact bytes)
let store_b2 = store_b.clone();
b.set_ingest_bytes_sink(move |bytes: &[u8]| store_b2.put_op_cbor(bytes));

    let (_state_a, digest_a) = replay_full(&dag_a);
    let (_state_b, digest_b) = replay_full(&dag_b);
    assert_eq!(digest_a, digest_b, "replay digests differ");

    Ok(())
}
