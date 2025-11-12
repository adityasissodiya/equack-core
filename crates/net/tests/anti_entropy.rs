use anyhow::Result;
use libp2p::Multiaddr;
use tokio::task::yield_now;
use tokio::time::{timeout, Duration};

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::replay::replay_full;
use ecac_core::serialize::canonical_cbor;

use ecac_net::serializer::sign_announce;
use ecac_net::transport::Node;

use ecac_store::Store;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn loopback_addr() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}

async fn tick_both(a: &mut Node, b: &mut Node) -> Result<bool> {
    let mut progressed = false;
    tokio::select! { r = a.poll_once() => { progressed |= r?; } r = b.poll_once() => { progressed |= r?; } }
    tokio::select! { r = b.poll_once() => { progressed |= r?; } r = a.poll_once() => { progressed |= r?; } }
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
async fn anti_entropy_round_converges() -> Result<()> {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .is_test(true)
        .try_init();

    let n = 64;
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
    let store_a_clone_for_provider = store_a.clone();
    a.set_fetch_bytes_provider(move |id: &OpId| {
        store_a_clone_for_provider.get_op_bytes(id).ok().flatten()
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

    // Wire ANNOUNCE sources (heads+bloom) + signer for both nodes.
    let mut rng = OsRng;
    let sk_a = SigningKey::generate(&mut rng);
    let sk_b = SigningKey::generate(&mut rng);

    // Helper: NodeId = blake3(vk_bytes)
    let node_id_of =
        |sk: &SigningKey| -> [u8; 32] { *blake3::hash(&sk.verifying_key().to_bytes()).as_bytes() };

    // ---- A wires to its store (clone per-closure to avoid moves) ----
    let sk_a_clone = sk_a.clone();
    let store_a_for_watermark = store_a.clone();
    let store_a_for_heads = store_a.clone();
    let store_a_for_bloom = store_a.clone();
    a.set_announce_sources(
        move || node_id_of(&sk_a_clone),
        move || {
            store_a_for_watermark
                .get_topo_watermark()
                .ok()
                .flatten()
                .unwrap_or(0)
        },
        move |k| store_a_for_heads.heads(k).unwrap_or_default(),
        move |n| store_a_for_bloom.recent_bloom(n).unwrap_or([0; 2]),
        move |ann| sign_announce(ann, &sk_a),
    );

    // ---- B wires to its store (clone per-closure to avoid moves) ----
    let sk_b_clone = sk_b.clone();
    let store_b_for_watermark = store_b.clone();
    let store_b_for_heads = store_b.clone();
    let store_b_for_bloom = store_b.clone();
    b.set_announce_sources(
        move || node_id_of(&sk_b_clone),
        move || {
            store_b_for_watermark
                .get_topo_watermark()
                .ok()
                .flatten()
                .unwrap_or(0)
        },
        move |k| store_b_for_heads.heads(k).unwrap_or_default(),
        move |n| store_b_for_bloom.recent_bloom(n).unwrap_or([0; 2]),
        move |ann| sign_announce(ann, &sk_b),
    );

    // Listen + connect
    a.listen(loopback_addr())?;
    b.listen(loopback_addr())?;

    // Wait for listen addrs
    let a_addr = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(addr) = a.listen_addr_rx.try_recv() {
                break Ok::<_, anyhow::Error>(addr);
            }
            let _ = tick_both(&mut a, &mut b).await?;
        }
    })
    .await??;

    let b_addr = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(addr) = b.listen_addr_rx.try_recv() {
                break Ok::<_, anyhow::Error>(addr);
            }
            let _ = tick_both(&mut a, &mut b).await?;
        }
    })
    .await??;

    a.add_peer(b.peer_id, b_addr.clone())?;

    // Make gossip robust: be explicit peers and subscribe (idempotent)
    a.add_gossip_explicit_peer(b.peer_id);
    b.add_gossip_explicit_peer(a.peer_id);
    let _ = a.subscribe_announce();
    let _ = b.subscribe_announce();

    // Start periodic anti-entropy (short period for tests)
    a.start_anti_entropy(Duration::from_millis(150), 8, 64);
    b.start_anti_entropy(Duration::from_millis(150), 8, 64);

    // Wait until connected both ways
    timeout(Duration::from_secs(10), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            if a.is_connected_to(&b.peer_id) && b.is_connected_to(&a.peer_id) {
                break Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await??;

    // Drive both swarms until B has ingested all N ops (no explicit publish anywhere).
    timeout(Duration::from_secs(10), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            let count_b = store_b.topo_ids()?.len();
            if count_b >= n {
                break Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await??;

    // Sanity: deterministic replay equality
    let ids_a = store_a.topo_ids()?;
    let ids_b = store_b.topo_ids()?;
    assert_eq!(ids_a.len(), n);
    assert_eq!(ids_b.len(), n);

    let bytes_a = store_a.load_ops_cbor(&ids_a)?;
    let bytes_b = store_b.load_ops_cbor(&ids_b)?;
    let mut dag_a = Dag::new();
    for bts in &bytes_a {
        dag_a.insert(serde_cbor::from_slice::<Op>(bts)?);
    }
    let mut dag_b = Dag::new();
    for bts in &bytes_b {
        dag_b.insert(serde_cbor::from_slice::<Op>(bts)?);
    }

    let (_state_a, dig_a) = replay_full(&dag_a);
    let (_state_b, dig_b) = replay_full(&dag_b);
    assert_eq!(dig_a, dig_b, "replay digests differ");

    Ok(())
}
