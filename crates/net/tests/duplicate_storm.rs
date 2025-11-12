use anyhow::Result;
use libp2p::gossipsub::PublishError;
use libp2p::Multiaddr;
use tokio::task::yield_now;
use tokio::time::{sleep, timeout, Duration};

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::serialize::canonical_cbor;

use ecac_net::transport::Node;
use ecac_net::types::{Announce, SignedAnnounce};
use ecac_store::Store;

async fn tick_both(a: &mut Node, b: &mut Node) -> Result<bool> {
    let mut progressed = false;
    tokio::select! { r = a.poll_once() => { progressed |= r?; } r = b.poll_once() => { progressed |= r?; } }
    tokio::select! { r = b.poll_once() => { progressed |= r?; } r = a.poll_once() => { progressed |= r?; } }
    yield_now().await;
    Ok(progressed)
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_announce_storm_is_ignored() -> Result<()> {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .is_test(true)
        .try_init();

    // Minimal content: one op in A
    let (sk, vk) = generate_keypair();
    let vk_bytes = vk_to_bytes(&vk);
    let payload = Payload::Data {
        key: "noop".into(),
        value: Vec::new(),
    };
    let op = Op::new(vec![], Hlc::new(100, 0), vk_bytes, payload, &sk);

    let tmp_a = tempfile::tempdir()?;
    let tmp_b = tempfile::tempdir()?;
    let store_a = Store::open(tmp_a.path(), Default::default())?;
    let store_b = Store::open(tmp_b.path(), Default::default())?;
    store_a.put_op_cbor(&canonical_cbor(&op))?;

    let mut a = Node::new("proj")?;
    let mut b = Node::new("proj")?;

    // Provider on A
    let store_a2 = store_a.clone();
    a.set_fetch_bytes_provider(move |id| store_a2.get_op_bytes(id).ok().flatten());
    // Ingest on B
    let store_b2 = store_b.clone();
    b.set_ingest_bytes_sink(move |bytes| store_b2.put_op_cbor(bytes));
    // Planner on B
    let store_b_have = store_b.clone();
    b.set_sync_providers(
        move |id| store_b_have.contains(id).unwrap_or(false),
        move |_id| vec![],
    );

    // Listen/connect/subscribe
    a.listen("/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap())?;
    b.listen("/ip4/127.0.0.1/tcp/0".parse::<Multiaddr>().unwrap())?;

    let _a_addr = timeout(Duration::from_secs(5), async {
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

    a.add_peer(b.peer_id, b_addr)?;
    a.add_gossip_explicit_peer(b.peer_id);
    b.add_gossip_explicit_peer(a.peer_id);
    let _ = a.subscribe_announce();
    let _ = b.subscribe_announce();

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

    // Wait until A sees at least one subscribed peer on the announce topic.
    timeout(Duration::from_secs(10), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            if a.announce_subscribed_count() > 0 {
                break Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await??;

    /// Give gossip a brief settle time for membership/fanout before we publish.
    timeout(Duration::from_secs(1), async {
        // ~ a few hundred ms of ticks is plenty with 200ms heartbeat
        for _ in 0..10 {
            let _ = tick_both(&mut a, &mut b).await?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;

    // Build the announce (same as you already do)
    let heads = store_a.heads(8)?;
    let bloom = store_a.recent_bloom(32)?;
    let sa = SignedAnnounce {
        announce: Announce {
            node_id: [0u8; 32],
            topo_watermark: 0,
            head_ids: heads.clone(),
            bloom16: bloom,
        },
        sig: vec![],
        vk: [0u8; 32],
    };

    // Robust publish: keep retrying on InsufficientPeers until one publish succeeds.
    use libp2p::gossipsub::PublishError;
    let mut published_once = false;

    timeout(Duration::from_secs(3), async {
        loop {
            match a.publish_announce(&sa) {
                Ok(()) => {
                    published_once = true;
                    break Ok::<_, anyhow::Error>(());
                }
                Err(PublishError::InsufficientPeers) => {
                    // drive both swarms, then try again
                    let _ = tick_both(&mut a, &mut b).await?;
                    continue;
                }
                Err(e) => anyhow::bail!("unexpected publish error: {:?}", e),
            }
        }
    })
    .await??;

    assert!(published_once, "never managed to publish to any peers");
    // *** Mesh warm-up ***
    // Gossipsub only forms/updates the mesh on its heartbeat. Give it ~1 heartbeat.
    sleep(Duration::from_millis(1200)).await;
    // Drive once more so both sides process any heartbeats before we publish.
    let _ = tick_both(&mut a, &mut b).await?;

    // Build a one-shot announce from A
    let heads = store_a.heads(8)?;
    let bloom = store_a.recent_bloom(32)?;
    let sa = SignedAnnounce {
        announce: Announce {
            node_id: [0u8; 32],
            topo_watermark: 0,
            head_ids: heads.clone(),
            bloom16: bloom,
        },
        sig: vec![],
        vk: [0u8; 32],
    };

    // Publish once, retrying until gossipsub accepts (handles transient InsufficientPeers).
    timeout(Duration::from_secs(10), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            match a.publish_announce(&sa) {
                Ok(()) | Err(PublishError::Duplicate) => break Ok::<_, anyhow::Error>(()),
                Err(PublishError::InsufficientPeers) => continue, // keep driving and retry
                Err(e) => anyhow::bail!("unexpected publish error: {:?}", e),
            }
        }
    })
    .await??;

    // Storm: spam duplicates; they must be de-duped (no extra effects).
    for _ in 0..50 {
        match a.publish_announce(&sa) {
            Ok(()) | Err(PublishError::Duplicate) | Err(PublishError::InsufficientPeers) => { /* ignore */
            }
            Err(e) => anyhow::bail!("unexpected publish error during storm: {:?}", e),
        }
        let _ = tick_both(&mut a, &mut b).await?;
    }

    // Eventually B should fetch the single op and stop.
    timeout(Duration::from_secs(10), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            if store_b.topo_ids()?.len() >= 1 {
                break Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await??;

    Ok(())
}
