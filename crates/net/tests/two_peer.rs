// crates/net/tests/two_peer.rs
use anyhow::Result;
use libp2p::Multiaddr;
use tokio::task::yield_now;
use tokio::time::{timeout, Duration};

use ecac_core::op::OpId;
use ecac_net::transport::Node;
use ecac_net::types::{FetchMissing, RpcFrame};

// Helper
fn loopback_addr() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}

// Drive both swarms once; return true if either made progress.
async fn tick_both(a: &mut Node, b: &mut Node) -> anyhow::Result<bool> {
    let mut progressed = false;

    // First poll whichever is ready first.
    tokio::select! {
        r = a.poll_once() => { progressed |= r?; }
        r = b.poll_once() => { progressed |= r?; }
    }

    // Then poll in the opposite order to avoid bias.
    tokio::select! {
        r = b.poll_once() => { progressed |= r?; }
        r = a.poll_once() => { progressed |= r?; }
    }

    // Give the scheduler a chance to run keepalive/ping timers.
    yield_now().await;

    Ok(progressed)
}

// Wait until `node.listen_addr_rx` yields an addr, driving both nodes meanwhile.
async fn get_listen_addr(
    a: &mut Node,
    b: &mut Node,
    which_a: bool,
    dur: Duration,
) -> Result<Multiaddr> {
    timeout(dur, async {
        loop {
            if which_a {
                if let Ok(addr) = a.listen_addr_rx.try_recv() {
                    return Ok(addr);
                }
            } else {
                if let Ok(addr) = b.listen_addr_rx.try_recv() {
                    return Ok(addr);
                }
            }
            let _ = tick_both(a, b).await?;
        }
    })
    .await?
}

// 1) Transport emits listen addresses
#[tokio::test(flavor = "multi_thread")]
async fn emits_listen_addrs() -> Result<()> {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("ecac_net=trace,libp2p_swarm=info"),
    )
    .is_test(true)
    .try_init();

    let mut a = Node::new("proj")?;
    let mut b = Node::new("proj")?;

    a.listen(loopback_addr())?;
    b.listen(loopback_addr())?;

    let a_addr = get_listen_addr(&mut a, &mut b, true, Duration::from_secs(10)).await?;
    let b_addr = get_listen_addr(&mut a, &mut b, false, Duration::from_secs(10)).await?;

    assert!(a_addr.to_string().starts_with("/ip4/127.0.0.1/tcp/"));
    assert!(b_addr.to_string().starts_with("/ip4/127.0.0.1/tcp/"));
    Ok(())
}

// 2) Two peers connect (no pubsub)
#[tokio::test(flavor = "multi_thread")]
async fn connects_two_peers() -> Result<()> {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("ecac_net=trace,libp2p_swarm=info"),
    )
    .is_test(true)
    .try_init();

    let mut a = Node::new("proj")?;
    let mut b = Node::new("proj")?;

    a.listen(loopback_addr())?;
    b.listen(loopback_addr())?;

    let _a_addr = get_listen_addr(&mut a, &mut b, true, Duration::from_secs(10)).await?;
    let b_addr = get_listen_addr(&mut a, &mut b, false, Duration::from_secs(10)).await?;

    a.add_peer(b.peer_id, b_addr)?;

    timeout(Duration::from_secs(20), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            if a.is_connected_to(&b.peer_id) && b.is_connected_to(&a.peer_id) {
                break Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await??;

    Ok(())
}

// 3) RR fetch without provider (server surfaces request; test replies OpBytes+End)
#[tokio::test(flavor = "multi_thread")]
async fn rr_fetch_roundtrip_via_channel() -> Result<()> {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("ecac_net=trace,libp2p_request_response=debug,libp2p_swarm=info"),
    )
    .is_test(true)
    .try_init();

    let mut a = Node::new("proj")?;
    let mut b = Node::new("proj")?;

    a.listen(loopback_addr())?;
    b.listen(loopback_addr())?;

    let _a_addr = get_listen_addr(&mut a, &mut b, true, Duration::from_secs(10)).await?;
    let b_addr = get_listen_addr(&mut a, &mut b, false, Duration::from_secs(10)).await?;

    a.add_peer(b.peer_id, b_addr)?;

    timeout(Duration::from_secs(20), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            if a.is_connected_to(&b.peer_id) && b.is_connected_to(&a.peer_id) {
                break Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await??;

    // Client A sends FetchMissing
    let req = FetchMissing {
        want: vec![[9u8; 32]],
    };
    let _rid = a.send_fetch(b.peer_id, req);

    // Server B should get the request via rpc_req_rx; reply with bytes then End
    timeout(Duration::from_secs(15), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            if let Ok((_peer, ch, _req)) = b.rpc_req_rx.try_recv() {
                b.respond_fetch(ch, RpcFrame::OpBytes(vec![0xAA]));
                // optional: send End so client knows stream is finished
                // b.respond_fetch(ch, RpcFrame::End);
                break Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await??;

    // Client A must receive at least the OpBytes
    timeout(Duration::from_secs(10), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            if let Ok((_peer, _req_id, frame)) = a.rr_resp_rx.try_recv() {
                match frame {
                    RpcFrame::OpBytes(bytes) => {
                        assert_eq!(bytes, vec![0xAA]);
                        break Ok::<_, anyhow::Error>(());
                    }
                    RpcFrame::End => {
                        // if server chose to send End first, it is still a valid response
                        break Ok::<_, anyhow::Error>(());
                    }
                    _ => {}
                }
            }
        }
    })
    .await??;

    Ok(())
}

// 4) RR fetch with provider (matches current provider semantics: first match OR End)
#[tokio::test(flavor = "multi_thread")]
async fn rr_fetch_with_provider_minimal() -> Result<()> {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("ecac_net=trace,libp2p_request_response=debug,libp2p_swarm=info"),
    )
    .is_test(true)
    .try_init();

    let mut a = Node::new("proj")?;
    let mut b = Node::new("proj")?;

    a.listen(loopback_addr())?;
    b.listen(loopback_addr())?;

    let _a_addr = get_listen_addr(&mut a, &mut b, true, Duration::from_secs(10)).await?;
    let b_addr = get_listen_addr(&mut a, &mut b, false, Duration::from_secs(10)).await?;

    a.add_peer(b.peer_id, b_addr)?;

    timeout(Duration::from_secs(20), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            if a.is_connected_to(&b.peer_id) && b.is_connected_to(&a.peer_id) {
                break Ok::<_, anyhow::Error>(());
            }
        }
    })
    .await??;

    // Install minimal provider on B: returns bytes only for [9;32]
    let b_pid = b.peer_id;
    b.set_fetch_bytes_provider(move |id: &OpId| {
        eprintln!("[{:?}] provider asked for {:?}", b_pid, id);
        if *id == [9u8; 32] {
            Some(vec![0xAA])
        } else {
            None
        }
    });

    // A asks for three ids; current provider sends *one* OpBytes for the first match OR End
    let want = vec![[9u8; 32], [10u8; 32], [11u8; 32]];
    let _rid = a.send_fetch(b.peer_id, FetchMissing { want });

    // A should receive either OpBytes(0xAA) or End (if no match). Assert the 0xAA path.
    timeout(Duration::from_secs(5), async {
        loop {
            let _ = tick_both(&mut a, &mut b).await?;
            if let Ok((_peer, _req_id, frame)) = a.rr_resp_rx.try_recv() {
                match frame {
                    RpcFrame::OpBytes(bytes) => {
                        assert_eq!(bytes, vec![0xAA]);
                        break Ok::<_, anyhow::Error>(());
                    }
                    RpcFrame::End => {
                        panic!("provider returned End without matching id; expected OpBytes for [9;32]");
                    }
                    _ => {}
                }
            }
        }
    }).await??;

    Ok(())
}
