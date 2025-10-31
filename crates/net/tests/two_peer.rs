// crates/net/tests/two_peer.rs
use std::time::Duration;
use libp2p::Multiaddr;
use anyhow::Result;
use tokio::time::{timeout, sleep};

use ecac_net::transport::Node;
use ecac_net::types::{FetchMissing, RpcFrame};

// tiny helper
fn loopback_addr() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn two_peer_gossip_and_fetch() -> Result<()> {
    // Respect RUST_LOG if provided; otherwise use a sane default
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(
            "ecac_net=trace,libp2p_swarm=info,libp2p_request_response=debug,libp2p_gossipsub=debug"
        )
    ).is_test(true).try_init();

    let mut a = Node::new("proj").expect("node a");
    let mut b = Node::new("proj").expect("node b");

    // Start listeners and drive until we learn the listen addrs.
    a.listen(loopback_addr()).unwrap();
    b.listen(loopback_addr()).unwrap();

    let _a_addr = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(addr) = a.listen_addr_rx.try_recv() { break addr; }
            // Drive both concurrently while we wait for either side to emit an event
            tokio::select! {
                r = a.poll_once() => { r.unwrap(); }
                r = b.poll_once() => { r.unwrap(); }
            }
        }
    }).await.expect("a listen addr timeout");

    let b_addr = timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(addr) = b.listen_addr_rx.try_recv() { break addr; }
            tokio::select! {
                r = a.poll_once() => { r.unwrap(); }
                r = b.poll_once() => { r.unwrap(); }
            }
        }
    }).await.expect("b listen addr timeout");

    // Single-direction dial to avoid simultaneous dial races during handshake
    a.add_peer(b.peer_id, b_addr.clone())?;

    // Drive both swarms concurrently until *both* report connected.
    timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                r = a.poll_once() => { r?; }
                r = b.poll_once() => { r?; }
            }
            if a.is_connected_to(&b.peer_id) && b.is_connected_to(&a.peer_id) {
                break Ok::<_, anyhow::Error>(());
            }
        }
    }).await.expect("connectivity timeout").unwrap();

    // Now request-response should be safe to use.
    let req = FetchMissing { want: vec![[9u8; 32], [10u8; 32]] };
    let _id = a.send_fetch(b.peer_id, req);

    // Drive until B (the server side) receives a fetch request.
    let got_req = timeout(Duration::from_secs(5), async {
        loop {
            // Progress whichever side has work, first.
            tokio::select! {
                r = a.poll_once() => { r?; }
                r = b.poll_once() => { r?; }
            }

            // Handle inbound request on B when it arrives.
            if let Ok((_peer, ch, _req)) = b.rpc_req_rx.try_recv() {
                // Send a single data frame; if you want a second frame (End), call respond_fetch again.
                b.respond_fetch(ch, RpcFrame::OpBytes(vec![1,2,3]));
                break Ok::<_, anyhow::Error>(());
            }
        }
    }).await;

    assert!(got_req.is_ok(), "timed out waiting for RR request at server side");

    // Flush a few more events to settle the pipe
    for _ in 0..20 {
        tokio::select! {
            r = a.poll_once() => { let _ = r?; }
            r = b.poll_once() => { let _ = r?; }
            _ = sleep(Duration::from_millis(10)) => {}
        }
    }

    Ok(())
}
