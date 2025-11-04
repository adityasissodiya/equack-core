// crates/net/tests/two_peer.rs
use std::time::Duration;
use libp2p::Multiaddr;
use anyhow::Result;
//use tokio::time::{timeout, sleep};
use tokio::time::timeout;
use ecac_net::transport::Node;
use ecac_net::types::{FetchMissing, RpcFrame, Announce, SignedAnnounce};
use ecac_net::gossip::announce_topic;

// tiny helper
fn loopback_addr() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}

// Minimal test helper: build a syntactically-valid SignedAnnounce.
fn mk_test_signed_announce() -> SignedAnnounce {
        SignedAnnounce {
            announce: Announce {
                node_id: [0u8; 32],
                topo_watermark: 0,
                head_ids: Vec::new(),
                bloom16: [0u8; 2],
            },
            // For tests we don't validate the signature; serializer just (de)serializes.
            sig: vec![0u8; 64],
            vk: [0u8; 32],
        }
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

        // Ensure both sides are SUBSCRIBED to the announce topic before publishing.
    a.subscribe_announce()?;
    b.subscribe_announce()?;

    // Give gossipsub a short moment to exchange subscription control messages.
    let _ = timeout(Duration::from_millis(300), async {
        // a few cooperative ticks so the SUBSCRIBE propagates
        for _ in 0..20 {
            tokio::select! {
                r = a.poll_once() => { let _ = r; }
                r = b.poll_once() => { let _ = r; }
            }
        }
    }).await;


        // --- Exercise gossipsub announce path once on each side (anti-entropy publish hook) ---
        let sa_a = mk_test_signed_announce();
        let sa_b = mk_test_signed_announce();
        a.publish_announce(&sa_a)?;
        b.publish_announce(&sa_b)?;
    // Drive both swarms briefly to flush gossipsub processing (no assertions; smoke only).
    let _ = timeout(Duration::from_secs(1), async {
        loop {
            tokio::select! {
                r = a.poll_once() => { r?; }
                r = b.poll_once() => { r?; }
            }
            // a tiny delay: break after some progress so we don't spin forever in case of flakiness
            if false { break Ok::<_, anyhow::Error>(()); }
        }
    }).await.ok();


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

        // Now assert A actually got the response frame.
        let got_resp = timeout(Duration::from_secs(3), async {
            loop {
                let _ = a.poll_once().await?;
                let _ = b.poll_once().await?;
                if let Ok((peer, _req_id, frame)) = a.rr_resp_rx.try_recv() {
                    assert_eq!(peer, b.peer_id, "response should come from B");
                    match frame {
                        RpcFrame::OpBytes(bytes) => {
                            assert_eq!(bytes, vec![1,2,3]);
                            break Ok::<_, anyhow::Error>(());
                        }
                        other => panic!("unexpected frame: {:?}", other),
                    }
                }
            }
        }).await;
        assert!(got_resp.is_ok(), "timed out waiting for RR response at client side");

        // Negative path: send a request to a random peer with no known addresses; expect OutboundFailure.
    let bogus_peer = {
            let kp = libp2p::identity::Keypair::generate_ed25519();
            libp2p::PeerId::from(kp.public())
        };
        let _rid2 = a.send_fetch(bogus_peer, FetchMissing { want: vec![] });
    
                // Drive both swarms; after each tick, try to drain the failure channels.
                // Using try_recv avoids aliasing &mut borrows of `a`/`b` in `tokio::select!`.
                let got_fail = timeout(Duration::from_secs(5), async {
                    loop {
                        tokio::select! {
                            r = a.poll_once() => { r?; }
                            r = b.poll_once() => { r?; }
                        }
                        if let Ok((peer, _req_id, err)) = a.rr_out_fail_rx.try_recv() {
                            assert_eq!(peer, Some(bogus_peer),
                                "failure should pertain to the bogus peer we requested");
                            assert!(matches!(err,
                                libp2p::request_response::OutboundFailure::DialFailure
                                | libp2p::request_response::OutboundFailure::UnsupportedProtocols
                                | libp2p::request_response::OutboundFailure::ConnectionClosed
                                | libp2p::request_response::OutboundFailure::Timeout
                            ), "unexpected outbound failure: {:?}", err);
                            break Ok::<_, anyhow::Error>(());
                        }
                        if let Ok((peer, _req_id, err)) = b.rr_out_fail_rx.try_recv() {
                            // Defensive: if the bogus request were ever sent from B by mistake,
                            // don't hang—still validate and break.
                            assert_eq!(peer, Some(bogus_peer),
                                "failure should pertain to the bogus peer we requested");
                            assert!(matches!(err,
                                libp2p::request_response::OutboundFailure::DialFailure
                                | libp2p::request_response::OutboundFailure::UnsupportedProtocols
                                | libp2p::request_response::OutboundFailure::ConnectionClosed
                                | libp2p::request_response::OutboundFailure::Timeout
                            ), "unexpected outbound failure: {:?}", err);
                            break Ok::<_, anyhow::Error>(());
                        }
                    }
                }).await;
        assert!(got_fail.is_ok(), "timed out waiting for RR outbound failure on bogus peer");

            // --- Exercise gossipsub announce path on each side (now that both are subscribed) ---
    let sa_a = mk_test_signed_announce();
    let sa_b = mk_test_signed_announce();
    a.publish_announce(&sa_a)?;
    b.publish_announce(&sa_b)?;


    Ok(())
}
