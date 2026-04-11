//! equack_node -- Minimal EQUACK network node for E16 multi-node experiment.
//!
//! Runs an HTTP server on port 9000 with background peer sync for testing
//! networked convergence under partition and delay.
//!
//! Environment variables:
//!   NODE_ID  - e.g., "node1"
//!   PEERS    - comma-separated "host:port", e.g., "equack-node2:9000,equack-node3:9000"
//!
//! HTTP API:
//!   GET  /api/state/digest  → {"digest":"<hex>","ops":<n>}
//!   POST /api/generate      (body: {"ops":<n>}) → generates hb-chain workload
//!   POST /api/sync          (body: CBOR Vec<OpId>) → returns CBOR Vec<Op> of missing ops

use std::collections::HashSet;
use std::env;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use ecac_core::crypto::vk_to_bytes;
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, OpId, Payload};
use ecac_core::replay;
use ed25519_dalek::SigningKey;

struct SharedState {
    dag: Dag,
    ops: Vec<Op>,
    known_ids: HashSet<OpId>,
    node_id: String,
    signing_key: SigningKey,
    pk_bytes: [u8; 32],
    hlc: Hlc,
    op_counter: u64,
}

fn main() {
    let node_id = env::var("NODE_ID").unwrap_or_else(|_| "node1".to_string());
    let peers_str = env::var("PEERS").unwrap_or_default();
    let peers: Vec<String> = if peers_str.is_empty() {
        vec![]
    } else {
        peers_str.split(',').map(|s| s.trim().to_string()).collect()
    };

    let node_num: u32 = node_id
        .strip_prefix("node")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let sk = derive_key(42, node_id.as_bytes());
    let pk = vk_to_bytes(&sk.verifying_key());

    let state = Arc::new(RwLock::new(SharedState {
        dag: Dag::new(),
        ops: Vec::new(),
        known_ids: HashSet::new(),
        node_id: node_id.clone(),
        signing_key: sk,
        pk_bytes: pk,
        hlc: Hlc::new(1000, node_num),
        op_counter: 0,
    }));

    eprintln!("[{}] starting on :9000, peers: {:?}", node_id, peers);

    // Background sync thread
    let sync_state = Arc::clone(&state);
    thread::spawn(move || sync_loop(sync_state, peers));

    // HTTP server
    let listener = TcpListener::bind("0.0.0.0:9000").expect("bind :9000");
    for stream in listener.incoming().flatten() {
        let st = Arc::clone(&state);
        thread::spawn(move || {
            if let Err(e) = handle_request(stream, &st) {
                eprintln!("[http] error: {}", e);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

fn handle_request(
    stream: TcpStream,
    state: &Arc<RwLock<SharedState>>,
) -> Result<(), Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    // Request line
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0];
    let path = parts[1];

    // Headers
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
        let lower = line.to_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }

    // Body
    let body = if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        reader.read_exact(&mut buf)?;
        buf
    } else {
        vec![]
    };

    // Route
    match (method, path) {
        ("GET", "/api/state/digest") => {
            let s = state.read().unwrap();
            let (_, digest) = replay::replay_full(&s.dag);
            let hex = to_hex(&digest[..8]);
            let n = s.dag.len();
            let resp = format!(r#"{{"digest":"{}","ops":{}}}"#, hex, n);
            send_response(&mut writer, 200, "application/json", resp.as_bytes())?;
        }
        ("POST", "/api/generate") => {
            let n = if body.is_empty() {
                1000
            } else {
                let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                v["ops"].as_u64().unwrap_or(1000) as usize
            };
            generate_ops(state, n);
            let s = state.read().unwrap();
            let resp = format!(
                r#"{{"generated":{},"total":{}}}"#,
                n,
                s.dag.len()
            );
            eprintln!("[{}] generated {} ops (total {})", s.node_id, n, s.dag.len());
            send_response(&mut writer, 200, "application/json", resp.as_bytes())?;
        }
        ("POST", "/api/sync") => {
            // Caller sends CBOR-encoded Vec<OpId> of IDs it already has.
            // We respond with CBOR-encoded Vec<Op> of ops the caller is missing.
            let their_ids: HashSet<OpId> = if body.is_empty() {
                HashSet::new()
            } else {
                let v: Vec<OpId> = serde_cbor::from_slice(&body)?;
                v.into_iter().collect()
            };
            let s = state.read().unwrap();
            let missing: Vec<Op> = s
                .ops
                .iter()
                .filter(|op| !their_ids.contains(&op.op_id))
                .cloned()
                .collect();
            let resp = serde_cbor::to_vec(&missing)?;
            send_response(&mut writer, 200, "application/cbor", &resp)?;
        }
        ("POST", "/api/ops/push") => {
            // Accept CBOR-encoded Vec<Op> and ingest them.
            let incoming: Vec<Op> = serde_cbor::from_slice(&body)?;
            let mut s = state.write().unwrap();
            let mut added = 0usize;
            for op in incoming {
                if s.known_ids.insert(op.op_id) {
                    s.dag.insert(op.clone());
                    s.ops.push(op);
                    added += 1;
                }
            }
            let resp = format!(r#"{{"added":{},"total":{}}}"#, added, s.dag.len());
            send_response(&mut writer, 200, "application/json", resp.as_bytes())?;
        }
        _ => {
            send_response(&mut writer, 404, "text/plain", b"not found")?;
        }
    }

    Ok(())
}

fn send_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        status_text,
        content_type,
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

// ---------------------------------------------------------------------------
// Workload generation
// ---------------------------------------------------------------------------

fn generate_ops(state: &Arc<RwLock<SharedState>>, n: usize) {
    let mut s = state.write().unwrap();
    let mut parents: Vec<OpId> = s.ops.last().map(|op| vec![op.op_id]).unwrap_or_default();

    for _ in 0..n {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        s.hlc.tick_local(now_ms);

        let payload = Payload::Data {
            key: format!("set+:o:x:{}v{}", s.node_id, s.op_counter),
            value: vec![],
        };

        let op = Op::new(parents, s.hlc, s.pk_bytes, payload, &s.signing_key);
        parents = vec![op.op_id];
        s.known_ids.insert(op.op_id);
        s.dag.insert(op.clone());
        s.ops.push(op);
        s.op_counter += 1;
    }
}

// ---------------------------------------------------------------------------
// Background sync
// ---------------------------------------------------------------------------

fn sync_loop(state: Arc<RwLock<SharedState>>, peers: Vec<String>) {
    // Wait for containers to start
    thread::sleep(Duration::from_secs(3));

    loop {
        for peer in &peers {
            match sync_with_peer(&state, peer) {
                Ok(n) if n > 0 => {
                    let s = state.read().unwrap();
                    eprintln!("[{}] synced {} ops from {}", s.node_id, n, peer);
                }
                Err(e) => {
                    // Expected during partitions; don't spam
                    let _ = e;
                }
                _ => {}
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

fn sync_with_peer(
    state: &Arc<RwLock<SharedState>>,
    peer: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    // Collect our known IDs
    let known_ids: Vec<OpId> = {
        let s = state.read().unwrap();
        s.known_ids.iter().cloned().collect()
    };

    let body = serde_cbor::to_vec(&known_ids)?;

    // Connect to peer
    let addr = peer
        .to_socket_addrs()?
        .next()
        .ok_or("DNS resolution failed")?;
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    // Send request
    let req = format!(
        "POST /api/sync HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: application/cbor\r\n\r\n",
        peer,
        body.len()
    );
    writer.write_all(req.as_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;

    // Read response status line
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;

    // Read headers
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() {
            break;
        }
        let lower = line.to_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }

    // Read body
    if content_length == 0 {
        return Ok(0);
    }
    let mut resp_body = vec![0u8; content_length];
    reader.read_exact(&mut resp_body)?;

    let missing_ops: Vec<Op> = serde_cbor::from_slice(&resp_body)?;
    if missing_ops.is_empty() {
        return Ok(0);
    }

    let count = missing_ops.len();
    let mut s = state.write().unwrap();
    for op in missing_ops {
        if s.known_ids.insert(op.op_id) {
            s.dag.insert(op.clone());
            s.ops.push(op);
        }
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn derive_key(seed: u64, label: &[u8]) -> SigningKey {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&seed.to_le_bytes());
    let h = blake3::hash(&[&input, label].concat());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&h.as_bytes()[..32]);
    SigningKey::from_bytes(&bytes)
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
