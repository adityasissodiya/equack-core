use std::{env, fs, path::PathBuf};

use ecac_core::dag::Dag;
use ecac_core::op::{Op, Payload};
use ecac_core::policy::{build_auth_epochs_with, derive_action_and_tags, is_permitted_at_pos};
use ecac_core::status::StatusCache;
use ecac_core::trust::TrustStore;

fn read_ops(path: &str) -> anyhow::Result<Vec<Op>> {
    let bytes = fs::read(path)?;
    if let Ok(v) = serde_cbor::from_slice::<Vec<Op>>(&bytes) {
        return Ok(v);
    }
    if let Ok(op) = serde_cbor::from_slice::<Op>(&bytes) {
        return Ok(vec![op]);
    }
    anyhow::bail!("{}: not a CBOR Vec<Op> or Op", path);
}

fn hex32(arr: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in arr {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn main() -> anyhow::Result<()> {
    // Args: <op.cbor>...
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() {
        eprintln!("usage: vc_replay <op_or_vec1.cbor> [more.cbor ...]");
        std::process::exit(2);
    }

    // Build DAG
    let mut dag = Dag::new();
    let mut ids_in = Vec::new();
    for p in &args {
        for op in read_ops(p)? {
            ids_in.push(op.op_id);
            dag.insert(op);
        }
    }
    let order = dag.topo_sort();

    // Load trust/status and build VC-backed epochs
    let trust = TrustStore::load_from_dir("./trust")
        .map_err(|e| anyhow::anyhow!("trust load failed: {:?}", e))?;
    let mut status = StatusCache::load_from_dir("./trust/status");
    let idx = build_auth_epochs_with(&dag, &order, &trust, &mut status);

    println!(
        "order=[{}]",
        order.iter().map(hex32).collect::<Vec<_>>().join(",")
    );

    // Walk data ops and decide allow/deny at their position.
    for (pos, id) in order.iter().enumerate() {
        let op = dag.get(id).unwrap();
        if let Payload::Data { key, .. } = &op.header.payload {
            if let Some((action, _obj, _field, _elem, tags)) = derive_action_and_tags(key) {
                let allow =
                    is_permitted_at_pos(&idx, &op.header.author_pk, action, &tags, pos, op.hlc());
                println!(
                    "{}: {} → {}",
                    hex32(id),
                    key,
                    if allow { "ALLOWED" } else { "DENIED" }
                );
            }
        }
    }

    Ok(())
}
