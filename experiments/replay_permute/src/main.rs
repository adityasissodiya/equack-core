use std::collections::HashMap;
use std::env;
use std::fs;

use anyhow::{anyhow, bail, Context, Result};
use blake3;
use ecac_core::dag::Dag;
use ecac_core::op::{Op, OpId};
use ecac_core::replay;
use ecac_core::{crypto::vk_to_bytes, hlc::Hlc, op::Payload};
use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use serde_cbor;

enum Source {
    File(String),
    Scenario {
        name: String,
        ops: usize,
        seed: u64,
        peers: usize,
    },
}

fn parse_args() -> Result<(Source, usize, u64)> {
    let mut args = env::args().skip(1);
    let mut source: Option<Source> = None;
    let mut trials: usize = 20;
    let mut seed: u64 = 42;
    let mut scenario: Option<String> = None;
    let mut ops: Option<usize> = None;
    let mut peers: usize = 4;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--scenario" => scenario = Some(args.next().ok_or_else(|| anyhow!("missing scenario"))?),
            "--ops" => {
                ops = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("missing --ops value"))?
                        .parse()
                        .context("invalid ops")?,
                )
            }
            "--peers" => {
                peers = args
                    .next()
                    .ok_or_else(|| anyhow!("missing --peers value"))?
                    .parse()
                    .context("invalid peers")?
            }
            "--trials" => {
                trials = args
                    .next()
                    .ok_or_else(|| anyhow!("missing --trials value"))?
                    .parse()
                    .context("invalid trials")?
            }
            "--seed" => {
                seed = args
                    .next()
                    .ok_or_else(|| anyhow!("missing --seed value"))?
                    .parse()
                    .context("invalid seed")?
            }
            other => {
                if source.is_none() {
                    source = Some(Source::File(other.to_string()));
                } else {
                    bail!("unexpected arg '{}'", other);
                }
            }
        }
    }

    if let Some(name) = scenario {
        let ops = ops.ok_or_else(|| anyhow!("--ops required with --scenario"))?;
        let src = Source::Scenario {
            name,
            ops,
            seed,
            peers,
        };
        return Ok((src, trials, seed));
    }

    let src = source.ok_or_else(|| {
        anyhow!("usage: replay_permute <ops.cbor> [trials] [seed] OR replay_permute --scenario <hb-chain|concurrent|offline-revocation> --ops <n> [--peers <n>] [--trials <n>] [--seed <seed>]")
    })?;
    Ok((src, trials, seed))
}

fn load_ops(path: &str) -> Result<Vec<Op>> {
    let data = fs::read(path).with_context(|| format!("read {}", path))?;
    serde_cbor::from_slice(&data).with_context(|| format!("decode CBOR ops from {}", path))
}

fn digest_for_order(ops: &[Op]) -> Result<[u8; 32]> {
    let mut dag = Dag::new();
    for op in ops {
        dag.insert(op.clone());
    }
    let (_state, digest) = replay::replay_full(&dag);
    Ok(digest)
}

fn topo_permutation(ops: &[Op], rng: &mut StdRng) -> Result<Vec<Op>> {
    let mut children: HashMap<OpId, Vec<OpId>> = HashMap::new();
    let mut indegree: HashMap<OpId, usize> = HashMap::new();
    let mut by_id: HashMap<OpId, Op> = HashMap::new();

    for op in ops {
        indegree.insert(op.op_id, op.header.parents.len());
        by_id.insert(op.op_id, op.clone());
        for p in &op.header.parents {
            children.entry(*p).or_default().push(op.op_id);
        }
    }

    let mut ready: Vec<OpId> = indegree
        .iter()
        .filter_map(|(id, &deg)| if deg == 0 { Some(*id) } else { None })
        .collect();

    let mut order: Vec<OpId> = Vec::with_capacity(ops.len());
    while let Some(_) = ready.last() {
        ready.shuffle(rng);
        let id = ready.pop().expect("non-empty ready");
        order.push(id);
        if let Some(kids) = children.get(&id) {
            for child in kids {
                if let Some(deg) = indegree.get_mut(child) {
                    *deg -= 1;
                    if *deg == 0 {
                        ready.push(*child);
                    }
                }
            }
        }
    }

    if order.len() != ops.len() {
        bail!(
            "topological sort incomplete: got {} of {} ops",
            order.len(),
            ops.len()
        );
    }

    let permuted = order
        .into_iter()
        .map(|id| by_id.remove(&id).expect("op by id"))
        .collect();
    Ok(permuted)
}

fn main() -> Result<()> {
    let (source, trials, seed) = parse_args()?;

    let ops = match source {
        Source::File(ref path) => load_ops(path)?,
        Source::Scenario {
            name,
            ops,
            seed,
            peers,
        } => gen_scenario(&name, seed, ops, peers)?,
    };
    if ops.is_empty() {
        bail!("no ops to process");
    }

    let baseline = digest_for_order(&ops)?;
    println!("loaded {} ops. baseline digest: {:02x?}", ops.len(), baseline);

    for i in 0..trials {
        let mut rng = StdRng::seed_from_u64(seed + i as u64);
        let permuted = topo_permutation(&ops, &mut rng)?;
        let digest = digest_for_order(&permuted)?;
        if digest != baseline {
            bail!("digest mismatch on trial {}: {:02x?} != {:02x?}", i, digest, baseline);
        }
        println!("trial {:03}: ok", i);
    }

    println!("All {} permutations matched baseline digest.", trials);
    Ok(())
}

// -------------------- Scenario generators (mirrors CLI bench) --------------------

fn key_pair(seed: u64, label: &[u8]) -> SigningKey {
    let mut bytes = [0u8; 32];
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&seed.to_le_bytes());
    let h = blake3::hash(&[&input, label].concat());
    bytes.copy_from_slice(&h.as_bytes()[..32]);
    SigningKey::from_bytes(&bytes)
}

fn gen_hb_chain(seed: u64, n: usize) -> Result<Vec<Op>> {
    let sk = key_pair(seed, b"hb");
    let pk = vk_to_bytes(&sk.verifying_key());
    let mut out = Vec::with_capacity(n);
    let mut parents: Vec<OpId> = vec![];
    let mut logical = 1u32;
    for i in 0..n {
        let payload = Payload::Data {
            key: "mv:o:x".to_string(),
            value: format!("v{i}").into_bytes(),
        };
        let op = Op::new(
            parents.clone(),
            Hlc::new(1_000 + i as u64, logical),
            pk,
            payload,
            &sk,
        );
        parents = vec![op.op_id];
        logical = logical.saturating_add(1);
        out.push(op);
    }
    Ok(out)
}

fn gen_concurrent_writers(seed: u64, n: usize, peers: usize) -> Result<Vec<Op>> {
    let n_authors = std::cmp::max(2, std::cmp::min(peers, 8));
    let sks: Vec<SigningKey> = (0..n_authors)
        .map(|i| key_pair(seed, format!("concurrent/{i}").as_bytes()))
        .collect();
    let pks: Vec<[u8; 32]> = sks
        .iter()
        .map(|sk| vk_to_bytes(&sk.verifying_key()))
        .collect();
    let mut parents: Vec<Vec<OpId>> = vec![Vec::new(); n_authors];

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let a = i % n_authors;
        let sk = &sks[a];
        let pk = pks[a];
        let payload = Payload::Data {
            key: "mv:o:x".to_string(),
            value: format!("v{i}").into_bytes(),
        };
        let tick = 1_000u64 + i as u64;
        let op = Op::new(
            parents[a].clone(),
            Hlc::new(tick, (i as u32) + 1),
            pk,
            payload,
            sk,
        );
        parents[a].clear();
        parents[a].push(op.op_id);
        out.push(op);
    }
    Ok(out)
}

fn plan_offline_revocation(seed: u64, n: usize) -> Result<Vec<Op>> {
    let all = gen_hb_chain(seed ^ 0x5EED_CAFEu64, n)?;
    if n == 0 {
        return Ok(Vec::new());
    }
    let cut = std::cmp::max(1, (n as f64 * 0.7).round() as usize);
    Ok(all[..cut].to_vec())
}

fn gen_scenario(name: &str, seed: u64, n: usize, peers: usize) -> Result<Vec<Op>> {
    match name {
        "hb-chain" => gen_hb_chain(seed, n),
        "concurrent" => gen_concurrent_writers(seed, n, peers),
        "offline-revocation" => plan_offline_revocation(seed, n),
        other => bail!("unsupported scenario '{}'", other),
    }
}
