use std::fs;
use std::path::PathBuf;
use std::process::Command;

use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use rand::rngs::StdRng;
use rand::{seq::SliceRandom, SeedableRng};

fn write_cbor_temp(ops: &[Op], label: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("ecac_e2e_{}_{}.cbor", label, std::process::id()));
    // serde_cbor::to_vec<T>(&T) needs Sized; wrap slice as Vec
    let bytes = serde_cbor::to_vec(&ops.to_vec()).expect("serialize ops");
    fs::write(&path, &bytes).expect("write cbor");
    path
}

fn make_hb_chain() -> Vec<Op> {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);
    let a = Op::new(
        vec![],
        Hlc::new(10, 1),
        pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"A".to_vec(),
        },
        &sk,
    );
    let b = Op::new(
        vec![a.op_id],
        Hlc::new(11, 1),
        pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"B".to_vec(),
        },
        &sk,
    );
    let c = Op::new(
        vec![b.op_id],
        Hlc::new(12, 1),
        pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"C".to_vec(),
        },
        &sk,
    );
    vec![a, b, c]
}

fn make_mv_concurrent() -> Vec<Op> {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);
    let a = Op::new(
        vec![],
        Hlc::new(10, 1),
        pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"A".to_vec(),
        },
        &sk,
    );
    let b = Op::new(
        vec![],
        Hlc::new(10, 2),
        pk,
        Payload::Data {
            key: "mv:o:x".into(),
            value: b"B".to_vec(),
        },
        &sk,
    );
    vec![a, b]
}

fn make_orset_race() -> Vec<Op> {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);
    let add1 = Op::new(
        vec![],
        Hlc::new(10, 1),
        pk,
        Payload::Data {
            key: "set+:o:s:e".into(),
            value: b"v1".to_vec(),
        },
        &sk,
    );
    let rem_conc = Op::new(
        vec![],
        Hlc::new(10, 2),
        pk,
        Payload::Data {
            key: "set-:o:s:e".into(),
            value: vec![],
        },
        &sk,
    );
    let add2 = Op::new(
        vec![],
        Hlc::new(11, 1),
        pk,
        Payload::Data {
            key: "set+:o:s:e".into(),
            value: b"v2".to_vec(),
        },
        &sk,
    );
    let rem_hb = Op::new(
        vec![add1.op_id],
        Hlc::new(12, 1),
        pk,
        Payload::Data {
            key: "set-:o:s:e".into(),
            value: vec![],
        },
        &sk,
    );
    vec![add1, rem_conc, add2, rem_hb]
}

fn run_replay(path: &PathBuf) -> (String, String) {
    // Always build+run via cargo; works regardless of bin path.
    let out = Command::new("cargo")
        .args([
            "run",
            "-p",
            "ecac-cli",
            "--quiet",
            "--",
            "replay",
            &path.to_string_lossy(),
        ])
        .output()
        .expect("spawn cargo");
    assert!(
        out.status.success(),
        "run replay: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8(out.stdout).expect("utf8");
    let mut lines = s.lines();
    let json = lines.next().unwrap_or("").to_string();
    let digest_line = lines.next().unwrap_or("").to_string();
    (json, digest_line)
}

fn run_project(path: &PathBuf, obj: &str, field: &str) -> String {
    let out = Command::new("cargo")
        .args([
            "run",
            "-p",
            "ecac-cli",
            "--quiet",
            "--",
            "project",
            &path.to_string_lossy(),
            obj,
            field,
        ])
        .output()
        .expect("spawn cargo");
    assert!(
        out.status.success(),
        "run project: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_string()
}

#[test]
fn e2e_permutations_converge_and_project() {
    let cases = vec![
        ("hb_chain", make_hb_chain(), ("o", "x")),
        ("mv_conc", make_mv_concurrent(), ("o", "x")),
        ("orset", make_orset_race(), ("o", "s")),
    ];

    for (label, ops, (obj, field)) in cases {
        let mut rng = StdRng::seed_from_u64(0xECAC_5157_u64);
        let mut json0 = None;
        let mut dig0 = None;

        for i in 0..3 {
            let mut v = ops.clone();
            v.shuffle(&mut rng);
            let path = write_cbor_temp(&v, &format!("{}_{}", label, i));

            let (json, dig) = run_replay(&path);

            if let Some(j) = &json0 {
                assert_eq!(&json, j, "JSON mismatch for case {label} perm {i}");
            } else {
                json0 = Some(json.clone());
            }
            if let Some(d) = &dig0 {
                assert_eq!(&dig, d, "digest mismatch for case {label} perm {i}");
            } else {
                dig0 = Some(dig.clone());
            }

            let proj = run_project(&path, obj, field);
            assert!(
                proj.contains(r#""type":"mv"#) || proj.contains(r#""type":"set"#),
                "unexpected project output"
            );
        }
    }
}
