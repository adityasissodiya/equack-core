use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::replay::replay_full;

fn main() {
    let (admin_sk, admin_vk) = generate_keypair();
    let admin_pk = vk_to_bytes(&admin_vk);
    let (user_sk, user_vk) = generate_keypair();
    let user_pk = vk_to_bytes(&user_vk);

    // Offline edit + concurrent revoke
    let grant = Op::new(vec![], Hlc::new(10,1), admin_pk, Payload::Grant {
        subject_pk: user_pk, role: "editor".into(), scope_tags: vec!["hv".into()],
        not_before: Hlc::new(10,1), not_after: None
    }, &admin_sk);
    let revoke = Op::new(vec![], Hlc::new(20,1), admin_pk, Payload::Revoke {
        subject_pk: user_pk, role: "editor".into(), scope_tags: vec!["hv".into()],
        at: Hlc::new(20,1)
    }, &admin_sk);
    let edit_before = Op::new(vec![], Hlc::new(19,1), user_pk, Payload::Data {
        key: "mv:o:x".into(), value: b"BEFORE".to_vec()
    }, &user_sk);
    let edit_after = Op::new(vec![], Hlc::new(21,1), user_pk, Payload::Data {
        key: "mv:o:x".into(), value: b"AFTER".to_vec()
    }, &user_sk);

    let mut dag = Dag::new();
    for op in [grant.clone(), edit_before.clone(), revoke.clone(), edit_after.clone()] {
        dag.insert(op);
    }
    let (state, digest) = replay_full(&dag);
    println!("{}", state.to_deterministic_json_string());
    println!("digest={}", {
        let mut s = String::new();
        for b in &digest { s.push_str(&format!("{:02x}", b)); }
        s
    });
}
