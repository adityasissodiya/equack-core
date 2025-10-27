use ecac_core::crypto::{generate_keypair, vk_to_bytes};
use ecac_core::dag::Dag;
use ecac_core::hlc::Hlc;
use ecac_core::op::{Op, Payload};
use ecac_core::replay::replay_full;
use proptest::prelude::*;
use rand::seq::SliceRandom;
use rand::SeedableRng;

mod util;
use util::make_credential_and_grant;

proptest! {
    #[test]
    fn permutations_with_policy_converge(seed in any::<u64>()) {
        let (admin_sk, admin_vk) = generate_keypair();
        let admin_pk = vk_to_bytes(&admin_vk);
        let (issuer_sk, _issuer_vk) = generate_keypair();
        let (user_sk, user_vk) = generate_keypair();
        let user_pk = vk_to_bytes(&user_vk);

        // Policy+data with two VC-backed grants:
        // cred1 -> grant1 -> w1 -> r1 -> w2 -> cred2 -> grant2 -> w3
        let (cred1, grant1) = make_credential_and_grant(
            &issuer_sk, "oem-issuer-1", user_pk, "editor", &["hv"], 10, 200, &admin_sk, admin_pk
        );
        let w1 = Op::new(vec![], Hlc::new(11,1), user_pk,
            Payload::Data { key: "mv:o:x".into(), value: b"A".to_vec() }, &user_sk);
        let r1 = Op::new(vec![], Hlc::new(12,1), admin_pk,
            Payload::Revoke { subject_pk: user_pk, role: "editor".into(), scope_tags: vec!["hv".into()], at: Hlc::new(12,1) }, &admin_sk);
        let w2 = Op::new(vec![], Hlc::new(13,1), user_pk,
            Payload::Data { key: "mv:o:x".into(), value: b"B".to_vec() }, &user_sk);
        let (cred2, grant2) = make_credential_and_grant(
            &issuer_sk, "oem-issuer-1", user_pk, "editor", &["hv"], 14, 200, &admin_sk, admin_pk
        );
        let w3 = Op::new(vec![], Hlc::new(15,1), user_pk,
            Payload::Data { key: "mv:o:x".into(), value: b"C".to_vec() }, &user_sk);

        let base = vec![cred1, grant1, w1, r1, w2, cred2, grant2, w3];

        // baseline
        let mut dag0 = Dag::new(); for op in base.clone() { dag0.insert(op); }
        let (state0, _d0) = replay_full(&dag0);
        let json0 = state0.to_deterministic_json_string();

        // shuffle several times
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        for _ in 0..8 {
            let mut v = base.clone();
            v.shuffle(&mut rng);
            let mut dag = Dag::new();
            for op in v { dag.insert(op); }
            let (s, _d) = replay_full(&dag);
            let got = s.to_deterministic_json_string();
            prop_assert_eq!(got.as_str(), json0.as_str());
        }
    }
}
