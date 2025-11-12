use ecac_core::{
    crypto::*,
    dag::Dag,
    hlc::Hlc,
    op::{Op, Payload},
};

fn hex32(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let (sk, vk) = generate_keypair();
    let pk = vk_to_bytes(&vk);
    let parent = Op::new(
        vec![],
        Hlc::new(10, 1),
        pk,
        Payload::Data {
            key: "k".into(),
            value: b"p".to_vec(),
        },
        &sk,
    );
    let child = Op::new(
        vec![parent.op_id],
        Hlc::new(11, 1),
        pk,
        Payload::Data {
            key: "k".into(),
            value: b"c".to_vec(),
        },
        &sk,
    );

    let mut dag = Dag::new();
    dag.insert(child); // inserted first on purpose
    dag.insert(parent);

    for id in dag.topo_sort() {
        println!("{}", hex32(&id));
    }
}
