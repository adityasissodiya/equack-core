//! In-memory DAG with deterministic topological sorting and pending staging.

use std::collections::{BTreeSet, HashMap};

use crate::hlc::Hlc;
use crate::op::{Op, OpId};

#[derive(Default)]
pub struct Dag {
    nodes: HashMap<OpId, Op>,                  // activated ops
    children: HashMap<OpId, Vec<OpId>>,        // parent -> children (activated)
    pending: HashMap<OpId, Pending>,           // ops waiting for parents
    wait_index: HashMap<OpId, BTreeSet<OpId>>, // missing_parent -> children
}

#[derive(Clone)]
struct Pending {
    op: Op,
    missing: BTreeSet<OpId>,
}

impl Dag {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    pub fn get(&self, id: &OpId) -> Option<&Op> {
        self.nodes.get(id)
    }

    pub fn insert(&mut self, op: Op) {
        let id = op.op_id;
        if self.nodes.contains_key(&id) || self.pending.contains_key(&id) {
            return;
        }
        let mut missing: BTreeSet<OpId> = BTreeSet::new();
        for p in &op.header.parents {
            if !self.nodes.contains_key(p) {
                missing.insert(*p);
            }
        }
        if missing.is_empty() {
            self.activate(op);
        } else {
            for m in &missing {
                self.wait_index.entry(*m).or_default().insert(id);
            }
            self.pending.insert(id, Pending { op, missing });
        }
    }

    fn activate(&mut self, op: Op) {
        let id = op.op_id;
        if self.nodes.contains_key(&id) {
            return;
        }

        for p in &op.header.parents {
            self.children.entry(*p).or_default().push(id);
        }
        self.nodes.insert(id, op);

        if let Some(dependents) = self.wait_index.remove(&id) {
            let to_process: Vec<OpId> = dependents.into_iter().collect();
            for child_id in to_process {
                if let Some(mut pend) = self.pending.remove(&child_id) {
                    pend.missing.remove(&id);
                    if pend.missing.is_empty() {
                        for parent in &pend.op.header.parents {
                            if let Some(s) = self.wait_index.get_mut(parent) {
                                s.remove(&child_id);
                                if s.is_empty() {
                                    self.wait_index.remove(parent);
                                }
                            }
                        }
                        let child_op = pend.op;
                        self.activate(child_op);
                    } else {
                        self.pending.insert(child_id, pend);
                    }
                }
            }
        }
    }

    /// Deterministic topo order of activated nodes: parents before children; tie: (HLC, OpId).
    pub fn topo_sort(&self) -> Vec<OpId> {
        let mut indegree: HashMap<OpId, usize> = HashMap::with_capacity(self.nodes.len());
        for (id, op) in &self.nodes {
            let mut deg = 0usize;
            for p in &op.header.parents {
                if self.nodes.contains_key(p) {
                    deg += 1;
                }
            }
            indegree.insert(*id, deg);
        }

        let mut ready: BTreeSet<(Hlc, OpId)> = BTreeSet::new();
        for (id, deg) in &indegree {
            if *deg == 0 {
                let hlc = self.nodes.get(id).map(|o| o.hlc()).unwrap();
                ready.insert((hlc, *id));
            }
        }

        let mut out = Vec::with_capacity(self.nodes.len());
        let mut indeg = indegree;

        while let Some((hlc, id)) = ready.iter().next().cloned() {
            ready.remove(&(hlc, id));
            out.push(id);

            if let Some(children) = self.children.get(&id) {
                for &c in children {
                    if let Some(d) = indeg.get_mut(&c) {
                        if *d > 0 {
                            *d -= 1;
                            if *d == 0 {
                                let ch_hlc = self.nodes.get(&c).map(|o| o.hlc()).unwrap();
                                ready.insert((ch_hlc, c));
                            }
                        }
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_keypair, vk_to_bytes};
    use crate::hlc::Hlc;
    use crate::op::{Op, Payload};

    #[test]
    fn chain_parent_before_child_even_if_child_inserted_first() {
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
        dag.insert(child.clone()); // pending
        assert_eq!(dag.len(), 0);
        assert!(dag.topo_sort().is_empty());

        dag.insert(parent.clone()); // activates parent then child
        assert_eq!(dag.topo_sort(), vec![parent.op_id, child.op_id]);
    }

    #[test]
    fn multi_parent_child_activates_only_after_all_parents_arrive() {
        let (sk, vk) = generate_keypair();
        let pk = vk_to_bytes(&vk);

        let a = Op::new(
            vec![],
            Hlc::new(10, 1),
            pk,
            Payload::Data {
                key: "k".into(),
                value: b"a".to_vec(),
            },
            &sk,
        );
        let b = Op::new(
            vec![],
            Hlc::new(10, 2),
            pk,
            Payload::Data {
                key: "k".into(),
                value: b"b".to_vec(),
            },
            &sk,
        );
        let c = Op::new(
            vec![a.op_id, b.op_id],
            Hlc::new(12, 1),
            pk,
            Payload::Data {
                key: "k".into(),
                value: b"c".to_vec(),
            },
            &sk,
        );

        let mut dag = Dag::new();
        dag.insert(c.clone()); // pending on a & b
        dag.insert(a.clone()); // still pending (b missing)
        assert_eq!(dag.topo_sort(), vec![a.op_id]);

        dag.insert(b.clone()); // now c activates
        assert_eq!(dag.topo_sort(), vec![a.op_id, b.op_id, c.op_id]);
    }
}
