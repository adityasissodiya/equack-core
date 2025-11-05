// crates/net/src/sync.rs
#![allow(dead_code)]

use std::collections::{BTreeSet, HashMap, HashSet};

use ecac_core::crypto::hash_bytes;
use ecac_core::op::OpId;

/// Phase 0: placeholder type; real ingestion driver lands later.
pub struct SyncPlanner;

/// Tiny 16-bit bloom “maybe” check over three lanes derived from blake3(op_id).
/// Bits are little-endian; false positives tolerated.
pub fn bloom16_maybe_contains(bloom: [u8; 2], id: &OpId) -> bool {
    let h = hash_bytes(id);
    let idx = [
        (u16::from_le_bytes([h[0], h[1]]) % 16) as u8,
        (u16::from_le_bytes([h[2], h[3]]) % 16) as u8,
        (u16::from_le_bytes([h[4], h[5]]) % 16) as u8,
    ];
    let bit_is_set = |i: u8| {
        let byte = (i / 8) as usize;
        let bit = i % 8;
        (bloom[byte] & (1u8 << bit)) != 0
    };
    bit_is_set(idx[0]) && bit_is_set(idx[1]) && bit_is_set(idx[2])
}

// Visible only in tests for readable traces
#[cfg(test)]
fn _fmt_hex32(id: &OpId) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for &b in id {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FetchPlan {
    /// Parent-first batches; each inner vec is deterministically ordered.
    pub batches: Vec<Vec<OpId>>,
}

impl SyncPlanner {
    /// Plan fetches given:
    /// - `remote_heads`: remote’s tip ids
    /// - `local_recent_bloom16`: bloom hint of **local** recent ops (used as a boundary hint)
    /// - `have`: local presence predicate
    /// - `parents`: function to read parents for an op id
    ///
    /// Strategy:
    /// - Walk backwards from heads.
    /// - Hard boundary (have): do NOT include `id`, but **still expand to parents** (close gaps).
    /// - Soft boundary (bloom “maybe”): do NOT include `id`; expand to parents but **do not**
    ///   expand past them (no grandparents).
    /// - Collect the missing set; then layer parent→child by indegree restricted to that set.
    pub fn plan_with<FHave, FParents>(
        remote_heads: &[OpId],
        local_recent_bloom16: [u8; 2],
        mut have: FHave,
        mut parents: FParents,
    ) -> FetchPlan
    where
        FHave: FnMut(&OpId) -> bool,
        FParents: FnMut(&OpId) -> Vec<OpId>,
    {
        if remote_heads.is_empty() {
            return FetchPlan::default();
        }
    
        // 1) Walk back to boundary; collect missing ids and local parent/child edges.
        let mut missing: BTreeSet<OpId> = BTreeSet::new();
        let mut parents_map: HashMap<OpId, Vec<OpId>> = HashMap::new();
        let mut children_map: HashMap<OpId, Vec<OpId>> = HashMap::new();
    
        // Stack carries (node, expand?). expand=false means: visit this node,
        // but DO NOT traverse further to its parents.
        let mut stack: Vec<(OpId, bool)> =
            remote_heads.iter().cloned().map(|h| (h, true)).collect();
        let mut seen: HashSet<OpId> = HashSet::new();
    
        // ----- test-only probes to understand traversal -----
        #[cfg(test)]
        {
            let heads_dbg = remote_heads.iter().map(_fmt_hex32).collect::<Vec<_>>().join(",");
            eprintln!("planner: HEADS   = [{}]", heads_dbg);
            eprintln!(
                "planner: BLOOM16 = {:08b} {:08b}",
                local_recent_bloom16[1], local_recent_bloom16[0]
            );
        }
    
        while let Some((id, expand)) = stack.pop() {
            let has_it = have(&id);
            let bloom_here = bloom16_maybe_contains(local_recent_bloom16, &id);
            let is_head = remote_heads.iter().any(|h| h == &id);
            
            // (Test-only diagnostics) compute `include` just for the debug line to avoid
            // the unused variable warning in non-test builds.
            #[cfg(test)]
            {
                let include_dbg = !has_it && (!bloom_here || is_head);
                eprintln!(
                    "planner: VISIT id={} head={} have={} bloom_here={} expand_in={}",
                    _fmt_hex32(&id), is_head, has_it, bloom_here, expand
                );
                eprintln!(
                    "planner: DECISION id={} -> include={} (rule: !have && (!bloom || head))",
                    _fmt_hex32(&id), include_dbg
                );
            }
    
            if !seen.insert(id) { continue; }
    
            // Include unless we already have it or bloom hints it's present locally.
            // Heads are NEVER skipped because of bloom.
            // (test-only) compute the decision just for the debug print to avoid an unused var in release
            #[cfg(test)]
            {
                let include_dbg = !has_it && (!bloom_here || is_head);
                eprintln!(
                    "planner: VISIT id={} head={} have={} bloom_here={} expand_in={}",
                    _fmt_hex32(&id), is_head, has_it, bloom_here, expand
                );
                eprintln!(
                    "planner: DECISION id={} -> include={} (rule: !have && (!bloom || head))",
                    _fmt_hex32(&id), include_dbg
                );
            }
    
            // Wire child->parent edges (needed for indegree). Expansion decision is separate.
            let ps = parents(&id);
            parents_map.insert(id, ps.clone());
            for p in &ps { children_map.entry(*p).or_default().push(id); }
    
            // Expand to parents? Per-parent bound: visit parent `p`, but if bloom says we
            // probably have `p`, don't expand *past* it.
            if expand {
                for p in ps {
                    let p_bloom = bloom16_maybe_contains(local_recent_bloom16, &p);
                    stack.push((p, !p_bloom));
                }
            }
    
            // Debugging: show what's being added to `missing`
            #[cfg(test)]
            {
                if !has_it && !bloom_here {
                    eprintln!("planner: Added id={} to missing", _fmt_hex32(&id));
                }
            }
    
            // Add to missing if we should (excluding local knowns and bloom hints)
            if !has_it && !bloom_here {
                missing.insert(id);
            }
        }
    
        if missing.is_empty() {
            #[cfg(test)]
            eprintln!("planner: DONE — missing set empty");
            return FetchPlan::default();
        }
    
        // 2) Layer inside the missing subgraph: indegree over edges restricted to `missing`.
        let mut indeg: HashMap<OpId, usize> = HashMap::with_capacity(missing.len());
        for &id in &missing {
            let mut d = 0usize;
            if let Some(ps) = parents_map.get(&id) {
                for p in ps {
                    if missing.contains(p) {
                        d += 1;
                    }
                }
            }
            indeg.insert(id, d);
            #[cfg(test)]
            eprintln!("planner: INDEG {} = {}", _fmt_hex32(&id), d);
        }
    
        // 3) Kahn layering: batch all indeg==0 (parents) first, then propagate to children.
        let mut plan = FetchPlan::default();
        let mut ready: BTreeSet<OpId> = indeg
            .iter()
            .filter_map(|(id, d)| if *d == 0 { Some(*id) } else { None })
            .collect();
    
        #[cfg(test)]
        {
            let ready0: Vec<_> = ready.iter().map(|x| _fmt_hex32(x)).collect();
            eprintln!("planner: READY0 = {:?}", ready0);
        }
    
        let mut remaining = missing.len();
        while !ready.is_empty() {
            // Deterministic batch order by OpId bytes.
            let batch: Vec<OpId> = ready.iter().cloned().collect();
            #[cfg(test)]
            {
                eprintln!(
                    "planner: BATCH size={} ids=[{}]",
                    batch.len(),
                    batch
                        .iter()
                        .map(|i| _fmt_hex32(i))
                        .collect::<Vec<_>>()
                        .join(",")
                );
            }
            plan.batches.push(batch.clone());
    
            #[cfg(test)]
            {
                let dbg: Vec<_> = batch.iter().map(|x| _fmt_hex32(x)).collect();
                eprintln!("planner: BATCH  = {:?}", dbg);
            }
    
            // Prepare next “ready” set.
            let mut next_ready: BTreeSet<OpId> = BTreeSet::new();
            for id in batch {
                remaining -= 1;
                if let Some(children) = children_map.get(&id) {
                    for &ch in children {
                        if !missing.contains(&ch) {
                            continue;
                        }
                        if let Some(d) = indeg.get_mut(&ch) {
                            if *d > 0 {
                                *d -= 1;
                                if *d == 0 {
                                    next_ready.insert(ch);
                                    #[cfg(test)]
                                    eprintln!("planner:   -> READY {}", _fmt_hex32(&ch));
                                }
                            }
                        }
                    }
                }
                indeg.remove(&id);
            }
            ready = next_ready;
        }
    
        // Defensive: if anything was left, the input wasn’t a DAG; we’ll just emit what we had.
        let _ = remaining;
    
        #[cfg(test)]
        {
            let dbg_batches: Vec<Vec<String>> = plan
                .batches
                .iter()
                .map(|b| b.iter().map(|x| _fmt_hex32(x)).collect())
                .collect();
            eprintln!("planner: DONE batches = {:?}", dbg_batches);
        }
    
        plan
    }
    
}
