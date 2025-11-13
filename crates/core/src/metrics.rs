// crates/core/src/metrics.rs
//! Minimal metrics core for M7.
//!
//! - Lock-free increments/observations (atomics) after first-time registration.
//! - Fixed millisecond histogram buckets + quantile extraction (p50/p95).
//! - Stable CSV order: keys are sorted lexicographically; each histogram expands
//!   to columns: *_count,*_sum_ms,*_p50_ms,*_p95_ms,*_max_ms.
//! - No wall clock dependency. You pass ms you measured elsewhere.
//!
//! Intended use:
//!   let m = Metrics::new();
//!   m.inc("ops_total", 1);
//!   m.observe_ms("replay_full_ms", 42);
//!   let csv = m.snapshot_csv(); // header + single row

use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};
use once_cell::sync::Lazy;
pub static METRICS: Lazy<Metrics> = Lazy::new(Metrics::new);

/// Static histogram bucket upper bounds in milliseconds.
/// The last bucket is +Inf (implicit).
const MS_BUCKETS: &[u64] = &[
    0, 1, 2, 5, 10, 20, 50, 100, 200, 500,
    1_000, 2_000, 5_000, 10_000, 30_000,
    60_000, 120_000, 300_000,
];

fn bucket_index(ms: u64) -> usize {
    match MS_BUCKETS.binary_search(&ms) {
        Ok(idx) => idx,           // exact match to an upper bound bucket
        Err(pos) => pos,          // first upper bound greater than ms
    }
}

/// Lock-free histogram after registration.
struct Histo {
    // One extra bucket for +Inf.
    buckets: Vec<AtomicU64>,
    sum_ms: AtomicU64,
    count: AtomicU64,
    max_ms: AtomicU64,
}

impl Histo {
    fn new() -> Self {
        let mut b = Vec::with_capacity(MS_BUCKETS.len() + 1);
        for _ in 0..(MS_BUCKETS.len() + 1) {
            b.push(AtomicU64::new(0));
        }
        Self {
            buckets: b,
            sum_ms: AtomicU64::new(0),
            count: AtomicU64::new(0),
            max_ms: AtomicU64::new(0),
        }
    }

    fn observe_ms(&self, ms: u64) {
        let idx = bucket_index(ms).min(self.buckets.len() - 1);
        self.buckets[idx].fetch_add(1, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ms.fetch_add(ms, Ordering::Relaxed);

        // fetch_max emulation
        let mut cur = self.max_ms.load(Ordering::Relaxed);
        while ms > cur {
            match self.max_ms.compare_exchange_weak(
                cur,
                ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(prev) => cur = prev,
            }
        }
    }

    fn reset(&self) {
        for b in &self.buckets {
            b.store(0, Ordering::Relaxed);
        }
        self.sum_ms.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
        self.max_ms.store(0, Ordering::Relaxed);
    }

    /// Return (count, sum_ms, p50_ms, p95_ms, max_ms).
    fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
        let mut counts: Vec<u64> = self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).collect();
        let total: u64 = counts.iter().sum();
        let sum_ms = self.sum_ms.load(Ordering::Relaxed);
        let max_ms = self.max_ms.load(Ordering::Relaxed);

        let p50 = quantile_ms(&counts, 0.50);
        let p95 = quantile_ms(&counts, 0.95);

        (total, sum_ms, p50, p95, max_ms)
    }
}

/// Upper-bound quantile (returns the bucket upper bound in ms).
fn quantile_ms(bucket_counts: &[u64], q: f64) -> u64 {
    let total: u64 = bucket_counts.iter().sum();
    if total == 0 {
        return 0;
    }
    // 1-based rank, ceil for "upper" quantile.
    let target = ((q * (total as f64)).ceil() as u64).max(1);
    let mut acc = 0u64;
    for (i, c) in bucket_counts.iter().enumerate() {
        acc += *c;
        if acc >= target {
            if i < MS_BUCKETS.len() {
                return MS_BUCKETS[i];
            } else {
                return u64::MAX; // +Inf bucket
            }
        }
    }
    // Fallback: +Inf
    u64::MAX
}

/// Metrics registry.
/// Registration uses short-lived locks; increments/observations are lock-free.
#[derive(Default)]
pub struct Metrics {
    counters: RwLock<BTreeMap<&'static str, Arc<AtomicU64>>>,
    histos: RwLock<BTreeMap<&'static str, Arc<Histo>>>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment a counter by `by` (counter is created if missing).
    pub fn inc(&self, key: &'static str, by: u64) {
                // IMPORTANT: never hold a read guard while trying to acquire a write guard on the same lock.
                // Using an inner scope forces the read guard to drop before we attempt the write path.
                let cell = if let Some(existing) = {
                    let r = self.counters.read().unwrap();
                    r.get(key).cloned()
                } {
                    existing
                } else {
                    let mut w = self.counters.write().unwrap();
                    w.entry(key)
                        .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                        .clone()
                };
        cell.fetch_add(by, Ordering::Relaxed);
    }

    /// Observe a timing in milliseconds into a histogram (created if missing).
    pub fn observe_ms(&self, key: &'static str, ms: u64) {
                // Same pattern as inc(): drop read guard before taking write.
                let h = if let Some(existing) = {
                    let r = self.histos.read().unwrap();
                    r.get(key).cloned()
                } {
                    existing
                } else {
                    let mut w = self.histos.write().unwrap();
                    w.entry(key)
                        .or_insert_with(|| Arc::new(Histo::new()))
                        .clone()
                };
        h.observe_ms(ms);
    }

    /// Reset all counters and histograms to zero (keys remain registered).
    pub fn reset(&self) {
        for (_, c) in self.counters.write().unwrap().iter_mut() {
            c.store(0, Ordering::Relaxed);
        }
        for (_, h) in self.histos.write().unwrap().iter_mut() {
            h.reset();
        }
    }

    /// Produce a 2-line CSV string: header + single row.
    ///
    /// Counter columns are the plain keys.
    /// Histogram columns are expanded as:
    ///   <key>_count,<key>_sum_ms,<key>_p50_ms,<key>_p95_ms,<key>_max_ms
    ///
    /// Keys are sorted for a stable schema.
    pub fn snapshot_csv(&self) -> String {
        let counters_map = self.counters.read().unwrap();
        let histos_map = self.histos.read().unwrap();

        let mut counter_keys: Vec<&'static str> = counters_map.keys().copied().collect();
        counter_keys.sort_unstable();

        let mut histo_keys: Vec<&'static str> = histos_map.keys().copied().collect();
        histo_keys.sort_unstable();

        // Build header
        let mut header = Vec::new();
        for k in &counter_keys {
            header.push((*k).to_string());
        }
        for k in &histo_keys {
            header.push(format!("{}_count", k));
            header.push(format!("{}_sum_ms", k));
            header.push(format!("{}_p50_ms", k));
            header.push(format!("{}_p95_ms", k));
            header.push(format!("{}_max_ms", k));
        }

        // Build row
        let mut row = Vec::new();
        for k in &counter_keys {
            let v = counters_map.get(k).unwrap().load(Ordering::Relaxed);
            row.push(v.to_string());
        }
        for k in &histo_keys {
            let (cnt, sum, p50, p95, maxv) = histos_map.get(k).unwrap().snapshot();
            row.push(cnt.to_string());
            row.push(sum.to_string());
            row.push(p50.to_string());
            row.push(p95.to_string());
            row.push(maxv.to_string());
        }

        let mut out = String::new();
        out.push_str(&header.join(","));
        out.push('\n');
        out.push_str(&row.join(","));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_is_stable_and_populated() {
        let m = Metrics::new();
        // Register in "random" order.
        m.inc("b_counter", 2);
        m.inc("a_counter", 1);
        m.observe_ms("replay_full_ms", 10);
        m.observe_ms("replay_full_ms", 20);
        m.observe_ms("replay_full_ms", 5);

        let csv = m.snapshot_csv();
        let mut lines = csv.lines();
        let header = lines.next().unwrap();
        let row = lines.next().unwrap();

        // Sorted order => a_counter first.
        assert!(header.starts_with("a_counter,b_counter,"));
        assert!(row.split(',').next().unwrap() == "1"); // a_counter=1
    }

    #[test]
    fn reset_zeros_values_but_keeps_keys() {
        let m = Metrics::new();
        m.inc("x", 7);
        m.observe_ms("h", 100);
        assert!(m.snapshot_csv().contains("7"));
        m.reset();
        let csv = m.snapshot_csv();
        assert!(csv.contains("0"));
    }
}
