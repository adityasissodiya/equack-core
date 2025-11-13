use std::collections::HashSet;
use ecac_core::metrics::METRICS;

/// Guard against accidental schema drift.
/// We "pre-register" keys exactly like the bench does (inc/observe with zero)
/// so the snapshot contains all columns even before any real run.
#[test]
fn metrics_header_contains_required_columns() {
    METRICS.reset();

    // Counters we rely on downstream
    let counters = [
        "ops_total",
        "ops_applied",
        "ops_skipped_policy",
        "revocations_seen",
        "ops_invalidated_by_revoke",
        "epochs_total",
        "gossip_announces_sent",
        "gossip_announces_recv",
        "fetch_batches",
        "ops_fetched",
        "ops_duplicates_dropped",
        "orset_tombstones_total",
    ];
    for k in counters {
        METRICS.inc(k, 0);
    }

    // Histograms we plot or check
    let histos = [
        "replay_full_ms",
        "replay_incremental_ms",
        "epoch_build_ms",
        "mvreg_concurrent_winners",
        "batch_write_ms",
        "checkpoint_create_ms",
        "checkpoint_load_ms",
        "convergence_ms",
    ];
    for h in histos {
        METRICS.observe_ms(h, 0);
    }

    let snapshot = METRICS.snapshot_csv(); // "header\nrow\n"
    let mut lines = snapshot.lines();
    let header = lines.next().expect("csv header");
    let cols: HashSet<&str> = header.split(',').collect();

    // Hard requirements for counters: exact column names must exist
    for k in counters {
        assert!(cols.contains(k), "missing counter column: {k}");
    }

    // Hard requirements for histogram quantiles (we test representative ones)
    let must_have = [
        "replay_full_ms_p50_ms",
        "replay_full_ms_max_ms",
        "replay_incremental_ms_p50_ms",
        "replay_incremental_ms_max_ms",
        "mvreg_concurrent_winners_p95_ms",
        // convergence may be unused locally but should still export quantiles
        "convergence_ms_p95_ms",
    ];
    for k in must_have {
        assert!(cols.contains(k), "missing histogram column: {k}");
    }
}