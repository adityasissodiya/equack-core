# ECAC Audit Trail (M8)

This document describes the tamper-evident audit log in ECAC: what it records, how it is encoded on disk, and how to verify it.

The goal of M8 is: for every important decision the system makes (“apply this op”, “skip that op and why”), we can later prove:

- which node emitted the decision,
- in what order decisions were made,
- why a given op was applied or skipped (including deny-wins reasons), and
- that the audit log itself has not been modified after the fact.

The audit log is **append-only**, **hash-linked**, and **signed** by a node key that is separate from user keys.

---

## Threat model

- We assume an attacker can read and attempt to modify the audit log on disk.
- We do **not** assume secrecy: audit entries are not encrypted.
- We want to detect:
  - removed entries (gaps),
  - reordered entries,
  - modified payloads, and
  - forged entries not signed by the node key.

We do **not** attempt multi-party notarisation (e.g., transparency logs) or long-term key rollover in M8.

---

## Event model

Application code emits a small set of `AuditEvent` variants:

```rust
enum AuditEvent {
    IngestedOp {
        op_id: [u8; 32],
        author_pk: [u8; 32],
        parents: Vec<[u8; 32]>,
        verified_sig: bool,
    },
    AppliedOp {
        op_id: [u8; 32],
        topo_idx: u64,
        reason: AppliedReason,    // currently: Authorized
    },
    SkippedOp {
        op_id: [u8; 32],
        topo_idx: u64,
        reason: SkipReason,       // see below
    },
    ViewEvent {
        // reserved for future M8+; not currently emitted
        viewer_node: [u8; 32],
        obj: String,
        field: String,
        projection_hash: [u8; 32],
    },
    Checkpoint {
        checkpoint_id: u64,
        topo_idx: u64,
        state_digest: [u8; 32],
    },
    SyncEvent {
        // reserved for net integration; not currently emitted
        peer_id: [u8; 32],
        fetched: u32,
        duplicates: u32,
    },
}
The deny-wins gate is reflected via SkipReason:

rust
Copy code
enum SkipReason {
    DenyWins,      // generic policy deny (legacy or no VC context)
    InvalidSig,    // op.signature failed verification
    BadParent,     // op references a parent that never appears earlier in topo order
    RevokedCred,   // VC was revoked by a later Revoke epoch
    ExpiredCred,   // VC has expired (HLC after not_after guard)
    OutOfScope,    // VC valid, but its scope does not cover the resource tags
}
The mapping policy → audit is:

Replay consults VC-backed epochs to derive a DenyDetail:

RevokedCred, ExpiredCred, OutOfScope, GenericDeny.

That is then mapped to SkipReason in replay::apply_over_order_with_audit:

GenericDeny → DenyWins

RevokedCred → RevokedCred

ExpiredCred → ExpiredCred

OutOfScope → OutOfScope

So for every data op that hits the policy gate, you can ask:
“Was it applied? If not, was it revoked, expired, out of scope, or just never enabled?”

On-disk chain format
Each on-disk entry is:

rust
Copy code
struct AuditEntryWire {
    seq: u64,
    ts_monotonic: u64,
    prev_hash: [u8; 32],
    event: AuditEvent,
    node_id: [u8; 32],
    signature: Vec<u8>,  // ed25519 over the preimage hash
}
seq is a monotonically increasing sequence number (no gaps in a valid log).

ts_monotonic is a monotonic counter / timestamp used for debugging; it is not part of the trust base.

node_id is the 32-byte public key of the node that wrote the entry.

prev_hash chains entries together:

For the first entry in a log: all zeroes.

For each subsequent entry: prev_hash = hash(entry_{seq-1}).

Hash and signature
For each entry, we compute:

text
Copy code
preimage = canonical_cbor({
    seq,
    ts_monotonic,
    prev_hash,
    event,
    node_id,
    // signature is omitted from the preimage
})

entry_hash = BLAKE3("ECAC_AUDIT_V1" || preimage)
signature = ed25519(node_sk, entry_hash)
Verification checks:

seq is strictly increasing and contiguous.

For each entry:

recompute entry_hash,

verify signature with node_id,

recompute prev_hash chain and require it to match.

Any deviation (gap in seq, hash mismatch, bad signature) makes verification fail with a precise location.

Log layout and rotation
Audit logs live in a directory (by default <db>/audit or .audit). The layout:

index.json: JSON index with an ordered list of segments and summary metadata;

segment-00000001.log, segment-00000002.log, …: append-only binary segments.

Each segment is a sequence of length-prefixed CBOR blobs:

text
Copy code
<u32 length (big-endian)> <length bytes of CBOR-encoded AuditEntryWire>
...
Rotation is size-based:

Once a segment reaches a size threshold, a new segment-XXXX.log is created.

index.json is updated to include:

segment path,

first/last seq,

first/last hashes, etc.

Tail repair
Crash-safety is handled by tail repair:

On audit-verify-chain, if the last segment ends with a partial entry
(truncated length or CBOR decode failure),
the verifier truncates the file back to the last valid offset and reports:

truncated tail repaired at <segment> (offset N)

All fully written entries before that point are still valid and verifiable.

We never silently accept half-written entries.

Emitters and integration points
Replay (ecac-core::replay)
In audit builds (--features audit), the replay path:

uses the same topological order as state replay,

enforces parent sanity (BadParent),

enforces signature validity (InvalidSig),

runs the policy gate (VC-backed epochs, deny-wins),

emits:

AppliedOp { op_id, topo_idx, Authorized } for each applied data op, and

SkippedOp { op_id, topo_idx, reason } for each skipped data op.

At the end of replay, it emits a Checkpoint with:

checkpoint_id = processed_count,

topo_idx = processed_count,

state_digest = state.digest().

Ingest (ecac-cli op-append-audited)
The audited append path (op-append-audited) uses the same tolerant CBOR reader as replay and:

attempts to append each op into the store,

on signature failure, emits SkippedOp { reason: InvalidSig } into the audit log.

This gives you ingest-time coverage for invalid signatures, even before replay.

Network (SyncEvent)
The SyncEvent variant is reserved for the net layer (M6/M8 integration):

after each successful fetch batch, the net code can emit:

SyncEvent { peer_id, fetched, duplicates }.

At the time of writing, SyncEvent is defined but not yet emitted; it is a clean extension point for future work.

View events (ViewEvent)
ViewEvent is reserved for “who read what and when” tracking:

gated by a feature flag / CLI option,

intended to record projections (obj, field, hash of value) rather than raw payloads for privacy.

It is not wired up in the current M8 code path and is documented here as future work.

CLI commands
The CLI exposes several subcommands (behind the audit feature) to work with audit logs.

audit-record
Replay the store and write decision events to the on-disk audit log:

bash
Copy code
ECAC_NODE_SK_HEX=<64-hex-ed25519-secret> \
cargo run -p ecac-cli --features audit -- \
  audit-record --db <db_dir>
Opens the RocksDB store at <db_dir>.

Builds a DAG from all ops in parent-first topo order.

Runs replay_full_with_audit.

Writes AppliedOp / SkippedOp / Checkpoint entries into the default audit dir:

ECAC_AUDIT_DIR if set, otherwise <db_dir>/audit, otherwise .audit.

audit-verify-chain
Verify chain integrity (hashes + signatures + seq monotonicity):

bash
Copy code
cargo run -p ecac-cli --features audit -- \
  audit-verify-chain --dir <audit_dir>
Checks the hash-link and signatures across all segments referenced in index.json.

On success, prints OK: audit chain verified at <dir>.

On corruption or tampering, fails with an error pointing at the offending segment / seq.

audit-verify-full
Verify both chain integrity and replay decision consistency:

bash
Copy code
# Use ECAC_AUDIT_DIR override
ECAC_AUDIT_DIR=<audit_dir> \
cargo run -p ecac-cli --features audit -- \
  audit-verify-full --db <db_dir>

# Or let it pick <db_dir>/audit or .audit
cargo run -p ecac-cli --features audit -- \
  audit-verify-full --db <db_dir>
Algorithm:

Select the audit directory (ECAC_AUDIT_DIR, <db>/audit, or .audit).

Run the same chain verification as audit-verify-chain.

Rebuild a DAG from the store, replay with an in-memory MemAudit hook, and collect
all AppliedOp / SkippedOp events.

Stream all audit segments and collect AppliedOp / SkippedOp events from disk.

Sort both sequences and compare:

if (op_id, topo_idx, reason) match exactly, print:

OK: replay decisions match audit (N entries)

otherwise, show the first mismatch and per-reason summaries, then fail.

This is the core audit vs replay cross-check guarantee.

audit-cat
Decode and print audit entries from one or more segments:

bash
Copy code
# Entire log
cargo run -p ecac-cli --features audit -- audit-cat --dir <audit_dir>

# Single segment
cargo run -p ecac-cli --features audit -- \
  audit-cat --dir <audit_dir> --segment segment-00000001.log
Each entry is printed as a single JSON object with hex-encoded hashes, node_id, and signature.
Useful for debugging and for producing small examples in the paper.

audit-export
Produce a deterministic JSONL export:

bash
Copy code
cargo run -p ecac-cli --features audit -- \
  audit-export --dir <audit_dir> --out audit.jsonl
Verifies the chain first.

Streams all segments in index order.

Writes one JSON object per line with a stable field order and hex-encoded byte arrays.

Two exports of the same log must be byte-identical.

This is the artifact you’ll point to in the evaluation to show reproducible audit runs.

Repro: M8 dev check script
For convenience, the repo includes tools/scripts/m8-dev-check.sh, which runs a bundled set of checks:

Record decisions into an audit log using a temporary DB.

Verify the chain (audit-verify-chain).

Verify replay vs audit consistency (audit-verify-full).

Simulate a truncated tail and confirm that audit-verify-chain repairs it and still accepts.

Smoke-test the CLI op generators (op-make-min, op-make-orphan) and ensure audit verification still passes.

When all is well, it terminates with:

text
Copy code
All checks passed.
This script is what you should reference in docs/evaluation-plan.md as the “one-shot M8 audit integrity check”.

Limitations and non-goals
Audit logs are not encrypted; they may contain identifiers (op IDs, keys, object IDs, field names).

There is no multi-party notarisation; a single node controls its own audit key.

Key rotation and long-term log retention policies are out of scope.

ViewEvent and SyncEvent are defined but not wired into the UI / net layer yet.

These are all deliberate non-goals for M8 and can be called out as future work.

yaml
Copy code

---

## 2) Update `docs/evaluation-plan.md`

I do not have your current `docs/evaluation-plan.md`, so I cannot give a literal diff, but here is a drop-in section you can append to that file.

Add this near the end as a new top-level section:

```markdown
## M8: Audit integrity and tamper evidence

This section describes how we evaluate the M8 audit trail.

### Goals

- Every decision (`AppliedOp` / `SkippedOp`) made by replay is reflected in the audit log.
- The hash-linked, signed audit chain detects tampering (bit flips, deletions, truncation).
- JSONL exports of the audit log are deterministic and reproducible.

### One-shot check (`m8-dev-check.sh`)

We provide a helper script:

```bash
tools/scripts/m8-dev-check.sh
The script:

Creates a temporary DB and audit directory.

Sets ECAC_NODE_SK_HEX to a deterministic 32-byte ed25519 secret key.

Runs audit-record to replay the store and emit AppliedOp / SkippedOp / Checkpoint events.

Verifies the audit chain with audit-verify-chain.

Verifies replay vs audit consistency with audit-verify-full.

Forces a truncated tail on the last segment and checks that audit-verify-chain repairs it and still accepts.

Runs a small “CLI ops smoke” scenario using op-make-min, op-make-orphan, and op-append-audited, then validates the resulting audit log again.

A successful run ends with:

text
Copy code
All checks passed.
This is the command we use in the paper to claim “audit integrity holds” for a given build.

Manual reproduction
For completeness, the core commands are:

bash
Copy code
# 1) Record decisions into audit log
ECAC_NODE_SK_HEX=<64-hex-ed25519-secret> \
  cargo run -p ecac-cli --features audit -- \
    audit-record --db <db_dir>

# 2) Verify chain integrity
cargo run -p ecac-cli --features audit -- \
  audit-verify-chain --dir <db_dir>/audit

# 3) Verify replay vs audit decisions
ECAC_AUDIT_DIR=<db_dir>/audit \
  cargo run -p ecac-cli --features audit -- \
    audit-verify-full --db <db_dir>

# 4) Export JSONL for archival / analysis
cargo run -p ecac-cli --features audit -- \
  audit-export --dir <db_dir>/audit --out audit.jsonl
These steps are sufficient to independently verify that:

the audit trail is hash-linked and signed,

replay decisions are consistent with the audit log, and

audit exports are deterministic.

yaml
Copy code

---

## 3) What’s still “optional” for M8

- **Net integration:** emit `SyncEvent` from the network layer after each successful fetch batch.
- **View events:** add an opt-in `ViewEvent` hook in the CLI / API wherever a projection is materialised.

Both require touching other crates (`ecac-net` and any UI code). They are not required for the core M8 acceptance criteria you listed (chain integrity, replay cross-check, tamper detection, deterministic export, crash-safety, reason coverage), which you’ve now effectively satisfied.