# GPT Pro Writing Context (ECAC Paper)

This file summarizes the **authoritative evaluation context** and **data sources** for readability-focused edits. Use it to avoid inventing or changing technical content.

## 1) Primary Sources (authoritative for writing decisions)

- Paper: `/home/aditya/Downloads/ecac-core/Eventually_Consistent_Access_Control_with_Deterministic_Deny_Wins_Replay_for_Multi_Stakeholder_Offline_Systems/ecac.tex`
- Bibliography: `/home/aditya/Downloads/ecac-core/Eventually_Consistent_Access_Control_with_Deterministic_Deny_Wins_Replay_for_Multi_Stakeholder_Offline_Systems/ecac.bib`
- Experiment log (ground truth for metrics): `/home/aditya/Downloads/ecac-core/experiments/Experiments.md`
- Evaluation summary notes: `/home/aditya/Downloads/ecac-core/docs/eval/RESULTS.md` (some sections are outdated; treat as a template only)
- Evaluation harness (M7): `/home/aditya/Downloads/ecac-core/docs/eval/README.md`
- Plot data: `/home/aditya/Downloads/ecac-core/docs/eval/plots/*.csv` and `/home/aditya/Downloads/ecac-core/docs/eval/plots/README.md`

## 2) Non-authoritative or Draft Docs (use for background only)

These files contain draft or planning text; do not treat them as validated experimental results:

- `/home/aditya/Downloads/ecac-core/experiments/evaluation.tex` (contains placeholders, multi-node claims not executed)
- `/home/aditya/Downloads/ecac-core/docs/evaluation-plan.md` (M7 harness spec; includes warnings about policy not enforced)
- `/home/aditya/Downloads/ecac-core/docs/architecture.md`, `/home/aditya/Downloads/ecac-core/docs/policy-model.md`, `/home/aditya/Downloads/ecac-core/docs/protocol.md`
- `/home/aditya/Downloads/ecac-core/docs/m10_inband_trust.md`, `/home/aditya/Downloads/ecac-core/docs/vc_trust.md` (design notes; may include draft patches)
- `/home/aditya/Downloads/ecac-core/docs/paper/paper.md` (drafting guidance, not current results)

## 3) Local Paper Artifacts (used by the LaTeX)

All paper-referenced artifacts are local to the paper directory:

- Plots:
  - `.../fig-e6-scaling.png`
  - `.../fig-e7-throughput.png`
  - `.../fig-e10-checkpoint-speedup.png`
- Plot data:
  - `.../plot-data-e6-scaling.csv`
  - `.../plot-data-e7-throughput.csv`
  - `.../plot-data-e10-speedup.csv`
- CBOR logs:
  - `.../e3-policy.cbor`
  - `.../e4-policy.cbor`
  - `.../partition-A.cbor`
  - `.../partition-B.cbor`
- Architecture diagram:
  - `.../ecac-architecture.tex`

Paper dir: `/home/aditya/Downloads/ecac-core/Eventually_Consistent_Access_Control_with_Deterministic_Deny_Wins_Replay_for_Multi_Stakeholder_Offline_Systems/`

## 4) Confirmed Experimental Results (use these numbers)

From `experiments/Experiments.md` and current `ecac.tex`:

### E1 – Convergence under random ordering
- 10,000 ops, 100 permutations.
- Digest: `cbab89ee9efbe7bcdd7fd610c2cfda3ba7afd3a6844569a675512095b7f493b2`
- Mean replay time: 615 ms, σ = 18 ms.

### E3 – Revocation correctness (deny-wins)
- `e3-policy.cbor` (1004 ops: 1000 data + 2 grants + 2 revokes).
- Applied: 500 data writes; Skipped: 500 post-revoke writes.
- Digest: `8da8b49e9e10e012aaa72adefb75f79f63c0df12f5034ec5ab1452d346633fbf`.

### E4 – Multi-authority conflict resolution
- `e4-policy.cbor` (128 ops, 3 issuers).
- Applied: 100 (pre-revoke writes); Skipped: 20 (post-revoke writes).
- Digest: `f2fbb024537f80b164fe90ad88e62fb481f95f8d6c1534abacdbc0a61103c2b2`.

### E6 – Replay scaling
- Linear regression: `t = 0.019n + 120 ms`, `R^2 = 0.998`.
- Data in `plot-data-e6-scaling.csv`.

### E7 – Throughput
- hb-chain: ~45,000 ops/s.
- concurrent: ~7,000 ops/s.
- offline-revocation: ~28,000 ops/s.
- Data in `plot-data-e7-throughput.csv`.

### E10 – Checkpoint speedup
- 20K ops, 90% checkpoint: 10×.
- 100K ops, 90% checkpoint: 4×.
- Data in `plot-data-e10-speedup.csv`.

### E11 – Partition merge (revocation propagation)
- Logs: `partition-A.cbor`, `partition-B.cbor`.
- Merged digest: `69fae61ea535b4c8aaebd88907f0ebcb94055c90edf2fc4418c97d0d1a2986c1`.
- Applied: 50; Skipped: 10 (post-revoke writes).

### E13 – Confidentiality overhead (small baseline)
- 100 writes: plaintext replay ~76.8 ms; confidential replay ~81.8 ms (~6.5% overhead).

### E14 – Key rotation overhead (small baseline)
- KeyRotate ~78 ms (small run); store size ~15 MB after small test.

### Not completed / limitations
- E2 cross-platform convergence: not run.
- E8 storage growth: not measured.
- E9 memory peak: not measured.
- E12 network convergence: not measured.
- E5 audit integrity: chain verification works and tamper detection was demonstrated, but full policy/audit cross-check is listed as future work in `docs/eval/RESULTS.md`.

## 5) Reproducibility Environment

Common environment used for deterministic runs:

```
TZ=UTC
SOURCE_DATE_EPOCH=1
ECAC_TIME_MS=1000
HOME=/home/aditya
PATH=/home/aditya/.cargo/bin:$PATH
CARGO_NET_OFFLINE=true
```

## 6) Experiment Generators and Scripts (for provenance)

- Policy logs:
  - `experiments/make_policy_logs/src/main.rs` generates `e3-policy.cbor` and `e4-policy.cbor`.
- Partition logs:
  - `experiments/partition_sim/src/main.rs` generates `partition-A.cbor`, `partition-B.cbor`.
- Permutation runner:
  - `experiments/replay_permute/src/main.rs` for deterministic replay across random topological orderings.
- Harness:
  - `tools/scripts/reproduce.sh`, `tools/scripts/checks.py`, `tools/scripts/plot.py` (M7).

## 7) Important Caveats for Writing

- `docs/eval/RESULTS.md` contains older placeholder digests for E3/E4; **use the values listed in Section 4 above** (and `ecac.tex`), not the placeholders.
- `experiments/evaluation.tex` describes a multi-node testbed and W1–W5 workloads that were **not** executed. Treat as planning text only.
- M7 harness (`docs/eval/README.md`) notes **policy is not enforced** in `offline-revocation` for that harness; do not claim policy enforcement from those runs.
- `/tests/*.rs` are empty placeholders; do not imply test coverage from those files.

## 8) Suggested Writing Conventions

- Keep all values and claims identical to `ecac.tex` and `experiments/Experiments.md`.
- Prefer shorter sentences and explicit topic sentences for readability.
- Avoid adding claims about multi-node performance or cross-platform validation.
- Preserve citations and ordering.

