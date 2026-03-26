# EQUACK Revision Plan — Claude Code Execution Guide

## Context

You are working on revising a paper titled "Eventually Consistent Access Control with Deterministic Deny-Wins Replay for Multi-Stakeholder Offline Systems" (EQUACK), targeting IEEE TPDS. A detailed peer review has been completed. Your job is to apply the reviewer's comments systematically.

## Available Resources — Read These First

Two reference files have been prepared specifically for you. **Read them before doing anything else.**

1. **`material.md`** — Located alongside the repo and paper files. Contains:
   - Complete section map of the paper (section numbers, content summaries, figure/table inventory)
   - All formal model symbols and LaTeX notation (exact definitions of `Gate(e)`, `Replay`, `Auth`, audit chain, etc.)
   - Every experimental result with exact digest values and table data
   - All reviewer comments distilled to minimum-fix specs (M1–M5 major, m1–m7 minor)
   - Pre-written draft text fragments in IEEE transaction style, ready to insert
   - Pre-written BibTeX entries (with `% VERIFY` markers where uncertain)
   - Code change sketches (latency percentiles, proptest properties, workload struct, Docker Compose)
   - Explicit list of things you cannot verify and must flag for the human

   **Use `material.md` as your primary reference.** Do not re-read the full paper to find section numbers, symbol definitions, experimental results, or reviewer requirements — they are already extracted for you.

2. **Jacob & Hartenstein (2024) paper** — A PDF or text file of "To the best of knowledge and belief: On eventually consistent access control" is available in the working directory. This is the key prior work the reviewer demands differentiation from (Task 1.5). **Read it directly** — do not guess about its contents.

## Repository Orientation

The expected layout is documented in `material.md` Section 3 (Crate Layout). On first run, do a quick verification that the actual repo matches:

```
# Verify material.md's layout assumptions match reality (should take <30 seconds)
ls -la  # top-level contents
find . -name "*.tex" -maxdepth 2 | sort   # confirm .tex file locations
find . -name "*.bib" -maxdepth 2 | sort   # confirm .bib file locations
find . -name "Cargo.toml" -maxdepth 2     # confirm crate structure
```

If anything diverges from `material.md` Section 3, note the discrepancy and adjust your commands accordingly. Do NOT run broad discovery commands like `find . -name "*.rs" | head -60` — `material.md` already tells you where things are.

---

## Phase 0: Triage & Prep (do this first)

### 0.1 — Read material.md
```
cat material.md
```
This is non-negotiable. Do it before any other work.

### 0.2 — Read the Jacob & Hartenstein paper
```
# Find and read the J&H paper (PDF or text, placed in the working directory)
find . -maxdepth 2 -name "*jacob*" -o -name "*hartenstein*" -o -name "*eventually*consistent*access*" 2>/dev/null
# Then read it — use pdftotext if it's a PDF, or cat if text
```
Take notes on:
- Do J&H formalize the problem only, or also propose a mechanism?
- If they propose a mechanism, what is it? (consensus-based? CRDT? token-based?)
- What do they identify as open problems?
- Where does EQUACK advance beyond their work?

You will need these notes for Task 1.5.

### 0.3 — Snapshot current state
```
git log --oneline -5
git diff --stat  # check for uncommitted work
```

### 0.4 — Create a tracking file
Create `REVISION-TRACKER.md` in the repo root. Use it to log each completed task with a one-line summary of what changed. This is your running changelog for the revision response letter.

### 0.5 — Verify the paper compiles
```
# Use the main .tex filename from material.md Section 2
latexmk -pdf <main-file>.tex
```
Fix any pre-existing compilation issues before making changes.

---

## Phase 1: Related Work & References (Paper-only, no code changes)

These are the highest-impact, lowest-risk changes. They address the reviewer's most pointed criticism about missing literature without touching any technical claims.

### 1.1 — Add missing BibTeX entries

**Pre-written entries are in `material.md` Section 8.** Copy them into the `.bib` file. For each entry:
- If marked `% VERIFY`, do a quick web search to confirm correctness before inserting.
- If you cannot verify, insert as-is but keep the `% VERIFY` comment so the human can check later.

After inserting all entries, run:
```
bibtex <main-file>  # or biber, depending on the paper's build
```
Fix any warnings before proceeding.

**Must-add (7 entries):** `kleppmann2019localfirst`, `kleppmann2022bft`, `cutler2024cedar`, `birgisson2014macaroons`, `andersen2019wave`, `zanzibar2019`, `rfc9200`

**Should-add (6 entries):** `ucan2022`, `biscuit2023`, `willow2024`, `miller2006thesis`, `matrix_stateresv2`, `openfga`

### 1.2 — Expand gap analysis tables (Tables 1 and 2)

Add a fifth column for **capability-based systems**. The exact cell values and axis entries are in `material.md` Sections 9.6 and 9.7. Copy them and adapt to the existing table's LaTeX formatting.

Check that the expanded table still fits within IEEE double-column width. If it overflows, use abbreviations or reduce font size with `\footnotesize` inside the table environment.

### 1.3 — Add Related Work paragraph on capability-based systems

A draft paragraph is in `material.md` Section 9.1. Insert it into Section 2.5 or 2.6 (use the section map to find the right location). Adapt as needed to match surrounding prose style and ensure citations resolve against the entries added in 1.1.

### 1.4 — Add Zanzibar/OPA comparison paragraph

A draft paragraph is in `material.md` Section 9.2. Insert into Section 2.6 (mechanism-level comparison). Same adaptation instructions as 1.3.

### 1.5 — Sharpen differentiation from Jacob & Hartenstein (2024)

**You have the J&H paper available.** Using your notes from Phase 0.2, write 3–5 sentences after the existing citation to [8] that explicitly state:
- What J&H actually propose (problem formalization? mechanism? both?)
- What specific limitation of their approach EQUACK addresses
- If they only formalize, state that EQUACK provides the first concrete mechanism

Do NOT use the draft fragments in `material.md` for this task — they were written without access to J&H and may be wrong. Write fresh text based on your actual reading of the paper.

### 1.6 — Cite Matrix State Resolution v2

Add a paragraph in the mechanism comparison section (Section 2.6) discussing Matrix's state resolution as the closest deployed system solving a structurally similar problem. Key differentiators to state:
- Matrix: power-level-based authorization with specific tie-breaking rules, event-type precedence
- EQUACK: CRDT formalism, deny-wins semantics, VC-based authorization epochs
- Both: DAG of events, deterministic resolution across federated/replicated nodes

### 1.7 — Cite Kleppmann's local-first work

A draft sentence is in `material.md` Section 9.5. Insert into the Introduction after the problem statement paragraph. **Note:** the draft contains an approximate quote from Kleppmann. Either verify the quote against the actual paper (search the web if needed) or rephrase without quoting.

---

## Phase 2: Formal / Analytical Additions (Paper text, possibly light code)

These address the reviewer's concerns about insufficiently analyzed safety gaps and Cedar property transfer.

### 2.1 — Add "Safety Window" analysis

A draft paragraph with the formal definition is in `material.md` Section 9.3. Insert as a new `\paragraph{Pre-convergence safety window.}` in Section 3.6 or as a new subsection.

Key elements (all present in the draft):
- Definition: `W(r) = [t_r, t_heal]` where `t_heal` is when all correct replicas have `r`
- Bound: `W(r) ≤ Δ_partition + Δ_propagation` (finite under bounded partition assumption)
- Claim: EQUACK provides retroactive revocation safety, not real-time revocation
- Comparison: Zanzibar's Zookie provides real-time at cost of availability (CAP trade-off)

Use the formal symbols from `material.md` Section 4 to ensure consistency with existing notation.

### 2.2 — Qualify Cedar property transfer

A draft paragraph is in `material.md` Section 9.4. Insert into Section 3.3 after the existing Cedar discussion.

Three-part structure:
1. **Preserved locally:** decidability, totality per-node
2. **Lost during partitions:** global authorization consistency
3. **Restored after convergence:** deny-wins replay re-evaluates under converged state

### 2.3 — Discuss deny-overrides as the only combining algorithm

Add 2–3 sentences in Section 3.3 acknowledging the limitation. Frame deny-overrides as a deliberate safe default for multi-authority settings (no single authority should override a deny). Note that priority-based or temporal-precedence combining would require extending the epoch model — future work.

### 2.4 — Discuss VC status propagation mechanism

Locate Section 3.2 (TRUST events, TrustView). Add or clarify:
- Status-list updates propagate as in-band TRUST events in the causal DAG
- This sidesteps HTTP-based StatusList endpoints
- Trade-off: freshness bounded by event propagation latency, not polling intervals
- State compatibility stance with W3C Bitstring Status List

### 2.5 — Discuss entity hierarchy staleness

Add 2–3 sentences (Section 3.3 or 3.6) acknowledging that entity attributes may be stale during partitions. Entity changes are events in the DAG → replayed deterministically → converged state is correct. Transient local decisions may be incorrect but are corrected on merge.

---

## Phase 3: Experimental Improvements (Code + Paper)

The reviewer's strongest criticism. Not all achievable in one session — prioritize by impact. `material.md` Section 10 has code sketches for each task.

### 3.1 — Add latency distribution reporting to existing benchmarks

**Priority: HIGH (low effort, high signal)**

`material.md` Section 10.1 has a Rust sketch for percentile computation. Find the actual benchmark harness:
```
# material.md says benchmarks are likely in cli/ — verify
grep -rn "duration\|elapsed\|Instant" --include="*.rs" cli/
```

Modify to record per-op or per-batch durations and report p50/p95/p99. Update Tables 6 and 7 in the paper with the new columns.

### 3.2 — Add a realistic workload scenario

**Priority: HIGH (medium effort, directly addresses reviewer)**

`material.md` Section 10.2 has an `IoTFleetWorkload` struct sketch. Create a new workload generator that mixes TRUST, CREDENTIAL, GRANT, DATA, and REVOKE events with realistic proportions and a partition-heal cycle.

Add results to the paper as a new experiment (e.g., E15). Include in Table 4 (workload characteristics) and add a throughput entry to Table 7.

### 3.3 — Add OPA/Cedar baseline for policy evaluation latency

**Priority: MEDIUM (addresses "no baselines" criticism)**

Check if `cedar-policy` is already a dependency:
```
grep -r "cedar" Cargo.toml */Cargo.toml
```

If Cedar's Rust crate is already used, write a micro-benchmark that evaluates the same policy set directly via Cedar's API and compares per-evaluation latency against EQUACK's gate evaluation. This isolates policy evaluation from DAG replay.

If Cedar is not a dependency, consider adding it as a dev-dependency for benchmarking, or use OPA via `opa eval` in a shell benchmark.

### 3.4 — Implement multi-machine deployment script

**Priority: HIGH but requires human execution**

`material.md` Section 10.4 has Docker Compose and partition injection script scaffolds. Create:
- `deploy/docker-compose.yml` — 3–5 EQUACK nodes
- `deploy/inject-partition.sh` — uses `tc netem` to simulate partition
- `deploy/measure-convergence.sh` — queries state digests across nodes after heal

The human will run these on cloud VMs and collect results. Your job is production-ready scaffolding.

### 3.5 — Add Jepsen-style invariant checking

**Priority: MEDIUM (strengthens correctness claims)**

`material.md` Section 10.3 lists the four properties to test. Add `proptest` to dev-dependencies and write property-based tests for:
1. Convergence: any permutation of same event set → identical digest
2. Safety: no applied DATA lacks a valid epoch at its replay position
3. Deny-wins: REVOKE blocks all post-REVOKE DATA for that credential
4. Audit integrity: audit chain head is deterministic for same event set

### 3.6 — Expand E2 cross-platform determinism

**Priority: LOW (reviewer noted but didn't demand)**

Create `.github/workflows/cross-platform.yml` with matrix: `[ubuntu-latest, macos-latest, windows-latest]` × `[x86_64, aarch64]`. Each job replays the E2 fixture and asserts the hardcoded digest.

---

## Phase 4: Figures & Presentation (Paper-only)

### 4.1 — Update Table 1 and Table 2

Execute the changes specified in Phase 1.2. Verify rendering after compilation.

### 4.2 — Add a safety window diagram

Create a new TikZ figure (`fig-safety-window.tex` or inline) showing:
- Timeline with `t_revoke`, `t_heal`, and `W(r)` interval
- Replica A (has revocation) rejecting writes
- Replica B (missing revocation) accepting writes during `W(r)`
- Post-heal replay skipping those writes

Style should match existing figures (check `fig-partition-heal.tex` for visual language). This new figure should add information beyond what the partition-heal figure already shows — focus on the temporal bound and the retroactive correction, not the merge mechanics.

### 4.3 — Fix the three open TODOs in existing figures

```
grep -rn "TODO" --include="*.tex" .
```

Three known issues (from `material.md` Section 2):
1. Pre-revoke write count mismatch between figure and text
2. Identical subject keys for both writers (should differ)
3. Scope label inconsistency between figure and text

---

## Phase 5: Discussion Section Updates

### 5.1 — Expand Discussion with reviewer-requested topics

The paper currently has Section 5.4 (Limitations and Threats to Validity) and Section 6 (Conclusion). Locate where Discussion content lives, then add or expand:

1. **Safety window analysis** — cross-ref the formal addition from Phase 2.1
2. **Cedar property transfer** — cross-ref Phase 2.2
3. **Capability-based systems comparison** — why EQUACK is needed beyond UCAN/Macaroons (cross-ref Phase 1.3)
4. **Combining algorithm extensibility** — cross-ref Phase 2.3
5. **Prototype scope and limitations** — read the actual Rust code to determine which components are simplified. Be honest about:
   - Does VC validation implement the full W3C data model or a subset?
   - Does key rotation implement full X25519 key agreement or a simplified version?
   - Are all Cedar policy features supported or only a subset?
   - Is the libp2p gossip layer production-grade or a minimal implementation?

### 5.2 — Revise the Conclusion

Update to:
- Reflect any new experiments added (E15 realistic workload, latency percentiles)
- Acknowledge the safety window limitation explicitly
- Remove or qualify claims that new experiments don't fully support
- Update future work: mechanized proofs (TLA+/Lean), Jepsen testing, multi-machine evaluation, real-world deployment, log compaction

---

## Phase 6: Revision Response Letter

After all changes are applied, generate `response-letter.md` that:
- Lists each reviewer comment (use M1–M5 and m1–m7 labels from `material.md` Section 7)
- States what was done to address it
- References specific sections, figures, or experiments in the revised paper
- For any comment not fully addressed, explains why and what partial steps were taken

Use `REVISION-TRACKER.md` as the source for this.

---

## Execution Order

```
Phase 0       →  Read material.md + J&H paper, snapshot, verify compilation
Phase 1.1     →  BibTeX entries (copy from material.md Section 8, verify)
Phase 1.5     →  J&H differentiation (uses your Phase 0.2 reading — do while fresh)
Phase 1.2–1.4 →  Tables + paragraphs (copy drafts from material.md Sections 9.1–9.2, 9.6–9.7)
Phase 1.6–1.7 →  Matrix + Kleppmann citations
Phase 4.3     →  Fix existing figure TODOs (while you're in the .tex files)
Phase 2       →  Analytical additions (copy drafts from material.md Sections 9.3–9.4, then refine)
Phase 4.1–4.2 →  Updated tables + new safety window figure
Phase 5       →  Discussion + conclusion revisions
Phase 3.1     →  Latency percentiles (quick code win)
Phase 3.5     →  Property-based tests (strengthens correctness)
Phase 3.2     →  Realistic workload (medium effort)
Phase 3.3     →  OPA/Cedar baseline (medium effort)
Phase 3.4     →  Multi-machine infra scaffold (human runs it)
Phase 3.6     →  CI matrix (low priority)
Phase 6       →  Response letter (always last)
```

---

## Ground Rules

1. **Read `material.md` first.** It has pre-written text, BibTeX entries, table data, code sketches, and reviewer requirements. Do not re-derive what's already extracted.
2. **Read the J&H paper directly for Task 1.5.** Do not guess or use placeholder text. This is the one task where `material.md` explicitly says its drafts may be wrong.
3. **Never fabricate citations.** If a BibTeX entry from `material.md` is marked `% VERIFY` and you can't verify it, keep the marker — don't silently remove it.
4. **Compile after every .tex change.** Run `latexmk -pdf` and fix errors before moving on.
5. **Run `cargo test` after every .rs change.** Do not leave broken tests.
6. **Commit after each completed task** with a message referencing the phase/task number (e.g., `"Phase 1.1: add missing BibTeX entries"`).
7. **Log every completed task** in `REVISION-TRACKER.md`.
8. **Flag tasks requiring human input** with a `% TODO: HUMAN` or `// TODO: HUMAN` comment. The remaining items needing human action are listed in `material.md` Section 11 — but note that J&H (item 1 in that list) is now resolved since the paper is available.
9. **Respect IEEE TPDS formatting constraints** — double-column, typically ~14 pages. Check `\documentclass` options after adding content.
10. **Do not run broad discovery commands.** `material.md` tells you where things are. Verify with targeted `ls` or `find` commands, not sweeping searches.
