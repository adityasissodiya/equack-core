# EQUACK Paper Revision Tracker

Tracks changes made during the supervisor-feedback revision (supervisorFeedback.md).

---

## Phase 1: Rewrite the Introduction
**Status:** Complete

### Changes:
- Restructured intro into 6 blocks: offline enforcement problem, why existing approaches fail, what this paper does (ECAC instantiation), why that is novel, contributions, paper roadmap
- Added parenthetical example after "throughout its lifecycle" (compressor sold by vendor A, etc.)
- Broke federated research sharing into separate paragraph
- Added 2-3 sentence gap statement naming the mechanism-level gap
- Added ECAC introduction paragraph citing J&H, distinguishing causal vs topological authorization, listing what ECAC lacks
- Added Kleppmann cite connecting local-first + ECAC
- Added EQUACK introduction paragraph positioning it as concrete ECAC instantiation
- Added novelty sentence (replay mechanism, not ingredients)
- Reworded contribution 1 to position as ECAC instantiation with fine-grained policy support
- Added paper roadmap paragraph with section references

## Phase 2: Novelty Positioning (J&H Differentiation)
**Status:** Complete

### Changes:
- Shortened J&H paragraph in Section 2.1 from ~15 lines to ~4 lines (detailed analysis now in Introduction)
- Added mechanism-level differentiation sentence after Matrix paragraph in Section 2.5/2.6

## Phase 3: Five-Point Gap Enumeration
**Status:** Complete

### Changes:
- Added 5-point mechanism-level gap enumeration after Table 1 gap analysis paragraph
- Points: (i) deterministic reconciliation, (ii) deny-wins revocation, (iii) fine-grained policy evaluation, (iv) in-band propagation, (v) auditable linkage
- ECAC provides framework for (i) but not (ii)-(v); EQUACK fills these gaps

## Phase 4: Merge Model + Implementation
**Status:** Complete

### Changes:
- Renamed Section 3 to "EQUACK: Model and Realization"
- Added framing sentence and prototype summary (crypto choices, ~8500 LOC Rust)
- Renamed subsections with "Realization" concept-then-implementation structure
- Added realization paragraphs with module names to each subsection
- Removed standalone Section 4 (Implementation), kept Table 3
- Updated all cross-references

## Phase 5: Developer Interface Subsection
**Status:** Complete

### Changes:
- Added Section 3.7 "Developer Interface" with pseudocode API listing
- Extracted API surface from actual Rust prototype (replay.rs, dag.rs, crypto.rs, store, net, cli)
- Added factory scenario walkthrough connecting API to industrial use case
- Includes `% TODO: HUMAN` comment for user review

## Phase 6: Evaluation "Why It Matters" Sentences
**Status:** Complete

### Changes:
- Added interpretation sentence after E1 result: delivery order independence as prerequisite for safe offline operation
- Added interpretation sentence after E3 result: revoked engineer's post-revocation changes excluded regardless of reception order
- Added interpretation sentence after E5 result: any party can independently verify no authorization decisions altered
- Added interpretation sentence after E11 result: revocation across partition retroactively invalidates stale writes
- Added interpretation sentence after E12 result: end-to-end deny-wins enforcement across independently operating nodes

## Phase 7: Figure Redesign
**Status:** Complete

### Changes:
- Figure 1 (Offline Enforcement Problem): Bumped `\tiny` labels to `\scriptsize` for IEEE print DPI legibility
- Figure 2 (Architecture): Simplified to clean four-phase lifecycle view — removed implementation-specific details (RocksDB, libp2p, CBOR, op_id) from boxes; kept box-and-connector flow with numbered phase groups (1. Ingest, 2. Validate & 3. Replay, 4. Query); updated caption
- Figure 3 (Causal DAG): Confirmed Algorithm ref resolved correctly; no changes needed
- Figure 4 (Deny-wins replay): Good as-is; no changes
- Skipped optional workflow figure (page budget already met)

## Phase 8: Background Knowledge Reduction Pass
**Status:** Complete

### Changes:
- Added deny-wins definition on first body use (Introduction): "a conflict-resolution rule in which any revocation overrides concurrent permits"
- Added authorization epoch definition on first use (Section 3.2): "the interval during which that credential grants a subject a specific permission"
- Added TrustView definition on first use (Section 3.2): "the replica's materialized view of all issuer keys and credential-status evidence received so far"
- Added gate function explanation before formal definition (Section 3.5): "the predicate that determines whether a data event is authorized at its position in the replay order"
- Added materialized state parenthetical: "(the computed state after replaying all events)"
- Added Discussion section orienting sentence
- Replaced "anti-entropy" with "background synchronization (anti-entropy)" on first use
- Replaced "anti-entropy" label in Figure 1 with "sync"

## Phase 9: Discussion Paragraph Splitting
**Status:** Complete

### Changes:
- Split 4 merged Discussion paragraphs into 8 focused paragraphs:
  1. Partition-duration trade-off (vulnerability window, digital guarantee)
  2. Operational mitigation (short vs long disconnections)
  3. Scalability (memory, throughput, log size constraints)
  4. Deny-wins conservatism (conservative semantics, re-grant recovery)
  5. In-band trust (PKI elimination, TrustView growth, genesis governance)
  6. Comparison scope (paradigm-level comparison, p2panda distinction)
  7. Cedar properties (verified properties hold for converged state)
  8. Prototype scope (simplifications, evaluation limitations, future verification)
