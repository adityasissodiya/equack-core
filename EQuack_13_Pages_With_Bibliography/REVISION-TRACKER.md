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
