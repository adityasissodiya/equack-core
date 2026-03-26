# EQUACK Revision Tracker

This file logs each completed revision task with a summary of changes made.

## Completed Tasks

### Phase 1.1: Add missing BibTeX entries
- Added 7 must-add entries: `kleppmann2019localfirst`, `kleppmann2022bft`, `cutler2024cedar`, `birgisson2014macaroons`, `andersen2019wave`, `zanzibar2019`, `rfc9200`
- Added 6 should-add entries: `ucan2022`, `biscuit2023`, `willow2024`, `miller2006thesis`, `matrix_stateresv2`, `openfga`
- All entries compile without BibTeX warnings

### Phase 1.5: Sharpen differentiation from Jacob & Hartenstein (2024)
- Expanded the J&H citation paragraph from 1 sentence to a full paragraph
- Based on actual reading of the J&H paper (CODASPY '25)
- Key points: J&H formalize ECAC as a conceptual model AND propose an abstract algorithm; they use Matrix's LeABAC for authorization, not VCs or Cedar; no implementation or experiments
- EQUACK advances beyond: concrete deny-wins mechanism, VC-based epochs, Cedar policy evaluation, audit trail, evaluated Rust prototype

### Phase 1.2: Expand Table 1 (gap analysis)
- Added 5th column for capability-based systems (Macaroons, UCAN, WAVE)
- Capability-based: R1=Yes, R2=No, R3=Partial, R4=Partial, R5=Yes, R6=No
- Updated gap analysis text to mention five paradigms

### Phase 1.3: Add capability-based systems paragraph
- Inserted paragraph in Section 2.6 covering Macaroons, UCAN, Biscuit, ZCAP-LD, WAVE, Willow/Meadowcap
- Key argument: these satisfy R1 and R5 but not R2 (convergence) or R3 (retroactive revocation)

### Phase 1.4: Add Zanzibar/OPA comparison paragraph
- Inserted paragraph in Section 2.6 comparing Zanzibar (always-online, Spanner-backed) and policy engines (offline eval but no offline modification with convergence)
- Key argument: EQUACK occupies the gap between these

### Phase 1.2 (Table 2): Expand mechanism-level comparison
- Added 5th column for capability-based systems across all 5 axes
- Adjusted column widths to fit IEEE double-column format

### Phase 1.6: Cite Matrix State Resolution v2
- Added paragraph in Section 2.6 comparing EQUACK's linearization to Matrix's state resolution
- Differentiators: power-level vs deny-wins, LeABAC vs CRDT+Cedar

### Phase 1.7: Cite Kleppmann local-first work
- Added sentence in Introduction after problem statement citing Kleppmann et al. 2019
- Paraphrased (not direct quote) their identification of access control as open problem for local-first software

### Phase 2.1: Add safety window analysis
- Added formal definition of W(r) = [t_r, t_heal] in Section 3.6
- Bound: W(r) ≤ Δ_partition + Δ_propagation (finite under bounded partition)
- Explicit comparison to Zanzibar's Zookie (real-time at cost of availability)

### Phase 2.2: Qualify Cedar property transfer
- Added paragraph in Section 3.3 with three-part structure
- Preserved locally: decidability, totality per-node
- Lost during partitions: global authorization consistency
- Restored after convergence: deny-wins replay re-evaluates under converged state

### Phase 2.3: Discuss deny-overrides as only combining algorithm
- Added paragraph in Section 3.3 acknowledging limitation
- Framed as deliberate safe default; priority-based combining requires extending epoch model

### Phase 2.4: VC status propagation mechanism
- Added paragraph in Section 3.2 clarifying in-band TRUST event propagation
- Explained trade-off vs HTTP-based StatusList endpoints

### Phase 2.5: Entity hierarchy staleness
- Added paragraph in Section 3.3 acknowledging stale entity attributes during partitions
- Corrected on merge via deterministic replay

### Phase 4.3: Fix figure TODOs
- Resolved scope label inconsistency: changed "hv" to "confidential" in fig-deny-wins.tex
- Marked pre-revoke count and subject key issues as TODO: HUMAN for code-side fixes

### Phase 5.1: Expand Discussion
- Added pre-convergence safety window discussion paragraph
- Added Cedar property transfer discussion paragraph
- Added prototype scope and limitations paragraph (VC validation subset, key management simplifications, Cedar subset, libp2p simplifications)

### Phase 5.2: Revise Conclusion
- Updated future work: multi-machine evaluation, realistic workloads, baseline comparisons, TLA+/Lean mechanized verification, configurable combining algorithms, Jepsen testing
- Added explicit acknowledgment of safety window limitation and Cedar property transfer in limitations paragraph

### Phase 3.1: Add p99 latency percentile (in progress)
- Adding p99 to existing metrics system (p50/p95 already present)

### Phase 3.4: Multi-machine deployment scaffold (in progress)
- Creating deploy/docker-compose.yml, inject-partition.sh, measure-convergence.sh

### Phase 3.5: Property-based tests (in progress)
- Adding proptest tests for convergence, safety, deny-wins, audit integrity

### p2panda comparison (Section 2.6 + Discussion)
- Added 5 BibTeX entries: `p2panda2024`, `p2panda_auth2025`, `p2panda_encryption2025`, `p2panda_accesscontrol2025` (unused, omitted), `weidner2021dcgka`
- Inserted paragraph in Section 2.6 after Matrix State Resolution: p2panda is closest existing system; three differentiators (protocol-level deny-wins enforcement, VC-based epochs with Cedar-inspired ABAC, explicit audit trail)
- Inserted paragraph in Discussion (Comparison scope): enforcement location difference, encryption maturity acknowledgment, infeasibility of direct empirical comparison
- Verified all claims against equack-core source: Gate mandatory (replay.rs), HLC ordering (hlc.rs, dag.rs), XChaCha20-Poly1305 (crypto.rs), KeyRotate/KeyGrant (op.rs), audit chain (audit.rs, store/audit.rs)
- Note: Cedar is described as "Cedar-inspired" (matching paper's own language) since codebase has no actual Cedar dependency
- Paper compiles cleanly at 17 pages; all new citations resolve

### New diagrams: safety window, epoch lifecycle, enforcement comparison
- Created `diagrams/fig-safety-window.tex`: Timeline visualization of pre-convergence safety window W(r), showing two replicas during partition — one receives Revoke, the other accepts stale ops — then converging after anti-entropy (addresses reviewer M4 visually)
- Created `diagrams/fig-epoch-lifecycle.tex`: Authorization epoch lifecycle showing GRANT opens epoch → DATA ops applied → REVOKE closes → DATA ops skipped → re-GRANT opens fresh epoch. Visualizes the re-grant concept mentioned only textually in Section 3.3
- Created `diagrams/fig-enforcement-compare.tex`: Side-by-side EQUACK vs p2panda architecture stack, highlighting where deny-wins enforcement sits (protocol-level mandatory vs application-optional). Complements the new p2panda comparison text
- Inserted Figure 5 (enforcement comparison) in Section 2.6 after p2panda paragraph
- Inserted Figure 6 (epoch lifecycle) in Section 3.3 after epoch/re-grant discussion
- Inserted Figure 7 (safety window) in Section 3.6 after safety window formalization
- Paper compiles cleanly at 18 pages (1 page increase for 3 full-width figures)

### Fix Evaluation section: experiment overview + Theorem mapping + E10 resolution
- Added experiment summary table (Table 5) after Methodology, mapping each experiment (E1–E14, excluding E10) to the theorem(s) it validates (T1–T5) or "Perf" for performance experiments
- Fixed opening sentence of Section 5: replaced "(R2–R5)" with "(Theorems 1–5)" and removed awkward R1 assumption phrasing
- Replaced all R-labels in experiment paragraph headers with Theorem references: E1→T1,T2; E3→T3; E11→T2,T3; E4→T1–T3; E5→T4; E2→T1; E12→T2,T3; E13,E14→T5
- Resolved ghost E10: checkpoint efficiency data was already in E6's table (Table 6). Removed "(E6, E10)" → "(E6)" in Conclusion
- Added bridging sentence between overview table and Correctness subsection
- Verification: no stale R-labels remain in evaluation headers; no E10 references remain; paper compiles cleanly at 18 pages

### Redesign causal-dag figure: semantic edge types, labels, legend
- Replaced uniform parentlink arrows with three semantic edge styles: trust-chain (dashed teal), authorization (dotted blue), data/causal (solid orange)
- Added per-edge semantic labels: "verifies issuer", "causal dep", "activates VC", "gated by", "CRDT merge"
- Added edge-type entries to the legend alongside existing tiebreaking rules
- Added event-type badges (TRUST, CREDENTIAL, DATA, GRANT) to each node
- Connected annotation boxes ("Auth Epoch Builder" brace, "Deny-Wins Gate" arrow) to specific edges/nodes
- Added faint background replay-order path connecting nodes in linearisation order
- Updated figure caption to describe the three edge categories
- Updated reference text in Section 2 to match new figure content

## Pending Tasks

### Phase 3.2: Realistic workload scenario
- IoT fleet workload generator — deferred to human execution

### Phase 3.3: OPA/Cedar baseline
- Cedar not currently a dependency — requires adding cedar-policy crate

### Phase 3.6: Cross-platform CI
- GitHub Actions workflow — deferred to human execution

### Phase 6: Revision response letter
- To be generated after all changes are applied