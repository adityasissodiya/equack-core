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

## Pending Tasks

### Phase 3.2: Realistic workload scenario
- IoT fleet workload generator — deferred to human execution

### Phase 3.3: OPA/Cedar baseline
- Cedar not currently a dependency — requires adding cedar-policy crate

### Phase 3.6: Cross-platform CI
- GitHub Actions workflow — deferred to human execution

### Phase 6: Revision response letter
- To be generated after all changes are applied
