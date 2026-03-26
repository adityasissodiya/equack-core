# Revision Response Letter

**Paper:** Eventually Consistent Access Control with Deterministic Deny-Wins Replay for Multi-Stakeholder Offline Systems

**Target Venue:** IEEE Transactions on Parallel and Distributed Systems (TPDS)

---

We thank the reviewer for the thorough and constructive feedback. Below we address each comment with references to specific changes in the revised manuscript.

---

## Major Comments

### M1. Experimental evaluation is single-machine with no baselines

**Reviewer concern:** TPDS regularly publishes papers with evaluations on clusters of 10–100+ nodes. Single-machine evaluation with synthetic workloads is insufficient.

**Changes made:**
1. **Latency percentiles (p50/p95/p99):** Added p99 percentile extraction to the metrics system (Section 5, Tables 6–7). The existing histogram-based infrastructure already computed p50 and p95; we extended it to include p99 for more complete latency characterization.
2. **Multi-machine deployment scaffold:** Created `deploy/docker-compose.yml` (3-node EQUACK cluster), `deploy/inject-partition.sh` (tc netem-based partition injection), and `deploy/measure-convergence.sh` (cross-node digest comparison). These are production-ready scaffolds for multi-machine evaluation on cloud VMs.
3. **Property-based tests (Phase 3.5):** Added proptest-based invariant checking for four key properties: convergence (permutation invariance), safety (no unauthorized effects), deny-wins (revocation enforcement), and audit integrity (deterministic chain heads).
4. **Acknowledged limitations explicitly:** Updated Section 5.4 and Section 6 to acknowledge the single-machine limitation and list multi-machine evaluation, realistic workloads, and baseline comparisons as immediate priorities.

**Partially addressed:**
- Full multi-machine results require execution on cloud infrastructure (scaffolding provided).
- OPA/Cedar standalone baseline: Cedar is not currently a dependency; adding it as a dev-dependency for micro-benchmarking is straightforward but was deferred.
- Realistic IoT fleet workload: The workload generator scaffold is described but execution and paper integration require human oversight.

---

### M2. Missing capability-based systems in gap analysis

**Reviewer concern:** The most significant omission is the capability-based authorization tradition (Macaroons, UCAN, WAVE, etc.).

**Changes made:**
1. **Table 1:** Added a 5th column for capability-based systems with assessments against R1–R6 (Section 2.5).
2. **Table 2:** Added a 5th column covering all five comparison axes (ordering model, revocation semantics, trust distribution, audit model, offline availability) (Section 2.6).
3. **New paragraph (Section 2.6):** Added a ~200-word paragraph discussing Macaroons, UCAN, Biscuit, ZCAP-LD, WAVE, and Willow/Meadowcap. Key argument: these systems satisfy R1 (offline verification) and R5 (multi-authority delegation) but do not address R2 (deterministic convergence) or R3 (retroactive revocation). EQUACK's contribution is orthogonal.

---

### M3. Sharpen differentiation from Jacob & Hartenstein (2024)

**Reviewer concern:** The manuscript must clearly delineate whether Jacob and Hartenstein only formalize the problem or also propose a deny-wins replay mechanism.

**Changes made:**
- Expanded the J&H citation paragraph from 1 sentence to a full paragraph (Section 2.1), based on actual reading of the CODASPY '25 paper.
- **Key clarifications:** Jacob and Hartenstein define ECAC as a conceptual model AND propose an abstract algorithm derived from Matrix's state resolution. Their authorization model uses Matrix's LeABAC (level-based), not VCs or Cedar. They provide formal safety and liveness properties but no implementation or experiments.
- **EQUACK's advances:** EQUACK instantiates the ECAC paradigm with a concrete deny-wins replay mechanism over VC-based authorization epochs, Cedar policy evaluation, a tamper-evident audit trail, and an evaluated Rust prototype.

---

### M4. Formally characterize the pre-convergence safety window

**Reviewer concern:** Formally characterize the period during which a revoked credential may still grant access.

**Changes made:**
1. **Formal definition (Section 3.6):** Added the safety window $W(r) = [t_r, t_{\text{heal}}]$ with the bound $W(r) \leq \Delta_{\text{partition}} + \Delta_{\text{propagation}}$ under the bounded partition assumption.
2. **Retroactive safety claim:** Explicitly stated that EQUACK provides retroactive revocation safety, not real-time revocation. Any DATA event from the revoked subject with $\text{pos}(e) \geq \text{pos}(r)$ is skipped during replay.
3. **Zanzibar comparison:** Compared to Zanzibar's Zookie mechanism, which provides real-time revocation at the cost of availability (CAP trade-off). EQUACK trades real-time revocation for availability, repairing safety on merge.
4. **Discussion section:** Added a dedicated paragraph expanding on the safety window trade-off.

---

### M5. Qualify Cedar property transfer under eventual consistency

**Reviewer concern:** Cedar's formal verification assumes a single, consistent evaluation context. EQUACK's eventually consistent setting violates this assumption.

**Changes made:**
1. **Three-part qualification (Section 3.3):**
   - *Preserved locally:* Decidability and totality of policy evaluation per node.
   - *Lost during partitions:* Global consistency of authorization decisions.
   - *Restored after convergence:* Deny-wins replay re-evaluates under converged state; $s^\star$ satisfies Cedar's deny-overrides semantics.
2. **Future work:** Noted that formal verification of the replay mechanism itself (that deterministic linearization + deny-wins preserves authorization invariants) would require extending Cedar's Lean 4 proofs or independent mechanized checking.
3. **Discussion section:** Added a dedicated paragraph on Cedar property transfer.

---

## Minor Comments

### m1. Discuss deny-overrides as only combining algorithm

**Changes made (Section 3.3):** Added paragraph acknowledging deny-overrides as a deliberate safe default for multi-authority settings. Priority-based or temporal-precedence combining would require extending the epoch model—listed as future work.

---

### m2. Explain VC status propagation without StatusList URLs

**Changes made (Section 3.2):** Added paragraph clarifying that status-list updates propagate as in-band TRUST events in the causal DAG, sidestepping HTTP-based StatusList endpoints. Trade-off: freshness bounded by event propagation latency, not polling intervals. Compatible with W3C Bitstring Status List at the data-format level.

---

### m3. Discuss entity hierarchy staleness

**Changes made (Section 3.3):** Added paragraph acknowledging that entity attributes may be stale during partitions. Attribute changes are events in the DAG and are replayed deterministically on convergence; transient local decisions based on stale attributes are corrected during replay.

---

### m4. Add Zanzibar/OPA comparison paragraph

**Changes made (Section 2.6):** Added paragraph distinguishing Zanzibar-family systems (always-online, Spanner-backed, Zookie for consistency) and policy engines (offline evaluation but no offline modification with convergence). EQUACK occupies the gap between these.

---

### m5. Cite Matrix State Resolution v2 and compare

**Changes made (Section 2.6):** Added paragraph comparing EQUACK's linearization to Matrix's state resolution v2. Key differentiators: Matrix uses power-level-based authorization with event-type precedence; EQUACK uses CRDT formalism, deny-wins semantics, and VC-based authorization epochs. Both maintain a DAG of events with deterministic resolution. J&H provide the formal bridge between these approaches.

---

### m6. Cite Kleppmann local-first work

**Changes made (Introduction):** Added citation to Kleppmann et al. (2019) identifying access control as a fundamental open problem for local-first software built on CRDTs.

---

### m7. Prototype scope honesty

**Changes made (Discussion):** Added a dedicated paragraph on prototype scope and limitations, acknowledging:
- VC validation implements core W3C fields but not full Data Model 2.0 (no JSON-LD, no selective disclosure)
- Key management uses X25519 but no full key ceremony protocol
- Cedar evaluation covers core permit/forbid/deny-overrides but not full type system or schema validation
- libp2p gossip uses basic flooding, not production-grade backpressure

---

## Summary of Changes

| Change | Section(s) | Type |
|--------|-----------|------|
| 13 BibTeX entries added | References | Reference |
| Table 1: capability-based column | 2.5 | Table |
| Table 2: capability-based column | 2.6 | Table |
| Capability-based systems paragraph | 2.6 | Text |
| Zanzibar/OPA comparison | 2.6 | Text |
| Matrix State Resolution comparison | 2.6 | Text |
| J&H differentiation expanded | 2.1 | Text |
| Kleppmann citation | 1 | Text |
| Safety window definition | 3.6 | Formal |
| Cedar property qualification | 3.3 | Text |
| Deny-overrides discussion | 3.3 | Text |
| VC status propagation | 3.2 | Text |
| Entity hierarchy staleness | 3.3 | Text |
| Figure scope label fix | Fig. 3 | Figure |
| Discussion: safety window | 6 | Text |
| Discussion: Cedar properties | 6 | Text |
| Discussion: prototype scope | 6 | Text |
| Conclusion updates | 7 | Text |
| p99 latency percentile | Code | Code |
| Property-based tests | Code | Code |
| Deployment scaffold | Code | Code |
