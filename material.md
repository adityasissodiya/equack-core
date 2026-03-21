# EQUACK Revision — Reference Material for Claude Code

> **Purpose:** This file contains everything you need to execute the revision plan (`equack-revision-plan.md`) without guessing, hallucinating references, or re-reading the full paper. Treat this as your ground truth. If something isn't here and you can't find it in the repo, **flag it for the human** rather than inventing content.

---

## 1. Paper Metadata

- **Title:** Eventually Consistent Access Control with Deterministic Deny-Wins Replay for Multi-Stakeholder Offline Systems
- **Authors:** Ulf Bodin, Eric Chiquito, Johan Kristiansson, Aditya Sissodiya
- **Affiliation:** Luleå University of Technology, Sweden
- **Target venue:** IEEE Transactions on Parallel and Distributed Systems (TPDS)
- **Model name:** EQUACK (Eventually Consistent Access Control)
- **Prototype name:** EQUACK (Rust), repository: `equack-core`
- **Prototype size:** ~8,500 lines of Rust (excluding tests)

---

## 2. Paper Structure (Section Map)

Use this to locate where edits go. Section numbers match the submitted PDF.

| Section | Title | Content Summary |
|---------|-------|-----------------|
| 1 | Introduction | Factory scenario, problem statement, contributions list (4 items) |
| 2 | Problem Analysis | System model, threat model, R1–R6 requirements, gap analysis (Table 1), mechanism comparison (Table 2) |
| 2.1 | The Offline Enforcement Problem | Partition-time divergence, out-of-order delivery, multi-authority conflicts |
| 2.2 | System Model | Replicas, subjects, issuers, PEP, HLC timestamps, causal DAG, gossip/anti-entropy |
| 2.3 | Threat Model and Assumptions | Adversary capabilities, 4 scoping assumptions |
| 2.4 | Conceptual Requirements | R1–R6 definitions |
| 2.5 | Gap Analysis | Table 1: 4 paradigms × R1–R6 |
| 2.6 | Mechanism-Level Comparison | Table 2: 5 axes × 4 paradigms |
| 3 | EQUACK Model | Four key elements, four-phase lifecycle (Figure 1) |
| 3.1 | Event Log and Deterministic Deny-Wins Replay | Causal DAG, HLC+op-ID ordering, deny-wins rule |
| 3.2 | Authorization Epochs via VCs and Status Lists | VC format, status lists, TrustView, in-band TRUST events |
| 3.3 | Policy Semantics (Cedar) and Deny-Overrides Alignment | Cedar-inspired ABAC, deny-overrides, REVOKE terminates epochs, replay example |
| 3.4 | Tamper-Evident Audit Trail | Hash-chained audit records, signed per-replica |
| 3.5 | Confidentiality and Key Rotation | Per-tag XChaCha20-Poly1305, KeyRotate, KeyGrant, leaver security |
| 3.6 | Formal Model and Guarantees | Full formal definitions, Algorithm 1, Theorems 1–5 |
| 4 | Implementation | 4 crates (core, store, net, cli), crypto choices, Table 3 (concept→module map) |
| 5 | Evaluation | 14 experiments (E1–E14), Tables 4–9 |
| 5.1 | Methodology | Single Linux x86_64, Rust 1.85 release, 3 synthetic workloads + 2 CBOR logs |
| 5.2 | Correctness | E1 (convergence), E2 (cross-platform), E3 (deny-wins), E4 (multi-authority), E5 (audit), E11 (partition), E12 (multi-node sync) |
| 5.3 | Performance | E6 (replay scaling), E7 (throughput by workload), E8 (storage), E9 (memory), E13–E14 (encryption) |
| 5.4 | Limitations and Threats to Validity | Partition window, log growth, metadata privacy, single-machine caveat |
| 6 | Conclusion | Summary, immediate priorities, longer-term directions |

### Figures

| Figure | Content | File (likely) |
|--------|---------|---------------|
| Fig. 1 | EQUACK prototype overview (4-phase lifecycle flow) | `fig-architecture.tex` or similar |
| Fig. 2 | Operation structure + causal DAG topological sort | `fig-dag.tex` or similar |
| Fig. 3 | Deterministic replay slice from compliance fixture (deny-wins) | `fig-deny-wins.tex` |
| Fig. 4 | Partition-heal semantics diagram | `fig-partition-heal.tex` |

### Tables

| Table | Content |
|-------|---------|
| Table 1 | Gap analysis: 4 paradigms × R1–R6 (needs new column: capability-based) |
| Table 2 | Mechanism comparison: 5 axes × 4 paradigms (needs new column: capability-based) |
| Table 3 | Concept → implementation module mapping |
| Table 4 | Synthetic workload characteristics |
| Table 5 | Multi-node sync convergence (E12) |
| Table 6 | Replay time vs. log size (E6) — needs latency percentiles |
| Table 7 | Replay throughput by scenario (E7) |
| Table 8 | Storage growth vs. op count (E8) |
| Table 9 | Peak RSS during replay (E9) |

### Known TODOs in existing figures

Search for `%TODO` in `.tex` files. Three known issues from prior editing sessions:
1. **Pre-revoke write count mismatch** — a figure labels a different number of pre-revoke writes than the text describes
2. **Identical subject keys for both writers** — two writers in a diagram use the same public key label when they should differ
3. **Scope label inconsistency** — a scope label in one figure doesn't match the scope used in the corresponding text

---

## 3. Crate Layout (Implementation)

```
equack-core/
├── core/       # Operations, DAG, replay, policy (Cedar), VC parsing/verification, CRDTs
│   ├── dag.rs          # Causal DAG construction
│   ├── replay/
│   │   └── topo_sort.rs  # Algorithm 1: deterministic linearization
│   ├── epoch.rs        # Authorization epoch builder
│   ├── policy/
│   │   └── gate.rs     # Deny-wins gate
│   ├── trust.rs        # TrustView assembly
│   ├── vc.rs           # VC verification
│   ├── crdt.rs         # MVReg, OR-Set
│   └── crypto.rs       # Per-tag encryption
├── store/      # RocksDB persistence, checkpoints, audit chain
│   ├── audit.rs
│   └── checkpoint.rs
├── net/        # libp2p gossip + anti-entropy
│   └── gossip.rs
└── cli/        # CLI for workload generation, log manipulation, experiments
```

**Crypto choices:** Ed25519 (signatures), BLAKE3 (hashing), XChaCha20-Poly1305 (encryption), SHA-256 (status list bitstrings). Serialization: CBOR.

**Key dependencies (expected):**
- `ed25519-dalek` or `ring` for Ed25519
- `blake3` for hashing
- `chacha20poly1305` for encryption
- `rocksdb` for persistence
- `libp2p` for networking
- `serde` + `serde_cbor` or `ciborium` for CBOR
- Possibly `cedar-policy` crate for policy evaluation

---

## 4. Formal Model Reference (for writing LaTeX)

Use these exact symbols and definitions when adding formal content.

### Core Sets and Types
```
Subj        — subjects (principals)
Res         — resources
Act         — actions
Attr        — attribute valuations
Tms = (ℕ, ≤)  — physical time in milliseconds
NodeId      — replica identifiers
Thlc := Tms × ℕ × NodeId  — HLC timestamps, ordered lexicographically
phys : Thlc → Tms   — projects physical millisecond component
H           — collision-resistant hash (BLAKE3)
Sig_k(·)    — secure signature scheme (Ed25519)
```

### Event Types
```
Ev = DATA ⊎ GRANT ⊎ REVOKE ⊎ TRUST ⊎ KEY
```

### Op-ID and Signing
```
op_id(e) := H(domain ∥ CBOR(h₀(e)))
σ_e := Sig_{sk_r}(op_id(e))
h(e) := (h₀(e), σ_e)
```

### Deterministic Key
```
k(e) := ⟨hlc(e), op_id(e)⟩   — ordered lexicographically
```

### Authorization Predicate
```
Auth(s, a, e) := ∃c s.t.  phys(hlc(e)) ∈ [nb, na)
                         ∧ c grants (s, a)
                         ∧ SL^{pos(e)}_{iss(c)}(id(c)) = good
```

### Gate Function
```
Gate(e) := ∃ ep ∈ Epochs(s, a) s.t.
           pos(e) ∈ [p_start, p_end)
           ∧ phys(hlc(e)) ∈ [nb, na)
           ∧ P(s, a, r, α_e) = allow
```

### Replay
```
Replay(s₀, ⟨e⟩◁) := fold(s₀, λ(s, e). { U(s, e)  if e ∈ DATA ∧ Gate(e)
                                            s        otherwise })
s⋆ := Replay(s₀, ⟨e⟩◁)
```

### Audit Chain
```
Aud(i) = ⟨e_i, Gate(e_i), H(s_i)⟩
ch₀ := ⊥
ch_{i+1} := H(ch_i ∥ Aud(i))
```

### Theorems (paper claims these 5)
1. **Determinism:** Unique ◁ order and unique s⋆ for any DAG G and initial state s₀
2. **Convergence:** Same anchors B + same event set → byte-identical s⋆₁ = s⋆₂
3. **Policy-Safety (deny-wins):** Every effect in s⋆ originates from a DATA event where Gate(e) held; deny → no effect
4. **Audit tamper-evidence:** Modification of first N audit records is detectable against pinned ch_N
5. **Leaver security:** Revoked subjects cannot decrypt post-rotation ciphertexts (IND-CPA)

---

## 5. Experimental Results Reference (for updating tables)

### E1 — Convergence
- 10,000-op concurrent workload, 100 valid orderings
- All 100 → digest `cbab89ee...b7f493b2`
- Mean replay: 615 ms (σ = 18 ms)

### E3 — Deny-wins revocation
- 1,004-op log (1000 Data + IssuerKey + Credential + Grant + Revoke)
- Revoke after write 500
- First 500 applied, remaining 500 skipped
- Digest: `8da8b49e...46633fbf`

### E4 — Multi-authority conflict
- 3 issuers (I1, I2, I3), 128-op log, 10 replicas
- All converged: `f2fbb024...1103c2b2`

### E5 — Audit integrity
- 3 tamper modes (byte flip, deletion, swap) all detected

### E6 — Replay scaling (Table 6)
| Ops | Full (ms) | Incr. (ms) | Speedup |
|-----|-----------|------------|---------|
| 10K | 949 ± 395 | 98 ± 37 | 9.7× |
| 20K | 1294 ± 79 | 147 ± 21 | 8.8× |
| 50K | 3328 ± 233 | 404 ± 54 | 8.2× |
| 100K | 6071 ± 92 | 708 ± 86 | 8.6× |
| 250K | 13689 ± 1814 | 1644 ± 232 | 8.3× |
| 500K | 26616 ± 2091 | 3137 ± 310 | 8.5× |

- Linear scaling: ~0.052 ms/op, R² > 0.99, ~19K ops/s sustained (hb-chain)

### E7 — Throughput by workload (Table 7)
| Scenario | Throughput (ops/s) |
|----------|--------------------|
| hb-chain (linear) | 45,000 |
| concurrent (8 writers) | 7,000 |
| offline-revocation | 28,000 |

### E11 — Partition-heal
- 50 pre-revoke writes applied (both partitions)
- 10 post-revoke writes from partition B skipped
- Merged digest: `69fae61e...1a2986c1`

### E12 — Multi-node sync (Table 5)
| Scenario | Ops | Sync (ms) | Bytes | Msgs | Replay (ms) |
|----------|-----|-----------|-------|------|-------------|
| No partition | 3000 | 13 | 2.5 MB | 6000 | 411 |
| Partition + heal | 3000 | 7 | 1.3 MB | 3201 | 368 |

### E13–E14 — Encryption
- ~6.5% replay overhead (76.8 vs 81.8 ms on 100 writes)
- 40 bytes/payload ciphertext expansion
- Key rotation: ~78 ms per KeyRotate

---

## 6. Conceptual Requirements (R1–R6) — Exact Definitions

Use these verbatim when referencing requirements:

- **R1 — Offline enforceability:** Authorization decisions must be enforceable without contacting a central PDP or ledger; disconnected nodes operate using locally verifiable evidence.
- **R2 — Deterministic post-partition convergence:** Given the same set of events, all parties must compute the same final authorization state regardless of message arrival order.
- **R3 — Revocation safety under partition:** Revocations must deterministically invalidate effects in the replicated state after reconciliation, even if the revocation arrives after the operations it should have blocked.
- **R4 — Tamper-evident accountability:** The history of grants, revokes, and authorization decisions must form an append-only, verifiable trace.
- **R5 — Decentralized multi-authority issuance:** Independent issuers must grant and revoke permissions without coordination; verifiers check authenticity offline using locally available evidence.
- **R6 — Confidentiality with post-revocation protection:** Unauthorized parties should not read protected content; after revocation-triggered key rotation, revoked principals cannot decrypt data created after their access ended.

---

## 7. Reviewer Comments — Exact Requirements

This section lists every actionable reviewer demand with the **minimum** change needed. Cross-reference the revision plan for execution details.

### MAJOR (must address for resubmission)

#### M1. Experimental evaluation is single-machine with no baselines
**Reviewer says:** "TPDS regularly publishes papers with evaluations on clusters of 10–100+ nodes... Single-machine evaluation with synthetic workloads is insufficient."
**Minimum fix:**
- Add p50/p95/p99 latency percentiles to Table 6 and Table 7 (code change)
- Add at least one realistic workload (IoT fleet or collaborative editing)
- Add at least one baseline comparison (OPA or Cedar standalone for policy eval latency)
- Scaffold multi-machine deployment infrastructure (Docker Compose + tc netem)
- Actual multi-machine results are ideal but scaffolding + acknowledging in Limitations is acceptable for major revision

#### M2. Missing capability-based systems in gap analysis
**Reviewer says:** "The most significant omission is the capability-based authorization tradition."
**Minimum fix:**
- Add 5th column to Table 1 (capability-based: UCAN/Macaroons/WAVE)
- Add 5th column to Table 2 (capability-based offline checks)
- Add 150–200 word paragraph in Related Work on capability-based systems
- Key point: these systems solve offline *verification* of delegated authority but not *conflict resolution* for concurrent authorization state modifications

#### M3. Sharpen differentiation from Jacob & Hartenstein (2024)
**Reviewer says:** "The manuscript must clearly delineate whether Jacob and Hartenstein only formalize the problem or also propose a deny-wins replay mechanism."
**Minimum fix:** Add 3–5 sentences after cite [8] explaining what J&H actually propose and where EQUACK differs.
**WARNING:** You (Claude Code) may not have access to the J&H paper. If you cannot find it in the repo or on the web, **flag this for the human** and leave a `% TODO: human — add J&H differentiation after verifying their actual contributions` comment.

#### M4. Formally characterize the pre-convergence safety window
**Reviewer says:** "Formally characterize the pre-convergence safety window — the period during which a revoked credential may still grant access."
**Minimum fix:** Add a definition of W(r) ≤ partition_duration + propagation_delay to Section 3.6 or a new subsection. Explicitly state EQUACK provides retroactive correction, not real-time revocation. Compare to Zanzibar's Zookie approach.

#### M5. Qualify Cedar property transfer under eventual consistency
**Reviewer says:** "Cedar's formal verification assumes a single, consistent evaluation context... EQUACK's eventually consistent setting violates this assumption."
**Minimum fix:** Add a paragraph in Section 3.3 stating:
- Preserved: decidability and totality of individual policy evaluation per node
- Lost during partitions: global consistency of authorization decisions
- Restored after convergence: deny-wins replay re-evaluates under converged state
- Not covered: Cedar's verification does not extend to the replay mechanism itself

### MINOR (should address)

#### m1. Discuss deny-overrides as only combining algorithm
**Fix:** 2–3 sentences in Section 3.3 acknowledging the limitation and discussing extensibility.

#### m2. Explain VC status propagation without StatusList URLs
**Fix:** Clarify in Section 3.2 that status-list updates propagate as in-band TRUST events in the DAG, sidestepping HTTP-based StatusList endpoints.

#### m3. Discuss entity hierarchy staleness
**Fix:** 2–3 sentences acknowledging that entity attributes may be stale during partitions; corrected on merge via deterministic replay.

#### m4. Add Zanzibar/OPA comparison paragraph
**Fix:** Paragraph distinguishing Zanzibar-family (always-online, Spanner-backed) and policy engines (offline evaluation but not offline modification with convergence).

#### m5. Cite Matrix State Resolution v2 and compare
**Fix:** Paragraph comparing EQUACK's linearization to Matrix's state resolution algorithm. Differentiate: Matrix uses power-level auth with specific tie-breaking, not CRDT formalism or deny-wins.

#### m6. Cite Kleppmann local-first work
**Fix:** 1–2 sentences in Introduction citing Kleppmann et al. 2019 (local-first software) noting AC is an identified open problem.

#### m7. Prototype scope honesty
**Fix:** In Discussion, add a subsection on which prototype components are simplified (e.g., VC validation subset, key rotation simplifications).

---

## 8. BibTeX Entries to Add

These are best-effort entries. **Verify each against DBLP or the actual publication before using.** If any field is uncertain, it's marked with `% VERIFY`.

```bibtex
@inproceedings{kleppmann2019localfirst,
  author    = {Martin Kleppmann and Adam Wiggins and Peter van Hardenberg and Mark McGranaghan},
  title     = {Local-First Software: You Own Your Data, in spite of the Cloud},
  booktitle = {Proceedings of the 2019 ACM SIGPLAN International Symposium on New Ideas, New Paradigms, and Reflections on Programming and Software (Onward!)},
  year      = {2019},
  pages     = {154--178},
  publisher = {ACM},
  doi       = {10.1145/3359591.3359737},
}

@inproceedings{kleppmann2022bft,
  author    = {Martin Kleppmann},
  title     = {Making CRDTs Byzantine Fault Tolerant},
  booktitle = {Proceedings of the 9th Workshop on Principles and Practice of Consistency for Distributed Data (PaPoC)},
  year      = {2022},
  publisher = {ACM},
  doi       = {10.1145/3517209.3524042},
}

@article{cutler2024cedar,
  author    = {Craig Cutler and Emina Torlak and others},  % VERIFY full author list
  title     = {Cedar: A New Language for Expressive, Fast, Analyzable, and Secure Authorization},
  journal   = {Proceedings of the ACM on Programming Languages},
  volume    = {8},
  number    = {OOPSLA},  % VERIFY
  year      = {2024},
  publisher = {ACM},
  % VERIFY doi
}

@inproceedings{birgisson2014macaroons,
  author    = {Arnar Birgisson and Joe Gibbs Politz and Ulfar Erlingsson and Ankur Taly and Michael Vrable and Mark Lentczner},
  title     = {Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud},
  booktitle = {Proceedings of the 2014 Network and Distributed System Security Symposium (NDSS)},
  year      = {2014},
  publisher = {Internet Society},
  % VERIFY doi
}

@inproceedings{andersen2019wave,
  author    = {Michael P. Andersen and Sam Kumar and Moustafa AbdelBaky and Gabe Fierro and John Kolb and Hyung-Sin Kim and David E. Culler and Raluca Ada Popa},
  title     = {{WAVE}: A Decentralized Authorization Framework with Transitive Delegation},
  booktitle = {Proceedings of the 28th USENIX Security Symposium},
  year      = {2019},
  publisher = {USENIX Association},
  pages     = {1375--1392},
}

@inproceedings{zanzibar2019,
  author    = {Ruoming Pang and Ramon Caceres and Mike Burrows and Zhifeng Chen and Pratik Dave and Nathan Gerber and Alexander Giber and others},  % VERIFY full list
  title     = {Zanzibar: Google's Consistent, Global Authorization System},
  booktitle = {Proceedings of the 2019 USENIX Annual Technical Conference (USENIX ATC)},
  year      = {2019},
  publisher = {USENIX Association},
  pages     = {33--46},
}

@misc{rfc9200,
  author       = {Ludwig Seitz and G\"{o}ran Selander and Erik Wahlstroem and Samuel Erdtman and Hannes Tschofenig},
  title        = {Authentication and Authorization for Constrained Environments Using the OAuth 2.0 Framework ({ACE-OAuth})},
  howpublished = {RFC 9200},
  year         = {2022},
  publisher    = {IETF},
  doi          = {10.17487/RFC9200},
}

% --- Should-add entries (verify all) ---

@misc{ucan2022,
  author       = {Brooklyn Zelenka and Philipp Kr\"{u}ger and others},  % VERIFY
  title        = {{UCAN} Specification v0.10.0},
  year         = {2022},
  howpublished = {\url{https://github.com/ucan-wg/spec}},
  note         = {Accessed: 2025},  % VERIFY date
}

@misc{biscuit2023,
  author       = {Geoffroy Couprie and others},  % VERIFY
  title        = {Biscuit: Bearer Tokens with Offline Attenuation and Decentralized Verification},
  year         = {2023},
  howpublished = {\url{https://www.biscuitsec.org/}},
  note         = {Accessed: 2025},  % VERIFY
}

@misc{willow2024,
  title        = {Willow Protocol Specification},
  author       = {Aljoscha Meyer and Sam Gwilym},  % VERIFY
  year         = {2024},
  howpublished = {\url{https://willowprotocol.org/}},
  note         = {Includes Meadowcap capability system. Accessed: 2025},  % VERIFY
}

@phdthesis{miller2006thesis,
  author  = {Mark S. Miller},
  title   = {Robust Composition: Towards a Unified Approach to Access Control and Concurrency Control},
  school  = {Johns Hopkins University},
  year    = {2006},
}

@misc{matrix_stateresv2,
  title        = {Matrix Specification: State Resolution v2},
  author       = {{The Matrix.org Foundation}},
  howpublished = {\url{https://spec.matrix.org/v1.8/rooms/v2/}},  % VERIFY version
  year         = {2023},
  note         = {Accessed: 2025},
}

@misc{openfga,
  title        = {{OpenFGA}: An Open-Source Authorization Solution},
  author       = {{Auth0/Okta}},
  howpublished = {\url{https://openfga.dev/}},
  year         = {2023},
  note         = {CNCF Sandbox project. Accessed: 2025},
}
```

---

## 9. New Content to Write — Draft Fragments

These are **drafts** for Claude Code to refine and insert. They are written to match the paper's existing style (formal, dense, IEEE transaction tone). Adapt as needed to fit surrounding context.

### 9.1 — Capability-based systems paragraph (for Section 2.5 or 2.6)

> Capability-based authorization constitutes a fifth paradigm not captured by Table~1. Systems such as Macaroons~\cite{birgisson2014macaroons}, UCAN~\cite{ucan2022}, Biscuit~\cite{biscuit2023}, ZCAP-LD, and WAVE~\cite{andersen2019wave} enable offline verification of delegated authority via cryptographic token chains: a holder can attenuate and present capabilities without contacting the issuer. The Willow Protocol~\cite{willow2024} couples peer-to-peer data synchronization with Meadowcap, a capability system supporting read/write authorization with delegation and attenuation. These designs satisfy R1 (offline verification) and R5 (multi-authority delegation) but do not address R2 (deterministic convergence of conflicting authorization state across partitions) or R3 (retroactive invalidation of effects authorized under stale evidence). Revocation in capability systems either relies on expiry, requiring short-lived tokens and frequent re-issuance, or on propagation of revocation lists, which faces the same freshness problem as VC status lists. EQUACK's contribution is orthogonal: it provides the conflict-resolution and replay mechanism that deterministically reconciles divergent authorization decisions after partition healing—a problem that capability chains alone do not address.

### 9.2 — Zanzibar/OPA comparison paragraph (for Section 2.6)

> Zanzibar~\cite{zanzibar2019} and its derivatives (SpiceDB, OpenFGA~\cite{openfga}) provide relationship-based authorization backed by strongly consistent stores (Spanner in Zanzibar's case). The Zookie mechanism ensures that a check never returns stale results by encoding a consistency token tied to the latest write—an approach that requires always-on connectivity and globally consistent infrastructure, violating R1 by construction. Policy engines such as OPA and Cedar~\cite{cutler2024cedar} support offline policy \emph{evaluation} via pre-loaded policy bundles, but not offline policy \emph{modification} with deterministic convergence: when two disconnected nodes independently modify authorization state (e.g., one grants while another revokes), these engines provide no reconciliation mechanism. EQUACK occupies the gap between these: it supports offline operation (like capability tokens) while providing deterministic post-partition convergence of authorization state (like centralized systems), without requiring global consensus.

### 9.3 — Safety window definition (for Section 3.6 or new subsection)

> \paragraph{Pre-convergence safety window.} Let $r$ be a revocation event created at physical time $t_r$ on some replica. Define the \emph{safety window} $W(r)$ as the interval $[t_r, t_{\text{heal}}]$ where $t_{\text{heal}}$ is the earliest time at which all correct replicas have received $r$ via anti-entropy. During $W(r)$, replicas that have not yet received $r$ may accept operations from the revoked principal under stale authorization evidence. Under the bounded partition assumption (Section~2.3, item~4), $W(r) \leq \Delta_{\text{partition}} + \Delta_{\text{propagation}}$ is finite.
>
> EQUACK does not prevent tentative authorization during $W(r)$; it guarantees that the materialized state $s^\star$ computed after reconciliation reflects $r$. Specifically, any DATA event $e$ from the revoked subject with $\text{pos}(e) \geq \text{pos}(r)$ in the deterministic order $\triangleleft$ is skipped by the deny-wins gate, regardless of which replica originally accepted $e$. This provides \emph{retroactive revocation safety}: the final digital state is consistent with the revocation, even though individual replicas may have temporarily acted on stale evidence. In contrast, Zanzibar's Zookie mechanism~\cite{zanzibar2019} provides real-time revocation at the cost of availability during partition (consistent with CAP theorem constraints). EQUACK trades real-time revocation for availability, repairing safety on merge.

### 9.4 — Cedar qualification paragraph (for Section 3.3)

> Cedar's formal verification~\cite{cutler2024cedar} establishes decidability, totality, and soundness of authorization evaluation under a single consistent context—all entity data and policies are available and coherent at decision time. In EQUACK's eventually consistent setting, this assumption holds locally (each replica evaluates deterministically given its local state) but not globally during partitions: two replicas may reach different permit/deny outcomes for the same request if one has received a forbid policy or revocation that the other has not. The deny-wins replay mechanism restores global consistency after convergence: once all replicas hold the same event set, replay re-evaluates every operation under the converged policy set, and the final materialized state $s^\star$ satisfies Cedar's deny-overrides semantics. Cedar's verified properties thus hold for $s^\star$ but not for the transient local decisions made during partitions. Formal verification of the replay mechanism itself—specifically, that deterministic linearization plus deny-wins gating preserves the intended authorization invariants—is future work and would require extending Cedar's Lean~4 proofs or independent mechanized checking.

### 9.5 — Kleppmann citation (for Introduction, after the problem statement)

> Kleppmann et al.~\cite{kleppmann2019localfirst} identify access control as a fundamental open problem for local-first software built on CRDTs, noting that ``revoking access in a decentralized setting remains an unsolved problem.'' EQUACK addresses this gap directly.

**Note:** The quote is approximate. Verify against the actual paper or rephrase without quoting.

### 9.6 — Table 1 new column data (capability-based)

```latex
% Add to Table 1 header: & Capability-based
% Row data:
% R1 Offline enforceability:    Yes
% R2 Deterministic convergence: No
% R3 Revocation safety:         Partial
% R4 Tamper-evident audit:      Partial
% R5 Multi-authority issuance:  Yes
% R6 Confidentiality:           No
```

### 9.7 — Table 2 new column data (capability-based offline checks)

```latex
% Ordering model:       No shared history; delegation chains are acyclic but unordered
% Revocation semantics: Expiry-based or propagation-dependent; no retroactive invalidation
% Trust distribution:   Delegation chains from root capabilities; offline-verifiable
% Audit model:          Token chain provides delegation provenance; no operation-level audit
% Offline availability: Yes for authorization checks; freshness-limited for revocation
```

---

## 10. Code Changes Reference

### 10.1 — Latency percentile reporting

Find the benchmark/experiment runner. It likely uses `std::time::Instant` or `criterion`. Add:

```rust
// After collecting per-op or per-batch durations into a Vec<Duration>:
fn report_percentiles(durations: &mut Vec<Duration>) {
    durations.sort();
    let n = durations.len();
    let p50 = durations[n * 50 / 100];
    let p95 = durations[n * 95 / 100];
    let p99 = durations[n * 99 / 100];
    println!("p50: {:?}, p95: {:?}, p99: {:?}", p50, p95, p99);
}
```

This is a sketch. Adapt to whatever timing infrastructure exists in the codebase.

### 10.2 — Realistic workload scaffold

Create in `cli/src/bin/` or as a subcommand. Key parameters:

```rust
struct IoTFleetWorkload {
    num_devices: usize,        // e.g., 50
    num_orgs: usize,           // e.g., 5
    num_engineers: usize,      // e.g., 20
    credential_duration_ms: u64,
    revocation_rate: f64,      // fraction of engineers revoked mid-run
    partition_at_op: usize,    // op number where partition starts
    heal_at_op: usize,         // op number where partition heals
    total_ops: usize,          // e.g., 10_000
}
```

The workload should generate a CBOR log that mixes:
- TRUST events (issuer keys for each org)
- CREDENTIAL events (per-engineer, time-bounded)
- GRANT events (engineer → device scope)
- DATA events (device parameter writes)
- REVOKE events (at configured rate, mid-run)
- A partition-heal cycle

### 10.3 — Property-based tests (proptest)

Add to `core/` dev-dependencies:
```toml
[dev-dependencies]
proptest = "1"
```

Key properties to test:

```rust
// 1. Convergence: any permutation of the same event set produces identical digest
// 2. Safety: no applied DATA event lacks a valid epoch at its replay position
// 3. Deny-wins: if a REVOKE exists for a credential, no DATA after the REVOKE's
//    replay position using that credential is applied
// 4. Audit integrity: audit chain head is deterministic for the same event set
```

### 10.4 — Multi-machine scaffold (Docker Compose)

```yaml
# deploy/docker-compose.yml
version: '3.8'
services:
  node1:
    build: ..
    environment:
      - NODE_ID=node1
      - PEERS=node2:9000,node3:9000
    ports: ["9001:9000"]
  node2:
    build: ..
    environment:
      - NODE_ID=node2
      - PEERS=node1:9000,node3:9000
    ports: ["9002:9000"]
  node3:
    build: ..
    environment:
      - NODE_ID=node3
      - PEERS=node1:9000,node2:9000
    ports: ["9003:9000"]
```

Partition injection script using `tc netem`:
```bash
#!/bin/bash
# deploy/inject-partition.sh
# Isolate node3 from node1 and node2
docker exec node3 tc qdisc add dev eth0 root netem loss 100%
sleep $PARTITION_DURATION
docker exec node3 tc qdisc del dev eth0 root
```

---

## 11. Things You Cannot Verify — Flag for Human

1. **Jacob & Hartenstein (2024) actual content** — you likely don't have this paper. Do NOT guess what they propose. Leave a TODO.
2. **Kleppmann quote accuracy** — the quote in Section 9.5 is approximate. Either verify or rephrase without quoting.
3. **Cedar OOPSLA 2024 author list and metadata** — marked `% VERIFY` in BibTeX. The full author list should be checked on DBLP.
4. **Willow Protocol / Meadowcap stability** — these specs may have changed. Check current URLs.
5. **Cross-platform CI results** — cannot be generated by Claude Code. The human must set up and run the CI pipeline.
6. **Multi-machine experiment results** — scaffolding can be generated; actual numbers require human execution.
7. **IEEE TPDS page limits** — verify current limits for regular papers (typically ~14 pages double-column). The added content must fit.
