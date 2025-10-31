# ECAC — Eventually Consistent Access Control

**Deterministic deny‑wins replay with CRDTs, verifiable credentials, and tamper‑evident audit — built for offline, multi‑stakeholder systems.**

***

## ✨ What is ECAC?

ECAC is a **blockchain‑free** model and prototype for **access control with revocation** in **offline‑first** environments. It solves a hard problem: *how to keep working while disconnected, and still end up in a policy‑correct state once devices sync back up.*

**Key idea:** we **replay** all signed operations (writes, grants, revokes) in a fixed, deterministic order. During replay, a **deny‑wins** rule removes any effects that weren’t authorized. This guarantees that all replicas eventually converge to the **same, policy‑correct** state.

***

## 🧩 Core Principles

*   **Everything is an event**: each action is a signed, hash‑linked event in a causal DAG (parents‑first).
*   **Work offline, reconcile later**: nodes apply local knowledge; when they sync, **deterministic replay** fixes the final state.
*   **Deny‑wins**: if there’s doubt about authorization at a point in time, the operation is **skipped** during replay.
*   **Audit by construction**: the audit trail is signed and hash‑linked; an independent verifier can re‑run replay and check it matches.
*   **Security over throughput**: correctness and verifiability come first.

***

## 🏗️ Repository Layout

    crates/
     ├── core/        # Ops, DAG, CRDTs, replay engine
     ├── policy/      # Authorization epochs & deny-wins filtering (Cedar semantics)
     ├── crypto/      # Signatures (Ed25519), hashing (BLAKE3), AEAD (XChaCha20-Poly1305)
     ├── store/       # RocksDB persistence + checkpoints
     ├── net/         # libp2p Gossipsub sync + Noise transport
     ├── vc/          # Verifiable Credential handling + status lists (TrustView)
     ├── audit/       # Tamper-evident audit trail and verifier
     ├── metrics/     # Bench harness + metrics exporter
     ├── cli/         # Command-line tool and scenarios
     └── ui/          # (optional) local-first viewer
    docs/
     ├── protocol.md
     ├── policy-model.md
     ├── evaluation-plan.md
     ├── audit.md
     └── paper/       # Overleaf-ready LaTeX skeleton (ecac.tex, ecac.bib)
    scripts/
     ├── reproduce.sh
     ├── verify_golden.sh
     └── plot.py

> **Implementation status:** finished up to **M5** (core CRDT + replay + policy epochs + VCs + persistent store). The rest is scaffolded.

***

## 🧠 Model in One Page

### Event format

```json
{
  "op_id": "blake3(canonical_bytes)",
  "parents": ["OpId", "..."],
  "hlc": "HybridLogicalClock",
  "author": "PublicKey",
  "payload": { "type": "...", "data": { /* CRDT update, Grant, Revoke, ... */ } },
  "sig": "Ed25519Signature"
}
```

### Deterministic replay (deny‑wins)

1.  **Order** events **topologically** (parents-first; tie-break by `(hlc, op_id)`).
2.  For each event:
    *   If the **author** is not authorized for `(action, resource)` **at that HLC** → **skip** (deny‑wins).
    *   Else, apply its **CRDT effect** (e.g., OR‑Set, MV‑Register).
3.  All replicas that see the same event set reach **identical state**.

### Authorization epochs

*   Grants and revocations build **time intervals** of validity for each `(principal, action, resource)`.
*   Epochs are computed from **VCs** (Verifiable Credentials), **issuer keys**, and **status lists** (revocations), all carried **in‑band** as signed events.

***

## 🔒 Cryptography & Trust

*   **Signatures:** Ed25519 (`ed25519-dalek`)
*   **Hashing:** BLAKE3
*   **Confidential fields:** XChaCha20‑Poly1305 (per‑tag keys)
*   **Credentials:** W3C **VCs** (JWT‑VC style)
*   **TrustView:** issuer keys + status lists shared **in‑band** through events
*   **Audit:** every decision (applied/skipped/sync/checkpoint) is **signed, hash‑linked**, and independently verifiable

***

## 📜 Policy Semantics (Cedar)

*   Policies use **AWS Cedar** deny‑overrides semantics.
*   During replay, ECAC evaluates Cedar policies **at the event’s HLC** with the current TrustView and epoch index.
*   **Revocations beat grants** when concurrent → **deny‑wins** makes policy safer by default.

***

## 📦 Storage & Recovery

*   **RocksDB** with column families (ops, edges, keys, audit, checkpoints).
*   **Append‑only** writes with `sync=true` for crash consistency.
*   Deterministic **checkpoints** + **replay parity** → same bytes after re‑ingest.
*   Audit logs are **tamper‑evident** (hash‑linked + signature chain).

***

## 🌐 Replication (no blockchain)

*   **libp2p Gossipsub** for anti‑entropy; **Noise** for transport security.
*   **Parent‑first fetch** ensures causal completeness.
*   Nodes exchange only **signed / encrypted ops**, not raw state.

***

## 🧾 Audit & Verification

*   Audit stream records: `IngestedOp`, `AppliedOp`, `SkippedOp{reason}`, `SyncEvent`, `Checkpoint`.
*   The **audit verifier** replays the DAG and checks the audit matches the deterministic outcome (detects tampering, omissions, or divergent decisions).

***

## 🔑 Confidential Read Control

*   Confidential fields stored as:
    ```json
    { "tag": "...", "key_version": N, "nonce": "...", "aead_tag": "...", "ciphertext": "..." }
    ```
*   Only holders of `KeyGrant{tag, version}` can decrypt.
*   **KeyRotate** bumps the version → revoked users cannot read future data (**forward secrecy**).
*   Non‑authorized readers see consistent `<redacted>` placeholders.

***

## ✅ What ECAC Guarantees

1.  **Convergence**: same events → same final state across replicas.
2.  **Policy Safety**: unauthorized effects are removed by replay.
3.  **Determinism**: given the same DAG, replay is a pure function.
4.  **Audit Integrity**: audit stream equals the replay’s semantic trace.
5.  **Forward Secrecy**: after key rotation, old readers can’t decrypt new data.

***

## ⚠️ Assumptions, Non‑Claims, and Pitfalls

**Assumptions**

*   Crypto primitives (Ed25519, BLAKE3, XChaCha20‑Poly1305) are secure.
*   Eventual delivery; crash-consistent storage; HLC monotonicity per node.
*   Deterministic tie‑break `(hlc, op_id)` is faithfully implemented.

**Non‑claims**

*   Not chasing maximum throughput.
*   We do **not** prevent **pre‑sync** use of stale permissions while offline; we **do** ensure policy‑correct **final** state after sync.
*   Not anonymous authorization; identities are tied to VCs.

**Pitfalls to watch**

*   **Revocation latency** is bounded by delivery time of status lists (offline nodes may act on stale knowledge temporarily).
*   **Issuer key compromise** detection depends on revocation propagation.
*   **Schema evolution** (VCs, policy attributes) needs versioning and migration rules.

***

## 📊 Evaluation Plan (what exists + what’s coming)

*   **Property‑based tests**: random DAGs; check convergence + policy safety.
*   **Fuzzing**: replay ordering, DAG merge, epoch edges.
*   **Crash recovery**: partial writes → identical replay after restart.
*   **Audit parity**: verifier must match replay decisions (and flag tampering).
*   **Scenarios (S1–S6)**:
    *   S1: Offline partition + late revocation
    *   S2: Multi‑issuer disagreement → status list reconciliation
    *   S3: Key rotation under concurrent writes
    *   S4: Crash during checkpoint
    *   S5: Adversarial reordering/duplication
    *   S6: Scale‑out anti‑entropy sync

**Metrics**

*   Convergence rate; revocation enforcement latency; replay determinism (byte‑identical); audit detection rate; confidentiality coverage; costs (ms/op, bytes/op), availability during partitions.

***

## 🏭 Industrial Context: RemaNet & EU Data Spaces

*   **Principals**: OEMs, remanufacturers, logistics, auditors.
*   **Capabilities/Resources**: repair steps, test results, device histories.
*   **VCs**: capability credentials issued by OEMs/Notified Bodies; status lists shared as events.
*   **Policies**: Cedar rules define who can do what, at which step, with what evidence.
*   **Compliance**: export audit as evidence bundles; **deterministic re‑verification** supports dispute resolution.

***

## 🧱 Roadmap (Milestones)

| Milestone | Summary                                             |
| --------- | --------------------------------------------------- |
| **M1–M2** | CRDT core + signed op DAG + deterministic replay    |
| **M3**    | Authorization epochs + deny‑wins                    |
| **M4–M5** | Verifiable credentials + durable RocksDB store      |
| **M6**    | Gossip sync + causal completeness                   |
| **M7**    | Bench harness + metrics                             |
| **M8**    | Tamper‑evident audit log & verifier                 |
| **M9**    | Confidential read control + key rotation            |
| **M10**   | In‑band issuer trust & revocation lists             |
| **M11**   | Reproducible builds (CI, SBOM, golden artifacts)    |
| **M12**   | Paper docs + evaluation summary + artifact manifest |

> Current: **M5 complete**; subsequent items have scaffolding and placeholders.

***

## 🤝 Contributing

1.  Open an issue describing the bug/feature with a **minimal repro**.
2.  Add tests (property‑based when possible).
3.  Keep changes **deterministic** (no time‑dependent branching in core).
4.  Run the full verification suite before submitting a PR.

***

## 🔍 FAQ

**Q: Why not just use a blockchain?**  
A: We need **offline operation**, predictable latency, and low overhead in OT environments. ECAC gives **auditability and policy‑correct convergence** without the cost or coordination model of a ledger.

**Q: Can nodes “cheat” while offline?**  
A: They can act on stale credentials **locally**, but when syncing, **deny‑wins replay** removes any unauthorized effects. The audit will also show those decisions.

**Q: How do you handle clock skew?**  
A: We use **Hybrid Logical Clocks** and a deterministic tie-break `(hlc, op_id)`. Minor skew doesn’t break determinism.

**Q: What about data confidentiality?**  
A: Sensitive fields are **encrypted** with per‑tag keys. **KeyRotate** enforces **forward secrecy**; non‑holders always see `<redacted>`.

***

## 📦 Reproducibility

*   **Deterministic builds** (Rust, locked deps); **SBOM** planned.
*   **Golden outputs**: `scripts/verify_golden.sh` checks byte‑level replay parity.
*   **Audit verifier** replays store state and cross‑checks audit.

***

## 📚 References (informal pointers)

*   CRDTs for eventual consistency; deterministic, parent‑first replay.
*   W3C **Verifiable Credentials** (status lists, multi‑issuer).
*   Cedar policy **deny‑overrides** semantics.
*   Tamper‑evident logs + independent re‑verification (no blockchain required).

*(Formal citations live in `docs/paper/ecac.bib`.)*

***

## 📝 License

TBD (e.g., Apache‑2.0 or MIT). Recommend a permissive license to encourage adoption and external verification.

***
