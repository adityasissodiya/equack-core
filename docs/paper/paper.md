Good. You’re basically at the “freeze and package” stage. Let’s finish M12 in a way that you can actually implement in an afternoon, not some hand-wavy wishlist.

Below is:

1. A **concrete todo list** for M12 given your current repo state (commit `e36141fce92d`, working `scripts/reproduce.sh` / `scripts/golden.sh`).
2. **Drop-in drafts** for all the `docs/paper/*.md` files, tuned to what you’ve actually built. You can paste and then adjust details if something is slightly off.

---

## 0. Where you stand now (important context)

You already have:

* Deterministic pipeline: `scripts/reproduce.sh` builds with `--locked --release --features audit`, runs `hb-chain`, `concurrent`, `offline-revocation`, seeds an audited DB, exports `audit.jsonl`, verifies it, hashes outputs, and builds `ecac-artifacts-e36141fce92d.tar.gz`.
* `scripts/golden.sh` that compares tarball SHA-256; last run:

  * Tarball: `docs/eval/out/ecac-artifacts-e36141fce92d.tar.gz`
  * SHA-256: `c7490dd7b7309bedad0aa8cbf84d91b82c2ea5ced6ae5a5762f593ff06920cf6`

So M11’s core is *done* in practice.

What’s missing for M12 is:

* The **paper docs tree**.
* A **tagged release** with artifacts + SBOM/signature.
* A couple of minimal **repo/docs cross-refs** (README + LaTeX snippet).

Everything below targets those.

---

## 1. Create the paper docs tree

Create the directory and files:

```bash
mkdir -p docs/paper
touch docs/paper/{model,invariants,usecase_induction_motor,evaluation_summary,threat_model,reproducibility_manifest}.md
```

You will also eventually drop in:

* `docs/paper/architecture_diagram.svg`
* `docs/paper/deny_wins_timeline.png`

(I’ll assume you can export those from whatever diagramming / plotting tooling you’re using.)

### 1.1 `docs/paper/model.md`

Use this as a first draft; tweak identifiers to match your exact type names if needed:

```markdown
# Model

This section describes the abstract state machine implemented by `ecac-core`. The goal is to separate *what* the system guarantees from *how* the Rust implementation and CLI behave.

We model the system as a deterministic function from a finite **event set** `E` to a **state** `S`:

\[
S = \mathsf{apply}\bigl(\mathsf{sorted}(E \setminus \mathsf{unauthorized}(E))\bigr)
\]

where:

- `E` is a set of signed, hash-linked events (ops, policy changes, trust updates, key events).
- `sorted(E)` is any total order consistent with the happens-before partial order derived from event edges.
- `unauthorized(E)` is the set of events that fail policy checks under deny-wins replay (defined below).
- `apply` is a pure function that folds events into an abstract store (CRDT state, policy state, trust view, and key registry).

## Event types

All events share a common header:

- `id`: unique hash identifier `H(header, body)` using BLAKE3.
- `parents`: a non-empty list of parent IDs forming a causal DAG.
- `issuer`: public key of the party issuing the event (Ed25519).
- `ts`: a logical timestamp (HLC) used only for tie-breaking and diagnostics.
- `sig`: Ed25519 signature over the header and body.

We distinguish four logical classes of events:

1. **Operation events (`Op`)**

   These represent application-level writes:

   - target object key,
   - CRDT payload (e.g., MVReg or OR-Set update),
   - tags determining which read/write policy applies,
   - optional encrypted payload protected via XChaCha20-Poly1305 under a per-tag data-encryption key.

2. **Policy events**

   These represent changes to authorization state, expressed as credential-guarded grants and revocations:

   - grant events associate a principal, tag, and capability (read/write/admin) with a validity interval and credential reference;
   - revoke events invalidate a specific grant or a credential.

3. **Trust events**

   These model issuer public keys and status lists for verifiable credentials:

   - issuer key events introduce or rotate an `IssuerId → PublicKey` binding;
   - status list events introduce or update revocation bitmaps for credential batches.

4. **Key events**

   These represent encryption key creation and rotation for confidential tags:

   - key-create introduces a new data-encryption key for a tag and epoch;
   - key-share binds that key to specific recipients’ public keys.

Audit records are derived from calls into the store (`op-append-audited`) and form a separate tamper-evident log; they do not participate in the DAG or the state transition function.

## Causal DAG and merge rule

Events are arranged in a directed acyclic graph:

- vertices are event IDs;
- edges point from each event to its parents;
- the genesis state is an empty DAG and empty store.

Given a finite set of events `E`, we choose any total order `≺` that extends the transitive closure of the parent relation. In practice, the implementation uses a topological sort with `(ts, id)` as a stable tiebreaker.

The **merge rule** is:

1. Compute a causal order `e₁, …, eₙ` of `E`.
2. Replay events in that order, maintaining:

   - a CRDT state `S_crdt`,
   - a policy state `S_policy`,
   - a trust view `S_trust`,
   - a key registry `S_keys`.

3. For each event `eᵢ`:

   - If `eᵢ` is a trust, policy, or key event, update the corresponding subsystem.
   - If `eᵢ` is an operation event:

     - Check whether `eᵢ` is **authorized** under the current policy state and trust view, using the issuer’s credentials and any attached VCs.
     - If authorized, apply the CRDT update to `S_crdt`.
     - If unauthorized, record `eᵢ` as **skipped**; it has no effect on `S_crdt`.

Because the order is causal and the replay function is pure, any two replicas that see the same event set `E` and perform the same replay logic must converge to the same `(S_crdt, S_policy, S_trust, S_keys)` up to isomorphism.

## Deny-wins semantics

Deny-wins replay is encoded in the `unauthorized(E)` set above. Intuitively:

- Policy and trust events are always applied in causal order.
- Each operation event is evaluated against **the policy and trust state in force at its replay point**, not at the time it was originally appended.
- If a previously valid credential or grant is revoked by a later event in the DAG, any operations depending on that credential become unauthorized during replay and are skipped.

Formally, `unauthorized(E)` is the set of operation events `e` such that there exists **no** valid authorization chain for `e` when replaying `E` in causal order under the deny-wins rules (see `invariants.md` for the policy-safety invariant and proof sketch).

This gives us **eventual policy correctness**: once revocations are propagated, all replicas that have integrated the revocation event will exclude its dependent operations from their final state.
```

---

### 1.2 `docs/paper/invariants.md`

```markdown
# Invariants

We state two key invariants and sketch why the implementation satisfies them. Throughout, let `E` be a finite set of events and `Interp(E)` be the deterministic replay function defined in `model.md`, returning an abstract state:

\[
\mathsf{Interp}(E) = (S_{\text{crdt}}, S_{\text{policy}}, S_{\text{trust}}, S_{\text{keys}})
\]

## Invariant 1 — Convergence

> **Convergence.** For any two replicas `R₁` and `R₂` that have processed the same event set `E`, their observable application state is identical:
>
> \[
> \mathsf{Interp}_{R_1}(E).S_{\text{crdt}} = \mathsf{Interp}_{R_2}(E).S_{\text{crdt}}.
> \]

**Sketch.**

1. The network layer (libp2p) and RocksDB log store events as opaque, signed blobs referenced by hash. They do not mutate event contents.
2. The replay logic used by the CLI and library operates exclusively on the event DAG and is:

   - deterministic (pure functions),
   - based on CRDT operations (MVReg, OR-Set) that are known to be confluent under causal delivery,
   - independent of wall-clock time and local environment.

3. Any two replicas with the same `E` will construct a DAG with the same edges (parents are explicit) and thus the same set of valid topological orders.
4. For CRDT events, the update functions are designed to be **commutative** and **idempotent** over the event set, so any causal order yields the same `S_crdt`.
5. Policy, trust, and key events influence only authorization and decryption; they do not introduce nondeterminism in CRDT application.

Therefore `Interp(E)` is a function of `E` alone, and convergence follows.

In practice, we cross-check this with:

- property tests that randomly generate DAGs and compare multiple replay orders, and
- the M7 benchmark harness, which runs scenarios across multiple peers and asserts state equality at the end of each run.

## Invariant 2 — Policy Safety (deny-wins)

> **Policy Safety.** For any event set `E`, no unauthorized operation influences the final application state:
>
> \[
> \forall e \in E.\ \text{if } e \text{ is an operation and } e \in \mathsf{unauthorized}(E) \text{ then } \mathsf{Interp}(E).S_{\text{crdt}} = \mathsf{Interp}(E \setminus \{e\}).S_{\text{crdt}}.
> \]

Equivalently: every effect observable in `S_crdt` is explainable by a subset of operations that were authorized at replay time under the deny-wins rules.

**Sketch.**

1. Authorization is implemented as a pure predicate:

   \[
   \mathsf{auth}(e, S_{\text{policy}}, S_{\text{trust}}) \in \{\text{allow}, \text{deny}\}
   \]

   computed during replay from:

   - the issuer public key in the event,
   - attached credentials,
   - the current grant/revoke state,
   - trust anchors and status lists.

2. For each operation event `eᵢ` in causal order, we do:

   - compute `auth(eᵢ, ...)`;
   - if `deny`, we do not modify `S_crdt`;
   - if `allow`, we apply the corresponding CRDT operation.

3. Revocations are just policy or trust events that change the outcome of `auth` for subsequent replays. Once a revocation event `r` is present in `E`, any operation that depended on the revoked credential will evaluate to `deny` and be skipped.

By construction, unauthorized events never reach the CRDT update layer, so they cannot affect `S_crdt`. The implementation exposes this directly in the audit trail:

- each replay step is annotated as **APPLIED** or **SKIPPED**, with the policy reason; and
- the audit verification command (`audit-verify-chain`) re-checks these decisions offline against the same replay rules.

This ties the invariant back to M9’s audit cross-checks: if audit verification passes for a given `E`, then the sequence of applied/skipped decisions is consistent with the deny-wins policy semantics, and thus policy safety holds for that event set.
```

---

### 1.3 `docs/paper/usecase_induction_motor.md`

You will need to align actor names and steps with your actual case study; this is a structured template:

````markdown
# Induction Motor Refurbishment Use Case

This section walks through an end-to-end scenario inspired by ReMaNet-style industrial remanufacturing. The goal is to show how deny-wins replay and audit interact in a realistic workflow spanning multiple organizations and offline work.

## Actors and roles

- **OEM** — original equipment manufacturer; defines base tags and initial policy.
- **Operator** — plant that owns and operates the induction motor.
- **Remanufacturer** — third-party workshop performing refurbishments and upgrades.
- **Inspector** — independent body issuing condition reports and safety approvals.

Each actor controls its own Ed25519 keypair and issues/holds credentials encoded as verifiable credentials (VCs) tied into the TrustView.

## Initial state

1. OEM issues a digital product passport for the motor, tagged `motor/<serial>` and `config`.
2. OEM grants the Operator a write capability on `motor/<serial>` for maintenance logs.
3. OEM grants the Remanufacturer a time-limited write capability on `motor/<serial>` and `config` for the duration of a refurbish order.
4. Credentials are published as VC events; corresponding policy grant events reference them.

At this point, all parties are online and converge on the same state.

## Offline refurbish + concurrent revocation

The interesting behavior arises when the Remanufacturer goes offline:

1. The Remanufacturer clones the event DAG and policy state and then goes offline (no network).
2. While offline, they:

   - update the motor’s configuration to reflect bearing and insulation replacements;
   - append a series of maintenance and test ops under their valid write grant.

3. Meanwhile, the OEM receives a security incident report and **revokes** the Remanufacturer’s credential:

   - OEM appends a revocation event to the TrustView and a corresponding policy revoke event that invalidates the grant to the Remanufacturer.
   - The Operator and Inspector quickly converge on this revocation, but the Remanufacturer is still offline.

## Reconnection and deny-wins replay

When the Remanufacturer comes back online:

1. Their node gossips all locally pending events (offline maintenance + config updates) to the Operator/OEM.
2. The OEM’s node merges the Remanufacturer’s offline branch with the global DAG, which now includes the revocation.

On replay, the deny-wins semantics take effect:

- Operations that relied on the now-revoked credential are evaluated under the **current** TrustView and policy state and are marked **SKIPPED**.
- Earlier operations that were authorized before the revocation and are still consistent with the updated policy remain **APPLIED**.

The result is that all replicas converge to a state where:

- the revoked Remanufacturer can no longer change motor configuration;
- any offline edits that conflict with the revocation are rolled back deterministically;
- the audit trail records which offline ops were skipped and why.

## CLI transcript (excerpt)

The offline-revocation scenario is reproducible via:

```bash
target/release/ecac-cli bench \
  --scenario offline-revocation \
  --seed 42 \
  --out-dir docs/eval/out/offline-revoke-42
````

A shortened excerpt from the audit verification output illustrates deny-wins in action:

```text
[APPLIED] op=... issuer=OEM         reason=policy(allow)
[APPLIED] op=... issuer=Operator    reason=policy(allow)
[APPLIED] op=... issuer=Reman       reason=policy(allow; credential VC#123 valid)
[APPLIED] policy-revoke=... issuer=OEM reason=revoke(VC#123)
[SKIPPED] op=... issuer=Reman       reason=policy(deny; VC#123 revoked by <revoke-id>)
```

(Replace the placeholders with the actual IDs and messages from your `audit.jsonl`.)

This transcript demonstrates that the system is able to:

1. accept offline work while a credential is valid,
2. later incorporate a revocation issued while the node was offline, and
3. deterministically roll back affected operations so that all replicas enforce the same deny-wins policy.

````

---

### 1.4 `docs/paper/evaluation_summary.md`

You should fill in the actual numbers from your CSVs; the table below shows the shape:

```markdown
# Evaluation Summary

We evaluate three synthetic scenarios from the M7 benchmarking harness, each with 200 operations and a fixed RNG seed. All scenarios are reproducible via `scripts/reproduce.sh`, which populates `docs/eval/out/*.csv` and `*.jsonl`.

## Summary table

| Scenario         | Ops | Revokes | Skipped | Replay ms | Convergence ms |
| ---------------- | --- | ------- | ------- | --------- | -------------- |
| hb-chain         | 200 | 0       | 0       | XX        | 0              |
| concurrent       | 200 | 0       | 0       | YY        | 0              |
| offline-revocation | 200 | 3     | 6       | ZZ        | WW             |

- **Ops** — number of operation events generated by the harness.
- **Revokes** — number of explicit revocation events (policy or trust).
- **Skipped** — number of operations marked unauthorized under deny-wins replay.
- **Replay ms** — median end-to-end replay time for a single node.
- **Convergence ms** — time until all peers converge in the networked variant (if enabled).

Fill `XX`, `YY`, `ZZ`, `WW` from the metrics computed in your plotting script.

## Figures

The following figures are generated from the CSV artifacts using `docs/eval/plot.py` (not shown here):

1. **Deny-Wins Replay Timeline** (`docs/paper/deny_wins_timeline.png`)  
   Shows when revocations occur and which operations are subsequently skipped in the offline-revocation scenario.

2. **Replay Cost vs. Ops**  
   Plots replay time as a function of the number of operations for the hb-chain and concurrent scenarios.

3. **Skipped Ops vs. Revocations**  
   Shows the relationship between the number of revocations and the number of skipped operations under deny-wins replay.

Because all plots are computed from committed CSVs under `docs/eval/out/`, reviewers can regenerate them with a single command:

```bash
scripts/reproduce.sh
python docs/eval/plot.py
````

````

---

### 1.5 `docs/paper/threat_model.md`

```markdown
# Threat Model

This section summarizes what `ecac-core` guarantees and what it does not. The goal is to make the security assumptions explicit for reviewers.

## Assets

- **Control state** — logical authorization and policy decisions for tags and objects.
- **Data state** — application payloads stored in CRDTs (optionally encrypted per tag).
- **Audit log** — tamper-evident record of applied and skipped operations.
- **Trust state** — issuer keys and credential status lists.

## Adversary capabilities

We consider an adversary that may:

- intercept, drop, delay, and reorder messages on the network;
- compromise or misconfigure individual peers (honest-but-curious or malicious);
- read persistent storage on a compromised peer;
- replay old messages and events.

We assume:

- standard hardness assumptions for Ed25519, XChaCha20-Poly1305, and BLAKE3;
- eventual message delivery between at least one honest peer in each trust domain;
- endpoints may be compromised, but key compromise is detectable (signatures) and recoverable by revocation and key rotation.

We **do not** assume a trusted network or centralized oracle.

## Guarantees

Under these assumptions, the system guarantees:

1. **Integrity of events**

   - All events are signed with Ed25519 and hash-linked, making tampering and reordering detectable.
   - Audit logs are keyed by event hashes and verified offline via `audit-verify-chain`.

2. **Authenticity of actions**

   - Every operation is bound to the issuer’s keypair.
   - Authorization decisions are traceable to a chain of grants and revocations grounded in verifiable credentials.

3. **Eventual policy correctness (deny-wins)**

   - Once revocation and policy updates are delivered, all honest replicas converge on the same state that excludes unauthorized operations.
   - Offline and concurrent edits that rely on revoked credentials are deterministically skipped on replay.

4. **Confidentiality for tagged data**

   - Application payloads for protected tags are encrypted under per-tag data-encryption keys.
   - Keys are rotated via in-band key events and shared only with authorized readers.

5. **Auditability**

   - Each applied or skipped operation is recorded with a machine-checkable reason.
   - External auditors can reconstruct the replay and check invariants without trusting any single node.

## Non-goals and limitations

The following are **explicitly out of scope**:

1. **Immediate revocation in offline mode**

   - A peer that is offline while a revocation is issued will continue to act on stale policy until it reconnects.
   - Deny-wins replay ensures eventual correction, not instantaneous enforcement.

2. **Endpoint security**

   - Compromise of an endpoint (e.g., malware on a peer) is out of scope.
   - An attacker who steals long-term keys can impersonate that peer until revocation and key rollover.

3. **Full byzantine fault tolerance**

   - The current design assumes that at least one honest peer validates signatures and audit chains.
   - It does not implement threshold signatures or BFT consensus; a coalition of malicious peers can eclipse an honest node.

4. **Strong confidentiality guarantees for historical data**

   - The system supports forward secrecy via key rotation, but does not implement retroactive re-encryption of old ciphertexts.
   - Data read or exfiltrated while a key was valid cannot be “taken back”.

5. **DoS and side-channel defenses**

   - Denial-of-service, traffic analysis, and side channels (timing, cache attacks) are out of scope.

These limitations reflect the target deployment: industrial multi-stakeholder remanufacturing with honest-but-curious participants and offline operation as a first-class requirement.
````

---

### 1.6 `docs/paper/reproducibility_manifest.md`

For your current working state (commit `e36141fce92d`, tarball SHA shown by `golden.sh`), you can use:

````markdown
# Reproducibility Manifest

This manifest describes exactly how to reproduce the artifacts used in the paper, including toolchain versions, commit identifiers, and artifact hashes.

## Implementation identity

- Repository: `https://github.com/adityasissodiya/ecac-core`
- Paper tag: `v1.0-paper` (to be created)
- Commit (short): `e36141fce92d`
- Default branch at tag: `main`

## Toolchain and environment

- Rust toolchain: `1.85.0` (as reported by `rustup` when running `cargo build`)
- Components: `cargo`, `rustc`, `clippy`, `rustfmt`
- Target OS: Linux (tested on Ubuntu 24.04)
- Database: RocksDB (via `librocksdb-sys`)

The repository pins:

- `Cargo.lock` for all Rust dependencies.
- `scripts/reproduce.sh` sets:

  - `LC_ALL=C`
  - `TZ=UTC`
  - `SOURCE_DATE_EPOCH=1` (or environment override)
  - `RUSTFLAGS="-C debuginfo=0 -C strip=symbols -C link-arg=-s"`

These settings ensure deterministic builds and stable hashes across runs on the same platform.

If you use Nix, you can additionally provide a `flake.nix` that fixes the system packages (compiler, RocksDB, OpenSSL). The pipeline itself does not rely on Nix.

## One-command reproduction

From a clean checkout of the `v1.0-paper` tag:

```bash
git clone https://github.com/adityasissodiya/ecac-core.git
cd ecac-core
scripts/reproduce.sh
````

This script:

1. Cleans previous state (`docs/eval/out`, `.ecac.db`, `.audit`).

2. Builds the workspace with `cargo build --workspace --release --locked --features audit`.

3. Runs three benchmark scenarios with a fixed seed:

   * `hb-chain` (seed 42),
   * `concurrent` (seed 42),
   * `offline-revocation` (seed 42),

   and normalizes their outputs to:

   * `docs/eval/out/hb-chain-42.{csv,json,jsonl}`
   * `docs/eval/out/concurrent-42.{csv,json,jsonl}`
   * `docs/eval/out/offline-revoke-42.{csv,json,jsonl}`

4. Seeds a fresh RocksDB store and audit log with a deterministic minimal op:

   * `docs/eval/out/m11-min.op.cbor`
   * `audit.jsonl` and `audit.verify.txt` in `docs/eval/out/`

5. Computes `SHA256SUMS` for all artifacts in `docs/eval/out/`.

6. Bundles everything into a deterministic tarball:

   * `docs/eval/out/ecac-artifacts-e36141fce92d.tar.gz`

## Golden artifacts and hashes

The paper references a **golden tarball** built from the same commit, published as part of the `v1.0-paper` release:

* Golden tarball name: `ecac-artifacts-e36141fce92d.tar.gz`
* SHA-256:

  ```text
  c7490dd7b7309bedad0aa8cbf84d91b82c2ea5ced6ae5a5762f593ff06920cf6
  ```

To check that your local run matches the golden tarball bit-for-bit:

```bash
scripts/reproduce.sh
scripts/golden.sh /path/to/ecac-artifacts-e36141fce92d.tar.gz
```

`golden.sh` reports both SHA-256 hashes and exits non-zero if they differ.

The file `docs/eval/out/SHA256SUMS` lists hashes for all individual artifacts (CSV, JSONL, JSON, CBOR, audit logs).

## SBOM and signatures

For the paper tag, we additionally generate:

* **SBOM** (CycloneDX):

  ```bash
  cargo cyclonedx --format json --output docs/eval/out/sbom.json
  ```

* **Signature** of the artifacts tarball:

  ```bash
  cosign sign-blob docs/eval/out/ecac-artifacts-e36141fce92d.tar.gz \
    > docs/eval/out/cosign.sig
  ```

The GitHub release `v1.0-paper` attaches:

* `ecac-artifacts-e36141fce92d.tar.gz`
* `SHA256SUMS`
* `sbom.json`
* `cosign.sig`
* the contents of `docs/paper/`

Reviewers can verify the tarball using:

```bash
cosign verify-blob \
  --signature docs/eval/out/cosign.sig \
  docs/eval/out/ecac-artifacts-e36141fce92d.tar.gz
```

## CI status

A dedicated GitHub Actions workflow (`.github/workflows/repro.yml`) runs on the `v1.0-paper` tag:

* `scripts/reproduce.sh`
* `cargo audit` / `cargo deny` (optional)
* SBOM generation
* `scripts/golden.sh` against the golden tarball

The README includes a badge pointing at this workflow and a link to the `v1.0-paper` release / DOI.

````

---

## 2. Tag and version freeze

Once you’re happy with the docs and pipeline:

1. Ensure working tree is clean and `scripts/reproduce.sh` passes.
2. Tag:

   ```bash
   git tag -a v1.0-paper -m "Paper artifact tag"
   git push origin v1.0-paper
````

3. On GitHub:

   * Create a release from `v1.0-paper`.
   * Attach:

     * `docs/eval/out/ecac-artifacts-e36141fce92d.tar.gz`
     * `docs/eval/out/SHA256SUMS`
     * `docs/eval/out/sbom.json` (once you generate it)
     * `docs/eval/out/cosign.sig`
     * a zip of `docs/paper/` if you want.

4. If you care about a DOI: mint it via Zenodo and link the DOI back to this release.

---

## 3. README and paper cross-references

### README additions

Add a short “Reproduce” section:

````markdown
## Reproducing the Paper Artifacts

To reproduce all evaluation artifacts from the paper (M7–M12):

```bash
git clone https://github.com/adityasissodiya/ecac-core.git
cd ecac-core
git checkout v1.0-paper
scripts/reproduce.sh
````

Artifacts are written under `docs/eval/out/` and bundled as
`docs/eval/out/ecac-artifacts-e36141fce92d.tar.gz`.

To verify against the published golden tarball:

```bash
scripts/golden.sh /path/to/ecac-artifacts-e36141fce92d.tar.gz
```

````

Also add:

- Supported OS list (e.g., “Tested on Ubuntu 24.04; other Linux distros may work but are not part of the artifact evaluation claim.”)
- Citation line and artifact DOI.

### LaTeX cross-refs

In your paper source, add something like:

```latex
\footnote{Artifact DOI and code: https://github.com/adityasissodiya/ecac-core/releases/tag/v1.0-paper}
````

And ensure:

* The “Deny-Wins Replay Timeline” figure points at `docs/paper/deny_wins_timeline.png`.
* The evaluation table matches `evaluation_summary.md`.
* The audit listing is taken from `audit.verify.txt` or `audit.jsonl` (with IDs redacted if needed).

---

## 4. Sanity checklist to truly “complete this”

Here’s the uncompromising list. You’re done when all are true:

* [ ] `docs/paper/*.md` exist and are in sync with what the implementation actually does.
* [ ] `scripts/reproduce.sh` and `scripts/golden.sh` run clean on your machine.
* [ ] `rust-toolchain.toml` pins Rust 1.85.0 (or whatever you finalize).
* [ ] `docs/eval/out/ecac-artifacts-<gitsha>.tar.gz` built from `scripts/reproduce.sh` matches the released golden tarball.
* [ ] `sbom.json` and `cosign.sig` are generated and attached to the `v1.0-paper` release.
* [ ] `.github/workflows/repro.yml` runs `scripts/reproduce.sh` on the tag and passes.
* [ ] README has: one-line install/run, supported OS, artifact DOI, citation line.

You’ve already done the hard part (design, implementation, and M11 pipeline). M12 is mostly disciplined paperwork and freezing the state. The drafts above give you something you can drop in and then surgically adjust where your implementation details differ.
