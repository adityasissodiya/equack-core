# Figure 3 — Context & Fix Guide

## What This File Is

This document provides all the context needed to visually fix the TikZ diagram
for **Figure 3** of the ECAC paper. The figure is titled *"Concrete deterministic
replay slice from the compliance fixture."*  Hand this file plus the TikZ source
to Claude Chat so it can produce a cleaner version.

---

## 1. File Locations

| Artifact | Path (relative to paper directory) |
|---|---|
| **TikZ source (used in paper)** | `PaperC_Diagrams/tex/fig-deny-wins.tex` |
| **Old/unused generic version** | `fig-deny-wins.tex` (root — NOT included; ignore) |
| **Included from** | `ecac.tex` line 328: `\input{PaperC_Diagrams/tex/fig-deny-wins.tex}` |
| **Wrapped in** | `\begin{figure*}[htbp] ... \resizebox{\textwidth}{!}{...}` |
| **Compliance fixture code** | `experiments/partition_sim/src/main.rs` |
| **Evaluation log** | `experiments/Experiments.md` (Phase 3) |
| **Policy engine** | `crates/core/src/policy.rs` |
| **Replay engine** | `crates/core/src/replay.rs` |

---

## 2. What the Figure Must Communicate

The figure illustrates a **concrete, end-to-end deterministic replay** of the
partition-simulation compliance fixture. It must show:

1. **In-band trust bootstrap**: A single `IssuerKey` op registers an issuer
   public key into the replica-local TrustView (first-wins semantics).

2. **VC-backed epoch opening**: Two `Credential` ops carry compact JWTs; each
   is verified against the TrustView. A `Grant` op references the credential's
   BLAKE3 hash and opens an **authorization epoch** for that subject+role+scope.

3. **Concurrent data writes**: Both writers emit DATA ops during their open
   epochs. These are causally independent (different partitions) and interleaved
   by the deterministic topo sort (HLC + OpID tie-break).

4. **Merge**: The two partition logs are combined (set-union of ops). No
   explicit "merge op" exists in the DAG — this is a conceptual moment.

5. **Revocation**: A `Revoke` op closes any open epoch whose scope intersects
   the revoke scope, **at the revoke's topo-order position**. Only writer B's
   epoch is closed; writer A's stays open.

6. **Deny-wins gate outcomes**: Post-revoke DATA ops from writer B are
   **SKIP**ped (reason: `RevokedCred`). Writer A's post-revoke ops are
   **APPLY**ed because A's epoch remains open.

7. **Audit events**: Every DATA op emits either `AppliedOp` or
   `SkippedOp(reason)` into a hash-chained audit trail.

8. **Epoch bars**: A timeline at the bottom showing epoch A as an open arrow
   (still active) and epoch B as a line terminated by a revocation marker.

9. **Determinism tagline**: "Same merged event set -> same topo order -> same
   apply/skip decisions on every replica."

---

## 3. The Concrete Scenario (from the paper prose)

From `ecac.tex` line 322:

> Our compliance fixture contains an in-band `IssuerKey`,
> credential-and-grant pairs for two writers, 50 concurrent pre-revoke
> writes from each writer, a merge point, a `REVOKE` for one writer, and
> 10 post-revoke writes from each writer.

**The figure should depict:**

| Lane | Pre-revoke | Post-revoke | Gate outcome |
|---|---|---|---|
| Trust/policy | IssuerKey -> Cred A -> Grant A -> Cred B -> Grant B -> [Merge] -> Revoke(B) | | |
| Writer A data | 50 writes | 10 writes | APPLY x50, APPLY x10 |
| Writer B data | 50 writes | 10 writes | APPLY x50, **SKIP x10** |

---

## 4. Technical Discrepancies Found (Paper/Figure vs. Code)

### 4.1 Writer B pre-revoke count: 50 (paper/figure) vs. 20 (code)

**Paper prose** (line 322) says "50 concurrent pre-revoke writes from each
writer." **The figure** shows "B writes x50." **The actual code**
(`experiments/partition_sim/src/main.rs` lines 227-232) does only **20**
pre-revoke writes for Partition B:

```rust
for i in 0..20 {  // <-- 20, not 50
    let op = data_op(&subject_sk, "mv:o:x", &format!("B_pre{i}"), hlc_b, last_b.unwrap());
    ...
}
```

The Experiments.md log (line 100) confirms: "Partition B: same IssuerKey +
VC/Grant, **20 pre-revoke writes**, 10 post-revoke writes."

**Decision needed**: Either update the code to 50 to match the paper/figure,
or update the paper prose and figure to say 20. The paper and figure should
match whatever the code actually produces, since the evaluation results
(digests, audit counts) are derived from the code.

### 4.2 Same subject key for both "writers"

Both partitions use the **same** signing key:
```rust
let subject_sk = parse_sk_hex(&"cc".repeat(32))?;  // same key
```

The paper and figure describe "writer A" and "writer B" as if they are
**different principals**. In reality, they are the **same principal** operating
in two network partitions. This matters because:

- A `Revoke` targets a `subject_pk` — if both writers share the same key, one
  revoke closes **all** their epochs, not just "B's epoch."
- The paper claims "Revoke(B) closes only B's epoch" and A continues. For this
  to be true, A and B must have **different** subject keys so the revoke
  specifically targets B's key.

**If the intent is two distinct writers**: The code should use different subject
keys (e.g., `cc` for A and `dd` for B), and the revoke should target only B's
public key. Currently the fixture does not model this correctly.

**If the intent is one writer in two partitions**: The paper prose, figure, and
caption should say "the same writer operating across two partitions" and the
revoke closes that writer's epoch everywhere. The figure would then show all
post-revoke writes (from both partitions) as SKIP.

### 4.3 Audit counts don't fully add up

Experiments.md (line 106): "AppliedOp=50, SkippedOp=10."

If A has 60 DATA ops (50+10) and B has 30 DATA ops (20+10), the total is 90,
but only 60 are accounted for (50+10). Possible explanations:
- The audit export may only count a subset of ops.
- The same-subject-key issue (4.2) may cause B's credential to fail
  verification (duplicate `cred_id` or same subject already granted), making
  B's ops never enter an epoch at all and not counted as policy-gated skips.
- Or the counts in Experiments.md may be stale/from a different run.

This needs investigation if you want the numbers to be rigorous.

### 4.4 Scope label: "hv" (figure) vs. "confidential" (code)

The figure labels grants as `Grant A: editor, hv`. The code uses
`scope=["confidential"]`. The resource key `"mv:o:x"` maps to tags
`{"hv", "confidential"}` via `tags_for("o", "x")` in policy.rs, so the
intersection check passes either way. But the figure should use the same scope
label as the code for accuracy. **Use "confidential"** or at minimum note both.

### 4.5 Grant payload no longer carries role/scope

The figure's old generic version (`fig-deny-wins.tex` at root) shows
`Grant(U, VC_hash)`. The actual `Payload::Grant` in the code is:
```rust
Payload::Grant { subject_pk, cred_hash }
```
Role and scope come from the **verified VC**, not the Grant itself. The
PaperC figure correctly shows Grant referencing "editor, hv" but this is
actually the VC's claims, not the Grant's fields. The explanation box in the
figure correctly says "A Grant opens an epoch only if its cred_hash points to
a verified VC" — this is accurate.

---

## 5. Current TikZ Structure (What You're Fixing)

The file is `PaperC_Diagrams/tex/fig-deny-wins.tex` (151 lines). Structure:

### 5.1 Colors defined
- `figtrust` (brown), `figgrant` (green), `figrevoke` (red),
  `figwritera` (blue), `figwriterb` (purple), `figmerge` (gray),
  `figaudit` (orange), `figapply` (green), `figskip` (dark red),
  `fignote` (cream)

### 5.2 Layout zones
- **Top band** (y: 2.1–8.2): "Concrete Replay Slice" — three swim lanes:
  - Trust/policy ops (y=6.95): IssuerKey, Cred A, Grant A, Cred B, Grant B,
    Merge, Revoke B
  - Writer A data (y=5.10): A writes x50, A writes x10
  - Writer B data (y=3.45): B writes x50, B writes x10
  - Outcome badges below each write block (APPLY/SKIP)

- **Bottom band** (y: -2.6–1.5): "Authorization State Derived from the Same
  Replay Order" — three explanation boxes:
  - TrustView + VC verification (left)
  - Epoch builder (center)
  - Audit (right)

- **Epoch bars** (y: -1.35 and -2.00): horizontal lines showing epoch A
  (open arrow) and epoch B (closed with revoke marker)

- **Determinism annotation** (y: -2.35): tagline text

### 5.3 Known visual problems
1. **Cramped trust/policy lane**: 7 boxes (IssuerKey through Revoke) packed
   into one horizontal line at y=6.95. The boxes are only 2.05cm wide with
   small text.
2. **Long diagonal arrows**: `grantb.east` fans out to both `apre.west` and
   `bpre.west` using `to[out=0, in=180]` curves that cross lanes sloppily.
3. **Merge arrows converge messily**: `apre.north east` and `bpre.north east`
   both target `merge.south west` with different bend angles (25 and 35).
4. **Outcome badges disconnected**: The APPLY/SKIP badges sit at y=4.15 and
   y=2.50, disconnected from the flow. They look like floating annotations
   rather than integral parts of the diagram.
5. **Explanation boxes too wordy**: The three note boxes at the bottom contain
   dense paragraphs that compete with the diagram for attention.
6. **Epoch bars disconnected**: At the very bottom (y=-1.35 to -2.00), far
   from the main content. The visual connection between "Revoke writer B" and
   "epoch B closed" is weak.
7. **Inconsistent box widths**: opbox minimum width is 2.05cm but some boxes
   override to 2.2cm or 1.9cm, creating visual inconsistency.
8. **Total width ~23cm**: The diagram spans x=1.8 to x=23.4, which is very
   wide. When `\resizebox{\textwidth}{!}` scales it down, text becomes tiny.
9. **No visual grouping of concurrent ops**: The two write blocks (A and B)
   at x=15.8 are vertically stacked but there's no visual indication they are
   concurrent/interleaved in the topo order.

---

## 6. Design Goals for the Fixed Version

1. **Clarity over density**: Reduce the number of labeled boxes. Consider
   combining Credential+Grant into a single "Cred+Grant A" box since they
   always appear as a pair.
2. **Cleaner swim lanes**: Use subtle horizontal band colors or dashed
   separators instead of cramming everything into opbox nodes.
3. **Better flow arrows**: Avoid long diagonal arrows. Use right-angle
   connectors or a clear left-to-right time axis.
4. **Integrated outcomes**: Show APPLY/SKIP as colored borders or overlays on
   the write blocks themselves, not as separate floating badges.
5. **Compact explanation**: Move the explanation text into a legend or margin
   note, or reduce to one-line annotations.
6. **Connected epoch bars**: Place epoch bars closer to the write lanes, or
   use colored background bands behind the write blocks to show epoch scope.
7. **Readable at column width**: Keep total width reasonable so text remains
   legible after `\resizebox{\textwidth}{!}`.
8. **Time axis**: Consider adding a subtle horizontal time arrow to
   communicate the left-to-right replay order.

---

## 7. Relevant Data Structures (for label accuracy)

### Epoch (from policy.rs)
```rust
pub struct Epoch {
    pub scope: TagSet,           // BTreeSet<String>, e.g., {"confidential"}
    pub start_pos: usize,        // inclusive topo-order index
    pub end_pos: Option<usize>,  // exclusive; None = still open
    pub not_before: Option<Hlc>, // from VC nbf
    pub not_after: Option<Hlc>,  // from VC exp
}
```

### EpochIndex
```rust
pub struct EpochIndex {
    // Keyed by (subject_pk, role) -> Vec<Epoch>
    pub(crate) entries: BTreeMap<(PublicKeyBytes, String), Vec<Epoch>>,
}
```

### Gate check (deny-wins)
```
Gate(e) = exists epoch in EpochIndex[(e.author, role)]:
    e.pos in [epoch.start_pos, epoch.end_pos)
    AND e.hlc in [epoch.not_before, epoch.not_after)
    AND epoch.scope INTERSECTS resource_tags(e)
```

### Audit events
```rust
AuditEvent::AppliedOp { op_id, topo_idx, reason: Authorized }
AuditEvent::SkippedOp { op_id, topo_idx, reason: RevokedCred | ExpiredCred | OutOfScope | DenyWins }
```

### Payload variants shown in figure
```rust
Payload::IssuerKey { issuer_id, key_id, algo, pubkey, valid_from_ms, valid_until_ms, ... }
Payload::Credential { cred_id, cred_bytes (JWT), format: Jwt }
Payload::Grant { subject_pk, cred_hash }
Payload::Revoke { subject_pk, role, scope_tags, at: Hlc }
Payload::Data { key: "mv:o:x", value: ... }
```

---

## 8. Caption (current — keep or adjust to match fixes)

> Concrete deterministic replay slice from the compliance fixture. An in-band
> `IssuerKey` seeds TrustView, verified `Credential`+`Grant` pairs open epochs
> for writers A and B, and `Revoke(B)` closes only B's epoch. The deny-wins
> gate therefore applies both writers' pre-revoke data, skips B's post-revoke
> data, continues applying A's post-revoke data, and emits matching audit
> events.

---

## 9. Summary of Actions Needed

1. **Visual cleanup** of `PaperC_Diagrams/tex/fig-deny-wins.tex` — the main
   ask. Use the design goals in Section 6.
2. **Resolve discrepancy 4.1** (B's pre-revoke count: 50 vs 20). Decide which
   is correct and update paper prose + figure + code to match.
3. **Resolve discrepancy 4.2** (same subject key). If the paper means two
   distinct writers, the code needs different keys. If same writer in two
   partitions, the prose/figure narrative needs updating.
4. **Optional**: Fix scope label (4.4) from "hv" to "confidential" for
   consistency with code.
