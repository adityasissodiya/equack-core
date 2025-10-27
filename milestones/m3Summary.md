
## The story so far

* In **M1**, we made a **chain of signed events** (ops) that fits together like LEGO: each piece points to its parents, and we can line them up in a **single, deterministic order** (parents first; ties by HLC, then hash).
* In **M2**, we took those events and **built the data**, using two smart rules (**CRDTs**):

  * **MV-Register**: “last-writer wins” unless two writes are **concurrent**—then both are kept.
  * **OR-Set**: adds and removes; a remove only kills **adds it has actually seen** (by causality).

So far, **anyone** could write. That’s not safe.

---

## What M3 adds: “who’s allowed to write?”

We add **policy events** into the *same* log:

* **Grant**: “this person can do X (role) on things tagged Y (scope).”
* **Revoke**: “take that power away.”

And we add a **gate** in the replay:

> For every data event, we **check permission first**. If not allowed, we **skip it**.

This is called **deny-wins**: if a deny (or absence of permission) is in force at the moment of an op, that op has **no effect**. No retroactive blessing later.

---

## “Epochs” = when you’re allowed

Think of **epochs** like a **green light** interval for a person’s role+scope.

How do we build them?

1. We take the **same total order** from M1.
2. We walk through it and maintain “open/close” intervals:

   * A **Grant** opens an interval for *(subject, role, scope)* starting at its position/time.
   * A **Revoke** closes any matching open intervals at its position/time.
3. Result: for each *(subject, role, scope)* we have **non-overlapping time windows**: `[start, end)`.

> These windows are **keyed by the total order**, not by the wall clock. That keeps all replicas in lock-step.

---

## The permission check (the gate)

When we replay a **data op**:

1. Identify its **action**:

   * `SetField` → MV-Register write
   * `SetAdd` → OR-Set add
   * `SetRem` → OR-Set remove
2. Compute the op’s **resource tags** from its key (we use a fixed `(obj, field) → tags` table).
3. Look up an **epoch** for *(author, role that permits this action, matching scope)* such that:

   * The op’s **position/time** lies **inside** the epoch.
   * The op’s **resource tags** **intersect** the grant’s **scope**.
4. If such an epoch exists → **apply** the data op.
   Otherwise → **skip** (deny-wins).

That’s it. Simple gate; deterministic.

---

## Why “deny-wins”?

Because we want **safety** under any delivery order:

* If a **Revoke** happens before a user’s write (by causal order or tie-break), the write is **blocked**.
* If a **Grant** arrives **after** a write, we **do not** retroactively approve the earlier write. It still gets skipped. (No time travel.)

---

## Concurrency rules (the tricky edge)

Two events can be concurrent (neither is an ancestor). We still need a decision that every replica agrees on:

* We already have a single replay order from M1 (parents → children; tie by HLC, then op hash).
* We **use that order** to break the tie:

  * If **Grant** is ordered **before** the data op → **allowed**.
  * If data op is ordered **before** the Grant → **skipped**.
* Same for **Revoke** vs data op: if **Revoke** is earlier → **skipped** (deny-wins).

No debate; everyone gets the same answer.

---

## How this interacts with CRDTs

M2’s CRDT logic still applies—**but only for ops that pass the gate**:

* **MV-Reg**: only permitted writes can overwrite earlier ones; concurrent permitted writes produce multiple winners.
* **OR-Set**: permitted removes only kill **observed** permitted adds; concurrent permitted add+remove resolves by the same total order.

If an op is **skipped**, the CRDT **never sees it**, so it can’t change the result.

---

## Two concrete scenarios you already ran

### 1) “offline_edit”

* Grant → user writes (**before** revoke) → **Revoke** → user writes (**after** revoke).
* Result: first write stays, second write is **skipped** (deny-wins).
* Deterministic JSON and digest match across runs.

### 2) “grant_after_edit”

* User writes (**before** they had any grant) → Grant → another write.
* Result: the early write is **skipped** (no retroactive approval). The later write is applied.

These match the prints you saw from `ecac-cli simulate`.

---

## What we guarantee in M3

* **Policy safety**: no op outside a valid epoch can change state.
* **Determinism with policy**: same events → same state, regardless of delivery order.
* **Epoch correctness**: grant–revoke–regrant makes exactly the windows you expect.
* **Scope semantics**: we used **intersects**—the op’s tags only need to overlap the grant’s scope.
* **Incremental parity**: replaying in chunks equals replaying all at once.

---

## What we **didn’t** do (yet)

* We **trust** grants in the log at face value. No external credentials yet.
* No network calls, no databases.
* No fancy attributes; just **roles** and **tag scopes**.

(That’s exactly what **M4** will fix: a Grant only counts if a **verifiable credential** backs it and is valid, trusted, and not revoked.)

---

## One-line mental model

> M3 is **M2 + a gate**. We build **when you’re allowed** (epochs) from Grants/Revoke in the **same order** as the data, and we **drop** any data op that isn’t inside a valid window. Everything else (CRDTs, determinism) stays the same.
