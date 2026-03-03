Alright—picture a playground. Kids want to use the big slide (make writes). A kid can only slide if they’re holding a **permission ticket** that’s:

1. **Signed by a trusted grown-up**,
2. **Still valid in time** (not too early, not expired), and
3. **Not on the “taken away” list** if they misbehaved later.

That’s M4 in a nutshell. Now the “hard bits,” without skipping them:

# What changed

* **Grants aren’t enough anymore.**
  A “Grant” in the log used to say “let this kid slide.” Now it just says **“I’m tied to this specific ticket”** via a 32-byte **cred_hash**. If the ticket doesn’t check out, the grant does nothing.

* **The ticket is a JWT-VC (verifiable credential).**
  It’s a compact JWT with fields like: `iss` (who issued), `sub_pk` (the kid’s public key), `role`, `scope` (tags), `nbf`/`exp` (not-before/expiry), optional `status` (list + index).
  We **base64-decode** header/payload, demand `alg:"EdDSA"`, and **verify the Ed25519 signature** using the issuer’s public key we pin in `trust/issuers.toml`.

* **cred_hash = BLAKE3 over the exact compact JWT bytes.**
  No re-encoding tricks; we hash **the exact bytes** you’d copy-paste. The `Grant { cred_hash }` must match this, or it’s ignored.

* **Issuer trust is explicit and offline.**
  We only trust issuers listed in `trust/issuers.toml`. If the JWT’s `iss` isn’t there, the ticket is worthless.

* **Revocation is a tiny local bitstring.**
  Each status list is a file like `trust/status/list-0.bin`. If bit *i* is 1, the ticket at index *i* is revoked. We added a `vc-status-set` CLI helper to **flip any bit** so you can demo “credential gets revoked” without the internet.

* **Time rules use HLC physical time—no wall clock.**
  We compare `nbf`/`exp` against the **physical part of the op’s HLC**, so replay is deterministic. If an op happens before `nbf` or after `exp`, it’s denied—even if a grant exists.

* **From tickets to “epochs”.**
  When a `Grant` points to a **verified** ticket, we create an **auth epoch**: “this subject may do role X in scope Y from `nbf` to `exp` (minus any revokes).”
  Data ops are allowed **only if** they sit **inside** a live epoch that **intersects their tags**.

* **Deny-wins gate (from M3) still applies.**
  If there are *any* policy ops, a data op must pass the epoch check or it’s skipped.

# Why this is solid

* **Deterministic:** No network, no system clock. Trust & status are local files; hashing and signature checks are pure functions.
* **Tamper-evident:** If someone tweaks a credential byte, the **cred_hash** won’t match; the grant is dead on arrival.
* **Revocation actually works:** Flip one bit and replay; all post-revocation writes from that subject get denied.

# What you can do now

* `vc-verify <vc.jwt>` — See the parsed claims, computed cred hash, and whether it’s currently revoked.
* `vc-attach <vc.jwt> ...` — Emit `Credential` + `Grant{cred_hash}` ops to the log for testing.
* `vc-status-set <list-id> <index> <0|1>` — Flip the revocation bit and replay to watch access vanish/return.

# How we proved it

* **Positive tests:** Valid VC + matching grant lets the right writes through within `[nbf, exp)`.
* **Negative tests:**

  * **Expired** → no epoch, ops skipped.
  * **Not-yet-valid** → ops before `nbf` skipped.
  * **Unknown issuer** → skipped.
  * **Hash mismatch** → skipped.
* **Property tests:** Shuffle operation orderings; final state stays identical.

So, in kid terms: **you can only slide if you have a real, un-revoked, in-date ticket from a trusted adult—and we check the ink, the date, and the naughty list, every time, the same way for everyone.**


Great question—and you’re right to poke at it.

Short answer: **there’s no “central server” in ECAC.**
What M4 adds is *verifiable* proof that “Alice may do X,” but **who you accept proof from is entirely local**. Each replica carries its own **trust store** (`trust/issuers.toml`) and **status lists** (`trust/status/*.bin`). That’s not a central authority—it’s a *local policy knob*. Different deployments (or even different nodes) can choose different issuers, and replay remains deterministic for that node given its files.

Here’s how that squares the circle:

# Who is the “trusted adult”?

* It’s **whoever *you* configure** as an issuer in your trust store: a manufacturer, a team’s CA, a DAO multisig, your lab’s HSM—your call.
* Multiple issuers are fine. A grant counts if its VC is signed by **any** issuer you accept (union). You can also evolve policy to demand **k-of-n** issuers (federation) by requiring multiple grants/creds.

# Why this isn’t centralization

* **No online dependency.** Verification is offline: pinned keys + local revocation bitstrings. No calls out to a mothership.
* **Trust agility.** Each node can rotate, add, or remove issuers by changing files (and you can even distribute those changes through the log in a later milestone).
* **Many authorities, not one.** You can run with:

  * A single-tenant model (one issuer per tenant),
  * A **federation** (several issuers; union or k-of-n),
  * A **community / DAO** issuer (threshold signatures),
  * Or completely different trust stores per replica (split-brain by design if you want isolation).

# Why require any “adult” at all?

In a distributed system, you still need a **root of attestation** for *who a key belongs to* and *what role/scope it has*. M4 just says: “don’t trust a grant unless there’s a **cryptographic, auditable** statement tying the subject to that authority.”
The authority is *not* centralized infrastructure—it’s just a **public key you decided to trust**. The log plus verification rules keep everyone honest without a central service.

# Where this can go next (if you want even less “central”)

* **k-of-n issuers** per grant (policy requires multiple VCs).
* **Transparency log** for issuer keys (gossiped through ECAC itself).
* **On-chain or threshold-signed status lists**, still ingested offline.
* **Per-object trust**: objects declare acceptable issuers (scoped trust).

So: M4 adds *verifiability*, not centralization. The “trusted adult” is simply a **local, pluggable trust anchor**—you choose it, you can have many, and nothing phones home.
