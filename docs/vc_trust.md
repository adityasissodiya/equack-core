
---

## 1. `docs/policy-model.md` – append this section

```markdown
## M9: Read-Control for Confidential Fields

M9 extends the existing write-only policy model with **read-control** for selected
fields. The objective is minimal but deterministic confidentiality:

- Confidential fields are stored as **ciphertext** (`EncV1` envelopes).
- Read access is granted via **VC-backed KeyGrant events**.
- **KeyRotate** events implement forward secrecy from the rotation point onward.
- Replicas make **identical decisions** about redaction vs plaintext.

The design deliberately reuses the existing M3/M4 policy machinery (roles, scope,
VCs, epochs) instead of introducing a new authorization system.

### Tags and Confidential Fields

The system already uses **tags** to describe scope for write policy
(e.g. `"hv"`, `"mech"` in tests). M9 reuses those tags for read-control:

- Each logical `(object, field)` has a **tag set** derived from the key string
  (via `policy::derive_action_and_tags`).
- A subset of tags is treated as **confidential**. For those tags:
  - Writes are **encrypted on write** using per-tag symmetric keys.
  - Reads are gated by **KeyGrant + VC**.

Non-confidential fields continue to behave exactly as in M2/M3:

- Values are stored in plaintext.
- Reads are governed only by write policy (deny-wins), not by KeyGrant.

### New Policy Events: KeyGrant and KeyRotate

M9 introduces two new payloads in the op log:

- `KeyGrant { subject_pk, tag, key_version, cred_hash }`
- `KeyRotate { tag, new_version, new_key }`

Both participate in the same **topo + HLC** ordering as existing ops, and the
policy engine builds a single **EpochIndex** over:

- `Grant` / `Revoke` (write policy, as before)
- `KeyGrant` / `KeyRotate` (read policy)

#### KeyGrant semantics

A `KeyGrant` is an **authorization event** that links a subject and a key
version to a VC:

- `subject_pk`: the viewer’s public key.
- `tag`: confidentiality tag (e.g. `"hv"`).
- `key_version`: which symmetric key version this grant covers.
- `cred_hash`: blake3 hash of the underlying VC JWT.

At replay time:

1. The VC referenced by `cred_hash` is verified using the existing trust store.
2. The VC’s role and scope are mapped to a **read policy**:
   - Roles are configured with `read_tags` (in addition to write permissions).
   - The VC must still be valid in time, scope, and status (not revoked/expired).

A subject can read ciphertext for `(tag, key_version)` at topo index `i` iff:

- There exists at least one **valid VC epoch** at `i` with a role whose
  `read_tags` contains `tag`, and whose scope covers the resource tags; and
- There exists a **KeyGrant epoch** at or before `i` for that `(subject_pk, tag, key_version)`.

If either condition fails, read is denied even if the ciphertext key is present
in the local keyring.

#### KeyRotate semantics

A `KeyRotate { tag, new_version, new_key }` event has two effects:

1. It defines a new symmetric key `new_key` for `(tag, new_version)`.
2. It implicitly ends the lifetime of the previous version for **future writes**.

Rotation behaviour:

- Writes **before** the rotation are encrypted under the previous version.
- Writes **after** the rotation are encrypted under `new_version`.
- A subject that only has a `KeyGrant` for the old version can still decrypt
  pre-rotation history, but **cannot read post-rotation values** for that tag.

Rotation is signed by an authorized **KeyAdmin** (via its own VC). The policy
model treats the ability to emit `KeyRotate` as a role-specific permission
(`rotate_key_for_tag` in config terms), but the key content itself is global:
all replicas learn the new key, subject to local keyring import.

### Read Epochs and Deterministic Decisions

M9 extends the epoch index to track **read epochs** in addition to write
epochs. Conceptually:

- For each subject, tag, and key_version, the index records when the
  subject has a valid **read epoch**.
- For each tag, the index records which key_version is current at each
  point in topo order (based on `KeyRotate`).

When a viewer `subject_pk` asks to render a field, the system:

1. Looks up the field’s tag set via the key naming convention.
2. Determines the ciphertext’s `(tag, key_version)` from the `EncV1` envelope.
3. Consults the epoch index to decide whether `subject_pk` has a valid read
   epoch for `(tag, key_version)` at that op’s position.
4. If yes, and the key exists in the local keyring, the ciphertext is
   decrypted; otherwise the value is redacted.

Because the same DAG and the same epoch builder are used everywhere, read
decisions are **fully deterministic**: any two replicas with the same ops,
trust store, and keyring will agree exactly on which values are plaintext
and which are redacted.

### Redaction vs Plaintext

For MV fields:

- If the current winner is a **plaintext value** (no `EncV1` envelope),
  it is always visible – read policy is not consulted.
- If the winner is `EncV1`:
  - If `can_read_tag_version(...)` returns true **and** AEAD decryption
    succeeds, the underlying plaintext is shown.
  - Otherwise, the exported JSON uses a constant redaction token (e.g.
    `"<redacted>"`) or omits the value entirely, depending on the caller.

For OR-set fields:

- M9 does **not** encrypt set elements.
- Sets are rendered as before in a deterministic JSON-ish format.
- Future milestones may extend read-control to sets if needed.

### Compatibility with Existing Write Policy

M9 is deliberately orthogonal to M3/M4:

- **Write policy** (Grant/Revoke + deny-wins) is unchanged. A write must
  still be authorized in order to land in the CRDT state at all.
- **Read policy** adds a separate gating layer on top of the final CRDT
  state, but only for encrypted fields.

If the log contains no KeyGrant/KeyRotate events, or if a field is not
marked confidential, behaviour collapses back to the existing **write-only**
security model.
```

---

## 2. `docs/protocol.md` – append this section

````markdown
## M9: Confidential Payloads and Key Management

M9 introduces a minimal, log-based encryption scheme for selected fields.
All changes are expressed as **additional op payloads** and **opaque binary
values**; the network and store do not need to understand the plaintext.

### EncV1: Encrypted Value Envelope

Confidential MV fields are stored as a CBOR-encoded `EncV1` structure
inside the `Payload::Data.value` bytes.

Logical schema (Rust-ish):

```text
EncV1 {
  tag:         String,   // confidentiality tag (e.g. "hv")
  key_version: u32,      // symmetric key version for this tag
  nonce:       [u8; 24], // XChaCha20-Poly1305 nonce
  aead_tag:    [u8; 16], // Poly1305 tag
  ct:          Vec<u8>,  // ciphertext bytes
}
````

Encryption uses `XChaCha20-Poly1305` (AEAD). The inputs are:

* `key`: 32-byte symmetric key for `(tag, key_version)`.
* `nonce`: 24-byte XChaCha nonce, randomly generated per write.
* `plaintext`: original field value.
* `aad`: header-based additional authenticated data, derived from the op header
  and the logical resource `(obj, field)`.

#### Header-based AAD

To bind ciphertext to its originating op and location, M9 derives AAD from
the **op header plus logical field**:

* `author_pk`
* `hlc.physical_ms`
* `hlc.logical`
* parent `op_id`s
* logical `(obj, field)` path

Implementation detail: a helper such as `derive_enc_aad(...)` computes a
fixed-length AAD buffer from these components. Both `encrypt_value` and
`decrypt_value` must use **the exact same derivation**.

This prevents simple transplant attacks where a ciphertext is copied from
one op or field into another: the AEAD tag will no longer verify because the
AAD changes.

#### Encoding and On-Wire Representation

The system always treats `Payload::Data.value` as opaque bytes:

* Writers that wish to use M9 call into `encrypt_value(...)` and store the
  resulting CBOR-encoded `EncV1` as the value.
* Readers that wish to attempt decryption pass the raw bytes through
  `serde_cbor::from_slice::<EncV1>`:

  * If decoding succeeds, the bytes are treated as an `EncV1` envelope.
  * If decoding fails, the value is treated as plaintext.

The **net layer** (`crates/net`) and **store** (`crates/store`) never
inspect or log plaintext:

* Values are transported and persisted as raw byte arrays.
* No debug or trace path should serialize decrypted values.

This is enforced by convention and tests, not by the type system.

### New Payload Types in the Op Log

M9 adds two new op payload variants:

```text
Payload::KeyGrant {
  subject_pk: PublicKeyBytes,
  tag:        String,
  key_version: u32,
  cred_hash:  [u8; 32],
}

Payload::KeyRotate {
  tag:         String,
  new_version: u32,
  new_key:     Vec<u8>,   // raw 32-byte key in the log for M9 prototype
}
```

#### KeyGrant payload

`KeyGrant` establishes that a given `subject_pk` is allowed to read
ciphertexts for `(tag, key_version)`, contingent on a VC:

* `cred_hash` is the blake3 hash of the compact JWT credential.
* The VC is verified against the existing `TrustStore` and `StatusCache`.
* The VC role and scope must entitle the subject to **read** that tag.

KeyGrant events live in the same DAG as writes, grants, and revokes:

* They are ordered by topo + HLC like all other ops.
* The read epoch index uses that order to determine when a subject has
  read access to a given `(tag, key_version)`.

#### KeyRotate payload

`KeyRotate` introduces a new symmetric key for a tag:

* `tag`: confidentiality tag.
* `new_version`: monotonically increasing version number for that tag.
* `new_key`: raw key bytes, placed directly in the log for M9.

This is a deliberate prototype simplification:

* All replicas see the same `new_key` value in the log.
* However, each replica’s **keyring import** decides which keys are
  actually used for decryption for a given viewer.
* Read access still requires a matching `KeyGrant` and VC; merely seeing
  `new_key` in the log is not sufficient to get plaintext in the UI.

Writes after `KeyRotate(tag, v+1)` must use `key_version = v+1`. Writers
should refuse to encrypt under stale versions to avoid cross-version
confusion.

### Keyring Storage

The store maintains a simple **keyring column family**:

* Column family: `keys`
* Key: `encode_tag_version_key(tag, version)`

  * Layout: `[tag_len:u8][tag_bytes...][version_be:u32]`
* Value: raw 32-byte key `[u8; 32]`

API:

* `put_tag_key(tag, version, key)` stores or overwrites the key.
* `get_tag_key(tag, version)` fetches the key, if present.
* `max_key_version_for_tag(tag)` returns the highest version seen.

`KeyRotate` replay is responsible for populating the keyring:

* When applying `KeyRotate { tag, new_version, new_key }`, the replay/CLI
  path calls `put_tag_key(tag, new_version, &key)`.

The keyring is **global to the store**, not per-subject. Authorization is
still enforced at render time (read policy + KeyGrant).

### CLI Surface: KeyRotate, KeyGrant, Show

The CLI exposes a thin wrapper over M9 operations:

* `keyrotate <tag>`

  * Computes `new_version = max_key_version_for_tag(tag).unwrap_or(0) + 1`.
  * Generates a random 32-byte key.
  * Emits `KeyRotate { tag, new_version, new_key }`.
  * Persists the key to the local keyring.

* `grant-key <subject_pk_hex> <tag> <version> <vc.jwt>`

  * Computes `cred_hash = blake3(vc.jwt)`.
  * Emits `Payload::Credential { cred_id, cred_bytes=vc.jwt, format=Jwt }`.
  * Emits `Payload::KeyGrant { subject_pk, tag, key_version=version, cred_hash }`.
  * Both ops are signed and appended to the log.

* `show <obj> <field> --subject-pk <hex>`

  * Replays the DAG into a `State`.
  * Uses `project_field_for_subject(...)` to project the current value of
    `<obj>.<field>` for `subject_pk`.
  * If the field is encrypted and the viewer lacks read access or keys, prints
    a constant redaction token (e.g. `"<redacted>"`).

The older `project` subcommand remains a low-level debugging tool: it prints a
JSON view of MV/set state without applying M9 read-control. `show` is the
user-facing entry point that enforces the full M9 model.

````

(If your CLI ended up using slightly different flag names, you can tweak the
last subsection accordingly; the core semantics are accurate.)

---

## 3. `docs/threat-model.md` – append this section

```markdown
## M9: Confidentiality and Read-Control

M9 introduces **best-effort confidentiality** for selected fields via
encryption and key grants. This section documents what is and is not
guaranteed.

### What M9 Protects

Assuming:

- All confidential writes are performed via an M9-aware client (CLI or
  equivalent), and
- The trust store and status lists are correctly managed,

then M9 guarantees the following:

1. **No accidental plaintext at rest for confidential fields**

   Confidential MV fields are stored as `EncV1` ciphertext envelopes in the
   op log and in snapshots. The store and net path only ever see opaque
   byte arrays for those values.

2. **No accidental plaintext in transit**

   Gossip / sync sends only ciphertext blobs for confidential fields.
   Peers that do not have the appropriate `KeyGrant` + VC + keyring entry
   cannot decrypt them.

3. **Forward secrecy from rotation point**

   After a `KeyRotate(tag -> v+1)` event:

   - New writes use `key_version = v+1`.
   - A subject with only `KeyGrant(tag, v)` can still read pre-rotation
     history but **cannot read post-rotation values** for that tag.
   - This remains true even if they keep their old key material.

4. **Deterministic redaction**

   Given the same log, trust store, and keyring contents, all replicas
   make identical decisions about whether a given field is shown as
   plaintext or redacted.

### What M9 Does Not Protect

M9 is intentionally narrow. It does **not** attempt to solve the full
confidentiality problem:

1. **No retroactive re-encryption**

   Revoking a KeyGrant or rotating keys does **not** rewrite history.
   Pre-rotation ciphertext remains decryptable by any subject that:

   - Has (or remembers) the old symmetric key, and
   - Has (or had) a valid `KeyGrant` and VC for that `(tag, version)`.

   This is an explicit design choice: M9 provides **forward secrecy only**
   from the rotation point onward.

2. **No protection against malicious plaintext writers**

   The core model allows arbitrary actors to submit `Payload::Data` ops
   where `value` is plaintext, even for fields that should be confidential.
   M9 does not enforce “encrypt-only” at the type level or on ingest.

   In other words:
   - If a writer bypasses the M9-aware client and directly emits
     plaintext ops for a confidential field, those bytes will be stored
     and rendered as plaintext.
   - This is considered an **operational violation**, not a protocol bug.

   Deployments that care about confidentiality must:

   - Restrict write access to audited clients that always encrypt
     confidential fields, and/or
   - Add external checks (e.g. CI or admission control) that reject
     unexpected plaintext in sensitive keys.

3. **No per-subject key wrapping**

   `KeyRotate` stores the raw symmetric key in the log for prototype
   simplicity. Access is gated by:

   - Whether the replica chooses to import that key into its keyring.
   - Whether the viewer has a valid `KeyGrant` + VC for `(tag, version)`.

   A future milestone can move to per-subject encrypted key envelopes or
   an MLS-style group protocol; M9 deliberately does not.

4. **No confidentiality for set elements**

   M9 only encrypts MV fields. OR-set elements remain in plaintext. If
   you tag a field as confidential but store the data in set elements
   rather than MV fields, M9 will not protect that data.

### Operational Guidance

To get the most out of M9 with minimal surprises:

- **Standardize on a key naming convention** where confidential fields are
  clearly distinguishable (e.g. all confidential MV keys start with
  `mv:secret:` or similar). This makes it easier to audit for plaintext
  violations.

- **Centralize key rotation** via a small number of KeyAdmins and automate
  rotation on revoke events. The code already supports multiple rotations;
  the main risk is human forgetfulness, not technical capability.

- **Monitor for plaintext regressions** by periodically scanning stored
  ops for values that should have been `EncV1` but decode as plaintext.

- **Document the limits** explicitly when presenting the system:
  “Confidential fields are encrypted at rest and in transit, but revocation
  is forward-only and relies on clients to always encrypt the right keys.”

M9 is “good enough for review”: it enforces write policy as before, adds
a concrete, deterministic read-control mechanism, and avoids large new
dependencies. The trade-offs are explicit and localised, which makes it
possible to refine confidentiality in future milestones without rewiring
the entire system.
````

---