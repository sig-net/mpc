# Checkpoint-safe upgrades

## 1. Goal

Make a binary upgrade safe with respect to checkpoints so that all correct nodes can settle
and adopt the latest checkpoint from a durable body they can read, and then vote from it. If
that cannot be guaranteed, the system must halt rather than settle a wrong digest or vote from
a divergent backlog. Correctness takes priority over availability.

## 2. Failure modes

"Checkpoint format" is three independent version gates plus one timing gap.

1. **The consensus digest.** The digest is `SHA3-256(chain, height, request IDs in order,
   CBOR of each entry's facts)`. Those CBOR bytes are consensus: the contract stores the voted
   digest verbatim and never recomputes it. Any change to digest-covered fields or their
   encoding makes old and new binaries compute different digests for the same height, which
   splits the vote. A guard is needed so that adding a field to the entry facts forces an
   explicit decision about its inclusion in the digest, along with a digest version bump and
   cross-version golden vectors.

2. **Persisted bodies.** Bodies are CBOR encoded and stored in Redis. There is no version
   field inside the body and no migration for the checkpoint type. The storage version is a
   key namespace, so a namespace bump strands existing data rather than translating it.

3. **Wire and mesh versions.** The protocol and checkpoint wire versions are compared with
   strict equality, with no tolerance range. A mismatch rejects peer checkpoint exchange or
   removes the peer from the mesh.

4. **The confirmation-to-promotion gap.** The contract settles only a 32-byte digest, never
   the body. A node persists a body before voting its digest, so between settlement and local
   promotion the body exists only in node storage. A restart cannot lose it if that storage is
   durable. What can go wrong is mistaking a durable but unsettled body for the backlog seed,
   or re-voting it after a restart. Recreating the body by re-indexing is not a safe fallback:
   new code can apply the same historical blocks differently and produce a different digest.

Promotion itself is atomic: the durable base is written before any pending entry is deleted.
The exposure is entirely in how unsettled durable bodies are treated before promotion.

## 3. Invariant

> From the moment a node votes for a checkpoint until it becomes the base, a durable body for
> that checkpoint exists and is readable by whatever binary eventually promotes it. Only a
> contract-settled digest is authoritative for building and voting; an unconfirmed durable
> body is never a seed or a vote on its own.

## 4. Design

### 4.1 Height-keyed orphan set

Add one key pair with the same shape as the existing pending keys: an orphan body hash keyed
by height, and an orphan digest index mapping digest to height. The new keys are additive and
do not change the encoding of existing data.

At the start of every recovery pass, active pending bodies are moved into the orphan set and
pending is cleared. The move uses the existing digest index, so no digest is recomputed. It is
idempotent: once pending is empty, repeating it has no effect.

Orphans remain durable, servable by digest to peers, and promotable. They are deliberately
excluded from two things: they never seed the in-memory backlog, and they are never re-voted
at startup. Recovery seeds only from the confirmed base. Restarting with no confirmed base
means re-indexing from the chain's start height rather than resuming from an orphan. Orphans
do not consume the pending cap.

The move must maintain a strict index invariant: if the orphan digest index maps a digest to
a height, the body stored at that height is that digest's body. Because orphans are
height-keyed, writing a new body at a height already occupied by an orphan overwrites it. All
orphan index entries pointing at that height must therefore be purged before the new mapping
is installed. Without this, a stale index entry could resolve a settled digest to a different
body and promote the wrong checkpoint.

### 4.2 Promotion and discard

Promotion resolves the settled digest through the pending index first, then the orphan index,
in a single atomic operation. It writes the base, retires the matched body from both the body
store and the index, and deletes every pending and orphan entry at or below the promoted
height except the matched digest. Regression resets durable state to a consensus checkpoint
and clears both stores.

Promotion relies on the index invariant rather than re-verifying the body: the demotion
operation is the only writer of the orphan index and maintains that invariant, so an indexed
digest identifies its own body. Lookups that serve bodies to callers do verify the decoded
body's digest before returning it, treating the index as a lookup hint rather than a trust
boundary.

### 4.3 Peer-body verification

A body arriving from a peer crosses a trust boundary. It is decoded and its digest recomputed
and compared with the digest the contract settled. A peer whose body does not hash to the
settled digest is skipped, and if no peer supplies a matching body, nothing is adopted and
alignment halts. An old-format body still reproduces its original digest through the legacy
hash path, so verification does not reject legitimate historical data.

This is distinct from local promotion. For a body already in local storage the index is
authoritative; for a body crossing the network boundary, recomputation is the integrity
check.

### 4.4 Same-height bodies and the peer-fetch fallback

Because orphans are height-keyed, a new-format body and an old-format body at the same height
cannot both be retained. If the contract settles a digest whose body the node cannot read
locally, the node fetches it from a peer. Peer-body verification guarantees the fetched body
matches the settled digest. If no peer serves a matching body, the node halts. This is an
availability cost accepted in exchange for never adopting an unverified body.

### 4.5 Base-format portability and digest stability

A binary must be able to read a base or orphan body written by an earlier binary. The body
needs an in-body format version and a permanently retained legacy decoder. The legacy reader
is never removed: removing it is an explicit exception to ordinary two-phase deprecation,
because an unreadable base is unrecoverable without relying on re-indexing.

The digest-covered field set must remain closed. Adding a field to the entry facts must force
an explicit decision about whether it is hashed. Cross-version golden vectors guard against
silent digest changes. Any change to digest-covered fields or their encoding requires a
digest version bump, and the digest encoding and the storage encoding must never change in
the same release.

### 4.6 Verification requirements

Tests must cover demotion idempotency, orphan serving by digest, promotion from an orphan, the
two-restart same-height overwrite case, ordering of orphan against a higher base, and
peer-body digest rejection. Backend-specific tests are required because the in-memory and
persistent implementations must choose identically.

A mixed-cluster test must cover the confirmation-to-promotion gap: an older binary creates
and votes for a checkpoint, the contract settles it, the whole cluster restarts before any
promotion, and the newer binaries then promote using the stored body without re-indexing and
reach agreement on the next checkpoint.

## 5. Alternatives rejected

- **Epoch-gated activation at a fixed checkpoint height.** Correct, but requires coordinating
  an activation height across every chain. The operational cost is not justified for this
  change.
- **Memory-only pending.** Unsafe. If all nodes restart in the confirmation-to-promotion gap,
  no body remains and recreation across an upgrade is not deterministic.
- **A digest-keyed orphan store with additional base metadata.** More powerful, because two
  bodies at one height can coexist without a peer fetch, but substantially more state and a
  full rewrite of the storage operations. The extra complexity is not warranted for the
  failure mode being addressed.
- **Re-index-to-settled as the safety net.** Not a reliable recovery path, because an upgrade
  can change how historical blocks are applied.

## 6. Tradeoffs

- One extra key pair and modest additions to the storage operations. The CBOR body and the
  storage version are unchanged.
- Orphans are height-keyed, so a second body at the same height replaces the first. The
  fallback is a peer fetch, and a halt if no peer has the body.
- A restart with no confirmed base re-indexes from the chain's start height.
- The permanently retained legacy decoder is ongoing maintenance cost, accepted for
  correctness.

## 7. Design questions

- **Does serving by digest require decoding the body?** Yes, for integrity. The index is
  resolved to a height, the body is decoded, and it is accepted only if its recomputed digest
  equals the requested digest. Legacy-format bodies use the legacy hash path and reproduce
  their original digest. The contract-settled digest is the authority; the storage index is a
  lookup hint.
- **Is the existing legacy digest field sufficient as the authoritative digest?** For
  matching a locally stored body, the authority is the storage index together with the
  contract settlement, not a field inside the body. Body-level changes belong with the format
  version and permanent legacy decoder.
