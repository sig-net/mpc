# Mesh "active" subsystem review

Scope: `chain-signatures/node/src/mesh/` (`mod.rs`, `connection.rs`, `state.rs`),
the `/sync` and `/status` endpoints that feed it (`web/mod.rs`, `node_client.rs`),
`protocol/sync/mod.rs`, and the consumers of `MeshState::active()`
(`protocol/request/organize.rs`, `protocol/triple.rs`, `protocol/presignature.rs`,
`backlog/consensus.rs`, `stream/recovery.rs`, `indexer_hydration/mod.rs`).

## How it works today

Each node runs a `connection::Pool` holding one `NodeConnection` task per peer
listed in the contract. That task polls the peer's `/status` every
`MPC_MESH_PING_INTERVAL` (default 1s) and derives a `NodeStatus`:

- `/status` unreachable, or `protocol_version` mismatch -> `Offline`
- peer reports anything other than `Running` -> `Inactive`
- peer reports `Running`, and we were previously not `Active` -> `Syncing`
- `Syncing` -> `Active` only when `Pool::report_node_synced` is called, which
  happens after `SyncTask` completed a `/sync` round-trip with that peer

Status changes flow through a broadcast channel into `ConnectionWatcher`, which a
task inside `Mesh::run` folds into a `watch::Sender<MeshState>`. `MeshState` holds
two `Participants` maps, `active` and `need_sync`. Everything downstream reads
`active()` to decide who can be used in a protocol, and `need_sync()` drives the
next `/sync` broadcast.

## Findings

Ordered by severity. IDs are referenced by the implementation plan below.

### S1 (critical) — `/sync` is unauthenticated and can remotely delete protocol artifacts

`POST /sync` is served with no authentication
([web/mod.rs:74](chain-signatures/node/src/web/mod.rs:74)). The body deserializes
straight into a `SyncUpdate`, whose `from: Participant` field is an unverified
attacker-controlled claim, and is passed to
`TripleStorage::remove_outdated(update.from, &update.triples)`
([protocol/sync/mod.rs:82](chain-signatures/node/src/protocol/sync/mod.rs:82)).

`remove_outdated` treats the supplied id list as the owner's authoritative set and
deletes everything we hold for that owner which is *not* in the list
([storage/protocol_storage.rs:400](chain-signatures/node/src/storage/protocol_storage.rs:400)).
So:

```
POST /sync  {from: P, triples: [], presignatures: []}
```

deletes every triple and presignature we hold that is owned by `P`. Iterating `P`
over the participant set wipes the node's entire artifact store; replaying it in a
loop keeps it wiped. Presignature and triple generation is the expensive part of
the protocol, so this is a cheap, remote, unauthenticated, indefinitely repeatable
denial of service against signing — and it can be aimed at every node in the
network simultaneously.

The endpoint is reachable from the internet: `infra/partner-mainnet/main.tf`
fronts port 3000 with an `EXTERNAL` global HTTPS load balancer on a public IP,
the URL map has no path restrictions, and there is no Cloud Armor policy in the
repo. The GCE firewall rule only constrains the direct instance path, not the LB.

The fix already exists in the codebase and is used by `/msg`:
`SignedMessage::encrypt` / `decrypt_with`
([protocol/message/crypto.rs](chain-signatures/node/src/protocol/message/crypto.rs))
HPKE-seals a payload to the recipient's `cipher_pk` and signs it with the sender's
`sign_sk`, and `decrypt_with` returns the *authenticated* sender after checking the
signature against the contract's `ParticipantMap`. `/sync` should use the same
envelope, and the authenticated sender — not the `from` field inside the payload —
must be what reaches storage.

### S2 (high) — unauthenticated 20 MB body and unbounded work per request

`/sync` sets `DefaultBodyLimit::max(20 * 1024 * 1024)`
([web/mod.rs:75](chain-signatures/node/src/web/mod.rs:75)). Anyone can post 20 MB
of CBOR ids and make the node run a Redis Lua script over all of them, with no
rate limit and no concurrency bound. Fixed as a side effect of S1 (the envelope
must decrypt and verify before any work happens), but the limit should also be
sized to the real maximum (participants x per-owner artifact cap) rather than a
round 20 MB.

### S3 (high) — lost connection updates are silently swallowed

`ConnectionWatcher::next` matches `Ok(update) = self.conn_update.recv()`
([mesh/connection.rs:361](chain-signatures/node/src/mesh/connection.rs:361)). A
`broadcast::error::RecvError::Lagged` does not match the pattern, so the branch is
skipped and the missed updates are gone with no log. A dropped
`ConnectionUpdate::New(p, rx)` means `p`'s status watcher is never registered, so
`p` can never become active on this node — a silent, permanent capacity loss that
persists until the next contract change happens to re-create the connection. The
channel holds 256 entries; a contract update touching a large participant set
while the consumer is busy is enough to lag it.

### S4 (high) — `ConnectionWatcher::next` panics when the pool goes away

In the same `select!`, if the broadcast channel is closed (all senders dropped,
i.e. `Pool` dropped) the first branch is permanently disabled, and if `watchers` is
empty `StreamMap::next()` returns `None`, disabling the second. `tokio::select!`
with all branches disabled and no `else` panics. The updater task in `Mesh::run`
([mesh/mod.rs:74](chain-signatures/node/src/mesh/mod.rs:74)) is a detached
`tokio::spawn` with no join handle and no supervision, so the panic is invisible:
`MeshState` freezes at its last value forever while the node keeps reporting
healthy on `/status` and `/`. A frozen-but-populated `MeshState` is worse than an
empty one, because downstream `wait_threshold_active` calls succeed against stale
data and protocols are started with peers that may be long gone.

### S5 (medium) — `MeshState` is never reconciled against the contract

`MeshState` is only ever mutated incrementally, one participant at a time. The
only removal driven by contract state is `previous_me`
([mesh/mod.rs:102](chain-signatures/node/src/mesh/mod.rs:102)). Removal of any
other participant depends entirely on a `ConnectionUpdate::Drop` arriving — which
S3 shows is not guaranteed. There is no periodic or event-driven pass that asserts
"`active` is a subset of the current contract participants". A participant removed
from the contract can therefore stay in `active()` and be selected as a
presignature holder or a sign-round participant.

### S6 (medium) — we exempt ourselves from the liveness checks we apply to peers

On a `Running` contract, `Mesh::run` marks *this* node `Active` unconditionally
([mesh/mod.rs:96](chain-signatures/node/src/mesh/mod.rs:96)). `ProtocolState::Running`
describes the network, not this node: locally we may still be in `Joining`,
`Generating`, or `WaitingForConsensus`, exactly the states for which we would
classify a *peer* as `Inactive`. We also skip the `Syncing` handshake we require of
every peer. The result is that `active().len()` is inflated by one during our own
startup, so `wait_threshold_active` and
`OrganizingPhase::wait_for_active_participants` can clear the threshold using a
node that cannot actually participate. Self status should be derived from
`NodeStateWatcher`, the same source `/status` serves to peers.

### S7 (medium) — byzantine peers can drive artifact pruning

`process_sync_responses` takes a peer's `not_found` list at face value and calls
`remove_holder_and_prune(peer, threshold, ...)`, which deletes the artifact
outright once the holder set drops below `threshold`
([storage/protocol_storage.rs:1021](chain-signatures/node/src/storage/protocol_storage.rs:1021)).
The Lua script defends against a peer touching artifacts we do not own, but not
against a participant that simply lies about everything being missing. One
byzantine (or badly desynced) participant can therefore force pruning across the
network. This is a design property rather than a bug, but it is unmonitored: there
is no metric or alert on prune volume, so it would present as unexplained
presignature starvation. This is the same failure shape as the devnet holder-set
shrinkage already seen in production.

### S8 (medium) — `Drop` updates fabricate a placeholder `ParticipantInfo`

To satisfy the `(Participant, NodeStatus, ParticipantInfo)` return type,
`ConnectionWatcher::next` invents `ParticipantInfo::new(u32::MAX)` for drops
([mesh/connection.rs:370](chain-signatures/node/src/mesh/connection.rs:370)). It is
harmless only because `MeshState::update` happens to ignore `info` on the
`Offline` arm. Any future change that inserts on `Offline` silently writes a
participant with a bogus id and an empty URL into the mesh state. The type should
make the drop case unrepresentable rather than relying on a downstream coincidence.

### S9 (medium) — head-of-line blocking in the sync broadcast

`SyncTask` holds a single global broadcast slot and skips all work while one is in
flight ([protocol/sync/mod.rs:180](chain-signatures/node/src/protocol/sync/mod.rs:180)).
The receiver set is snapshotted when the broadcast starts, so a peer entering
`need_sync` one tick later waits for the whole current broadcast — up to
`BROADCAST_TIMEOUT` (120s) — before its sync is even attempted. With per-request
client timeouts this is usually short, but the worst case is a peer sitting in
`need_sync`, and therefore out of `active()`, for two minutes for no reason of its
own.

### S10 (low) — the mesh emits no metrics at all

There is no gauge for active count, `need_sync` count, or per-peer status; no
counter for status transitions; no histogram for time spent in `Syncing` or below
threshold. `wait_threshold_active` and `wait_for_active_participants` can both
block forever and each logs exactly one line when they start waiting (already
recorded as a known gap). Every incident in this subsystem currently has to be
diagnosed from logs.

### S11 (low) — version mismatch is indistinguishable from unreachable

A protocol version mismatch and a dead peer both collapse to `Offline`
([mesh/connection.rs:120](chain-signatures/node/src/mesh/connection.rs:120)). During
a rolling upgrade, version skew is expected and self-resolving; a network partition
is not. Operators cannot tell them apart from the mesh state.

### S12 (low) — small maintenance items

- `Pool::report_node_synced` is an `async fn` with no `await`
  ([mesh/connection.rs:314](chain-signatures/node/src/mesh/connection.rs:314)).
- `Pool::connect` takes `ProtocolState` by value only to clone participants out of
  it ([mesh/connection.rs:211](chain-signatures/node/src/mesh/connection.rs:211)).
- The mesh state machine is not documented anywhere; the `NodeStatus` variant docs
  are good but do not describe the transitions or who drives them.

### S13 (low) — mesh tests are sleep-based, and one asserts nothing

- Every mesh test paces itself with `tokio::time::sleep(PING_INTERVAL * 3)` and
  will get flaky on a loaded machine. `expect_status` already shows the right
  pattern (poll until a condition holds, with a timeout); the rest should use it.
- `test_pool_update`'s second loop inserts into the `syncing` set and never reads
  it back ([mesh/mod.rs:219](chain-signatures/node/src/mesh/mod.rs:219)). The test
  passes whether or not any node reaches `Active`.
- `MeshState` has a single unit test. `remove`, `clear`, and re-adding a
  participant under a different `Participant` index are untested.

## Implementation plan

Ordered so that each step is independently reviewable and shippable.

1. **S1 + S2** — authenticate `/sync` with the existing `SignedMessage` envelope.
   Storage must key off the verified sender, not the payload's `from`.
2. **S3 + S4** — make `ConnectionWatcher` lag-aware and panic-free; supervise the
   mesh updater task.
3. **S5 + S6** — reconcile `MeshState` against the contract participant set on
   every contract update, and derive self status from `NodeStateWatcher`.
4. **S8 + S12** — tighten the update type so drops carry no fabricated info; drop
   the spurious `async`; take `&ProtocolState`; document the state machine.
5. **S10 + S11** — add mesh metrics, splitting version mismatch from unreachable.
6. **S13** — replace sleeps with condition waits, fix the vacuous assertions, and
   cover the untested `MeshState` transitions.
7. **S7 + S9** — design work, not covered by the steps above: bound how much a
   single peer's sync response can prune per round, and replace the global
   broadcast slot with per-peer sync tasks.
