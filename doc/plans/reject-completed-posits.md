# Ending straggler sign tasks with a completed notice

## Problem

A node that finishes a sign request puts the id in `dead_ids` and drops every
later posit for it in silence (`SignatureSpawner::handle_posit`). A node whose
indexer missed the respond event keeps rotating rounds forever: propose, no
answer, timeout, bump the round, with round timeouts growing to the 600s
ceiling. Only its own indexer can end it, which is what fails in #891 (the
Solana indexer loses respond events during catchup after a restart).

## Design

A *notice* is one posit message: a reject carrying a new `request_completed`
flag, sent by a node whose own indexer saw the request answered on chain. A
straggler ends its task once `f + 1` distinct participants have sent it one.

`f = n - threshold` (3 at the deployed 5-of-8, so 4 reports), which is what
`SinglePositCounter::enough_rejects` already uses. A `threshold`-of-`n` network
tolerates `min(threshold - 1, n - threshold)` faults, so `n - threshold` is
exact at 5-of-8 and conservative below a majority, never the weaker of the two.
`f + 1` guarantees one honest reporter, not a majority of them: one honest node
with a broken indexer plus `f` liars can still end a live task. A majority would
mean `2f + 1`, which is 7 of 8 here and blocked by any two nodes being down.
Accepting one honest remote observation, where a node already acts on one local
observation, is the consistent choice.

Fixed decisions:

- Only chain-observed completions license a notice. A finished local generation
  is not enough: the publish can still fail (#1063), and the straggler rotating
  on is then the only path left to a signature.
- A node that ends on `f + 1` notices does not send any. Hearsay never becomes
  first-hand testimony one hop on.
- Termination drops in-memory state only. The backlog entry stays, so a requeue
  after catchup brings the request back if we were wrong.
- Reports are counted in the spawner, not in the posit phases.

### Two phases

1. **Answer on demand.** A node holding a completed id answers a straggler's
   `Propose` with a notice. Covers #891, and is where correctness lives.
2. **Announce on completion**, only if phase 1 leaves zombies behind. Pure
   addition on top of phase 1; see the trigger below.

### Why the spawner counts, not the task

Counting inside `PositPhase` loses reports three ways: `Generating` consumes and
discards them, `Organizing` never reads the mailbox, and `SignState` is rebuilt
on every respawn. It also has to be hoisted above the stale-round filter in two
loops, an ordering the next refactor of those loops would quietly break, and it
needs a new `SignError` variant. `handle_posit` already sees every posit for
every id, already owns the dead-id decision and already has governance in scope.
Counting there is phase-independent by construction and reuses the existing
teardown. `posit.rs`, `state.rs`, `task.rs` and `signature.rs` stay untouched.

The cost: the spawner cannot see the phase, so a task already in `Generating` is
aborted too. Intended. The evidence says the request is answered, so that
generation is producing a signature nobody will publish.

## Phase 1: answer on demand

### Changes

`protocol/message/types.rs`, `.../inbox.rs`

- `PositMessage` gains `#[serde(default)] request_completed: bool`.
- The `signature_posit` subscriber payload is a six-tuple; replace it with
  `SignPositMessage` and put the flag there. Only the spawner reads it.

A field and not a `PositRejectReason::Completed` variant, because the outbox
CBOR-encodes each 256kb partition as one `Vec<Message>` and the receiver decodes
it all-or-nothing: an unknown variant drops the whole partition, including
unrelated triple, presignature and generating traffic. The nodes that are behind
during a rolling upgrade are the likely stragglers, so a variant misfires
exactly where it is needed. Serde ignores unknown fields, so this is compatible
both ways, the same trick as `stale_round`, for about eleven bytes per posit.

`protocol/request/mod.rs`

- `completed_ids: LruCache<SignId, ()>`, the licence to send a notice.
  `handle_completion` inserts, `add_request` removes as it re-admits a request,
  `AbortChain` clears it. One writer, and `dead_ids` keeps its current type and
  meaning.
  - `AbortChain` clears everything rather than one chain's entries: a regression
    rolls back the respond event, nodes re-index at different times, and a node
    that has not re-indexed yet would otherwise talk the first node that
    re-drives the request out of retrying. Clearing across chains costs a few
    licences and, unlike clearing `dead_ids`, cannot resurrect orphan mailboxes.
- `SignEntry` gains `completed_reports: HashSet<Participant>`, created and
  dropped with the request, so there is no extra lifecycle and nothing to bound.
- `handle_posit` takes `&GovernanceInfo`, becomes async, and gains two branches:
  - *Answer*: id in `completed_ids` and action is `Propose` gets a notice back,
    with the id echoing the sender's `(sign_id, presignature_id, round)`, the
    same "the id is an address, not content" convention as the `StaleRound`
    reply. `Accept`, `Reject` and `Start` are never answered, since replying to
    a reject ping-pongs. Everything else keeps today's silent drop. Await the
    send like every other sender: `MAX_MESSAGE_OUTGOING` is about a million, so
    there is no backpressure to design around.
  - *Count*: flag set, sender is a current participant, id is tracked, then
    insert into `completed_reports` and compare its size against
    `participants.len().saturating_sub(threshold) + 1`. Membership checked on
    insert keeps the quorum test to one comparison. On quorum, retire the
    request and abort the task exactly as `handle_completion` does, but leave
    `completed_ids` alone.
- The flag counts whatever action carries it; coupling it to `RejectWithReason`
  buys no safety, since the same node can send a reject. Senders always pair it
  with one so that a node not knowing the field reads something sane.
- Observability, and phase 2's decision data: log each new distinct report with
  its running count, warn on quorum with the reporter set, add
  `SIGN_ENDED_BY_COMPLETED_QUORUM` by chain, and a gauge of the highest round in
  flight per chain (`round` is already in `SignEntry`). The gauge is the
  important one. Quorum successes are visible; the case phase 2 exists for shows
  up only as an absence.

### Tests

1. **Quorum and wiring**: four participants, threshold three, so quorum two is
   distinguishable from both `f` and `n`. One sender repeated leaves the task
   alive; a second distinct sender retires the request and aborts the task.
2. **Licence gating**: after `handle_completion` a `Propose` draws a notice and
   creates no mailbox; after `AbortChain` it draws nothing. The safety branch:
   never claim a rolled-back request is answered.
3. **Wire compatibility**: extend
   `test_posit_stale_round_field_is_wire_compatible` to carry the new field too
   and rename it, rather than copying thirty lines. The one failure that only
   appears during a deploy.

Tests 1 and 2 need the fixture `test_abort_chain_dead_ids_lifecycle` builds
inline today; extract a `fn test_spawner(...)`. Not worth writing: an
integration test (cannot run here, Docker is x86_64 and unavailable), proposer
and deliberator variants (one code path), metric assertions.

### What it leans on

- `MessageInbox::verify_senders` drops messages whose claimed `from` differs
  from the authenticated envelope sender, so one node cannot forge `f + 1`
  reports. This is load-bearing.
- Losing a notice is harmless: the posit channel is `try_send_lossy`, and the
  straggler asks again next time it proposes. Duplicates collapse in the set.
- A notice is about the request, not an attempt, so no round ordering has to be
  maintained anywhere.
- An id is either tracked or completed, never both, so the two branches of
  `handle_posit` cannot both fire.
- Aborting releases what the task held: an uncommitted presignature reservation
  returns to the pool on drop, along with the limiter permit.

## Phase 2: announce on completion

**Trigger.** Ship phase 1, then read the round gauge for a few weeks on devnet
and testnet. If requests still sit above a full proposer rotation (round 8 at 8
nodes) minutes after the network answered them, push earns its place. Expect
those leftovers on loaded nodes: a straggler cannot propose without a
presignature and one of the four proposer slots, and cannot be answered until it
proposes.

**Changes.** `handle_completion` sends the same notice to every other
participant, once, when the id is new to `completed_ids` and we were tracking
the request. Both triggers build it through one `completed_notice(...)`.

- Only on that transition, so a duplicate respond event or a checkpoint replay
  does not re-broadcast; only for tracked requests, which keeps catchup replays
  quiet.
- An unsolicited notice has no attempt to point at, so it carries
  `presignature_id: 0` and `round: 0`. Zero is the only safe round: a receiver
  buffering a future-round message sets `highest_seen_round` from it, and 0 can
  neither raise that nor displace a live mailbox slot.
- Sent to all participants without consulting the mesh; the outbox already
  retries unreachable peers for `message_timeout` and gives up.
- Cost `n(n - 1)` per completed request, paid whether or not anyone is behind:
  56 messages of roughly 60 bytes at 8 nodes, batched into partitions the outbox
  already sends.

**Test.** One `handle_completion` for a tracked id puts one notice per other
participant in the outbox; a second one, and one for an untracked id, put
nothing there. Without the transition gate a replayed respond event
re-broadcasts on every catchup, which is a production-only failure.

## Limits

- Phase 1 needs the straggler to propose: once every `n` rounds, and not at all
  when it cannot reserve a presignature or a proposer slot. At the 600s round
  ceiling that is up to about 80 minutes, or never for a starved node. Phase 2
  is the answer to that, which is why it is a phase and not a rejection.
- #891 is a pull case. That node is down while a push would have gone out, so
  phase 2 would not have shortened it.
- The licence expires: LRU eviction and restarts wipe `completed_ids`, after
  which peers drop silently again and an old straggler never reaches `f + 1`.
- Fewer than `f + 1` observers, no effect: if a catchup gap made most indexers
  miss the respond event, the request rotates as it does today.
- This is resilience against an indexer that loses respond events. Fixing the
  #891 catchup gap removes the stragglers; this only removes their effect.

## Rejected alternatives

- **Tagging `dead_ids` with a retirement reason** instead of a second cache: one
  map, but four `retire_task` call sites must pass a reason and two paths write
  the same id, so `handle_task_exit` running after `handle_completion` silently
  downgrades the tag and disables the feature. A single-writer cache makes that
  impossible rather than merely documented.
- **A new `PositRejectReason` variant, or a dedicated `Message` variant**: drops
  whole partitions on not-yet-upgraded nodes.
- **Counting in the posit phases**: loses reports during generation, needs round
  ordering in two loops, resets on respawn.
- **Local generation success as evidence**: reaches quorum more often, but a
  finished generation is not a landed publish, and it would end the task of the
  one node that could still drive the request to a signature.
- **Removing the backlog entry on quorum**: survives a restart, at the price of
  deleting a locally pending request on peer testimony alone.
- **A deadline instead of phase 1**: far simpler, and it ends live requests as
  readily as dead ones. Worth adding as a backstop on its own merits, not as a
  substitute for evidence-based termination.
- **Buffering notices for untracked ids**: a cache keyed by an id a peer
  chooses, for nothing. A merely lagging indexer sees request then respond in
  order; a straggler indexed the request first by definition, so its task exists
  when a notice arrives.
- **Pushing from one node**: a straggler needs `f + 1` distinct reporters, so a
  single broadcaster ends nothing on its own.

## Non-goals

No hearsay relay, no backlog changes, no changes to triple or presignature
posits, no new message type, no aborting a generation except via the quorum
path above.
