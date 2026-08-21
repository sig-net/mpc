# Ending stuck sign tasks with a completed notice

## The problem

When a node finishes a sign request it puts the id in `dead_ids` and silently
drops every later posit message for it. A node whose indexer missed the respond
event never learns the request is over. It keeps rotating rounds forever:
propose, no answer, timeout, bump the round, with round timeouts growing to the
600s ceiling. It also keeps taking one of the four proposer slots that live
requests need. This is #891, where the Solana indexer loses respond events
during catchup after a restart.

## The idea

A node whose own indexer saw a request answered on chain tells the stuck node
so, and the stuck node ends its task once enough peers have told it.

The message is a *notice*: an ordinary posit reject carrying a new
`request_completed` flag. Nothing else is added to the wire. The stuck node
counts distinct senders, and at `f + 1` it retires the request and aborts its
task. It does not then send notices itself, so what it heard second-hand never
travels a second hop.

Only a chain-observed completion counts. A node that merely finished generating
locally stays quiet, because the publish can still fail (#1063) and the stuck
node rotating on is then the last path to a signature.

Ending a task drops in-memory state only. The backlog entry stays, so if the
report was wrong the usual requeue after a catchup brings the request back.

### Why `f + 1`

`f = n - threshold`, so 3 at the deployed 5-of-8 and 4 reports to end a task,
the same count `SinglePositCounter::enough_rejects` already uses. A
`threshold`-of-`n` network tolerates `min(threshold - 1, n - threshold)` faults,
so `n - threshold` is exact at 5-of-8 and conservative below a majority.

`f + 1` guarantees one honest sender, not a majority of them, so one honest node
with a broken indexer plus `f` liars can still end a live task. A majority would
need `2f + 1`, unreachable at 8 nodes whenever two are down. One honest remote
observation, where a node already acts on one local observation, is the bar.

### Why not just a timeout

Capping how long a sign task may live is far simpler and would clear the
zombies, but a timer cannot tell "answered elsewhere" from "slow" from "waiting
out a partition" and ends all three, which endless rotation never does. Worth
having as a backstop, not as a substitute.

### Two phases

1. Answer a stuck node when it asks. This covers #891 and carries the
   correctness.
2. Announce on completion, without waiting to be asked. Only if phase 1 leaves
   zombies behind, and purely additive on top of it.

## Phase 1: answer when asked

### On the wire

`protocol/message/types.rs`, `.../inbox.rs`

`PositMessage` gains `#[serde(default)] request_completed: bool`. The
`signature_posit` subscriber payload, today a six-tuple, becomes
`SignPositMessage` carrying the flag; only the spawner reads it.

A field rather than a `PositRejectReason::Completed` variant, because the outbox
CBOR-encodes each 256kb partition as one `Vec<Message>` and the receiver decodes
it all or nothing. An unknown variant would drop the entire partition, including
unrelated triple, presignature and generating traffic, and the nodes running old
code during a rolling upgrade are exactly the likely stragglers. Serde ignores
unknown fields, so a field is compatible both ways. This is the same trick as
`stale_round`, for about eleven bytes per posit message.

### In the spawner

`protocol/request/mod.rs`

`completed_ids: LruCache<SignId, ()>` is the licence to send a notice.
`handle_completion` inserts, `add_request` removes as it re-admits a request,
`AbortChain` clears the whole cache; `dead_ids` is untouched. Clearing across
chains is deliberate: a regression rolls back the respond event, nodes re-index
at different times, and one that has not re-indexed yet would otherwise talk the
first node that retries out of retrying.

`SignEntry` gains `completed_reports: HashSet<Participant>`, created and dropped
with the request, so there is no new lifecycle and nothing to bound.

`handle_posit` gains two branches, which cannot both fire because an id is
either tracked or completed, never both:

- Answer. An id in `completed_ids` whose incoming action is `Propose` gets a
  notice back, its id echoing the sender's `(sign_id, presignature_id, round)`
  so the sender can see which attempt is being answered. `Accept`, `Reject` and
  `Start` are never answered, since replying to a reject ping-pongs. Everything
  else keeps today's silent drop. The notice goes out through a new
  `MessageChannel::try_send`, which logs and drops when the outgoing channel is
  full: a notice is a hint, not a delivery obligation, and blocking here would
  stall the one loop that routes every posit, sign command and task exit.
- Count. If the flag is set, the sender is a current participant and the id is
  tracked, insert the sender into `completed_reports` and compare its size
  against `participants.len().saturating_sub(threshold) + 1`. On quorum, retire
  the request and abort its task exactly as `handle_completion` does, but leave
  `completed_ids` alone. The flag counts whatever action carries it; senders
  pair it with a reject so that a node not knowing the field still reads
  something sane.

Counting belongs here rather than in the posit phases, which would discard
reports during generation, never read them during organizing, reset them on
respawn, and need hoisting above the stale-round filter in two loops. The cost
is that the spawner cannot see the phase, so a task already generating is
aborted too. That is intended: the request is answered, so that generation is
producing a signature nobody will publish.

### What we watch

Log each new distinct report with its running count, and warn on quorum with the
reporter set. Then three signals, all local:

- `SIGN_ENDED_BY_COMPLETED_QUORUM` by chain: peers ended a stuck task.
- Highest round in flight, by chain: whether stuck tasks exist at all. A healthy
  request finishes in a few rounds, so anything past a full proposer rotation is
  a task making no progress.
- Rounds where we were the elected proposer but gave up before sending
  `Propose`, by reason (no presignature, no proposer slot): whether those tasks
  can be reached at all.

### Why it holds up

- `MessageInbox::verify_senders` drops any message whose claimed `from` differs
  from the authenticated envelope sender, so one node cannot forge `f + 1`
  reports. Everything rests on this.
- Losing a notice is harmless. The posit channel is lossy by design and the
  stuck node asks again on its next `Propose`; duplicates collapse in the set.
- A notice is about the request, not about an attempt, so no round ordering has
  to be maintained anywhere.
- Aborting releases what the task held: an uncommitted presignature reservation
  returns to the pool on drop, along with the limiter permit.

### Tests

1. Quorum and wiring: four participants and threshold three, so quorum two is
   distinguishable from both `f` and `n`. One sender repeated leaves the task
   alive; a second distinct sender retires the request and aborts the task.
2. Licence gating: after `handle_completion` a `Propose` draws a notice and
   creates no mailbox; after `AbortChain` it draws nothing. Never claim a
   rolled-back request is answered.
3. Wire compatibility: extend `test_posit_stale_round_field_is_wire_compatible`
   to carry the new field and rename it. The one failure that appears only
   during a deploy.

Tests 1 and 2 need the fixture that `test_abort_chain_dead_ids_lifecycle` builds
inline today; extract a `fn test_spawner(...)`. Skip an integration test (Docker
is x86_64 and unavailable here), proposer and deliberator variants (one code
path), and metric assertions.

## Phase 2: announce on completion

Phase 1 only reaches a node that proposes, which happens once every `n` rounds
and not at all when it cannot get a presignature or a proposer slot. Phase 2
sends the notice without being asked.

Build it if the phase 1 signals show stuck tasks that cannot be reached. A quiet
quorum counter alone is ambiguous, since it means either that nothing is stuck
or that what is stuck never proposes:

- High rounds, and rounds lost to failed proposals: stuck and unreachable. Build
  it.
- High rounds, proposals going out, no quorum: peers are being reached and fewer
  than `f + 1` of them know. Announcing would not help either; the indexers are
  the problem.
- No high rounds: nothing to do.

The change is that `handle_completion` sends the same notice to every other
participant, once, when the id is new to `completed_ids` and we were tracking
the request. Both call sites build it through one `completed_notice(...)`.

- Only on that transition, so a duplicate respond event or a checkpoint replay
  does not re-broadcast, and only for tracked requests, which keeps catchup
  replays quiet.
- An unsolicited notice has no attempt to point at, so it carries
  `presignature_id: 0` and `round: 0`. Zero is the only safe round: a receiver
  buffering a future-round message takes `highest_seen_round` from it, and 0 can
  neither raise that nor displace a live mailbox slot.
- Sent with the same `try_send` to all participants, `n - 1` at a time from the
  spawner loop, which is what makes the non-blocking send worth its few lines.
- Costs `n(n - 1)` messages per completed request whether or not anyone is
  behind: 56 of roughly 60 bytes at 8 nodes, batched into partitions the outbox
  already sends.

One test: one `handle_completion` for a tracked id puts one notice per other
participant in the outbox; a second one, and one for an untracked id, put
nothing there. Without the transition gate a replayed respond event
re-broadcasts on every catchup.

## What it does not fix

- Stuck tasks that never propose, until phase 2 exists.
- Ids evicted from `completed_ids` by the LRU or lost in a restart: peers go
  back to dropping silently and an old stuck task never reaches `f + 1`.
- A catchup gap wide enough that fewer than `f + 1` nodes saw the respond event.
  The request then rotates as it does today.
- The cause. This is resilience against an indexer that loses respond events;
  fixing the #891 catchup gap removes the stragglers themselves.

Out of scope: relaying second-hand reports, backlog changes, triple and
presignature posits, and any new message type.

## Alternatives considered

- Tagging `dead_ids` with a retirement reason instead of a second cache: one map
  instead of two, but two paths then write the same id, so a task exiting just
  after `handle_completion` silently downgrades the tag and disables the
  feature. A single-writer cache makes that impossible.
- A new `PositRejectReason` variant, or a dedicated `Message` variant: drops
  whole partitions on nodes running old code.
- Treating local generation success as evidence: reaches quorum more often, but
  a finished generation is not a landed publish.
- Removing the backlog entry on quorum: survives a restart, at the price of
  deleting a locally pending request on peer testimony alone.
- Buffering notices for ids we do not track: a cache keyed by an id a peer
  chooses, for nothing. A stuck node indexed the request before it could get
  stuck, so its task already exists when a notice arrives.
- Announcing from one node instead of all: a stuck node needs `f + 1` distinct
  senders, so a single announcer ends nothing on its own.
