# Ending straggler sign tasks with a `completed` reject

## Problem

When a node finishes a sign request, the id goes into `dead_ids` and every late
posit message for it is dropped in silence (`SignatureSpawner::handle_posit`).
A node whose indexer missed the respond event keeps rotating rounds for that
request: it proposes, nobody answers, it times out, it bumps the round, and
round timeouts grow towards the 600s ceiling. Nothing ends the task until that
node's own indexer reports the completion, which is exactly what fails in the
lingering-signId incidents (#891: the Solana indexer misses respond events
during catchup after a restart).

## Design

A node that has seen a request answered on chain replies to a straggler's
`Propose` with a reject carrying a `request_completed` flag. The straggler ends
its task once `f + 1` distinct participants have told it so, where
`f = n - threshold` (8 nodes, threshold 5 => f = 3, so 4 reports). `f + 1`
guarantees at least one honest reporter, so `f` colluding nodes cannot end an
honest task. The same arithmetic already appears in
`SinglePositCounter::enough_rejects`, which fires above `n - threshold` rejects.

The tolerated fault count of a `threshold`-of-`n` signing network is
`min(threshold - 1, n - threshold)`: more corrupt nodes than the first can forge
a signature, more offline nodes than the second stop it. Using `n - threshold`
is therefore correct at 5-of-8 and, for any threshold below a majority,
overestimates `f` and so asks for more reports than strictly needed. It is never
the weaker of the two.

Decisions:

- **Only chain-observed completions license the reject.** An id qualifies only
  if it was retired via `SignCommand::Completion`, i.e. our own indexer saw the
  respond event. Local generation success is not enough: publishing can still
  fail (#1063 has no publish failover) and a straggler rotating on is then the
  only remaining path to a signature.
- **A node that ends on `f + 1` reports does not repeat them.** It marks the id
  dead without the chain-completed tag, so hearsay never turns into first-hand
  testimony one hop later.
- **The straggler ends its task in memory only.** The backlog entry is left
  alone; a restart plus catchup requeue re-drives the request and the same
  mechanism ends it again.
- **Reports are counted in the spawner, not in the posit phases.** See below.
- **The flag is an optional message field, not a new `PositRejectReason`
  variant.** See the wire-format section.

### Why the spawner counts, not the task

The first draft threaded a `completed` flag into `SignPositMessage` and counted
it inside `PositPhase::wait_for_propose` and `PositPhase::advance`. That is the
wrong place:

- Reports that arrive while the task is in `Generating` are consumed by
  `GeneratingPhase::reject_late_propose` and thrown away, and reports that
  arrive during `Organizing` sit in the mailbox behind the phase that does not
  read it. Evidence is lost for reasons that have nothing to do with the
  evidence.
- Both posit loops filter on the round before they look at the action, so the
  counting has to be carefully hoisted above the stale-round branch in two
  places, with a test to pin the ordering. That ordering is a latent bug
  waiting for the next refactor of those loops.
- The count lives in `SignState`, which is rebuilt on every task respawn.
- It needs a new `SignError` variant and a new terminal path through the phase
  machine.

`handle_posit` already sees every posit message for every sign id, already owns
the dead-id decision, and already has the governance info. Counting there is
phase-independent, survives respawns, loses nothing, and reuses the existing
termination path: reaching quorum does what `handle_completion` does, minus the
chain-completed tag. `posit.rs`, `state.rs`, `task.rs` and `signature.rs` are
untouched.

The cost of the choice: the spawner does not know which phase the task is in, so
a task that has reached `Generating` is aborted too. That is intended. The
evidence is `f + 1` reports that the request is already answered on chain, so
the generation in flight is producing a second signature nobody will publish.
(If generation must never be aborted, the alternative is an `AtomicBool` in
`SignEntry` set by `GeneratingPhase` and a deferred kill; that is more
machinery for a case that does not need it.)

## Changes

### 1. `chain-signatures/node/src/protocol/request/mod.rs`

- `dead_ids: LruCache<SignId, Retirement>` with
  `enum Retirement { CompletedOnChain(Chain), Other }`. `retire_task` takes the
  retirement: `handle_completion` records `CompletedOnChain(chain)`; task exits
  (`Ok`, `Err(Aborted)`, interrupted), `AbortChain` and the quorum path record
  `Other`. The regression case is the one that matters: a rolled-back chain must
  never make peers claim the request is answered.
- `AbortChain(chain)` also walks `dead_ids` (`iter_mut`, at most 4096 entries on
  a rare event) and downgrades every `CompletedOnChain(chain)` to `Other`. A
  regression rolls back the respond event that licensed the answer, and nodes
  re-index at different times: without this, the nodes that have not re-indexed
  yet answer `request_completed` to the first node that re-drives the request
  and talk it out of the retry. The entries stay in the cache, they just lose
  the licence to answer.
- `mark_dead` is monotonic: `CompletedOnChain` is never downgraded to `Other`.
  Without this the feature silently disables itself, because a task that exits
  on its own just after `handle_completion` retired the id runs `retire_task`
  a second time through `handle_task_exit`.
- `handle_completion` and the quorum path share one
  `fn end_request(&mut self, sign_id, retirement, reason)` that retires and
  aborts, so the two callers cannot drift apart.
- `SignEntry` gains `completed_reports: HashSet<Participant>`. Per-request state
  with a lifecycle that already exists: it is created in `add_request` and
  dropped in `retire_task`, so there is no second map to keep in step and no
  memory to bound. Reports for a sign id we do not track are ignored, which is
  also what stops a peer from growing our memory with reports for made-up ids.
- `handle_posit` takes `&GovernanceInfo` (already in scope in the select loop)
  and gains two branches:
  - **Answering.** If the id is dead as `CompletedOnChain` and the action is
    `Propose`, reply to the sender with `RejectWithReason(Unknown)` and
    `request_completed: true`, with the id echoing the sender's
    `(sign_id, presignature_id, round)`, the same "the id is an address, not
    content" convention as the `StaleRound` reply. `Accept`, `Reject` and
    `Start` are never answered: replying to a reject ping-pongs between nodes.
    A `Other` id keeps today's silent drop. The reply must not block the
    spawner select loop and must not spawn a task per inbound message, so add a
    non-blocking `MessageChannel::try_send` (the outgoing channel is a bounded
    tokio mpsc) and drop the reply when the outbox is full. Best effort is the
    right semantics here: the straggler asks again next time it proposes, and
    the rest of the codebase already drops posit traffic under load
    (`try_send_lossy`).
  - **Counting.** If the message carries `request_completed` and we track the
    sign id, insert the sender into `completed_reports`, intersect it with the
    current participant set, and compare against
    `participants.len().saturating_sub(threshold) + 1`. On quorum, run the
    same teardown as `handle_completion` with `Retirement::Other`.
- Observability, because a straggler that never reaches quorum is otherwise
  invisible: log each new distinct report at info with the running count
  (`2/4`), warn on quorum with the reporter set, and add two counters,
  `SIGN_COMPLETED_REJECTS_SENT` and `SIGN_ENDED_BY_COMPLETED_QUORUM` (labelled
  by chain, read off `SignEntry` before the request is dropped).
- The flag is counted whatever action carries it. Coupling it to
  `RejectWithReason` would buy no safety, since the same node can send a reject,
  and it would be one more branch to keep in step. The sender always pairs it
  with a reject so that a node which does not know the field still reads
  something sane.

### 2. `chain-signatures/node/src/protocol/message/types.rs`, `.../inbox.rs`

- `PositMessage` gains `#[serde(default)] request_completed: bool`, documented
  as "set by a node that has seen this request answered on chain; paired with
  `RejectWithReason(Unknown)` so that nodes which do not know the flag read an
  ordinary reject".
- The `signature_posit` subscriber payload is already a six-tuple; carry
  `SignPositMessage` through it instead of widening the tuple again.

Why a field and not a `PositRejectReason::Completed` variant: the outbox groups
per-peer messages into 256kb partitions, CBOR-encodes each partition as one
`Vec<Message>`, and the receiver decodes it all-or-nothing
(`cbor_from_bytes::<Vec<Message>>`). An unknown enum variant fails the whole
vector, so a not-yet-upgraded node would drop every message in that partition,
including unrelated triple, presignature and generating traffic. During a
rolling upgrade the nodes that are behind are precisely the ones being
restarted, i.e. the likely stragglers, so a variant misfires exactly where it is
needed. Serde ignores unknown struct fields, so an added field is compatible in
both directions; this is the same trick as `stale_round`. Cost: about eleven
bytes on every posit message, including triple and presignature posits. Folding
the flag into `PositRejectReason` is a follow-up for after the fleet is
upgraded, together with `stale_round`.

## What the design leans on

- **Reports are counted per distinct sender, and the sender is authenticated.**
  `MessageInbox::verify_senders` drops any message whose claimed `from` differs
  from the signature-authenticated envelope sender, so one Byzantine node cannot
  forge `f + 1` reports by varying a claimed field. This is the load-bearing
  assumption of the whole scheme.
- **Losing a report is harmless.** The posit subscriber channel is
  `try_send_lossy` and drops under load. Every report is regenerated the next
  time the straggler proposes, and duplicates are idempotent (the inbox dedups
  by signature, the report set dedups by sender).
- **A sign id is either tracked or dead, never both.** `add_request` clears the
  dead tag and `retire_task` drops the request as it sets one, so the answering
  branch and the counting branch of `handle_posit` are mutually exclusive
  without an explicit check.
- **Ending a task releases what it held.** An uncommitted presignature
  reservation returns to the pool on drop and the limiter permit is released
  with it, so aborting during organizing or posit costs nothing. A presignature
  already committed for generation is consumed either way.
- **Answering costs at most one message per message received.** A participant
  that floods `Propose` for a completed id gets one reply each, so there is no
  amplification, and the replies are dropped rather than queued when the outbox
  is full.
- **A report is not tied to a round or an attempt.** It is a statement about the
  request. Counting in the spawner keeps it that way by construction, which is
  why no ordering against the stale-round filter has to be maintained.
- **Governance changes do not inflate a stale count.** Quorum is computed from
  the current participant set and the report set is intersected with it, so
  reports from participants that left do not count towards a smaller quorum.
- **A re-indexed request resets everything.** `add_request` clears the dead tag,
  so after a regression recovery the node stops answering `request_completed`
  for that id and starts a fresh count.
- **The evidence is no weaker than what each reporter acted on itself.** An
  honest reporter ends its own task on exactly one respond event; the straggler
  ends its task on `f + 1` independent copies of that same observation.

## Tests

Three, each pinning something that would otherwise break silently.

1. **Quorum and wiring** (`request/mod.rs`): with four participants and
   threshold three (quorum two, so the test can tell `f + 1` from both `f` and
   `n`), feed `handle_posit` reports for a tracked sign id whose task is the
   `DropProbe` future the existing test already uses. One sender repeated twice
   leaves the task alive; a second distinct sender retires the request and
   aborts the task. Covers the Byzantine parameter, sender dedup, and the
   teardown wiring in one test.
2. **Retirement gating** (`request/mod.rs`): after `handle_completion`, a
   `Propose` for the dead id draws a reply carrying the flag and creates no
   mailbox; after `AbortChain`, the same `Propose` draws nothing. This is the
   safety branch: never claim a rolled-back request is answered.
3. **Wire compatibility** (`message/crypto.rs`): extend
   `test_posit_stale_round_field_is_wire_compatible` to carry
   `request_completed` alongside `stale_round` and rename it for both fields,
   rather than copying thirty lines for a second one. It already asserts the
   property that matters in both directions: a batch decodes on a node that does
   not know the field, and a batch without the field decodes as the default.
   This is the one failure mode that only shows up during a deploy, so it is
   worth the test even though the pattern is proven.

Tests 1 and 2 need the spawner fixture that
`test_abort_chain_dead_ids_lifecycle` builds inline today; extract it into a
`fn test_spawner(...)` helper rather than copying fifty lines twice.

Not worth writing: an integration test (cannot run here, Docker is x86_64 and
unavailable, and it would only re-cover the unit-tested logic), separate
proposer and deliberator variants of test 1 (one code path now), and any test
asserting a metric increments.

## Limits

- **Termination takes up to `n` proposing rounds.** A straggler only draws
  replies in rounds where it proposes, and the proposer rotates as
  `(entropy[0] + round) % n`, so it proposes once every `n` rounds. It also has
  to get that far: `OrganizingPhase` gives up before proposing when no
  presignature can be reserved or no proposer slot is free
  (`MAX_CONCURRENT_PROPOSERS`), and a starved node stays silent and therefore
  unanswerable. Once it does propose, every peer answers at once and quorum is
  reached inside that round. With eight nodes and round timeouts at the 600s
  ceiling, that is up to about 80 minutes, averaging 40. Much better than never, but not immediate. The fix, if
  that is too slow, is a one-shot broadcast when an id is retired as
  `CompletedOnChain`: `n - 1` extra messages per completed request, paid on
  every request whether or not anyone is behind. Out of scope here.
- **The evidence expires.** `MAX_DEAD_IDS = 4096` LRU eviction and peer restarts
  both wipe the dead-id tag, after which peers go back to dropping silently and
  an old straggler never reaches `f + 1`.
- **Fewer than `f + 1` observers, no effect.** If a catchup gap made most
  indexers miss the respond event, the request rotates as it does today.

## Non-goals

No relaying of hearsay, no backlog changes, no changes to triple or
presignature posits, no new message type.

## Rejected alternatives

- **Counting in the posit phases**: loses reports during generation, needs
  ordering against the round filters in two loops, resets on respawn. See above.
- **A new `PositRejectReason` variant**: drops whole message partitions on
  not-yet-upgraded nodes during a rolling deploy.
- **Also treating local generation success as evidence**: reaches quorum in more
  cases, but a finished generation is not a landed publish, and it would end the
  task of the one node that could still have driven the request to a signature.
- **Clearing all of `dead_ids` on a chain regression** instead of downgrading
  the affected entries: simpler, but late posits for unaffected chains would
  start recreating orphan mailboxes, which is the leak `dead_ids` exists to
  prevent.
- **Removing the backlog entry on quorum**: makes the termination survive a
  restart, at the price of deleting a locally pending request on peer testimony
  alone.
