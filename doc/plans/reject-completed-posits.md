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

A *notice* is one posit message: a reject carrying the `request_completed`
flag. The same notice is sent on two triggers, one push and one pull. Push: node A's
indexer sees the respond event, A retires the id as completed-on-chain and
sends every participant one notice. Pull: whenever a node holding the
completed tag receives a `Propose` for that id, it answers the sender with the
same notice. Straggler S counts distinct senders in its spawner, across rounds
and phases; at `f + 1` it retires the request and aborts the task, without
itself gaining the right to answer for that id.

Push is the fast path and covers the straggler that cannot propose at all.
Pull is the reliable path and covers everything the one-shot missed: S was
down, restarted, or had not indexed the request yet when the push went out.
Correctness rests on pull; push only shortens the wait.

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
- **The push is one shot, on the transition to completed-on-chain**, for
  requests we actually tracked. No repeats, no retries, no state to keep.
- **The flag is an added message field, not a new `PositRejectReason`
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

Footprint: one added wire field, one enum, one set per in-flight request, one
message constructor with two call sites, across four files. Nothing in the sign
state machine changes.

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
- `mark_dead` returns whether the id transitioned into `CompletedOnChain`,
  which is what gates the push; no separate "already broadcast" set is needed.
- `mark_dead` is monotonic: `CompletedOnChain` is never downgraded to `Other`.
  Without this the feature silently disables itself, because a task that exits
  on its own just after `handle_completion` retired the id runs `retire_task`
  a second time through `handle_task_exit`. The regression downgrade above is
  the one deliberate exception and goes through its own path, not `mark_dead`.
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
    An `Other` id keeps today's silent drop. The reply must not block the
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
- **Broadcasting.** `handle_completion` sends the same notice to every other
  participant, once, when the id transitions to `CompletedOnChain` and we were
  tracking the request. Both triggers build the message through one
  `fn completed_notice(sign_id, presignature_id, round) -> PositMessage`, so
  there is a single definition of what a notice is.
  - Only on the transition, so a duplicate respond event or a checkpoint replay
    does not re-broadcast.
  - Only for requests in `self.requests`, which keeps a catchup replay of old
    respond events quiet and bounds the traffic to requests we participated in.
  - The unsolicited notice has no attempt to point at, so it carries
    `presignature_id: 0` and `round: 0`. Zero is the only safe round: a
    receiver that buffers a message for a future round sets
    `highest_seen_round` from it, and round 0 can never raise that, nor
    displace a live mailbox slot (the mailbox only overwrites on a round `>=`
    the one it holds).
  - Sent with the same `try_send`, to all participants without consulting the
    mesh: the outbox already retries unreachable peers for `message_timeout`
    and then gives up.
- Observability, because a straggler that never reaches quorum is otherwise
  invisible: log each new distinct report at info with the running count
  (`2/4`), warn on quorum with the reporter set, and add two counters:
  `SIGN_COMPLETED_NOTICES_SENT` labelled `kind={broadcast,reply}` (the two
  triggers answer different questions and must be readable apart) and
  `SIGN_ENDED_BY_COMPLETED_QUORUM` labelled by chain, read off `SignEntry`
  before the request is dropped.
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
- The flag has to reach `handle_posit`, so the `signature_posit` subscriber
  payload carries it. That payload is already a six-tuple: replace it with
  `SignPositMessage` and add `request_completed` there instead of widening the
  tuple again. Only the spawner reads the field; the mailbox and the posit
  phases carry it and ignore it.

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
bytes on every posit message, including triple and presignature posits, plus
`n * (n - 1)` notices per completed request from the push (56 messages of
roughly 60 bytes at 8 nodes, batched into the partitions the outbox already
sends, against kilobytes per peer for the signing protocol itself). Folding
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
- **The push cannot make anything worse than not sending it.** A notice for an
  id the receiver does not track is dropped, a notice that loses the race
  against the receiver indexing the request is simply not counted, and a
  duplicate from the same sender collapses in the report set. Every one of
  those outcomes leaves the pull path exactly where it was.
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
  ends its task on `f + 1` independent copies of that same observation. `f + 1`
  guarantees one honest reporter, not a majority of honest reporters, so a
  single honest node with a broken indexer can still end a live task with `f`
  liars behind it. Demanding a majority means `2f + 1` reports, which is 7 of 8
  at the deployed parameters and would be blocked by any two nodes being down.
  One honest remote observation for what a node already accepts from one local
  observation is the consistent choice.
- **A wrongly ended task is recoverable.** Termination only drops in-memory
  state, so the requeue path (`take_requeueable_requests` after a catchup, or a
  re-index after a regression) delivers the request again, and `add_request`
  clears the dead tag as it re-admits it.

## Tests

Four, each pinning something that would otherwise break silently.

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
3. **Push fan-out and its transition rule** (`request/mod.rs`): one
   `handle_completion` for a tracked id puts one notice per other participant in
   the outbox, each carrying the flag and round 0; a second `handle_completion`
   for the same id, and a `handle_completion` for an id we never tracked, put
   nothing there. Without the transition rule a replayed respond event
   re-broadcasts on every catchup, which is the kind of thing that is only
   noticed in production.
4. **Wire compatibility** (`message/crypto.rs`): extend
   `test_posit_stale_round_field_is_wire_compatible` to carry
   `request_completed` alongside `stale_round` and rename it for both fields,
   rather than copying thirty lines for a second one. It already asserts the
   property that matters in both directions: a batch decodes on a node that does
   not know the field, and a batch without the field decodes as the default.
   This is the one failure mode that only shows up during a deploy, so it is
   worth the test even though the pattern is proven.

Tests 1 to 3 need the spawner fixture that
`test_abort_chain_dead_ids_lifecycle` builds inline today; extract it into a
`fn test_spawner(...)` helper rather than copying fifty lines three times.
Test 3 also needs the outbox interception the posit tests already use
(`MessageOutbox::intercept_outgoing_messages`).

Not worth writing: an integration test (cannot run here, Docker is x86_64 and
unavailable, and it would only re-cover the unit-tested logic), separate
proposer and deliberator variants of test 1 (one code path now), a separate test
for the pull path's message contents (test 2 already reads it), and any test
asserting a metric increments.

## Limits

- **A straggler that misses the push waits for its own next proposal.** With
  the task alive when the push goes out, termination is immediate. Otherwise it
  falls back to pull, and a straggler only draws replies in rounds where it
  proposes: the proposer rotates as `(entropy[0] + round) % n`, so it proposes
  once every `n` rounds, and with eight nodes at the 600s round ceiling that is
  up to about 80 minutes. Worse, it has to get that far at all: `OrganizingPhase`
  gives up before proposing when no presignature can be reserved or no proposer
  slot is free (`MAX_CONCURRENT_PROPOSERS`), so a starved straggler is
  unanswerable by pull alone. That case is exactly what the push covers, and it
  is the reason both paths exist.
- **The incident that motivated this is a pull case, not a push case.** In #891
  the node restarts, recovers from a checkpoint older than the respond event and
  misses that event during catchup. The push went out while it was down, so the
  notice is gone and only the pull path can end that task. Do not expect the
  push to shorten that particular scenario.
- **The pull evidence expires.** `MAX_DEAD_IDS = 4096` LRU eviction and peer
  restarts both wipe the dead-id tag, after which peers go back to dropping
  silently and an old straggler never reaches `f + 1` by asking. The push does
  not depend on the cache at all, it fires at completion time, so only the
  fallback path degrades.
- **Fewer than `f + 1` observers, no effect.** If a catchup gap made most
  indexers miss the respond event, the request rotates as it does today.

## How we will know it works

`SIGN_ENDED_BY_COMPLETED_QUORUM` going above zero on devnet is the signal that a
straggler was ended by peers rather than by its own indexer, and
`SIGN_COMPLETED_NOTICES_SENT` split by `kind` shows which of the two paths is
carrying it: `broadcast` should be steady with request volume, `reply` should be
near zero and spike only when a node is genuinely behind. The check that
matters is the one from #891 and #829: sign ids that used to rotate for hours
after the response landed should stop doing so.

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
- **A dedicated `Message` variant for the notice**: reads better than a reject
  with a flag, and fails on not-yet-upgraded nodes for the same reason a new
  `PositRejectReason` variant does, only worse, since it drops partitions on
  every node rather than the few that get a reject.
- **Buffering notices for sign ids we do not track**, so a straggler that
  indexes the request after the push still counts them: needs a size-capped
  cache keyed by an id a peer chooses, and buys nothing. A node whose indexer is
  merely lagging sees the request and then the respond event in order and never
  becomes a straggler; the node that does become one indexed the request first
  by definition, so its task exists when the notice arrives.
- **Pushing from one node instead of all `n`**: a straggler needs `f + 1`
  distinct reporters, so a single broadcaster cannot end anything on its own,
  and picking which node broadcasts would add coordination to save 3KB.
- **Clearing all of `dead_ids` on a chain regression** instead of downgrading
  the affected entries: simpler, but late posits for unaffected chains would
  start recreating orphan mailboxes, which is the leak `dead_ids` exists to
  prevent.
- **Removing the backlog entry on quorum**: makes the termination survive a
  restart, at the price of deleting a locally pending request on peer testimony
  alone.
