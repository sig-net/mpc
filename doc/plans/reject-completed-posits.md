# Ending straggler sign tasks with a `completed` reject

## Problem

When a node finishes a sign request, the id goes into `dead_ids` and every late
posit message for it is dropped in silence
(`SignatureSpawner::handle_posit`). A node whose indexer missed the respond
event keeps rotating rounds for that request: it proposes, nobody answers, it
times out, it bumps the round, round timeouts grow towards the 600s ceiling.
Nothing ends the task until that node's own indexer reports the completion,
which is exactly what fails in the lingering-signId incidents (#891: the Solana
indexer misses respond events during catchup after a restart).

## Approach

A node that knows a request is already answered on chain replies to a straggler's
`Propose` with a reject carrying a `completed` flag. The straggler ends its task
once `f + 1` distinct participants have told it so, where `f = n - threshold`
(8 nodes, threshold 5 => f = 3, so 4 reports). `f + 1` guarantees at least one
honest reporter, so `f` colluding nodes cannot kill an honest task. The same
arithmetic already appears in `SinglePositCounter::enough_rejects`, which fires
at more than `n - threshold` rejects.

Decisions taken up front:

- **Only chain-observed completions license the reject.** An id is eligible only
  if it was retired via `SignCommand::Completion`, i.e. our own indexer saw the
  respond event on chain. Local generation success is not enough: publishing can
  still fail (#1063 has no publish failover), and the straggler rotating on is
  then the only remaining path to a signature.
- **The straggler ends its task in memory only.** The backlog entry is left
  alone. A restart plus catchup requeue re-drives the request and the same
  mechanism ends it again a round or two later.
- **The flag is an optional message field, not a new enum variant.** See the
  wire-format section.
- **Counting happens in the posit phases only.** Generation is not aborted.

## Changes

### 1. Tag why a sign id is dead

`chain-signatures/node/src/protocol/request/mod.rs`

- `dead_ids: LruCache<SignId, DeadReason>` with
  `enum DeadReason { ChainCompleted, Retired }`. `retire_task` takes the reason:
  `handle_completion` records `ChainCompleted`; task exits (`Ok`, `Err(Aborted)`,
  interrupted) and `AbortChain` record `Retired`. The regression case matters: a
  rolled back chain must never make peers claim the request is answered.
- `handle_posit` takes `&GovernanceInfo` (already in scope in the select loop).
  For a `ChainCompleted` id and an incoming `Propose`, reply to the sender with
  `RejectWithReason(Unknown)` plus `completed: Some(true)`, with the id echoing
  the sender's `(sign_id, presignature_id, round)` — the same "the id is an
  address, not content" convention as the `StaleRound` reply. Accept, Reject and
  Start are never answered: replying to a reject ping-pongs between nodes.
  `Retired` keeps today's silent drop.
- The reply must not block the spawner select loop: clone the `MessageChannel`
  and `tokio::spawn` the send instead of making `handle_posit` async.

### 2. Wire format

`chain-signatures/node/src/protocol/message/types.rs`, `.../inbox.rs`

- `PositMessage` gains
  `#[serde(default, skip_serializing_if = "Option::is_none")] completed: Option<bool>`.
- The `signature_posit` subscriber payload is already a six-tuple; carry
  `SignPositMessage` through it instead of widening the tuple.
  `SignPositMessage` gains `completed: bool`.

Why a field and not a `PositRejectReason::Completed` variant: the outbox groups
per-peer messages into 256kb partitions, CBOR-encodes each partition as one
`Vec<Message>`, and the receiver decodes it all-or-nothing
(`cbor_from_bytes::<Vec<Message>>`). An unknown enum variant fails the whole
vector, so a not-yet-upgraded node would drop every message in that partition,
including unrelated triple/presignature/generating traffic. During a rolling
upgrade the nodes that are behind are precisely the ones being restarted, i.e.
the likely stragglers, so a variant misfires exactly where it is needed. Serde
ignores unknown struct fields, so an optional field is compatible in both
directions; this is the same trick as `stale_round`.

### 3. Count reports and end the task

`chain-signatures/node/src/protocol/request/state.rs`, `.../posit.rs`

- `SignState` gains `completed_reports: HashSet<Participant>`, a
  `record_completed_report(from)` and a quorum check against
  `governance.participants.len()` and `governance.threshold`. Sender-deduped,
  round independent, accumulating across rounds within one task incarnation. A
  respawn resets it; peers re-send on the next `Propose`.
- Both posit loops record the report *before* any round filtering:
  `wait_for_propose` (which today `continue`s on every reject) and `advance`
  (which drops rejects for older rounds outright). A completion is a statement
  about the request, not about the attempt, so a report carried on a stale round
  still counts.
- On quorum, return `SignPhase::Complete(Err(SignError::CompletedElsewhere))`.
  `wait_for_propose` already returns `Err(SignPhase)`, so it drops straight out.
- `handle_task_exit` matches the new variant: a warn log naming the reporters, a
  counter labelled by chain, and retire with `DeadReason::Retired` — a node that
  ended on hearsay does not go on to repeat it as first-hand knowledge.
  `durations.emit` stays `Ok`-only so latency histograms are not polluted.

## Tests

- `SignState` quorum: `f` reports do not end the task, `f + 1` do; a duplicate
  sender does not count twice; reports spread over several rounds accumulate.
- `request/posit.rs`: a deliberator ends in `wait_for_propose`; a proposer ends
  in `advance`; a report carried on an older round still counts (this is the one
  that pins the ordering against the round filter).
- `request/mod.rs`: after `handle_completion` a `Propose` draws a reply and
  creates no mailbox; after `AbortChain` it draws nothing.
- `message/crypto.rs`: wire compatibility both directions, next to
  `test_posit_stale_round_field_is_wire_compatible`.
- Integration coverage can be written but cannot run on this machine (Docker is
  x86_64 and unavailable); say so rather than claim it passed.

## Limits

- Termination latency is bounded by proposer rotation: a straggler only draws
  replies in rounds where it proposes, so up to `n` rounds, and round timeouts
  grow towards 600s. A one-shot broadcast when an id is retired would fix this
  but is out of scope here.
- `MAX_DEAD_IDS = 4096` LRU eviction and peer restarts both wipe the evidence;
  after that peers silently drop again and an old straggler never reaches
  `f + 1`.
- If fewer than `f + 1` nodes indexed the respond event, nothing changes.

## Non-goals

No relaying of hearsay, no backlog changes, no changes to triple or
presignature posits, no aborting an in-flight generation.
