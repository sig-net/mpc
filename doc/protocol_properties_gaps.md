# Closing the gaps in `protocol_properties.md`

What the code still owes the properties in [protocol_properties.md](protocol_properties.md),
and how each item would be tackled. Code references are against `develop` at
`92108fc6`. Every gap below is one the properties doc already names; nothing here
is a new requirement.

| # | Gap | Property | Already bites under | Issue | Size |
|---|-----|----------|----------------------|-------|------|
| 1 | Publish has no failover and does not survive a restart | L3 | crash-recovery | [#1063](https://github.com/sig-net/mpc/issues/1063), [#837](https://github.com/sig-net/mpc/issues/837) | large |
| 2 | Redis persistence does not back D3's "durably" | D3 | crash-recovery | [#1008](https://github.com/sig-net/mpc/issues/1008), [#562](https://github.com/sig-net/mpc/issues/562) | small, operational |
| 3 | One peer can drive another node's round arbitrarily high | L1, D2 | malicious (or buggy) | unfiled | small |
| 4 | A respawned task runs round 0's budget at its carried round | L1 | crash-recovery | unfiled | trivial |
| 5 | Organizing waits for the active set with no timeout | L1 | crash-recovery | unfiled ([#876](https://github.com/sig-net/mpc/issues/876) adjacent) | small, needs a decision |
| 6 | Orphan posit mailboxes are unbounded | D5 | crash-recovery | unfiled ([#793](https://github.com/sig-net/mpc/issues/793) adjacent) | small |
| 7 | S1 rests on quorum intersection alone | S1 | crash-recovery | [#611](https://github.com/sig-net/mpc/issues/611) | medium |
| 8 | Epochs are separated by a best-effort wipe, not by the artifact's name | S1 | crash-recovery | unfiled ([#5](https://github.com/sig-net/mpc/issues/5) adjacent) | small |
| 9 | Sync reports per batch, not per peer | L4 | crash-recovery | [#658](https://github.com/sig-net/mpc/issues/658) | medium |

The fault model column says whether a gap already bites under §2's
crash-recovery model, with no adversary anywhere, or whether it needs a member to
misbehave. Only 3 needs one. Two of the other eight bite harder under f
corruptions as well, 6 because a peer can flood the map faster than a stalled
indexer leaks it, and 7 because quorum intersection is what covers the Byzantine
case that the binding would replace.

Ordered by importance, most important first. 1 is the only property the doc
declares broken and the only one that loses requests with no adversary present. 2
is nearly free and decides whether any persistence work below it survives a
container replacement, so it is worth settling before 1 is built. 3 is a liveness
attack reachable at f = 1, and 4 is a one-line fix on a path every committee change
takes. 5 needs its rotation question answered before code. 7 and 8 both change how
an artifact is named in storage and should be decided together, and 7 also carries
the fsync trade left open in 2. 9 costs latency only.

## 1. L3: settlement failover and restart survival

*Related: [#1063](https://github.com/sig-net/mpc/issues/1063) (has a proposed
design), [#837](https://github.com/sig-net/mpc/issues/837),
[#829](https://github.com/sig-net/mpc/issues/829),
[#1008](https://github.com/sig-net/mpc/issues/1008).*

**Now.** Every participant builds a `PublishState` and marks the request
publishing, but only the round's proposer submits
(`protocol/signature.rs:283-313`). The retry is infinite with 5 s to 60 s backoff
and lives in the publishing process only (`rpc/mod.rs:611`). After a catchup the
resume path skips non-proposers (`stream/ops.rs:73`), and late posits for the
sign id are dropped as dead (`protocol/request/mod.rs:271`). #1063 also records a
permanent-stall edge case: a node regressing to a peer's checkpoint adopts
`is_proposer: false`, so after the original proposer regresses nobody considers
itself the publisher.

Persistence is better than the properties doc currently claims, but only for some
chains. Backlog entries, including `SignStatus::PendingPublish { publish }` with
the full signature, are CBOR-encoded into checkpoints
(`backlog/mod.rs:108-144`) and production runs `Backlog::persisted(CheckpointStorage::Redis(..))`
(`cli/mod.rs:680`). That state reaches Redis only once a checkpoint is confirmed
(#1008), and NEAR and Bitcoin produce no checkpoints at all
(`primitives/src/chain.rs:23`). So for NEAR, the chain with the hard 200 s
deadline, a pending publish is purely in memory.

**Plan.**

1. Rank the participants by a pure function of shared inputs, as D2 requires: reuse
   `proposer_per_round(k, participants, entropy)` with `k` as the failover index,
   so rank 0 is the instance's proposer and no extra message is needed to agree on
   the order.
2. Arm a timer per holder of a `PendingPublish` entry at
   `indexed_at + (rank + 1) * delta`, cancelled by the respond event
   (`stream/ops.rs:process_respond_event` already removes the entry) or by a
   completion command. Anchor on the request's indexed timestamp, never on local
   task start, or a restarted node restarts the clock.
3. Make `delta` chain-scoped, derived from `expected_response_time_secs`
   (`primitives/src/chain.rs:61`). On NEAR the whole failover ladder has to fit
   inside 200 s, so `delta` there is roughly `200 s / n`, not a global constant.
4. Drop the `is_proposer` filter in `resume_pending_publish_requests`
   (`stream/ops.rs:73`) and replace it with the rank plus elapsed-time check, so a
   restarted node comes back as a candidate publisher rather than a bystander.
5. Persist the pending publish independently of checkpoints: write `PublishState`
   to Redis keyed by `sign_id` when the request is marked publishing, delete it on
   the respond event. This is what makes the property hold on NEAR, and it also
   kills #1063's regression edge case, since the record is local and not adopted
   from a peer's checkpoint.
6. Before enabling, confirm respond idempotence per chain. NEAR rejects a second
   respond with `RequestNotFound` (`contract/src/lib.rs:283`), so duplicates fail
   cheaply; the EVM contract emits a second event and the downstream consumer
   deduplicates (§1 step 6 of the properties doc); Solana, Canton, Midnight and
   Hydration each need the same check written down.

**Tests.** Unit test for the rank function (same order on every node, proposer
first). A `stream/ops_tests.rs`-style test where the proposer never publishes and
the rank-1 node does after `delta`. A test that a respond event observed before
the timer cancels it. A restart test that a persisted `PublishState` is republished
on startup without waiting for a checkpoint.

**Risks and decisions.** Duplicate responses cost gas and are an E-property
regression, which §5 says is acceptable, but only if idempotence is confirmed for
every chain first. The NEAR budget is the real constraint: with `delta` small
enough to fit the ladder into 200 s and L1's round ceiling at 10 minutes, a
request that spent its budget rotating proposers cannot be rescued by failover at
all. That interaction should be stated in the doc whichever way we implement it.

## 2. D3: make "durably" true, or say what it is worth

*Related: [#1008](https://github.com/sig-net/mpc/issues/1008),
[#562](https://github.com/sig-net/mpc/issues/562),
[#829](https://github.com/sig-net/mpc/issues/829).*

**Now.** `chain-signatures/node/redis.conf` sets `appendonly yes` (`:672`) with
`appendfsync everysec` (`:702`), so a host crash can lose up to a second of
acknowledged deletes, which is exactly the resurrected-share case S1 warns about.
Its `dir` is `/etc/redis` (`:263`), inside the container image, while the partner
templates mount the host volume at `/data`
(`infra/partner-mainnet/main.tf:21-27`, `:108-115`), so a container replacement
starts from an empty store. Losing artifacts is allowed by D3; losing the backlog
and checkpoints in the same store is what #1008 and #829 are about.

**Plan.**

1. Point `dir` at the mounted path so artifacts, backlog checkpoints and the
   secret store survive container replacement, and confirm the mount path in the
   Dockerfile matches what the templates mount.
2. Decide on `appendfsync`. `always` makes S1's crash argument sound at a per-write
   fsync on the artifact hot path. `everysec` keeps current throughput and leaves a
   one second window. Item 7 changes this trade: with a binding record written in
   the same script as the delete, a resurrected pair is caught at the second take,
   so `everysec` becomes defensible. Decide 2 and 7 together.
3. Whatever we pick, write it into D3 rather than leaving "durably" unqualified,
   and verify on a running node (`redis-cli CONFIG GET appendfsync dir`).

**Tests.** None in-repo. This is a deployment check, so it belongs in whatever
runbook covers node bring-up.

## 3. L1, D2: the round a node adopts is peer-supplied and unchecked

*Not filed. Found by a code-checked review of the properties doc, 2026-08-12.*

**Now.** A posit message whose round is above the local one is buffered before
anything about it is validated (`protocol/request/posit.rs:98-105`), ahead of both
the `PositAction::Propose` check at `:108` and any check of who sent it.
`buffer_future_posit_message` records the claimed round in `highest_seen_round`
(`protocol/request/state.rs:101-110`), and `bump_round` then advances to
`max(round + 1, highest_seen_round)` (`:80-88`). `record_peer_round`, fed by
`StaleRound` rejects, takes the same unchecked path (`:92-99`).

So one committee member, Byzantine or merely buggy, can send a posit stamped with
any round it likes and move a victim there on its next bump. Two consequences:
`round_timeout` jumps to the 10 minute ceiling, and proposer election, which is
`(entropy[0] + round) % n`, becomes attacker-selectable. That is a liveness attack
at f = 1 against an L1 that only assumes ≥ t correct members, and it is reachable
without breaking any safety property. The comment at `:96` shows the immediate-jump
case was considered; the next-bump case was not.

**Plan.**

1. For a Propose, the receiver can check the sender itself: `proposer_per_round` is
   a pure function of shared inputs (D2), so reject any Propose whose sender is not
   the elected proposer for the round it claims, before buffering it.
2. For `StaleRound` rejects, the rejector's round cannot be checked directly, so
   require evidence: adopt a higher round only once f + 1 distinct senders have
   claimed at least it. One of them is then honest, which is the same amplification
   argument the fault bound already rests on. Keep the current one-slot-per-sender
   buffer so the evidence set costs nothing extra to maintain.
3. Cap the per-bump jump as a backstop, so a bug on the evidence path degrades to
   slow catch-up rather than a jump to the ceiling.

**Tests.** A task-level test where a non-proposer sends a Propose for round 10^6 and
the victim's round is unchanged. A test that f + 1 `StaleRound` rejects do move the
round, and that f do not.

**Risks.** Step 2 slows genuine catch-up when fewer than f + 1 peers have rejected,
costing a round. That is the same cost D4 already accepts on retry, and it is
bounded, unlike the current behaviour.

## 4. L1: a respawned task runs round 0's budget

*Not filed. Found by a code-checked review of the properties doc, 2026-08-12.*

**Now.** `SignState::new` restores `round` from the carried counter but sets
`budget: TimeoutBudget::new(round_timeout(0))` unconditionally
(`protocol/request/state.rs:38-48`). A task respawned at round 9 therefore runs a
20 s budget while its peers run `round_timeout(9)`, roughly 6 s. `spawn_tasks`
respawns every retained request on any committee change, so this is a normal path,
not a rare one. It contradicts L1's "peers in the same round agree on the proposer
and the deadline", which is what makes rotation converge.

This is the other half of [#1100](https://github.com/sig-net/mpc/pull/1100): the
round was carried across respawns, the budget derived from it was not.

**Plan.** Use `round_timeout(round)` for the initial budget, with `round` the value
just loaded from the carried counter.

**Tests.** Construct a state with a carried round above zero and assert the budget
matches `round_timeout(that round)`.

**Risks.** None beyond the fix being correct: a respawned task at a high round now
gets the same short budget as its peers, which is the intent.

## 5. L1 caveat (i): bound the wait for the active set

*Related: [#876](https://github.com/sig-net/mpc/issues/876),
[#814](https://github.com/sig-net/mpc/issues/814),
[#892](https://github.com/sig-net/mpc/issues/892). Not filed on its own; it should
be.*

**Now.** `wait_for_active_participants` (`protocol/request/organize.rs:25-58`)
loops on `mesh_state.changed()` with no timeout of its own and never consults
`state.budget`. A failure detector that is wrong in the pessimistic direction
stalls the request for as long as it stays wrong, which contradicts L1's "within
bounded time" and makes the stall invisible to the round metrics.

**Plan.**

1. Wrap the wait in `tokio::time::timeout(state.budget.remaining(), ..)` and, on
   expiry, return `state.reorganize("no active participants")`, which bumps the
   round and resets the budget.
2. Do not let that path spin: for `r >= 1` the schedule's floor already keeps a
   round at 2 s or more, so the bump rate is bounded, but the existing "waiting for
   enough active participants" log should stay rate-limited.
3. Distinguish "peers are Syncing" from "peers are gone". If the shortfall is
   covered by peers in `need_sync` (`mesh/state.rs:12`), waiting is the right
   behaviour and rotating only wastes proposer slots. A cheap rule: bump only when
   the active set is short of t and no peer is in `need_sync`.

**Tests.** A task-level test with a mesh watch channel that never reaches t,
asserting the phase returns to `Organizing` with an incremented round inside the
budget instead of hanging.

**Risks and decisions.** This is the item that needs a decision before code.
Rotating while the network is genuinely down burns rounds and pushes
`round_timeout(r)` toward the 10 minute ceiling, so the request is then slow to
recover once the network returns. Options: cap the round that the organizing
timeout alone may drive the request to, or reset the round when the active set
recovers to t. Both need to keep D2 intact, so any reset rule must be a function
of shared inputs and not of the local failure detector.

## 6. D5: bound the orphan posit mailboxes

*Related: [#793](https://github.com/sig-net/mpc/issues/793),
[#892](https://github.com/sig-net/mpc/issues/892),
[#864](https://github.com/sig-net/mpc/issues/864),
[#873](https://github.com/sig-net/mpc/issues/873),
[#1105](https://github.com/sig-net/mpc/issues/1105). Not filed on its own.*

**Now.** `posit_mailboxes: HashMap<SignId, Arc<PositMailbox>>`
(`protocol/request/mod.rs:131`) gains an entry for any sign id a peer sends a
posit for, as long as it is not in `dead_ids` (`:271`), and loses one only in
`retire_task` (`:346`). A sign id that is never indexed therefore never retires.
Each mailbox is itself bounded (one slot per sender), so the leak is in the number
of mailboxes, and a single committee member can grow it at will. `dead_ids` is the
only capped structure here (`MAX_DEAD_IDS = 4096`, `:111`).

Buffering posits for not-yet-indexed requests is deliberate and S2 depends on it:
a Propose that arrives before this node's indexer delivers the request must not be
answered, but must still be there when the task spawns. The fix has to keep that.

**Plan.**

1. Split the map by whether the sign id is live. Keep `posit_mailboxes` for ids
   with an entry in `requests`, and add
   `orphan_mailboxes: LruCache<SignId, Arc<PositMailbox>>` with a cap
   (`MAX_ORPHAN_MAILBOXES`, 1024 is a reasonable start) for ids not yet indexed.
   `lru` is already a dependency (`:20`).
2. `handle_posit` routes to the live map when `requests.contains_key(&sign_id)`,
   otherwise `put`s into the LRU, which evicts the stalest orphan.
3. `spawn_task` pops the orphan mailbox if present, otherwise creates a fresh one,
   then installs it in the live map. This preserves the pre-index buffering.
4. `retire_task` removes from both.
5. Add a gauge for orphan mailbox count and a counter for evictions, so devnet
   shows whether the cap is ever reached.

**Tests.** Feed `MAX_ORPHAN_MAILBOXES + 1` distinct unknown sign ids and assert the
map stays at the cap. Assert a Propose that arrives before the indexed request
still reaches the spawned task (regression guard for S2's buffering path).

**Risks.** Under a flood, eviction can drop a legitimate early Propose, costing
that node one round; D4 already covers that, since the proposer retries in the
next round. The cap must comfortably exceed the realistic in-flight request count,
so size it against the observed queue depth rather than guessing.

## 7. S1 hardening: bind a presignature to its first sign id

*Related: [#611](https://github.com/sig-net/mpc/issues/611),
[#793](https://github.com/sig-net/mpc/issues/793).*

**Now.** Consumption is delete-on-first-use inside one Lua script
(`storage/protocol_storage.rs:615-637`), and S1 leans on quorum intersection to
rule out two disjoint honest holder sets. That argument has no margin at n = 3 and
exactly one honest node at n congruent 1 mod 3. A share resurrected by a crash
inside the fsync window (item 2) or by a restored backup is served honestly a
second time.

**Plan.**

1. In the same script as the take, write `presig:consumed:<presignature_id> -> sign_id`
   with a TTL longer than the longest window in which the request can still be
   retried.
2. Make the take fail when the record exists with a different sign id. The
   deliberator's `contains` check (`protocol/request/posit.rs:95`) should consult
   it too, so the refusal surfaces as a `MissingArtifact` reject in the posit
   round rather than as a missing share during generation.
3. Plumb `sign_id` into `PresignatureStorage::take`, which today takes only
   `(id, owner)`.
4. Keying on the sign id rather than a plain "consumed" flag is what keeps D4's
   retry-fresh rule working: a retry of the same request that re-picks the same
   presignature must still succeed.

**Tests.** Storage-level test that a second take under a different sign id fails
while a retry under the same sign id succeeds, plus a test that the record expires.

**Risks.** One small Redis key per consumed presignature until the TTL expires. The
TTL is the only real parameter: too short and the guarantee lapses while a request
can still retry, too long and the keyspace grows. A fixed generous value (one hour)
is simpler to defend than deriving it from the round schedule.

## 8. S1: separate the epochs by name, not by a best-effort wipe

*Related: [#5](https://github.com/sig-net/mpc/issues/5), which asks for
epoch-partitioned triple storage for a different reason (serving requests from the
old pool while a resharing runs). Not filed on its own.*

**Now.** An artifact's keys are `<kind>:<version>:<account_id>`
(`storage/protocol_storage.rs:242-245`), with no epoch anywhere in them, so nothing
in a stored artifact's name says which sharing produced it. What separates one
epoch from the next is `ResharingState::try_finalize`, which calls
`triple_storage.clear()` and `presignature_storage.clear()` after the new secret
share is stored (`protocol/cryptography.rs:386-392`). Both calls are best-effort: a
failure is logged at error level and finalization proceeds into the new epoch, with
nothing retrying it and nothing re-checking at the next startup. The failure is
also quiet, since a resharing keeps the public key (`:377`), so a surviving
artifact looks like any other to every check that exists today.

**Plan.**

1. Put the epoch into the storage prefix, so an artifact from a previous sharing
   cannot be named in the new epoch and the wipe becomes cleanup rather than a
   correctness step. This is the direction #5 already wants.
2. Failing that, retry the wipe and re-run it at startup, so a node that crashed
   between storing the secret and clearing the pools converges instead of carrying
   the old pool forward indefinitely.

**Tests.** Storage-level test that a take under epoch e+1 cannot see an artifact
written under epoch e. A `try_finalize` test where `clear` fails and the node still
ends up unable to serve the old artifacts.

**Risks.** Option 1 changes the key layout, so a node that upgrades mid-epoch
starts from an empty pool and refills by L2, costing a supply dip and nothing else.
Refusing to finalize a resharing until both pools report cleared is the obvious
third option and the wrong one: what a stale artifact costs is aborts and wasted
rounds, so stalling a resharing on a Redis failure trades a liveness problem for a
worse one.

## 9. L4: report sync results per peer

*Related: [#658](https://github.com/sig-net/mpc/issues/658),
[#482](https://github.com/sig-net/mpc/issues/482),
[#814](https://github.com/sig-net/mpc/issues/814).*

**Now.** The sync task holds a single broadcast handle
(`protocol/sync/mod.rs:175`), skips the 200 ms trigger while one is in flight
(`:177-181`), and processes results only once the whole batch has finished
(`:205-215`). `broadcast_sync` collects into a `Vec` under `BROADCAST_TIMEOUT`
(120 s, `:27`, `:349-405`). A fast peer therefore activates at the slowest peer's
pace, and a peer that becomes reachable just after a batch starts waits for the
next one, which is where the doc's "roughly two `BROADCAST_TIMEOUT`s" comes from.

**Plan.**

1. Change `broadcast_sync` to send `(Participant, SyncPeerResponse)` into an mpsc
   as each task completes, keeping the `JoinSet` and the deadline for aborting
   stragglers.
2. Split `process_sync_responses` (`:269`) into a per-peer
   `process_sync_response(peer, result)` and call it from the sync task's select
   loop as results arrive. The mesh notification (`synced_peer_tx`) then fires at
   the peer's own round-trip.
3. Replace the single `broadcast` slot with a set of in-flight peers, so a newly
   `need_sync` peer starts its sync on the next 200 ms tick instead of waiting for
   the current batch. Cap concurrency at n, which is the natural bound.

**Tests.** Extend the existing sync tests with one where a slow peer and a fast
peer are synced together and the fast peer is reported while the slow one is still
outstanding.

**Risks.** More concurrent `remove_holder_and_prune` work against Redis, bounded
by n, which is small. Ordering of mesh notifications changes, so anything that
implicitly assumed batch order (nothing found so far) needs a second look.

## Note on L3's persistence wording

An earlier draft of L3 said "nothing about a pending publish is persisted". That
holds for NEAR and Bitcoin, which produce no checkpoints
(`primitives/src/chain.rs:23`), but not for the other chains, where the backlog
entry including the signature is CBOR-encoded into checkpoints stored in Redis
(`backlog/mod.rs:108-144`, `cli/mod.rs:680`), subject to the confirmation caveat in
[#1008](https://github.com/sig-net/mpc/issues/1008). The properties doc now names
that split, which is why plan item 1 step 5 writes the publish record outside the
checkpoint path: it is the only way NEAR gets restart survival.
