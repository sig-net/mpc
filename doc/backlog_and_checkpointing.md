# Backlog and checkpointing

## Scope

The backlog is the node's durable record of requests it has observed on a
source chain and whose final response, a plain signature or a bidirectional
response, is not yet finalised there. One map per source chain.
Checkpointing keeps those maps in sync across restarts without silently
diverging, and lets a joining or rejoining node catch up without replaying
every block.

Approach. Checkpoints are due at fixed heights, the same grid for every
node. A node reaching one votes in the governance contract for a digest of
its backlog there, and the contract settles that height once f+1 nodes have
voted for the same digest, enough that at least one correct node holds the
body behind it. Every node polls for what settled. A node that derived that
digest itself carries on indexing; any other fetches the body from a peer
and installs it, and everything it derives from then on hangs off that
checkpoint.

A node that has passed the height under vote and sees nothing settle there
reads the vote counts, on a growing backoff. If 2f+1 have voted with nothing
settled, it throws away everything it derived above the checkpoint it holds
and indexes that stretch again, on the chance that its own reading of a
block was the odd one.

This is a design doc. Section 7 says what it would take to get there.

## 1. Background

The network is n nodes, at most f < n/3 faulty, in a crash-recovery model:
correct nodes may crash, restart and act according to the protocol, and
faulty nodes may deviate from it arbitrarily. Protocol upgrades, committee
and threshold changes.

A correct node is told the truth by its RPC provider, and keeps up: it indexes
faster than the chain produces blocks, so it reaches the tip from wherever it
starts. The governance chain is assumed live and readable throughout, so a
node that cannot see a settlement or get a vote recorded is a node with its
own problem rather than a network without a contract.

Vocabulary, per node per source chain:

* **Watermark**: the height the cursor has reached, inclusive. Installing a
  checkpoint may move it, back or forward.

* **Backlog**: one *entry* per request admitted and not finished, holding the
  request id as its key, the request as the chain gave it, the contract that
  made it, and `signature_finalized`, true once the first call of  `Respond`
  for it has been finalised on the source chain, never when this node merely
  finished signature generation or published one. Nothing else, and every field a
  fact about the source chain. 

* **Boundary**: a height at which a checkpoint is due, the chain's start
  height plus a multiple of a constant interval, whether or not a block is
  delivered there. Both are per chain, and every node computes the same grid
  from them.

* **Checkpoint**: a height and the backlog at that height. Its *digest* binds
  the chain, the height and the entries over a canonical encoding (section 2).

  * **Open height**: the one height a vote may be cast at, the first
    boundary above the settled height. The node's is measured from the
    checkpoint it holds and the contract's from the settlement it has
    recorded, and the two differ for a node that has not polled since a
    settlement. Unqualified, it is the node's.

  * **Settled**: a digest the governance contract has fixed for a height.

  * **Installed**: a node has made a settled checkpoint its base, durably,
    so that every backlog it derives from then on descends from that one.

  * **Genesis checkpoint**: an empty backlog at the chain's start height,
    which the contract holds.

## 2. Digest and interfaces

### The digest

```
digest(height, backlog) = H(
    chain
    height
    for each entry, in request id order:
        request id
        request
        contract
        signature_finalized
)
```

Encoding for digest must be canonical so it's one byte string per checkpoint,
no two checkpoints reaching the same one. Request id order is design rather
than encoding: insertion order is node-local, and a digest taken over it
would differ between nodes holding the same backlog.

### Governance contract

```
vote_checkpoint(CheckpointDigest)      // carries chain, height and digest
  // accepts votes for the open height, overwriting this node's previous one

latest_checkpoint(chain) -> CheckpointDigest

checkpoint_votes(chain) -> (height, [node: (digest, count)])
  // the contract's open height, the votes there, and how many times each
  // node has voted at it
```

The contract is the only writer of settled checkpoints. It settles a height
when one digest reaches f+1 votes, settles it at most once, and its settled
height never decreases. One vote per node per height, a later one replacing
the earlier and counted. The count is a diagnostic and gates nothing: a node
barred from a height after too many votes would have no way back in.

Settling a checkpoint requires a threshold of f+1 to guarantee that at least
one correct node holds the checkpoint. Guaranteeing a majority of at least
f+1 *correct* nodes hold a settled checkpoint needs a threshold of 2f+1,
which makes settling under a buggy non-deterministic implementation harder,
needing more nodes to have reached the same backlog for a given height.

### Peer

```
get_checkpoint(chain, height, digest) -> Checkpoint
  // reply with the Checkpoint matching the chain, height and digest, if
  // available locally
```

## 3. Properties, per source chain

### Safety

**S1 Agreement.** The backlog at a height is a deterministic function of the
newest checkpoint the node has installed and the finalised blocks since, so
correct nodes at a height hold the same backlog.

**S2 Validity.** A digest the contract settles at a height is one a correct
node derived at that height from the settled checkpoint below it, so the
settled checkpoints are a chain back to genesis and every entry a node acts
on was read from finalised chain state by a correct node.

**S3 Containment.** A node acts and votes only inside a window around what
the network has agreed.
(i) It neither acts on a source chain's backlog nor votes there while it is
missing the backlog of the newest settled checkpoint it has read from the
contract (thus the poll period defines how stale that reading can be).
(ii) It acts and votes only within a bounded distance of the newest
checkpoint it has installed, and at that bound it does neither, until it
installs a newer one or starts again from the one it has.

### Liveness, during a long-enough synchronous interval

**L1 Settlement.** Checkpoints keep settling, as long as f+1 correct nodes
reach the next checkpoint height, agree there, and can store what they vote
for.

**L2 Convergence.** A node whose backlog disagrees with a settled checkpoint
finds out at the next settlement it sees, and ends up holding a settled
backlog and indexing on from it, given a reachable node holding one. 

## 4. Design

Described for one node, one source chain. `commit` is a single durable
write, so an install cannot leave `base` replaced and `voted` not, or the
other way round. `acted_through` is neither, and an install leaves it where
it is.

The backlogs recorded in `crossed` and `voted` are snapshots, not the
live map, so what was hashed is what is still there. Serving
`get_checkpoint` is outside all of this and waits for none of it, which is
what serving snapshots allows.

Base and cursor. The node indexes the chain with a watermark cursor, which
holds the backlog the node acts on and records at every boundary it crosses
the digest it derived there and the backlog behind it. The `base` is the
settled checkpoint it indexes from, replaced when polling the contract shows
a newer one. Its body comes from what the cursor recorded, from the body
behind a digest the node voted, or from a peer.

Cap: how many boundaries beyond the base a node derives before it waits,
which is `len(crossed)`. It is
how far the network will go on signing from state nobody has agreed to, and
only incidentally a bound on what `crossed` holds. One block crossing
several boundaries takes it past the cap, and the cursor stops on the next
block rather than at an exact count.

Note that signatures and attestations a node produces are persisted too, 
however, they don't need to be in the backlog, therefore we don't talk about
them in detail here. 

### Per-chain Node State

```
persistent:
    base             (Height, Digest, Backlog)   // from governance contract
    voted            {Digest -> Backlog}         // every digest we have voted
                                                 // at the open height, held
                                                 // until that height is
                                                 // installed
    acted_through    Height                      // acting (signing, attesting, 
                                                 // publishing) is done up to 
                                                 // and including this height

in memory:
    backlog       RequestId -> Entry          
    watermark     Height
    crossed       Height -> (Digest, Backlog)    // checkpoints above base
    want          (Height, Digest)?              // a settled checkpoint we
                                                 // have read and do not
                                                 // hold; unset on start, so
                                                 // a crash lifts the hold
```

### Event Handlers

```
on start:
  rebase()
```
Governance contract polling
```
on settlement poll period expiry:
  h, d = contract.latest_checkpoint(chain)
  if h == base.height:
    rebase_if_stuck()
    return
  body = crossed[h].backlog if crossed[h].digest == d else voted[d]
                                // a digest binds its height, so voted cannot
                                // answer for the wrong one
  if body is none:
    want = (h, d)               // S3(i): the cursor stops until we hold it
    return                      // asking peers is section 2's get_checkpoint
  install(h, d, body)
```
Interacting with peers
```
on receiving a peer's reply (h, d, backlog) to what we asked for:
  if want == (h, d) and digest(h, backlog) == d:
    install(h, d, backlog)
```
Indexing
```
on block b finalised, the next one above the watermark:       //indexing
  if want is set or len(crossed) >= CAP:
    return                           
  for each boundary B with watermark < B < height(b):
    crossed[B] = (digest(B, backlog), backlog)   // nothing between the
                                     // watermark and B changed the backlog,
                                     // or that block would be this one
  backlog.update(b)                  // add/change/remove entries, idempotent
  watermark = height(b)
  if height(b) is a boundary:
    crossed[height(b)] = (digest(height(b), backlog), backlog)
  if a boundary was crossed:
    vote_if_ready(open height)
  if watermark > acted_through:
    act on backlog                 // Sign, watch, attest, publish
    acted_through = watermark      // and not repeated over a replay
```

No two handlers run their bodies at once, and none runs against itself.

A boundary is not a block. Where only blocks carrying requests or responses
are delivered, the cursor can go from 119 to 500 with 120 a boundary nobody
observed, so a checkpoint is recorded at the boundary and never at the block
that crossed it. The backlog to bind there is the one in hand: a block
between the watermark and the boundary that changed the backlog would have
been delivered before this one. That is why a skipped boundary is recorded
before the block is applied and a delivered one after.

`backlog.update` changes state and nothing else; effects (signing,
publishing, attesting) only happen later if at all.

`acted_through` is written lazily, so it is a lower bound: a crash loses the
last of it and the replay acts twice, which is the case the destination
already has to absorb. It is not reset by a `rebase`, a rebase being about
what the node believes rather than what it has already done.

Instead of `len(crossed) >= CAP` and `watermark > acted_through` alternative
conditions can be defined without changing the properties materially.

### Rebase and install

```
rebase():
  backlog, watermark = base
  crossed = {}                     // which also puts the cap back under its
                                   // bound
```
```
install(h, d, body):
  mine = crossed[h].digest == d // the cursor derived it this run
  base = (h, d, body) ; voted = {} ; commit
                                // one write: a crash partway would leave the
                                // old base with no body for what we voted,
                                // and the f+1 holders one short
  want = none                   // in memory, so outside the write
  if mine and watermark > h:    // only the cursor's own reading lets it keep
    crossed.remove_below(h+1)   // remove entries no longer needed
    vote_if_ready(open height)  // open height moved with h
  else:                         // read h differently, or has not reached it
    rebase()
```
```
rebase_if_stuck():
  if not crossed[open height]:   // still replaying towards it, so we have no
    return                       // vote there and a rebase would only lose
                                 // the replay
  if backoff not met yet: return // prevent spinning
  increase backoff for this height
  if contract.checkpoint_votes() shows 2f+1 voted with nothing settled:
    rebase()
```

The tally is read for one thing, 2f+1 having voted with nothing settled. In
model that cannot happen, since correct nodes agree and f+1 of them settle a
height, so seeing it means several nodes read the chain differently and this
one rebases on the chance that it is among them and rebasing may help. 
The tally is not scrutinized to find a
digest worth rebasing towards: at f+1 such a digest has settled by the time
we could see it, and the node learns it is wrong from the settlement poll
finding the settled digest is not the one it recorded.

Who it serves is the node whose reading of a block is not reproducible.
Crossing the open height is what makes a node vote, and absent a settlement
a rebase is the only thing that makes it cross again, so without this a
second reading never reaches the contract and a flaky network never takes a
second draw. Where readings are reproducible it re-derives the same digest
and re-casts the same vote, and the backoff is what makes that cheap.
### Voting

```
vote_if_ready(h):
  if h is not our open height: return  // a vote above it is one we cannot
                                       // justify, having not installed what
                                       // is below; the contract separately
                                       // rejects a vote at any height but
                                       // its own open one
  d = crossed[h].digest
  if d is none: return                 // the open height is not crossed yet
  if d not in voted and len(voted) == KEEP:
    return                             // we could not keep it, so we do not
                                       // claim it: whatever we voted last
                                       // stands
  voted[d] = crossed[h].backlog        // before the vote, so anything the
  contract.vote_checkpoint(h, d)       // network settles, somebody holds
```

### Asking peers

While `want` is set the node asks peers for `get_checkpoint(chain, want)`,
and a reply that hashes to its digest installs. This is not a call anything
waits on: it has no result to return and no run to abandon, so nothing has
to decide when to give up on it.

Asking for a superseded height goes unanswered, since every holder of that
digest cleared its `voted` on installing a later one. That costs nothing
here: the next poll reads the contract and overwrites `want` with whatever
is settled then, so the poll period bounds how long the node asks the wrong
question.




Rules the code does not show:

* A cursor pauses for two reasons and reads no block either way, so it
  crosses nothing, votes nowhere and does not act. The cap releases itself
  when `crossed` shrinks, which an install and a `rebase` both do. The
  install hold releases on the install, and the next poll overwrites `want`
  if something else settled meanwhile.

## 5. Why the properties hold

*S1.* The backlog changes two ways only: applying the events of the next
finalised block, a function of that block alone, and installing a checkpoint,
whose backlog some correct node derived the first way. Entries carry nothing
local, which keeps the induction closed.

Effects sit outside it. This design does not solve the output commit problem;
it acts ahead of agreement and requires the duplicate to be harmless. It does
not produce duplicates gratuitously either: #1301 signs on admission and has
no tip gate, so a replay would open a signing round for every request in the
range, each pulling in the nodes a signing round takes, which is why
`acted_through` exists.
What it cannot prevent is the range a crash loses, so the duplicate still has
to be harmless. On the source chain the contract emits the event either way
and the receiving library drops a response whose request it no longer has
outstanding; on a destination chain the effect is the same signed transaction
arriving twice.

*S2.* An entry enters by admission from a finalised block this node fetched,
or by installing a digest f+1 voted for, of which one is correct and a
correct node votes only for a backlog it derived. The digest covers the
entries, so matching it means being that backlog and the supplier can
substitute nothing. Quorums never have to intersect: the contract settles a
height once.

The chain is the open-height rule doing it. A node's open height is the first
boundary above its own base, so one that has not installed the settlement at
h has its open height at h and cannot vote above it. Every vote at the next
boundary is therefore from a node that installed h, and the induction S1
relies on has a base.

*L1.* Correct nodes agree (S1), so the bar is about how many are up, and f+1
of n - f leaves n - 2f - 1 correct nodes free to be down, four at n = 9 with
f = 2. Votes persist until the height settles, so nodes need not be up
together, and a node catching up votes on reaching the open height rather
than waiting for the head. Voting only for the next height keeps one height
open: the faulty are f and cannot settle anything alone. A node whose
provider has healed gives a different answer only by reading the chain again,
which it does after an install it did not predict. What bounds a node running
ahead is the cap, so one the contract will not hear from pauses like any
other.

*Retention*, which L2 needs. Every digest a node has voted at a height is one
it can still produce the backlog for, until that height is settled and the
node has installed it or a later one. A node keeps what it votes and a later
vote evicts nothing, the bound being what it can hold rather than which
digest it currently believes.

*L2.* Installing replaces the backlog wholesale rather than reconciling entry
by entry: a node behind moves forward and keeps indexing, one that diverged
takes the settled body and rebases onto it.

The body is there to be had, by retention: the f+1 behind a settled digest
hold it the moment it settles, one of them correct, and hold it until they
install it. There is no escape by voting again at the same height, which
would drop what the voter had and, where a node's reading of a block is not
reproducible, could take the last copy of a digest the network had just
settled. One guaranteed holder is thin, and it is what the threshold costs.
Where no node can produce it at all there is no recovery here, which section
6 owns.

Draining is not among these. An entry leaves when the source chain retires
it, and nothing here makes the source chain do so: an entry whose signature
nobody broadcasts produces no event and stays, which is #1301's open point.

What is here is whether the entry can be signed at all. Admission is a
function of the block, so anything in one correct node's backlog is in all of
them, which is n - f holders, exactly the t that signing takes. It needs t of
them acting at once, and the budget for a correct node not acting is f,
shared with the nodes that are faulty, so it is zero exactly when the model
is at its limit.
Section 1 gives that each correct node keeps up, not that all are up
together. Three things here stop a node acting: it has rebased and is
replaying back to `acted_through`, it is paused at the cap, or it is holding
for an install. The cap is the one that spends no budget at all, because it
spends the lot: it counts from the base, which is the settled height and so
the same on every node up to a poll, so a vote-settle-install round trip
slower than the boundary interval leaves every node at the cap at once.

Closure and convergence, self-stabilisation's two halves, are S1 and L2 here,
so the weight falls on S1 being checkable: every defect this design has had
was S1 failing quietly.

## 6. Limits and failure modes

* A provider that keeps changing its mind makes the node repair endlessly
  without being repaired. Such a node is faulty by section 1, and wants
  repair or removal rather than another rebase.
* A node needing a body it does not hold depends on a peer answering, the one
  place something outside the node decides how long it stays out.
* One correct node reading wrongly for one round is enough to settle its
  reading, the f faulty supplying the rest. f+1 is what the agreement needs
  and no more, so a transient bad provider on any single node is inside the
  settling threshold rather than outside it. 2f+1 would put it outside, at
  the cost of the tally and the two rebase triggers it fed.
* Settlement stalled with nobody disagreeing, which takes more than f nodes
  down or slow. The cap on `crossed` is what keeps the node from running
  ahead, at the price that it counts from the settled height, so nodes reach
  it together and the network signs nothing until settlement catches up. An
  operator has to notice.
* Settlement stalled with everyone disagreeing too finely to resolve, no
  digest able to reach f+1. Out of model twice over, since correct nodes
  agree and there are n - f of them, so at n = 9 it takes five distinct
  readings. Every node sees the stall in the tally and rebases, and if their
  readings are stable they land on the same split and go round again on a
  growing backoff.
* A node whose votes never reach the contract runs ahead to the cap and
  pauses there, and nothing re-casts for it. Section 1 assumes the governance
  chain live and readable, so this is a node with its own problem.
* Every copy of the settled backlog lost: nothing here recovers, a peer
  being the only source of a body. What makes it remote is `voted` being
  durable, and a new vote never evicting the body behind an earlier one, so
  the f+1 behind a settled digest still hold a copy across a restart, one of
  them correct.
* A node that has voted `KEEP` distinct digests at one height votes no more
  there, and the last one it cast stands. It goes on indexing and acting; it
  has simply run out of room to claim anything new, which a node whose
  reading of a block is not reproducible will do and a node whose reading is
  will not.
* A restart loses the watermark cursor and replays from `base`
  to the tip. A long absence does not replay the absence: the first poll
  takes the body in one reply, so the cost is the settlement lag either
  way.
* A storage format change must read the old layout or migrate it in place. A
  node coming up empty is only behind, but doing that to every node at once,
  which a storage version in the key prefix does, is the network-wide replay
  above. Staged migration is a last resort, and the batch is not a clean f:
  t = n - f leaves no slack, so every node already out comes from the same
  budget.

Three signals: a watermark that does not move with `crossed` under its cap,
for the node that cannot index; rebases one after another,
for the node repairing endlessly; and the settled height standing still while
tips move on, for a network that cannot agree. The tally's vote counts say
which nodes a stall is coming from, which the local ones cannot, being kept
by the node whose reading is in question.

Beyond the model, where more than f nodes are wrong, the design has nothing to
offer: enough nodes hold backlogs nobody shares that no digest reaches f+1.
August 2026 came close, twelve nodes with eight against four, which is f = 4
against a model allowing three, and yet the eight were a clear majority. Under
this design they would have settled long before that and the four would have
installed them, which says what the bar costs and nothing about safety.

Whether such a split heals turns on the requests dividing it. A request fewer
than t nodes admitted can never be signed, so it separates their digests for
ever; one held by t nodes across several groups can be signed, and then it
stops dividing them. The cap makes it permanent either way: a paused cursor
signs nothing. August had no in-band recovery at all, and what it took was
pausing traffic and restarting every node from an empty backlog, which is what
this design exists to avoid.

## 7. Getting there from here

Most of the machinery exists. `align_backlog_with_consensus` already fetches a
settled checkpoint from a peer, checks it and installs it, and
`PendingRequests::from_checkpoint` already sets the watermark forwards or
backwards.

| | today | here | step |
|---|---|---|---|
| the digest covers | request ids and a phase tag | the entries, `signature_finalized` among them | 5 |
| settling takes | the signing threshold | f+1, at one open height | 6 |
| checkpoints kept | a store of them | `base` and what we voted | 11 |
| a diverged node | `reset_checkpoints`, by an operator | fetches, then rebases, in band | 6, 9, 10 |
| a vote that does not settle | nothing retries it | re-cast on a backoff | 9 |
| a node catching up | votes at no boundary | votes on reaching the open height | 3 |
| the boundary grid | node configuration | the contract, with the start height | 7 |
| a checkpoint's height | the observed height that crossed the interval | the boundary | 7 |
| a full checkpoint store | halts event consumption | declines to vote | 1 |

Small. Steps 1 and 3 stand alone; step 2 waits for step 5 and step 4 for
steps 5 and 8, both of which are below:

1. Stop the pending cap gating event consumption. The guard on the
   supervisor's receive branch turns a full checkpoint store into a total halt
   for that chain, which wedged devnet in August 2026. What is left of the cap
   is the rule that a node which cannot store a checkpoint declines to vote.
2. Drop `detect_regression`'s no-local-checkpoint guard and take the path
   startup already takes, so a node that comes up empty converges instead of
   voting its own view for ever (L2).
3. Vote on reaching the open height while catching up, not only at the head.
   L1 rests on it.
4. Make `Backlog::insert` leave an existing entry alone, so re-observing a
   request does not reset an entry that has advanced (S1). Not enough on its
   own: the enqueue that follows happens whether or not the entry was new.

Needs a coordinated switch, a digest change splitting the network until every
node has it (S1):

5. Hash the entries rather than request ids and a phase tag. Today's entry
   carries node-local state, `PublishState` with its `is_proposer` and
   participant list, and on a bidirectional entry the assembled `execution_tx`
   its watcher is keyed by; the transaction need not be carried, following
   from the request and the signature. `SignStatus::consensus_tag` is today's
   answer to the same problem, projecting the status onto two values; this
   design records `signature_finalized` instead. What is left is the request payload
   and a decision about `unix_timestamp_indexed`, a node-local wall clock
   inside the request, which is why step 8 travels with this. The encoding is
   the other half and today's is not canonical: it runs fields together in a
   way that is unambiguous only while they are all the same size. Fence the
   switch on a height the contract records, or a rolling upgrade passes
   through a point where upgraded nodes settle digests the rest cannot verify.
6. Settle at f+1 rather than the signing threshold, and vote only for the
   height above the settled one. The contract holds `latest_checkpoints`
   per chain and `checkpoint_votes` as `CheckpointDigest` to a set of
   accounts, and offers `latest_checkpoint(chain)`, `vote_checkpoint(digest)`
   and `checkpoint_votes(chain)`, the last returning a count per digest.
   `latest_checkpoint` is section 2's already, the digest carrying its own
   chain and height. What is missing is three things.
   One vote per node per height, since a map keyed by the whole digest keeps
   an account's earlier vote alongside its later one. A count per node, which
   a set per digest cannot carry. And an open height, there being none today:
   a node may vote at any height above the settled one, so several gather at
   once. Section 2 puts the last two into `checkpoint_votes`, and the open
   height needs the grid from step 7. A contract change, so it travels with
   step 5. It retires
   `reset_checkpoints` with no replacement, and it cannot reject a vote at the
   wrong height until the contract holds the grid, so step 7 comes with it
   rather than after.

Larger, step 7 excepted:

7. Move the anchors and intervals into the governance contract and index from
   an anchor rather than the live head. Ethereum has an issue for the start
   height; the interval has to travel with it. Step 6 needs it. The same step
   settles what a checkpoint's height is: today it is the observed height
   that crossed the bucket, `height / interval`, kept that way because
   Solana's indexer sees only slots carrying relevant transactions and may
   jump from 119 to 500. Two nodes crossing one bucket at different heights
   then hash different heights over the same backlog, so here the height is
   the boundary and the crossing block only triggers the record.
8. Take an entry's timestamp from the block that finalised the request. Only
   Ethereum carries a block timestamp into its events today, so this touches
   every chain's event plumbing.
9. Add the voting: vote on crossing the open height, and pause indexing at
   the cap. The per-node vote count belongs with it.
   The cap is not step 1's cap returning: it holds in memory, releases on the
   next install, and needs no operator. Follows step 6, there being no single
   open height before it.
10. Fetch only when the contract has settled above the base.
    `find_consensus_checkpoint` retries for ever inside the recovery the
    supervisor runs before spawning the indexer, so a node nobody answers
    never starts. Here the same call blocks, which is the deliberate trade of
    section 6, but the poll reaches it only when there is a settled height
    the node does not hold, and then one answer beats indexing the gap.
11. Stop storing what can be derived. That deletes the pending cap and the
    store's growth through an outage. It needs the
    store migrated rather than orphaned: take `CHECKPOINT_STORAGE_VERSION` out
    of the key prefixes, since a bump empties every node at once.

Not needed: reconciling entry by entry, and any new peer call.

## 8. Prior art

The shape is PBFT's (Castro and Liskov, OSDI 1999): periodic checkpoints,
stable once a threshold of matching digests arrive, a lagging replica caught
up by state transfer validated against the stable digest. Two borrowings are
explicit: the digest covers the whole state rather than identifiers into it
(S2), and one mechanism repairs both a lagging node and a diverged one. Their
water marks are not borrowed. The availability rule, that a node votes only
for a checkpoint it holds, is Narwhal's dissemination/ordering split (EuroSys
2022). S1 above a genesis checkpoint is weak subjectivity and installing is
checkpoint sync.

S1, S2 and L1 are consensus's agreement, validity and termination; S1 and L2
are self-stabilisation's closure and convergence (Dijkstra 1974). The fault
model is the crash-recovery one of Aguilera, Chen and Toueg (DISC 1998), whose
question, what a node must keep in stable storage, is section 4's three
durable fields. What that literature carries and this does not is a stabilisation-time
bound (open point 4); what the design does have is fault containment, a
diverged node stopping rather than spreading, though only until it
restarts.

The alternative not taken is a settled checkpoint as a bare anchor, with a
diverged node rebasing and replaying rather than fetching a backlog. That
deletes the peer call and the coordinated switch, and fails on the case that
matters: with no backlog at the anchor, a node whose provider skipped a block
re-derives the same wrong backlog from the same provider.

From the rollback-recovery literature (Elnozahy, Alvisi, Wang and Johnson, ACM
Computing Surveys 2002) most does not apply, its checkpoints being a cut
across concurrent processes and ours a function of a single ordered log at
agreed heights: no orphans, no domino effect, no recovery line, no zigzag
paths. Two things do. Log-based recovery rests on the piecewise deterministic
assumption; S1 is that assumption with the set of nondeterministic events
empty, which is why nothing logs determinants. And the output commit problem
is the one this design declines to solve.

## 9. Open

1. **Whether an entry should record where its response was.** `signature_finalized`
   is a bit, so re-arming a destination-chain watcher means finding a
   `Respond` the node may never have indexed. Replacing the bit with the
   height that set it costs no extra field and turns that search into one
   block fetch; against it, a height in the digest is a height every node has
   to agree on exactly.
2. **How far ahead, how much to keep, and the two periods.** The cap on
   `crossed` is how far ahead of agreement a node may run before it waits,
   `KEEP` is 10 until something says otherwise, a node needing more being
   one whose readings are not reproducible. Nodes reach the cap together, counting from the settled height, so it is the network that
   waits. The poll is the other period and cannot grow: convergence and
   S3(i) both rest on it.
3. **Per-block work**, which grows with the backlog unless entries are
   revisited on a schedule. Bounded waste is acceptable, so the schedule may
   be heuristic.
4. **A stabilisation bound.** L2 says a diverged node converges and not how
   long, which is what an operator would watch.
5. **Membership changes and upgrades**, which section 1 sets aside.
