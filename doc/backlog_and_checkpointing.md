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
and promotes it, and everything it derives from then on hangs off that
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
starts. A provider that misleads a node otherwise following the protocol
leaves it neither faulty nor in agreement, but diverged, which is what L2
is for. The governance chain is assumed live and readable throughout, so a
node that cannot see a settlement or get a vote recorded is a node with its
own problem rather than a network without a contract.

Vocabulary, per node per source chain:

* **Processed height**: the height the indexer has reached, inclusive. Promoting a
  checkpoint may move it, back or forward.

* **Backlog**: one *entry* per request admitted and not finished, holding the
  request id as its key, the request as the chain gave it, the contract that
  made it, and `signature_finalized`, true once the first call of  `Respond`
  for it has been finalised on the source chain, never when this node merely
  finished signature generation or published one. Nothing else, and every field a
  fact about the source chain. 

* **Boundary**: a height at which a next checkpoint is due, e.g., the
  chain's start height plus a multiple of a constant interval. Every node
  computes the same ones, and one falls due whether or not a block is
  delivered at that height.

* **Checkpoint**: a height and the backlog at that height. Its *digest* binds
  the chain, the height and the entries over a canonical encoding (section 2).

  * **Open height**: the one height a vote may be cast at, the first
    boundary above the settled height. The node's is measured from the
    checkpoint it holds and the contract's from the settlement it has
    recorded, and the two differ for a node that has not polled since a
    settlement. Unqualified, it is the node's.

  * **Settled**: a digest the governance contract has fixed for a height.

  * **Promoted**: a node has made a settled checkpoint its base, durably,
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
newest checkpoint the node has promoted and the finalised blocks since, so
correct nodes at a height hold the same backlog.

**S2 Validity.** A digest the contract settles at a height is one a correct
node derived at that height from the settled checkpoint below it, so the
settled checkpoints are a chain back to genesis and every entry a node acts
on was read from finalised chain state by a correct node.

**S3 Containment.** 
(i) A node neither acts on a source chain's backlog nor votes there while it is
missing the backlog of the newest settled checkpoint it has read from the
contract (thus the poll period defines how stale that reading can be).
(ii) A node acts and votes only within a bounded distance of the newest
checkpoint, and at that bound it does neither, until it promotes a newer one or
starts again from the one it has.

### Liveness, during a long-enough synchronous interval

**L1 Settlement.** Checkpoints keep settling, as long as f+1 correct nodes
reach the next checkpoint height, agree there, and can store what they vote
for.

**L2 Convergence.** A node whose backlog disagrees with a settled checkpoint
finds out at the next settlement it sees, and ends up holding a settled
backlog and indexing on from it, given a reachable node holding one. 

## 4. Design

Described for one node, one source chain. `commit` is a single durable
write, so a promotion cannot leave `base` replaced and `voted` not, or the
other way round. 

The backlogs recorded in `pending` and `voted` are snapshots, not the
live map. `pending` is derived: indexing fills it again on the way back up,
and a restart drops it. A checkpoint is persisted when a vote is cast,
not when crossing a boundary.

`CAP` is how many boundaries beyond the base a node derives before it
waits, which bounds how far the network signs from state nobody has agreed
to. One block crossing several boundaries takes it past the cap, and
indexing stops at the next one.

Note that signatures and attestations a node produces are persisted too, 
however, they don't need to be in the backlog, therefore we don't talk about
them in detail here. 

### Per-chain Node State

```
persistent:
    base           (Height, Digest, Backlog)       // Checkpoint according to
                                                   // governance contract
    voted          {Digest -> Backlog}             // every digest we have voted
                                                   // at the open height, held
                                                   // until that height is
                                                   // promoted
    acted_through  Height                          // acting (signing, attesting, 
                                                   // publishing) is done up to 
                                                   // and including this height

in memory:
    backlog           RequestId -> Entry
    processed_height  Height
    pending           Height -> (Digest, Backlog)  // checkpoints above base
    want              (Height, Digest)?            // a settled checkpoint we
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
  body = pending[h].backlog if pending[h].digest == d else voted[d]
                                // a digest binds its height, so voted cannot
                                // answer for the wrong one
  if body is none:
    want = (h, d)               // S3(i): indexing stops until we hold it
    return                      // asking peers is section 2's get_checkpoint
  promote(h, d, body)
```
Interacting with peers
```
on receiving a peer's reply (h, d, backlog) to what we asked for:
  if want == (h, d) and digest(h, backlog) == d:
    promote(h, d, backlog)
```
Indexing
```
on block b finalised, the next one above the processed height:
  if want is set or len(pending) >= CAP:
    return                           
  for each boundary B with processed_height < B < height(b):
    pending[B] = (digest(B, backlog), backlog)   // no block between the
                                     // processed height and B changed it,
                                     // or that block would be this one
  backlog.update(b)                  // add/change/remove entries, idempotent
  processed_height = height(b)
  if height(b) is a boundary:
    pending[height(b)] = (digest(height(b), backlog), backlog)
  if a boundary was crossed:
    vote_if_ready(open height)
  if processed_height > acted_through:
    act on backlog                     // Sign, watch, attest, publish
    acted_through = processed_height   // and not repeated over a replay
```

No two handlers run their bodies at once, and none runs against itself.

Where only blocks carrying requests or responses are delivered a boundary
can pass unobserved, so a checkpoint is recorded at the boundary and never
at the block that crossed it. The backlog to bind there is the one in hand,
a block in between that changed it having been delivered first.

`backlog.update` changes state and nothing else; effects (signing,
publishing, attesting) only happen later if at all.

`acted_through` is written lazily, so it is a lower bound: a crash loses the
last of it and the replay acts twice, which is the case the target
already has to absorb. It is not reset by a `rebase`, a rebase being about
what the node believes rather than what it has already done.

Instead of `len(pending) >= CAP` and `processed_height > acted_through` alternative
conditions can be defined without changing the properties materially.

### Rebase and promote

```
rebase():
  backlog, processed_height = base
  pending = {}                     
```
```
promote(h, d, body):
  mine = pending[h].digest == d       // the backlog computed in this run
  base = (h, d, body) ; voted = {} ; commit
  want = none                   
  if mine and processed_height > h:   
    pending.remove_below(h+1)         // drop what is now below the base
    vote_if_ready(open height)        // open height moved with h
  else:                               // read h differently, or not yet there
    rebase()
```
```
rebase_if_stuck():
  if not pending[open height]:   // still replaying towards it, so we have no
    return                       // vote there and a rebase would only lose
                                 // the replay
  if backoff not met yet: return // prevent spinning
  increase backoff for this open height
  if contract.checkpoint_votes() shows 2f+1 voted with nothing settled:
    rebase()
```

The tally is read for one thing, 2f+1 having voted with nothing settled. 
In a bug-free world with honest RPC services only this will never happen,
so seeing it means several nodes interpreted the chain differently and this
one rebases on the chance that it is among them and rebasing may help. 

### Voting

```
vote_if_ready(h):
  if h is not our open height: return  // a vote above it is one we cannot
                                       // justify, having not promoted what
                                       // is below; the contract separately
                                       // rejects a vote at any height but
                                       // its own open one
  d = pending[h].digest
  if d is none: return                 // the open height is not crossed yet
  if d not in voted and len(voted) == KEEP:
    return                             // store <= KEEP checkpoints
  voted[d] = pending[h].backlog        // before the vote, so we hold it
  contract.vote_checkpoint(h, d)       // in case it settles
```

### Asking peers

While `want` is set the node asks peers for `get_checkpoint(chain, want)`,
repeatedly and a reply that hashes to its digest is promoted via the handler 
described above. 

Asking for a superseded height goes unanswered, since every holder of that
digest cleared its `voted` on promoting a later one. That costs nothing
here: the next poll reads the contract and overwrites `want` with whatever
is settled then, so the poll period bounds how long the node asks the wrong
question.


## 5. Why the properties hold

*S1.* The backlog changes two ways: applying the events of the next
finalised block, a deterministic step reading that block and the backlog it
is applied to and nothing else, and promoting a checkpoint, whose backlog
some correct node derived the first way. A rebase is neither, assigning the
base, which is a promotion's result. Entries carry nothing local, which
keeps the induction closed, and the bases it runs on lie on one chain, which
is S2 below. Nodes reading the same finalised blocks therefore hold the same
backlog at a height; one reading something else is the diverged node L2
covers.

Effects sit outside it. This design does not solve the output commit problem;
it acts ahead of agreement and requires the duplicate to be harmless. It does
not produce duplicates gratuitously either. #1301 signs on admission and has
no tip gate, so a replay would open a signing round for every request in the
range, and each round pulls in the n - f nodes that signing takes.
`acted_through` is what stops a replay doing that.
What it cannot prevent is the range a crash loses, so the duplicate still has
to be harmless. On the source chain the contract emits the event either way
and the receiving library drops a response whose request it no longer has
outstanding; on a target chain the effect is the same signed transaction
arriving twice.

*S2.* An entry enters by admission from a finalised block this node fetched,
or by promoting a digest f+1 voted for, of which one is correct and a
correct node votes only for a backlog it derived. The digest covers the
entries, so matching it means being that backlog and the supplier can
substitute nothing. Safety here is not two quorums meeting, which is what a
height settling twice would need: it is one correct voter behind the digest
and one settlement per height, and that is why f+1 suffices.

The chain is the open-height rule doing it. A node's open height is the first
boundary above its own base, so one that has not promoted the settlement at
h has its open height at h or below and cannot vote above it. Every correct
vote at the next boundary is therefore from a node that promoted h, and
settling takes one of those. The faulty may vote at any height and are f, so
they settle nothing between them. The induction S1 relies on has a base.

*S3.* (i) is `want`. A poll that reads a settled checkpoint the node cannot
produce sets it, and the block handler returns while it is set, so the node
stops indexing, acting and voting until it holds that body. The poll period
is what bounds the staleness, the contract being read nowhere else. (ii) is
the cap. A node that has derived `CAP` boundaries beyond its base stops in
the same handler and for the same reason, and the base is a settled height,
so the distance is measured from agreement rather than from wherever the
node started. Both release on a promotion.

*L1.* Correct nodes agree (S1), so the bar is about how many are up, and f+1
of n - f leaves n - 2f - 1 correct nodes free to be down, four at n = 9 with
f = 2. Votes persist until the height settles, so nodes need not be up
together, and a node catching up votes on reaching the open height rather
than waiting for the head. Voting only for the next height keeps one height
open: the faulty are f and cannot settle anything alone. A node whose
provider has healed gives a different answer only by reading the chain again,
and two things make it do so: promoting a checkpoint it did not derive, and
`rebase_if_stuck` when the tally shows the height is not settling. The second
is the one that matters when nothing settles at all, there being no promotion
to trigger the first. A node the contract never hears from runs ahead only to
the cap and stops there, so it settles nothing and disturbs nothing.

*Retention*, which L2 needs. Every digest a node has voted at a height is one
it can still produce the backlog for, until that height is settled and the
node has promoted it or a later one. A node keeps what it votes and a later
vote evicts nothing, the bound being what it can hold rather than which
digest it currently believes.

*L2.* Promoting replaces the backlog wholesale rather than reconciling entry
by entry: a node behind moves forward and keeps indexing, one that diverged
takes the settled body and rebases onto it.

The body is there to be had, by retention: the f+1 behind a settled digest
hold it the moment it settles, one of them correct. Promoting it loses
nothing, the body becoming the base. What ends a holder's ability to serve it
is promoting a later checkpoint, by which time the settlement the fetcher is
chasing has moved too and its next poll asks for that one instead. There is
no escape by voting again at the same height, which would drop what the voter
had and, where a node's reading of a block is not reproducible, could take
the last copy of a digest the network had just settled. One guaranteed
holder is thin, and it is what the threshold costs.
Where no node can produce it at all there is no recovery here, which section
6 owns.


## 6. Limits and failure modes

* One node reading wrongly for one round is enough to settle its
  reading, the f faulty supplying the rest. f+1 is what the agreement needs
  and no more, so a transient bad provider on any single node is inside the
  settling threshold rather than outside it. 2f+1 would put it outside, at
  the cost of the tally and the two rebase triggers it fed.
* Stalling
  * Settlement stalled with nobody disagreeing, which takes more than f nodes
    down or slow. The cap on `pending` is what keeps the node from running
    ahead, at the price that it counts from the settled height, so nodes
    reach it together and the network signs nothing until settlement catches
    up. An operator has to notice.
  * Settlement stalled with everyone disagreeing too finely to resolve, no
    digest able to reach f+1. Out of model twice over, since correct nodes
    agree and there are n - f of them, so at n = 9 it takes five distinct
    readings. Every node sees the stall in the tally and rebases, and if
    their readings are stable they land on the same split and go round again
    on a growing backoff.
  * Every copy of the settled backlog lost: nothing here recovers, a peer
    being the only source of a body. What makes it unlikely is `voted` being
    durable, and a new vote never evicting the body behind an earlier one, so
    the f+1 behind a settled digest still hold a copy across a restart, one
    of them correct.
* A node whose votes never reach the contract runs ahead to the cap and
  pauses there, and nothing re-casts for it. Section 1 assumes the governance
  chain live and readable, so this is a node with its own problem.
* A node that has voted `KEEP` distinct digests at one height votes no more
  there, and the last one it cast stands. It goes on indexing and acting; it
  has simply run out of room to claim anything new, which a node whose
  reading of a block is not reproducible will do and a node whose reading is
  will not.
* A restart loses the cursor and replays from `base`
  to the tip. A long absence does not replay the absence: the first poll
  takes the body in one reply, so the cost is the settlement lag either
  way.
* A storage format change must read the old layout or migrate it in place. A
  node coming up empty is only behind, but doing that to every node at once,
  which a storage version in the key prefix does, is the network-wide replay
  above. Staged migration is a last resort, and the batch is not a clean f:
  t = n - f leaves no slack, so every node already out comes from the same
  budget.
* `voted` containing more than one entry: non-determinism in the implementation.


## 7. Getting there from here

Most of the machinery exists. `align_backlog_with_consensus` already fetches a
settled checkpoint from a peer, checks it and promotes it, and
`PendingRequests::from_checkpoint` already sets the processed height
forwards or
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
   next promotion, and needs no operator. Follows step 6, there being no single
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
