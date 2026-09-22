# Backlog and checkpointing

## TL;DR

The backlog is the node's record of requests it has observed on a source
chain and whose final response, a plain signature or a bidirectional
response, is not yet finalised there. One map per source chain, in memory.
Checkpoints are what persist: they keep those maps in sync across restarts
without silently diverging, and let a joining or rejoining node catch up
without replaying every block.

### Approach
Checkpoints are due at fixed heights, the same grid for every node. A node
reaching one votes in the governance contract for a digest of its backlog
there, and the contract settles that height once f+1 nodes have voted for
the same digest (n nodes, at most f of them faulty, section 1), enough that
at least one correct node holds the body behind it; section 2 says why f+1
rather than the signing threshold. Every node polls for what settled. A node
that derived that digest itself carries on indexing; any other fetches the
body from a peer and promotes it, and everything it derives from then on
hangs off that checkpoint.

A node that has passed the height under vote and sees nothing settle there
reads the vote counts, on a growing backoff. If 2f+1 have voted with nothing
settled, it throws away everything it derived above the checkpoint it holds
and indexes that stretch again, on the chance that its own reading of a
block was the odd one.

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

The indexer reports coverage rather than events: it tells the node it has
reached height h, and most heights change nothing. The cursor therefore
lands on every boundary. An indexer that reports in jumps instead, as one
scanning a range of Solana slots does, has to record the boundaries it
passed over, with the backlog it held at each; that is an implementation
matter, and nothing below depends on which way it reports. The indexer also
says when it has reached the chain's finalised head, which is what *caught
up* means below.

Vocabulary, per node per source chain:

* **Processed height**: the height the indexer has reached, inclusive. It
  advances with the indexer; only a rebase sets it elsewhere, back or forward.

* **Backlog**: one *entry* per request admitted and not finished, holding the
  request id as its key, the request as the chain gave it, the contract that
  made it, and `signature_finalized`, true once the first call of  `Respond`
  for it has been finalised on the source chain, never when this node merely
  finished signature generation or published one. Nothing else, and every field a
  fact about the source chain. 

* **Boundary**: a height at which a next checkpoint is due, e.g., the
  chain's start height plus a multiple of a constant interval. Every node
  computes the same ones.

* **Checkpoint**: a height and a snapshot of the backlog at that height. Its
  *digest* binds the chain, the height and the entries over a canonical
  encoding (section 2).

  * **Open height**: the first boundary above the node's base, the one
    height it may vote at.

  * **Settled**: a digest the governance contract has fixed for a height.

  * **Promoted**: a node has made a settled checkpoint its base, durably,
    so that every backlog it derives from then on descends from that one.

  * **Genesis checkpoint**: an empty backlog at the chain's start height,
    whose digest the contract holds.

## 2. Digest and interfaces

### The digest

```
digest(height, backlog) = H(
    chain
    height
    for each entry, in request id order:
        request id
        signature_finalized
)
```

Encoding for digest must be canonical so it's one byte string per checkpoint,
no two checkpoints reaching the same one. Request id order is design rather
than encoding: insertion order is node-local, and a digest taken over it
would differ between nodes holding the same backlog. It is the order today's
snapshot already sorts by.

### Governance contract

```
vote_checkpoint(CheckpointDigest)      // carries chain, height and digest
  // accepted above the settled height, rejected at or below it

latest_checkpoint(chain) -> CheckpointDigest

checkpoint_votes(chain) -> [(CheckpointDigest, count)]
  // the votes it still holds, counted per digest
```

The contract is the only writer of settled checkpoints. It settles a height
when one digest reaches f+1 votes, settles it at most once, and its settled
height never decreases. Votes at or below a settled height are rejected, and
votes at heights it has passed are discarded.

That is the whole of it, and apart from the threshold it is what the
contract does today. Three things it deliberately does not do. It does not
police the open height: a correct node votes only at its own (section 4),
and a vote at any other height needs f+1 accounts behind one digest before
it settles anything, which it cannot reach without a correct node joining
it. It does not hold one vote per node per height: a node that votes twice
at a height counts behind both digests, and retention (section 5) means it
still holds both bodies, so whichever settles it can serve. And it counts
per digest rather than per node, which is enough for the stuck test, since
summing the counts at the node's open height overstates the turnout only
when somebody voted twice, and rebasing sooner is the harmless direction.

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
node derived at that height from the settled checkpoint below it. So the
settled checkpoints form a chain back to genesis, and every entry a node acts
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

Described for one node, one source chain. Two words are borrowed from the
code and mean less here: a node promotes only a checkpoint the contract has
settled, and `pending` is derived and in memory, not the store the code
keeps under that name. `commit` is a single durable write, so a promotion
cannot leave `base` replaced and `voted` not, or the other way round.

The backlogs recorded in `pending` and `voted` are snapshots, not the
live map. `pending` is derived: indexing fills it again on the way back up,
and a restart drops it. A checkpoint is persisted when a vote is cast,
not when crossing a boundary.

`CAP` is how many boundaries beyond the base a node derives before it
waits, which bounds how far the network signs from state nobody has agreed
to.

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
                                                   // hold; unset on start.
    caught_up         bool                         // the indexer has reached
                                                   // the finalised head
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
  backlog.update(b)                  // add/change/remove entries, idempotent
  processed_height = height(b)
  if processed_height is a boundary:
    pending[processed_height] = (digest(processed_height, backlog), backlog)
    vote_if_ready(processed_height)
  if caught_up and processed_height > acted_through:
    act on backlog                     // Sign, watch, attest, publish
    acted_through = processed_height   // and not repeated over a replay
```

No two handlers run their bodies at once, and none runs against itself.

`backlog.update` changes state and nothing else; effects (signing,
publishing, attesting) only happen later if at all, and only once the node
is caught up. A node behind the head indexes and votes but does not act, so
it opens no signing round for a request the network finished while it was
away, and spends no presignature on one. Indexing and voting cannot wait
for the head, L1 needs them; acting can.

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

### *S1, correct nodes at a height hold the same backlog.*
Two things change the
backlog. One is applying the events of the next finalised block, a
deterministic step that reads the block and the backlog it is applied to and
nothing else. The other is promoting a checkpoint, whose backlog some
correct node built the first way. A rebase brings in nothing new, assigning
the base, which a promotion put there.

The argument is then an induction over heights: nodes that hold the same
backlog at one height and apply the same block hold the same backlog at the
next. Entries carry nothing node-local, so nothing outside the block enters
along the way, and the induction starts from a base the nodes share, which
is the chain S2 gives below. What it rests on is the blocks being the same.
A node whose provider gave it something else diverges, and L2 is what brings
it back.

Effects sit outside that argument. This design acts ahead of agreement and
needs the duplicate to be harmless, the output commit problem being one it
does not solve. #1301 signs on admission and relies on the caught-up gate
for the rest: without it a replay would open a signing round for every
request in the range, each round pulling in the n - f nodes signing takes
and each spending a presignature. What the gate does not cover is a crash at
the head, where the replay of that last stretch is caught up almost at once;
`acted_through` bounds what it acts on again, down to the range the crash
loses. That range is why harmless matters: on the source chain the contract emits the event either
way and the receiving library drops a response whose request it no longer
has outstanding, and on a target chain the effect is the same signed
transaction arriving twice.

### *S2, a settled digest is derived by a correct node, chained from genesis.*
An entry enters by admission from a finalised block this node fetched, or by
promoting a digest that f+1 nodes voted for. At most f of those voters are
faulty, so one of them is correct, and a correct node votes only for a
backlog it built itself. The digest covers the entries, so a body that
matches it is that backlog, and the supplier can substitute nothing. The
contract settles a height once, so all that is left to want is a correct
voter behind the digest, and f+1 gives one. This rests on section 1's
provider assumption; one node misled for a single round settles its reading,
which section 6 owns.

The chain comes from the open-height rule. A node's open height is the first
boundary above its own base, so one that has not promoted the settlement at
h has its open height at h or below and cannot vote above it. Every correct
vote at the next boundary is therefore from a node that promoted h, and
settling takes one of those. The faulty may vote at any height and are f, so
they settle nothing between them. So S1's induction has its base.

### *S3, nodes act and vote inside a window around settled height.*
(i) relies on `want`. A poll that reads a settled checkpoint the node
cannot produce sets it, and the indexing handler returns while it is set, so
the node stops indexing, acting and voting until it holds that body. The
poll period is what bounds the staleness, the contract being read nowhere
else. (ii) relies on the cap. A node that has crossed `CAP` boundaries beyond
its base stops in the same handler, and the base is a settled height, so the
distance is measured from agreement rather than from wherever the node
started. A promotion releases both, and a rebase also releases the cap.

### *L1, checkpoints keep settling.*
Correct nodes agree (S1), so what is left is how many are up. Taking f+1
votes out of the n - f correct nodes leaves n - 2f - 1 of them free to be
down, four at n = 9 with f = 2. Votes persist until the height settles, so
nodes need not be up together, and a node catching up votes on reaching the
open height rather than waiting for the head. A node whose provider has
healed gives a different answer only by reading the chain again, and two
things make it do so: promoting a checkpoint it did not derive, and
`rebase_if_stuck` when the tally shows the height is not settling. The
second is the one that matters when nothing settles at all, there being no
promotion to trigger the first.

### *L2, a node that disagrees with a settled checkpoint ends up holding one.*
Promoting replaces the backlog wholesale rather than reconciling entry by
entry: a node behind moves forward and keeps indexing, one that diverged
takes the settled body and rebases onto it.

Retention: Every digest a node has voted at a height is one it can still
produce the backlog for, until that height is settled and the node has
promoted it or a later one. A node keeps what it votes, a later vote for the
same height evicting nothing: the bound is what it holds, not what it
currently believes.

That is what makes the body available. The f+1 behind a settled digest
hold it the moment it settles, and one of them is correct. Promoting it
loses nothing, the body becoming the base. A holder stops being able to
serve it only when it promotes a later checkpoint, and by then the
settlement the fetcher is chasing has moved too, so its next poll asks for
that one instead. Voting again at the same height is no way out of holding
it: that would drop what the voter had, and where a node's reading of a
block is not reproducible it could take the last copy of a digest the
network had just settled. One guaranteed holder is thin, and it is what the
threshold costs. Where no node can produce it at all there is no recovery
here, which section 6 owns.


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
* A restart loses the processed height and replays from `base`to the tip. 
  A long absence does not replay the absence: the first poll takes the body in
  one reply, so the cost is the settlement lag either way.
* A storage format change must read the old layout or migrate it in place. A
  node coming up empty is only behind, but doing that to every node at once,
  which a storage version in the key prefix does, is the network-wide replay
  above. Staged migration is a last resort, and the batch is not a clean f:
  t = n - f leaves no slack, so every node already out comes from the same
  budget.
* `voted` containing more than one entry: non-determinism in the implementation.
