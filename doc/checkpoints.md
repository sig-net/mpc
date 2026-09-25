# Checkpoints

## TL;DR

The backlog is the node's record of requests it has observed on a source chain and whose final response, a plain signature or a bidirectional response, is not yet finalised there.
One map per source chain, in memory.
Checkpoints are what persist: they keep those maps in sync across restarts without silently diverging, and let a joining or rejoining node catch up without replaying every block.

### Approach
Checkpoints are due at fixed heights, the same grid for every node.
A node reaching one votes in the governance contract for a digest of its backlog there, and the contract settles that height once f+1 nodes have voted for the same digest (n nodes, at most f of them faulty, Section 1), enough that at least one correct node holds the checkpoint behind it; Section 2 says why f+1 rather than the signing threshold.
Every node polls for what settled and rebases onto it, taking the checkpoint from its own store if it voted for that digest and from a peer if not, so everything it indexes from then on hangs off that checkpoint.

A node that has passed the height under vote and sees nothing settle there reads the vote counts, on a growing backoff.
If 2f+1 distinct nodes have voted with nothing settled, it throws away everything it indexed above the checkpoint it holds and indexes that stretch again, on the chance that its own reading of a block was the odd one.

## 1. Background

The network is n nodes, at most f < n/3 faulty, in a crash-recovery model: correct nodes may crash, restart and act according to the protocol, and faulty nodes may deviate from it arbitrarily.
Protocol upgrades, committee and threshold changes are out of scope.

A correct node is told the truth by its RPC provider, and keeps up: it indexes faster than the chain produces blocks, so it reaches the head from wherever it starts.
A node whose provider misleads it counts among the f faulty for as long as it is misled.
The governance chain is assumed live and readable throughout.

Vocabulary, per node per source chain:

* **Processed height**: the last height whose block the node has finished processing, its events applied to the backlog.
  The indexer reports every height, even one where nothing happened, so the processed height passes through every boundary.
  Apart from the indexer, only a rebase moves it, back or forward.

* **Caught up**: the node has finished processing every block up to the chain's finalised head.

* **Backlog**: one *entry* per request admitted and not finished, holding the request id as its key, the request as the chain gave it, the contract that made it, and `signatures`, every signature for it that has been published and finalised on the source chain, not one this node merely generated or submitted.
  Thus, every entry is a fact about the source chain, and the backlog as described in this document holds nothing else.
  The implementation may store additional information about a request, e.g. a signature before it is finalised on the source chain, destination chain events and attestations, keyed by request id; these are not discussed here.

* **Boundary**: a height at which a next checkpoint is due, e.g., the chain's start height plus a multiple of a constant interval.
  Every node computes the same ones.

* **Checkpoint**: a height and a snapshot of the backlog at that height.
  Its *digest* binds the chain, the height and a set of requests over a canonical encoding (Section 2).
  What a peer serves, what `pending` stores and what a node rebases onto is always a checkpoint.

  * **Open height**: the first boundary above the node's base, the one height it may vote at.

  * **Settled**: a digest the governance contract has fixed for a height.

  * **Base**: the settled checkpoint a node indexes from, held durably.
    *Rebasing* onto a checkpoint makes it the base and, unless the node's own backlog already descends from it, sets the processed height back to it, so every backlog the node builds from then on descends from that one.

  * **Genesis checkpoint**: the checkpoint with an empty backlog at the chain's start height.
    Every node builds this checkpoint locally instead of fetching it from a peer.
    Until the contract settles its first checkpoint, nodes treat the genesis checkpoint as settled.

## 2. Digest and interfaces

### The digest

```
digest(height, requests) = H(
    chain
    height
    for each entry, in request id order:
        request id
        request
        contract
        signatures
)
```

Encoding for digest must be canonical so it's one byte string per checkpoint, no two checkpoints reaching the same one; the request has variable-length fields, so each gets its length before it.
The order must be fixed too: entries go in request id order, which today's snapshot already sorts by, and an entry's signatures in the order the source chain published them.

A checkpoint carries everything a node needs to sign, watch and attest for the requests in it, and nothing node-local, and the digest covers all of it.

### Governance contract

```
vote_checkpoint(CheckpointDigest)      // carries chain, height and digest
  // accepted above the settled height, rejected at or below it

latest_checkpoint(chain) -> CheckpointDigest?
  // none until something has settled

checkpoint_votes(chain) -> ([(CheckpointDigest, count)], num_voters)
  // how many nodes voted for each digest, and how many distinct nodes
  // it holds a vote from
```

The contract is the only writer of settled checkpoint digests.
It settles a height when one digest reaches f+1 votes, settles it at most once, and its settled height never decreases.
A vote arriving at or below the settled height is rejected with an error, unless it repeats the settled digest, which is a no-op; votes it holds at a height it has settled or passed are dropped.


Note that the contract does not hold one vote per node per height: a node that votes for two different digests at a height counts behind both digests.
Thanks to retention (Section 5), a node still holds both checkpoints, so it can serve whichever settles.
A node voting twice for the same digest does not increase the vote count for that digest.
So the per-digest counts can add up to more than the number of nodes that voted, which is why the view also counts distinct voters.

The signing threshold, n - f, would need every correct node up and agreeing whenever the faulty ones abstain.
A threshold of 2f+1 would guarantee at least f+1 correct holders and keep one misled node on top of the f from settling its reading, at the price that a buggy, non-deterministic implementation needs more nodes to reach the same backlog.

### Peer

```
get_checkpoint(chain, height, digest) -> Checkpoint
  // reply with the Checkpoint matching the chain, height and digest, if
  // available locally
```

## 3. Properties, per source chain

### Safety

**S1 Agreement.** The backlog at a height is a deterministic function of the node's base and the finalised blocks since, so correct nodes at a height hold the same backlog.

**S2 Validity.** For each `(chain, height, digest)` tuple settled by the contract it holds that there is at least one correct node that created a checkpoint with this digest for this height by reading the chain starting from the settled checkpoint below it.

**S3 Containment.** (i) A node neither acts on a source chain's backlog nor votes while it is missing the newest settled checkpoint it has read from the contract (thus the poll period defines how stale that reading can be).
(ii) A node acts and votes only within a bounded distance of its base, and at that bound it does neither, until it rebases, onto a newer checkpoint or the one it has.

### Liveness, during a long-enough synchronous interval

**L1 Settlement.** Checkpoints keep settling, as long as f+1 correct nodes reach the next checkpoint height, agree there, and can store what they vote for.

**L2 Convergence.** A node whose backlog disagrees with a settled checkpoint finds out at the next settlement it sees, and ends up holding a settled checkpoint and indexing on from it, given a reachable node holding one.

## 4. Design

Described for one node, one source chain.
`pending` is the code's store of pending checkpoints with two differences: a checkpoint goes in when the node votes for it rather than at every boundary, and it holds at most `KEEP`, all at the open height.
`commit` is a single durable write, so a rebase cannot leave `base` replaced and `pending` not, or the other way round.

A checkpoint holds a snapshot of `requests`, not the live map, so what was hashed is what is still there.

`CAP` is how far above its base a node indexes before it waits, at least one interval so that it can reach its open height.
It bounds how far the network signs from state nobody has agreed to.

The backlog is #1301's `tracked` without what is node-local, with #1301's rules for what enters it.
#1301 adds a node's own signature to `signatures` as soon as it is made; here only signatures read from a finalised `Signature` event count, since a node outside the signing round learns of one only then.
A node's own signature before that, and its attestations, are kept apart and survive a rebase, which replaces `requests` and leaves them alone; losing them in a crash costs redoing that work, which #1301 already tolerates.
An entry leaves the backlog only on a source-chain event, so M5 in #1301, which drops an entry on destination-chain data, has to wait until its decision is read back from the source chain.

### Per-chain Node State

```
Checkpoint = (Height, Digest, snapshot of requests)

persistent:
    base      Checkpoint               // the settled checkpoint we index from
    pending   {Digest -> Checkpoint}   // every checkpoint we have voted for
                                       // at the open height, at most KEEP

in memory:
    requests          RequestId -> Entry
    processed_height  Height
    want              (Height, Digest)?  // a settled checkpoint we have read
                                         // and do not hold; unset on start
    caught_up         bool               // processed up to the finalised
                                         // head
    created           Digest?            // digest of the checkpoint this run
                                         // created at the open height
```

### Event Handlers

```
on start:
  base = the one held, or the genesis checkpoint
  rebase(base)
```
Governance contract polling
```
on settlement poll period expiry:
  h, d = contract.latest_checkpoint(chain), or the genesis checkpoint's
  if (h, d) == (base.height, base.digest):
    rebase_if_stuck()                // nothing new has settled
  else if h < base.height:           // a stale read
    return
  else if d == digest(h, {}):        // an empty backlog needs no peer:
    rebase((h, d, {}))               // build it
  else if d in pending:              // we voted for it, so we hold it
    rebase(pending[d])
  else:
    want = (h, d)                    // S3(i): indexing stops until we hold
                                     // it; asking peers is get_checkpoint
```
Interacting with peers
```
on receiving a peer's reply c to what we asked for:
  if want == (c.height, digest(c.height, c.requests)):
    rebase(c)
```
Indexing
```
on block b finalised, the next one above the processed height:
  if want is set or processed_height >= base.height + CAP:
    return
  requests.update(b)                 // add/change/remove entries, idempotent
  processed_height = height(b)
  if processed_height == open height:
    d = digest(processed_height, requests)
    created = d
    vote((processed_height, d, requests))
  if caught_up:
    act on requests                  // sign, watch, attest, publish, for
                                     // each entry whatever it still needs
```

No two handlers run at once, and none runs against itself.

`requests.update` changes state and nothing else; effects (signing, publishing, attesting) only happen later if at all, and only once the node is caught up.
A node behind the head indexes and votes but does not act, so it opens no signing round for a request the network finished while it was away, and spends no presignature on one.
Indexing and voting cannot wait for the head, L1 needs them; acting can.
Today's code indexes while it catches up, but neither votes nor acts until it is caught up.

Acting on `requests` is a sweep: for each entry, whatever it still needs that has not been started.
What has been started is in the node's separate state, not in `requests`, which is what lets the sweep run at every block without repeating itself.
A crash loses what was in flight, and the replay starts it again, which is the case the destination already has to absorb.

### Rebase

```
rebase(c):                           
  if c is not base:
    base = c ; pending = {} ; commit // one write: a crash partway must not
                                     // leave the old base and nothing we
                                     // voted for
  want = none
  if created == c.digest and processed_height < open height:
    return                           // aligned: our requests descend from c
                                     // and the next open height is ahead
  created = none
  caught_up = false                  // until it processes up to the head again
  requests, processed_height = c.requests, c.height
```
```
rebase_if_stuck():
  if processed_height < open height: // still replaying towards it, so no
    return                           // vote there yet, and a rebase would
                                     // only lose the replay
  if backoff not met yet: return     // prevent spinning
  increase backoff for this open height
  re-cast every vote in pending      // a repeat is a no-op at the contract
  if checkpoint_votes shows 2f+1 distinct voters:
    rebase(base)
```

Every change of base goes through `rebase`.
When the node's own checkpoint settles within an interval, the node is aligned and carries on, as today's code does.
Otherwise it goes back to the new base and re-indexes, not acting until it is at the head again, so the replay spends no presignatures on requests finished meanwhile.

The tally matters only as 2f+1 distinct voters with nothing settled.
At least f+1 of them are correct and at the open height, and would have settled a digest they agreed on, so some reading is not reproducible; the node rebases on the chance that it is its own.

### Voting

```
vote(c):                             // c is the checkpoint at the open height
  if len(pending) == KEEP: return    // out of room; the last vote stands
  pending[c.digest] = c ; commit     // store before voting, so we hold it
  contract.vote_checkpoint(c.height, c.digest)   // in case it settles
```

### Asking peers

While `want` is set the node keeps asking peers for `get_checkpoint(chain, want)`.
The reply handler above rebases onto a checkpoint whose digest matches.

Asking for a superseded height comes back without it, since every holder of that digest dropped it on rebasing onto a later one.
That costs nothing here: the next poll reads the contract and overwrites `want` with whatever is settled then, so the poll period bounds how long the node asks the wrong question.


## 5. Why the properties hold

### *S1, correct nodes at a height hold the same backlog.*
Two things change the backlog.
One is applying the events of the next finalised block, a deterministic step that reads the block and the backlog it is applied to and nothing else.
The other is rebasing onto a settled checkpoint, whose backlog some correct node built the first way.

The argument is then an induction over heights: nodes that hold the same backlog at one height and apply the same block hold the same backlog at the next.
Entries carry nothing node-local, so nothing outside the block enters along the way, and the induction starts from a base the nodes share, which is the chain S2 gives below.
What it rests on is the blocks being the same.
A node whose provider gave it something else diverges, and L2 is what brings it back.

Effects sit outside that argument.
This design acts ahead of agreement, so an effect can happen twice (the same signature published twice, the same transaction sent twice), and it needs that to be harmless.
#1301 describes what the network does; per node, acting waits until the node is caught up.
Without that gate a replay would open a signing round for every request in the range, each round pulling in the n - f nodes signing takes and each spending a presignature.
What the gate does not cover is a crash at the head: the replay of that last stretch is caught up almost at once and starts again whatever was in flight when the node went down.
That is why harmless matters: on the source chain the contract emits the event either way and the library #1301 puts in the application contract drops a response whose request it no longer has outstanding, and on a destination chain the effect is the same signed transaction arriving twice.

### *S2, a settled digest is created by a correct node, chained from genesis.*
An entry enters by admission from a finalised block this node fetched, or by rebasing onto a digest that f+1 nodes voted for.
At most f of those voters are faulty, so one of them is correct, and a correct node votes only for a backlog it built itself.
The digest covers the entries, so a checkpoint that matches it holds that backlog, and the supplier can substitute nothing.
Since the contract settles a height only once, one correct voter behind the digest is all it takes, and f+1 votes guarantee one.
A node misled by its provider counts among the f (Section 1); Section 2 says what 2f+1 would add.

The chain back to genesis holds because of the open-height rule.
A node's open height is the first boundary above its own base, so one that has not rebased onto the settlement at h has its open height at h or below and cannot vote above it.
Every correct vote at the next boundary is therefore from a node that rebased onto h, and settling takes one of those.
The faulty may vote at any height and are f, so they settle nothing between them.
So S1's induction has its base.

### *S3, nodes act and vote inside a window around settled height.*
For (i): when a poll reads a settled checkpoint the node does not hold, it sets `want`, and the indexing handler does nothing while `want` is set.
So the node neither indexes, acts nor votes until it holds that checkpoint, and the poll period bounds how long it can go without noticing.
For (ii): the cap.
A node that has indexed `CAP` above its base stops in the same handler, and the base is a settled height, so the distance is measured from agreement rather than from wherever the node started.
A rebase releases both.

### *L1, checkpoints keep settling.*
Correct nodes agree (S1), so what is left is how many are up:

* f+1 votes out of the n - f correct nodes leaves n - 2f - 1 of them free to be down, four at n = 9 with f = 2.
* Votes persist until the height settles, so nodes need not be up together.
* A node catching up votes on reaching the open height rather than waiting for the head.
* A node whose provider has healed reads the chain again after a settlement it did not create, and from `rebase_if_stuck` when the tally shows the height is not settling, which is what matters when nothing settles at all.
* A vote the contract missed or rejected, while it was resharing say, is cast again from `rebase_if_stuck` on the same backoff.

### *L2, a node that disagrees with a settled checkpoint ends up holding one.*
Rebasing replaces the backlog wholesale rather than reconciling entry by entry: a node behind and a node that diverged both take the settled checkpoint and index on from it.

Retention: Every digest a node has voted at a height is one it can still produce the checkpoint for, until that height is settled and the node has rebased onto it or a later one.
A node keeps every checkpoint it votes for, up to `KEEP`, and a later vote at the same height evicts none of them.

That is what keeps a settled checkpoint available.
The f+1 behind a settled digest hold it the moment it settles, and one of them is correct.
Rebasing onto it loses nothing, the checkpoint becoming the base.
A holder stops being able to serve it only when it rebases onto a later checkpoint, and by then the settlement the fetcher is chasing has moved too, so its next poll asks for that one instead.
One guaranteed holder is thin, and it is what the threshold costs.
Where no node can produce it at all there is no recovery here, which Section 6 owns.


## 6. Limits and failure modes

* Stalling
  * Settlement stalled with nobody disagreeing, which takes more than f nodes down or slow.
    The cap is what keeps the node from running ahead, at the price that it counts from the base, a settled height, so nodes reach it together and the network signs nothing until settlement catches up.
    An operator has to notice.
  * Settlement stalled with everyone disagreeing too finely to resolve, no digest able to reach f+1.
    Out of model twice over, since correct nodes agree and there are n - f of them, so at n = 9 it takes four distinct readings.
    Every node sees the stall in the tally and rebases, and if their readings are stable they land on the same split and go round again on a growing backoff.
  * Every copy of a settled checkpoint lost: nothing here recovers, a peer being the only source of a checkpoint.
    What makes it unlikely is `pending` being durable, and a new vote never evicting the checkpoint behind an earlier one, so the f+1 behind a settled digest still hold a copy across a restart, one of them correct.
* A node whose votes do not reach the contract, because it is resharing or the call fails, runs ahead to the cap and waits there, re-casting them on a growing backoff until they land.
* A node that has voted `KEEP` distinct digests at one height votes no more there, and the last one it cast stands.
  It goes on indexing and acting; it has simply run out of room to claim anything new, which a node whose reading of a block is not reproducible will do and a node whose reading is will not.
* A restart loses the processed height and replays from `base` to the head.
  A node that was down for a long time does not index the whole gap: its first poll finds a newer settled checkpoint, it fetches that from a peer, and indexes on from there.
* A correct node catching up does not act, so for signing it counts as down: it comes out of the same budget of f as the faulty nodes, and signing needs n - f nodes acting at once.
* `pending` holding more than one checkpoint means this node created different checkpoints for one height: its reading of the chain is not reproducible.
  Nothing here stops it, but it is worth alerting on.
