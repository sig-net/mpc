# Checkpoints

## TL;DR

The backlog is a node's in-memory map, one per source chain, of the requests it has admitted and that are not yet finished there, with what the source chain says about them.
Checkpoints keep these maps in sync across nodes and they let a joining or rejoining node catch up without replaying every block.

### Approach
Checkpoints are due at fixed heights, the same grid for every node.
A node reaching a checkpoint height votes in the governance contract for a digest of its backlog at that height.
The contract settles that height once t nodes, the signing threshold, have voted for the same digest.
Every node polls for what settled and rebases onto it, from its own store if it created that checkpoint and from a peer if not, so everything it indexes from then on descends from it.
A node that has run as far ahead of its base as it may stops and waits for a settlement.

## 1. Background

The network is n nodes, at most f < n/3 faulty, in a crash-recovery model: correct nodes follow the protocol and may crash and restart; faulty nodes may deviate from it arbitrarily.
t is the signing threshold, f+1 ≤ t ≤ n - f: fewer than t nodes cannot sign, and the correct nodes alone can.
Protocol upgrades, committee and threshold changes are out of scope of this doc.

A correct node is told the truth by its RPC provider, and keeps up: it indexes faster than the chain produces blocks, so it reaches the head from wherever it starts.
A node whose provider misleads it is faulty, one of the f.
The governance chain is assumed live and readable throughout.
A correct node's durable storage survives a crash; a node that lost it, but not its key share, rejoins as a new node (S4).

Requests, signatures, executions, attestations and the source and destination chains are those of bidirectional_calls.md.

Vocabulary, per node per source chain:

* **Boundary**: a height at which a checkpoint is due, one every fixed number of blocks.
  Every correct node computes the same ones.

* **Processed height**: the last height whose block the node has finished processing, its events applied to the backlog.
  The indexer reports every height, even one where nothing happened, so the processed height passes through every boundary.
  Apart from the indexer, only a re-index (see Base) moves it, back or forward.

* **Caught up**: the node has finished processing every block up to the chain's finalised head, as in bidirectional_calls.md (Section 4.3).

* **Backlog**: one *entry* per request admitted and not *finished*, that is, not yet removed by a finalised source-chain event.
  An entry holds the request id (rid) as its key, the request as the chain gave it, the contract that made it, and `signatures`.
  `signatures` is the set of signatures for the request published in finalised blocks on the source chain.
  * Only finalised source-chain events add, change or remove an entry, and nothing read from a destination chain does; it is the same backlog as in bidirectional_calls.md.
  * Everything else a node keeps about a request is *node-local*. A node stores in `local` the signatures and attestations it took part in producing and what it read on the destination chain. `local` is persisted and does not go into checkpoints.

* **Acting**: for each entry in the backlog, doing whatever it still needs: signing, looking for the execution, attesting, publishing.
  Taking part in a signing that a peer started is acting too.
  It covers what bidirectional_calls.md (Section 4.3) does on admission, on a destination block and on a `Response`.

* **Checkpoint**: a height and a snapshot of the backlog at that height.
  Its *digest* binds the chain, the height and the entries over a canonical encoding (Section 2).

  * **Settled**: a digest the governance contract has fixed for a height.

  * **Base**: the settled checkpoint a node indexes from, held durably.
    A backlog *descends from* a checkpoint if the node built it by applying blocks on top of that checkpoint's backlog.
    *Rebasing* onto a checkpoint makes it the base.
    *Re-indexing* sets the backlog and the processed height to the base and indexes on from there.

  * **Genesis checkpoint**: the checkpoint with an empty backlog at the chain's start height.
    Every node builds this checkpoint locally instead of fetching it from a peer.
    Until the contract settles its first checkpoint, nodes treat the genesis checkpoint as settled.

## 2. Digest and interfaces

### The digest

```
digest(height, backlog) = H(
    chain                            // CAIP-2 id
    height
    for each entry, in rid order:
        rid
        request
        contract
        signatures
)
```

The request goes in whole because the rid does not cover all of it, e.g., the schema.
`signatures` goes in because a node rebased onto a checkpoint never reads the `Signature` events below its height again.
A peer that served a checkpoint without one of them would leave that node looking for too few executions: each signature fixes one transaction ID to look for, and a request can have several (bidirectional_calls.md, Section 2).

The encoding of the entry must be canonical, one byte string per entry; the request has variable-length fields, so each gets its length before it.
The order must be fixed too: entries go in rid order, and an entry's signatures in the order of their bytes.

### Governance contract

```
vote_checkpoint(CheckpointDigest)      // carries chain, height and digest;
                                       // accepted from committee nodes only

latest_checkpoint(chain) -> CheckpointDigest?
  // none until something has settled

```

The contract is the only writer of settled checkpoint digests.
It settles a height when one digest has votes from t nodes, settles it at most once, and its settled height never decreases.
A vote arriving at or below the settled height is rejected, and votes it holds at or below a newly settled height are dropped in the settlement step.
A node's vote counts once per digest, and a node may hold votes for several digests at one height.

Any threshold from f+1 up puts a correct voter behind every settled digest.
t is the signing threshold: a node that rebases onto a settled checkpoint adopts its requests, so fewer nodes than can sign must not be able to settle one.
At t = n - f this is every correct node (Section 6).

### Peer

```
get_checkpoint(chain, height, digest) -> Checkpoint
  // reply with the Checkpoint matching the chain, height and digest, if
  // held as `base` or in `pending`
```

## 3. Properties, per source chain

### Safety

**S1 Agreement.** The backlog at a height is a deterministic function of the node's base and the finalised blocks since, so correct nodes at a height hold the same backlog.

**S2 Validity.** Every settled `(chain, height, digest)` was created by at least one correct node, descending from a settled checkpoint below it.

**S3 Containment.** (i) A node neither acts on a source chain's backlog nor casts a new vote while it is missing the newest settled checkpoint it has read from the contract.
(ii) A node acts and votes only within a bounded distance of its base.
At that bound it stops acting and creates no new checkpoint, until it rebases onto a newer checkpoint.

**S4 Sufficiency.** A node holding only a settled checkpoint and its key share can do the same as a node that indexed from genesis but didn't participate in signing: join signing rounds, find executions, attest, and vote at the next boundary.
The exception is attesting Unviable (Section 6).

### Liveness, during a long-enough synchronous interval

**L1 Settlement.** Checkpoints keep settling, as long as t correct nodes reach the next checkpoint height, agree there, and can store what they vote for.

**L2 Convergence.** A node whose backlog disagrees with a settled checkpoint finds out at the next settlement it sees, and ends up holding a settled checkpoint and indexing on from it, given a reachable node holding one.

## 4. Design

Described for one node, one source chain; `backlog` is the node's backlog.

* The node indexes finalised blocks in order.
  At every boundary it creates a checkpoint, stores it in `pending` under its height, and votes for it.
* It polls the contract for the settled checkpoint, and one of three things follows.
  * Nothing new has settled: the node does nothing.
  * The settled checkpoint is the one the node stored at that height: it becomes the base.
    If the node has processed up to that height or past it, it carries on.
    If not, it re-indexes from it.
  * The settled checkpoint is another one: the node stops indexing, fetches it from a peer, makes it the base and re-indexes from it.
* A node is *at the cap* when its processed height is `MAX_PENDING` boundaries above its base.
  There it processes no block and waits for a settlement, caught up or not.
  This bounds how far the network signs from state nobody has agreed to.
* It acts only while it is caught up, is not at the cap, and is not missing a settled checkpoint it has read (`want` below).
  This holds for everything acting covers, between blocks too.

`persist` writes durably and is retried until it succeeds.
`vote(c)` calls `vote_checkpoint` with c's chain, height and digest, and is retried until the contract has recorded the vote or has settled that height or a later one.

### Per-chain node state

```
Checkpoint = (Height, Digest, snapshot of backlog)

persistent:
    base      Checkpoint               // the settled checkpoint we index from
    pending   {Height -> Checkpoint}   // the checkpoints we created above base,
                                       // one per boundary
    local     RequestId -> Local       // node-local, as in
                                       // bidirectional_calls.md

in memory:
    backlog           RequestId -> Entry
    processed_height  Height
    want              (Height, Digest)?  // a settled checkpoint we have read
                                         // and do not hold; unset on start
```

### Handlers

```
on start:
  base = the one held, or the genesis checkpoint
  re_index()
```
Indexing
```
on block b finalised, the next one above the processed height:
  if want is set or at the cap:           // wait for checkpoint or settlement;
    return                                // b comes again
  backlog.update(b)                       // add/change/remove entries
  processed_height = height(b)
  if processed_height is a boundary:
    d = digest(processed_height, backlog)
    c = (processed_height, d, backlog)
    pending[c.height] = c ; persist       // store so we hold what we vote for;
                                          // a different one there is a bug
    vote(c)
  if b is the finalised head:             // caught up
    delete local[rid] where rid not in backlog
    act on backlog
```
Polling the governance contract
```
on settlement poll period expiry:
  h, d = contract.latest_checkpoint(chain), or the genesis checkpoint
  if h <= base.height:               // nothing new; another digest at
    return                           // base.height is a bug to alert on
  if want is set and h < want.height:
    return                           // older than what we already read
  if pending[h] has digest d:        // we created it, so we hold it
    rebase(pending[h])
  else:
    want = (h, d)                    // S3(i): indexing stops until we hold
                                     // it (Asking peers, below)
```
A peer's reply
```
on receiving a peer's reply c to what we asked for:
  if want == (c.height, digest(c.height, c.backlog)):
    rebase(c)
```

Handlers run one at a time on the state above.
What a handler starts, a contract call, a signing round, a request to a peer, need not finish inside the handler.
Acting waits until the node is caught up because behind the head its backlog may still hold requests the chain has answered.
What the node already produced is in its node-local records, so it repeats nothing (bidirectional_calls.md, Section 4.3).

That document deletes a node-local record when the node processes the `Response` for its request.
A node that rebases forward skips those Responses, so a caught-up node also deletes the records of requests that are not in its backlog.
A node that is behind does not, since it may hold a record for a request above its processed height, and it must not take a stale reading of the head for caught up, since deletion cannot be undone.

### Rebase and re-index

```
rebase(c):                                        // c settled, above base
  aligned = pending[c.height] has c's digest      // backlog descends from c
            and processed_height >= c.height
  base = c ; persist                              // store base, then prune
  pending.drop_up_to(c.height) ; persist
  want = none
  if not aligned: re_index()

re_index():                                       // start over from base
  backlog, processed_height = base.backlog, base.height
```

### Asking peers

While `want` is set the node keeps asking peers for `get_checkpoint(chain, want)`.
Asking for a height below the settled one comes back without a checkpoint, since holders drop it on rebasing onto a later one.
The next poll overwrites `want` with whatever is settled then, so the poll period bounds how long the node asks for the wrong checkpoint.

### When backlogs differ

The arguments of Section 5 assume that correct nodes build the same backlog from the same blocks.
A bug can make nodes build different backlogs from the same blocks, on more than f nodes at once, which the model does not cover.
In this case only S3 is still guaranteed: the nodes run to the cap and stop there.
Section 6 describes an alternative design where nodes re-index at the cap if no checkpoint settled despite more than 2f votes.

## 5. Why the properties hold

### *S1, correct nodes at a height hold the same backlog.*
Two things change the backlog.
One is applying the events of the next finalised block, a deterministic step that reads the block and the backlog and nothing else.
The other is rebasing onto a settled checkpoint, whose backlog some correct node built the first way.
A rebase does not always replace the backlog: when the checkpoint the node stored at that height is the settled one and the node has processed up to it, the node keeps its own.
That rests on one fact: a node stores the checkpoint it built whenever it passes a height, in place of an older one there.
So the stored checkpoint at or below the processed height was built from the current backlog, and if it is the settled one, resetting to it would change nothing.

The argument is an induction over heights.
Nodes that hold the same backlog at one height and apply the same block hold the same backlog at the next, and nothing node-local enters along the way.
The induction starts from a base the nodes share: genesis, or a settled checkpoint, which a correct node built the same way from a settled checkpoint below it (S2).
What it rests on is the blocks being the same, and a node whose provider gave it something else is faulty (Section 1).
It also needs every node to reach the same verdict on an event from the event alone, which a `Response` does not yet allow (Section 6).

Effects sit outside that argument.
Acting ahead of agreement can publish a signature or send a transaction twice, and bidirectional_calls.md makes both harmless (C3a, replay protection).

### *S2, a settled digest is created by a correct node, chained from genesis.*
A settled digest has votes from t nodes.
At most f < t of them are faulty, so one is correct, and a correct node votes only for a checkpoint it built itself, from its base and the blocks after it.
The digest covers the entries, so a checkpoint that matches it holds that backlog, and a peer serving it can substitute nothing.
The base of that node is a settled checkpoint or genesis, so by induction over settled heights the chain goes back to genesis.
A vote a correct node cast before it rebased or re-indexed stays valid: it is for a checkpoint built the same way from an earlier base.
The faulty may vote at any height and are f, so they settle nothing between them.
So S1's induction has its base.

### *S3, nodes act and vote inside a window around settled height.*
For (i): when a poll reads a settled checkpoint the node does not hold, it sets `want`.
The indexing handler does nothing while `want` is set, and the rule on acting covers the time between blocks, so the node neither indexes, starts to act nor casts a new vote until it holds that checkpoint.
For (ii): a node stops at the cap, `MAX_PENDING` boundaries above its base, so it neither acts nor creates a checkpoint beyond it.
The base is a settled height, so the distance is measured from agreement rather than from wherever the node started.
A rebase lifts both waits.

### *S4, a settled checkpoint is enough to take part.*
Each thing a node does for a request reads the entry and nothing older than the checkpoint.
Signing and joining a round read the request and the contract, which give the key and the bytes to sign, and `signatures`, whose being empty says that no signature is final yet.
Finding an execution reads `signatures`, which give the transaction IDs, and attesting reads the request's schema.
Voting reads the backlog, which the node builds from the checkpoint and the blocks after it (S1).
Attesting Unviable is the exception: it follows from the execution or the `Response` of another request (bidirectional_calls.md, Section 4.3), and once that request has left the backlog the checkpoint holds no trace of it.
What the checkpoint cannot give back is node-local: a node that lost its storage has lost the signatures it issued and not yet seen published.
They are not lost to the network where another correct node was in the round, which keeps and publishes its own (bidirectional_calls.md, Section 6).

### *L1, checkpoints keep settling.*
Correct nodes agree (S1), so what is left is how many are up:

* t votes out of the n - f correct nodes leaves n - f - t of them free to be down, none at t = n - f.
* Votes persist until the height settles, so nodes need not be up together.
* A node catching up votes at every boundary it passes rather than waiting for the head.
* A vote is retried until the contract has it, and after a restart the node casts it again when it passes that boundary.

### *L2, a node that disagrees with a settled checkpoint ends up holding one.*
Rebasing replaces the backlog wholesale rather than reconciling entry by entry, so a node behind and a node that diverged both take the settled checkpoint and index on from it.

Retention keeps that checkpoint available: a node stores a checkpoint before it votes for it and drops it only on rebasing at or past its height; one it builds again at that height is the same (S1).
So the t voters of a settled digest hold it the moment it settles, at least t - f of them correct.
A holder drops it only on rebasing onto a later settled checkpoint, which a fetcher's next poll then asks for instead.
Where no node can produce a checkpoint at all there is no recovery here (Section 6).

## 6. Limits and failure modes

### Inside the model

* Settlement stalls when fewer than t nodes reach a boundary and vote.
  At t = n - f one correct node down while the others index `MAX_PENDING` boundaries past the base is enough.
  The nodes that are up run to the cap and wait for a settlement.
* Signing stalls while more than n - t nodes are faulty or not acting: catching up, at the cap, or missing a settled checkpoint.
* A restart re-indexes from the base, up to `MAX_PENDING` intervals without acting, unless a newer settled checkpoint is fetched.
* A fetch slower than the time between two settlements never completes.
  Holders drop a checkpoint when they rebase onto the next one.
* Nothing bounds the size of a checkpoint.
  A flood of requests makes checkpoints large to store, vote on and serve.
* Nothing bounds the contract's vote store.
  A faulty node may vote at any height and for any number of digests.

### Dependencies on features not implemented yet

* A bidirectional `Response` cannot yet be checked from the event alone.
  A node that holds the output removes the entry and one that does not keeps it.
  Their digests differ, and S1 does not hold for that entry.
* Unviable is attested from another request's execution or answer.
  A node that starts from a checkpoint taken after that answer holds no trace of it and cannot attest.
  A request's entry in the backlog must store that another request's response made it unviable.

### Outside the model: nodes build different backlogs

* No digest reaches t.
  Nodes run to the cap, about two hours on Ethereum and four on Solana at today's settings, and stop.
  There is no in-band way out.
  Nodes restarted with the fix build the same checkpoints from the base again, and the next settlement realigns them.
* A node that wrongly takes a request for finished deletes its record, with the signatures it issued.
* Every copy of a settled checkpoint may be lost.
  Nothing here recovers from that; retention (Section 5, L2) makes it unlikely.
* A node that rebuilds a checkpoint at a height and gets a different one is the sign of such a bug.
  It stores and votes for the new one; nothing here stops it, but it is worth alerting on.
  An earlier vote of the node for the old one can still settle it, with no node holding it any more.

### Options

Each closes one of the limits above, at a price.

* Resume after a restart from the checkpoint created last, instead of re-indexing from the base.
  This needs the creation order across heights, for instance a counter stored with each checkpoint.
  On start the node sets its backlog and processed height to the checkpoint with the highest counter and casts its vote for it again, since a vote in flight at the crash is lost.
  A restart then replays at most one interval instead of up to `MAX_PENDING`.
* Settle at f+1 instead of t, the smallest threshold with a correct voter behind every settled digest.
  Settlement then needs the fewest nodes up and agreeing: n - 2f - 1 correct nodes may be down.
* One vote per node and height in the contract, the newest replacing an older one.
  A vote in flight at a restart can then not settle a digest its node no longer holds, and faulty nodes cannot inflate a tally.
  The price is a contract change.
* Re-index at the cap: a node at the cap that sees, in a view of the vote counts, more than 2f votes at the first boundary above its base settling nothing re-indexes from its base, on a backoff that grows each time and resets on a rebase.
  For a correct node in the model this changes nothing, it builds the same checkpoints again.
  It gives a second attempt, without an operator, where building the backlog again can come out differently, and not where a node repeats the same result.
  It needs a list of checkpoints per height, so that a node keeps what it voted for beside what it rebuilt, and one vote per node and height in the contract, since otherwise faulty nodes can trigger it at will.
* Settle through communication with peers instead of the contract: a node asks all peers for the digests they hold and takes a height as settled once it has heard 2f+1 matching answers, its own counted.
  This drops the vote loop, and any answer that differs from the node's own digest is a faulty node or a bug and can be alerted on.
  The price: a node that restarts behind the others needs 2f+1 peers up at once that hold a common height above its base, not the chain and one peer, and there is no shared record of what settled when.
