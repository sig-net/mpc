# Backlog and checkpointing

## Scope

The backlog is the node's durable record of requests it has observed on a
source chain and whose final response, a plain signature or a bidirectional
response, is not yet finalised there. One map per source chain.
Checkpointing keeps those maps in sync across restarts without silently
diverging, and lets a joining or rejoining node catch up without replaying
every block.

The governance contract decides on the next highest checkpoint, based on
votes from the nodes. The nodes keep polling for the latest checkpoint, 
if nothing new has settled and this node has already crossed the 
next height, on a growing backoff: 
read the vote counts, and if 2f+1 nodes have voted with nothing settled, 
throw away everything derived above the latest checkpoint and try again.

This is intended design. Section 7 says what it would take to get there.

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

* **Watermark**: the height the cursor has reached, inclusive. Adopting a
  checkpoint may move it, back or forward.

* **At the tip**: the watermark is at the chain's finalised head.

* **Backlog**: one *entry* per request admitted and not finished, holding the
  request id as its key, the request as the chain gave it, the contract that
  made it, and `signature_finalized`, true once the first call of  `Respond`
  for it has been finalised on the source chain, never when this node merely
  finished signature generation or published one. Nothing else, and every field a
  fact about the source chain. 

* **Boundary**: a height at which a checkpoint is due, the chain's start
  height plus a multiple of a constant interval. Both are per chain, and
  every node computes the same grid from them.

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

Signing needs a threshold of t = n - f. Settling a checkpoint requires 
a threshold of f+1 to guarantee that at least one correct node holds 
the checkpoint. Guaranteeing  a majority of at least f+1 *correct* nodes hold
a settled checkpoint needs a threshold of 2f+1, which makes settling under 
a buggy non-deterministic implementation harder, needing more nodes to have
reached the same backlog for a given height. 

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

Encoding for digest must be canonical so it's one byte string per
checkpoint, no two checkpoints reaching the same one. Request id order is
design rather than encoding: insertion order is node-local, and a digest
taken over it would differ between nodes holding the same backlog.

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

### Peer

```
get_checkpoint(chain, height, digest) -> Checkpoint
  // reply with the Checkpoint matching the chain, height and digest, if
  // available locally
```

## 3. Properties, per source chain

### Safety

**S1 Agreement.** The backlog at a height is a deterministic function of the
newest checkpoint the node has adopted and the finalised blocks since, so
correct nodes at a height hold the same backlog.

**S2 Validity.** A digest the contract settles at a height is one a correct
node derived at that height from the settled checkpoint below it, so the
settled checkpoints are a chain back to genesis and every entry a node acts
on was read from finalised chain state by a correct node.

**S3 Containment.** A node acts and votes only inside a window around what
the network has agreed.
(i) It neither acts on a source chain's backlog nor votes there while it is
missing the backlog of the newest settled checkpoint it has read from the
contract. The poll period is how stale that reading can be.
(ii) It acts and votes only within a bounded distance of the newest
checkpoint it has adopted, and at that bound it does neither, until it adopts
a newer checkpoint or starts again from the one it has.

### Liveness, during a long-enough synchronous interval

**L1 Settlement.** Checkpoints keep settling, as long as f+1 correct nodes
reach the next checkpoint height, agree there, and can store what they vote
for.

**L2 Convergence.** A node whose backlog disagrees with a settled checkpoint
finds out at the next settlement it sees, and ends up holding a settled
backlog and indexing on from it, given a reachable node holding one. 

## 4. Design

One node, one source chain. `commit` is a single durable write, so the two
fields an install replaces cannot be left half replaced. The handlers are
mutually exclusive: no two run
their bodies at once and none runs against itself. `reconcile` is the one
exception and only while it fetches, which is unbounded and cannot be held
across. It sets `installing` before releasing, so a block handler starting
meanwhile sees the flag and returns having touched nothing, and a later
`reconcile` supersedes it, dropping the fetch and the rest of that run with
it. So the only overlap is a handler that does nothing.

The backlogs recorded in `crossed` and `voted` are snapshots, not the
live map, so what was hashed is what is still there. Serving
`get_checkpoint` is outside all of this and waits for none of it, which is
what serving snapshots allows.

Base and cursor. The node indexes the chain with a watermark cursor, which
holds the backlog the node acts on and records at every boundary it crosses
the digest it derived there and the backlog behind it. The base is
`local_checkpoint`, replaced when polling the contract shows a newer settled
height. Its body comes from what the cursor recorded, from the body behind a
digest the node voted, or from a peer.

Cap: how many boundaries beyond the base a node derives before it waits,
which is `len(crossed)`. It is
how far the network will go on signing from state nobody has agreed to, and
only incidentally a bound on what `crossed` holds.

Note that signatures and attestations a node produces are persisted too, 
however, they don't need to be in the backlog, therefore we don't talk about
them in detail here. 

### State

```
durable:
    local_checkpoint (Height, Digest, Backlog)   // the base
    voted            {Digest -> Backlog}         // every digest we have voted
                                                 // at the open height, held
                                                 // until that height is
                                                 // installed, KEEP = 10
    acted_through    Height                      // acting is done up to and
                                                 // including this height

in memory:
    backlog       RequestId -> Entry          
    watermark     Height
    crossed       Height -> (Digest, Backlog)     // checkpoints above base
    installing    bool                            // reconcile has read a
                                                  // settled height it has
                                                  // not installed yet;
                                                  // false on start, so a
                                                  // crash mid-install lifts
                                                  // the hold
```

### Event Handlers

```
on start:
  local_checkpoint = the one held, or the chain's genesis
  rebase()
  reconcile()
  
on the settlement poll, re-armed at a fixed interval:
  reconcile()

on block b finalised, the next one above the watermark:
  if installing or len(crossed) >= CAP:
    return                           
  backlog.update(b)                  // add/change/remove entries, idempotent
  watermark = height(b)
  if at boundary:
    crossed[height(b)] = (digest(height(b), backlog), backlog)
    vote_if_ready(height(b))
  if watermark > acted_through:
    act on backlog                 // #1301's. Here only that it is per block
    acted_through = watermark      // and not repeated over a replay
```

`backlog.update` changes state and nothing else; effects (signing,
publishing, attesting) only happen later if at all.

`acted_through` is written lazily, so it is a lower bound: a crash loses the
last of it and the replay acts twice, which is the case the destination
already has to absorb. It is not reset by a `rebase`, a rebase being about
what the node believes rather than what it has already done.

### Rebase and reconcile

```
rebase():
  backlog, watermark = local_checkpoint
  crossed = {}                     // which also puts the cap back under its
                                   // bound
```

```
reconcile():
  h, d = contract.latest_checkpoint(chain)
  if h == local_checkpoint.height:
    rebase_if_stuck()
    return
  installing = true             // S3(i): do not act on a backlog we already
                                // know is superseded
  mine = crossed[h].digest == d // the cursor derived it this run
  body = crossed[h].backlog if mine else voted[d] or fetch(h, d)
                                // a digest binds its height, so voted cannot
                                // answer for the wrong one
  local_checkpoint = (h, d, body) ; voted = {} ; commit
                                // one write: a crash between them would
                                // leave the old base with no body for what
                                // we voted, and the f+1 holders one short
  if mine and watermark > h:    // only the cursor's own reading lets it keep
    crossed.remove_below(h+1)   // remove entries no longer needed
    vote_if_ready(open height)  // open height moved with h
  else:                         // read h differently, or 
    rebase()
  installing = false
  
```

### Fetch

```
fetch(h, d):
  ask peers for get_checkpoint(chain, h, d) until one replies with a
    checkpoint hashing to d
```

A fetch does not give up by itself. Once every holder of `d` has installed a
later height, its `voted` is cleared and nothing can answer, so a fetch for a
superseded height waits for ever. What ends it is the next poll, whose
`reconcile` drops this run and fetches the height that did settle. So
supersession rather than success is what terminates a fetch that has fallen
behind, and the poll period bounds how long that takes.

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

### Rebase if stuck

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
we could see it, and the node learns it is wrong from `reconcile` finding the
settled digest is not the one it recorded.

Who it serves is the node whose reading of a block is not reproducible.
Crossing the open height is what makes a node vote, and absent a settlement
a rebase is the only thing that makes it cross again, so without this a
second reading never reaches the contract and a flaky network never takes a
second draw. Where readings are reproducible it re-derives the same digest
and re-casts the same vote, and the backoff is what makes that cheap.


Rules the code does not show:

* A cursor pauses for two reasons and reads no block either way, so it
  crosses nothing, votes nowhere and does not act. The cap releases itself
  when `crossed` shrinks, which an install and a `rebase` both do. The
  install hold releases when `reconcile` returns, either way it went.

## 5. Why the properties hold

*S1.* The backlog changes two ways only: applying the events of the next
finalised block, a function of that block alone, and adopting a checkpoint,
which installs a backlog some correct node derived the first way. Entries carry
nothing local, which keeps the induction closed.

Effects sit outside it. This design does not solve the output commit problem;
it acts ahead of agreement and requires the duplicate to be harmless. It does
not produce duplicates gratuitously either: #1301 signs on admission and has
no tip gate, so a replay would open a signing round for every request in the
range, each pulling in t participants, which is why `acted_through` exists.
What it cannot prevent is the range a crash loses, so the duplicate still has
to be harmless. On the source chain the contract emits the event either way
and the receiving library drops a response whose request it no longer has
outstanding; on a destination chain the effect is the same signed transaction
arriving twice.

*S2.* An entry enters by admission from a finalised block this node fetched,
or by adoption of a digest f+1 voted for, of which one is correct and a
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
them, which is t = n - f holders. Signing needs them at the tip together, and
the budget for being off it is f, shared with the nodes that are faulty, so
it is zero exactly when the model is at its limit. Section 1 gives that each
correct node keeps up, not that all are up together, and a node that has
rebased is off the tip until it is back. The cap is a third way off the tip
and the one that spends no budget at all, because it spends the lot: it
counts from the base, which is the settled height and so the same on every
node up to a poll, so a vote-settle-install round trip slower than the
boundary interval leaves every node at the cap at once.

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
* A restart loses the watermark cursor and replays from `local_checkpoint`
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
adopted them, which says what the bar costs and nothing about safety.

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
| checkpoints kept | a store of them | `local_checkpoint` and what we voted | 11 |
| a diverged node | `reset_checkpoints`, by an operator | fetches, then rebases, in band | 6, 9, 10 |
| a vote that does not settle | nothing retries it | re-cast on a backoff | 9 |
| a node catching up | votes at no boundary | votes on reaching the open height | 3 |
| the boundary grid | node configuration | the contract, with the start height | 7 |
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
   height; the interval has to travel with it. Step 6 needs it.
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
    section 6, but `reconcile` reaches it only when there is a settled height
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
2022). S1 above a genesis checkpoint is weak subjectivity and adoption is
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
