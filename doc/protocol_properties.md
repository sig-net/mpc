# **Protocol Properties** 

Goals:

* capture *what must hold* in the MPC node coordination layer and *why* to be able to reason about simplifications that improve robustness

Protocol properties defined below are separated into

* safety (nothing bad ever happens: no key leak, no unrequested signature)  
* liveness (every request eventually completes), and  
* efficiency (we try not to waste artifacts or rounds doing it). Some waste is acceptable as long as it stays bounded.

Not all of the below is implemented. Where a property or invariant is only partly enforced today, the gap is named where it is claimed.

## 1\. Request lifecycle and its objects

* Sign request flow  
  1. request is finalized on-chain 
  2. indexed by each node's own indexer; the request\_id is a deterministic function of the request, so every node derives the same one  
  3. a per-node task organizes rounds (attempts) until one generation instance produces a signature  
  4. the signature is submitted on-chain
  5. settlement is chain-specific: NEAR verifies the signature and resumes the yielded promise, emitting no event of its own; the EVM contract keeps no request state and emits an event for any submitter without checking anything  
  6. downstream process is responsible for event verification and exactly once semantics 

Both artifacts below have a single owner, the node that coordinated their generation, which simplifies statesync and coordination, and a set of holders, the nodes storing their shares.

* Triple pair (artifact): two secret-shared random triples, produced in the background and stored, owned and consumed as a single artifact under one id, spent to build one presignature.

* Presignature (artifact): pre-computed, secret-shared ECDSA nonce (big\_r, and shares k, sigma).

* Posit: prepare phase leading up to an instance
  * proposer sends Propose message to each peer  
  * peers answer Accept/Reject  
  * proposer sends Start carrying the final participant list to each accepter  
  * the proposer reserves its artifact when proposing and commits it, removing it from the pool, when generation starts; aborting before the commit releases the reservation, aborting after does not  

* Instance: one attempt to run the protocol to completion over a specific artifact, named by that artifact
  * Signature: (sign\_id, presignature\_id) (the code's SignId wraps the request\_id above, same 32 bytes)  
  * Triple pair/presignature: identified by artifact id. A triple pair's id is drawn at random by its proposer; a presignature's id is derived from the pair it consumes (hash of the pair id), not chosen.  

  A request's round tries to establish a signature instance; since the artifact tentatively picked for this round can differ round to round, rounds are usually different instances. If a round is not successful, a new proposer is chosen deterministically (rotating over the nodes). Only posit messages name the round; generation messages name only (sign\_id, presignature\_id), so two rounds that re-pick the same presignature, possible when the first aborted before committing it, share one name.

## 2\. System model

* On-chain information
  * Entities: n nodes; membership, threshold t, and epoch are fixed by the NEAR governance contract. 
    * Together with the public keys and whether the contract is `Running`, they form the **committee** a node operates under (`GovernanceInfo` in code).
    * Each node holds its own local, read-only snapshot of it, refreshed on contract update. Throughout, *committee* and *committee member* are contract-scoped, while *participant* and *participant list* always refer to one instance.
  * Request and response (per supported chain): NEAR holds pending requests, verifies signatures for them and settles them. The others mostly emit an event for whoever submits, which is why exactly-once is the consumer's job (§1).
  
  (i) all nodes observe the same finalized sequence of requests and committee states, possibly at different times;  
  (ii) nodes act only on finalized state (finalization definition may differ per chain).  
* Hybrid fault model.  
  * Liveness is argued under crash-recovery: correct nodes may halt and restart (otherwise never deviating). After restart the node's durable storage is assumed to be intact.  
  * Safety of S1–S4 must hold against f arbitrarily corrupted nodes.
    Two conditions bound f. 
    * f \< t keeps the adversary from assembling a signing quorum out of its own key shares; with f ≥ t it holds one and all bets are off. 
    * f \< 2t − n makes any two participant lists share at least one honest member, which is what stops one artifact being consumed by two otherwise disjoint lists. The contract sizes t at ⌊2n/3⌋ \+ 1 for n ≥ 5 and thus works for every f up to n − t; a threshold vote can only raise t further, since the contract clamps a proposed threshold to \[⌊2n/3⌋ \+ 1, n − 1\], and both conditions get easier as t grows, so that floor is what keeps the model intact. Below n \= 5 it falls back to a simple majority (⌊n/2⌋ \+ 1), which does not: at n \= 3 that gives 2t − n \= 1, so only f \= 0 is inside the model. The floor is applied on resharing and by threshold votes, not to the value passed at contract initialization, which is checked only against n, so a network can also be deployed outside the model.  
* Network  
  * Safety is guaranteed under asynchrony (no bounds on message delivery), while liveness is guaranteed for the periods where the network is synchronous (messages between honest nodes arrive within some bound δ, not assumed known) for long enough.  
    * Formally (see e.g., Shoup, DISC 2024): the network is δ-synchronous over \[a, b+δ\] if every message an honest node sends at time T in \[a, b\] reaches its honest recipient by T+δ ; liveness needs such an interval lasting longer than the current timeout. With unknown δ, the classic technique is to increase timeouts until progress is observed (DLS 1988, used as view-timeout doubling in PBFT and as a linear per-round schedule in Tendermint; the Simplex family instead assumes a known bound and fixes ∆timeout ≥ 3δ per slot). This implementation sits in between: the per-round schedule `round_timeout(r)` grows only up to a hard ceiling, which amounts to assuming a whole round fits inside that ceiling: a Propose, Accept and Start exchange, the generation protocol, and the indexing skew between two nodes. Liveness is therefore argued for δ up to a fraction of the ceiling, not for arbitrary finite δ (more details in L1)  
  * Links are fair-lossy (may drop messages), which every phase compensates for by timeout-and-retry, so during a synchronous interval, communication between live nodes is effectively reliable and timely.
  * Channels are authenticated and encrypted. 
* Each node runs its own chain indexers and eventually observes every finalized request (assumption; liveness depends on it, safety does not).  
* Chain state reaches a node only through its RPC provider, which sits outside the fault model above: a provider that reports a committee or a request the chain never finalized breaks S3 and S2 at that node, and nothing in this layer detects it. Verifying responses against a light client is what would remove the assumption; until then it is one, and it covers the indexers as well.  
* The mesh active set is a local, unreliable failure detector: each node's own guess at which members are currently reachable and up-to-date (active), a subset of the committee. It may be wrong, and no two nodes ever need the same guess; §6 D2 governs what may be derived from it. A reachable peer is additionally kept *out* of the active set while an initial or post-reconnect state sync runs (a transient Syncing state), so "active" is strictly narrower than "reachable".

## 3\. Safety properties

* **S1. One-shot artifacts are consumed at most once:** No presignature is used in signature shares for more than one sign request, and no triple pair for more than one presignature.
* **S2. Only indexed requests are signed:** An honest node contributes a signature share only to requests its own indexer delivered from a finalized chain state.  
* **S3. Membership and epochs change only on-chain:** No honest node adopts a committee other than from finalized contract state, and no node processes requests under a non-Running state. 
* **S4. Instance-local agreement:** Any two honest participants that reach the generating phase of the same instance use the same participant list or they abort.

Violating any of these is unacceptable in any execution within §2's fault bound. See Appendix for more details, including enforcing mechanisms.

## 4\. Liveness

Progress is guaranteed during a sufficiently long synchronous interval, never at a fixed time. The precise bounds and the enforcing mechanisms are in the Appendix.

* **L1. Signature progress:** during a long-enough δ-synchronous interval with ≥ t correct committee members online, a usable presignature (owner and holders online), and ≥ t of that presignature's holders having indexed the request, the request produces a signature within bounded time (O(f \+ p)·∆timeout \+ one generation round, where p counts the members that are offline or own no usable presignature). That such a presignature keeps existing is L2.  
* **L2. Artifact supply:** during a long-enough synchronous interval with ≥ t members (itself included) in the node's active set, a node below its artifact floor and under the network-wide cap eventually completes a generation, given its inputs (none for a triple pair, one owned triple pair for a presignature).   
* **L3. Settlement:** once a signature is produced with a correct, online owner, it is eventually accepted on-chain (on NEAR this must happen before the request's yield deadline).  
* **L4. Mesh convergence:** during a long-enough synchronous interval, every correct, reachable committee member (re)enters each correct node's active set within bounded time. 

## 5\. Efficiency targets

E1. Amortized ≈ 1 presignature consumed per settled signature. 

E2. ≈ 1 generation instance per request at a time. 

Mechanisms striving towards these targets are deterministic proposer rotation, the posit round, and a backoff that pauses proposing when so many peers reject with "already generating" that no threshold set is left to work with.

Duplicate instances, duplicate on-chain responses, and wasted rounds are correct but wasteful. On NEAR the contract settles a request on the first valid response and later ones simply fail; on chains whose contract keeps no request state, every response emits another event and the downstream consumer is the one that has to deduplicate (§1). Consequently, any mechanism that serves only E-properties may be lossy, heuristic, or deleted; it must be judged on cost, not correctness.

## 6\. Design Invariants

Incomplete list of general, implementation-independent rules (the *how*) that keep the properties above (the *what*) true.
 
* D1. The chain is the sole arbiter. Request settlement and membership live on-chain. The off-chain layer must remain safe under arbitrary duplication, reordering, loss, and retry of its own actions. *Serves S2, S3 (safety-critical agreement is delegated to the chain) and is necessary for D4.*  
* D2. Anything two nodes must compute identically (shared input, e.g. "who proposes in round r") may depend only on contract state, request data (e.g. the entropy, which is chain-fixed per request, the transaction hash on Ethereum), and the round number, never on the local failure detector or local clocks.  Rationale: local views differ by design; deriving shared roles from them silently reintroduces the agreement problem this layer avoids. Two caveats: shared is not the same as unbiasable, since a requester who controls the transaction controls the entropy and with it the first proposer; and "not local clocks" constrains the mapping from shared inputs to roles, not the round number itself, which each node advances on its own timeouts (nodes disagreeing about the current round is expected and is repaired by buffering future-round messages and by stale-round rejects). *Serves L1.*  
* D3. One-shot resources are single-writer. Consumption is initiated only by the recorded owner; every holder deletes on first use, durably before emitting anything derived from the artifact.  Losing an artifact (e.g., due to a crash) is acceptable; reusing one is not. The code orders the delete correctly, so "durably" rests on the store's configuration, and today's does not fully back it: a host crash can lose a second of acknowledged deletes, which weakens S1's crash argument since a resurrected share can honestly serve a second request. *Serves S1.*  
* D4. Abort anywhere, retry fresh. Every phase must be abortable without cleanup obligations on peers, and retried with fresh resources or resources provably safe to reuse (i.e., derived only from D2's shared inputs, never from this attempt's own messages or local view, and never a D3 one-shot artifact). No step may assume any peer observed a previous attempt. *Serves L1, L2 and protects S1 on retry.*  
* D5. Local state is bounded. Any map, buffer, or cache keyed on something peers or requests can produce without limit must carry a size bound and an eviction rule. Rationale: memory-driven restarts are churn, and churn is what the liveness bounds spend themselves absorbing, so an unbounded structure turns a remote peer's behaviour into a local restart. Not yet enforced: a posit for a sign id this node never indexes creates a mailbox with no bound and no eviction, so a peer can grow that map at will (§S2). *Serves L1, L2, L4.*


# **Protocol Appendix: Property Details**

### S1. One-shot artifacts are consumed at most once

*Property.* No presignature is used in signature shares for more than one sign request, and no triple pair for more than one presignature.

*Rationale.* Two ECDSA signatures on one nonce are two equations in the two unknowns (k, x): the private key follows. The per-request re-randomization does not change that, since the delta is public and both signatures share the same underlying k; it only makes the two *derived* signatures distinct, which is why even two requests with equal payloads count as different.

*Enforcement*: ensured by the single-writer rule of §D3, applied locally at every holder and needing no agreement. Only the artifact's recorded owner can open an instance on it, which each holder checks itself rather than trusting the proposer, though only when it takes its share (§S4). Taking is what burns it: when generation starts the proposer removes the artifact from storage and every deliberator takes its own share, so a later attempt finds nothing at any holder that already served one, and the removal must reach durable storage before anything derived from the artifact is sent or a crash resurrects the share. Every message names its instance and is fed only to the instance it names, so an attempt cannot pick up shares meant for another (§D4).

Per-holder deletion is enough because lists intersect. Two **disjoint** sets of honest holders could otherwise each serve their own first request on one artifact. Both instances need a participant list of at least t (the posit phase starts an instance only once t nodes including the proposer have accepted), any two such lists share at least 2t − n members, and f \< 2t − n (§2) leaves at least one of those shared members honest. That holder burned the artifact on the first instance and refuses the second, which therefore never reaches t shares. Consuming one artifact twice would take f ≥ 2t − n, outside the model.

### S2. Only indexed requests are signed

*Property.* An honest node contributes a signature share only to requests its own indexer delivered from a finalized chain state.

*Rationale.* A node that signs anything its own chain view did not finalize gives peers a way to obtain signatures for transactions no user ever requested.

*Enforcement*: signature tasks are spawned exclusively from local indexer output, and posit messages for unknown sign ids are buffered, never answered directly. Each mailbox holds one message per sender, but the map of mailboxes is keyed on sign id with no bound and no eviction for ids that never get indexed (§D5); only recently-completed ids are capped, by a 4096-entry LRU. 

### S3. Membership and epochs change only on-chain

*Property.* No honest node adopts a committee other than from finalized contract state, and no node processes requests under a non-Running state.

*Rationale.* Every other safety claim here is stated in terms of n, t and the committee, so a node acting on an unfinalized committee quietly voids the fault bound the rest of the document argues against.

*Enforcement*: 
The contract's ProtocolState is Initializing, Running, or Resharing. Initializing yields no committee at all; Resharing yields the incoming membership, threshold, and epoch with the Running flag clear; only Running yields a committee cleared for work. A node's committee is its local snapshot of that state as reported by the chain's RPC provider. Sign tasks are held whenever the flag is clear.

### S4. Instance-local agreement

*Property.* Any two honest participants that reach the generating phase of the same instance use the same participant list or they abort.

*Rationale.* Each node's computations depend on its participant list, so nodes working from different lists cannot combine into a valid signature, and catching the divergence turns a guaranteed dead end into a clean abort.

*Enforcement*: An instance is identified by (sign\_id, presignature\_id) for signing, and analogously by artifact id for triple/presignature generation. The instance's proposer alone determines the participant list and sends it in Start to each accepter; anything inconsistent is rejected and the instance aborts (§D4). Only the presignature's owner can consume it (§D3), but that check runs at take time, so a non-owner can drive a posit as far as Start; the instance then dies when every holder's take fails. No agreement *across* instances is claimed: two rounds of the same request may overlap, and safety does not depend on that never happening.

This holds even against a Byzantine proposer: A malicious proposer can send divergent lists to different honest accepters, but each honest node uses the list it was told and different nodes were told different lists, so they never reconstruct a valid signature: the combine fails and the instance aborts. The worst outcome is an abort, never a bad signature. 

### L1. Signature progress.

*Property.* During a long-enough δ-synchronous interval with ≥ t correct committee members online, a usable presignature (owner and holders online), and ≥ t of that presignature's holders having indexed the request, the request produces a signature within bounded time (O(f \+ p)·∆timeout \+ one generation round, where p counts the members that are offline or own no usable presignature). That such a presignature keeps existing is L2.

A round only makes progress if the proposer that round elects owns a usable presignature, since a proposer proposes one of its own. Rotation is what turns "some node owns one" into "some round has one", which is why the bound is stated over rounds and not over a single attempt. Rotation is blind to who holds what, so it passes correct proposers with nothing to propose exactly as it passes faulty ones: that is the p in the bound, and where one node owns the only usable presignature it is n − 1 rounds.

∆timeout is not a constant: the round budget follows the shared schedule `round_timeout(r)` (a generous round 0, then geometric growth from a short floor to a hard ceiling), so rotating past the f \+ p proposers that cannot deliver costs the sum of `round_timeout` over the failed rounds. That sum is dominated by the round-0 budget while that count is small (20 s, then 2 s, 2.3 s, 2.6 s, ...): the ceiling is reached only after tens of rounds, so (f \+ p) times the ceiling is a bound, not an estimate.

*Rationale.* This is the property a user actually observes: a request that never reaches a signature is indistinguishable from the service being down.

*Enforcement*: 
The proposer starts as soon as every invitee has answered (Accept or Reject) and at least t have accepted, so with everyone honest and up-and-running the signature is produced at network speed in one generation round, independent of ∆timeout. Silent invitees do not hold the round hostage: 500 ms after it sends Propose the proposer goes ahead with whoever accepted, as long as that is still t. An alternative proposer gets a chance after ∆timeout.

Proposer election is a pure function of shared inputs (`proposer_per_round` over round, membership, entropy) and the deadline `round_timeout(r)` depends only on the round `r`. Therefore peers in the same round agree on the proposer and the deadline (D2). A round advance is only ever triggered locally (deadline, enough rejects, abort), but the round it advances to is the highest a peer has shown us, so a node that falls behind catches up in one bump by learning the rejector's current round rather than climbing one round per attempt. 

Three caveats remain: (i) organizing waits for the local active set to reach t (this node included) with no timeout of its own, so a wrongly short failure-detector view stalls the request while it lasts; (ii) the timeout is capped at a ceiling of 10 minutes; since two nodes can only transact while both are inside the same round, that ceiling less the messages a round has to fit is what caps the combined δ and indexing skew the schedule can absorb, though for NEAR-originated requests it is out of reach because L3's deadline expires first; (iii) a node proposes for at most 4 requests at a time, and a proposer that cannot get a slot inside its round budget burns the round, so a burst of requests this node is elected for costs rounds even with a perfectly healthy network.

### L2. Artifact supply.

*Property.* During a long-enough synchronous interval with ≥ t members (itself included) in the node's active set, a node below its artifact floor and under the network-wide cap eventually completes a generation, given its inputs (none for a triple pair, one owned triple pair for a presignature).

A node under its own floor still generates nothing while the network-wide potential is at the cap. That is intended, the pool being full, but it means the floor alone does not entail progress.

*Rationale.* L1 assumes a usable presignature is there to consume, so without supply that precondition eventually fails and signing stops while the network is otherwise perfectly healthy.

*Enforcement*: 
A node re-proposes every 100 ms while it is below its floor (`min_triples` / `min_presignatures`) and the network-wide potential is under the cap (`max_triples` / `max_presignatures`); concurrency counters free themselves as generation tasks finish and as proposals expire.  
Generation is skipped entirely while \< t nodes are in the active set, so the failure detector gates supply though never correctness.

### L3. Settlement

*Property.* Once a signature is produced with a correct, online owner, it is eventually accepted on-chain (on NEAR this must happen before the request's yield deadline).

*Rationale.* A signature that never reaches the chain is worth no more to the user than no signature at all, while the presignature spent producing it is gone either way.

For NEAR-originated requests this requires settling before the yielded promise's bounded lifetime expires (a hard deadline of 200 blocks \~= 200s)  

L1 and L3 draw on that one deadline, and the rounds spend it first: round 0 costs 20 s and later rounds start at 2 s and grow by 1.15, so about 19 further rounds fit inside 200 s. A NEAR request that needs more rounds than that cannot settle at all, however the settlement path is built, which is the constraint any republish or failover schedule has to fit into.

*Enforcement*: The owner republishes on a timer, retrying indefinitely with backoff capped at 60 s.
Currently not guaranteed, for two reasons. Only the successful instance's proposer publishes, and no other participant takes over, even though every participant holds the finished signature. And the retry itself lives in the publishing process, so what survives a restart is only what reached a confirmed checkpoint: on the checkpointed chains that includes the pending publish and its signature, while NEAR and Bitcoin produce no checkpoints at all and keep it in memory alone. On NEAR the 200 s yield deadline can also expire while the publisher is still backing off.

### L4. Mesh convergence

*Property.* During a long-enough synchronous interval, every correct, reachable committee member (re)enters each correct node's active set within bounded time.

*Rationale.* Without it a reconnecting node never resumes work, so an ordinary restart becomes an indefinite local outage instead of a transient one.

*Enforcement.* A peer reporting Running waits in Syncing, outside the active set, until a sync round-trip succeeds; for a correct, reachable peer in a synchronous interval it does, so the property holds. The bound is the poll interval, the round-trip, and the batch it rides in: syncs run concurrently but report as one group capped by `BROADCAST_TIMEOUT` (120 s), so a fast peer activates at the slowest peer's pace. A peer that becomes reachable just after a batch starts is not picked up by it either, since only one batch runs at a time, which puts the worst case at roughly two `BROADCAST_TIMEOUT`s. Per-peer reporting would cut that to the peer's own round-trip.