# **Protocol Properties** 

Draft, last updated 2026, July 23, 15:31 UTC

Goals:

* capture *what must hold* in the MPC node coordination layer and *why* to be able to reason about simplifications that improve robustness

Protocol properties defined below are separated into

* safety (nothing bad ever happens: no key leak, no unrequested signature)  
* liveness (every request eventually completes), and  
* efficiency (we try not to waste artifacts or rounds doing it, but it’s not the end of the world if we do create some waste (ideally bounded)).

The coordination layer neither achieves nor requires consensus; safety-critical agreement is delegated to the on-chain contract or avoided via single-writer ownership, and per-instance coordination is leader-dictated agreement with abort, never consensus.

## 1\. Request lifecycle and its objects

* Sign request flow  
  finalized on-chain → indexed by each node's own indexer, assign request\_id  
  → a per-node task organizes rounds (attempts) until one generation instance produces a signature  
  → the proposer submits it on chain  
  → the contract settles the request and emits events (NEAR verifies the submitted signature via check\_ec\_signature; other chains accept any response as-is)  
  → downstream process is responsible for event verification and exactly once semantics (on non-NEAR chains this includes signature verification)

* Triple (artifact)

  * secret-shared random values produced in the background, consumed in pairs to build presignature,  
  * unique owner (node that coordinated its generation, for easier statesync and coordination in signature generation) and a set of holders (nodes storing its shares).  
* Presignature (artifact)

  * pre-computed, secret-shared ECDSA nonce (big\_r, and shares k, sigma)  
  * unique owner (node that coordinated its generation) and a set of holders (nodes storing its shares).  
* Posit  
  prepare phase leading up to an instance

  * proposer sends Propose to each peer  
  * peers answer Accept/Reject  
  * proposer sends Start carrying the final participant list to each peer .  
* Instance  
  one attempt to run protocol to completion over a specific artifact and participant list

  * Signature: (sign\_id, presignature\_id) (the code's SignId wraps the request\_id above, same 32 bytes)  
  * Triple/presignature: identified by artifact id for triple/presignature generation  
    (picked by proposer uniformly at random for triple pair)  
  * Note: Serhii is currently looking into running at most one instance at a time (to avoid having many rounds that don’t agree on who is participating)

  A request's round attempts to establish an instance; since the artifact tentatively picked for this round (peeked, not yet committed) can differ round to round, different rounds are generally different instances.

## 2\. System model

* n nodes; membership, threshold t, and epoch are fixed by the contract. Changing them (join/leave/resharing) is real consensus, and it happens on-chain only (§S3).  
  * (i) all nodes observe the same finalized sequence of requests and governance states, possibly at different times;  
  * (ii) nodes act only on finalized state (finalization definition may differ per chain).  
* Hybrid fault model.  
  * Liveness is argued under crash-recovery: correct nodes may halt and restart (otherwise never deviating). After restart the node's durable storage is assumed to be intact.  
  * Safety of S1–S4 should hold up against up to f ≤ t-1 arbitrarily corrupted nodes; with f ≥ t the adversary holds a signing quorum of key shares and all bets are off.  
* Network  
  * Safety is guaranteed under asynchrony (no bounds on message delivery), while liveness is guaranteed for the periods where the network is synchronous (messages between honest nodes arrive within some bound δ, not assumed known) for long enough.  
    * Formally (see e.g., Shoup, DISC 2024): the network is δ-synchronous over \[a, b+δ\] if every message an honest node sends at time T ≤ b reaches its honest recipient by T+δ ; liveness needs such an interval lasting longer than the current timeout. Because δ is unknown, timeouts must increase until progress is observed (the DLS 1988 technique, used as view-timeout doubling in PBFT and as a linear per-round schedule in Tendermint; the Simplex family instead assumes a known bound and fixes ∆timeout ≥ 3δ per slot)  
  * Links are fair-lossy (may drop messages), which every phase compensates for by timeout-and-retry, so during a synchronous interval, communication between live nodes is eﬀectively reliable and timely (caveat: currently not guaranteed due to message queue implementation).  
  * Channels are authenticated and encrypted.  
* Each node runs its own chain indexers and eventually observes every finalized request (assumption; liveness depends on it, safety does not).  
* The mesh active set is a local, unreliable failure detector: each node's own guess at which members are currently reachable and up-to-date (active): a subset of the participant set, never a substitute for it.  It may be wrong, and no two nodes ever need the same guess (currently, this does not hold, see §D3). A reachable peer is additionally kept *out* of the active set while an initial or post-reconnect state sync runs (a transient Syncing state, §7.2), so "active" is strictly narrower than "reachable".

## 3\. Safety properties

* **S1  No cross-request use of artifacts:** No honest node emits a signature share derived from a given presignature for more than one sign request.  
* **S2  Only indexed requests are signed:** An honest node contributes a signature share only to requests its own indexer delivered from a finalized chain state.  
  Note: maybe add tests or other measures to prevent this  
* **S3  Membership and epochs change only on-chain:** No honest node adopts a participant set, threshold, or epoch other than a finalized contract state reported by RPC service provider.  
* **S4 Instance-local agreement:** Any two honest participants that reach the generating phase of the same instance use the same participant list or they abort.

Violating any of these is unacceptable in any execution with fewer than t corrupted nodes.  See Appendix for more details.

## 4\. Liveness

Progress is guaranteed during a suﬃciently long synchronous interval, never at a fixed time. The precise bounds, the two regimes behind L1, and the enforcing mechanisms are in the Appendix.

* **L1. Signature progress:** during a long-enough δ-synchronous interval with ≥ t correct participants online, a usable presignature (owner and holders online), and ≥ t nodes having indexed the request, the request produces a signature within bounded time (O(f)·∆timeout \+ one generation round). That such a presignature keeps existing is L2.  
* **L2. Artifact supply:** during a long-enough synchronous interval with ≥ t peers in the node's active set, a node below its artifact floor ( min\_triples / min\_presignatures ) eventually completes a generation, given its inputs (none for a triple, one owned triple pair for a presignature). Presignature supply therefore rests on triple supply: the two are one property under diﬀerent input preconditions.  
* **L3. Settlement:** once a signature is produced with a correct, online owner, it is eventually accepted on-chain.

Currently L1 and L3 are not met; L2 holds only while the node's local active set stays ≥ t (see §7.1, §7.2, and Appendix).

## 5\. Efficiency targets

E1. Amortized ≈ 1 presignature consumed per settled signature. (Currently violated on any failed generation)

E2. ≈ 1 generation instance per request at a time. Best-effort via rotation, the posit round, and the AlreadyGenerating back-off (request/posit.rs). After §8 Move 1: via deterministic rotation and the reject-while-generating reply.

Duplicate instances, duplicate on-chain responses, and wasted rounds are correct but wasteful: the contract settles a request on the first valid response and the rest are harmless. Consequently, any mechanism that serves only E-properties may be lossy, heuristic, or deleted; it must be judged on cost, not correctness.

## 6\. Design Invariants

These are design invariants: the *how* that keeps the properties (the *what*) true.

* D1. The chain is the sole arbiter. Request settlement and membership live on-chain. The off-chain layer must remain safe under arbitrary duplication, reordering, loss, and retry of its own actions. *Serves S2, S3 (safety-critical agreement is delegated to the chain) and underwrites D2.*  
* D2. Abort anywhere, retry fresh. Every phase must be abortable without cleanup obligations on peers, and retried with fresh resources (or resources provably safe to reuse, cf. §7.4). No step may assume any peer observed a previous attempt. *Serves L1, L2 (retry drives progress) and protects S1 on retry.*  
* D3. Peer-identical values come from shared inputs only. Anything two nodes must compute identically (e.g. "who proposes in round r") may depend only on contract state, request data (e.g. the entropy, which is chain-fixed per request, the transaction hash on Ethereum), and the round number, never on the local failure detector or local clocks. The active set may steer *scheduling* (what to attempt, whom to include as candidates), never the *identity* of a coordination role. Rationale: local views differ by design; deriving shared roles from them silently reintroduces the agreement problem this layer avoids. *Serves L1 (its violation is the §7.1 election bug).*  
  * Unlike D1/D2/D4, this rule is currently violated:  state.round and the proposer are computed by filtering candidates through the local active set (`request/organize.rs:83-97`).  
    §8 Move 1 proposes the fix.  
* D4. One-shot resources are single-writer. Consumption is initiated only by the owner; every holder deletes on first use, durably before emitting anything derived from the artifact (§S1). Losing an artifact (owner crash) is acceptable; reusing one is not. *Serves S1.*

