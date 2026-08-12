# **Protocol Properties** 

Draft, last updated 2026, August 12, 15:31 UTC

Goals:

* capture *what must hold* in the MPC node coordination layer and *why* to be able to reason about simplifications that improve robustness

Protocol properties defined below are separated into

* safety (nothing bad ever happens: no key leak, no unrequested signature)  
* liveness (every request eventually completes), and  
* efficiency (we try not to waste artifacts or rounds doing it, but it’s not the end of the world if we do create some waste (ideally bounded)).

Note that not all of the below has been implemented fully.

## 1\. Request lifecycle and its objects

* Sign request flow  
  1. request is finalized on-chain 
  2. indexed by each node's own indexer, assigned an request\_id  
  3. a per-node task organizes rounds (attempts) until one generation instance produces a signature  
  4. the successful generation's proposer submits it on chain  
  5. the contract emits settlement events (NEAR verifies the submitted signature via check\_ec\_signature; other chains accept any response as-is)  
  6. downstream process is responsible for event verification and exactly once semantics 

* Triple (artifact)
  * secret-shared random values produced in the background, consumed in pairs to build presignature,  
  * unique owner (node that coordinated its generation, for easier statesync and coordination in signature generation) and a set of holders (nodes storing its shares).  

* Presignature (artifact)
  * pre-computed, secret-shared ECDSA nonce (big\_r, and shares k, sigma)  
  * unique owner (node that coordinated its generation) and a set of holders (nodes storing its shares).  

* Posit: prepare phase leading up to an instance
  * proposer sends Propose message to each peer  
  * peers answer Accept/Reject  
  * proposer sends Start carrying the final participant list to each peer .  

* Instance : one attempt to run protocol to completion over a specific artifact and participant list
  * Signature: (sign\_id, presignature\_id) (the code's SignId wraps the request\_id above, same 32 bytes)  
  * Triple/presignature: identified by artifact id for triple/presignature generation  
    (picked by proposer uniformly at random for triple pair)  

  A request's round tries to establish a signature instance; since the artifact tentatively picked for this round can differ round to round, different rounds are  different instances. If a round is not successful, a new proposer is chosen deterministically (rotating over the nodes)

## 2\. System model

* n nodes; membership, threshold t, and epoch are fixed by the contract. Together with the public keys and whether the contract is `Running`, they form the **committee** a node operates under (`GovernanceInfo` in code).
Eeach node holds its own local, read-only snapshot of it, refreshed on contract update.
* Contract keeps committee state, requests and responses
  * (i) all nodes observe the same finalized sequence of requests and committee states, possibly at different times;  
  * (ii) nodes act only on finalized state (finalization definition may differ per chain).  
* Hybrid fault model.  
  * Liveness is argued under crash-recovery: correct nodes may halt and restart (otherwise never deviating). After restart the node's durable storage is assumed to be intact.  
  * Safety of S1–S4 must hold against f arbitrarily corrupted nodes.
    Two conditions bound f. 
    * f \< t keeps the adversary from assembling a signing quorum out of its own key shares; with f ≥ t it holds one and all bets are off. 
    * f \< 2t − n keeps any two participant lists of size t sharing at least one honest member, which is what stops one artifact being consumed by two otherwise disjoint lists (§S1). The second is the stronger whenever t \< n, so it is the bound assumed here. The contract sizes t at ⌊2n/3⌋ \+ 1 for n ≥ 5, which admits every f up to n − t, the same count the threshold leaves room to have offline, though the margin narrows to one node by n \= 100. Below n \= 5 the contract uses a simple majority instead, and n \= 3 does not satisfy the bound at all: with t \= 2 two lists share a single node, which may be the corrupted one.  
* Network  
  * Safety is guaranteed under asynchrony (no bounds on message delivery), while liveness is guaranteed for the periods where the network is synchronous (messages between honest nodes arrive within some bound δ, not assumed known) for long enough.  
    * Formally (see e.g., Shoup, DISC 2024): the network is δ-synchronous over \[a, b+δ\] if every message an honest node sends at time T in \[a, b\] reaches its honest recipient by T+δ ; liveness needs such an interval lasting longer than the current timeout. With unknown δ, the classic technique is to increase timeouts until progress is observed (DLS 1988, used as view-timeout doubling in PBFT and as a linear per-round schedule in Tendermint; the Simplex family instead assumes a known bound and fixes ∆timeout ≥ 3δ per slot). This implementation sits in between: the per-round schedule `round_timeout(r)` grows only up to a hard ceiling, which amounts to assuming δ never exceeds that ceiling; liveness is therefore argued for δ up to the ceiling, not for arbitrary finite δ (more details in Appendix)  
  * Links are fair-lossy (may drop messages), which every phase compensates for by timeout-and-retry, so during a synchronous interval, communication between live nodes is eﬀectively reliable and timely.
  * Channels are authenticated and encrypted. 
* Each node runs its own chain indexers and eventually observes every finalized request (assumption; liveness depends on it, safety does not).  
* The mesh active set is a local, unreliable failure detector: each node's own guess at which members are currently reachable and up-to-date (active), a subset of the participant set. It may be wrong, and no two nodes ever need the same guess; §6 D2 governs what may be derived from it. A reachable peer is additionally kept *out* of the active set while an initial or post-reconnect state sync runs (a transient Syncing state), so "active" is strictly narrower than "reachable".

## 3\. Safety properties

* **S1  One-shot artifacts are consumed at most once:** No presignature is used in signature shares for more than one sign request, and no triple pair for more than one presignature.
* **S2  Only indexed requests are signed:** An honest node contributes a signature share only to requests its own indexer delivered from a finalized chain state.  
* **S3  Membership and epochs change only on-chain:** No honest node adopts a participant set, threshold, or epoch other than from finalized contract state, and no node processes requests under a non-Running state. 
* **S4 Instance-local agreement:** Any two honest participants that reach the generating phase of the same instance use the same participant list or they abort.

Violating any of these is unacceptable in any execution within §2's fault bound.  See Appendix for more details.

## 4\. Liveness

Progress is guaranteed during a suﬃciently long synchronous interval, never at a fixed time. The precise bounds and the enforcing mechanisms are in the Appendix.

* **L1. Signature progress:** during a long-enough δ-synchronous interval with ≥ t correct participants online, a usable presignature (owner and holders online), and ≥ t nodes having indexed the request, the request produces a signature within bounded time (O(f)·∆timeout \+ one generation round). That such a presignature keeps existing is L2.  
* **L2. Artifact supply:** during a long-enough synchronous interval with ≥ t peers in the node's active set, a node below its artifact floor ( min\_triples or min\_presignatures ) eventually completes a generation, given its inputs (none for a triple, one owned triple pair for a presignature).   
* **L3. Settlement:** once a signature is produced with a correct, online owner, it is eventually accepted on-chain (on NEAR this must happen before the request's yield deadline).  
* **L4. Mesh convergence:** during a long-enough synchronous interval, every correct, reachable participant (re)enters each correct node's active set within bounded time. 

## 5\. Efficiency targets

E1. Amortized ≈ 1 presignature consumed per settled signature. 

E2. ≈ 1 generation instance per request at a time. 

Mechanisms striving towards these targets are deterministic proposer rotation, the posit round, and backoff if a a nodes is already generating.

Duplicate instances, duplicate on-chain responses, and wasted rounds are correct but wasteful: the contract settles a request on the first valid response and the rest are harmless. Consequently, any mechanism that serves only E-properties may be lossy, heuristic, or deleted; it must be judged on cost, not correctness.

## 6\. Design Invariants

Incomplete list of general, implementation-independent rules (the *how*) that keep the properties above (the *what*) true.
 
* D1. The chain is the sole arbiter. Request settlement and membership live on-chain. The off-chain layer must remain safe under arbitrary duplication, reordering, loss, and retry of its own actions. *Serves S2, S3 (safety-critical agreement is delegated to the chain) and is necessary for D4.*  
* D2. Anything two nodes must compute identically (shared input, e.g. "who proposes in round r") may depend only on contract state, request data (e.g. the entropy, which is chain-fixed per request, the transaction hash on Ethereum), and the round number, never on the local failure detector or local clocks.  Rationale: local views differ by design; deriving shared roles from them silently reintroduces the agreement problem this layer avoids. *Serves L1.*  
* D3. One-shot resources are single-writer. Consumption is initiated only by the recorded owner; every holder deletes on first use, durably before emitting anything derived from the artifact.  Losing an artifact (e.g., due to a crash) is acceptable; reusing one is not. *Serves S1.*  
* D4. Abort anywhere, retry fresh. Every phase must be abortable without cleanup obligations on peers, and retried with fresh resources or resources provably safe to reuse (i.e., derived only from D2's shared inputs, never from this attempt's own messages or local view, and never a D3 one-shot artifact). No step may assume any peer observed a previous attempt. *Serves L1, L2 and protects S1 on retry.*  
* D5. Local state is bounded. Any map, buffer, or cache keyed on something peers or requests can produce without limit must carry a size bound and an eviction rule. Rationale: memory-driven restarts are churn, and churn is what the liveness bounds spend themselves absorbing, so an unbounded structure turns a remote peer's behaviour into a local restart. *Serves L1, L2, L4.*

# **Protocol Appendix: Property Details and Precedents**

### S1. One-shot artifacts are consumed at most once

*Property.* No presignature is used in signature shares for more than one sign request, and no triple pair for more than one presignature.

*Why it matters.* Two ECDSA signatures on one nonce are two equations in the two unknowns (k, x): the private key follows. The per-request re-randomization (keyed on request id, request entropy, and big\_r) does not change this: the delta is public and both signatures share the same underlying k. It only makes the two *derived* signatures distinct, which is why even two requests with equal payloads count as "different".

*Enforcement* Three local rules:

1. Single writer. Only the artifact's recorded owner initiates consumption, checked by every holder rather than trusting the proposer.
2. Delete-on-first-use at every holder when generation starts. The proposer removes the artifact from storage and every deliberator takes its local share, so a later attempt fails at any holder that already used it. The removal must reach durable storage *before* any message derived from the artifact is sent, or a holder that crashes and recovers resurrects the share and honestly serves a second request.
3. Instance naming. Every message names its instance, and a node feeds each one only to the instance it names.

*Why deleting at each holder suffices.* Per-holder deletion by itself would still allow two **disjoint** sets of honest holders to each serve their own first request on one artifact. Quorum intersection rules that out: both instances need a participant list of at least t (the posit phase starts an instance only once t peers have accepted), any two such lists share at least 2t − n members, and f \< 2t − n (§2) leaves at least one of those shared members honest. That holder burned the artifact on the first instance and refuses the second, which therefore never reaches t shares. Consuming one artifact twice would take f ≥ 2t − n, outside the model.

*Hardening.* Binding the artifact to its first consumer rather than merely deleting it (on first use persist presignature\_id → sign\_id, refuse that presignature under any other sign\_id, and keep the record as long as the request can be retried) would hold S1 even where the intersection argument does not reach: at n \= 3, and at large n where the margin is a single node. It stays local and single-writer, so it costs no agreement.

### S2. Only indexed requests are signed

*Property.* An honest node contributes a signature share only to requests its own indexer delivered from a finalized chain state.

*Why it matters.* A signature is spendable authority, so a node that signs anything its own chain view did not finalize gives peers a way to obtain signatures for transactions no user ever requested.

*Enforcement*: signature tasks are spawned exclusively from local indexer output, and posit messages for unknown sign ids are buffered, never answered. 

### S3. Membership and epochs change only on-chain

*Property.* No honest node adopts a participant set, threshold, or epoch other than from finalized contract state, and no node processes requests under a non-Running state.

*Why it matters.* Every other safety claim here is stated in terms of n, t and the participant set, so a node acting on an unfinalized committee quietly voids the fault bound the rest of the document argues against.

*Enforcement*: 
The contract's ProtocolState is Initializing, Running, or Resharing; only Running carries a usable participant set, threshold, and epoch. A node's committee (§2) is its local snapshot of that state as reported by the chain's RPC provider, with the three variants flattened to a single Running flag. It is not agreed on directly: a node's committee is correct exactly when its snapshot matches the finalized contract state.

Currently enforced by: the committee is a snapshot of contract state; tasks pause whenever the contract is not Running.

### S4. Instance-local agreement

*Property.* Any two honest participants that reach the generating phase of the same instance use the same participant list or they abort.

*Why it matters.* Each node scales its signature share by Lagrange coefficients taken from its own participant list, so nodes working from different lists cannot combine into a valid signature, and catching the divergence turns a guaranteed dead end into a clean abort.

An instance is identified by (sign\_id, presignature\_id) for signing, and analogously by artifact id for triple/presignature generation.

*Enforcement*: The instance's proposer alone determines the participant list and sends it in Start to each accepter; anything inconsistent is rejected and the instance aborts (§D4). Uniqueness of the dictator per instance follows from S1's single-writer rule: only the presignature's owner can open an instance on it. No agreement *across* instances is claimed anywhere. Two rounds of the same request may overlap, and safety must not (and does not) depend on that never happening.

This holds even against a Byzantine proposer, at a liveness cost. A malicious proposer can send divergent lists to different honest accepters, but each honest node scales its signature share by the Lagrange coeﬃcients of *its own* list, so mismatched lists never reconstruct a valid signature: the combine fails and the instance aborts. The forbidden event (two honest nodes proceeding to completion on different lists) is therefore unreachable; the worst outcome is an abort, never a bad signature. That is why S4 is enforced by detect-and-abort rather than prevention (§2).

### L1. Signature progress.

*Property.* During a long-enough δ-synchronous interval with ≥ t correct participants online, a usable presignature (owner and holders online), and ≥ t nodes having indexed the request, the request produces a signature within bounded time (O(f)·∆timeout \+ one generation round). That such a presignature keeps existing is L2.

*Why it matters.* This is the property a user actually observes: a request that never reaches a signature is indistinguishable from the service being down, and on NEAR the yield deadline makes that outcome permanent.

Spelled out, given a

* δ-synchronous interval long enough,  
* ≥ t correct participants online throughout,  
* a usable presignature whose holders are online and owner is correct and online (*that such a presignature keeps existing is L2)*  
* and ≥ t nodes having indexed the request when the interval starts,

then the request produces a signature within bounded time (O(f)·∆timeout \+ one generation round). ∆timeout is not a constant: the round budget follows the shared schedule `round_timeout(r)` (a generous round 0, then geometric growth from a short floor to a hard ceiling), so rotating past f dead proposers costs the sum of `round_timeout` over the failed rounds, at most f times the ceiling.

How it is meant to work, combines two regimes  
(i) Optimistic (honest, reachable proposer). The proposer starts the instant every invitee has Accepted (meets\_totality()), so the signature is produced at network speed, one generation round, independent of ∆timeout. (ii) Advance (crashed / slow proposer). Rotation must carry all nodes past the bad proposer to the next round within ∆timeout \+ O(δ).

Mechanisms: election is a pure function of shared inputs (`proposer_per_round` over round, membership, entropy) and the deadline `round_timeout(r)` depends only on r, so peers that agree on the round agree on the proposer and the deadline (D2). Rounds still advance on local timeouts only; a node that falls behind catches up in one `bump_round`, because StaleRound rejects carry the rejector's current round (sent from both the deliberator and the proposer path) and the round survives a task respawn instead of resetting to 0. Two caveats remain: organizing waits for the local active set to reach t with no timeout of its own, so a wrongly short failure-detector view stalls the request while it lasts (the same local-active gate as L2); and the schedule is capped at its ceiling, so the advance bound holds only while the real δ stays under that ceiling (§2).

### L2. Artifact supply.

*Property.* During a long-enough synchronous interval with ≥ t peers in the node's active set, a node below its artifact floor ( min\_triples or min\_presignatures ) eventually completes a generation, given its inputs (none for a triple, one owned triple pair for a presignature).

*Why it matters.* L1 assumes a usable presignature is there to consume, so without supply that precondition eventually fails and signing stops while the network is otherwise perfectly healthy.

Spelled out, if

* the network is synchronous for a suﬃciently long interval and  
* ≥ t peers are in the node's active set,

then a node holding fewer artifacts than its floor (min\_triples / min\_presignatures) eventually completes a generation, provided its inputs are available: none for a triple, one owned triple pair for a presignature.

Presignature supply therefore depends on triple supply; the two are the same property under diﬀerent input preconditions.

Mechanism: re-proposes every 100 ms while a node is below its floor; concurrency counters free themselves as generation tasks finish and as proposals expire.  
Local-active gate: generation is skipped entirely while active.len() \< threshold, so the failure detector gates supply though never correctness.

### L3. Settlement

*Property.* Once a signature is produced with a correct, online owner, it is eventually accepted on-chain (on NEAR this must happen before the request's yield deadline).

*Why it matters.* A signature that never reaches the chain is worth no more to the user than no signature at all, while the presignature spent producing it is gone either way.

For NEAR-originated requests this requires settling before the yielded promise's bounded lifetime expires (a hard deadline outside our control, 200 blocks \~= 200s)  
For other chains it requires the publisher to eventually (re)submit the signature until it lands.

Currently not guaranteed, since there's no timer-based resubmit.

*Deadline note (NEAR).* A hard deadline turns L1 \+ L3 into a joint time budget: the rounds a request burns, one generation round, and submission must together fit inside \~200 s. The round schedule does not enforce this: cumulative `round_timeout` crosses 200 s after roughly 20 rounds, and a single ceiling-length round (600 s) exceeds the deadline on its own. The node only observes a miss (a delayed-request watcher and the SIGN\_REQUEST\_DELAYED metric), it does not abort or prioritize. Whether the budget is met is therefore an emergent property of how few rounds a request needs, which is exactly what L1 bounds during synchrony.

### L4. Mesh convergence

*Property.* During a long-enough synchronous interval, every correct, reachable participant (re)enters each correct node's active set within bounded time.

*Why it matters.* Without it a reconnecting node never resumes work, so an ordinary restart becomes an indefinite local outage instead of a transient one.

*Why it is a property, not an assumption.* L1 and L2 are conditioned on the local active set holding ≥ t peers, and the active set is this layer's own failure detector (§2), maintained by its own code. Its recovery is therefore something the layer must provide; without L4, nothing says the gate that L1 and L2 wait behind ever opens. The consumers of the gate do not bound the wait themselves: organizing waits for ≥ t active peers with no timeout of its own (`wait_for_active_participants`), and artifact generation is skipped entirely while the view is short (L2's local-active gate).

*Current state.* Every transition into Active, including any reconnection, first forces a state sync: the peer is held in Syncing, outside the active set, until a sync round-trip to it succeeds *and* its stale holder entries are pruned locally; only that success path flips it to Active. There is no fallback activation on failure: the peer stays queued and is retried, so convergence is one round-trip on the happy path but unbounded when syncs keep failing. Broadcasts are also serialized with a 120 s deadline (`BROADCAST_TIMEOUT`), so a single unresponsive peer stretches every broadcast cycle to the full deadline and delays the activation of healthy reconnectors behind it. While the resulting view is short, every request on the node stalls (L1) and supply halts (L2). The sync's work is garbage collection of stale holder data, not a correctness gate: only owners initiate consumption (D3), so a stale view costs a MissingArtifact round at worst. Convergence time is log-derivable from the status-transition lines.

### Round-timeout precedents (§2)

Increasing round durations for unknown δ originates in DLS 1988 and appears as view-timeout doubling in PBFT. Tendermint ships a linear per-round schedule in production, reset per height (`timeout_propose + r · timeout_propose_delta`). ICC's recommended delay functions are linear in a shared index, the proposer's rank (∆prop(k) \= 2∆bnd·k, ∆ntry(k) \= 2∆bnd·k \+ η); its production implementation (dfinity/ic `rs/consensus`, `get_block_maker_delay` / `get_adjusted_notary_delay`) ships that linear-in-rank base and keys further adaptivity to a *shared progress gap* rather than learned local timing: the rank component is multiplied by 1.5^(notarized − finalized gap) with rank 0 exempt, execution lag adds a linear backlog delay with an exemption where the gap has a known benign cause (upgrades), and oversized gaps hard-stop the notary. These adjustments carry no hysteresis state: each is a memoryless function of the current gap (or of a sliding window of recent blocks), so the delay relaxes automatically when the gap closes; the base constants come from the registry and are never adapted at runtime. The round number r is the same kind of progress index, and its per-request reset gives it the same relaxation-by-construction, which is why no relaxation policy appears anywhere in the schedule. Simplex (Shoup 2024\) instead fixes ∆timeout ≥ 3δ per slot with δ effectively assumed bounded, deferring unknown δ to "standard techniques of dynamically increasing timeouts."

The shipped schedule (`round_timeout`) grows gently (×23/20 per round) from a short floor to a hard ceiling instead of PBFT-style doubling: most failed rounds here are dead-or-unable proposers, not a slow network, so slow growth wastes the least on them and `bump_round`'s jumps land on sane values; doubling wins only at converging to a very large unknown δ, an abnormal regime, and the ceiling bounds the δ the schedule can absorb.
