# System model

What the protocol docs assume about nodes, faults, the network and the chains.
The properties the design guarantees, and the design invariants that keep them, are in [protocol-properties.md](protocol-properties.md).

* On-chain information
  * Entities: n nodes; membership, threshold t, and epoch are fixed by the governance contract. 
    * Together with the public keys and whether the contract is `Running`, they form the **committee** a node operates under (`GovernanceInfo` in code).
    * Each node holds its own local, read-only snapshot of it, refreshed on contract update. Throughout, *committee* and *committee member* are contract-scoped, while *participant* and *participant list* always refer to one instance.
    * The floor for t is ⌊2n/3⌋ \+ 1 for n ≥ 5 and ⌊n/2⌋ \+ 1 for n \< 5.
      Every join and kick resets t to the floor, and a threshold vote can set it to any value from the floor to n − 1.
      The value given at initialization must be at most n, but nothing checks that it is at least the floor, so a network can start outside the model.
      At the floor, t meets the conditions on f under the *Hybrid fault model* for every f with n ≥ 3f \+ 1; a value above n − f gives up liveness.  
  * Request and response (per supported chain): 
  
  (i) all nodes observe the same finalized sequence of requests and committee states, possibly at different times;  
  (ii) nodes act only on finalized state (finalization definition may differ per chain).  
* Hybrid fault model.  
  * Liveness is argued under crash-recovery: correct nodes may halt and restart (otherwise never deviating). After restart the node's durable storage is assumed to be intact.  
  * Safety must hold against f arbitrarily corrupted nodes, with n ≥ 3f \+ 1.
    Three conditions bound f.
    * f \< t keeps the adversary from assembling a signing quorum out of its own key shares; with f ≥ t it holds one and all bets are off. 
    * f \< 2t − n makes any two participant lists share at least one honest member, which is what stops one artifact being consumed by two otherwise disjoint lists.
    * t ≤ n − f lets the correct nodes sign on their own; liveness needs it, safety does not.
* Network  
  * Safety is guaranteed under asynchrony (no bounds on message delivery), while liveness is guaranteed for the periods where the network is synchronous (messages between honest nodes arrive within some bound δ, not assumed known) for long enough.  
    * Formally (see e.g., Shoup, DISC 2024): the network is δ-synchronous over \[a, b+δ\] if every message an honest node sends at time T in \[a, b\] reaches its honest recipient by T+δ ; liveness needs such an interval lasting longer than the current timeout. With unknown δ, the classic technique is to increase timeouts until progress is observed (DLS 1988, used as view-timeout doubling in PBFT and as a linear per-round schedule in Tendermint; the Simplex family instead assumes a known bound and fixes ∆timeout ≥ 3δ per slot). This implementation sits in between: the per-round schedule `round_timeout(r)` grows only up to a hard ceiling. Liveness is therefore argued for δ up to a fraction of the ceiling, not for arbitrary finite δ (details in [protocol-properties.md L1](protocol-properties.md#l1-signature-progress))  
  * Links are fair-lossy (may drop messages), which every phase compensates for by timeout-and-retry, so during a synchronous interval, communication between live nodes is effectively reliable and timely.
  * Channels are authenticated and encrypted: a node accepts a message only from a current committee member, signed by that member (details in *Authenticated channels* in [protocol-properties.md](protocol-properties.md#authenticated-channels)).
* Each node runs its own chain indexers and eventually observes every finalized request (assumption; liveness depends on it, safety does not).  
* Chain state reaches a node only through its RPC provider. Different nodes can use different RPC providers. A node its provider misleads is faulty, one of the f, so the model holds only if the nodes served by misleading providers and all other faulty nodes are at most f together.  
* The mesh active set is a local, unreliable failure detector: each node's own guess at which members are currently reachable and up-to-date (active), a subset of the committee. It may be wrong, and no two nodes ever need the same guess; D2 in [protocol-properties.md, Section 6](protocol-properties.md#6-design-invariants) governs what may be derived from it. A reachable peer is additionally kept *out* of the active set while a state sync runs (a transient Syncing state), whether that sync is the initial one, a post-reconnect one, or one triggered by the peer's `MissingArtifact` reject of a presignature we list it as holding (only when the rejects end the round), so "active" is strictly narrower than "reachable".
