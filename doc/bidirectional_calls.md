# Bidirectional calls: entities, API, properties

## 1. Entities and Happy Path

* *Application contract*: the contract a developer writes on the source
  chain. "The contract" below means this one.
* *Library*: code we ship, embedded in the application contract. Everything
  in section 4.1 runs inside the application contract's own transactions and
  storage. A contract that bypasses the library is on its own.
* *Signet contract*: our contract on the source chain, through which
  requests, signatures and responses are published. It holds no per-
  application state.
* *MPC network*: the nodes that sign and attest.
* *Broadcaster*: whoever submits the signed transaction to the destination
  chain. Untrusted; the design does not depend on who it is.

Happy path:

1. The application contract calls the library, which records the call and
   asks the signet contract to emit a sign request.
2. The MPC signs the transaction, publishes the signature on the source
   chain, and starts looking for the transaction on the destination chain.
3. Any entity can broadcast the signed transaction to the destination chain.
4. When the transaction is finalised on the destination chain, the MPC
   attests the outcome and publishes the attestation to the signet contract.
5. Once delivered to the application contract, the library accepts or drops
   it, and on acceptance runs the contract's response handler.

## 2. Vocabulary

* *Transaction*: the bytes of an unsigned destination-chain transaction.
* *Transaction ID*: the identifier under which the destination chain records
  a submitted transaction, computable from the transaction and the signature
  in the encoding that chain accepts. ECDSA has two encodings that verify
  alike, of which EVM takes the low-s one, so a re-encoded signature names
  the same transaction rather than a new one.
* *Request*: what a call asks for, the tuple (tx, dest, key, schemas): the
  transaction, its destination chain, the key parameters to sign it with,
  and the schemas for decoding its output and encoding the response. Written
  `req` in the pseudocode.
* *Request ID* (rid): a collision-resistant hash over (contract, tx, dest,
  key) in a length-committing encoding, so within one source chain a rid
  names one execution and nothing else: rid(a) = rid(b) <=> a.tx = b.tx. The
  schemas are outside it, so that two calls for one transaction cannot both
  be outstanding. The key parameters must be canonical, or two rids could
  name one execution.
* *Outcome*: a pair (kind, data), with four kinds.
  * *Executed*: the transaction was finalised, succeeded, and its return
    data decoded against the contract's schema; data is that decoded return
    data.
  * *Failed*: the transaction was finalised and reverted; data is a bounded
    prefix of the revert reason.
  * *Unviable*: a finalised transaction carrying other bytes took tx's
    nonce, so tx can never be included; data is empty.
  * *Undecodable*: the transaction was finalised and succeeded, but its
    return data does not decode against the contract's schema; data is a
    bounded prefix of that return data.
* *Attestation key*: a signing key the MPC derives from its root key, the
  source chain and the contract, used for nothing but attestations to that
  contract.
* *Attestation*: a statement (rid, height, outcome) signed with the
  attestation key of rid's contract, each field length-committed. height is
  the height of the block the outcome describes: the execution's, or for
  Unviable the block that took the nonce.
* *Response*: an attestation delivered to its contract.

Events for a call c made by the application contract:

* call(c): the contract asks for transaction tx(c) to be signed and executed
  on destination chain dest(c). It is identified by rid(c).
* exec(c): tx(c) is included in a finalised destination block.
  height(exec(c)) is that block's height.
* resp(c, o): a response for rid(c) carrying outcome o.

How a call ends, as seen by the application contract:

* *Refused*: the library rejects call(c), and the caller learns it at once.
* *Accepted*: the contract takes a resp(c, o) as the answer to call(c) and
  runs its response handler (section 3.1).
* *Unanswered*: no response is ever accepted.

A call is *outstanding* from the moment it is made until a response to it is
accepted; the library records it as an entry in `outstanding` (section 4.1).
An unanswered call is outstanding forever, and from inside the contract this
is indistinguishable from a response that has not arrived yet.

*Happens-before*: A happens-before B if A caused B. On one chain, an earlier
block happens-before a later one. Across chains, an execution happens-before
the source block in which a response attesting it lands. The relation is
transitive.

## 3. API and guarantees

### 3.1 API offered to the application contract

```
sign_bidirectional(
    transaction: SerializedTransaction,
    destination: ChainId,
    key:         (DerivationPath, KeyVersion, SigningScheme),
    schemas:     (OutputDeserialization, ResponseSerialization),
) -> RequestId | Refused
// the four arguments together are the request, written req below

// implemented by the application contract, called by the library
on_response(rid: RequestId, outcome: (kind, data))
```

The transaction is passed in full rather than as a commitment. On EVM the
transaction ID is computable only from the bytes and the signature. Where
the bytes travel, call data or an event, is a cost question this design does
not settle.

### 3.2 Guarantees

G1 to G4 are safety, G5 is liveness. G2 and G5 together give "exactly one
accepted response per call whose transaction executes".

* G1 Causal order: an accepted resp(c, o) reports destination state that
  does not happen-before call(c).
* G2 At-most-once: for each execution, at most one response reporting it is
  ever accepted, however many calls named its transaction and however many
  times it is attested.
* G3 Finality: an outcome is reported only once the destination state it
  describes is final.
* G4 Integrity: an accepted resp(c, o) carries the true outcome of tx(c),
  never of another transaction.
* G5 Delivery: if tx(c) is finalised under a signature the MPC issued and
  published for call(c), a resp(c, o) is eventually accepted.

### 3.3 Assumptions

* Chains
  * Finality: no re-orgs on source or destination chain below the finality
    criterion the MPC uses to index requests and attest outcomes.
  * Payload-level replay protection: once a transaction has executed on the
    destination chain under a key, no transaction with the same bytes executes
    again under that key, whatever signature it bears (EVM account nonce, spent
    UTXO, Solana durable nonce). Solana transactions using a recent blockhash
    do not qualify; see open points.
  * Source and destination chains eventually make progress: an outage only
    delays delivery
* Contracts and library
  * Durable contract state: the library's state (section 4.1) survives upgrades
    and migrations. A contract that keeps its key and loses this state can be
    replayed against everything it ever executed.
  * On Midnight, someone enqueues every published response and runs `process`
    (section 4.2).
* MPC
  * at most f of the n nodes are faulty, a signature or attestation needs a
    threshold t of participants with f < t <= n - f, so faulty nodes alone
    cannot produce one and honest nodes alone can, and honest nodes eventually
    publish. The contract sets t = floor(2n/3) + 1, which is 2f+1 at n = 3f+1.
  * Honest nodes observe the same finalised destination state, receipts and
    return data included, and compute the attestation content as the same pure
    function of receipt and schemas, which an upgrade does not change for
    requests already made; otherwise nodes split and no attestation reaches
    the threshold.

## 4. Pseudocode and properties per entity

Each entity is an event handler over its own state. `drop` means the event
has no effect. Key versions are omitted throughout: `attestation_key(self)`
stands for the key at the version the contract uses.

### 4.1 Library (inside the application contract)

```
state (per application contract):
    last_seen:   ChainId -> Height       // initialised as described below
    outstanding: RequestId -> Entry
    Entry = { dest: ChainId, known: Height }

on sign_bidirectional(req) from the application logic:
    rid = request_id(self, req)
    if rid in outstanding:                                // C1
        return Refused
    outstanding[rid] = { req.dest, known: last_seen[req.dest] }   // C2
    signet.sign_bidirectional(rid, req)
    return rid

on response(rid, att = (kind, height, data), sig):
    if rid not in outstanding:                          // C3a
        drop
    e = outstanding[rid]
    if not verify(sig, H(rid || att)):                  // C3b
        drop
    if height <= e.known:                               // C3c
        drop
    last_seen[e.dest] = max(last_seen[e.dest], height)  // C3d
    delete outstanding[rid]                             // C4
    self.on_response(rid, (kind, data))
```

The entry keeps `dest` because the rid is a hash and cannot yield it, and
C3d needs it to pick the last_seen to raise.

When the library starts tracking a destination, last_seen[dest] starts at
dest's finalised height at that moment. At deployment and on the first call
to a new destination 0 is equivalent, since nothing has executed under the
contract's key there yet. At an upgrade from a version without last_seen a
lower start would let a response to a call answered before the upgrade be
accepted again.

Properties:

* C1 A call is refused while an entry with the same rid is outstanding.
* C2 Every outstanding entry records last_seen[dest] at creation.
* C3 A response is accepted only if it verifies, an entry for its rid is
  outstanding, and its height is strictly above that entry's recorded
  height. Acceptance raises last_seen to at least that height.
* C4 Entries are removed by acceptance only. No timers.

### 4.2 Library on Midnight: inbox and processing

Midnight has two programming languages, Impact and Compact

Compact generates a proof against a snapshot of the contract's state and fails at inclusion if any state it read has changed, it then issues impact instructions to change the state of the ledger. Some of our circuits take 30 seconds to prove. Section 4.1 reads last_seen on every call (C2) and writes it on every response (C3d), so a response landing while a call is being proven fails that call, and the contract handles at most one message per proving time.

Impact runs on the tip of the chain, and is a simple stack machine.

To avoid this, ordering and processing are separated:

First we put the call, or validated response into the inbox/outbox, as a compact call.

We then issue Impact ops which stamp with and update the last seen on these calls/responses.

```
case message of
    Call(rid, dest) =>
        outstanding[rid].known <- copy last_seen[dest]
    Response(rid, chain_id, height, outcome, sig) =>
        last_seen[chain_id] <- max height last_seen[chain_id]
```

We then emit the call_bidirectional request, or process the response.

* A call is made, in the sense of C2, when it is processed rather than
  enqueued, so its known height is last_seen at processing time. A Call
  carries the application's continuation, which runs then with the return
  value of sign_bidirectional, Refused included: this is where a Midnight
  caller learns of a refusal.

What must hold is that every message enters through the inbox, is processed
exactly once, and that `process` touches only the entries it deletes.

Property:

* C5 On Midnight, calls and responses are enqueued without touching shared
  state and processed in one total order; C1 to C4 hold for the processed
  sequence.

### 4.3 Signet contract (per source chain)

It holds no per-application state, verifies nothing, and anyone may call
it. It emits three events:

* `SignRequest { contract, rid, req }`, when a contract asks for a
  signature.
* `Signature { rid, signature }`, when a signature is published, for the
  broadcaster.
* `Response { contract, rid, att, sig }`, when an attestation is published.
  Where the chain allows it, the contract's `response` handler is called in
  the same transaction.

The library verifies responses (C3b) and the MPC verifies the requests and
responses it reads (section 4.4).

### 4.4 MPC network

Written as if the network were one process; the real one is a threshold
protocol whose result is what this process outputs. The state below is per
source chain, so a rid from one chain never meets a rid from another.

```
authentic(contract, rid, req): bool
    the request provably comes from `contract`, and rid recomputes from it

processable(req): bool
    req.dest parses to a chain this MPC can watch
    key derivation is valid: parameters canonical, key derivable for the
      source chain, path not the attestation key's
    req.tx is non-empty, parses as an unsigned transaction in dest's
      format, commits to dest (EVM: carries its chain id), and attaching
      any signature yields a well-formed signed transaction
    req.schemas are valid for dest and source chain respectively

state:
    pending: RequestId -> Entry
    Entry = { req, contract, signatures: Set<Signature>, attestation? }

on SignRequest { contract, rid, req } finalised on the source chain:
    if not authentic(contract, rid, req):                 // M1
        drop
    if rid in pending:                                    // repeat
        drop
    if processable(req):                                  // M4
        pending[rid] = { req, contract, signatures: {} }
        signature = threshold_sign(req.tx, derived_key(contract, req.key))   // M1
        pending[rid].signatures.add(signature)
        publish_signature(rid, signature)

on Signature { rid, signature } finalised on the source chain:
    if rid in pending and signature verifies:
        pending[rid].signatures.add(signature)

on destination block at height h finalised on chain dest:
    for (rid, e) in pending with e.req.dest = dest, e.signatures nonempty,
      and no e.attestation:
        ours = { txid(s, e.req.tx) for s in e.signatures }
        if some id in ours has a receipt r, finalised at height h':
            (kind, data) = decode(r, e.req.schemas)         // Undecodable
            attest(rid, (kind, h', data))                   // if not (M5)
        else if this block holds a finalised transaction that is not in
          ours and uses e.req.tx's nonce:
            attest(rid, (Unviable, h, empty))               // M6

attest(rid, att):
    e = pending[rid]
    e.attestation = att
    sig = threshold_sign(H(rid || att), attestation_key(e.contract))     // M2
    publish_response(e.contract, rid, att, sig)

on Response { contract, rid, att, sig } finalised on the source chain:
    if sig verifies under attestation_key(contract):
        delete pending[rid]
```

The MPC asks one question about each signed request: has its transaction
been finalised under any signature that verifies for it. There can be
several, for instance when a node whose share went into one run restarts and
joins another, so all of them are looked up; they cover the same transaction
bytes, so replay protection lets at most one execute. Lookup is by
transaction ID at any height, so when a node starts looking does not matter.
A transaction is reported Unviable when a node processing a finalised
destination block sees a transaction in it take the request's nonce. The MPC
does not search for that block: a node that was not watching at the time
would have to query historical state, so a nonce taken before the request
was admitted is not reported. Such a transaction gets no response, nor does
a request the MPC cannot process (see the appendix).

Restarts. A node keeps `pending` durably and indexes forward from it, so
what it admitted survives a restart, what it dropped stays dropped (M4), and
each entry resumes at the step it is missing: signing, lookup or publishing.
The source chains supply the rest: every verifying Signature event is looked
up, whoever produced it, and a verified Response event ends the request.
Every signature the network issues lands there, since a run needs more
participants than there are faulty nodes, so at least one honest node was in
it and publishes (section 3.3). A second signature is looked up like the
first, and a duplicate attestation has the same content (section 3.3) and is
dropped (C3a), so restarting at any point is harmless.

Properties:

* M1 The MPC signs a request only if it provably comes from the contract it
  names, and signs it with a key derived from that contract. The attestation
  key is derived from the contract and its source chain as well, under a
  reserved path that no
  request may name (`processable`); otherwise a contract could have the
  MPC sign an arbitrary hash with its own attestation key and forge a
  response to itself.
* M2 An attestation binds rid, kind, height and data as separate length-
  committed fields, and describes only destination state finalised at that
  height.
* M3 The MPC attests an outcome only from a finalised transaction: the
  receipt of tx(c) under a signature it issued, or, for Unviable, another
  transaction that took tx(c)'s nonce. Nothing else.
* M4 The MPC drops a request that is not authentic, or that it cannot
  process, and keeps no state for it, so the call is unanswered.
* M5 An execution whose return data does not decode is attested Undecodable,
  at its own height, with a bounded prefix of that data.
* M6 Unviable is attested only from a block a node processed, so a nonce
  taken before the request was admitted is not reported.

## 5. Why the guarantees hold (sketch)

* G1: an accepted response for c reports an execution of tx(c) (M3) at a
  height above e.known (C3c). Suppose that execution happened before
  call(c). tx(c) executes at most once (replay protection) and only on a
  call of this contract, which has the same rid (M1, section 2). That
  earlier call was either still outstanding, so call(c) was refused (C1),
  or its entry was removed by accepting a response reporting this very
  execution (C4, M3), which raised last_seen[dest] to its height (C3d)
  before call(c) recorded it (C2). Either way the response is not accepted;
  the diagram shows the second case.

```mermaid
flowchart LR
  subgraph A["Chain A (source)"]
    direction LR
    A12["A12<br/>call(c)"] --> A13["A13<br/>exec(c')"] --> A14["A14"] --> A15["A15<br/>resp(c, o)"] --> A16["A16<br/>call(c) again"]
  end
  subgraph B["Chain B (destination)"]
    direction LR
    B46["B46"] --> B47["B47<br/>call(c')"] --> B48["B48<br/>exec(c)"] --> B49["B49"] --> B50["B50<br/>resp(c', o')"]
  end
  B48 --> A15
  A13 --> B50
  A12 -.-> B48
  B47 -.-> A13
  style A16 stroke:#c00,color:#c00
```

Caption: Solid arrows are happens-before, dashed arrows are cross-chain
calls, which are deliberately not part of the relation. exec(c) at B48
happens-before A15 and therefore before the second call(c) at A16, so a
response attesting B48 is dropped for that call (C3c in section 4.1). The
first call(c) at A12 has no such path, so a response attesting B48 is
accepted for it.

For an Unviable response the argument is shorter. The only cross-chain edge
into the source chain is an accepted response, so a destination block at
height h happens-before call(c) only if a response attesting at least h was
accepted before it, which raised last_seen[dest] (C3d) and so e.known (C2),
and C3c drops it.

* G2: suppose two responses reporting the same execution (height h) are
  accepted by entries e1 and e2. Both carry the same rid, since the
  execution fixes every input to the rid (section 2). By C1 they were not
  outstanding together, so e2 was created after e1 was removed, after the
  first acceptance. By C3d last_seen[dest] was already at least h then,
  so by C2 e2.known >= h, and C3c drops the second response. Contradiction.
  exec(c) itself happening at most once is the replay-protection assumption,
  not something the library enforces.

* G3: M2, the finality assumption, and C3b (only attestations under the key
  are accepted).

* G4: the attestation key binds the source chain and the contract (M1), the
  attestation binds the rid (M2), the rid binds the transaction (a length-
  committing hash), and the MPC reports only the receipt of tx(c) under the
  signature issued for rid (M3). So the reported receipt is tx(c)'s own.

* G5: the signature was issued after call(c) was finalised (M1) and e.known
  is at most the destination height finalised by then (C2), so
  height(exec(c)) > e.known. The MPC finds the execution by its receipt,
  whenever it started looking, and decodes it or not (M5); either way honest
  nodes compute the same attestation and publish it (assumptions). By C4 the
  entry is still outstanding unless a response for rid(c) was accepted
  first, and any such response reports exec(c) too, since at most one
  signature executes (replay protection) and M3 attests only that receipt.
  So a response reporting exec(c) passes C3 and is accepted.

## 6. Open design points

* Which replay protection to assume. This draft assumes once a transaction
  has executed, the same bytes never execute again under that key. EVM
  nonces, spent UTXOs and Solana durable nonces give this. Using a recent
  blockhash can be made to work if the MPC remembers completed rids for as
  long as a differently signed copy could still execute, about a minute on
  Solana.
* A failing `on_response`. The response transaction fails with the handler
  and the entry stays outstanding, so a re-delivery is a retry rather than a
  loss. On Midnight a handler that always fails blocks every `process` batch
  carrying its message, so `process` has to isolate handler failures.
  Removing the entry before the handler runs is not an alternative, since
  C3a would then drop the re-delivery.
* `pending` grows without bound. An entry lives until a verified Response,
  and a request whose signature nobody broadcasts never produces one. A
  cancel transaction that takes the nonce ends the entry on both sides, so
  an application has a way out, but nothing bounds the entries nobody
  clears. The library's `outstanding` grows the same way and for the same
  reason. Checking old entries less often bounds the work per block, which
  is the part that matters.

## Appendix: the failures the MPC does not report

Two things leave a call unanswered: a transaction nobody broadcasts and
whose nonce no node sees taken (M6), and a request the MPC refuses to
process. An earlier draft answered both with `Failed`.

Every attestation carries the height of the block it describes (M2), and the
library accepts it only if that height is above what it has already seen
(C3c). Neither of these has a block to name, so the nodes would have to
agree on a height between themselves, and for a refused request on the
refusal as well, which differs between node versions during an upgrade.
Agreeing like that means each node committing to one answer per rid before
it contributes its first share, machinery the rest of this design does
without.

What it costs is that an application waits for an answer that never comes.
Unanswered is not unobserved: the MPC refuses a request for a reason it can
name, and that reason belongs in the node's logs. On the source chain it
would instead be a message under the request's rid, which makes it part of
the API, and the library has no rule that could act on a message carrying no
height.

