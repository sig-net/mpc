# Glossary

Terms used across the docs.  
Each entry names the code that implements the term, if any: the symbol and
its file. Paths are relative to `chain-signatures/node/src/`,
except those starting with `chain-signatures/` or `signet-`, which are
relative to the repository root.  
Some entries note under *Code today* where the code does not match yet, with
the tracking issue where there is one.

## Active set

A node's local, unreliable guess at which [committee](#committee) members are
reachable, report the `Running` state and have finished a [state
sync](#state-sync) with the node. No two nodes need the same guess
(`MeshState::active`, `mesh/state.rs`). See [protocol-properties.md
§2](protocol-properties.md#2-system-model).

## Admitted request

A [request](#request) the network has found authentic and processable and
added to its [backlog](#backlog). Only an admitted request is ever signed or
attested. See [bidirectional-calls.md
§2](bidirectional-calls.md#2-vocabulary).

## Artifact

A one-shot input generated ahead of time and consumed by at most one
[instance](#instance): a [triple pair](#triple-pair) or a
[presignature](#presignature) (`ProtocolArtifact`,
`storage/protocol_storage.rs`). Each artifact has a single [owner](#owner) and
a set of [holders](#holder).

Its states are `Generating` (the [generation](#generation) protocol that
produces it is still running), `Available` (stored and ready to use) and
`Using` (taken by a running generation), with implicit `init` and `done`. The
explicit states are stored and ideally persisted, and the change to `Using`
must be persisted as soon as the artifact leaves storage. See
[node-specification.md](node-specification.md) and
[state-sync.md](state-sync.md).

*Code today:* artifacts are stored in Redis, and their marks `Generating`,
`Pending` (a [reservation](#reservation)) and `Using` live only in memory
(`ReservedKind`, `storage/protocol_storage.rs`). There is no `Available`
mark: an artifact in Redis with no mark plays that role. A crash loses an
artifact in `Using`, and `Using` clears whenever the consuming generation
ends, even when it fails.

## Attestation

A statement ([request id](#request-id), height, [outcome](#outcome)) about a
[bidirectional request](#bidirectional-request), signed with the attestation
key of the [request](#request)'s contract at the request's key version, over a
[digest](#digest) that commits to a domain tag and the output length.
See [bidirectional-calls.md §2](bidirectional-calls.md#2-vocabulary).

*Code today:* only for requests from Midnight
([#1429](https://github.com/sig-net/mpc/issues/1429)).

## Backlog

Each node keeps one backlog per [source chain](#source-chain), with one entry
per [admitted](#admitted-request) [request](#request) that is not finished. An
entry holds the [request id](#request-id), the request, the contract that made
it and, for a [bidirectional request](#bidirectional-request), the signatures
for it [published](#publish) in final source chain blocks. Only final source
chain events change it; anything else a node keeps about a request stays out of
it (`Backlog`, `backlog/`). See [checkpoints.md
§1](checkpoints.md#1-background).

*Code today:* `BacklogEntry` holds the request and the node's progress,
including phases set from what the node read on the [target
chain](#target-chain), and the whole entry goes into the
[checkpoint](#checkpoint); there is no `signatures` list.

## Bidirectional request

A [request](#request) to sign a transaction for a [target
chain](#target-chain) and report its [outcome](#outcome) back to the [source
chain](#source-chain) (`SignKind::SignBidirectional`,
`chain-signatures/primitives/src/requests.rs`). See
[bidirectional-calls.md](bidirectional-calls.md).

## Caught up

A node is caught up on a chain once it has processed every block up to the
finalized head its [indexer](#indexer) read at startup: one bounded pass,
without chasing blocks finalized meanwhile. Until then it starts no new
signing, attesting or publishing for that chain. The per-chain flag is set when
the indexer reports `ChainEvent::CatchupCompleted`
(`chain-signatures/primitives/src/events.rs`) and cleared by every restart of
the indexer or the node; a node that falls behind without a restart keeps
signing. See [checkpoints.md
§1](checkpoints.md#1-background).

## Checkpoint

A height and a snapshot of a chain's [backlog](#backlog) at that height,
identified by a [digest](#digest) that nodes vote on in the [governance
contract](#governance-contract) (`Checkpoint`, `backlog/checkpoints.rs`). See
[checkpoints.md](checkpoints.md).

## Committee

Membership, [threshold](#threshold) t and [epoch](#epoch) as fixed by the
[governance contract](#governance-contract), together with the root public key
and whether the contract is `Running`; each node holds its own snapshot
(`GovernanceInfo`, `rpc/mod.rs`). Committee is contract-scoped; compare
[participant](#participant). See [protocol-properties.md
§2](protocol-properties.md#2-system-model).

## Correct node

A node that follows the protocol, apart from crashing and restarting with its
durable storage intact. Its RPC provider tells it the truth, and it indexes
faster than the chains produce blocks. Compare [faulty node](#faulty-node).
See [protocol-properties.md §2](protocol-properties.md#2-system-model) and
[checkpoints.md §1](checkpoints.md#1-background).

## Deliberator

In a [posit](#posit), a node other than the [proposer](#proposer). It answers
PROPOSE with ACCEPT or REJECT and joins the [generation](#generation) when
START lists it. See [posit-state-machine.md](posit-state-machine.md).

## Delta

The public per-request scalar every [participant](#participant) uses to
re-randomize a [presignature](#presignature), `H(request_id || big_r ||
entropy)`. See [delta-derivation.md](delta-derivation.md).

*Code:* `derive_delta` (`chain-signatures/crypto/src/kdf.rs`) instantiates H as
HKDF-SHA3-256 with the [entropy](#entropy) as key material and, as info, a
fixed prefix, the [request id](#request-id) and `big_r`.

## Digest

A short hash that stands for a larger structure. The docs use two:

- The checkpoint digest, which nodes vote on. It binds a
  [checkpoint](#checkpoint)'s chain, height and [backlog](#backlog)
  (`CheckpointDigest`, `chain-signatures/primitives/src/backlog.rs`). See
  [checkpoints.md §2](checkpoints.md#2-digest-and-interfaces).
- The attestation digest, which nodes sign. It stands for an
  [attestation](#attestation), the statement of a [bidirectional
  request](#bidirectional-request)'s outcome. See [bidirectional-calls.md
  §7.5.2.1](bidirectional-calls.md#7521-attestation-digest).

## Entropy

A value from the block that holds a [request](#request). The requester cannot
know or influence it before that block is validated. Nodes read it from a final
block, so every node derives the same [delta](#delta) (`SignArgs::entropy`,
`chain-signatures/primitives/src/crypto.rs`). It also seeds the
[proposer](#proposer) election. See
[delta-derivation.md](delta-derivation.md).

## Epoch

The [committee](#committee)'s version number, fixed by the [governance
contract](#governance-contract); each completed resharing raises it by one
(`RunningContractState::epoch`, `chain-signatures/contract/src/state.rs`; each
node's copy is `GovernanceInfo::epoch`, `rpc/mod.rs`).

## Epsilon

The per-account scalar derived from the key version, chain, sender and
derivation path, used to derive the account's key from the root key
(`derive_epsilon`, `derive_key`, `signet-crypto/src/kdf.rs`). See
[account-derivation.md](account-derivation.md).

## f

The number of [faulty nodes](#faulty-node) the model tolerates. Safety needs f
< [t](#threshold) and f < 2t − [n](#n). See [protocol-properties.md
§2](protocol-properties.md#2-system-model).

## Faulty node

A node that may deviate arbitrarily from the protocol; at most [f](#f) of the
[n](#n) nodes are faulty. A node whose RPC provider misleads it counts as
faulty. Compare [correct node](#correct-node). See [protocol-properties.md
§2](protocol-properties.md#2-system-model) and [checkpoints.md
§1](checkpoints.md#1-background).

## Final block

A block the network treats as final, so it will stay in the chain unchanged
(called solidified on Tron). Nodes read [requests](#request) and attest
[outcomes](#outcome) only from final blocks; what counts as finalized differs
per chain. See [bidirectional-calls.md
§3.3](bidirectional-calls.md#33-assumptions) and [protocol-properties.md
§2](protocol-properties.md#2-system-model).

## Generation

Running a cryptographic protocol (triple, [presignature](#presignature) or
signature protocol) among an [instance](#instance)'s
[participants](#participant) once the [posit](#posit) fixed them.

## Governance contract

The NEAR contract that fixes the [committee](#committee) and the root public
key and takes the [threshold](#threshold), join, leave, reshare and
[checkpoint](#checkpoint) votes (`chain-signatures/contract`,
`ProtocolContractState`). On NEAR it is also the [signet
contract](#signet-contract).

## Holder

A node that stores a share of an [artifact](#artifact).

## Indexer

The per-chain part of a node that reads final blocks from its RPC provider and
turns them into events (`ChainEvent`,
`chain-signatures/primitives/src/events.rs`).

## Instance

One attempt to run a protocol to completion over a specific
[artifact](#artifact), named by the artifact's id, together with the sign id
for a signature: (sign id, [presignature](#presignature) id). The sign id
(`SignId`, `signet-primitives/src/crypto.rs`) wraps the [request
id](#request-id), the same 32 bytes.

## Mesh

A node's connections to its peers, each `Offline` (no answer), `Inactive`
(answers but does not take part), `Syncing` (takes part, [state
sync](#state-sync) not done) or `Active` (`mesh/connection.rs`). Only `Active`
peers are eligible for a [participant](#participant) list. See
[mesh.md](mesh.md).

## n

The number of nodes in the [committee](#committee). See
[protocol-properties.md §2](protocol-properties.md#2-system-model).

## Outcome

What happened to a [bidirectional request](#bidirectional-request)'s
transaction, one of three kinds:

- **Executed.** Included in a [final block](#final-block) of the [target
  chain](#target-chain), succeeded, and its return data decodes against the
  request's schema; the outcome carries the decoded data.
- **Failed.** Included in a final block and reverted.
- **Unviable.** Can never be included, because a transaction with different
  unsigned bytes, from the same key, used up its replay protection, or its
  validity window closed.

See [bidirectional-calls.md §2](bidirectional-calls.md#2-vocabulary).

*Code today:* Unviable is attested only for requests from Midnight, and even
there not when only another request's response shows it
([#1429](https://github.com/sig-net/mpc/issues/1429),
[#1430](https://github.com/sig-net/mpc/issues/1430)).

## Owner

The node that coordinated an [artifact](#artifact)'s
[generation](#generation). It decides about the artifact, and only an
[instance](#instance) it proposes can consume the artifact. Having one owner
per artifact keeps coordination and [state sync](#state-sync) simple.

## Participant

A node on one [instance](#instance)'s participant list, fixed by
[START](#posit). Always instance-scoped; compare [committee](#committee)
(`cait_sith::protocol::Participant`, which the code also uses for committee
members).

## Plain sign request

A [request](#request) for a signature with nothing to report back
(`SignKind::Sign`, `chain-signatures/primitives/src/requests.rs`). Its first
[published](#publish) signature finishes it. See
[checkpoints.md §1](checkpoints.md#1-background).

## Posit

The agreement phase before an [instance](#instance), in four messages
(`PositAction`):

- **PROPOSE.** For a signature or a [presignature](#presignature), the
  [proposer](#proposer) [reserves](#reservation) the [artifact](#artifact) to
  consume and offers it to the artifact's active [holders](#holder). For a
  [triple pair](#triple-pair), which consumes no artifact, it proposes to
  every node in its [active set](#active-set).
- **ACCEPT** or **REJECT.** Each [deliberator](#deliberator) agrees, or
  refuses with a reason (`PositRejectReason`).
- **START.** The proposer commits the reserved artifact, removing it from the
  pool, and sends the final [participant](#participant) list. Aborting before
  the commit releases the reservation; aborting after it does not
  (`ArtifactReservation::commit`, `storage/protocol_storage.rs`).

Code: `protocol/posit.rs`, `protocol/request/`. See
[posit-state-machine.md](posit-state-machine.md).

## Presignature

A pre-computed, secret-shared ECDSA nonce (`big_r` and the shares k and
sigma), built from one [triple pair](#triple-pair) and consumed by one
signature (`Presignature`, `protocol/presignature.rs`). Its id is derived from
the pair's id, not chosen (`hash_as_id`). Abbreviated P.

## Proposer

The node that drives a [posit](#posit). For a signature it is elected per
[round](#round): the [committee](#committee) member at index (entropy[0] + r)
mod n (`protocol/request/organize.rs`), so every node agrees on it without
messaging; for a [triple pair](#triple-pair) or
[presignature](#presignature) it is the [owner](#owner). See
[posit-state-machine.md §5](posit-state-machine.md#5-bumping-rounds).

## Publish

To submit a signature or an [attestation](#attestation) to the [signet
contract](#signet-contract), which anyone may do. A signature or attestation
counts as published once the event carrying it is final on the [source
chain](#source-chain). See
[bidirectional-calls.md §2](bidirectional-calls.md#2-vocabulary).

## Request

What a contract asks the network to sign. A [bidirectional
request](#bidirectional-request) is the tuple (transaction, target, key,
schema), made when the contract passes it to `sign_bidirectional` and that
call accepts it (`IndexedSignRequest`, `SignKind`,
`chain-signatures/primitives/src/requests.rs`). See
[bidirectional-calls.md §2](bidirectional-calls.md#2-vocabulary).

## Request id

A deterministic function of a [request](#request), so every node derives the
same one; for a [bidirectional request](#bidirectional-request), a
collision-resistant hash of (contract, transaction, target, key) in a
length-committing encoding (`SignId`, `signet-primitives/src/crypto.rs`). See
[bidirectional-calls.md §2](bidirectional-calls.md#2-vocabulary).

*Code today:* bidirectional request ids are computed this way only for
Midnight sources ([#1429](https://github.com/sig-net/mpc/issues/1429)).

## Reservation

A [proposer](#proposer)'s claim on one of its own stored
[artifacts](#artifact) for a [posit](#posit), so that its other posits
running at the same time do not pick the same artifact. The artifact stays
stored and, in the spec's terms, `Available`. The START commit removes it and
makes it `Using`; a posit that ends before START releases it. A reservation
is local to the proposer and kept only in memory, so a restart drops it
(`ArtifactReservation`, `ReservedKind::Pending`,
`storage/protocol_storage.rs`). See
[posit-state-machine.md](posit-state-machine.md).

## Round

One attempt within a [request](#request)'s sign task, numbered from 0. The
round fixes the [proposer](#proposer) and the [round
timeout](posit-state-machine.md#6-the-round-timeout). See
[posit-state-machine.md §5](posit-state-machine.md#5-bumping-rounds).

## Settled

A [digest](#digest) the [governance contract](#governance-contract) has fixed
for a height, once [threshold](#threshold) t nodes voted for it. A settled
digest never changes. See [checkpoints.md §1](checkpoints.md#1-background).

## Signet contract

The contract on a [source chain](#source-chain) that takes
[requests](#request) and receives [published](#publish) signatures and
[attestations](#attestation), for example `ChainSignatures.sol` on EVM chains
(`chain-signatures/contract-eth/contracts/`) and `chain-signatures/contract-sol`
on Solana. See [bidirectional-calls.md
§4.2](bidirectional-calls.md#42-signet-contract-per-source-chain).

## Source chain

The chain a [request](#request) is made on and answered on.

## State sync

The exchange in which an [artifact](#artifact)'s [owner](#owner) and its
[holders](#holder) repair the holder directory after one of them lost data.
It runs whenever a node connects or reconnects to a peer, and when a sign
[posit](#posit) fails on REJECTs: the peers that rejected its
[presignature](#presignature) as missing (`MissingArtifact`) are synced again
(`protocol/sync/`, `protocol/request/posit.rs`). See
[state-sync.md](state-sync.md).

## Take

A [holder](#holder) removing its own share of an [artifact](#artifact) from
storage when the [generation](#generation) that consumes it starts. Taking is
what burns the artifact, and the removal must reach durable storage before
anything derived from it is sent (`take`, `ArtifactTaken`,
`storage/protocol_storage.rs`). See
[protocol-properties.md,
S1](protocol-properties.md#s1-one-shot-artifacts-are-consumed-at-most-once).

## Target chain

The chain a [bidirectional request](#bidirectional-request)'s transaction
executes on (`executionDest` on the wire). See
[bidirectional-calls.md](bidirectional-calls.md).

## Threshold

t, the number of nodes needed to sign, set by the [governance
contract](#governance-contract): ⌊2n/3⌋ + 1 for n ≥ 5 and ⌊n/2⌋ + 1 below.
A threshold vote cannot take it outside the range [⌊2n/3⌋ + 1, n − 1] of
`vote_threshold` (`chain-signatures/contract/src/lib.rs`). The floor applies
on resharing and to threshold votes; the initial value is checked only against
n. See [protocol-properties.md §2](protocol-properties.md#2-system-model).

## Triple pair

Two secret-shared random triples, produced in the background and stored, owned
and consumed as one [artifact](#artifact) under one id, spent to build one
[presignature](#presignature) (`TriplePair` in `storage/triple_storage.rs`,
`TripleId` in `protocol/triple.rs`). Its id is drawn at random by its
[proposer](#proposer). Abbreviated T, which is not the
[threshold](#threshold) t.
