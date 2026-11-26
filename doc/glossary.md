# Glossary

Terms used across the docs. An entry says what the term is and why it
matters, and leaves out:

- How it works and why it is designed so. The doc it links covers that.
- Current values of constants and settings. It says what
  `LATEST_MPC_KEY_VERSION` is, not what it is set to now.

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
(`MeshState::active`, `mesh/state.rs`). See [system-model.md](system-model.md).

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
a set of [holders](#holder). See
[node-specification.md](node-specification.md#triple-and-pre-signature-state-machine)
and [state-sync.md](state-sync.md).

## Attestation

A statement ([request id](#request-id), height, [outcome](#outcome)) about a
[bidirectional request](#bidirectional-request), signed with the attestation
key of the [request](#request)'s contract at the request's key version, over
its [digest](#digest). See [bidirectional-calls.md
§2](bidirectional-calls.md#2-vocabulary).

*Code today:* only for requests from Midnight
([#1429](https://github.com/sig-net/mpc/issues/1429)).

## Backlog

A node's record of the [admitted](#admitted-request) [requests](#request) on
one [source chain](#source-chain) that are not finished, one entry each. An
entry holds the [request id](#request-id), the request and, for a
[bidirectional request](#bidirectional-request), the ids of the transactions
that the signatures [published](#publish) for it give and the height at which
another request's response left it [unviable](#outcome) (`Backlog`,
`BacklogEntry`, `backlog/`). See [checkpoints.md
§1](checkpoints.md#1-background).

*Code today:* `BacklogEntry` also holds the node's progress on the request.
See [checkpoints.md §7](checkpoints.md#7-implementation-status).

## Bidirectional request

A [request](#request) to sign a transaction for a [target
chain](#target-chain) and report its [outcome](#outcome) back to the [source
chain](#source-chain) (`SignKind::SignBidirectional`,
`chain-signatures/primitives/src/requests.rs`). See
[bidirectional-calls.md](bidirectional-calls.md).

## Caught up

A node is caught up on a chain once it has processed every block up to the
finalized head its [indexer](#indexer) read when it last started. Until then
it starts no new signing, attesting or publishing for that chain. Falling
behind later does not undo it (`ChainEvent::CatchupCompleted`,
`chain-signatures/primitives/src/events.rs`). See [checkpoints.md
§1](checkpoints.md#1-background).

## Checkpoint

A height and a snapshot of a chain's [backlog](#backlog) at that height,
identified by a [digest](#digest) that nodes vote on in the [governance
contract](#governance-contract) (`Checkpoint`, `backlog/checkpoints.rs`). See
[checkpoints.md](checkpoints.md).

## Committee

Membership, [threshold](#threshold) t and [epoch](#epoch) as fixed by the
[governance contract](#governance-contract); each node holds its own snapshot
(`GovernanceInfo`, `rpc/mod.rs`). Committee is contract-scoped; compare
[participant](#participant). See [system-model.md](system-model.md).

## Correct node

A node that follows the protocol, apart from crashing and restarting with its
durable storage intact. Its RPC provider tells it the truth, and it indexes
faster than the chains produce blocks. Compare [faulty node](#faulty-node).
See [system-model.md](system-model.md) and
[checkpoints.md §1](checkpoints.md#1-background).

## Deliberator

In a [posit](#posit), a node other than the [proposer](#proposer). It answers
PROPOSE with ACCEPT or REJECT and joins the [generation](#generation) when
START lists it. See [posit-state-machine.md](posit-state-machine.md).

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

A value from the block that holds a [request](#request) that the requester
cannot know or influence before that block is validated. Nodes derive the
signature's delta and the request's [proposers](#proposer) from it
(`SignArgs::entropy`, `chain-signatures/primitives/src/crypto.rs`). See
[delta-derivation.md](delta-derivation.md).

## Epoch

A counter in the [governance contract](#governance-contract) that each
completed resharing raises by one (`RunningContractState::epoch`,
`chain-signatures/contract/src/state.rs`).

## f

The number of [faulty nodes](#faulty-node) the model tolerates. Safety needs f
< [t](#threshold) and f < 2t − [n](#n). See [system-model.md](system-model.md).

## Faulty node

A node that may deviate arbitrarily from the protocol; at most [f](#f) of the
[n](#n) nodes are faulty. A node whose RPC provider misleads it counts as
faulty. Compare [correct node](#correct-node). See
[system-model.md](system-model.md) and [checkpoints.md
§1](checkpoints.md#1-background).

## Final block

A block the network relies on to stay in its chain unchanged (called
solidified on Tron). What counts as final differs per chain. See
[bidirectional-calls.md
§3.3](bidirectional-calls.md#33-assumptions) and
[system-model.md](system-model.md).

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
id](#request-id).

## Key version

Which MPC root key and derivation format a key uses. See
[account-derivation.md](account-derivation.md#derivation-path-structure).
Every request names its key version. The network signs only up to the latest
key version (`LATEST_MPC_KEY_VERSION`, `signet-primitives/src/lib.rs`).

## Mesh

A node's connections to its peers, each `Offline` (no answer), `Inactive`
(answers but does not take part), `Syncing` (takes part, [state
sync](#state-sync) not done) or `Active` (`mesh/connection.rs`). Only `Active`
peers are eligible for a [participant](#participant) list. See
[mesh.md](mesh.md).

## n

The number of nodes in the [committee](#committee). See
[system-model.md](system-model.md).

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

*Code today:* Unviable is attested only for requests from Midnight
([#1429](https://github.com/sig-net/mpc/issues/1429)).

## Owner

The node that coordinated an [artifact](#artifact)'s
[generation](#generation). It decides about the artifact, and only an
[instance](#instance) it proposes can consume the artifact.

## Participant

A node on one [instance](#instance)'s participant list, fixed by
[START](#posit). Always instance-scoped; compare [committee](#committee)
(`cait_sith::protocol::Participant`, which the code also uses for committee
members).

## Plain sign request

A [request](#request) for a signature with nothing to report back
(`SignKind::Sign`, `chain-signatures/primitives/src/requests.rs`). See
[checkpoints.md §1](checkpoints.md#1-background).

## Posit

The phase before an [instance](#instance) in which nodes agree on its
[participants](#participant). The [proposer](#proposer) sends PROPOSE, each
[deliberator](#deliberator) answers ACCEPT or REJECT, and the proposer sends
START with the final participant list (`PositAction`, `PositRejectReason`,
`protocol/posit.rs`, `protocol/request/`). See
[posit-state-machine.md](posit-state-machine.md).

## Presignature

A pre-computed, secret-shared ECDSA nonce, built from one [triple
pair](#triple-pair) and consumed by one signature (`Presignature`,
`protocol/presignature.rs`). Abbreviated P.

## Proposer

The node that drives a [posit](#posit): for a signature, the node elected
for the [round](#round) (`protocol/request/organize.rs`); for a [triple
pair](#triple-pair) or [presignature](#presignature), its [owner](#owner). See
[posit-state-machine.md §5](posit-state-machine.md#5-bumping-rounds).

## Publish

To submit a signature or an [attestation](#attestation) to the [signet
contract](#signet-contract), which anyone may do. A signature or attestation
counts as published once the event carrying it is final on the [source
chain](#source-chain). See
[bidirectional-calls.md §2](bidirectional-calls.md#2-vocabulary).

## Purpose of the key

What a key signs: [plain sign requests](#plain-sign-request),
[bidirectional requests](#bidirectional-request),
[attestations](#attestation) or a [system account](#system-account)'s
transactions. It applies from [key version](#key-version) 2. See
[account-derivation.md](account-derivation.md#derivation-path-structure).

## Request

What a contract asks the network to sign. A [bidirectional
request](#bidirectional-request) is the tuple (sender, transaction, target,
key, schema), where the sender is the requesting contract
(`IndexedSignRequest`, `SignKind`,
`chain-signatures/primitives/src/requests.rs`; `SignBidirectionalEvent`,
`chain-signatures/primitives/src/bidirectional.rs`). See
[bidirectional-calls.md §2](bidirectional-calls.md#2-vocabulary).

## Request id

The identifier of a [request](#request), a deterministic function of it, so
every node derives the same one (`SignId`, `signet-primitives/src/crypto.rs`).
See
[bidirectional-calls.md §2](bidirectional-calls.md#2-vocabulary).

## Reservation

A [proposer](#proposer)'s claim on one of its own stored
[artifacts](#artifact) for a [posit](#posit), so that its other posits
running at the same time do not pick the same artifact
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
([sig-net/ethereum-signet-contract](https://github.com/sig-net/ethereum-signet-contract)) and `chain-signatures/contract-sol`
on Solana. On Midnight it is two contracts: requests are notified to the
Signet singleton, and the signet responder receives published signatures
and attestations. See [bidirectional-calls.md
§4.2](bidirectional-calls.md#42-signet-contract-per-source-chain).

## Signing scheme

The signature algorithm and curve a key signs with: ECDSA over secp256k1
today, with EdDSA planned. A request names its signing scheme among its key
parameters, in a field the contracts call `algo`. See
[bidirectional-calls.md
§7.1](bidirectional-calls.md#71-request-signbidirectionaleventv1).

## Source chain

The chain a [request](#request) is made on and answered on.

## State sync

The exchange in which an [artifact](#artifact)'s [owner](#owner) and its
[holders](#holder) repair the holder directory after one of them lost data
(`protocol/sync/`). See
[state-sync.md](state-sync.md).

## System account

An account the MPC network itself controls on a chain, rather than one a
[request](#request)'s sender controls: the admin of the Ethereum contract
(`ChainSignatures.sol`), for instance. See
[account-derivation.md](account-derivation.md#derivation-path-structure).

## Take

A [holder](#holder) removing its own share of an [artifact](#artifact) from
storage when the [generation](#generation) that consumes it starts. Taking is
what burns the artifact (`take`, `ArtifactTaken`,
`storage/protocol_storage.rs`). See
[protocol-properties.md,
S1](protocol-properties.md#s1-one-shot-artifacts-are-consumed-at-most-once).

## Target chain

The chain a [bidirectional request](#bidirectional-request)'s transaction
executes on, also called the destination chain (`executionDest` on the wire).
See
[bidirectional-calls.md](bidirectional-calls.md).

## Threshold

t, the number of nodes needed to sign, set by the [governance
contract](#governance-contract) (`vote_threshold`,
`chain-signatures/contract/src/lib.rs`). See [system-model.md](system-model.md).

## Triple pair

Two secret-shared random triples, produced in the background and stored, owned
and consumed as one [artifact](#artifact) under one id, spent to build one
[presignature](#presignature) (`TriplePair` in `storage/triple_storage.rs`,
`TripleId` in `protocol/triple.rs`). Abbreviated T, which is not the
[threshold](#threshold) t.
