# MPC docs

How to write and update these docs: [Documentation conventions](../CONTRIBUTING.md#documentation).

## Protocol

- [Protocol properties](protocol-properties.md): safety, liveness and efficiency properties of the coordination layer, and how the code enforces them.
- [Posit state machine](posit-state-machine.md): the per-request signing state machine, rounds and timeouts, as implemented.
- [Bidirectional calls](bidirectional-calls.md): entities, API and properties of a call signed for a target chain whose outcome is reported back to the source chain.
- [Checkpoints](checkpoints.md): the per-chain backlog, how nodes agree on it at fixed heights through governance votes, and how a joining or lagging node catches up from the agreed checkpoint.
- [Mesh](mesh.md): how a node tracks each peer's status (Offline, Inactive, Syncing, Active) and which peers it may propose to.
- [Node specification](node-specification.md): the original design of protocol invocations, artifact lifecycle and participant selection.
- [State sync](state-sync.md): how an artifact's owner and its holders repair the share holder directory after one of them lost data, and why that never deletes a share still in use.

## Keys

- [Account derivation](account-derivation.md): how per-chain accounts and keys are derived from the root key.
- [Delta derivation](delta-derivation.md): requirements for the per-request re-randomization scalar and its inputs, in particular the chain entropy.

## Operations

- [Secret management](secret-management.md): how secret material is represented, passed around, logged and stored in the node.
- [Logging](logging.md): log level policy, what each level means and how to log retries.
- [Releasing](releasing.md): branches, versioning, the biweekly release flow through testnet to mainnet, and hotfixes.

## Build

- [CI caching](ci-caching.md): cache policy for the GitHub workflows.
