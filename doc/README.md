# MPC docs

## Protocol

- [Protocol properties](protocol-properties.md): safety, liveness and efficiency properties of the coordination layer, and how the code enforces them.
- [Posit state machine](posit-state-machine.md): the per-request signing state machine, rounds and timeouts, as implemented.
- [Bidirectional calls](bidirectional-calls.md): entities, API and properties of a call signed for a target chain whose outcome is reported back to the source chain.
- [Node specification](node-specification.md): the original design of protocol invocations, artifact lifecycle, peer status and state sync. Graph sources are in [graphs/](graphs/).

## Keys

- [Account derivation](account-derivation.md): how per-chain accounts and keys are derived from the root key.

## Chains

- [Midnight publisher](midnight-publisher.md): how the node builds, proves, pays for and posts its Midnight responses, and which events the reader supports.

## Operations

- [Secret management](secret-management.md): how secret material is represented, passed around, logged and stored in the node.
- [Logging](logging.md): log level policy, what each level means and how to log retries.

## Build

- [CI caching](ci-caching.md): cache policy for the GitHub workflows.
