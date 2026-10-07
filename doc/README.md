# MPC docs

## Protocol

- [Protocol properties](protocol-properties.md): safety, liveness and efficiency properties of the coordination layer, and how the code enforces them.
- [Posit state machine](posit-state-machine.md): the per-request signing state machine, rounds and timeouts, as implemented.
- [Node specification](node-specification.md): the original design of protocol invocations, artifact lifecycle, peer status and state sync. Graph sources are in [graphs/](graphs/).

## Keys

- [Account derivation](account-derivation.md): how per-chain accounts and keys are derived from the root key.

## Operations

- [Secret management](secret-management.md): how secret material is represented, passed around, logged and stored in the node.
- [Logging](logging.md): log level policy, what each level means and how to log retries.

## Build

- [CI caching](ci-caching.md): cache policy for the GitHub workflows.
