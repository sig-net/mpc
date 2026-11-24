# Chain integration capability and ownership matrix

Current `mpc-node` capabilities and settings ownership for every
`signet_primitives::Chain` variant.

- **Optional:** constructed when the chain is configured.
- **Unsupported:** no production implementation, not merely unconfigured.

## Settings

- **S — static protocol semantics:** [chain identity](account-derivation.md#chain-identification)
  and deterministic admission, derivation, signing, or response behavior.
- **D — deployment-profile value:** nodes in one deployment must agree;
  includes contracts/programs, target networks, and [checkpoint
  cadence](checkpoints.md#1-background).
- **L — local operational configuration:** process connectivity, credentials,
  enablement, storage, resources, and timing policy.
- After **D/L**, **· CLI/env** or **· constant** gives today's source.
- `mpc-node start --help` lists operator parameters; cells name their owners instead.

## Consumer paths

- **C1 — source admission/supervision:**
  [`spawn_indexers`](../chain-signatures/node/src/cli/mod.rs) →
  [`run_supervised`](../chain-signatures/node/src/stream/supervisor.rs) →
  [`handle_chain_event`](../chain-signatures/node/src/stream/mod.rs) →
  [`process_sign_request`](../chain-signatures/node/src/stream/ops.rs) or a
  published-response processor.
- **C2 — target admission/construction:** `process_sign_request` →
  [`SignBidirectionalEventExt::validate`](../chain-signatures/node/src/sign_bidirectional/mod.rs);
  first-leg response →
  [`advance_bidirectional_to_execution`](../chain-signatures/node/src/stream/ops.rs) →
  [`to_bidirectional_tx`](../chain-signatures/node/src/sign_bidirectional/mod.rs) /
  [`sign_and_hash_transaction`](../chain-signatures/node/src/sign_bidirectional/signing.rs) →
  execution watch.
- **C3 — execution/final response:** watcher
  [`ExecutionConfirmed`](../chain-signatures/primitives/src/events.rs) →
  [`process_execution_confirmed`](../chain-signatures/node/src/stream/ops.rs) →
  `answer_execution` →
  [`respond_bidirectional::CompletedTx`](../chain-signatures/node/src/respond_bidirectional.rs) →
  final source-chain sign request → C4.
- **C4 — publishing:**
  [`ChainStack::publishers`](../chain-signatures/node/src/cli/mod.rs) →
  [`RpcExecutor::dispatch_loop`](../chain-signatures/node/src/rpc/mod.rs) →
  `execute_publish` →
  [`ChainPublisher`](../chain-signatures/chain-integration-core/src/publish.rs).
  Publish failover uses the same path.

## Matrix

- [Plain sign requests](glossary.md#plain-sign-request), [bidirectional
  requests](glossary.md#bidirectional-request), and
  [`Unviable`](bidirectional-calls.md#2-vocabulary) use the protocol definitions.
- [Bidirectional-calls §8](bidirectional-calls.md#8-implementation-status)
  records current source/target role support.
- Dev/test deployments reuse the chain's static [CAIP-2 derivation
  identity](account-derivation.md#chain-identification); network selection does
  not change it.

| Chain | Source events | Response publisher | Target preparation | Target watcher | Networks / selection | Network-wide settings | Local settings |
|---|---|---|---|---|---|---|---|
| **NEAR** | **Test-only plain:** `mpc_chain_near::run` → sign queue, outside C1. **Production: unsupported.** | **Always:** `NearClient` → C4; currently serves the test-only source. | **Unsupported:** C2 rejects. | **Unsupported.** | Implicit: RPC **L** + `mpc_contract_id` **D**; local sandbox in tests. | **S:** `near:mainnet`; no checkpoints. **D · CLI/env:** `mpc_contract_id`. | **L · CLI/env:** NEAR node parameters. |
| **Ethereum** | **Optional plain:** `EthereumIndexer` → C1. | **Optional:** `EthClient` → C4; batches responses; shares `EthConfig` with indexing. | **Supported:** unsigned validation and `sign_and_hash_ethereum` → C2. | **Optional:** `ExecutionWatcher` inside `EthereumIndexer` → C1/C3; watches every source's Ethereum targets. | Explicit: `EthNetwork` **D · CLI/env** — Mainnet/Sepolia; Anvil in tests. | **S:** `eip155:1` target identity and signing semantics. **D · CLI/env:** `contract_address`. **D · constant:** checkpoints every 20 blocks. | **L · CLI/env:** local `EthConfig` fields. **L · constant:** `chain-ethereum` defaults. |
| **Solana** | **Optional plain + bidirectional:** `SolanaIndexer` → C1. | **Optional plain + bidirectional:** `SolanaClient` → C4. | **Unsupported:** C2 rejects. | **Unsupported.** | Implicit: RPC **L** + `program_address` **D**; local validator in tests. | **S:** fixed mainnet identity; Borsh responses. **D · CLI/env:** `program_address`. **D · constant:** checkpoints every 1200 slots. | **L · CLI/env:** local `SolConfig` fields. **L · constant:** `chain-solana` defaults. |
| **Bitcoin** | **Unsupported:** no indexer/wiring. | **Unsupported:** no registration. | **Unsupported:** C2 rejects. | **Unsupported.** | **Unsupported.** | **S:** identity and `ChainConfig` defaults only; no runtime capability implied. **D:** none. | **L:** none; no chain config. |
| **Hydration** | **Optional plain + bidirectional:** `HydrationIndexer` → C1. | **Optional plain + bidirectional:** `HydrationClient` → C4. | **Unsupported:** C2 rejects. | **Unsupported.** | Implicit: RPC **L**; no network validation or integration harness. | **S:** `polkadot:2034`; Borsh responses. **D · constant:** checkpoints every 240 blocks. | **L · CLI/env:** `HydrationConfig`. |
| **Canton** | **Optional bidirectional only:** `CantonIndexer` → C1. | **Optional bidirectional only:** `CantonClient` → C4; rejects plain `Sign`. | **Unsupported:** C2 rejects. | **Unsupported.** | Implicit: ledger APIs **L** + signer IDs **D**; local sandbox in tests. | **S:** synthetic `canton:global`; ABI responses. **D · CLI/env:** `signer_contract_id`, `signer_template_id`. **D · constant:** checkpoints every 50 offsets. | **L · CLI/env:** local `CantonConfig` fields. |
| **Midnight** | **Optional bidirectional only:** `MidnightIndexer` → C1 after the root key is available. | **Optional bidirectional only:** `RecoveringMidnightPublisher`/`MidnightPublisher` → C4; rejects plain `Sign`. | **Unsupported:** C2 rejects. | **Unsupported.** | Node-reported `NetworkId`: Mainnet/Preprod/Preview/Stagenet; `Undeployed` in local tests. | **S:** `midnight:mainnet`; Fab responses, attestation hashing, `Unviable`. **D · CLI/env:** `central_address`, `responder_address`. **D · constant:** checkpoints every 120 blocks. | **L · CLI/env:** local `MidnightConfig` fields and DUST storage. **L · constant:** `chain-midnight` defaults. |
| **Tron** | **Unsupported:** no source indexer; response hashing rejects Tron sources. | **Unsupported:** no registration. | **Supported:** raw validation, SHA-256 txID, owner/expiry checks → C2. | **Optional target-only:** `TronWatcher` → C1/C3; watches every source's Tron targets. | Implicit: endpoint **L**; recorded Nile fixtures, no live local harness. | **S:** `tron:mainnet` target identity and transaction/expiry semantics; no checkpoints. | **L · CLI/env:** `TronConfig` fields. **L · constant:** `chain-tron` defaults. |

- Ethereum, Solana, Hydration, Canton, and Midnight share one optional config
  between source indexing and publishing; the roles cannot be enabled separately.
- Ethereum watching also shares the source indexer/config. Tron configures only
  its watcher.
- NEAR governance is always on: `NearGovernanceClient` reads protocol
  state/config/checkpoints and submits governance/checkpoint votes through
  `RpcExecutor`. It is neither a production source nor a target role.

## Current ambiguities

- **D · CLI/env values can diverge:** Ethereum contract, Solana program,
  Midnight central/responder addresses, Canton signer identifiers, and NEAR MPC
  contract. Nodes can select different request universes or response
  destinations. Canton `party_id` remains node-local.
- **`ChainConfig` mixes categories:** response encoding, target support, and
  `Unviable` support are **S**; [`checkpoint_interval`](checkpoints.md#7-implementation-status)
  is **D · constant**;
  finality, observation, response, and stall timings are **L · constant**
  supervision, monitoring, and failover policy despite encoding network-derived
  facts.
- **Watchers do not define target support:** C2 admits only Ethereum and Tron
  targets regardless of watcher configuration. Without Tron config, requests
  are admitted and signed but remain `Executing`; without Ethereum config, they
  also lose execution watching and the EIP-155 admission check.
