# Chain integration capability and ownership matrix

Current chain-integration roles and settings ownership. Labels apply to each
role, not to the chain itself.

- **Config-gated:** the role is implemented and constructed when its chain
  configuration is present.
- **Not implemented:** the chain has no production implementation of this role.

## Settings

- **S — static protocol semantics:** [chain identity](account-derivation.md#chain-identification),
  reused across dev/test networks, and deterministic request/response rules,
  including target and `Unviable` support.
- **D — deployment-wide values:** values shared by every node, including
  contracts/programs, execution networks, [`checkpoint_interval`](checkpoints.md#7-implementation-status),
  and finality/observation/response expectations.
- **L — local operations:** endpoints, credentials, enablement, storage, and
  stall/feed-stall budgets.

Suffixes show the current source: **· CLI/env** or **· constant**. For **D**,
CLI/env is a delivery mechanism, not independent ownership.

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
  execution watch. [Target support](bidirectional-calls.md#8-implementation-status)
  is static (Ethereum and Tron), independent of watcher configuration.
- **C3 — execution/final response:** watcher
  [`ExecutionConfirmed`](../chain-signatures/primitives/src/events.rs) →
  [`process_execution_confirmed`](../chain-signatures/node/src/stream/ops.rs) →
  `answer_execution` →
  [`respond_bidirectional::CompletedTx`](../chain-signatures/node/src/respond_bidirectional.rs) →
  final source-chain sign request.
- **C4 — publishing:**
  [`ChainStack::publishers`](../chain-signatures/node/src/cli/mod.rs) →
  [`RpcExecutor::dispatch_loop`](../chain-signatures/node/src/rpc/mod.rs) →
  `execute_publish` →
  [`ChainPublisher`](../chain-signatures/chain-integration-core/src/publish.rs).
  Publish failover uses the same path.

## Matrix

| Chain | Source events | Response publisher | Target preparation | Target watcher | Networks / selection | Network-wide settings | Local settings |
|---|---|---|---|---|---|---|---|
| **NEAR** | **Test-only [plain](glossary.md#plain-sign-request):** `mpc_chain_near::run` → sign queue, outside C1. **Production: not implemented.** | **Always:** `NearClient` → C4; currently serves the test-only source. | **Not implemented:** C2 rejects. | **Not implemented.** | Implicit: RPC **L** + `mpc_contract_id` **D**; local sandbox in tests. | **S:** `near:mainnet`; no checkpoints. **D · CLI/env:** `mpc_contract_id`. | **L · CLI/env:** NEAR node parameters. |
| **Ethereum** | **Config-gated plain:** `EthereumIndexer` → C1. | **Config-gated:** `EthClient` → C4; batches responses; shares `EthConfig` with indexing. | **Implemented:** unsigned validation and `sign_and_hash_ethereum` → C2. | **Config-gated:** `ExecutionWatcher` inside `EthereumIndexer` → C1/C3; watches every source's Ethereum targets. No `EthConfig`: no watcher or EIP-155 admission check. | Explicit: `EthNetwork` **D · CLI/env** — Mainnet/Sepolia; Anvil in tests. | **S:** `eip155:1` target identity and signing semantics. **D · CLI/env:** `contract_address`. **D · constant:** checkpoints every 20 blocks. | **L · CLI/env:** local `EthConfig` fields. **L · constant:** `chain-ethereum` defaults. |
| **Solana** | **Config-gated plain + [bidirectional](glossary.md#bidirectional-request):** `SolanaIndexer` → C1. | **Config-gated plain + bidirectional:** `SolanaClient` → C4. | **Not implemented:** C2 rejects. | **Not implemented.** | Implicit: RPC **L** + `program_address` **D**; local validator in tests. | **S:** fixed mainnet identity; Borsh responses. **D · CLI/env:** `program_address`. **D · constant:** checkpoints every 1200 slots. | **L · CLI/env:** local `SolConfig` fields. **L · constant:** `chain-solana` defaults. |
| **Hydration** | **Config-gated plain + bidirectional:** `HydrationIndexer` → C1. | **Config-gated plain + bidirectional:** `HydrationClient` → C4. | **Not implemented:** C2 rejects. | **Not implemented.** | Implicit: RPC **L**; no network validation or integration harness. | **S:** `polkadot:2034`; Borsh responses. **D · constant:** checkpoints every 240 blocks. | **L · CLI/env:** `HydrationConfig`. |
| **Canton** | **Config-gated bidirectional only:** `CantonIndexer` → C1. | **Config-gated bidirectional only:** `CantonClient` → C4; rejects plain `Sign`. | **Not implemented:** C2 rejects. | **Not implemented.** | Implicit: ledger APIs **L** + signer IDs **D**; local sandbox in tests. | **S:** synthetic `canton:global`; ABI responses. **D · CLI/env:** `signer_contract_id`, `signer_template_id`. **D · constant:** checkpoints every 50 offsets. | **L · CLI/env:** local `CantonConfig` fields. |
| **Midnight** | **Config-gated bidirectional only:** `MidnightIndexer` → C1 after the root key is available. | **Config-gated bidirectional only:** `RecoveringMidnightPublisher`/`MidnightPublisher` → C4; rejects plain `Sign`. | **Not implemented:** C2 rejects. | **Not implemented.** | Node-reported `NetworkId`: Mainnet/Preprod/Preview/Stagenet; `Undeployed` in local tests. | **S:** `midnight:mainnet`; Fab responses, attestation hashing, [`Unviable`](bidirectional-calls.md#2-vocabulary). **D · CLI/env:** `central_address`, `responder_address`. **D · constant:** checkpoints every 120 blocks. | **L · CLI/env:** local `MidnightConfig` fields and DUST storage. **L · constant:** `chain-midnight` defaults. |
| **Tron** | **Not implemented:** no source indexer; response hashing rejects Tron sources. | **Not implemented:** no registration. | **Implemented:** raw validation, SHA-256 txID, owner/expiry checks → C2. | **Config-gated target-only:** `TronWatcher` → C1/C3; watches every source's Tron targets. Without config, admitted/signed requests remain `Executing`. | Implicit: endpoint **L**; recorded Nile fixtures, no live local harness. | **S:** `tron:mainnet` target identity and transaction/expiry semantics; no checkpoints. | **L · CLI/env:** `TronConfig` fields. **L · constant:** `chain-tron` defaults. |

- Ethereum, Solana, Hydration, Canton, and Midnight share one config gate
  between source indexing and publishing; the roles cannot be enabled separately.
- Ethereum watching also shares the source indexer/config. Tron configures only
  its watcher.
- NEAR governance is always on: `NearGovernanceClient` reads protocol
  state/config/checkpoints and submits governance/checkpoint votes through
  `RpcExecutor`. It is neither a production source nor a target role.
