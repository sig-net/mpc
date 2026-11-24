# Chain integration capability and ownership matrix

Current `mpc-node` capabilities and settings ownership for every
`signet_primitives::Chain` variant.

- **Optional:** constructed when the chain is configured.
- **Unsupported:** no production implementation, not merely unconfigured.

## Settings

- **S — static protocol semantics:** chain identity and deterministic admission,
  derivation, signing, or response behavior.
- **D — deployment-profile value:** nodes in one deployment must agree;
  includes contracts/programs, target networks, and checkpoint cadence.
- **L — local operational configuration:** process connectivity, credentials,
  enablement, storage, resources, and timing policy.
- **†:** **D** value currently supplied per node through CLI/env.

## Consumer paths

- **C1 — source admission/supervision:** `spawn_indexers` → `run_supervised` →
  `handle_chain_event` → `process_sign_request` or a published-response
  processor.
- **C2 — target admission/construction:** `process_sign_request` →
  `SignBidirectionalEventExt::validate`; first-leg response →
  `advance_bidirectional_to_execution` → `to_bidirectional_tx` /
  `sign_and_hash_transaction` → execution watch.
- **C3 — execution/final response:** watcher `ExecutionConfirmed` →
  `process_execution_confirmed` → `answer_execution` →
  `respond_bidirectional::CompletedTx` → final source-chain sign request → C4.
- **C4 — publishing:** `ChainStack::publishers` →
  `RpcExecutor::dispatch_loop` → `execute_publish` → `ChainPublisher`.
  Publish failover uses the same path.

## Matrix

| Chain | Source events | Response publisher | Target preparation | Target watcher | Network-wide settings | Local settings |
|---|---|---|---|---|---|---|
| **NEAR** | **Test-only plain:** `mpc_chain_near::run` → sign queue, outside C1. **Production: unsupported.** | **Always:** `NearClient` → C4; currently serves the test-only source. | **Unsupported:** C2 rejects. | **Unsupported.** | **S:** `near:mainnet`; no checkpoints. **D:** `mpc_contract_id`†. | **L:** RPC, account ID/keys. |
| **Ethereum** | **Optional plain:** `EthereumIndexer` → C1. | **Optional:** `EthClient` → C4; batches responses; shares `EthConfig` with indexing. | **Supported:** unsigned validation and `sign_and_hash_ethereum` → C2. | **Optional:** `ExecutionWatcher` inside `EthereumIndexer` → C1/C3; watches every source's Ethereum targets. | **S:** `eip155:1` target identity and signing semantics. **D:** `contract_address`†, `EthNetwork`/EIP-155 chain ID†, checkpoints every 20 blocks. | **L:** execution RPC, response key, enablement, RPC/gas/publisher/indexer tuning. |
| **Solana** | **Optional plain + bidirectional:** `SolanaIndexer` → C1. | **Optional plain + bidirectional:** `SolanaClient` → C4. | **Unsupported:** C2 rejects. | **Unsupported.** | **S:** fixed mainnet identity; Borsh responses. **D:** `program_address`†, checkpoints every 1200 slots. | **L:** RPC, payer key, enablement, polling/retry/gating. |
| **Bitcoin** | **Unsupported:** no indexer/wiring. | **Unsupported:** no registration. | **Unsupported:** C2 rejects. | **Unsupported.** | **S:** identity and `ChainConfig` defaults only; no runtime capability implied. **D:** none. | **L:** none; no chain config. |
| **Hydration** | **Optional plain + bidirectional:** `HydrationIndexer` → C1. | **Optional plain + bidirectional:** `HydrationClient` → C4. | **Unsupported:** C2 rejects. | **Unsupported.** | **S:** `polkadot:2034`; Borsh responses. **D:** checkpoints every 240 blocks; no separate network/contract setting. | **L:** WebSocket RPC, signer URI, enablement. RPC implicitly selects the network. |
| **Canton** | **Optional bidirectional only:** `CantonIndexer` → C1. | **Optional bidirectional only:** `CantonClient` → C4; rejects plain `Sign`. | **Unsupported:** C2 rejects. | **Unsupported.** | **S:** synthetic `canton:global`; ABI responses. **D:** `signer_contract_id`†, `signer_template_id`†, checkpoints every 50 offsets. | **L:** HTTP/WS APIs, OIDC credentials, ledger user, `party_id`, enablement. |
| **Midnight** | **Optional bidirectional only:** `MidnightIndexer` → C1 after the root key is available. | **Optional bidirectional only:** `RecoveringMidnightPublisher`/`MidnightPublisher` → C4; rejects plain `Sign`. | **Unsupported:** C2 rejects. | **Unsupported.** | **S:** `midnight:mainnet`; Fab responses, attestation hashing, `Unviable`. **D:** `central_address`†, `responder_address`†, checkpoints every 120 blocks. | **L:** node/indexer URLs, funding seed, DUST store, output storage, artifacts, timing/retry policy. |
| **Tron** | **Unsupported:** no source indexer; response hashing rejects Tron sources. | **Unsupported:** no registration. | **Supported:** raw validation, SHA-256 txID, owner/expiry checks → C2. | **Optional target-only:** `TronWatcher` → C1/C3; watches every source's Tron targets. | **S:** `tron:mainnet` target identity and transaction/expiry semantics; no checkpoints. **D:** no separate network setting. | **L:** endpoint, API key, watcher enablement, polling/timeout/retry. Endpoint implicitly selects the network. |

- Ethereum, Solana, Hydration, Canton, and Midnight share one optional config
  between source indexing and publishing; the roles cannot be enabled separately.
- Ethereum watching also shares the source indexer/config. Tron configures only
  its watcher.
- NEAR governance is always on: `NearGovernanceClient` reads protocol
  state/config/checkpoints and submits governance/checkpoint votes through
  `RpcExecutor`. It is neither a production source nor a target role.

## Current ambiguities

- **D values use local inputs:** Ethereum contract, Solana program, Midnight
  central/responder addresses, Canton signer identifiers, and NEAR MPC contract.
  Nodes can select different request universes or response destinations.
  Canton `party_id` remains node-local.
- **`ChainConfig` mixes categories:** response encoding, target support, and
  `Unviable` support are **S**; `checkpoint_interval` is **D**; finality,
  observation, response, and stall timings act as **L** supervision, monitoring,
  and failover policy despite encoding network-derived facts.
- **Ethereum has two network identities:** CAIP-2 is always `eip155:1`, while
  `EthNetwork` selects Mainnet, Sepolia, or Anvil. Admission separately compares
  the transaction's EIP-155 chain ID with the configured network. That choice is
  propagated to every source; without Ethereum config, the check is skipped.
- **Watchers do not define target support:** C2 admits only Ethereum and Tron
  targets regardless of watcher configuration. Without Tron config, requests
  are admitted and signed but remain `Executing`; without Ethereum config, they
  also lose execution watching and the EIP-155 admission check.
