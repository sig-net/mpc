# Chain integration capability and ownership matrix

Current and planned chain-integration roles and settings ownership. Labels
apply to each role, not to the chain itself; planned rows list required work.

- **Config-gated:** the role is implemented and constructed when its chain
  configuration is present.
- **Not implemented:** the chain has no production implementation of this role.

## Settings

- **S — static protocol semantics:** [chain identity](account-derivation.md#chain-identification),
  reused across dev/test networks, and deterministic request/response rules,
  including target signing schemes and `Unviable` support.
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

| Chain | Integration role | Request types | Target signing | Execution watcher | Networks / selection | Network-wide settings |
|---|---|---|---|---|---|---|
| **NEAR** | Governance + test-only source | Test-only [plain](glossary.md#plain-sign-request); production not implemented. | Not implemented. | Not implemented. | Implicit: RPC **L** + `mpc_contract_id` **D**; local sandbox in tests. | **S:** `near:mainnet`; no checkpoints. **D · CLI/env:** `mpc_contract_id`. |
| **Ethereum** | Source + target | Plain | secp256k1/ECDSA; Keccak-256; EIP-155 transaction semantics via C2. | Config-gated; no `EthConfig` also skips the EIP-155 admission check. | Explicit: `EthNetwork` **D · CLI/env** — Mainnet/Sepolia; Anvil in tests. | **S:** `eip155:1` target identity and signing semantics. **D · CLI/env:** `contract_address`. **D · constant:** checkpoints every 20 blocks. |
| **Solana** | Source-only | Plain + [bidirectional](glossary.md#bidirectional-request) | Not implemented. | Not implemented. | Implicit: RPC **L** + `program_address` **D**; local validator in tests. | **S:** fixed mainnet identity; Borsh responses. **D · CLI/env:** `program_address`. **D · constant:** checkpoints every 1200 slots. |
| **Canton** | Source-only | Bidirectional only | Not implemented. | Not implemented. | Implicit: ledger APIs **L** + signer IDs **D**; local sandbox in tests. | **S:** synthetic `canton:global`; ABI responses. **D · CLI/env:** `signer_contract_id`, `signer_template_id`. **D · constant:** checkpoints every 50 offsets. |
| **Midnight** | Source-only | Bidirectional only | Not implemented. | Not implemented. | Node-reported `NetworkId`: Mainnet/Preprod/Preview/Stagenet; `Undeployed` in local tests. | **S:** `midnight:mainnet`; Fab responses, attestation hashing, [`Unviable`](bidirectional-calls.md#2-vocabulary). **D · CLI/env:** `central_address`, `responder_address`. **D · constant:** checkpoints every 120 blocks. |
| **Tron** | **Target-only; includes Midnight → Tron** | Not implemented. | secp256k1/ECDSA; SHA-256 txID; owner/expiry semantics via C2. | Config-gated; without it, admitted/signed requests remain `Executing`. | Implicit: endpoint **L**; recorded Nile fixtures, no live local harness. | **S:** `tron:mainnet` target identity and transaction/expiry semantics; no checkpoints. |
| **Zcash** | **Planned target-only; Midnight → Zcash** | Not implemented. | **TBD:** transaction family, curve/signing scheme, sighash/txID, replay/expiry, and network binding. | **Planned:** target watcher and disabled-watcher behavior. | **TBD:** Mainnet/Testnet/local selection. | **S:** CAIP-2 identity TBD. **D:** finality/observation expectations TBD; no source checkpoints. |

- Source indexing and C4 publishing share one config gate on Ethereum, Solana,
  Canton, and Midnight. NEAR's publisher is always registered for its test-only
  source.
- Ethereum watching also shares the source indexer/config. Tron configures only
  its watcher.
- NEAR governance is always on: `NearGovernanceClient` reads protocol
  state/config/checkpoints and submits governance/checkpoint votes through
  `RpcExecutor`. It is neither a production source nor a target role.
- Remaining configuration is **L**: per-node endpoints, credentials, enablement,
  storage, and worker timing/retry policy. These live in the chain config and
  chain-crate defaults; Midnight also has node-local DUST storage.
