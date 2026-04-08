# Canton MPC Integration Review

**Date:** 2026-04-11
**Scope:** 60-agent review (50 initial + 10 verification + 10 deep verification) across `mpc/` (Rust) and `canton-mpc-poc/` (Daml + TS)
**Lines reviewed:** ~25,000

---

## Executive Summary

The Canton integration is architecturally sound. It follows the same plug-in pattern as ETH/Solana/Hydration, the protocol layer is fully chain-agnostic, request ID computation is consistent across Rust/Daml/TypeScript, and the serde types correctly match Canton's wire format.

The initial 50-agent pass produced 12 "Critical" findings. After 20 verification agents did deep code-level analysis, **7 of those 12 were false positives**. The only production-impacting bug is silent hex parse failures in the Canton indexer.

---

## Confirmed Bugs

### 1. Silent hex parse failures (must fix)

**Files:** `chain-signatures/node/src/indexer_canton/mod.rs` lines 91, 103, 157, 173-179

Multiple `hex::decode(...).unwrap_or_default()` and `from_str_radix(...).unwrap_or(0)` calls silently substitute empty bytes or zero values when Canton event fields are malformed. `BytesHex` in Daml is `type Text` with zero validation, so a malicious requester can submit non-hex values through Daml choice arguments.

**Impact:** Wrong request IDs (hash mismatch) and wrong unsigned transactions (signs over incorrect payload). The most consequential instance is `build_calldata` (line 158), which produces wrong transaction calldata.

**Fix:** Replace all `unwrap_or_default()`/`unwrap_or(0)` with `?` error propagation and `tracing::warn!` before returning. Optionally add `ensure` clauses in Daml templates to validate hex format at submission time.

**Instances:**
- `pad_left_32` (line 92): `U256::from_str_radix(stripped, 16).unwrap_or(U256::ZERO)` -- used in request ID hash computation
- `hash_bytes_list` (line 104): `hex::decode(item).unwrap_or_default()` -- corrupts request ID hash
- `build_calldata` (line 158): `hex::decode(arg).unwrap_or_default()` -- produces wrong transaction calldata
- `to_tx_eip1559` (lines 174-180): `from_str_radix(...).unwrap_or(0)` on chain_id, nonce, gas_limit, max_fee, max_priority_fee, value -- produces wrong EIP-1559 transaction

### 2. Canton integration test does not verify signature (should fix)

**File:** `integration-tests/tests/cases/canton.rs` line 129

The test only asserts `!signature_hex.is_empty()`. ETH and Solana tests reconstruct the derived public key and mathematically verify the signature via ecrecover. Canton would pass even with garbage bytes.

**Fix:** Add signature verification matching the ETH/Solana test pattern.

### 3. `(!!) 1` partial function without length guard (should fix)

**Files:** `canton-mpc-poc/daml-packages/daml-vault/daml/Erc20Vault.daml` lines 188, 221

`evmTxParams.args !! 1` is called without validating `length args >= 2`. All existing callers construct exactly 2 elements by convention (ERC-20 `transfer(address,uint256)` parameters), but no `ensure` clause enforces this in the Daml contract. A malicious requester could submit fewer elements, causing an uncatchable runtime crash.

**Fix:** Add `assertMsg "args must have 2 elements" (length evmTxParams.args == 2)` in both `RequestDeposit` and `RequestWithdrawal`.

---

## Confirmed Dead Code

| Item | Location | Action |
|---|---|---|
| `discover_signer_cid` | `indexer_canton/mod.rs:425` | Remove or wire up |
| `CheckpointVotes` struct | `contract/src/primitives.rs:365` | Remove (full impl, zero callers) |
| `Chain`/`PendingTx` re-exports | `contract/src/primitives.rs:1` | Remove (consumers import from `mpc_primitives`) |
| `visit_f64` arm | `canton-types/contracts.rs:122-127` | Remove (unreachable with serde_json) |
| `signer_contract_id` config field | `indexer_canton/mod.rs:300` | Remove or wire into `verify_sign_event` |

---

## Confirmed DRY Violations

| Priority | What | Where | Fix |
|---|---|---|---|
| 1 | `MAX_SECP256K1_SCALAR` 3x | ETH + Solana + Hydration redeclare locally | Import from `mpc_primitives` (Canton already does) |
| 2 | Scalar validation block 5x | All indexers | Extract `hash_to_valid_scalar()` in `mpc_primitives` |
| 3 | `submit_canton_sign_request` body | `canton.rs` inline vs `canton_stream.rs` helper | Move to `CantonSandbox` method |
| 4 | `.get("payload").or_else(\|\| .get("createArgument"))` 5x | Test files | Extract `extract_payload()` helper |
| 5 | Key version guard block | Solana (2x) + Canton (1x) | Promote to `SignatureEvent` trait default method |

---

## Cosmetic Issues

| Item | Location | Severity |
|---|---|---|
| `Transaction::offset` as `Value` instead of `u64` | `ledger_api.rs:80` | Cosmetic (field never read) |
| `serde(default)` on `Option<String>` fields | `ledger_api.rs` multiple | Redundant but harmless |
| Port-wait loop duplicated in `run()` vs `Drop` | `integration-tests/src/canton.rs` | DRY in test infra |
| Blocking `Drop` impl (60s `thread::sleep`) | `integration-tests/src/canton.rs:273-303` | Test infrastructure only |
| Hardcoded port numbers 6865/6868 | `integration-tests/src/canton.rs` | Should be named constants |

---

## Test Coverage Gaps

| Gap | Comparison |
|---|---|
| No checkpoint cleanup verification test | ETH has one |
| No node recovery / offline resilience test | ETH has one |
| No Rust-side golden tests for `compute_request_id` | Daml + TS have them |
| Canton absent from store/sync/compat/nightly suites | ETH present in all |
| No `CantonSignAction` builder | ETH + Solana have them |
| Checkpoint test uses wrong backlog instance | `canton_stream.rs:317` |

---

## False Positives from Initial Review

These were originally flagged as Critical but verified to be incorrect:

| Claim | Why It's Wrong |
|---|---|
| `CatchupCompleted` stalls the node | Canton uses `RecoveryRequeueMode::Immediate`; no stall possible |
| Serde enum tagging mismatch | Canton OpenAPI spec confirms externally-tagged format matches serde default |
| `hashBytesList` violates EIP-712 | Not implementing EIP-712; it's a custom request ID scheme |
| No EIP-712 domain separator | Same -- not implementing EIP-712 |
| `uint256AddChecked` overflow bug | Implementation is correct; overflow check reads pre-clamp value |
| `signer_contract_id` security hole | Canton's package hash prevents deploying contracts with the same template ID |
| Canton emits zero metrics | `ChainEvent::Block` feeds shared `LATEST_BLOCK_NUMBER` gauge |
| `can_act_as`/`can_read_as` dead code | Used in integration test setup (`canton.rs:515-516`) |
| `rlp_encode_unsigned_eip1559` dead code | Called from `stream/ops.rs:137` |
| Recovery ID fixup should move to indexer | Correctly placed; indexer lacks `derived_public_key` for ecrecover |
| Vault `ClaimDeposit` replay | `Consume_*` is consuming; nonce archival prevents duplicates |
| Request ID diverges across languages | All three produce identical hashes |

---

## Architecture Assessment

### Alignment with Other Chains

Canton follows the same plug-in pattern as ETH/Solana/Hydration:

- `ChainStream` trait implementation
- `*Args` + `*Config` pair with `into_config()` / `from_config()` / `into_str_args()`
- `Drop` aborts spawned tasks
- Checkpoint via shared backlog (`ChainEvent::Block`)
- Metrics via shared stream layer (`LATEST_BLOCK_NUMBER`)
- No feature flag gating (consistent with other chains)

### Canton-Specific Code (All Justified)

- **JWT generation** -- Canton requires ES256 auth tokens
- **DER signature encoding** -- Daml's `secp256k1WithEcdsaOnly` only accepts DER
- **EVM tx reconstruction** -- Canton passes structured fields, not raw tx bytes
- **`verify_sign_event` defense-in-depth** -- Daml ledger lacks deposit-based spam filtering
- **Recovery ID fixup in `ops.rs:452`** -- DER encoding loses y-parity; fixup needs `derived_public_key` only available at this stage

### Adding a 4th Chain

Canton sets a good precedent. Required steps:
1. `Chain::NewChain` variant in `mpc-primitives`
2. `derive_epsilon_newchain` in `mpc-crypto`
3. `indexer_newchain` module in `mpc-node`
4. `NewChainArgs`/`NewChainConfig` flattened into `cli.rs`
5. Enum variants in `stream/ops.rs` (~15 match arms)

The match-arm accumulation in `ops.rs` is the long-term scaling concern.

### Daml Contracts

- **Signer:** Sound design, proper nonce replay prevention. `Consume_*` choices use `controller actor` with runtime `assertMsg` (non-idiomatic but safe under Canton's visibility model).
- **Vault:** ERC-20 custody model is correct. Replay prevented by consuming choices + nonce archival. `(!!) 1` needs a length guard.
- **ABI:** Correct per ABI spec. Oracle-verified against viem. Permissive bool decoding matches Solidity runtime.
- **UInt256:** Correct implementation with thorough 3-tier test suite (golden, property, edge-case). `div`/`mod` are unimplemented stubs.
- **EIP-712 module:** Not actually EIP-712 -- it's a custom request ID hashing scheme using keccak256 primitives. Daml/TS/Rust implementations are in sync.
