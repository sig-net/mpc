# Canton Integration Code Review

**Date:** 2026-04-11
**Scope:** MPC Rust indexer, canton-types crate, Daml contracts (6 packages), TypeScript MPC service, integration tests, CI/CD
**Method:** 50 review agents + 50 verification agents (100 total)

---

## Summary

| Category | Count |
|----------|-------|
| Confirmed issues | 21 |
| False / wrong claims (retracted) | 6 |
| Overstated / partially correct | 10 |
| Confirmed simplifications | 9 |

---

## Confirmed Issues

### Critical

#### 1. `rlp_encode_unsigned_eip1559` signs `keccak256(b"")` on error

**File:** `mpc/chain-signatures/node/src/indexer_canton/mod.rs:187-200`

On `to_tx_eip1559` failure, returns `vec![]` instead of propagating the error. Downstream `hash_rlp_data(vec![])` produces `keccak256(b"")`, and the node signs this wrong hash. `Scalar::from_bytes` accepts it (the value is below the curve order), so signing proceeds silently.

**Trace:**
```
to_tx_eip1559() -> Err
  -> rlp_encode_unsigned_eip1559() returns vec![]     (line 197)
  -> hash_rlp_data(vec![]) = keccak256(b"")           (line 247)
  -> Scalar::from_bytes(keccak256_empty) -> Some       (line 249)
  -> Node signs keccak256(b"") instead of bailing
```

**Fix:** Change `rlp_encode_unsigned_eip1559` to return `anyhow::Result<Vec<u8>>` and propagate with `?`.

#### 2. Deterministic entropy — structural asymmetry vs other chains

**File:** `mpc/chain-signatures/node/src/indexer_canton/mod.rs:744-745`

```rust
let request_id = canton_event.generate_request_id();
let entropy: [u8; 32] = keccak256(request_id).into();
```

Entropy is `keccak256(request_id)`, fully computable from event fields the requester controls. Ethereum uses the transaction hash (chain-derived); Solana uses the tx signature bytes (unpredictable). Canton entropy feeds into `derive_delta` in `kdf.rs`, which randomizes the presignature.

**Risk level:** The delta's purpose is to separate concurrent requests sharing a presignature, not to be a secret. Whether a requester who can predict delta can manipulate the signing protocol outcome requires deeper cryptographic analysis. The asymmetry with other chains warrants scrutiny.

#### 3. JWT 300s expiry contradicts design doc's `max-token-lifetime = 1.minute`

**File:** `mpc/chain-signatures/node/src/indexer_canton/mod.rs:72`

```rust
exp: now + 300,
```

Design doc (`proposals/canton-mpc-auth-design.md:194`) specifies `max-token-lifetime = 1.minute`. A freshly minted 300s token has remaining TTL ~300s, which exceeds 60s. Canton would reject it immediately if configured per the design.

Additionally, the `daml.ws.auth` WebSocket subprotocol supports in-band JWT refresh, but the code never sends a refresh message — the token is used only in the initial HTTP upgrade headers (line 604-611). Connections alive longer than 5 minutes operate with an expired JWT.

**Fix:** Use 30-60s for command submissions (per design), implement in-band refresh for WebSocket streams.

---

### High

#### 4. `to_tx_eip1559` uses `unwrap_or(0)` inconsistently with its own `Result` return type

**File:** `mpc/chain-signatures/node/src/indexer_canton/mod.rs:174-180`

```rust
chain_id: u64::from_str_radix(&p.chain_id, 16).unwrap_or(0),
nonce:    u64::from_str_radix(&p.nonce, 16).unwrap_or(0),
// ... 4 more fields
```

The function returns `anyhow::Result<TxEip1559>` and uses `?` for `hex::decode` on `p.to` (line 165), but silently substitutes zero for all numeric fields on parse failure. A zero `chain_id` switches EIP-155 replay domain; zero `gas_limit` causes immediate revert.

**Note:** Inputs from the Daml ledger are well-formed hex in practice (`BytesHex` values). The risk is latent, not active — but the inconsistency with the function's own error-handling contract is real.

**Fix:** Replace `unwrap_or(0)` with `.context("invalid chain_id hex")?` for each field.

#### 5. `process_canton_event` swallows channel-closed signal

**File:** `mpc/chain-signatures/node/src/indexer_canton/mod.rs:690-692`

`process_canton_event` returns `()`. When `tx.send()` fails inside the function, it logs and returns — but the caller loop at line 690 discards the return and continues processing remaining events in the transaction. Only the `Block` send at line 695 catches channel closure.

**Impact:** Up to N failed `send` attempts per transaction (where N = remaining events) before the Block send exits the loop.

**Fix:** Return `bool` from `process_canton_event`; break the event loop on `false`.

#### 6. `Consume_*` choices use `controller actor` with runtime `assertMsg`

**File:** `canton-mpc-poc/daml-packages/daml-signer/daml/Signer.daml:144-195`

All three `Consume_*` choices (`Consume_SignBidirectional`, `Consume_SignatureResponded`, `Consume_RespondBidirectional`) use `controller actor` where `actor` is a free parameter, with an `assertMsg` guard checking `actor` is in `operators` or is `requester`.

The threat surface is narrower than "any party" — Daml requires controller to have at least observer visibility. But `sigNetwork` (an observer on these contracts) could exercise the choice and be rejected only at the `assertMsg` level, not at the ledger authorization layer.

**Fix:** Replace `controller actor` + `assertMsg` with `controller operators, requester`.

#### 7. `VaultProposal.ensure` doesn't validate `alreadySigned ⊆ allOperators`

**File:** `canton-mpc-poc/daml-packages/daml-vault/daml/Erc20Vault.daml:78`

```daml
ensure not (null allOperators) && unique allOperators && unique alreadySigned
```

A proposal created with a party in `alreadySigned` that is not in `allOperators` passes the ensure check but becomes permanently stuck: `sort newSigned` will never equal `sort allOperators`.

**Fix:** Add `&& all (`elem` allOperators) alreadySigned` to the ensure clause.

#### 8. `try_publish_canton` uses raw `serde_json::json!{}` bypassing typed structs

**File:** `mpc/chain-signatures/node/src/rpc.rs:1887-1954`

Command submission constructs JSON via `json!{}` with string field names. Typed structs (`SubmitAndWaitForTransactionRequest`, `JsCommands`, `Command::ExerciseCommand`) exist in `canton-types` but are unused. A field name typo silently breaks at runtime.

**Fix:** Construct typed structs and serialize them.

---

### Medium

#### 9. Missing cryptographic assertion in integration test

**File:** `mpc/integration-tests/tests/cases/canton.rs:129`

```rust
assert!(!signature_hex.is_empty(), "signature is empty");
```

Ethereum tests verify recovered address against the expected derived key (full ECDSA recovery chain). Canton only checks non-empty string. The test would pass with garbage signature bytes.

#### 10. `startMonitor()` interval leak on WebSocket reconnect

**File:** `canton-mpc-poc/ts-packages/canton-sig/src/mpc-service/server.ts:90-93`

`startMonitor()` unconditionally calls `setInterval` with no guard. `onReady` fires on every WebSocket reconnect (confirmed in `ledger-stream.ts:135`), spawning duplicate intervals. Previous handle is orphaned — `clearInterval` can never reach it.

**Fix:** Add `if (this.monitorInterval !== null) return;` at the top.

#### 11. `curl | sh` in CI without checksum verification

**File:** `mpc/.github/workflows/canton.yml:50`

```yaml
curl -fsSL https://get.digitalasset.com/install/install.sh | sh
```

The only tool in the project installed via pipe-to-shell. All other tools use pinned GitHub Actions or package managers with version pinning.

#### 12. Missing "Nonce requester mismatch" test

**File:** `canton-mpc-poc/daml-packages/daml-signer/daml/Signer.daml:51`

The guard `assertMsg "Nonce requester mismatch" (nonce.requester == requester)` has no negative test. `testSignBidirectionalWrongSignerNonceFails` tests the *sigNetwork* mismatch (line 50), not the requester mismatch.

#### 13. Test authority inflation in Consume tests

**File:** `canton-mpc-poc/daml-packages/daml-signer/daml/TestSigner.daml:215,231`

Both `testConsumeSignBidirectionalByOperator` and `testConsumeSignBidirectionalByRequester` submit with `actAs operator <> actAs requester`. Neither verifies solo authorization. Other Consume tests (for `SignatureRespondedEvent`, `RespondBidirectionalEvent`) correctly use solo party submission.

#### 14. Checkpoint test doesn't test persistence

**File:** `mpc/integration-tests/tests/cases/canton_stream.rs:327-328`

`stream2` is created with `Backlog::new()` (fresh), not the checkpointed `backlog1`. The test verifies "a new stream receives events" — not "a new stream resumes from checkpoint." Same bug exists in `solana_stream.rs`.

#### 15. `verbose: true` + no server-side template filter on WS subscription

**File:** `mpc/chain-signatures/node/src/indexer_canton/mod.rs:626-637`

The subscription uses `verbose: true` with an empty `filters_by_party` value (`{}`). Canton sends full contract payloads for all events; the node processes only 2 templates (`SignBidirectionalEvent`, `SignatureRespondedEvent`) and discards everything else client-side. Up to 3 `format!` allocations per discarded event.

#### 16. No `record_request_latency` metrics

**File:** `mpc/chain-signatures/node/src/indexer_canton/mod.rs` — absent

Ethereum records indexing latency per sign request (`indexer_eth/mod.rs:1008`). Canton records nothing. The shared `run_stream` loop only records `LATEST_BLOCK_NUMBER`, not request latency.

#### 17. `discover_signer_cid` is dead public API

**File:** `mpc/chain-signatures/node/src/indexer_canton/mod.rs:425`

`pub async fn` with zero callers anywhere in the codebase.

#### 18. Misleading derives comment

**File:** `mpc/chain-signatures/node/src/indexer_canton/mod.rs:47`

Comment says "matches HydrationSignatureRespondedEvent" but Hydration derives `PartialEq, Eq` while Canton omits them.

#### 19. Double `compute_request_id` per sign event

**File:** `mpc/chain-signatures/node/src/indexer_canton/mod.rs:744,238`

`generate_request_id()` called once for entropy (line 744), then again inside `generate_sign_request` (line 238). Each invocation costs ~12 keccak256 calls (with 2 args).

**Fix:** Pass pre-computed `request_id` into `generate_sign_request`.

#### 20. `#[serde(default)]` on `Option<T>` redundant (10 instances)

**File:** `mpc/chain-signatures/canton-types/src/ledger_api.rs`

Serde already deserializes missing keys as `None` for `Option<T>`. The attribute is redundant noise across 10 fields.

#### 21. No per-node audit attribution (Known Gap #4 from design doc)

**Files:** `canton-mpc-poc/daml-packages/daml-signer/daml/Signer.daml:162,182`

`responder` field is always set to `sigNetwork`. All 8 MPC nodes share the same party. No `submittedBy` field exists for forensic attribution.

---

## Retracted Claims (False)

| # | Original Claim | Why It's Wrong |
|---|---------------|----------------|
| 2 | `mulLimbs` carry clobber in UInt256.daml | Algorithm is correct schoolbook multiplication. Each outer iteration writes carry to unique index `i+10`. Inner loops correctly read/accumulate previous values |
| 5 | `vec_string_33bytes` malformed golden vector | Vector is exactly 256 hex chars (4 slots x 64). Original agent miscounted — Slot 2+3 are on one line as 128 chars, not truncated |
| 15 | `args !! 1` before validation in RequestWithdrawal | Daml `let` is lazy. `assertMsg` at line 223 evaluates before `args !! 1` is forced at line 230. No crash before assertion |
| 16 | CatchupCompleted strands backlog entries | `chain_supports_catchup(Canton)` returns `false` (only Ethereum returns true). Canton always gets `RecoveryRequeueMode::Immediate`. Missing event is harmless by design |
| 25 | `CantonError` is dead code | Unused in Rust callers, but it's a `pub` type in a library crate modeling a real Canton API wire format (`JsCantonError` in OpenAPI spec). Intentional API coverage |
| 36 | Bidirectional coupling between indexer_canton and rpc.rs | Coupling is strictly one-way: `rpc.rs` imports from `indexer_canton`. Canton imports nothing from rpc |

---

## Overstated / Partially Correct Claims

| # | Original Claim | Corrected Assessment |
|---|---------------|---------------------|
| 3 | `unwrap_or_default` in `hash_bytes_list`/`build_calldata` "silently corrupts data" | Inputs from Daml are always well-formed hex. The real issue is `to_tx_eip1559`'s `unwrap_or(0)` inconsistency (see confirmed #4) |
| 6 | Consume choices: "any party can exercise" | Threat surface limited to parties with observer visibility (signatories/observers/disclosed), not "any party." `assertMsg` is still an anti-pattern |
| 7 | Original claim about `SignatureRespondedEvent.requestId` not verified | `RespondBidirectionalEvent.requestId` IS verified (lines 173-174, 274-275). Only `SignatureRespondedEvent` is consumed without field check — audit trail gap, not security bypass |
| 9 | `padLeft` silent truncation | Technically correct behavior, but not reachable with well-formed inputs. All field widths are at/below target by spec |
| 10 | `hexToInt` crashes on > 63-bit values | Theoretically correct, but no real EVM chain ID exceeds 2^63. Opaque `fromSome` error is the practical issue |
| 12 | No reconnect backoff (Canton-specific) | Correct, but Solana has identical fixed 1s retry. Project-wide convention, not Canton-specific |
| 14 | `Erc20Holding` missing `ensure` | Correct but not exploitable — Holdings only created inside Vault choices that enforce `not (null operators)` |
| 19 | All Canton tests never run in CI | Stream tests DO run via `canton.yml` with `--ignored` flag. Only `test_canton_eth_bidirectional_flow` truly never runs in CI |
| 24 | `EventFormatInline` duplicates `EventFormat` | They differ in `#[serde(default)]` on `filters_by_party`. Not truly identical |
| 31 | Both `mulAsym3A` and `mulAsym3Result` are overlong | Only `mulAsym3A` is 66 chars (confirmed bug). `mulAsym3Result` is 64 chars (correct) |
| 34 | Command deduplication entirely absent | Rust `rpc.rs` HAS deterministic `commandId` (`"mpc-respond-{requestId}"`). TS uses `crypto.randomUUID()` defeating dedup — that's the real gap |

---

## Confirmed Simplification Opportunities

### Rust

| Opportunity | Location | Impact |
|-------------|----------|--------|
| `template_suffix_matches` uses `format!` allocation | `canton-types/src/ledger_api.rs:389` | Up to 3 heap allocations per event in hot path. Use `strip_suffix` instead |
| `process_canton_event` nesting (7 levels, 3 duplicated blocks) | `indexer_canton/mod.rs:722-790` | Extract `send_event` helper, flatten with early returns |
| Test code duplication (`evm_tx_params`, `RequestDeposit`, requestId extraction) | `tests/cases/canton.rs` + `canton_stream.rs` | Move `submit_canton_sign_request` into `CantonSandbox::submit_sign_request(&mut self)` |
| `into_str_args` 7 repetitive `if let` blocks | `indexer_canton/mod.rs:355-378` | Valid but project-wide convention (ETH/SOL same pattern) |

### Daml

| Opportunity | Location | Impact |
|-------------|----------|--------|
| `foldl (<>) ""` should be `mconcat` | `daml-eip712/daml/Eip712.daml:56` | Inconsistent with `RequestId.daml:38` which uses `mconcat` |
| `ensureEvenHex` single-use helper | `daml-eip712/daml/Eip712.daml:29-31` | Sole caller is `hexToInt`. Inline it |
| `predecessorId`/`caip2Id` duplication | `daml-vault/daml/Erc20Vault.daml:135-137,234-237` | Identical in `RequestDeposit` and `RequestWithdrawal`. Extract `computeVaultIds` helper |
| `daml-uint256` is orphaned | `daml-packages/daml-uint256/` | Zero consumers in any daml.yaml or .daml import |
| `randUint256` excludes max limb value | `daml-uint256/daml/TestProperties.daml:19` | `limbMax = 268435455` should be `268435456` to cover full range |
| `mulAsym3A` test vector overlong | `daml-uint256/daml/TestUInt256.daml:719` | 66 hex chars instead of 64 (33 x `a5` instead of 32) |

### TypeScript

| Opportunity | Location | Impact |
|-------------|----------|--------|
| `templateSuffix` duplicated byte-for-byte | `server.ts:20` + `tx-handler.ts:41` | Extract to shared module |
| `MpcServerConfig` / `MpcServiceConfig` near-duplicate | `server.ts:27` + `tx-handler.ts:48` | Differ only in `parties` vs `actAs`. Unify |
