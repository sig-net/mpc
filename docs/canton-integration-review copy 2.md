# Canton Integration Review

**Date:** 2026-04-11
**Scope:** Canton MPC integration -- Rust indexer, canton-types crate, Daml contracts, integration tests
**Method:** 100 agents (50 review + 50 verification), each independently examining specific files and concerns

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 7 |
| High | 5 |
| Important | 32 |
| Refuted (false positives corrected) | 6 |

---

## Critical -- Must Fix

### C1. Silent data corruption via `unwrap_or(0)` / `unwrap_or_default()` on untrusted input

**Files:** `node/src/indexer_canton/mod.rs:91,104,158,174-180`

Malformed hex from Canton silently produces zero values for `chain_id`, `nonce`, `gas_limit`, `value`, and args. A `chain_id=0` removes EIP-1559 replay protection. A zeroed arg corrupts the request ID hash, causing a Rust/Daml hash mismatch.

Instances:
- `pad_left_32` (line 91): `U256::from_str_radix(...).unwrap_or(U256::ZERO)` -- returns `[u8; 32]`, can't propagate errors
- `hash_bytes_list` (line 104): `hex::decode(item).unwrap_or_default()` -- returns `[u8; 32]`, can't propagate
- `build_calldata` (line 158): `hex::decode(arg).unwrap_or_default()` -- returns `Vec<u8>`, can't propagate
- `to_tx_eip1559` (lines 174-180): `unwrap_or(0)` for chain_id, nonce, gas_limit, max_fee, max_priority_fee; `unwrap_or(U256::ZERO)` for value -- this function DOES return `anyhow::Result` but deliberately swallows errors

**Fix:** Change `pad_left_32`, `hash_bytes_list`, `build_calldata` to return `anyhow::Result`. In `to_tx_eip1559`, replace `unwrap_or(0)` with `.context("field_name")?`.

---

### C2. Empty-vec RLP encoding leads to signing `keccak256(b"")`

**File:** `node/src/indexer_canton/mod.rs:195-198,246-247`

When `to_tx_eip1559` fails, `rlp_encode_unsigned_eip1559` returns `vec![]`. The caller hashes `keccak256(b"")`, which produces a valid `Scalar` (`0xc5d246...`), passes the `MAX_SECP256K1_SCALAR` guard, and creates a real `IndexedSignRequest`. The MPC cluster signs garbage.

**Verified:** Full path traced through `generate_sign_request` -> `hash_rlp_data` -> `Scalar::from_bytes` -> `IndexedSignRequest`. No guard catches empty input.

**Fix:** Change `rlp_encode_unsigned_eip1559` to return `anyhow::Result<Vec<u8>>` and propagate errors via `?`.

---

### C3. `Address::from_slice` panic on short `to` field

**File:** `node/src/indexer_canton/mod.rs:167-170`

If `hex::decode(&p.to)` produces fewer than 20 bytes, the `else` branch passes a short slice to `Address::from_slice`, which calls `panic!` unconditionally (confirmed from alloy-primitives source). This bypasses the function's `anyhow::Result` return type.

**Fix:** Replace with `FixedBytes::try_from(addr_bytes).context("invalid address length")?`.

---

### C4. `controller actor` anti-pattern in Signer.daml Consume choices

**File:** `daml-signer/daml/Signer.daml:144-195`

All three `Consume_*` choices (`Consume_SignBidirectional`, `Consume_SignatureResponded`, `Consume_RespondBidirectional`) use:
```daml
choice Consume_X : ()
  with actor : Party
  controller actor
  do assertMsg "Not authorized" (actor `elem` operators || actor == requester)
```

`actor` is caller-supplied. Any party can submit the transaction -- authorization relies entirely on a runtime `assertMsg`, not Daml's ledger-level controller enforcement. This is the documented Daml anti-pattern for authorization.

**Fix:** Replace with `controller operators, requester` (or the appropriate subset) and remove the `actor` parameter.

---

### C5. `RequestDeposit`/`RequestWithdrawal` accept unvalidated `signerCid`

**File:** `daml-vault/daml/Erc20Vault.daml:113,146,202,245`

Both choices accept `signerCid : ContractId Signer` and exercise it directly without fetching or checking `signer.sigNetwork == sigNetwork`. A requester can pass a `Signer` from a different (possibly rogue) network.

**Fix:** Add before exercise:
```daml
signer <- fetch signerCid
assertMsg "Signer sigNetwork mismatch" (signer.sigNetwork == sigNetwork)
```

---

### C6. `nonceCidText` not validated against `nonceCid`

**File:** `daml-signer/daml/Signer.daml:41-55`

In `SignBidirectional`, the archived `nonceCid` and the `nonceCidText` stored in the `SignRequest` (propagated to `SignBidirectionalEvent`) are completely independent values. No assertion links them. A caller can pass any string as `nonceCidText` while providing a valid `nonceCid` to satisfy the archive, potentially enabling request ID collisions.

**Fix:** Add `assertMsg "nonceCidText mismatch" (nonceCidText == show nonceCid)` before archiving.

---

### C7. Counter advances before events are processed

**File:** `node/src/indexer_canton/mod.rs:688-698`

In `subscribe_and_process`, `*counter = value.offset` (line 688) runs before `process_canton_event` (line 690). If the channel closes mid-loop (`tx.send` returns `Err`), the outer reconnect loop uses the already-advanced `counter` as `begin_exclusive` (line 630), permanently skipping unprocessed events.

**Fix:** Advance counter only after all events are processed and `ChainEvent::Block` is sent:
```rust
for event in &value.events {
    process_canton_event(...).await;
}
if tx.send(ChainEvent::Block(value.offset)).await.is_err() {
    tracing::error!("canton event channel closed");
    return Ok(());
}
*counter = value.offset; // advance AFTER success
```

---

## High -- Should Fix

### H1. JWT expires mid-session without renewal

**File:** `node/src/indexer_canton/mod.rs:71,598`

JWT has a 5-minute TTL (`exp: now + 300`), generated once per WebSocket connection. No refresh mechanism exists during a session. Active streams can live indefinitely (stall watchdog resets on every message), meaning the token expires while the session is alive.

**Fix:** Either send a refresh frame before expiry using the `daml.ws.auth` subprotocol, or reconnect proactively ~30s before expiry.

---

### H2. No reconnect backoff

**File:** `node/src/indexer_canton/mod.rs:587`

Fixed 1-second `sleep` on every reconnect. No exponential backoff, no jitter, no max retry count. Same pattern exists in `indexer_sol.rs`.

**Fix:** Exponential backoff with jitter (1s -> 60s cap), resetting on successful long-lived connection.

---

### H3. No `wss://` scheme enforcement

**File:** `node/src/indexer_canton/mod.rs:600-615`

The WebSocket URL is accepted as-is from config. A `ws://` URL sends the JWT Bearer token in plaintext. Integration tests explicitly use `ws://`. No validation exists anywhere in the config chain.

**Fix:** Validate `wss://` scheme at startup in `CantonConfig` construction. Log a prominent warning (or reject) for `ws://`.

---

### H4. No `sigNetwork` check on `ClaimDeposit`/`CompleteWithdrawal`

**File:** `daml-vault/daml/Erc20Vault.daml:172-178,273-279`

After fetching `respondBidirectionalEventCid`, only `requestId` and the MPC signature are checked. No assertion that `outcome.sigNetwork == sigNetwork` or `outcome.operators == operators`. Defense-in-depth gap.

**Fix:** Add:
```daml
assertMsg "sigNetwork mismatch" (outcome.sigNetwork == sigNetwork)
assertMsg "operators mismatch" (sort outcome.operators == sort operators)
```

---

### H5. `IssueNonce` open to any party

**File:** `daml-signer/daml/Signer.daml:34-39`

```daml
nonconsuming choice IssueNonce : ContractId SigningNonce
  with requester : Party
  controller requester
  do create SigningNonce with sigNetwork; requester
```

Any party can mint unlimited `SigningNonce` contracts. No authorization check, no rate limit, `nonconsuming`.

**Fix:** Restrict to `controller sigNetwork` with `requester` as an argument, or add an allowlist.

---

### H6. `hex::decode` doesn't strip `0x` prefix (fragile)

**File:** `node/src/indexer_canton/mod.rs:104,158,165`

4 of 5 `hex::decode` call sites don't strip `0x` prefix. The `hex` crate (0.4) rejects `0x`-prefixed strings with `InvalidHexCharacter`. Currently safe because Daml `BytesHex` never has `0x` prefix, but fragile -- only `parse_der_signature` (line 941) defensively strips it.

**Fix:** Strip `0x` before `hex::decode` at all call sites, matching `pad_left_32`'s existing pattern.

---

## Important -- Structural & Simplification

### Rust Indexer Organization

**I1. Split 970-line `mod.rs` into sub-modules**

The file mixes 7 concerns. Proposed structure:
```
indexer_canton/
  mod.rs          # re-exports + SignatureEvent impl
  config.rs       # CantonConfig, CantonArgs, JWT generation
  eip712.rs       # hash_text, pad_left_32, hash_bytes_list, compute_request_id
  tx_encode.rs    # build_calldata, to_tx_eip1559, rlp_encode_unsigned_eip1559
  signature.rs    # der_encode_signature, parse_der_signature, parse_*_event
  verification.rs # verify_sign_event
  stream.rs       # CantonStream, run_canton_event_loop, subscribe_and_process
```

---

### Rust Types Cleanup

| Issue | File | Action |
|-------|------|--------|
| `CantonError` is dead code | `ledger_api.rs:365` | Delete |
| `templates` module misplaced | `ledger_api.rs:377-390` | Move to `contracts.rs` or indexer |
| Response payloads missing `sigNetwork`, `operators`, `requester` | `contracts.rs:74-97` | Add fields |
| `EventFormat` / `EventFormatInline` duplicated | `ledger_api.rs:182-187,312-317` | Merge into one struct |
| `OffsetCheckpointValue` single-field wrapper | `ledger_api.rs:221-224` | Inline into enum variant |
| `#[serde(default)]` on non-optional Daml `Text` fields | `contracts.rs:55,59,61` | Remove (masks schema drift) |
| `visit_f64` dead code in `deserialize_u32_lenient` | `contracts.rs:122-127` | Remove |
| Unused `Hash` derive on `EvmTransactionParams`/`SignBidirectionalRequestedEvent` | `contracts.rs:18,40` | Remove |
| `discover_signer_cid` never called | `mod.rs:425-474` | Remove (~50 lines) |
| `to_tx_eip1559` is `pub` but only used internally | `mod.rs:164` | Change to `fn` or `pub(crate)` |
| Import ordering inconsistent | `mod.rs:1-22` | Group: std, external, crate |

---

### Daml Simplification

| Issue | Files | Savings |
|-------|-------|---------|
| `SignRequest` and `SignBidirectionalEvent` duplicate 14 fields | `Signer.daml:86-150` | Extract shared `SignPayload` record (~30 lines) |
| `RequestDeposit`/`RequestWithdrawal` signing setup duplicated | `Erc20Vault.daml:135-151,234-250` | Extract helper (~20 lines) |
| `ClaimDeposit`/`CompleteWithdrawal` outcome verification duplicated | `Erc20Vault.daml:165-186,267-283` | Extract helper (~15 lines) |
| `PendingDeposit`/`PendingWithdrawal` nearly identical | `Erc20Vault.daml:33-57` | Unify with `OperationKind` discriminant (~10 lines) |
| Module named `Eip712.daml` but not real EIP-712 | `daml-eip712/daml/Eip712.daml` | Rename to `Hashing.daml` or document clearly |
| `hashBytesList` uses bare `keccak256` not `safeKeccak256` on elements | `Eip712.daml:56` | Use `map safeKeccak256 xs` |
| `VaultProposal.ensure` missing `alreadySigned` subset check | `Erc20Vault.daml:78` | Add `all (\`elem\` allOperators) alreadySigned` |
| `Erc20Holding` has no `ensure` clause | `Erc20Vault.daml:19-27` | Add `ensure not (null operators)` |
| `hexPadUint256` silently truncates overlong inputs | `HexCompare.daml:69-75` | Replace with `error` on overlong |
| `uint256Div/Mod/DivMod` dead stubs | `UInt256.daml:253-262` | Delete |

---

### Cross-chain Consistency

| Issue | Action |
|-------|--------|
| `MAX_SECP256K1_SCALAR` defined 3x (ETH+SOL local, Canton imports correctly) | ETH/SOL should import from `mpc_primitives` |
| Stall watchdog copy-pasted 3x (Canton + 2x Solana) | Extract shared `StallWatchdog` utility |
| Canton has zero direct metric instrumentation | Add `record_request_latency`, reconnect counter, security-drop counter |
| Canton entropy is predictable (`keccak256(request_id)` from public inputs) | Document design decision or anchor to unpredictable source |
| No `deposit == 0` guard (Hydration has it, Canton has no deposit field) | Document or add equivalent guard |
| `ethabi` duplicates `alloy-dyn-abi` (2 files use `ethabi::encode`) | Migrate to alloy, remove `ethabi` dependency |

---

### Observability

| Issue | File:Line | Fix |
|-------|-----------|-----|
| Full event struct logged at INFO with `{:?}` | `mod.rs:231` | Use structured fields, drop to DEBUG |
| No success log when sign request dispatched | `mod.rs:748-752` | Add `tracing::info!` with sign_id |
| `discover_signer_cid` has zero logging | `mod.rs:425-473` | Dead code -- remove |
| Verification rejections only logged, not counted | `mod.rs:739-742` | Add Prometheus counter |
| JWT expiry (300s), WS timeout (30s), stall timeout (60s), reconnect delay (1s) all hardcoded | scattered | Extract named constants or config fields |

---

### Test Gaps

| Issue | Impact |
|-------|--------|
| All 6 `canton_stream.rs` tests are `#[ignore]` | Zero automated regression coverage for Canton streaming |
| `test_canton_eth_bidirectional_flow` only checks `!signature_hex.is_empty()` | No cryptographic validation (ETH test does full ECDSA recovery) |
| Checkpoint persistence test uses fresh `Backlog::new()` in Phase 2 | Doesn't actually test checkpoint resume |
| Test fixture `Drop` blocks async runtime (up to 60s via `std::thread::sleep`) | Can stall CI / other tests |
| Missing negative test: nonce requester mismatch | `Signer.daml:51` assertion never exercised |
| Missing negative test: invalid MPC signature on claim | Crypto check in `ClaimDeposit`/`CompleteWithdrawal` never tested with bad sig |

---

## Refuted Claims (verified as false positives)

| Original Claim | Why Refuted |
|----------------|-------------|
| `CatchupCompleted` missing causes stall | Canton uses `RecoveryRequeueMode::Immediate` via `chain_supports_catchup()` -- `CatchupCompleted` not needed |
| `uint256AddChecked` overflow detection wrong for MAX+1 | Step-by-step trace: `ls[9]=16 >= topLimbMod=16` correctly returns `overflow=True` |
| `select!` with `read.next()` drops WebSocket frames | `futures_util::StreamExt::next()` IS cancellation-safe (holds only `&mut self`, no internal buffer) |
| `uint256MulChecked` overflow detection incomplete | Both `product[9] >= topLimbMod` and `any (/= 0) (drop 10 product)` are reachable and complementary |
| ~130 lines of `ledger_api.rs` dead code | Only `CantonError` is truly dead -- rest used by integration tests |
| `visit_f64` has float precision bug near u32::MAX | `u32::MAX` (4,294,967,295) is exactly representable in f64 -- no rounding error |

---

## Priority Order for Fixes

1. **C1 + C2 + C3** -- Error propagation in hex parsing / RLP encoding (prevents signing garbage)
2. **C7** -- Counter checkpoint ordering (prevents event loss on reconnect)
3. **C4 + C5** -- Daml authorization (`signerCid` validation, `controller actor` fix)
4. **C6** -- `nonceCidText` validation
5. **H1-H3** -- JWT refresh, reconnect backoff, `wss://` enforcement
6. **H4-H5** -- `sigNetwork` on claim, `IssueNonce` access control
7. Structural: split `mod.rs`, Daml deduplication, metrics, test coverage
