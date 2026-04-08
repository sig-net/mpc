# Canton Integration Review

**Date:** 2026-04-11
**Scope:** Canton MPC integration -- Rust indexer, canton-types crate, Daml contracts, integration tests
**Method:** 130 agents across 3 rounds (50 review, 50 verification, 30 deep re-verification against the full defense chain)

---

## Summary

The initial 50-agent review produced many false positives because agents analyzed files in isolation without understanding the full defense chain: Daml validation -> Canton privacy model -> MPC signature checks -> `verify_sign_event` Rust guards. The 30-agent re-verification round corrected this by tracing each claim through the complete pipeline.

| Severity | Count |
|----------|-------|
| Medium (real, actionable) | 1 |
| Low / Defense-in-depth | 3 |
| Cleanup (dead code, style) | 6 |
| Refuted (false positives) | ~25 |

---

## Medium -- Real Issue

### VaultProposal `ensure` missing `alreadySigned ⊆ allOperators`

**File:** `daml-vault/daml/Erc20Vault.daml:78`

```daml
ensure not (null allOperators) && unique allOperators && unique alreadySigned
```

Missing: `all (\`elem\` allOperators) alreadySigned`.

A party can create a `VaultProposal` where `alreadySigned` contains a non-operator. Operators then sign it via `SignVault` (each call succeeds), but the terminal check `sort newSigned == sort allOperators` always fails because the bogus initial signer is baked in. The proposal is permanently stuck with no cancel/archive escape hatch. This is a **DoS/griefing vector**.

**Fix:**
```daml
ensure
  not (null allOperators)
  && unique allOperators
  && unique alreadySigned
  && all (`elem` allOperators) alreadySigned
```

---

## Low -- Defense-in-Depth Improvements

These are not bugs -- the Daml layer prevents malformed data from reaching Rust. They are still worth fixing to make the Rust layer independently robust.

### 1. `rlp_encode_unsigned_eip1559` should return `Result`, not `vec![]`

**File:** `node/src/indexer_canton/mod.rs:195-198`

If `to_tx_eip1559` fails (requires invalid hex in `p.to`, which Daml prevents via `fromSome(fromHex(...))` validation), the function returns `vec![]`. The caller hashes `keccak256(b"")` and proceeds to sign. Currently unreachable due to Daml validation, but the silent fallback is a latent hazard.

**Fix:** Change return type to `anyhow::Result<Vec<u8>>` and propagate errors.

### 2. `Address::from_slice` should guard against short slices

**File:** `node/src/indexer_canton/mod.rs:167-170`

If `hex::decode(&p.to)` produces <20 bytes, `Address::from_slice` panics. Daml always produces a 20-byte address. The existing `> 20` guard handles the padded case but the `< 20` case is unguarded.

**Fix:** Add `anyhow::ensure!(addr_bytes.len() == 20, "...")` or use `FixedBytes::try_from`.

### 3. `controller actor` pattern on Consume choices

**File:** `daml-signer/daml/Signer.daml:144-195`

Style issue, not a security vulnerability. Only signatories/observers can see the contract, and the `assertMsg` correctly restricts to `operators || requester`. No external attack vector exists. Using `controller operators, requester` would make authorization statically verifiable by the Daml compiler.

---

## Cleanup -- Dead Code & Style

| Item | File | Action |
|------|------|--------|
| `discover_signer_cid` never called | `mod.rs:425-474` | Delete (~50 lines) |
| `EventFormat` / `EventFormatInline` duplicated | `ledger_api.rs:182-187,312-317` | Merge into single `EventFormat` |
| `#[serde(default)]` on non-optional `Text` fields | `contracts.rs:55,59,61` | Remove (improves deserialization strictness) |
| `visit_f64` dead code in `deserialize_u32_lenient` | `contracts.rs:122-127` | Remove (Canton never sends floats for `Int`) |
| `CantonError` dead type | `ledger_api.rs:365` | Delete |
| `uint256Div/Mod/DivMod` dead stubs | `UInt256.daml:253-262` | Delete |
| Unused `Hash` derive on `EvmTransactionParams`/`SignBidirectionalRequestedEvent` | `contracts.rs:18,40` | Remove |
| `to_tx_eip1559` is `pub` but only called internally | `mod.rs:164` | Change to `fn` |
| `OffsetCheckpointValue` single-field wrapper | `ledger_api.rs:221-224` | Inline into enum variant |

---

## Refuted Claims (false positives from rounds 1-2)

### Daml layer prevents malformed hex (refutes C1, C2, C3)

The Daml transaction that creates a `SignBidirectionalEvent` calls `chainIdToDecimalText` -> `hexToInt` -> `fromSome(fromHex(...))`, which aborts the transaction on invalid hex. Additionally, `computeRequestId` and `hashEvmParams` use `UInt256.daml`'s `hexCpToDigit` which calls `error` on non-hex characters. Malformed hex **aborts the Daml transaction before any event is committed to the ledger**. The Rust `unwrap_or(0)` calls are unreachable with bad data.

### `signerCid` validation is unnecessary (refutes C5)

`sigNetwork` in `SignBidirectionalEvent` comes from the **Vault's own field**, not from the exercised signer. A rogue signer can't influence the event's `sigNetwork`. The MPC signature is verified against `evmMpcPublicKey` (the vault's key), which is unforgeable. The full attack trace shows no exploitable path.

### Counter ordering is safe (refutes C6)

On same-process reconnect, the in-memory `counter` persists correctly. On process crash, the stale backlog checkpoint causes event **replay** (at-least-once delivery), not permanent loss. The design is correct.

### `nonceCidText` already validated at MPC level (refutes C9)

`verify_sign_event` Check 4 (lines 852-872) verifies that `nonceCidText` matches a consuming `ExercisedEvent` on a `SigningNonce` template in the same transaction. The check already exists.

### JWT expiry handled correctly (refutes H1)

Canton actively terminates WebSocket streams on token expiry (`ACCESS_TOKEN_EXPIRED` with gRPC `ABORTED`). The reconnect loop mints a fresh JWT on each iteration. Offset-based resumption ensures no events are lost. The 1-2 second blind spot every 5 minutes is by design and handled.

### No URL scheme validation is codebase convention (refutes H3)

No indexer (ETH, Solana, Hydration, Canton) validates URL schemes. This is consistent operator-trust convention. Adding it for Canton alone would be inconsistent.

### `IssueNonce` is restricted by Canton's privacy model (refutes H5)

The `Signer` template declares no `observer` clause. Only `sigNetwork` (the sole signatory) can see the contract. Arbitrary parties **cannot** call `IssueNonce` because they can't see the contract.

### `sigNetwork` check on claim is cosmetically nice but not exploitable (refutes H4)

The MPC signature check against `evmMpcPublicKey` is cryptographically unforgeable. A rogue `sigNetwork` cannot produce a valid signature under the vault's key.

### Other refutations

| Claim | Why Refuted |
|-------|-------------|
| Reconnect backoff missing | Cross-cutting (same in Solana). Not Canton-specific. |
| hex 0x prefix fragile | Stable Daml convention. Inconsistency is code quality only. |
| Response payloads missing fields | Fields are never read by Rust consumer. Adding them is dead code. |
| mod.rs should be split 7 ways | 973 lines is smaller than indexer_eth (1273). Over-engineering. |
| SignRequest/SignBidirectionalEvent field duplication | Intentional Daml CPI authority-bridge pattern. |
| All canton_stream tests `#[ignore]` | Justified -- dedicated `canton.yml` CI workflow runs them with `--ignored`. |
| Test fixture Drop blocks async | Test infra, never runs in standard CI, serves real port-cleanup purpose. |
| Erc20Holding no ensure | Only created inside Vault choices. Runtime catches empty operators. |
| hexPadUint256 truncation | Intentional, tested, unreachable from production callers. |
| deposit==0 guard missing | Daml authorization model is the structural equivalent. No deposit concept in Canton. |
| Canton zero metrics | Partially covered by `run_stream` shared infrastructure (block gauge + indexing counter). |
| uint256AddChecked overflow | Step-by-step trace: `ls[9]=16 >= topLimbMod=16` correctly returns `True`. |
| uint256MulChecked incomplete | Both conditions are reachable and complementary. |
| select! cancellation drops frames | `StreamExt::next()` IS cancellation-safe. |
| CatchupCompleted stalls recovery | Canton uses `Immediate` requeue mode. Not needed. |
| ethabi duplicates alloy | Not Canton code (Solana + Hydration). Out of scope. |
| MAX_SECP256K1_SCALAR duplication | Canton does it correctly. Issue is in ETH/SOL. |

---

## Lessons Learned

The initial 50-agent review produced ~25 false positives because:

1. **Agents analyzed files in isolation.** Each agent read one file and flagged issues without checking whether upstream/downstream guards prevented the scenario.
2. **Daml's transactional validation was missed.** Functions like `fromSome(fromHex(...))` abort the Daml transaction before events are committed, making Rust-side guards unreachable with bad data.
3. **Canton's privacy model was ignored.** Claims like "any party can call IssueNonce" assumed public visibility, but Daml contracts are only visible to signatories and observers.
4. **MPC cryptographic checks were underweighted.** The `secp256k1WithEcdsaOnly` signature verification against `evmMpcPublicKey` closes many attack paths that look open when viewing only the Daml contract layer.
5. **Cross-cutting patterns were attributed to Canton.** Issues shared with Solana/Hydration (reconnect backoff, URL validation, ethabi) were reported as Canton-specific findings.

For future reviews: always trace claims through the **full pipeline** (Daml -> Canton privacy -> Rust verification -> MPC crypto) before assigning severity.
