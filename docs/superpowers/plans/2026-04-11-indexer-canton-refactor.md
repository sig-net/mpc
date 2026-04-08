# Indexer Canton Refactor

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split `indexer_canton/mod.rs` (972 lines) into focused files and absorb the `canton-types` crate into the module.

**Architecture:** Two-phase refactor. Phase 1 extracts three files from `mod.rs` (api, stream, request_id) while preserving the public API via re-exports. Phase 2 moves `canton-types` content (`contracts.rs`, `ledger_api.rs`) into `indexer_canton/` as submodules and removes the crate from the workspace.

**Tech Stack:** Rust, Cargo workspaces

**Note:** `discover_signer_cid` (mod.rs:425-474) is dead code (never called anywhere). Keeping it during this refactor to stay scope-focused — can be removed in follow-up.

---

## Target Structure

```
indexer_canton/
├── mod.rs          — re-exports, event structs, config/args, SignatureEvent impl, tx encoding (~250 lines)
├── api.rs          — JWT generation, discover_signer_cid, der_encode_signature (~150 lines)
├── stream.rs       — CantonStream, event loop, WS, event processing, verification, parsing (~500 lines)
├── request_id.rs   — compute_request_id and keccak256 hash helpers (~65 lines)
├── contracts.rs    — Daml contract payload types (from canton-types crate)
└── ledger_api.rs   — Canton JSON Ledger API v2 types (from canton-types crate)
```

## Phase 1: Split mod.rs into focused files

### Task 1: Extract `request_id.rs`

**Files:**
- Create: `chain-signatures/node/src/indexer_canton/request_id.rs`
- Modify: `chain-signatures/node/src/indexer_canton/mod.rs`

- [ ] **Step 1: Create `request_id.rs` with extracted functions**

Move lines 78-142 from `mod.rs`. These are the keccak256 hashing helpers and `compute_request_id`.

```rust
use alloy::primitives::{keccak256, U256};
use super::{CantonEvmTransactionParams, CantonSignBidirectionalRequestedEvent};

/// keccak256(utf8(text)), or keccak256("") for empty string.
/// Mirrors Daml's `hashText` in Eip712.daml.
fn hash_text(text: &str) -> [u8; 32] {
    keccak256(text.as_bytes()).into()
}

/// Left-pad a hex string to 32 bytes (big-endian U256).
fn pad_left_32(hex_str: &str) -> [u8; 32] {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    U256::from_str_radix(stripped, 16)
        .unwrap_or(U256::ZERO)
        .to_be_bytes::<32>()
}

/// keccak256(concat(map keccak256 items)), or keccak256("") for empty list.
/// Mirrors Daml's `hashBytesList` in Eip712.daml.
fn hash_bytes_list(items: &[String]) -> [u8; 32] {
    if items.is_empty() {
        return keccak256(b"").into();
    }
    let mut concatenated = Vec::new();
    for item in items {
        let bytes = hex::decode(item).unwrap_or_default();
        let h: [u8; 32] = keccak256(&bytes).into();
        concatenated.extend_from_slice(&h);
    }
    keccak256(&concatenated).into()
}

/// Hash EvmTransactionParams — mirrors Daml's `hashEvmParams` in RequestId.daml.
fn hash_evm_params(p: &CantonEvmTransactionParams) -> [u8; 32] {
    let mut buf = Vec::with_capacity(9 * 32);
    buf.extend_from_slice(&pad_left_32(&p.to));
    buf.extend_from_slice(&hash_text(&p.function_signature));
    buf.extend_from_slice(&hash_bytes_list(&p.args));
    buf.extend_from_slice(&pad_left_32(&p.value));
    buf.extend_from_slice(&pad_left_32(&p.nonce));
    buf.extend_from_slice(&pad_left_32(&p.gas_limit));
    buf.extend_from_slice(&pad_left_32(&p.max_fee_per_gas));
    buf.extend_from_slice(&pad_left_32(&p.max_priority_fee));
    buf.extend_from_slice(&pad_left_32(&p.chain_id));
    keccak256(&buf).into()
}

/// Compute the request ID using flat keccak256(concat(hashed fields)).
/// Mirrors Daml's `computeRequestId` in RequestId.daml.
pub(super) fn compute_request_id(event: &CantonSignBidirectionalRequestedEvent) -> [u8; 32] {
    let key_version_hex = format!("{:x}", event.key_version);

    let mut buf = Vec::with_capacity(9 * 32);
    buf.extend_from_slice(&hash_text(&event.sender));
    buf.extend_from_slice(&hash_evm_params(&event.evm_tx_params));
    buf.extend_from_slice(&hash_text(&event.caip2_id));
    buf.extend_from_slice(&pad_left_32(&key_version_hex));
    buf.extend_from_slice(&hash_text(&event.path));
    buf.extend_from_slice(&hash_text(&event.algo));
    buf.extend_from_slice(&hash_text(&event.dest));
    buf.extend_from_slice(&hash_text(&event.params));
    buf.extend_from_slice(&hash_text(&event.nonce_cid_text));
    keccak256(&buf).into()
}
```

- [ ] **Step 2: Update `mod.rs` — add module declaration, remove extracted code**

Add `mod request_id;` to module declarations. Add `use request_id::compute_request_id;` for the `SignatureEvent` impl. Remove lines 78-142 (the "Flat keccak256 request ID computation" section).

- [ ] **Step 3: Verify compilation**

Run: `cd /Users/felipesousapessina/Documents/signet/currently-working/mpc && cargo check -p mpc-node`
Expected: compiles successfully

- [ ] **Step 4: Commit**

```bash
git add chain-signatures/node/src/indexer_canton/request_id.rs chain-signatures/node/src/indexer_canton/mod.rs
git commit -m "refactor(canton): extract request_id.rs from indexer_canton"
```

---

### Task 2: Extract `api.rs`

**Files:**
- Create: `chain-signatures/node/src/indexer_canton/api.rs`
- Modify: `chain-signatures/node/src/indexer_canton/mod.rs`

- [ ] **Step 1: Create `api.rs` with JWT, DER encode, and discover_signer_cid**

Move from `mod.rs`:
- Lines 49-76 (JWT: `JwtClaims`, `generate_jwt_with_key`)
- Lines 202-219 (DER: `der_encode_signature`)
- Lines 425-474 (`discover_signer_cid`)

```rust
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mpc_primitives::Signature;
use super::ledger_api;

// ---------------------------------------------------------------------------
// JWT token generation (ES256)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct JwtClaims {
    sub: String,
    /// Canton supports scope-based OR audience-based tokens, not both.
    /// We use scope-based (the default when no target-audience is configured).
    scope: String,
    iat: u64,
    exp: u64,
}

/// Generate a JWT using a pre-parsed EncodingKey.
pub(crate) fn generate_jwt_with_key(key: &EncodingKey, subject: &str) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = JwtClaims {
        sub: subject.to_string(),
        scope: "daml_ledger_api".to_string(),
        iat: now,
        exp: now + 300,
    };
    let header = Header::new(Algorithm::ES256);
    Ok(encode(&header, &claims, &key)?)
}

// ---------------------------------------------------------------------------
// DER signature encoding
// ---------------------------------------------------------------------------

/// DER-encode an ECDSA signature from an MPC Signature (big_r, s).
///
/// Canton's native Daml signature verification (`secp256k1WithEcdsaOnly`)
/// only accepts DER-encoded signatures — there is no built-in Daml function
/// to convert from raw `(r, s)` components to DER. We encode on the MPC
/// side so the Daml contracts can verify directly without conversion.
pub fn der_encode_signature(signature: &Signature) -> anyhow::Result<Vec<u8>> {
    use mpc_crypto::x_coordinate;

    let r_scalar = x_coordinate(&signature.big_r);
    let ecdsa_sig = k256::ecdsa::Signature::from_scalars(r_scalar, &signature.s)
        .map_err(|e| anyhow::anyhow!("failed to create ECDSA signature from (r, s) scalars: {e}"))?;
    Ok(ecdsa_sig.to_der().to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Signer CID discovery
// ---------------------------------------------------------------------------

/// Discover the Signer contract ID by querying active contracts.
/// Returns (contractId, templateId) for the unique Signer:Signer contract.
pub async fn discover_signer_cid(
    http_client: &reqwest::Client,
    json_api_url: &str,
    jwt_token: &str,
    party_id: &str,
) -> anyhow::Result<(String, String)> {
    let url = format!("{json_api_url}/v2/state/active-contracts");

    let mut filters_by_party = serde_json::Map::new();
    filters_by_party.insert(party_id.to_string(), serde_json::json!({}));

    let body = ledger_api::GetActiveContractsRequest {
        active_at_offset: 0,
        event_format: ledger_api::EventFormat {
            filters_by_party,
            verbose: false,
        },
    };

    let resp = http_client
        .post(&url)
        .bearer_auth(jwt_token)
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("active-contracts query failed: {status} {text}");
    }

    let items: Vec<ledger_api::ActiveContractEntry> = resp.json().await?;

    let mut signer_contracts: Vec<(String, String)> = Vec::new();
    for item in &items {
        if let Some(ledger_api::ContractEntry::JsActiveContract(active)) = &item.contract_entry {
            let ce = &active.created_event;
            if ledger_api::template_suffix_matches(&ce.template_id, ledger_api::templates::SIGNER) {
                signer_contracts.push((ce.contract_id.clone(), ce.template_id.clone()));
            }
        }
    }

    match signer_contracts.as_slice() {
        [] => anyhow::bail!("no active Signer:Signer contract found"),
        [single] => Ok(single.clone()),
        _ => anyhow::bail!("expected 1 Signer:Signer contract, found {}", signer_contracts.len()),
    }
}
```

Note: `api.rs` references `super::ledger_api`. During Phase 1 this resolves via `use canton_types::ledger_api` re-exported in mod.rs — we need to make `ledger_api` accessible. Currently mod.rs has `use canton_types::{contracts, ledger_api};` which is a private import. For `super::ledger_api` to work, mod.rs needs to either re-export the module or the api.rs should use `canton_types::ledger_api` directly. **Simplest approach during Phase 1:** have api.rs use `canton_types::ledger_api` directly, then in Phase 2 switch to `super::ledger_api`.

```rust
// Phase 1 version of the import in api.rs:
use canton_types::ledger_api;
```

- [ ] **Step 2: Update `mod.rs` — add module declaration, remove extracted code, add re-exports**

Add `mod api;` and re-exports:
```rust
pub use api::{der_encode_signature, discover_signer_cid};
pub(crate) use api::generate_jwt_with_key;
```

Remove from mod.rs:
- The JWT section (JwtClaims struct, generate_jwt_with_key function)
- The DER encode section (der_encode_signature function)
- The discover_signer_cid function

- [ ] **Step 3: Verify compilation**

Run: `cd /Users/felipesousapessina/Documents/signet/currently-working/mpc && cargo check -p mpc-node`
Expected: compiles successfully

- [ ] **Step 4: Commit**

```bash
git add chain-signatures/node/src/indexer_canton/api.rs chain-signatures/node/src/indexer_canton/mod.rs
git commit -m "refactor(canton): extract api.rs from indexer_canton"
```

---

### Task 3: Extract `stream.rs`

**Files:**
- Create: `chain-signatures/node/src/indexer_canton/stream.rs`
- Modify: `chain-signatures/node/src/indexer_canton/mod.rs`

- [ ] **Step 1: Create `stream.rs` with all WebSocket and event processing code**

Move lines 476-972 from `mod.rs`. This is the largest extraction.

Key imports for stream.rs:
```rust
use crate::backlog::Backlog;
use crate::protocol::Chain;
use crate::stream::ops::{
    RespondBidirectionalEvent, SignBidirectionalEvent, SignatureEvent,
    SignatureRespondedEvent,
};
use crate::stream::{ChainEvent, ChainStream};

use alloy::primitives::{keccak256, B256};
use canton_types::{contracts, ledger_api};  // Phase 1: direct crate import
use futures_util::{SinkExt, StreamExt};
use std::collections::HashSet;
use jsonwebtoken::EncodingKey;
use k256::Scalar;
use mpc_primitives::{ScalarExt, Signature};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;
use tokio_tungstenite::tungstenite::Message;

use super::{
    CantonConfig, CantonRespondBidirectionalEvent,
    CantonSignBidirectionalRequestedEvent, CantonSignatureRespondedEvent,
};
use super::api::generate_jwt_with_key;
```

Contents (copy verbatim from mod.rs lines 476-972):
- `struct CantonStreamStartState` (480-484)
- `pub struct CantonStream` (486-490)
- `impl Drop for CantonStream` (492-498)
- `impl CantonStream { pub fn new(...) }` (500-521)
- `impl ChainStream for CantonStream` (524-544)
- `async fn run_canton_event_loop(...)` (547-589)
- `async fn subscribe_and_process(...)` (592-716)
- `async fn process_canton_event(...)` (722-790)
- `fn verify_sign_event(...)` (804-875)
- `fn parse_sign_bidirectional_event(...)` (881-887)
- `fn parse_signature_responded_event(...)` (889-904)
- `fn parse_respond_bidirectional_event(...)` (906-924)
- `fn parse_der_signature(...)` (937-972)

- [ ] **Step 2: Update `mod.rs` — add module declaration, remove extracted code, add re-export**

Add `mod stream;` and `pub use stream::CantonStream;`. Remove lines 476-972 from mod.rs.

- [ ] **Step 3: Verify compilation**

Run: `cd /Users/felipesousapessina/Documents/signet/currently-working/mpc && cargo check -p mpc-node`
Expected: compiles successfully

- [ ] **Step 4: Commit**

```bash
git add chain-signatures/node/src/indexer_canton/stream.rs chain-signatures/node/src/indexer_canton/mod.rs
git commit -m "refactor(canton): extract stream.rs from indexer_canton"
```

---

### Task 4: Verify Phase 1 is complete

- [ ] **Step 1: Full workspace check**

Run: `cd /Users/felipesousapessina/Documents/signet/currently-working/mpc && cargo check`
Expected: entire workspace compiles

- [ ] **Step 2: Verify file sizes are reasonable**

Run: `wc -l chain-signatures/node/src/indexer_canton/*.rs`
Expected: mod.rs ~250, request_id.rs ~65, api.rs ~120, stream.rs ~500

---

## Phase 2: Absorb canton-types crate into indexer_canton

### Task 5: Move type files into indexer_canton

**Files:**
- Copy: `chain-signatures/canton-types/src/contracts.rs` -> `chain-signatures/node/src/indexer_canton/contracts.rs`
- Copy: `chain-signatures/canton-types/src/ledger_api.rs` -> `chain-signatures/node/src/indexer_canton/ledger_api.rs`
- Modify: `chain-signatures/node/src/indexer_canton/mod.rs`

- [ ] **Step 1: Copy contracts.rs into indexer_canton**

```bash
cp chain-signatures/canton-types/src/contracts.rs chain-signatures/node/src/indexer_canton/contracts.rs
```

File is self-contained (only needs `serde`). No modifications needed.

- [ ] **Step 2: Copy ledger_api.rs into indexer_canton**

```bash
cp chain-signatures/canton-types/src/ledger_api.rs chain-signatures/node/src/indexer_canton/ledger_api.rs
```

File depends on `serde`, `serde_json::Value`, `serde_json::Map` — all available in mpc-node.

- [ ] **Step 3: Update mod.rs — declare new public modules**

Add module declarations:
```rust
pub mod contracts;
pub mod ledger_api;
```

Update re-exports to use local modules instead of `canton_types`:
```rust
// Before:
pub use canton_types::contracts::EvmTransactionParams as CantonEvmTransactionParams;
pub use canton_types::contracts::SignBidirectionalRequestedEvent as CantonSignBidirectionalRequestedEvent;

// After:
pub use contracts::EvmTransactionParams as CantonEvmTransactionParams;
pub use contracts::SignBidirectionalRequestedEvent as CantonSignBidirectionalRequestedEvent;
```

Remove `use canton_types::{contracts, ledger_api};` import.

- [ ] **Step 4: Update api.rs — switch to local module**

```rust
// Before:
use canton_types::ledger_api;

// After:
use super::ledger_api;
```

- [ ] **Step 5: Update stream.rs — switch to local module**

```rust
// Before:
use canton_types::{contracts, ledger_api};

// After:
use super::{contracts, ledger_api};
```

- [ ] **Step 6: Verify mpc-node compiles**

Run: `cd /Users/felipesousapessina/Documents/signet/currently-working/mpc && cargo check -p mpc-node`
Expected: compiles (canton-types crate still exists, just unused by node now)

- [ ] **Step 7: Commit**

```bash
git add chain-signatures/node/src/indexer_canton/
git commit -m "refactor(canton): move contracts.rs and ledger_api.rs into indexer_canton"
```

---

### Task 6: Update integration-tests and remove canton-types crate

**Files:**
- Modify: `integration-tests/src/canton.rs`
- Modify: `integration-tests/Cargo.toml`
- Modify: `chain-signatures/node/Cargo.toml`
- Modify: `Cargo.toml` (workspace root)
- Delete: `chain-signatures/canton-types/` (entire directory)

- [ ] **Step 1: Update integration-tests imports**

In `integration-tests/src/canton.rs`, change line 3:
```rust
// Before:
use canton_types::ledger_api::{
    self, ActiveContractEntry, AllocatePartyRequest, AllocatePartyResponse, ContractEntry,
    CreateUserRequest, DisclosedContract, EventFormat, GetActiveContractsRequest, JsCommands,
    LedgerEndResponse, SubmitAndWaitForTransactionRequest, SubmitAndWaitForTransactionResponse,
    UserInfo,
};

// After:
use mpc_node::indexer_canton::ledger_api::{
    self, ActiveContractEntry, AllocatePartyRequest, AllocatePartyResponse, ContractEntry,
    CreateUserRequest, DisclosedContract, EventFormat, GetActiveContractsRequest, JsCommands,
    LedgerEndResponse, SubmitAndWaitForTransactionRequest, SubmitAndWaitForTransactionResponse,
    UserInfo,
};
```

- [ ] **Step 2: Remove canton-types from integration-tests/Cargo.toml**

Delete line:
```toml
canton-types.workspace = true
```

- [ ] **Step 3: Remove canton-types from node/Cargo.toml**

Delete line:
```toml
canton-types.workspace = true
```

- [ ] **Step 4: Remove canton-types from workspace Cargo.toml**

In `mpc/Cargo.toml`:
- Remove `"chain-signatures/canton-types"` from `[workspace] members`
- Remove `canton-types = { path = "chain-signatures/canton-types" }` from `[workspace.dependencies]`

- [ ] **Step 5: Delete canton-types crate directory**

```bash
rm -rf chain-signatures/canton-types/
```

- [ ] **Step 6: Verify full workspace compiles**

Run: `cd /Users/felipesousapessina/Documents/signet/currently-working/mpc && cargo check`
Expected: entire workspace compiles

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(canton): remove canton-types crate, types now in indexer_canton"
```

---

## Verification

After all tasks are complete:

```bash
cd /Users/felipesousapessina/Documents/signet/currently-working/mpc
cargo check                     # full workspace compiles
cargo test -p mpc-node --lib    # unit tests pass (if any)
cargo clippy -p mpc-node        # no new warnings
```

Verify no remaining references to the old crate:
```bash
grep -r "canton.types" --include="*.toml" .   # should return nothing
grep -r "use canton_types" --include="*.rs" .  # should return nothing
```

## Pitfalls

1. **`super::ledger_api` vs `canton_types::ledger_api`**: During Phase 1, `api.rs` and `stream.rs` use `canton_types::ledger_api` directly. In Phase 2 (Task 5), both switch to `super::ledger_api`. Don't mix up the phases.

2. **Visibility of `contracts` and `ledger_api`**: Must be `pub mod` (not `mod`) because integration-tests accesses them via `mpc_node::indexer_canton::ledger_api::*`.

3. **`generate_jwt_with_key` visibility**: Must be `pub(crate)` — used by `rpc.rs` which is in the same crate but different module.

4. **`crate::stream` vs local `stream`**: In stream.rs, `crate::stream` refers to the top-level `stream` module (with `ChainEvent`, `ChainStream`). The local file is accessed via `super::stream` from siblings. No ambiguity since stream.rs doesn't need to refer to itself.
