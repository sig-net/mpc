# Canton API Types Crate — Design Spec

> **Goal:** Replace hand-crafted `serde_json::json!()` construction and `serde_json::Value` parsing chains across the MPC node Canton indexer and integration tests with typed Rust structs in a shared crate.

> **Pattern:** Follows the existing chain pattern — hand-written shared types crate with serde derives (like `signet-program` for Solana). No build-time codegen.

---

## Context

The Canton indexer (`chain-signatures/node/src/indexer_canton/mod.rs`) and integration test client (`integration-tests/src/canton.rs`) both hand-craft JSON payloads and manually parse responses using `serde_json::Value`. This is error-prone — field name typos, missing fields, and type mismatches are only caught at runtime.

The other chain indexers use typed ecosystem crates:
- **Solana** → `signet-program` crate (Anchor-generated types)
- **Ethereum** → `alloy::sol!` macro / `ethers::abigen!`
- **Hydration** → `subxt` Substrate client types

Canton has no Rust ecosystem crate. The TypeScript side uses `openapi-typescript` for the generic API and `dpm codegen-js` for Daml types, but neither has a Rust equivalent.

---

## Crate Structure

```
canton-api-types/
├── Cargo.toml           # depends on: serde, serde_json
└── src/
    ├── lib.rs           # re-exports ledger_api and contracts modules
    ├── ledger_api.rs    # Canton JSON Ledger API v2 envelope types
    └── contracts.rs     # Daml contract payload types (from .daml sources)
```

Workspace member in the root `Cargo.toml`. Consumed by `mpc-node` and `integration-tests`.

---

## Type Inventory

### `ledger_api.rs` — Canton API Envelope Types

Derived from the Canton JSON Ledger API v2 OpenAPI spec (version 3.4.11). Only types that the MPC node or integration tests actually use.

All types use `#[derive(Debug, Clone, Serialize, Deserialize)]` and `#[serde(rename_all = "camelCase")]`.

#### Commands (request construction)

| Type | Used by | Source endpoint |
|------|---------|----------------|
| `JsCommands` | tests, node (Respond choice) | POST `/v2/commands/submit-and-wait-for-transaction` |
| `Command` (enum: `CreateCommand`, `ExerciseCommand`) | tests | nested in `JsCommands.commands` |
| `SubmitAndWaitForTransactionRequest` | tests, node | request wrapper |
| `SubmitAndWaitForTransactionResponse` | tests, node | response wrapper |
| `DisclosedContract` | tests | nested in `JsCommands.disclosed_contracts` |

#### Events (response parsing)

| Type | Used by | Source |
|------|---------|--------|
| `CreatedEvent` | node (WebSocket), tests | `Transaction.events[]` |
| `ArchivedEvent` | node (WebSocket) | `Transaction.events[]` |
| `Event` (enum wrapping Created/Archived) | node, tests | `Transaction.events[]` |
| `Transaction` | node, tests | `Update.Transaction` / response body |
| `OffsetCheckpoint` | node (WebSocket) | `Update.OffsetCheckpoint` |
| `Update` (enum: Transaction, OffsetCheckpoint) | node (WebSocket) | WebSocket message payload |

#### Parties & Users

| Type | Used by | Source endpoint |
|------|---------|----------------|
| `AllocatePartyRequest` | tests | POST `/v2/parties` |
| `AllocatePartyResponse` | tests | response body |
| `CreateUserRequest` | tests | POST `/v2/users` |
| `User` | tests | nested in `CreateUserRequest` |
| `UserRight` (enum: `CanActAs`, `CanReadAs`) | tests | nested in `CreateUserRequest.rights` |

#### WebSocket Subscription

| Type | Used by | Source |
|------|---------|--------|
| `GetUpdatesRequest` | node | WebSocket send on connect |
| `UpdatesFilter` | node | nested in `GetUpdatesRequest.filter` |

#### Active Contracts

| Type | Used by | Source endpoint |
|------|---------|----------------|
| `GetActiveContractsRequest` | tests | POST `/v2/state/active-contracts` |
| `ActiveContractEntry` | tests | response array items |

#### Errors

| Type | Used by | Source |
|------|---------|--------|
| `CantonError` | tests (error matching) | error response body |

**Total: ~20 types.**

### `contracts.rs` — Daml Contract Payload Types

Derived from `.daml` template source files in `canton-mpc-poc/daml-packages/`. These represent the `CreatedEvent.payload` content for specific Daml templates.

All types use `#[derive(Debug, Clone, Serialize, Deserialize)]` and `#[serde(rename_all = "camelCase")]`.

#### From `daml-signer/daml/Signer.daml`

| Type | Daml template/choice | Fields |
|------|---------------------|--------|
| `SignerPayload` | `Signer` template | `sig_network: String` |
| `SignBidirectionalRequestedEvent` | `SignBidirectional` choice result | `operators`, `sender`, `requester`, `sig_network`, `vault_id`, `evm_tx_params`, `caip2_id`, `key_version`, `path`, `algo`, `dest`, `params`, `nonce_cid_text`, `output_deserialization_schema`, `respond_serialization_schema` |
| `SignatureRespondedEvent` | `Respond` choice result | `sig_network`, `operators`, `requester`, `request_id`, `responder`, `signature` |
| `RespondBidirectionalEvent` | `RespondBidirectional` choice result | `sig_network`, `operators`, `requester`, `request_id`, `responder`, `signature`, `serialized_output` |

#### From `daml-vault/daml/Erc20Vault.daml`

| Type | Daml template/choice | Fields |
|------|---------------------|--------|
| `EvmTransactionParams` | Shared record | `to`, `function_signature`, `args`, `value`, `nonce`, `gas_limit`, `max_fee_per_gas`, `max_priority_fee`, `chain_id` |
| `PendingDepositPayload` | `PendingDeposit` template | `request_id`, `operators`, `requester`, `sig_network`, `vault_id`, `evm_tx_params`, ... |

**Total: ~6 types.**

---

## Design Decisions

### `CreatedEvent.payload` stays as `Value`

The Canton API returns contract payloads as opaque JSON. The ledger API envelope type defines `payload: serde_json::Value`. Consumers do a two-step parse:

```rust
let event: CreatedEvent = serde_json::from_value(raw)?;           // typed envelope
if event.template_id.contains("SignBidirectionalRequestedEvent") {
    let payload: SignBidirectionalRequestedEvent =
        serde_json::from_value(event.payload)?;                    // typed domain
}
```

This matches how the Solana indexer handles Anchor events — the transport layer is generic, domain parsing is type-specific.

### Serde rename strategy

Canton's JSON API uses `camelCase` field names. Daml contract payloads also use `camelCase`. All types use `#[serde(rename_all = "camelCase")]` globally.

For fields that don't follow the pattern (e.g., `templateId` mapping to `template_id`), individual `#[serde(rename = "...")]` annotations are used.

### No Default derives on request types

Request types that have required fields should NOT derive `Default`. Only types where all fields are optional (like `UpdatesFilter`) get `Default`.

### Enum representation

Canton API uses externally-tagged enums in JSON (e.g., `{"CreateCommand": {...}}`). Use `#[serde(tag)]` or untagged as appropriate per the OpenAPI spec.

---

## Migration Plan

### Phase 1: Create the crate

- Add `canton-api-types/` as a workspace member
- Write all types from the inventory above
- Ensure `cargo check` passes

### Phase 2: Migrate integration tests

- `integration-tests/Cargo.toml` depends on `canton-api-types`
- `integration-tests/src/canton.rs` replaces `json!()` with typed struct construction
- `integration-tests/tests/cases/canton_stream.rs` and `canton.rs` use typed event parsing

### Phase 3: Migrate MPC node indexer

- `chain-signatures/node/Cargo.toml` depends on `canton-api-types`
- `indexer_canton/mod.rs` replaces `Value` parsing chains with `serde_json::from_value::<T>()`
- Delete existing hand-written structs (`CantonSignBidirectionalRequestedEvent`, etc.) that are now in the shared crate
- `parse_sign_bidirectional_event()`, `parse_signature_responded_event()`, `parse_respond_bidirectional_event()` become one-liners

### Phase 4: Verify

- `cargo check --workspace`
- Run Canton stream integration tests
- Run existing MPC node unit tests

---

## Out of Scope

- OpenAPI codegen tooling (no `typify`, no `progenitor`)
- DAR/DALF binary parsing for type generation
- Generated HTTP/WebSocket client — existing `reqwest`/`tungstenite` code stays
- Types for Canton endpoints we don't use (reassignment, inspection, etc.)
