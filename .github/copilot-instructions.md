# Copilot Instructions for sig-net/mpc

## Project Overview

This repository implements **Sig.Network MPC** — a threshold Multi-Party Computation service that produces ECDSA signatures via smart contracts. Nodes collaboratively sign arbitrary payloads using the [cait-sith](https://github.com/sig-net/cait-sith) library; no single party ever holds the full private key. Signatures derive and control accounts on foreign chains (Ethereum, Bitcoin, Solana, Cosmos, Substrate, etc.).

**Workspace version**: 1.11.0 (all crates share this version).
**Protocol version**: `PROTOCOL_VERSION = 1` (in `chain-signatures/node/src/lib.rs`).

## Repository Layout

```
chain-signatures/
  contract/        # NEAR smart contract (Rust/WASM) — orchestrates signing and node membership
  contract-eth/    # Ethereum smart contract (Solidity/Hardhat)
  contract-sol/    # Solana program (Anchor) — sign/respond endpoints + indexer event types
  crypto/          # Low-level MPC cryptographic helpers (cait-sith / k256 wrappers)
  keys/            # HPKE encryption (X25519-HkdfSha256 + ChaCha20Poly1305) for inter-node messages
  node/            # MPC node binary — the core service
  primitives/      # Shared types used across crates (WASM-compatible)
integration-tests/ # End-to-end tests spinning up a local MPC cluster (Docker/Testcontainers)
doc/               # Architecture docs and specifications
infra/             # Terraform modules and deployment scripts
```

## Architecture Summary

- **Smart Contracts** (NEAR, Ethereum, Solana): accept `sign` requests from users and `respond` calls from MPC nodes. Manage node membership via `vote_*` methods.
- **MPC Nodes** (`chain-signatures/node`): index sign requests from multiple chains, coordinate triple and pre-signature generation, collaboratively produce the final signature, and submit it back to the contract.
- **Cryptographic pipeline**: Triple Generation → Pre-Signature Generation → Signature. Triples and pre-signatures are stockpiled ahead of time to reduce signing latency.
- **Multi-chain indexers**: Each supported chain has its own indexer module:
  - `indexer.rs` — NEAR (polls contract for sign requests)
  - `indexer_eth/` — Ethereum (JSON-RPC or Helios light client)
  - `indexer_sol.rs` — Solana (RPC + PubsubClient WebSocket)
  - `indexer_hydration.rs` — Substrate/Hydration
- **Networking**: Nodes maintain a mesh (`mesh/` module), tracking each peer's connection status and a share-holder directory for participant selection.
- **HTTP API**: `axum`-based web server (`web/` module) exposing node status, metrics, and debug endpoints.

For the authoritative protocol spec see `doc/mpc_node_specification.md`; for architecture overview see `doc/ARCHITECTURE.md`.

## Building

```bash
# Build all Rust crates
cargo build

# Build the NEAR WASM contract (pinned Rust 1.81.0 + wasm32-unknown-unknown target)
./build-contract.sh

# Build the Ethereum contract
cd chain-signatures/contract-eth && npm i && npx hardhat compile
```

## Testing

```bash
# Unit tests (all crates except integration-tests)
cargo test --workspace --exclude integration-tests

# Integration tests (requires Docker; redis:7.4.2 image pulled automatically)
cargo test -p integration-tests --jobs 1 -- --test-threads 1

# Integration tests inside Docker
cargo test -p integration-tests --features docker-test

# Ethereum contract unit tests
cd chain-signatures/contract-eth && npx hardhat test
```

Integration tests depend on `mpc_node` built with features `test-feature` and `debug-page`.

## Code Style and Conventions

- Rust edition: **2021** for all crates.
- rustfmt edition: **2024** (see `rustfmt.toml`).
- All compiler warnings denied: `RUSTFLAGS=-D warnings`.
- Format with `cargo fmt`; CI enforces `cargo fmt -- --check`.
- Lint with `cargo clippy --tests -- -Dclippy::all`.
- Run `cargo audit` to check for known vulnerabilities.
- Use `tracing` (not `println!` / `log`) for diagnostic output.
- Prefer `anyhow::Result` for application-level errors; use `thiserror` for library/crate-level error types.
- Async runtime: **Tokio** with `features = ["full"]`.

## Storage

The node uses multiple storage backends:

| Backend | What it stores | Config |
|---------|---------------|--------|
| **Redis** (`deadpool-redis`) | Triples, pre-signatures, indexer checkpoints | `--redis-url` / `MPC_REDIS_URL` |
| **GCP Secret Manager** | Node's secret key share (production) | `--sk-share-secret-id` / `MPC_SK_SHARE_SECRET_ID` + `--gcp-project-id` / `MPC_GCP_PROJECT_ID` |
| **Disk** | Node's secret key share (dev/test) | `--sk-share-local-path` / `MPC_SK_SHARE_LOCAL_PATH` |
| **In-memory** | Fallback for tests when no Redis/GCP is configured | Automatic |

Redis keys are namespaced as `{prefix}:{STORAGE_VERSION}:{account_id}`. The current `STORAGE_VERSION` is `"v11"` (in `chain-signatures/node/src/storage/mod.rs`); it is bumped on breaking schema changes to invalidate stale data.

Storage modules live in `chain-signatures/node/src/storage/`: `triple_storage.rs`, `presignature_storage.rs`, `protocol_storage.rs`, `secret_storage.rs`, `checkpoint_storage.rs`.

## Key Patterns

- **Protocol ownership**: Every protocol invocation (triple, pre-signature, signature) has exactly one `Owner` node. Other participants follow the owner's lead and must not make unilateral decisions about a non-owned invocation.
- **Non-reuse invariant**: Triples and pre-signatures must never be used more than once. Code that selects or consumes them must transition state atomically and persistently.
- **Event-sourcing for recovery**: While a protocol is `Running`, all received messages are persisted before being applied so in-memory state can be replayed after a crash.
- **State sync**: Runs on every new peer connection. The owner sends its directory of held inputs; the peer responds with any that are missing so both sides reconcile.
- **Key derivation**: Foreign-chain account derivation follows NEAR's chain-key derivation spec (see `doc/ACCOUNT_DERIVATION.md`).

## Important Files

| File | Purpose |
|------|---------|
| `chain-signatures/node/src/protocol/` | Core MPC protocol state machines (`triple.rs`, `presignature.rs`, `signature.rs`, `state.rs`, `consensus.rs`) |
| `chain-signatures/node/src/indexer.rs` | NEAR chain indexer for sign requests |
| `chain-signatures/node/src/indexer_eth/` | Ethereum indexer (RPC + Helios light client) |
| `chain-signatures/node/src/indexer_sol.rs` | Solana indexer (RPC + WebSocket) |
| `chain-signatures/node/src/indexer_hydration.rs` | Substrate/Hydration indexer |
| `chain-signatures/node/src/mesh/` | P2P mesh networking and peer state tracking |
| `chain-signatures/node/src/web/` | axum HTTP API (status, metrics, debug) |
| `chain-signatures/node/src/storage/` | All storage backends and `ProtocolStorage<A>` |
| `chain-signatures/contract/src/lib.rs` | NEAR contract entry points |
| `chain-signatures/contract-sol/src/lib.rs` | Solana Anchor program (sign, respond, respond_bidirectional) |
| `chain-signatures/crypto/` | Cryptographic primitives (cait-sith / k256 wrappers) |
| `chain-signatures/keys/src/hpke.rs` | HPKE encryption for inter-node messages |
| `integration-tests/src/` | Cluster setup helpers and test utilities |
| `doc/mpc_node_specification.md` | Authoritative distributed-algorithm spec |
| `doc/ARCHITECTURE.md` | Architecture overview |

## CI Workflows

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `unit.yml` | push to main/develop | Compile contract (WASM), compile ETH contract, cargo check/fmt/clippy/test/audit |
| `integration.yml` | push to develop | Full cluster integration tests in Docker |
| `prod-compatibility.yml` | PR / manual | Cross-version compatibility tests |
| `nightly.yml` | scheduled | Nightly regression suite |
| `k6-ci-loadtest.yml` | manual | k6-based load tests |
