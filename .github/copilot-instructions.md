# Copilot Instructions for sig-net/mpc

## Project Overview

This repository implements **Sig.Network MPC**, a threshold Multi-Party Computation (MPC) service that enables signing arbitrary payloads via smart contracts. Nodes collaboratively produce ECDSA signatures using the [cait-sith](https://github.com/sig-net/cait-sith) library without any single party ever holding the full private key.

Signatures can be used to derive and control accounts on foreign chains (Ethereum, Bitcoin, Solana, Cosmos, etc.).

## Repository Layout

```
chain-signatures/
  contract/        # NEAR smart contract (Rust/WASM) — orchestrates signing and node membership
  contract-eth/    # Ethereum smart contract (Solidity/Hardhat)
  contract-sol/    # Solana program (Anchor framework)
  crypto/          # Low-level MPC cryptographic helpers
  keys/            # Key management utilities
  node/            # MPC node binary — the core service
  primitives/      # Shared types used across crates
integration-tests/ # End-to-end tests that spin up a local MPC cluster (Docker/Testcontainers)
doc/               # Architecture docs and specifications
infra/             # Infrastructure / deployment helpers
```

## Architecture Summary

- **Smart Contracts** (NEAR, Ethereum, Solana): accept `sign` requests from users and `respond` calls from MPC nodes. Also manage node membership via `vote_*` methods.
- **MPC Nodes** (`chain-signatures/node`): index sign requests, coordinate triple generation and pre-signature generation, then collaboratively produce the final signature and submit it back to the contract.
- **Cryptographic pipeline**: Triple Generation → Pre-Signature Generation → Signature. Beaver triples and pre-signatures are stockpiled ahead of time to reduce latency.
- **Networking**: Nodes maintain a mesh, tracking each peer's connection status (`Active`, `Syncing`, `Inactive`, `Offline`) and a share-holder directory for participant selection.

For a detailed description of the distributed state machines and protocol, see [`doc/mpc_node_specification.md`](../doc/mpc_node_specification.md) and [`doc/ARCHITECTURE.md`](../doc/ARCHITECTURE.md).

## Building

```bash
# Build all Rust crates
cargo build

# Build the NEAR WASM contract (requires wasm32-unknown-unknown target + Rust 1.81.0)
./build-contract.sh

# Build the Ethereum contract
cd chain-signatures/contract-eth && npm i && npx hardhat compile
```

## Testing

```bash
# Unit tests (all crates except integration-tests)
cargo test --workspace --exclude integration-tests

# Integration tests (requires Docker with redis:7.4.2 image)
cargo test -p integration-tests --jobs 1 -- --test-threads 1

# Integration tests inside Docker
cargo test -p integration-tests --features docker-test

# Ethereum contract unit tests
cd chain-signatures/contract-eth && npx hardhat test
```

## Code Style and Conventions

- Rust edition: **2021** for all crates (see `Cargo.toml` files).
- rustfmt edition: **2024** (see `rustfmt.toml`).
- All compiler warnings are treated as errors (`RUSTFLAGS=-D warnings`).
- Format with `cargo fmt` before committing; CI enforces `cargo fmt -- --check`.
- Lint with `cargo clippy --tests -- -Dclippy::all`.
- Run `cargo audit` to check for known vulnerabilities in dependencies.
- Use `tracing` (not `println!` / `log`) for diagnostic output in the node.
- Prefer `anyhow::Result` for application-level error propagation; use `thiserror` for library/crate-level error types.
- Async runtime: **Tokio** (`features = ["full"]`).

## Storage

The node uses multiple storage backends depending on what is being stored:

- **Redis** (`deadpool-redis`): Primary persistent store for triples (`ProtocolStorage<TriplePair>`) and pre-signatures (`ProtocolStorage<Presignature>`). Keys are namespaced as `{prefix}:{STORAGE_VERSION}:{account_id}`. The current `STORAGE_VERSION` constant (in `chain-signatures/node/src/storage/mod.rs`) is bumped whenever a breaking schema change is made to clear stale data.
- **GCP Secret Manager**: Stores the node's secret key share (`PersistentNodeData`) in production via `SecretManagerNodeStorage`. Configured with `--sk-share-secret-id` / `MPC_SK_SHARE_SECRET_ID`.
- **Disk**: Local file storage for the secret key share (`DiskNodeStorage`), used in development and integration tests. Configured with `--sk-share-local-path` / `MPC_SK_SHARE_LOCAL_PATH`.
- **In-memory**: Fallback for both secret storage (`MemoryNodeStorage`) and indexer checkpoints (`CheckpointStorage::InMemory`). Used automatically in tests when no Redis URL or GCP config is provided.
- **Checkpoints** (`CheckpointStorage`): Tracks the latest indexed block per chain (NEAR, Ethereum, Solana) so the indexer can resume after a restart. Backed by Redis in production and in-memory in tests.

The `chain-signatures/node/src/storage/` directory contains all storage modules. `protocol_storage.rs` provides the generic `ProtocolStorage<A>` implementation used by both triples and pre-signatures.

## Key Patterns

- **Protocol ownership**: Every protocol invocation (triple, pre-signature, signature) has exactly one `Owner` node. Other participants follow the owner's lead and must not make unilateral decisions about a non-owned invocation.
- **Non-reuse invariant**: Triples and pre-signatures must never be used more than once. Code that selects or consumes these inputs must transition their state (`Available` → `Using` → done) atomically and persistently.
- **Event-sourcing for recovery**: While a protocol is `Running`, all received messages are persisted before being applied so the in-memory state can be replayed after a crash.
- **State sync**: Runs on every new peer connection. The owner sends its directory of held inputs; the peer responds with any that are missing so both sides can reconcile.
- **Key derivation**: Account derivation for foreign chains follows NEAR's [chain-key derivation spec](../doc/ACCOUNT_DERIVATION.md).

## Important Files

| File | Purpose |
|------|---------|
| `chain-signatures/node/src/protocol/` | Core MPC protocol state machines |
| `chain-signatures/node/src/indexer.rs` | NEAR chain indexer for sign requests |
| `chain-signatures/contract/src/lib.rs` | NEAR contract entry points |
| `chain-signatures/crypto/` | Cryptographic primitives (wrappers around cait-sith / k256) |
| `integration-tests/src/` | Cluster setup helpers and test utilities |
| `../doc/mpc_node_specification.md` | Authoritative distributed-algorithm spec |
