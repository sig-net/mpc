# Refactor Plan

## Goal
Unify indexed request representation so the same request data created by indexers is persisted in the backlog, remove `SignRequestType`, rename the request-kind enum to `SignKind`, and use a shared `SignStatus` workflow state across backlog and bidirectional execution tracking.

## Tasks
- [x] Define the new canonical request model
  - Remove `SignRequestType`
  - Introduce `SignKind`
  - Keep shared signing data on `IndexedSignRequest`
- [x] Refactor backlog persistence model
  - Persist indexed request data directly
  - Flatten backlog execution state so `BacklogEntry` stores `SignStatus` plus optional execution tx
  - Preserve bidirectional execution watcher behavior
- [x] Update request producers and consumers
  - Indexers
  - Stream processing and recovery
  - Protocol / RPC publishing / bidirectional flows
- [x] Update tests
  - Unit tests
  - Integration tests
- [x] Validate
  - Compile affected crates
  - Run targeted tests

## Progress
- [x] Plan created
- [x] Core request types updated
- [x] Backlog updated
- [x] Call sites updated
- [x] Validation complete
- [x] Shared status model unified (`PendingRequestStatus` → `SignStatus`, `BacklogStatus` removed)

## Validation Notes
- `cargo check -p mpc-node`
- `cargo test -p mpc-node --no-run`
- `cargo test -p integration-tests --no-run`
- `cargo test -p mpc-node test_backlog_chain_isolation -- --nocapture`
- `cargo test -p mpc-node test_stream_handles_sign_and_respond -- --nocapture`
- Added `IndexedSignRequest::{new, sign, sign_bidirectional, respond_bidirectional}` to reduce repeated request assembly.
- Added `BacklogEntry::{pending_execution, advance_to_execution}` to centralize workflow transitions.
- Re-ran `cargo test -p mpc-node --no-run`
- Re-ran `cargo test -p integration-tests --no-run`
- Ran `cargo test -p mpc-node test_stream_handles_sign_bidirectional_block_and_recover -- --nocapture`
- Renamed `PendingRequestStatus` to `SignStatus` and removed `BacklogStatus` by storing execution tx data directly on `BacklogEntry`.
- Re-ran `cargo test -p mpc-node --no-run`
- Ran `cargo test -p mpc-node test_backlog_chain_isolation -- --nocapture`
- Re-ran `cargo test -p mpc-node test_stream_handles_sign_bidirectional_block_and_recover -- --nocapture`
- Re-ran `cargo test -p integration-tests --no-run`
