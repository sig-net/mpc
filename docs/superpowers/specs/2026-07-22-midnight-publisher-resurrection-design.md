# midnight-publisher: resurrection + SGN2 updates (PR-1)

**Date:** 2026-07-22
**Status:** design approved; pending spec review, then writing-plans
**PR:** PR-1 `feat(midnight-publisher): sidecar + dependency firewall (three seams)`
**Related:** `doc/midnight-spec.md` §5.5; `doc/midnight-sgn2-mpc-tasks.md` PR-1; `doc/midnight-spec-decisions.md` §B.8, §B.9, §D

## Goal

Stand up the `midnight-publisher` sidecar: the localhost-bound out-of-process service that quarantines the unstable Midnight `node-toolkit` + `ledger` dependency universe from the main mpc workspace, and exposes the three seams the `chain-midnight` crate needs: prove+submit responds (`POST /respond`), decode contract state (`GET /state`), decode finalized block bodies (`GET /block`).

## Approach: resurrect, do not rewrite

A near-complete implementation exists as our own prior work in reflog commit `3a7705ca` (unreachable from any branch but a valid git object). It already solves the two hardest parts: the dependency firewall (a 12-entry `[patch.crates-io]` pin set that lets the nested workspace co-resolve the toolkit + ledger crates) and the `/respond` + `/state` seams. We resurrect it and apply a bounded set of updates rather than rederive it. This supersedes the "from scratch" note in `midnight-sgn2-mpc-tasks.md` PR-1, which was aimed at the messy chain integration, not this isolated artifact.

## What we resurrect verbatim (from `3a7705ca`)

Path `chain-signatures/midnight-publisher/`:
- `Cargo.toml` + `Cargo.lock`: nested workspace excluded from the root, own lockfile; deps `midnight-node-toolkit` and `midnight-node-ledger-helpers` (git, node tag) plus the 12-entry ledger `[patch.crates-io]` set, and `anyhow` / `hex` / `serde` / `serde_json` / `tiny_http`.
- `main.rs`: env config to `service::serve`; a smoke test that keeps the toolkit git-dep linked.
- `service.rs` (~832 lines): a `tiny_http` server, **sequential** (respond proving peaks ~11.5 GiB RSS); routes `GET /health`, `GET /state?address=`, `POST /respond`; JSON-RPC via a `curl` subprocess; the respond flow shells out to the toolkit binary (contract-state, then generate-intent in docker or native mode, then send-intent with `--funding-seed`); config from `MIDNIGHT_PUB_*` env vars.
- `state.rs`: `decode_contract_state(raw) -> Node` via `midnight-node-ledger-helpers`.
- `tests/`: `fake-toolkit.sh`, `fake-rpc.sh`, `fixtures/reference-state.mn`. The service logic is testable without the real toolkit or a live stack.

## Updates (the delta)

1. **Security: bind localhost.** `service.rs` currently binds `("0.0.0.0", port)` (confirmed the decisions §B.8 finding). Change to a configurable host `MIDNIGHT_PUB_BIND_HOST` defaulting to `127.0.0.1`. `funding_seed` is already env-required and never baked; keep. No auth beyond the localhost boundary (co-located sidecar; a unix socket is a possible later hardening).
2. **New `/block` seam.** `GET /block?hash=<0xhash>`: fetch the finalized block via JSON-RPC (`chain_getBlock`), decode each extrinsic's ledger transaction into `{call segments, transcript insert key/value, claimedContractCalls commitment}` in a new `block.rs` that parallels `state.rs` on the same `midnight-node-ledger-helpers`. Generic decode: no central-contract address knowledge, since the `chain-midnight` crate does the filtering. The exact ledger-helpers tx/transcript API is discovered during implementation (a reference read of `3a7705ca` and the crate is allowed). `/block` keyed by finalized hash (locked).
3. **Stack bump rc.3 to rc.4.** Bump the toolkit / ledger-helpers git tags `node-2.0.0-rc.3` to `node-2.0.0-rc.4`; re-verify the `[patch.crates-io]` ledger tags (the ledger is already `9.1.0.0-rc.3`, our target); regenerate `Cargo.lock`. Highest-risk item (alpha API drift); the fake-based tests stay green regardless.
4. **Native default.** Keep both intent modes; default `native` (decisions §B.9, no docker-in-docker in production). Docker mode stays as a local-dev convenience (locked).
5. **Build/CI wiring.** Keep the nested workspace excluded from the root; build and test with `--locked`; add a build+test CI gate (full CI hardening stays PR-15).

## Architecture

- One localhost `tiny_http` service, sequential request handling (proving is memory-heavy).
- Shell-out design (no async HTTP stack or heavy client deps inside the firewall): a `curl` subprocess for JSON-RPC reads; the `midnight-node-toolkit` binary (built from the same locked workspace) for prove/submit and contract-state.
- Seams: `GET /health`, `GET /state?address=`, `POST /respond`, `GET /block?hash=` (new).
- Config (env `MIDNIGHT_PUB_*`): intent mode (docker|native), funding seed (required), bind host (new, default `127.0.0.1`), port, work dir, toolkit bin, node url, curl bin.
- Trust plane: mechanism only. It holds a funding (gas) wallet, no signing shares. Every security decision (rid recompute, proofs) lives in `chain-midnight` over the raw bytes this service returns, so a publisher decode bug is a dropped request, never a wrong signature.

## Testing

Both tiers run in this session (per the build-and-test-here decision):
- **Fast (no stack):** unit/integration tests via `fake-toolkit.sh` + `fake-rpc.sh` + `reference-state.mn`, covering routing, request validation, `/state` and `/block` decode, `/respond` arg construction, and the localhost bind.
- **Heavy (real toolchain + stack):** the real `cargo build --locked` of the toolkit + ledger universe at rc.4; bring up the ledger-9 stack via `docker compose up` in `midnight-integration` (node rc.4 + proof-server rc.5); a live e2e exercising `/state`, `/block`, and a real `/respond` prove+submit against a deployed signet-contract. This is the alpha path: the rc.4 build may drift, the stack may need coaxing, and proving needs roughly 11.5 GiB RSS plus long build times. Big builds run in the background; results are reported truthfully, and an un-passable alpha wall is surfaced with its exact error rather than worked around.

## Scope boundary

PR-1 is the sidecar only. The mpc-node client that POSTs to it (`MidnightClient` in `chain-midnight`) is PR-3/4.

## Acceptance criteria

- Nested workspace builds `--locked` at rc.4 (heavy path); the fake-based tests pass (fast path).
- `/state` decodes `reference-state.mn` and a live contract state.
- `/block` extracts the notify insert key/value and the CCC commitment from a real notify block.
- `/respond` proves and submits a `postRespond` / `postRespondBidirectional` to finality (live path).
- Binds `127.0.0.1` only; `funding_seed` injected, never baked.

## Risks / open items

- rc.4 alpha build drift: top risk, mitigated by the fake tests and honest reporting.
- Stack bring-up and proving resource needs on this machine.
- `/block` decode API discovery against `midnight-node-ledger-helpers` (the one area intentionally left to implementation-time exploration).
- Locked defaults: `/block` keyed by hash; docker intent mode kept as dev-only.
