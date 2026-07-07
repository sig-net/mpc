# Midnight test fixtures

Compiled `signet-signer` artifacts + toolkit config for the Midnight integration tests — the Canton-DAR pattern: the contract source and compile pipeline live in the `midnight-erc20-vault` repo; this directory pins only what deployment and calls need.

- `signet-signer/` — compiled contract module (`contract/`), `compiler/contract-info.json`, `keys/*.verifier`, `zkir/*.bzkir` (~160 KB, committed). **`keys/*.prover` (~1 GB) are gitignored** — regenerate in `midnight-erc20-vault` (`npm run compact:signer`) and copy `managed/signet-signer/keys/*.prover` here; the sandbox errors with instructions if they are missing.
- `signer.config.ts` + `package.json` — toolkit-js contract config (witness wiring). `midnight-node-toolkit generate-intent` type-compiles it, so its dev deps must be installed next to it; the Rust sandbox runs `npm ci` here on demand.
- `stack/` — recipes for the two locally-built docker images: `build-indexer-image.sh` (pinned `contract-events-e2e` commit `c7c267cc` — the only source of the `contractEvents` GraphQL API) and `toolkit-033/` (`signet/midnight-node-toolkit:2.0.0-rc.3-compact033`; stock toolkit images ship compact ≤ 0.31).

The wire protocol is specified in `doc/signet-midnight-events.md` (SGN1) and pinned by `chain-signatures/chain-midnight/tests/goldens/` (vectors generated in the vault repo). The sandbox (`integration-tests/src/midnight.rs`) spawns node + indexer as testcontainers and drives deploy/calls through the toolkit from Rust:

    cargo test -p integration-tests --test lib -- midnight_stream --ignored --test-threads 1
    cargo test -p integration-tests --test lib -- cases::midnight --ignored --test-threads 1

RAM notes: `sign`/`respond` prove in-container; `sign_bidirectional` proves natively at ≈24 GiB RSS (signbi stream test + bidirectional e2e need a ≥32 GiB host); the publisher's `respond_bidirectional` peaks ≈11.5 GiB. Binaries: `cargo build --locked --release -p midnight-node-toolkit -p midnight-publisher` in `chain-signatures/midnight-publisher/`.
