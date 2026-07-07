# Midnight integration: architecture and pattern deviations

How `chain-midnight` differs from the other chain integrations, why, and where each deviation lives in code. The wire protocol itself is specified in `signet-midnight-events.md` (SGN1); the contract source and golden-vector generator live in the `midnight-erc20-vault` repo, with the compiled artifacts pinned at `integration-tests/fixtures/midnight/`.

## Out-of-process publisher (the one structural deviation)

Every other chain publishes signatures in-process. Midnight's respond path needs `midnight-node-toolkit` (there is no ledger-9 JS/Rust SDK), and the toolkit's dependency universe (polkadot-sdk, subxt, midnight-ledger) cannot co-resolve with this workspace's lockfile — any re-resolution destabilizes the pre-existing `chain-ethereum → helios → libp2p → core2` subtree. So:

- `chain-signatures/midnight-publisher/` is a **nested Cargo workspace** (root `Cargo.toml` `exclude`) with its own lockfile, seeded from midnight-node's lockfile at tag `node-2.0.0-rc.3` — never run bare `cargo update` there; build with `--locked`. A fresh resolve pulls a duplicate `pallas-primitives` that fails to compile.
- It exposes a tiny HTTP service (`POST /respond`) that drives the toolkit CLI as subprocesses (contract-state → generate-intent → send-intent). Intent generation runs in the pinned toolkit-033 docker image because it needs node/toolkit-js; proving and submission run through the natively built toolkit binary.
- The workspace-member crate `chain-signatures/chain-midnight/` stays light (reqwest/tungstenite/serde) and reaches the service via `MidnightClient` — structurally a Canton client with an HTTP seam. The JSON body is mirrored in both workspaces and pinned by identical test fixtures on each side.
- Guardrail: the main `Cargo.lock` must contain zero toolkit/polkadot entries (`grep -c polkadot Cargo.lock` = 0, enforced in `.github/workflows/midnight.yml`).

## Progress token = contract-event id, not block height

The indexer subscribes to the pinned midnight-indexer's `contractEvents` GraphQL API (the only source of ledger-9 contract events), whose monotonic event `id` is the natural resume cursor. Consequences, all in `chain-midnight/src/indexer.rs` and `reassembly.rs`:

- `ChainEvent::Block(event_id)` carries event ids; `CHECKPOINT_INTERVAL_MIDNIGHT` means "every N observed events" (Canton offset precedent, `primitives/src/chain.rs`).
- The cursor advances only at request boundaries (multi-part requests are all-or-nothing); reconnects over-fetch `MAX_PARTS − 1` ids and dedupe by "group completes past the cursor".
- Catchup targets a single anchor (the global `maxId`) instead of iterating heights: ids are shared across all contracts and the subscription emits nothing between our events, so per-id iteration would stall on foreign ids.

## Trust tier (SECURITY-CRITICAL caveat)

Event authenticity currently rests on: an operator-owned node + pinned indexer, a finality gate that checks `chain_getFinalizedHead` directly against the node RPC (`finality.rs` — never trusting the indexer's claim), request-id recomputation from the received bytes (`convert.rs`), MPC threshold independence, and consensus checkpoints. **There is no proof-of-inclusion yet** — Hydration-parity Merkle proofs (then a light client) must land before real value depends on Midnight-derived keys. Related gap: no deposit/spam gating; the indexer fixes `deposit = 1`.

## Other deviations

- **Respond output format is ABI** (`Chain::Midnight => SerDeserFormat::Abi` in `primitives/src/chain.rs`): the SGN1 goldens pin a 32-byte ABI bool word and hash it into the phase-2 message. For EVM contract-call requests the `outputSchema` must be the object form `[{"name":…,"type":…}]` — normative note in `signet-midnight-events.md`.
- **Synthetic CAIP-2** `midnight:mainnet` (no registered namespace; Canton `canton:global` precedent).
- **`chain_ctx = None`**: respond calls need only the configured contract address + request id, unlike Canton's per-request contract id.
- **Fixtures with regenerable provers** (`integration-tests/fixtures/midnight/`): the Canton-DAR pattern, except prover keys (~1 GB) are too large to commit — `keys/*.prover` is gitignored and regenerated in the vault repo. The toolkit-js contract config (`signer.config.ts`) is type-compiled by the toolkit, so the Rust sandbox runs `npm install` for its exact-pinned dep on demand; the toolkit-033 and indexer docker images are built locally from the recipes in `fixtures/midnight/stack/`.
- **Test sandbox drives external tools from Rust** (`integration-tests/src/midnight.rs`): node + indexer as testcontainers (no proof-server — the toolkit proves locally), deploy/call as toolkit subprocess sequences (the `dpm`-spawning Canton sandbox precedent, extended with docker-run steps for toolkit-js).
