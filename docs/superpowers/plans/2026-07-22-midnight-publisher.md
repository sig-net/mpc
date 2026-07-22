# midnight-publisher (PR-1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the `midnight-publisher` localhost sidecar (dependency firewall + three seams: `/respond` prove+submit, `/state` decode, `/block` decode) by resurrecting our prior implementation from reflog commit `3a7705ca`, bumping it to the current stack, adding `/block`, and securing the bind.

**Architecture:** A nested Cargo workspace (own lockfile, excluded from root) that quarantines the `midnight-node-toolkit` + `midnight-ledger` git dependency universe from the polkadot-free main workspace. A single sequential `tiny_http` service shells out to `curl` for JSON-RPC reads and to the `midnight-node-toolkit` binary (built from the same locked workspace) for prove/submit. It is a mechanism only: no signing keys, no security decisions.

**Tech Stack:** Rust (edition 2021), `tiny_http`, `midnight-node-toolkit` + `midnight-node-ledger-helpers` (git, tag `node-2.0.0-rc.4`), the ledger `[patch.crates-io]` set (`midnight-ledger` git tags), Docker (ledger-9 dev stack: node rc.4 + proof-server 9.0.0-rc.5).

## Global Constraints

- Nested workspace at `chain-signatures/midnight-publisher/`, EXCLUDED from the root workspace, with its OWN `Cargo.lock`. Always build/test `--locked`. `cargo update` only for the deliberate rc bump in Task 2.
- Target stack: `midnight-node` tag `node-2.0.0-rc.4`; ledger `9.1.0.0-rc.3`; proof-server `9.0.0-rc.5_experimental`.
- Bind `127.0.0.1` ONLY (never `0.0.0.0`). `funding_seed` is injected via env, NEVER baked into the image.
- Mechanism-not-authority: the publisher performs NO rid recompute, NO proof verification, NO filtering by contract address. It decodes and returns raw bytes; `chain-midnight` owns every security decision.
- Sequential request handling only (respond proving peaks ~11.5 GiB RSS).
- NO em dashes in any file content, comment, or commit message. Conventional commits, subject under 72 chars, NO AI/Claude attribution.

---

### Task 1: Resurrect the crate at its rc.3 baseline

**Files:**
- Restore (from `3a7705ca`): `chain-signatures/midnight-publisher/{Cargo.toml,Cargo.lock,src/main.rs,src/service.rs,src/state.rs,tests/fake-toolkit.sh,tests/fake-rpc.sh,tests/fixtures/reference-state.mn}`

**Interfaces:**
- Produces: the full rc.3 crate on disk. `state::{Node, MapEntry, decode_contract_state}`; `service::{Config, RespondRequest, serve, validate, circuit_args, run_respond_flow, handle_state, query_param}`. These are consumed by later tasks.

- [ ] **Step 1: Restore the publisher tree from the reflog commit**

```bash
cd <repo>/mpc
git checkout 3a7705ca -- chain-signatures/midnight-publisher
```

- [ ] **Step 2: Verify the expected file set is present**

Run: `ls -1 chain-signatures/midnight-publisher chain-signatures/midnight-publisher/src chain-signatures/midnight-publisher/tests`
Expected: `Cargo.toml`, `Cargo.lock`, `src/main.rs`, `src/service.rs`, `src/state.rs`, `tests/fake-toolkit.sh`, `tests/fake-rpc.sh`, `tests/fixtures/reference-state.mn`

- [ ] **Step 3: Confirm the root workspace still excludes it**

Run: `grep -nE 'midnight-publisher|exclude' Cargo.toml`
Expected: `midnight-publisher` is NOT a workspace member (it is a nested workspace). If the root `[workspace]` has an `exclude` list, it should contain `chain-signatures/midnight-publisher`; if members are explicit, it must not be listed. If neither holds, note it for Task 8. Do NOT build yet (Task 2 owns the one heavy build).

- [ ] **Step 4: Commit**

```bash
git add chain-signatures/midnight-publisher
git commit -m "feat(midnight-publisher): resurrect rc.3 sidecar baseline"
```

---

### Task 2: Bump to node rc.4 and get the nested workspace building green

This is the alpha gate and the one unavoidable heavy build (the toolkit + ledger + polkadot-sdk universe). It is operation-plus-triage, not a TDD cycle: the acceptance test is the resurrected suite passing at rc.4.

**Files:**
- Modify: `chain-signatures/midnight-publisher/Cargo.toml` (dependency + patch git tags)
- Regenerate: `chain-signatures/midnight-publisher/Cargo.lock`
- Possibly modify (only if rc.4 drifted the API): `chain-signatures/midnight-publisher/src/state.rs`, `src/service.rs`

**Interfaces:**
- Produces: a `--locked` green build at rc.4 and the fetched crate sources under `~/.cargo/git/` (Task 5 reads them).

- [ ] **Step 1: Bump the two node git tags rc.3 to rc.4**

In `Cargo.toml`, change both `midnight-node-toolkit` and `midnight-node-ledger-helpers` from `tag = "node-2.0.0-rc.3"` to `tag = "node-2.0.0-rc.4"`.

- [ ] **Step 2: Reconcile the ledger `[patch.crates-io]` tags with rc.4**

The patch set must match what `midnight-node @ node-2.0.0-rc.4` itself pins (patches do not propagate transitively). Read the rc.4 node's own `Cargo.toml` to get the exact ledger tags:

```bash
git ls-remote --tags https://github.com/midnightntwrk/midnight-node | grep node-2.0.0-rc.4
# then read that tag's Cargo.toml patch/deps to confirm each midnight-ledger tag
```

Update any changed tag in the `[patch.crates-io]` block. The ledger line is already `9.1.0.0-rc.3` (our target); most tags likely stay, but confirm rather than assume.

- [ ] **Step 3: Regenerate the lockfile and start the heavy build in the background**

```bash
cd chain-signatures/midnight-publisher
cargo update -p midnight-node-toolkit -p midnight-node-ledger-helpers
cargo build --locked 2>&1 | tee /tmp/mn-pub-build.log   # run in background; first build is very long
```
Run this in the background and monitor `/tmp/mn-pub-build.log`.

- [ ] **Step 4: Triage rc.4 drift until the build is green**

If the build fails, the errors are rc.4 API drift against `state.rs` (uses `midnight_node_ledger_helpers::{AlignedValue, ContractState, DefaultDB, StateValue, deserialize}`) or `service.rs`. For each error, read the current rc.4 crate API under `~/.cargo/git/checkouts/` and adjust the call site minimally. Do NOT change behavior; only track API renames/signature changes. Record each drift fix in the commit body. If a drift is not resolvable (a removed capability), STOP and surface the exact error.

- [ ] **Step 5: Run the resurrected fast test suite**

Run: `cargo test --locked`
Expected: PASS for all resurrected tests, including `state::tests::decodes_reference_state_fixture_to_atom_tree`, `service::tests::{respond_request_json_seam_is_stable, validation_rules, circuit_args_order, respond_flow_invokes_toolkit_in_driver_order, query_param_parses_address, state_rejects_bad_address, state_fetches_decodes_and_anchors_via_fake_rpc, state_decode_failure_is_502}`.
If a test fails due to a legitimate rc.4 behavior change (not a bug), update the assertion and note why.

- [ ] **Step 6: Commit**

```bash
git add chain-signatures/midnight-publisher/Cargo.toml chain-signatures/midnight-publisher/Cargo.lock chain-signatures/midnight-publisher/src
git commit -m "feat(midnight-publisher): bump toolkit+ledger to node rc.4"
```

---

### Task 3: Localhost bind + native intent default (config hardening)

**Files:**
- Modify: `chain-signatures/midnight-publisher/src/service.rs` (the `Config` struct, `Config::from_env`, and `serve`)
- Test: `chain-signatures/midnight-publisher/src/service.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `service::Config`, `service::serve`, the `env_or(key, default)` helper (already present).
- Produces: `Config.bind_host: String` (default `"127.0.0.1"`); `serve` binds `(cfg.bind_host.as_str(), cfg.port)`; `intent_mode` defaults to `Native` when `MIDNIGHT_PUB_INTENT_MODE` is unset.

- [ ] **Step 1: Write the failing test**

Add to `service.rs` tests. This asserts the two new defaults through `from_env` with only the required vars set:

```rust
#[test]
fn config_defaults_localhost_bind_and_native_intent() {
    let _guard = RPC_ENV_LOCK.lock().unwrap();
    // Set only the REQUIRED vars; leave bind host and intent mode unset.
    for (k, v) in [
        ("MIDNIGHT_PUB_FUNDING_SEED", &("00".repeat(31) + "01")),
        ("MIDNIGHT_PUB_WORK_DIR", &std::env::temp_dir().display().to_string()),
    ] {
        std::env::set_var(k, v);
    }
    std::env::remove_var("MIDNIGHT_PUB_BIND_HOST");
    std::env::remove_var("MIDNIGHT_PUB_INTENT_MODE");
    let cfg = Config::from_env().expect("from_env with required vars set");
    assert_eq!(cfg.bind_host, "127.0.0.1", "defaults to localhost bind");
    assert!(matches!(cfg.intent_mode, IntentMode::Native), "defaults to native");
}
```

Note: `from_env` reads other required vars via `env_required`; if this test needs more vars set to succeed, set exactly those the current `from_env` requires (read it first) and no more. Reuse the existing `RPC_ENV_LOCK` to serialize env mutation.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --locked config_defaults_localhost_bind_and_native_intent -- --nocapture`
Expected: FAIL (no `bind_host` field, and/or `from_env` bails on missing `MIDNIGHT_PUB_INTENT_MODE`).

- [ ] **Step 3: Add the `bind_host` field and the two defaults**

In the `Config` struct add:
```rust
    /// Interface to bind. Defaults to 127.0.0.1 (co-located sidecar; never 0.0.0.0).
    pub bind_host: String,
```
In `Config::from_env`, add `bind_host: env_or("MIDNIGHT_PUB_BIND_HOST", "127.0.0.1"),` and change the intent-mode read to default native, i.e. parse `env_or("MIDNIGHT_PUB_INTENT_MODE", "native")` instead of an `env_required`/bail-on-missing read (keep the `docker|native|other=>bail` match on the resulting value).

- [ ] **Step 4: Point `serve` at the configured host**

In `serve`, change:
```rust
let server = tiny_http::Server::http(("0.0.0.0", cfg.port))
    .map_err(|e| anyhow::anyhow!("bind :{}: {e}", cfg.port))?;
```
to:
```rust
let server = tiny_http::Server::http((cfg.bind_host.as_str(), cfg.port))
    .map_err(|e| anyhow::anyhow!("bind {}:{}: {e}", cfg.bind_host, cfg.port))?;
```
Update the startup `println!` to print `cfg.bind_host` and `cfg.port`. Add `bind_host` to every `Config { .. }` literal in the test module (set it to `"127.0.0.1".into()`).

- [ ] **Step 5: Run tests to verify pass**

Run: `cargo test --locked`
Expected: PASS, including the new `config_defaults_localhost_bind_and_native_intent` and all resurrected tests.

- [ ] **Step 6: Commit**

```bash
git add chain-signatures/midnight-publisher/src/service.rs
git commit -m "feat(midnight-publisher): bind 127.0.0.1 by default, native intent default"
```

---

### Task 4: Bring up the ledger-9 stack, deploy v3 contracts, capture fixtures

Operation task. Produces the live stack and the fixtures Task 6 and Task 7 need.

**Files:**
- Create: `chain-signatures/midnight-publisher/tests/fixtures/notify-block.json` (a captured finalized block containing a caller notify tx)
- Create: `chain-signatures/midnight-publisher/tests/fixtures/v3-reference-state.mn` (a live v3 caller contract state)

**Interfaces:**
- Produces: a running node (`:9944`) + proof-server (`:6300`); a deployed `signet-contract` + `caller-contract`; the two fixtures above; the finalized block hash of a notify tx (recorded in a comment in `notify-block.json`).

- [ ] **Step 1: Start the stack**

```bash
cd <repo>/midnight-integration
docker compose up -d
# wait for health
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getFinalizedHead","params":[]}' http://localhost:9944/
```
Expected: a JSON-RPC result (a `0x` block hash). If images fail to pull or the node never finalizes, STOP and surface the exact failure.

- [ ] **Step 2: Deploy the v3 contracts and submit one request**

Use the `midnight-integration` deploy + e2e tooling (`packages/signet-contract-deploy`, `packages/caller-contract`, `packages/integration-tests`; see `midnight-integration/.claude/skills/e2e/SKILL.md`) to deploy `signet-contract` and `caller-contract`, initialise the caller, and call `submitSignatureRequest` once. Record the caller address and the finalized block hash of the submit tx.

- [ ] **Step 3: Capture the v3 state fixture**

```bash
cd <repo>/mpc/chain-signatures/midnight-publisher
# via the publisher /state seam once it is running, or directly:
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"midnight_contractState","params":["<caller-addr-64hex>","<0xfinalizedhash>"]}' \
  http://localhost:9944/ | jq -r .result | sed 's/^0x//' | xxd -r -p > tests/fixtures/v3-reference-state.mn
```

- [ ] **Step 4: Capture the notify-block fixture**

```bash
curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getBlock","params":["<0xfinalizedhash>"]}' \
  http://localhost:9944/ > tests/fixtures/notify-block.json
```
Add a top-of-file comment (or sidecar `.txt`) recording the block hash and the caller address, so Task 6's test is self-describing.

- [ ] **Step 5: Commit the fixtures**

```bash
git add chain-signatures/midnight-publisher/tests/fixtures/notify-block.json chain-signatures/midnight-publisher/tests/fixtures/v3-reference-state.mn
git commit -m "test(midnight-publisher): capture v3 state and notify-block fixtures"
```

---

### Task 5: `/block` decode API discovery

Discovery task. Its deliverable is a findings note that unblocks Task 6, so Task 6's code is written against the real crate API, not a guess.

**Files:**
- Create: `docs/superpowers/notes/2026-07-22-block-decode-api.md`

**Interfaces:**
- Consumes: the fetched `midnight-node-ledger-helpers` + `midnight-node-toolkit` crate sources under `~/.cargo/git/checkouts/` (present after Task 2), `src/state.rs` (the `walk`/`deserialize` pattern), and `git show 3a7705ca` (reference read only).
- Produces: documented, exact API for: (a) which RPC returns a finalized block body and its shape (`chain_getBlock`), (b) how to deserialize an extrinsic's ledger `Transaction` (the helper name, mirroring `deserialize::<ContractState<DefaultDB>>`), (c) how to enumerate call segments and read each call's transcript `insert` key/value, (d) where the caller-frame `claimedContractCalls` commitment sits.

- [ ] **Step 1: Locate the ledger-helpers transaction + transcript API**

```bash
ls ~/.cargo/git/checkouts/ | grep -i midnight
grep -rniE 'pub fn|pub struct|Transaction|Transcript|claimedContractCalls|ContractCall|call.?segment|deserialize' \
  ~/.cargo/git/checkouts/midnight-node-*/*/ledger-helpers 2>/dev/null | grep -iE 'transaction|transcript|contractcall|claimed|deserialize' | head -60
```
Read the types those hits point at.

- [ ] **Step 2: Write the findings note**

Document the exact type names, function signatures, and the field path from a decoded block body down to `{insert key, insert value, claimedContractCalls}`. Include the concrete Rust snippet that deserializes one extrinsic into a ledger `Transaction`. If the block body is SCALE-encoded extrinsics wrapping the ledger tx, document the unwrap step. If any part is genuinely absent from the rc.4 crates, say so explicitly and flag it as a blocker for Task 6.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/notes/2026-07-22-block-decode-api.md
git commit -m "docs(midnight-publisher): block-decode API findings"
```

---

### Task 6: `/block` seam

**Files:**
- Create: `chain-signatures/midnight-publisher/src/block.rs`
- Modify: `chain-signatures/midnight-publisher/src/main.rs` (add `mod block;`), `src/service.rs` (add the `GET /block` route + a `handle_block` mirroring `handle_state`)
- Test: `chain-signatures/midnight-publisher/src/block.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: the Task 5 API; the `state.rs` `walk`/`value_atoms` pattern; the Task 4 `notify-block.json` fixture; `service::query_param`, `service::is_hex`, the `rpc_call`/`http_rpc_url` helpers.
- Produces: `block::{BlockNotify, BlockResponse, decode_block}`; `service::handle_block(cfg, url) -> (u16, String)`; route `GET /block?hash=<0xhash>`.

- [ ] **Step 1: Define the return shape**

In `block.rs`, add serde types for the decoded result. Keep it a faithful, policy-free projection (no filtering by central address):
```rust
/// One contract call extracted from a finalized block, with its transcript
/// insert key/value (the notify entry) and the caller-frame CCC commitment.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockNotify {
    /// Callee contract address the call targets, bare 64-hex.
    pub address: String,
    /// The insert key atoms (SignetMapKey: count ++ requestId), hex.
    pub insert_key: Vec<String>,
    /// The insert value atoms (SignBidirectionalEventNotification: version, payload), hex.
    pub insert_value: Vec<String>,
    /// The caller-frame claimedContractCalls commitment, hex, when present.
    pub claimed_contract_calls: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockResponse {
    pub calls: Vec<BlockNotify>,
}
```

- [ ] **Step 2: Write the failing test against the captured fixture**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_notify_block_fixture() {
        // notify-block.json is chain_getBlock's response for a finalized block
        // that contains exactly one caller submitSignatureRequest (see the
        // fixture's header comment for the block hash + caller address).
        let raw = std::fs::read("tests/fixtures/notify-block.json").unwrap();
        let resp = decode_block(&raw).expect("decode notify block");
        // At least the caller->central notify call is present.
        let notify = resp.calls.iter().find(|c| !c.insert_key.is_empty())
            .expect("a call carrying a transcript insert");
        // SignetMapKey is (count: Uint<64>, requestId: Bytes<32>): 2 atoms.
        assert_eq!(notify.insert_key.len(), 2, "count ++ requestId");
        // Notification is (version: Uint<8>, payload: Bytes<128>): 2 atoms.
        assert_eq!(notify.insert_value.len(), 2, "version ++ payload");
    }
}
```
If Task 5 found the block body carries the CCC commitment, add an assertion that `claimed_contract_calls.is_some()` for the CCC ride-along call. If the exact atom counts differ from the SGN2 struct shapes once decoded, correct the assertion to the real shape and note why (the struct shapes are in `doc/midnight-spec.md` §3.4).

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --locked decodes_notify_block_fixture -- --nocapture`
Expected: FAIL with "cannot find function `decode_block`".

- [ ] **Step 4: Implement `decode_block` using the Task 5 API**

Implement `pub fn decode_block(raw: &[u8]) -> anyhow::Result<BlockResponse>` in `block.rs`, following the `state.rs` `walk`/`value_atoms` pattern for atom extraction and the Task 5 findings for deserializing each extrinsic's ledger `Transaction` and reading its call segments' transcript inserts + `claimedContractCalls`. Do NOT filter by address (mechanism only). Do NOT recompute rids.

- [ ] **Step 5: Add the `GET /block` route + `handle_block`**

In `service.rs`, add `handle_block(cfg, url)` mirroring `handle_state`: read `hash` via `query_param`, validate it is 0x-prefixed 64-hex, call `rpc_call(cfg, "chain_getBlock", json!([hash]))`, pass the raw body to `crate::block::decode_block`, serialize `BlockResponse`. Add the route arm `("GET", "/block") => { let (code, body) = handle_block(&cfg, &url); respond(request, code, body); }`. Add `mod block;` to `main.rs`.

- [ ] **Step 6: Run tests to verify pass**

Run: `cargo test --locked`
Expected: PASS, including `decodes_notify_block_fixture` and all prior tests.

- [ ] **Step 7: Commit**

```bash
git add chain-signatures/midnight-publisher/src/block.rs chain-signatures/midnight-publisher/src/main.rs chain-signatures/midnight-publisher/src/service.rs
git commit -m "feat(midnight-publisher): add /block decode seam"
```

---

### Task 7: Live end-to-end validation against the stack

Operation task (the heavy path). Validates the rc.4 bump and real proving; no new production code.

**Files:**
- Create: `chain-signatures/midnight-publisher/tests/e2e.md` (a runbook recording the exact commands + observed results, so the heavy path is reproducible)

**Interfaces:**
- Consumes: the Task 4 stack + deployed contracts; the built publisher binary; the toolkit binary (`cargo build --locked -p midnight-node-toolkit`).

- [ ] **Step 1: Build the toolkit binary and start the publisher**

```bash
cd <repo>/mpc/chain-signatures/midnight-publisher
cargo build --locked -p midnight-node-toolkit
MIDNIGHT_PUB_FUNDING_SEED=<hot-dev-seed> MIDNIGHT_PUB_INTENT_MODE=native \
  MIDNIGHT_PUB_BIND_HOST=127.0.0.1 <other required env> cargo run --locked &
curl -s http://127.0.0.1:<port>/health   # expect: ok
```

- [ ] **Step 2: Live `/state` and `/block`**

```bash
curl -s "http://127.0.0.1:<port>/state?address=<caller-64hex>" | jq '.anchor, (.tree.kind)'
curl -s "http://127.0.0.1:<port>/block?hash=<0xnotifyhash>" | jq '.calls[] | {address, insert_key, insert_value}'
```
Expected: `/state` returns `{anchor, tree}` for the live v3 caller; `/block` returns the notify call with a 2-atom insert key and 2-atom value.

- [ ] **Step 3: Live `/respond` prove + submit**

POST a real `postRespondBidirectional` for the submitted request and confirm it lands on-chain and the posted signature verifies against the derived response key. Record proving wall-time and peak RSS.

```bash
curl -s -X POST http://127.0.0.1:<port>/respond -H 'Content-Type: application/json' -d '<RespondRequest JSON>'
# expect: {"status":"ok"}; then confirm the respondBidirectionalMap entry on-chain
```
If proving OOMs or the submit is rejected, capture the exact error in `e2e.md` and surface it. Do NOT fake success.

- [ ] **Step 4: Confirm localhost-only bind**

Run: `lsof -iTCP -sTCP:LISTEN -n -P | grep <port>`
Expected: bound to `127.0.0.1:<port>`, NOT `*` / `0.0.0.0`.

- [ ] **Step 5: Commit the runbook**

```bash
git add chain-signatures/midnight-publisher/tests/e2e.md
git commit -m "test(midnight-publisher): live e2e runbook and results"
```

---

### Task 8: Build wiring + CI gate

**Files:**
- Modify (if needed): `Cargo.toml` (root workspace `exclude`)
- Create: `.github/workflows/midnight-publisher.yml`

**Interfaces:**
- Consumes: the green `--locked` build from Task 2.
- Produces: a CI job that builds + tests the nested workspace `--locked` and guards main-lockfile purity.

- [ ] **Step 1: Ensure the root workspace excludes the nested one**

If Task 1 Step 3 found the exclusion missing, add to the root `Cargo.toml` `[workspace]`:
```toml
exclude = ["chain-signatures/midnight-publisher"]
```
Run: `cargo metadata --format-version 1 --no-deps | grep -c midnight-publisher` from the repo root.
Expected: `0` (the nested crate is NOT in the root workspace graph).

- [ ] **Step 2: Add the CI workflow**

Create `.github/workflows/midnight-publisher.yml` that, on changes under `chain-signatures/midnight-publisher/**`: checks out, installs Rust, runs `cargo build --locked` and `cargo test --locked` inside the nested workspace, and runs a lockfile-purity check that fails if the MAIN `Cargo.lock` contains any of `polkadot`, `subxt`, or `midnight-ledger` (the firewall guard). Model the multi-language/caching shape on the existing root `Dockerfile` and any current `.github/workflows/*.yml`.

- [ ] **Step 3: Verify locally**

Run: `cd chain-signatures/midnight-publisher && cargo build --locked && cargo test --locked`
Expected: PASS. And: `grep -cE 'polkadot|subxt|midnight-ledger' <repo>/mpc/Cargo.lock` prints `0`.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml .github/workflows/midnight-publisher.yml
git commit -m "ci(midnight-publisher): nested-workspace build+test gate"
```

---

## Notes on honesty and the alpha path

Tasks 2, 4, and 7 touch the unstable alpha toolchain and a live stack. Their "expected output" is a success criterion, not a transcript of a run that has not happened. If any hits an un-passable wall (rc.4 API removed a needed capability, images will not pull, proving OOMs), STOP that task and surface the exact error rather than working around it or faking a pass. Tasks 1, 3, 5, 6, 8 do not depend on the live stack and can proceed on the fake-based tests alone.
