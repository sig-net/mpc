# Hot-injectable indexers — design context

This note captures the full design discussion: why a parser fix does not unstick a stalled chain, how to recover checkpoints, whether parsers can be hot-injected, whether parser code belongs on the NEAR governance contract, and the related bidirectional schema-mismatch signing bug.

It is a design record, not an implementation spec. Issue 1 (parser generation + `clear_pending`) is the stall fix. Issue 2 (hot-inject) is deploy isolation. Bidirectional schema split is a signing-correctness bug that is independent of both.

---

## 1. Current architecture (what actually happens)

### Data flow

```
ChainIndexer::run()
  → ordered ChainEvent stream
      SignRequest | Respond | RespondBidirectional | Block | CatchupCompleted | ExecutionConfirmed
  → stream/supervisor.rs::run_supervised
  → stream/ops.rs
      process_sign_request → Backlog::insert
      process_block_event  → Backlog::set_processed_block → checkpoint() → vote_checkpoint
```

A `Checkpoint` durably freezes **already-parsed result**, not the raw block:

```
Checkpoint {
  chain,
  block_height,
  pending_requests: Vec<BacklogEntry>,   // parsed IndexedSignRequest bodies
  cumulative_digest,                     // sha3 of per-entry consensus tags
}
```

Digest is content-addressed over `(caip2, height, request_ids, cumulative_digest)` (`mpc_primitives::checkpoint_digest`). There is **no parser version in the digest**.

### The 32 pending cap

- `MAX_PENDING_CHECKPOINTS = 32` per chain (`backlog/mod.rs`).
- `persist_pending` returns `PendingCap` when full.
- `set_processed_block_interval` logs `checkpoint creation stalled` and returns `None` (no vote).
- Supervisor gates `events_rx.recv()` on `has_checkpoint_slot()` so the chain channel backs up; indexer `send().await` blocks; watermark stops.
- `load_local` **restores the full pending set** on restart by design (`checkpoints.rs`): a stall caused by consensus falling behind persists across restarts, because the cap is backpressure and only a consensus confirmation frees slots.

Redis keys (namespace `CHECKPOINT_STORAGE_VERSION = "v14"`):

- `{account}:checkpoint:latest:v14:{chain}`
- `{account}:checkpoint:pending:v14:{chain}`
- `{account}:checkpoint:pending_digest:v14:{chain}`

### Why a binary-only parser fix does not unstick

Pending checkpoints freeze parse **output**. A new binary only changes **future** parses. The 32 wrong pending bodies stay in Redis, are rehydrated verbatim, their digests never match consensus, slots never free.

Solana was this case:

- `#844` — `UiTransactionStatusMeta` failed to deserialize Solana 4.0 `BorshIoError` string form (host SDK / RPC JSON). Slot 466737912 / tx-32.
- `#1070` — `split_cpi_event` panicked on `<16B` CPI data (decoder kernel).
- Plus catchup-vs-live decode divergence (`#1140`, `#1158`).

Operators shipped a new `mpc-node` and restarted. They did **not** call `reset_checkpoints`. Stall survived.

### Existing nuclear recovery: `reset_checkpoints`

Contract admin (`#[private]`, contract account only):

```
reset_checkpoints(Vec<CheckpointReset { chain, height }>)
```

Settles the canonical empty-backlog digest `reset_checkpoint_digest(chain, height - 1)`. Nodes rebuild `Checkpoint::reset` locally (no peer fetch), `regress()` clears pending + latest, re-anchors cursor so indexing resumes at `height`.

This would have unstuck Solana. It was never invoked. It also **wipes the backlog at that height** (empty pending_requests), so it is the wrong tool for “re-parse unconfirmed pending.”

`vote_checkpoint` rejects behind/conflicting digests. Mixed parses of the same height split vote buckets and never reach threshold.

### Isolation today

Indexers are already **one `tokio::spawn(run_supervised)` per chain** (`cli/mod.rs::spawn_indexers`). Shared `Backlog` is keyed per `Chain` (`EnumMap`). One chain at cap does **not** stall ETH/Canton/Midnight.

What *does* interrupt other chains is shipping a new `mpc-node` binary: parsers are statically linked (`mpc-chain-ethereum`, `mpc-chain-solana`, `mpc-chain-canton`, `mpc-chain-midnight`, in-node `indexer_hydration`). A process restart reloads every chain’s pending set.

Hydration has its own loop (`indexer_hydration/mod.rs`), not `run_supervised`. NEAR has no checkpoint interval.

Catchup does not consume checkpoint slots (`ops.rs`: `if !ctx.caught_up { return }` before `set_processed_block`). Duplicate `Backlog::insert` is idempotent.

---

## 2. Issue 1 — parser generation (the stall fix)

**Primary recovery after a parser fix:** auto-reindex on a per-chain parser generation bump.

### Mechanism

Per-chain `PARSER_GENERATION` constant in the chain crate. On `load_local`, if stored gen ≠ binary gen **for that chain only**:

1. Delete that chain’s pending + pending_digest Redis hashes (**keep `latest`**).
2. Persist the new gen.
3. Resume from confirmed height (`get_processed_block + 1`).
4. Catchup re-parses; checkpoints are not created until `CatchupCompleted`, so the cap cannot refill during replay.
5. Live votes the new digests. Duplicate inserts are idempotent.

Do **not** bump `CHECKPOINT_STORAGE_VERSION` (`v14`) — that is a global namespace wipe.

| Layer | Role |
|---|---|
| Generation bump | Drops *unconfirmed* pending; last confirmed is still canonical |
| `reset_checkpoints(chain, height)` | Nuclear rewind when *confirmed* history is also wrong |

**Must-have API:** `clear_pending(chain)` that does not touch `latest`. Today only `reset_to_latest` clears pending.

Generation is a **local invalidation signal**, not part of the digest. Content-addressed digests already diverge when parses differ.

### Rollout

Bump gen in the **same PR** as the parser fix; roll all nodes. Mixed gen splits `vote_checkpoint` buckets (votes keyed by full digest); the chain stays below threshold until the upgrade completes. Same as today, except upgraded nodes can actually re-parse.

Apply the same gen check in Hydration’s loop.

### Solana runbook after this lands

1. Parser fix + `SOLANA_PARSER_GENERATION += 1`.
2. Roll `mpc-node`.
3. Each node drops Solana pending, catchup from last confirmed Solana checkpoint.
4. If that confirmed checkpoint itself omitted/invented requests: `reset_checkpoints([{chain: Solana, height: first_bad}])`.

### Implementation sketch (issue 1 only)

- Gen constant per chain crate.
- Redis gen key (per account + chain).
- `clear_pending(chain)`.
- `load_local` mismatch path.
- Tests: cap restore vs gen drop; catchup does not refill cap; other chains untouched.
- AGENTS/runbook: parser fixes must bump gen.

---

## 3. Issue 2 — hot-injectable parsers

Goal: fix a **singular chain** without stalling the full node / bouncing other chains.

Runtime isolation is already true (one task per chain). The remaining coupling is **compile-time**: parsers live in the same binary.

### What “parser” actually is

Two layers, only one of which is injectable:

| Layer | Job | Solana stall |
|---|---|---|
| **Host / fetcher** | RPC, JSON codecs, catchup, `ChainIndexer::run` | `#844` `UiTransactionStatusMeta` / `BorshIoError` — **this** |
| **Decoder kernel** | bytes / logs / CPI → `IndexedSignRequest` / `ChainEvent` | `#1070` short CPI — small, pure |

Stable ABI indexer → backlog is already `ChainEvent` over `mpsc`. That is the plugin boundary.

**Kernel purity by chain:**

| Chain | Kernel | Host-coupled |
|---|---|---|
| Ethereum | `parse_filtered_logs(Vec<Log>) -> Vec<IndexedSignRequest>` (~485 LOC `event_parsing.rs`) | alloy RPC, Helios, 2130-line execution watcher |
| Solana | `split_cpi_event` / Anchor `DISCRIMINATOR` + `AnchorDeserialize` (~594 LOC `events.rs`) | `solana-sdk` / `solana-transaction-status` JSON (`JsonParsed` `UiConfirmedBlock`) |
| NEAR | trivial `PendingRequest` passthrough | `near-fetch` view poll |
| Canton | DAML JSON + template suffix + signatory check | WS ledger API, oauth |
| Midnight | Compact/Maybe vectors + transcript decode | `midnight-ledger-v9`, subxt, ~1000 LOC reader |
| Hydration | `subxt` `field_values()` + Merkle `read_proof_check` | in-node, substrate light client |

Canton / Midnight / Hydration kernels are glued to ledger SDKs. They will not fit a guest WASM without a rewrite. ETH/SOL kernels (~100–500 LOC) are the only plausible injectables.

Every parser also applies shared guards before emit: deposit, `key_version`, `Scalar` range, chain-specific `derive_epsilon_*`, entropy from tx-hash / sign-id. KDF (`signet-crypto`) should stay **host-side**.

There is **no plugin runtime today**. `grep wasmtime|wasmer|libloading` hits only near-sdk test-transitive wasmtime. Node has no dynload.

### Recommended hot-inject shape (in-process, per chain)

Keep fetchers compiled into `mpc-node`. Extract `decode(raw) -> Vec<ChainEvent>`.

1. Node embeds `wasmtime`.
2. Supervisor holds `ArcSwap<Decoder>` per chain.
3. Config watch (already every 10s via `update_contract_data` / `read([State, Config, Checkpoints])`) sees a new manifest.
4. Download blob, verify sha256, instantiate, swap decoder **for that chain only**.
5. Bump that chain’s parser generation → drop **unconfirmed** pending, catchup from last confirmed (issue 1). Signing + other indexers stay up.

No process restart. No ETH/Canton bounce when Solana’s decoder changes.

**If the host SDK breaks** (Solana 4.0 JSON), you still ship a binary. WASM does not deserialize `UiConfirmedBlock`.

Sidecar-per-chain is the same idea with a process boundary; heavier; only worth it if we refuse `wasmtime` in the signer process.

### Cheaper middle layer (before WASM)

On-chain **parse tables**: discriminators, log hints, min ix length, event topics, program ids. Hundreds of bytes, governance-updatable, no runtime. Fixes layout knobs (`#1070`-class), not SDK breaks (`#844`).

---

## 4. Should parser code live on the NEAR governance contract?

**Manifest: yes. WASM body: no. Execute parse on NEAR: no.**

### What governance already does

`propose_update(code?, config?)` → storage-deposit-gated → `ProposedUpdates` → `vote_update(id)` at threshold → `update_config` or `deploy_contract+migrate`.

Nodes poll `read([State, Config, Checkpoints])` every 10s, deserialize `Config`, deep-merge local `--override-config` (`MPC_OVERRIDE_CONFIG` wins), fan out via `watch::Sender<Config>::send_if_modified`.

`Config` / `ProtocolConfig` have `#[serde(flatten)] other: HashMap<String, DynamicValue>` (Borsh-as-JSON). A parser manifest can ride `other` with **no contract migration**. Nodes currently only consume `protocol`; new keys are fetched but ignored until node code reads them.

There is no `code_hash` / binary-version field — only human `version(): CARGO_PKG_VERSION` and `latest_key_version()`.

`ProposedUpdates` entries are deleted on execution; no on-chain history of parser blobs.

### Why not store or run parser WASM on-contract

On-chain **execution** is the wrong machine: no Solana RPC, no gas for catchup, no `alloy` / `solana-sdk` / `midnight-ledger` in contract WASM.

On-chain **blob storage** collides with limits already encoded in this repo:

- Tx arg ceiling **~1.5 MB** (`contract/tests/updates.rs`: `1535 * 1024`, 40 Ⓝ deposit).
- Contract WASM itself expected **< ~1 MB** (`CURRENT_CONTRACT_DEPLOY_DEPOSIT = 11_000 mN`; comment: “make sure that it's not larger than 1mb”).
- `propose_update` already parks full contract WASM in `ProposedUpdates` until vote; stacking parser blobs fights that path.

### Storage staking math

NEAR: **1e19 yoctoNEAR / byte = 100 KB per 1 Ⓝ**. Deposit is locked while data lives, refunded on delete. `required_deposit = env::storage_byte_cost() * bytes_used` (`update.rs`). `bytes_used` counts code + JSON(config) + 128 * AccountId + `UpdateEntry` size.

| What | Size | Stake |
|---|---|---|
| Manifest `{chain, gen, sha256, uri}` × 5 | ~1–2 KB | ~0.02 Ⓝ |
| ETH stripped decoder WASM | 200–800 KB | 2–8 Ⓝ |
| SOL stripped (borsh + discriminator only) | 150–500 KB | 1.5–5 Ⓝ |
| SOL + `solana-sdk` | 3–8 MB | **over tx limit** |
| Midnight / Hydration ledger | 5–20 MB | **impossible on-chain** |
| `mpc_contract.wasm` (already) | ~1 MB | ~10 Ⓝ |

Money is fine for a stripped ETH/SOL kernel. The **1.5 MB arg cap** and Midnight/SDK size are not.

**Put blobs in GCS / GitHub releases / IPFS. Put `sha256 + uri + generation` on NEAR.**

If we ever stored a 400 KB SOL decoder on-contract: ~4 Ⓝ permanent on the contract account, plus ~4 Ⓝ again while it sits in `ProposedUpdates`. Still dominated by “can we even submit it.”

### What would have helped Solana

| Bug | On-chain WASM | Host WASM decoder | Gen bump + binary |
|---|---|---|---|
| `#844` RPC `BorshIoError` | no | no | **yes** |
| `#1070` CPI `< 16B` | overkill (a constant) | yes | yes |
| Catchup vs live decode split | no | maybe | yes |
| 32 pending after fix | no | only with gen drop | **yes** (issue 1) |

On-chain WASM does not buy the Solana-class unstick. Issue 1 does.

---

## 5. Bidirectional schemas — do not sign non-tx failures

Separate from indexer stall / hot-inject, but it shares “our codec is wrong vs the caller’s claim is wrong.”

### Flow

```
sign_bidirectional(sender, serialized_transaction, caip2_id,
                   output_deserialization_schema, respond_serialization_schema)
  → SignKind::SignBidirectional
  → admission validate()          // RLP / target_chain / epsilon only — NOT schemas vs dest
  → first MPC signature
  → watch_execution(target_chain)
  → user self-submits signed tx
  → Ethereum ExecutionWatcher::collect
  → ExecutionConfirmed { Success { output } | Failed }
  → process_execution_confirmed
  → second-round SignKind::RespondBidirectional
  → respond_bidirectional
```

Both schemas are opaque `Vec<u8>` on `BidirectionalTx` / `SignBidirectionalEvent`, **caller-supplied**, frozen on the original event. There is **no resupply path** on the same `request_id`. Midnight binds schemas into `request_id`. `dest` / `params` are metadata; the signed body is `serialized_transaction`.

Only Ethereum currently emits `ExecutionConfirmed`. Solana/Canton/Midnight parse bidirectional CPI/events but have no execution watcher.

### Attack

A source contract (or “standard” adapter) attaches `output_deserialization_schema` it believes applies to a class of dests. The user points `serialized_transaction.to` at a contract with a different ABI.

- First MPC signature is still valid (we signed the tx they asked for).
- Target receipt **succeeds**.
- Decode against the claimed schema **fails**.

Today that is `ExtractionFailure::Terminal` → `ExecutionOutcome::Failed` → signed `0xdeadbeef || true` (`MAGIC_ERROR_PREFIX` + Borsh `[0x01]` or ABI `uint256(1)`).

That is a **transaction-failure attestation for a successful tx**. It is not a transaction-level failure. It must not be signed.

The user cannot patch schema on that request. Completing the flow requires a **new** `sign_bidirectional` with a schema that matches the dest actually called.

### Current classification (too coarse)

`ExtractionFailure` is only:

- **Retryable** — node-local RPC / missing `debug_traceTransaction` / transport. Must not fail; peers with a healthy endpoint would extract. Retry next block.
- **Terminal** — “pure function of on-chain data + request schemas, consensus-safe” → sign `Failed`.

Everything deterministic (CREATE, `build_serialized_output` error, schema-decode mismatch, receipt `status == false`, sibling nonce replace) collapses to signed `Failed`.

### Required three-way split

| Class | Example | Do |
|---|---|---|
| **Tx failure** | `receipt.status == false`, sibling nonce replace, nonce consumed / no receipt | Sign `0xdeadbeef` as now |
| **Caller schema mismatch** | Successful receipt; ABI decode fail / empty-vs-output / invalid schema JSON vs actual return | **Quarantine. Do not sign.** |
| **Our serializer** | Successful receipt; schema matches return; our encode/decode bug (unsupported type, borsh shape, codec) | **Retry.** Parser generation bump on the **target** chain re-extracts after upgrade |

CREATE (unsupported) is not a tx failure if the receipt succeeded — treat like schema: quarantine, don’t attest.

### Quarantine

Same idea as `ops.rs` (~136–150): deterministic never-advance → `backlog.remove`. On schema mismatch:

1. Drop the execution watcher.
2. Remove / park the source-chain backlog entry.
3. Do **not** `create_failed_sign_request` / `respond_bidirectional`.
4. Log `schema_mismatch` with `sign_id`, dest, schema hash, decode error.

Source contract never gets a second signature. That is correct: we refuse to lie. If a source contract today *depends* on signed-failure for “I picked the wrong dest,” that contract is wrong; it was consuming a forged revert.

### Our serializer + generation

Keep watching (`Retryable`). Mixed binaries: old nodes must not sign `Failed` while new nodes extract `Success`. Generation bump (issue 1) on the **target** chain drops unconfirmed pending and re-runs extraction so the network meets on Success together.

### Code split sketch

1. `ExecutionOutcome` grows a third variant, **or** `ExtractionFailure` grows `SchemaMismatch` vs `Serializer` vs existing `Terminal` (tx-level) / `Retryable` (RPC).
2. `build_serialized_output` / `from_call_result` classify:
   - `abi_decode` fail, schema-empty vs data, invalid schema JSON → **SchemaMismatch**
   - type parse / borsh “must have one field” / unsupported `DynSolValue` → **Serializer** (retry)
3. `execution_confirmed_event`: receipt fail → `Failed`; schema → do **not** emit `ExecutionConfirmed { Failed }` — unwatch + signal ops to remove.
4. `process_execution_confirmed`: only `Failed` still calls `create_failed_sign_request`.
5. Tests:
   - schema-mismatch must **not** start with `0xdeadbeef`
   - revert still does
   - serializer error emits nothing and retries
   - gen bump then succeeds

Admission can reject **unparseable** schema JSON so garbage never gets a first signature. The redirect attack uses *valid* JSON for the wrong dest — that is not an admission check.

**Not in this change:** dest-ABI verification at first-sign time (possible later: `eth_call` dest with claimed schema before signing — different product). Hot-inject parsers. Putting schemas on NEAR.

---

## 6. Key files

### Checkpoints / stall

- `chain-signatures/node/src/backlog/mod.rs` — `MAX_PENDING_CHECKPOINTS=32`, `set_processed_block_interval`, `checkpoint()`, `regress`
- `chain-signatures/node/src/backlog/checkpoints.rs` — `Checkpoint`, `persist_pending` / `PendingCap`, `load_local` full-set restore, `has_slot`, `confirm` / promote
- `chain-signatures/node/src/backlog/consensus.rs` — `align_backlog_with_consensus`, reset digest rebuild, peer `/checkpoint` fetch
- `chain-signatures/node/src/storage/checkpoint_storage.rs` — Redis keys, Lua persist/promote/reset
- `chain-signatures/node/src/stream/supervisor.rs` — `has_checkpoint_slot` gate, regression abort, watchdog
- `chain-signatures/node/src/stream/ops.rs` — `process_sign_request`, `process_block_event` (caught_up guard), `process_execution_confirmed`
- `chain-signatures/node/src/stream/recovery.rs` — `load_local` then align
- `chain-signatures/node/src/lib.rs` — `CHECKPOINT_STORAGE_VERSION="v14"`
- `chain-signatures/primitives/src/backlog.rs` — `checkpoint_digest`, `reset_checkpoint_digest`
- `chain-signatures/primitives/src/chain.rs` — per-chain `checkpoint_interval` (ETH 20, SOL 120, Hydr 240, Canton 50, Midn 120; NEAR `None`)
- `chain-signatures/contract/src/lib.rs` — `vote_checkpoint`, `reset_checkpoints`
- `chain-signatures/node/src/cli/mod.rs` — `spawn_indexers`

### Chain parsers

- `chain-signatures/chain-integration-core/src/indexer.rs` — `ChainIndexer::run`
- `chain-signatures/chain-ethereum/src/event_parsing.rs`, `indexer.rs`, `execution_watcher.rs`, `respond_bidirectional.rs`
- `chain-signatures/chain-solana/src/events.rs`, `indexer.rs`, `client.rs`
- `chain-signatures/chain-canton/src/events.rs`, `daml.rs`, `signing.rs`
- `chain-signatures/chain-midnight/src/convert.rs`, `reader.rs`, `emissions.rs`
- `chain-signatures/node/src/indexer_hydration/mod.rs`

### Governance / config

- `chain-signatures/contract/src/update.rs` — `propose_update`, `bytes_used`, `required_deposit`
- `chain-signatures/contract/src/config/mod.rs` — `Config.other` flatten bag
- `chain-signatures/contract/tests/updates.rs` — 1.5 MB tx-arg ceiling, 11 Ⓝ deploy deposit
- `chain-signatures/node/src/rpc/mod.rs` — 10s `update_contract_data`
- `chain-signatures/node/src/config.rs` — `ContractConfig`, local override merge

### Bidirectional

- `chain-signatures/primitives/src/bidirectional.rs` — frozen schemas on the event
- `chain-signatures/primitives/src/events.rs` — `ExecutionOutcome::{Success, Failed}` (too coarse)
- `chain-signatures/node/src/respond_bidirectional.rs` — `MAGIC_ERROR_PREFIX`, `create_failed_sign_request`
- `chain-signatures/node/src/sign_bidirectional.rs` — `validate()` (no schema-vs-dest)
- `chain-signatures/contract-sol/src/lib.rs` — `sign_bidirectional` emits schemas verbatim

---

## 7. Recommended order of work

1. **Issue 1 — parser generation + `clear_pending`.** Unsticks Solana-class stalls without wiping confirmed history. Independent of WASM. Ship gen bump in the same PR as any parser fix.
2. **Bidirectional schema split.** Signing-correctness: do not attest `0xdeadbeef` for a successful tx whose caller schema does not match dest ABI. Quarantine. Retry our serializer bugs; couple retry-to-success to target-chain generation bump.
3. **Parse tables on NEAR `Config.other` (optional, cheap).** Discriminators / log hints / min lengths. Fixes layout knobs without a runtime.
4. **Hot-inject WASM decoders for ETH/SOL kernels (later).** Manifest on NEAR (`{chain, gen, sha256, uri}`), blob off-chain, in-process `wasmtime` + `ArcSwap` per chain, then generation bump. Does **not** replace host SDK / RPC fetchers. Does **not** help Midnight/Hydration without a rewrite. Does **not** put executable parser code in contract state.

Do not: store parser WASM on the contract, execute parse on NEAR, bump `CHECKPOINT_STORAGE_VERSION` for a single-chain fix, or expect a decoder plugin to unstick `#844`-class host deserialization bugs.
