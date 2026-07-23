# Task 6: `/block` decode seam — report

Status: **DONE_WITH_CONCERNS**

## What was built

A `GET /block?hash=<0xhash>` seam for the `midnight-publisher` sidecar that decodes a finalized block into notify inserts plus cross-contract-call provenance, mirroring how `/state` decodes contract STATE.

- `src/block.rs` (new):
  - `BlockNotify { address, insert_key, insert_value, claimed_contract_calls }` and `BlockResponse { calls }`, both `serde::Serialize`. `insert_key` / `insert_value` are field-aligned hex atoms produced by the reused `state.rs` helpers, so `/block` and `/state` share one atom schema.
  - `decode_block(&[RawTransaction])` → per Midnight tx: `decode_transaction` (tagged-deserialize the rc.4 `Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>`) → `Transaction::calls()` → per `ContractCall`, walk the guaranteed and fallible transcripts.
  - `scan_map_inserts`: the findings' state-independent symbolic stack replay. Covers ALL 28 rc.4 opcodes with pop/push arities taken verbatim from the authoritative `stack_req` table plus each opcode's push count in `onchain-vm/src/vm.rs` (a2c3c5d, tag `onchain-vm-4.0.0-rc.2`). A slot is `Concrete` only if it traces to an `Op::Push` (directly or via `Dup`/`Swap`); at each `Op::Ins` the value and first-popped key are the semantic leaf write, recorded iff both are concrete. Forward `Jmp` is honored; `Branch` pops its condition and falls through.
  - Step 3 provenance: `communication_commitment` (callee side, `Fr::as_le_bytes`) plus the transcript's `claimed_contract_calls` effects set (caller side), serialized to the `claimed_contract_calls` field.
- `src/service.rs`: `handle_block` (validates `0x` + 64 lowercase hex → 400; decode/fetch error → 502) and `fetch_block_response` (Step 1). Step 1 drives the toolkit fetcher lib in-process on a throwaway tokio runtime: `MidnightNodeClient::new(node_url)` → `fetcher::fetch_single_block(...)` → unwrap `RawTransaction::Midnight(bytes)`. Wired the `("GET", "/block")` route.
- `src/state.rs`: `walk` and `value_atoms` loosened to `pub(crate)`.
- `src/main.rs`: `mod block;`.
- `Cargo.toml`: added `subxt` and `tokio` (default-features = false; both already in the lockfile transitively via `midnight-node-toolkit`, so the lock gained only the two dependency edges — no new crates/versions).
- `tests/fixtures/serialized_tx.mn`: copied from the rc.4 checkout.

## Test summary

`cargo test --locked`: **21 passed, 0 failed, 1 ignored** (the ignored test is the pending live-SGN2 notify fixture). `cargo build --locked` and `cargo clippy --locked --tests` both clean (no warnings). Mutation-checked: breaking the "record only the leaf" invariant makes `scanner_records_only_leaf_of_multi_level_ins` fail as expected.

New tests: 7 synthetic-program scanner tests (flat insert, multi-level `Ins` splice records only the leaf, opaque value skipped, `Dup`/`Swap` tracking, forward `Jmp` skip, `Branch` fall-through), the rc.4 fixture decode/extract test, and a `handle_block` hash-validation test.

## Concerns

1. **Scanner SGN2 correctness is NOT verified against a real notify transcript.** The 7 synthetic tests verify the mechanics (per-opcode arities, concrete-vs-opaque tracking, leaf detection, `Jmp`/`Branch` control flow), but not which `Ins` in a REAL compiled SGN2 notify circuit is the semantic insert, nor the exact nesting depth the Compact compiler emits for the top-level `signBiRequests` map. That needs a live capture. The `notify_fixture_yields_expected_insert` test is written and `#[ignore]`d pending `tests/fixtures/notify-tx.mn`; I did NOT invent that fixture.

2. **The rc.4 fixture has ZERO contract calls** (confirmed: `reference tx fixture: 0 contract call(s), 0 notify insert(s)`). It predates SGN2, so it exercises tagged-deserialize + `Transaction::calls()` and yields a well-formed empty `BlockResponse` without panic, but it does NOT exercise the scanner or Step-3 decode on real call data. Those paths are covered only by the synthetic tests.

3. **rc.4 API deviations from the findings (all resolved):**
   - The findings' `fetch_single_block` body references `FetchTask::fetch_block` / `ComputeTask::extract_data`, but both are `pub(crate)` and uncallable. Only `fetch_single_block` (and `fetch_all`, `FetchTask::fetch`) are public. I used `fetch_single_block` (which the findings recommended as the entry point anyway). Its `chain_id` and `block_number` args are only cache keys for the `InMemory` store; since I pass a fresh per-request store, the block is fetched purely by hash, so I pass `H256::zero()` / `0` for them (documented in code).
   - `subxt::utils::H256` (the block-hash type `fetch_single_block` takes) is NOT re-exported by the toolkit or ledger-helpers, so `subxt` had to become a direct dep to name it. `tokio` had to become a direct dep to drive the async fetch from the sync tiny_http handler. Verified via `cargo tree` that `rt-multi-thread`/`rt`/`net`/`time` are already enabled in the graph, so `default-features = false` keeps `--locked` green.
   - `Effects` is re-exported at the ledger-helpers crate root under the alias `ContractEffects` (not `Effects`).
   - `Transaction::calls()` exists directly (yields `(u16, ContractCall<P, D>)`), so I used it instead of `StandardTransaction::actions()` + `ContractAction::Call` matching — same result, less boilerplate.

4. **`claimed_contract_calls: Option<String>` interpretation.** The mandated struct has one field for two Step-3 facts (callee `communication_commitment` and the caller-side `claimed_contract_calls` set). I encode both as a JSON blob `{"communication_commitment":"<hex>","claimed":[{position,address,entry_point,commitment},...]}` (claimed entries sorted for determinism). Because a decoded call always has a commitment, the field is always `Some` in practice; the `Option` is retained per the response contract. If the consumer wants the two facts as separate fields, the struct needs a second field.

5. **`Branch` is not statically resolvable.** The scanner pops its condition and takes the fall-through path; compiled circuits keep both arms stack-balanced, so stack depth stays consistent at the merge point regardless of the branch taken. A branch-heavy transcript whose real notify `Ins` sits only in the skipped arm would be missed — another reason the live-fixture validation (concern 1) matters.
