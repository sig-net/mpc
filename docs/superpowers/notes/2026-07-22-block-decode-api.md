# Block decode API research (node-2.0.0-rc.4)

Research only. No `/block` implementation was written. Goal: pin the exact `midnight-node-ledger-helpers` / `midnight-node-toolkit` / `midnight-ledger` API (tag `node-2.0.0-rc.4`) needed for a future `/block` seam that decodes a finalized block's `chain_getBlock(hash)` body down to Map-insert atoms and cross-contract-call commitments, mirroring how `chain-signatures/midnight-publisher/src/state.rs` already decodes contract STATE.

## Pinned sources used

All three findings below were verified by reading the actual checked-out source at the exact commit `midnight-publisher/Cargo.lock` pins for tag `node-2.0.0-rc.4`, not from memory or docs.

- `midnight-node-toolkit` / `midnight-node-ledger-helpers`: `~/.cargo/git/checkouts/midnight-node-a5e2d7071ca76673/651e043/` (commit `651e043b61ed445bf7a5066c60c87ea7bd606073`, the only one of the two fetched revs that matches `Cargo.lock`; the other rev dir, `30f081e`, is stale).
- `midnight-ledger-v9` crate (`mn_ledger`): `~/.cargo/git/checkouts/midnight-ledger-b2f9c59d942dfdca/85e769a/ledger/` (commit `85e769a0e352518c979cb6f7a07901b63e1c124d`, tag `crate-ledger-9.1.0.0-rc.3`).
- `midnight-onchain-runtime` crate: `.../37337e7/onchain-runtime/` (tag `onchain-runtime-4.0.0-rc.2`).
- `midnight-onchain-vm` crate (the actual home of `Op`/`ops.rs`/`vm.rs`): `.../a2c3c5d/onchain-vm/` (tag `onchain-vm-4.0.0-rc.2`).
- `midnight-onchain-state` crate (the actual home of `StateValue`): `.../a2a4aa5/onchain-state/` (tag `onchain-state-4.0.0-rc.3`).
- `midnight-transient-crypto` (for `Fr`): `.../29f5c5d/transient-crypto/` (tag `transient-crypto-3.0.0-rc.2`, the one `ledger_9` actually uses; there is also a stale `transient-crypto-2.2.0-rc.1` checkout used only by pre-ledger-9 code paths).

Twelve rev subdirectories exist under the `midnight-ledger` checkout because each `[patch.crates-io]` line in `midnight-publisher/Cargo.toml` pins a different git tag (hence a different commit) of the same repo; I resolved each crate to its correct rev by grepping `midnight-publisher/Cargo.lock` for that crate's `source = "git+...#<sha>"` line and matching the short SHA to the checkout directory name.

None of the three requested capabilities is absent from the rc.4 crates. All the types and fields exist and are public. The real news is in two gaps: no ready-made function extracts Map-insert key/value atoms from a transcript program (you write a small, fully-specified static scanner, detailed below), and the `chain_getBlock` to ledger-`Transaction`-bytes unwrap needs `subxt` plus generated chain metadata, which the toolkit's own CLI (`show-block`/`show-transaction`) does not expose as structured JSON (only a Rust `Debug` string). Both are documented in detail under "Gaps" at the end.

## Step 1: chain_getBlock body -> extrinsics -> ledger Transaction bytes

This is **not** a pure-bytes operation. The Substrate block body returned by `chain_getBlock` is a list of hex-encoded SCALE extrinsics, and isolating the `midnight_tx: Vec<u8>` argument of the `Midnight::send_mn_transaction` call requires metadata-aware SCALE decoding, i.e. `subxt`, not manual byte slicing (call indices and the argument layout are not stable across runtime versions, which is exactly why the toolkit dispatches by `RuntimeVersion`).

The toolkit already implements this end to end:

- `midnight_node_ledger_helpers::fork::raw_block_data::{RawBlockData, RawTransaction, LedgerVersion}` (`ledger/helpers/src/fork/raw_block_data.rs`): the version-agnostic output shape.
  - `RawTransaction::Midnight(Vec<u8>)`: "Raw bytes from `send_mn_transaction` extrinsic" (already unwrapped, ready for ledger deserialize).
  - `RawBlockData { hash, parent_hash, number, ledger_version, transactions: Vec<RawTransaction>, tblock_secs, state_root, .. }`.
- `midnight_node_toolkit::fetcher::compute_task::ComputeTask::process_block_with_protocol::<M: MidnightMetadata>` (`util/toolkit/src/fetcher/compute_task.rs:179-250`) does the actual unwrap:
  ```rust
  let extrinsics = block.block.extrinsics().from_bytes(block.raw_body.clone()).await; // subxt
  for ext in extrinsics.iter().filter_map(Result::ok) {
      let Ok(call) = ext.decode_call_data_as::<M::Call>() else { continue };
      if let Some(bytes) = M::send_mn_transaction(&call) {
          transactions.push(RawTransaction::Midnight(bytes));
      }
      ...
  }
  ```
- `M::send_mn_transaction` (`util/toolkit/src/fetcher/runtimes.rs:71-159`) is generated per runtime spec version via a macro over `subxt`-generated metadata modules (`midnight_node_metadata::midnight_metadata_2_0_0`, etc.). For rc.4 (spec `2_000_000`), the relevant impl is `MidnightMetadata2_0_0`, and the match arm is literally:
  ```rust
  if let mn_meta_2_0_0::Call::Midnight(mn_meta_2_0_0::midnight::Call::send_mn_transaction { midnight_tx }) = call {
      Some(midnight_tx.clone())
  }
  ```
  That `midnight_tx: Vec<u8>` is exactly the ledger-tagged-serialized `Transaction` bytes step 2 below consumes. A comment at `runtimes.rs:151-154` confirms the rc.4 extrinsic envelope (`send_mn_transaction` / `send_mn_system_transaction` / `timestamp.set`) is unchanged from the 1.0.0 metadata, only the inner ledger tx bytes differ.
- The whole RPC round trip (`chain_getBlockHash` then block body fetch via `subxt`'s blocks client, which issues `chain_getBlock` under the hood) is wrapped by `midnight_node_toolkit::fetcher::fetch_single_block` (`util/toolkit/src/fetcher.rs:75-90`):
  ```rust
  pub async fn fetch_single_block(
      chain_id: H256,
      block_number: u64,
      block_hash: H256,
      client: Option<&MidnightNodeClient>,
      storage: &(impl FetchStorage + Clone + 'static),
  ) -> Result<RawBlockData, FetchError>
  ```
  `util/toolkit/src/commands/show_block.rs:213-241` shows the full call pattern: resolve `block_number` to a hash via `FetchTask::fetch_block_hashes`, then call `fetch_single_block` with a `fetch_storage::InMemory::default()` (or `RedbBackend`/`PostgresBackend`) cache.

### Implementation-choice flag (not resolved here, needs a decision)

`midnight-node-toolkit` has an implicit lib target (`util/toolkit/src/lib.rs` declares `pub mod fetcher; pub mod commands; ...`, and the crate has no `[lib]` override in its `Cargo.toml`, only an explicit `[[bin]]`), so `fetcher::fetch_single_block` is reachable as a normal Rust function, not only via the CLI. But `midnight-publisher`'s current architecture (`chain-signatures/midnight-publisher/src/main.rs:1-5`, `service.rs:1-4`) explicitly shells out to the compiled toolkit binary as a subprocess for everything that needs the toolkit ("Quarantines the `midnight-node-toolkit` dependency universe from the main mpc workspace... this service drives the toolkit CLI as subprocesses"), and only links `midnight-node-ledger-helpers` directly as a library (see `state.rs`). Two real options for `/block`, with no upstream toolkit change needed for the first:

1. **Link `midnight-node-toolkit`'s lib target directly** and call `fetcher::fetch_single_block` (or the lower-level `FetchTask`/`ComputeTask` pieces) in-process to get a `RawBlockData`, then do the ledger-level decode (steps 2 and 3 below) yourself. This pulls `subxt` and the generated `midnight_node_metadata` crate into `midnight-publisher`'s build, which is fine: this nested workspace exists precisely to quarantine that dependency weight from the main mpc workspace, it is not currently avoiding it inside its own crate.
2. **Shell out to `toolkit show-block --block-number N --json`** (or `show-transaction`), matching the existing subprocess pattern. This is insufficient as-is: `ShowBlockJson.transactions: Vec<ShowBlockTransaction>` (`util/toolkit/src/commands/show_block.rs:81-89`) carries only `tx_type`, `size_bytes`, `hash`, and `debug_str: String`, a `format!("{tx:#?}")` Rust `Debug` dump of the whole deserialized `Transaction`, not structured JSON. There is no existing toolkit flag that serializes `Transaction`/`ContractCall`/`Transcript`/`Op` to JSON (I checked `util/toolkit/src/serde_def/{mod,transactions,ledger_types}.rs`: that module is serde plumbing for `SourceTransactions`/tx-batch loading used by the tx generator, unrelated to this). Option 2 only becomes viable for programmatic atom extraction if a new toolkit command/flag is added upstream, which is out of scope for a sidecar-only change.

Recommendation: option 1. It reuses the exact, already-tested unwrap logic instead of re-deriving SCALE/metadata decoding by hand, and the dependency cost is already accepted by this crate's existence.

## Step 2: ledger Transaction -> contract calls -> guaranteed/fallible transcripts -> Map insert atoms

### Types (all confirmed at the pinned revs above)

- `midnight_node_ledger_helpers::Transaction<S, P, B, D>` (curated re-export; real path `mn_ledger::structure::Transaction`, `ledger/src/structure.rs:1387`):
  ```rust
  pub enum Transaction<S: SignatureKind<D>, P: ProofKind<D>, B: Storable<D>, D: DB> {
      Standard(StandardTransaction<S, P, B, D>),
      ClaimRewards(ClaimRewardsTransaction<S, D>),
  }
  ```
- `StandardTransaction` (`structure.rs:1665-1690`):
  ```rust
  pub struct StandardTransaction<S, P, B, D> {
      pub network_id: String,
      pub intents: HashMap<Segment, Intent<S, P, B, D>, D>,  // Segment = u16
      pub guaranteed_coins: Option<Sp<ZswapOffer<P::LatestProof, D>, D>>,
      pub fallible_coins: HashMap<Segment, ZswapOffer<P::LatestProof, D>, D>,
      ...
  }
  impl StandardTransaction<..> {
      pub fn actions(&self) -> impl Iterator<Item = (Segment, ContractAction<P, D>)>; // ready-made
  }
  ```
  `GUARANTEED_SEGMENT: Segment = 0` (`structure.rs:1663`); any other segment id is a fallible intent segment. This is a coarser guaranteed/fallible axis than the per-call transcript split below; both exist independently.
- `ContractAction<P, D>` (curated re-export, `structure.rs:3029`):
  ```rust
  pub enum ContractAction<P, D> {
      Call(Sp<ContractCall<P, D>, D>),
      Deploy(Sp<ContractDeploy<D>, D>),
      Maintain(MaintenanceUpdate<D>),
  }
  ```
- `ContractCall<P, D>` (**not** curated-re-exported by short name at the ledger-helpers crate root; reach it via the raw re-exported crate alias `midnight_node_ledger_helpers::mn_ledger::structure::ContractCall`, `structure.rs:2644-2658`):
  ```rust
  pub struct ContractCall<P: ProofKind<D>, D: DB> {
      pub address: ContractAddress,
      pub entry_point: EntryPointBuf,
      pub guaranteed_transcript: Option<Sp<Transcript<D>, D>>,
      pub fallible_transcript: Option<Sp<Transcript<D>, D>>,
      pub communication_commitment: Fr,
      pub proof: P::Proof,
  }
  ```
  This is the "contract-call segments (guaranteed/fallible)" the call has up to two independent `Transcript`s, one per segment, each with its own ops and its own effects. `ContractCall` also carries ready-made cross-call helpers, see step 3.
- `Transcript<D>` (curated re-export, `onchain-runtime/src/transcript.rs:44-49`):
  ```rust
  pub struct Transcript<D: DB> {
      pub gas: RunningCost,
      pub effects: Effects<D>,
      pub program: storage::storage::Array<Op<ResultModeVerify, D>, D>,
      pub version: Option<Sp<TranscriptVersion, D>>,
  }
  ```
- `Op<M, D>` (curated re-export as `Op`; real home is `midnight-onchain-vm`'s `ops.rs`, re-exported by onchain-runtime as `pub use onchain_vm::ops;`, `onchain-runtime/src/lib.rs:35`). Full variant list, `onchain-vm/src/ops.rs:156-260`: `Noop, Lt, Eq, Type, Size, New, And, Or, Neg, Log, Root, Pop, Popeq{result}, Addi, Subi, Push{storage,value: StateValue<D>}, Branch, Jmp, Add, Sub, Concat, Member, Rem, Dup, Swap, Idx{cached,push_path,path: Array<Key,D>}, Ins{cached,n:u8}, Ckpt`.

### There is no `Op::Insert{key,value}` variant, and no helper function anywhere in ledger-helpers/toolkit/mn_ledger that extracts Map inserts from a transcript

`Op::Ins { cached, n }` is a low-level stack-machine instruction, not a semantic record. I traced its exact interpreter semantics in `onchain-vm/src/vm.rs:933-1053` (`run_program_internal`, the `Ins` match arm):

```rust
Ins { cached, n } => {
    let mut curr = stack.pop().unwrap();       // value being inserted (pushed last)
    for _ in 0..*n {
        let key = stack.pop().unwrap().0;      // map/array/bmt key
        let container = stack.pop().unwrap();  // the container (Map/Array/BoundedMerkleTree)
        // ... container.insert(key, curr) -> becomes the new `curr` for the next iteration
    }
    stack.push(curr);
}
```

So for a single flat `Map::insert(key, value)` (`n = 1`), the stack immediately before `Ins` executes is, top to bottom: `value`, `key`, `container`. `n > 1` is used to splice a written leaf back up through `n` levels of nested containers in one instruction (each extra iteration pops another (key, container) breadcrumb pair); those breadcrumbs are what `Op::Idx { push_path: true, .. }` leaves on the stack while descending (`vm.rs:915-918`: for each path step, if `push_path`, push `(curr.clone(), key.clone())` before descending further). I did not find or derive a definitive worked example of the *exact* number of `Ins` ops and nesting depth a compiled Compact circuit emits for a flat top-level `Map` field (the SGN2 shape, per the reference-state fixture in `state.rs`'s tests, is a top-level ordinal `Map`, so nesting is likely shallow, `n = 1` splicing directly into the state root array), so treat that specific shape as unverified until checked against a real rc.4 transcript.

Crucially, `Op::Push { storage, value: StateValue<D> }` always carries a **literal, concrete** `StateValue<D>` (`onchain-vm/src/vm.rs:656-676`), not something generic over the result mode. This holds even in the on-chain-stored `ResultModeVerify` transcript: whatever a circuit pushes (including dynamic, argument-derived values like the SGN2 `SignetMapKey`/`SignBidirectionalEventNotification` structs) is baked into the transcript as a plain public `StateValue` at proving time, so it is readable directly off the decoded transcript bytes with zero chain-state access. Likewise every opcode's stack in/out arity is fixed and data-independent (`vm.rs:388-414`'s `stack_req` match is the authoritative table, e.g. `Idx` pops `(#Key::Stack in path) + 1` and pushes 1, `Ins{n}` pops `2n+1` and pushes 1). That means the provenance of the two stack slots `Ins` consumes as key/value can be recovered by a **pure, state-independent, symbolic stack replay** of the `program` array: track each stack slot as either `Concrete(StateValue)` (traced back to a `Push`, optionally through `Concat`/`Addi`/`Subi`/`New`) or `Opaque` (came from `Idx`/`Root`/`Popeq`, which need real chain state to resolve and which you don't need for this purpose), using the fixed arities to keep stack depth correct, and whenever you hit `Ins`, read off whatever is `Concrete` in the value slot and the first popped key slot.

This scanner does not exist anywhere in the crates searched. It must be hand-written (roughly 40-60 lines) next to `state.rs`. Sketch (illustrative, not compiled or tested):

```rust
use midnight_node_ledger_helpers::{DefaultDB, Key, Op, StateValue};
use midnight_node_ledger_helpers::onchain_runtime::result_mode::ResultModeVerify;

#[derive(Clone)]
enum Sym {
    Concrete(StateValue<DefaultDB>), // traced back to a literal Push
    Opaque,                          // depends on real chain state (Idx/Root/Popeq/...)
}

pub struct MapInsert {
    pub key: StateValue<DefaultDB>,
    pub value: StateValue<DefaultDB>,
}

/// Sketch only: fill in the remaining opcodes' arities from vm.rs:388-414 before use,
/// and confirm against a real rc.4 transcript which `Ins` in the sequence is the
/// semantic SGN2 insert vs. a splice-continuation (see caveat above).
pub fn scan_map_inserts(program: &[Op<ResultModeVerify, DefaultDB>]) -> Vec<MapInsert> {
    let mut stack: Vec<Sym> = Vec::new();
    let mut found = Vec::new();
    for op in program {
        match op {
            Op::Push { value, .. } => stack.push(Sym::Concrete(value.clone())),
            Op::Idx { path, .. } => {
                let n_stack_keys = path.iter().filter(|k| matches!(k, Key::Stack)).count();
                for _ in 0..n_stack_keys { stack.pop(); }
                stack.pop(); // base container
                stack.push(Sym::Opaque);
            }
            Op::Ins { n, .. } => {
                let value = stack.pop().expect("Ins: missing value");
                for i in 0..*n {
                    let key = stack.pop().expect("Ins: missing key");
                    let _container = stack.pop().expect("Ins: missing container");
                    if i == 0 {
                        if let (Sym::Concrete(k), Sym::Concrete(v)) = (&key, &value) {
                            found.push(MapInsert { key: k.clone(), value: v.clone() });
                        }
                    }
                }
                stack.push(Sym::Opaque);
            }
            // Pop/Popeq/Branch/Log/... : apply the fixed arity from vm.rs:388-414,
            // push Opaque for anything that produces a result.
            _ => { /* TODO: remaining opcodes, see vm.rs:388-414 for exact arities */ }
        }
    }
    found
}
```

### Turning a recovered key/value StateValue into atoms: reuse `state.rs`, do not write a second decoder

`Op::Push`'s `StateValue<D>` and `state.rs`'s `StateValue<DefaultDB>` are the exact same type (`StateValue::Cell` wraps `Sp<AlignedValue, D>`, confirmed at `onchain-state/src/state.rs:78-97`, same crate `midnight_node_ledger_helpers` re-exports as `StateValue`/`AlignedValue`). `state.rs`'s `walk(&StateValue<DefaultDB>) -> anyhow::Result<Node>` and `value_atoms(&AlignedValue) -> Vec<String>` (`state.rs:46-82`) apply unchanged to a `MapInsert.key`/`.value`:

```rust
// state.rs currently has `walk` and `value_atoms` as private fns; loosen to `pub(crate)`.
let key_node = crate::state::walk(&map_insert.key)?;     // {"kind":"cell","atoms":[...]}
let value_node = crate::state::walk(&map_insert.value)?; // matches the pinned /state schema
```

For the SGN2 shape specifically (`SignetMapKey { count: u64, requestId: [u8;32] }`, `SignBidirectionalEventNotification { version: u8, payload: [u8;128] }`), expect both to decode as `Node::Cell { atoms }` with 2 atoms each, exactly like the task description states, assuming the Compact compiler flattens each struct's scalar fields into one `AlignedValue` (multiple field-aligned atoms in one `Cell`), matching the pattern `state.rs`'s own tests already exercise for the reference contract's fields.

## Step 3: the caller-frame `claimedContractCalls` commitment

Two related, both real and directly usable, pieces:

1. **Per-call field, callee side.** `ContractCall.communication_commitment: Fr` (`structure.rs:2655`) is a plain field on every `ContractCall`, the value a caller's claim must match. `Fr` (`transient-crypto/src/curve.rs:158`, `pub struct Fr(pub outer::Scalar)`) has a public `as_le_bytes(&self) -> Vec<u8>` (`curve.rs:373-375`), so `hex::encode(call.communication_commitment.as_le_bytes())` gives a stable hex string.

2. **The named `claimedContractCalls` set, caller side.** Lives on `Transcript.effects`, not on `ContractCall` directly. `Effects<D>` (`onchain-runtime/src/context.rs:640-655`):
   ```rust
   pub struct Effects<D: DB> {
       pub claimed_nullifiers: HashSet<Nullifier, D>,
       pub claimed_shielded_receives: HashSet<CoinCommitment, D>,
       pub claimed_shielded_spends: HashSet<CoinCommitment, D>,
       pub claimed_contract_calls: HashSet<ClaimedContractCallsValue, D>,
       pub shielded_mints: HashMap<HashOutput, u64, D>,
       pub unshielded_mints: HashMap<HashOutput, u64, D>,
       pub unshielded_inputs: HashMap<TokenType, u128, D>,
       pub unshielded_outputs: HashMap<TokenType, u128, D>,
       pub claimed_unshielded_spends: HashMap<ClaimedUnshieldedSpendsKey, u128, D>,
   }
   ```
   `ClaimedContractCallsValue` (`context.rs:578`, **not** curated-re-exported at the ledger-helpers crate root either, reach it via `midnight_node_ledger_helpers::onchain_runtime::context::ClaimedContractCallsValue`):
   ```rust
   pub struct ClaimedContractCallsValue(pub u64, pub ContractAddress, pub HashOutput, pub Fr);
   // fields: (position in transcript, callee address, callee entry-point hash, callee communication_commitment)
   ```
   So the caller's own `guaranteed_transcript`/`fallible_transcript` each carry a `HashSet` of these tuples, one per contract call the caller makes from that segment; matching a tuple's `(1, 2, 3)` fields against a callee `ContractCall`'s `(address, entry_point.ep_hash(), communication_commitment)` establishes the binding. `EntryPointBuf::ep_hash(&self) -> HashOutput` (`onchain-state/src/state.rs:669-674`) does `persistent_commit(&self[..], "midnight:entry-point"-domain-tag)`.

   **This exact matching logic is already implemented and reusable**, no need to hand-roll the intersection: `ContractCall::calls_with_seq` (`structure.rs:2724-2747`, a public inherent method on `ContractCall<P, D>`):
   ```rust
   impl<P: ProofKind<D>, D: DB> ContractCall<P, D> {
       pub fn calls(&self, callee: &ContractCall<P, D>) -> bool;
       pub fn calls_with_seq(&self, callee: &ContractCall<P, D>) -> Option<(bool /* guaranteed */, u64 /* position */)>;
   }
   ```
   `caller_call.calls_with_seq(&callee_call)` scans both of `caller_call`'s transcripts' `claimed_contract_calls` for an entry matching `callee_call`'s `(address, entry_point.ep_hash(), communication_commitment)`, and returns which segment (guaranteed/fallible) and transcript position it was claimed at. Use this directly instead of reimplementing the intersection.

## End-to-end snippet (step 1 output onward; step 1 itself needs subxt, see above)

```rust
use midnight_node_ledger_helpers::{
    deserialize, ContractAction, DefaultDB, ProofMarker, PureGeneratorPedersen, Signature,
    Transaction,
};
use midnight_node_ledger_helpers::mn_ledger::structure::ContractCall;
use midnight_node_ledger_helpers::onchain_runtime::context::ClaimedContractCallsValue;

type Tx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>;

/// `tx_bytes` = the `midnight_tx` argument already unwrapped from the
/// `Midnight::send_mn_transaction` extrinsic (step 1). Same call `midnight-node-toolkit`'s
/// own `common/show_transaction.rs:29` makes on `RawTransaction::Midnight(tx_bytes)`.
fn decode_transaction(tx_bytes: &[u8]) -> anyhow::Result<Tx> {
    Ok(deserialize(tx_bytes)?) // midnight_serialize::tagged_deserialize, checks the wire tag
}

fn contract_calls(tx: &Tx) -> Vec<(u16 /* intent segment id */, ContractCall<ProofMarker, DefaultDB>)> {
    let Transaction::Standard(std_tx) = tx else { return vec![] };
    std_tx
        .actions() // ready-made: StandardTransaction::actions()
        .filter_map(|(segment_id, action)| match action {
            ContractAction::Call(sp_call) => Some((segment_id, (*sp_call).clone())),
            _ => None,
        })
        .collect()
}

fn decode_one_call(call: &ContractCall<ProofMarker, DefaultDB>) {
    for (guaranteed, transcript) in [
        (true, call.guaranteed_transcript.as_ref()),
        (false, call.fallible_transcript.as_ref()),
    ] {
        let Some(transcript) = transcript else { continue };

        // Step 2: Map insert atoms (needs the hand-written scanner from Step 2 above).
        for insert in scan_map_inserts(&transcript.program) {
            let _key_node = crate::state::walk(&insert.key);     // reuse state.rs
            let _value_node = crate::state::walk(&insert.value); // reuse state.rs
        }

        // Step 3: claimedContractCalls the caller made from this segment.
        for claim in transcript.effects.claimed_contract_calls.iter() {
            let ClaimedContractCallsValue(position, callee_addr, callee_ep_hash, callee_commitment) =
                (*claim).clone();
            let _ = (guaranteed, position, callee_addr, callee_ep_hash, callee_commitment);
        }
    }

    // Step 3, callee side: direct field, no scanning.
    let _commitment_hex = hex::encode(call.communication_commitment.as_le_bytes());
}
```

## Testing without a live node

`res/test-tx-deserialize/serialized_tx.mn` and `res/test-tx-deserialize/serialized_tx_no_context.mn` exist in the node-2.0.0-rc.4 checkout (repo root, i.e. `~/.cargo/git/checkouts/midnight-node-a5e2d7071ca76673/651e043/res/test-tx-deserialize/`). They are `SerializedTx` JSON blobs (`ledger/helpers/src/fork/raw_block_data.rs:161-170`: `{ tx: RawTransaction, context: BlockContext, tx_hash }`) containing a real, already-unwrapped ledger `Transaction`'s bytes, and are exactly what `util/toolkit/src/commands/show_transaction.rs`'s own test (`test_show_transaction_funcs`) and `show_block.rs`'s own test (`test_show_block_from_file`) load. Good starting fixtures for unit-testing the Step 2/3 decode without needing `subxt` or a running node at all, though they likely predate SGN2 contracts being deployed, so they probably will not contain a real Map-insert transcript to exercise the scanner end to end.

## Summary of gaps (flagged, not invented around)

1. **Extrinsic unwrap needs `subxt` + generated chain metadata, and the toolkit CLI doesn't expose structured JSON for it.** Not a hard blocker (the toolkit's lib target reaches it fine, see "Implementation-choice flag" above), but it is a real scope/dependency decision the `/block` implementer must make explicitly, since it changes `midnight-publisher`'s dependency footprint beyond what `state.rs` needed.
2. **No existing function extracts Map-insert key/value atoms from a `Transcript.program`.** `Op::Ins` is a low-level stack opcode, not a semantic record. The extraction algorithm is fully specified above (state-independent symbolic stack replay) and is believed correct against the VM's actual interpreter semantics (`vm.rs:933-1053`), but the sketch is unverified against a real SGN2 transcript, in particular how many `Ins` ops and what nesting appear for a flat top-level `Map` insert. Recommend decoding one real rc.4 sandbox notify-call transcript by hand before finalizing the scanner.
3. **`ContractCall` and `ClaimedContractCallsValue` are not curated-re-exported by short name** at the `midnight_node_ledger_helpers` crate root (unlike `Transaction`, `ContractAction`, `Transcript`, `Op`, `StateValue`, all of which are). Both are still fully public, just reachable one level deeper through the raw re-exported crate aliases (`mn_ledger::structure::ContractCall`, `onchain_runtime::context::ClaimedContractCallsValue`), which the `latest`/`ledger_9` facade also re-exports. Minor, but easy to trip over.
