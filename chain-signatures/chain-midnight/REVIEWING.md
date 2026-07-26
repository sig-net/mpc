# Reviewing the Midnight indexer

A guide to reviewing `chain-signatures/chain-midnight` and its wiring. It is written for someone who has not read the code, and it is organised around where the risk actually is rather than around the file listing.

## The one-sentence summary of what to protect

A caller contract on Midnight writes a signature request into its own ledger and notifies a central singleton; this crate reads that, and the property that must hold is: **the MPC only ever signs a payload the caller actually filed, under a key derived from the address the record was read from, and one bad record never stops the indexer for everyone else.**

Almost every question worth asking during this review is a special case of that sentence.

## Scope

The branch is stacked on `feat/midnight-publisher` (PR #1058), so the sidecar package is not part of this review even though it is in the history. Reviewing only what this work adds:

```
git diff --stat $(git merge-base HEAD origin/develop) HEAD -- . ':(exclude)chain-signatures/midnight-publisher-ts' ':(exclude).github'
```

That is 35 files and roughly 9,800 added lines across 34 commits. Two thirds of the line count is tests and golden fixtures, which is deliberate and is where a good deal of the review value sits.

New crate: `config.rs`, `records.rs`, `request_id.rs`, `rpc.rs`, `sidecar.rs`, `reader.rs`, `tx.rs`, `convert.rs`, `indexer.rs`, `publisher.rs` (a stub for a later PR), `test_fixtures.rs`. Outside the crate: `crypto/src/kdf.rs` gains the Midnight epsilon derivation, `primitives/src/chain.rs` gains the enum variant, the node gains CLI args and spawn wiring, and `chain-integration-core` gains one defaulted telemetry method.

## Read it in dependency order, not alphabetically

The security argument composes upward, so reading it out of order makes each layer look either paranoid or careless. Read in this order:

1. `records.rs` and `request_id.rs` — the wire layout and the request-id hash. Everything above depends on these being byte-exact.
2. `reader.rs` — turning the sidecar's atom tree back into a record, plus the recompute-and-drop gate.
3. `tx.rs` — assembling the EVM transaction that gets signed.
4. `convert.rs` — building the `IndexedSignRequest`, including the epsilon derivation.
5. `indexer.rs` — the loop that drives all of the above, and the only place with concurrency and failure policy.
6. `rpc.rs`, `sidecar.rs`, `config.rs` — the plumbing. Least interesting, easiest to check.

## The three questions that carry the risk

### 1. Can a caller obtain a signature over something it did not file?

The defence is the recompute-and-drop gate: `resolve_verified_record` at `src/reader.rs:253`. It decodes the record stored under a request id and returns it only if `compute_request_id(&record)` equals the id it was filed under.

What to check, and this is the subtle part: `decode_record` (`src/reader.rs:113`) already takes the expected request id and uses it to choose between capacity splits that all decode cleanly, **falling back to the first clean decode when none matches**. So on the matching path the gate looks tautological, and someone will eventually propose deleting it. The fallback is why it is not: when no split matched, decode returned a guess, and the gate is the only thing between that guess and a signature.

Verify the gate covers the fallback rather than trusting the comment. `resolve_verified_record_drops_spoofed_filing` asserts in-test that `decode_record` *accepts* the spoofed filing before asserting the resolve drops it, which is what isolates the gate's own contribution. Without that precondition the test would pass whether the gate worked or decode rejected first, and only one of those verifies anything.

Also look at `key_matches_request_id` (`src/reader.rs:301`). Map keys arrive trailing-zero-trimmed, so a key may be shorter than 32 bytes and has to be re-padded. Convince yourself two distinct request ids cannot re-pad to the same value.

### 2. Can a caller obtain a signature under someone else's derived key?

This is the highest-severity question in the review, because getting it wrong is not a dropped request, it is a wrong signature under a key that belongs to another contract.

The defence is at `src/convert.rs:62`. Epsilon is derived from `read_address`, the address the record was **read from**, never from `record.sender`, and the two are asserted equal with a mismatch dropping the request. The reasoning: `sender` is caller-controlled record data, and a caller controls its whole ledger, so the request-id gate proves only internal consistency. Deriving from `sender` would let a caller write another contract's address into that field and obtain a signature under that contract's key.

Two things worth doing here rather than reading:

Check that `read_address` is bytes, not a string. `derive_epsilon_midnight` (`chain-signatures/crypto/src/kdf.rs:154`) is byte-literal on its address argument, so an uppercase or `0x`-prefixed rendering would derive a different, perfectly valid-looking key with no error anywhere. The epsilon fixture carries a `NEGATIVE-noncanonical-sender-form` vector precisely as a control for this.

Check there is exactly one place the address is rendered to a string. Two render sites is how this class of bug gets in.

### 3. Can one malformed record stop the indexer for everyone?

A caller can write anything into its own ledger, including records that fail every validation. If any of those failures propagates out of the per-block loop, `run()` returns `Err`, the supervisor restarts it, and it hits the same record again: a permanent outage triggered by one attacker for the price of one bad write.

Look at `src/indexer.rs:609`, where `to_sign_request` is called. Every `Err` must become a per-entry drop with a reason label and a `continue`, never a propagated error. Then check the other drop sites route through `drop_entry` (`src/indexer.rs:358`).

The inverse also matters: channel-send failures **should** propagate, because a closed channel means the supervisor is already shutting down. A reviewer should be able to state, for each `?` in the block loop, which of those two categories it is in.

## How to check the goldens are not circular

This crate leans hard on golden vectors, and a golden that was produced by the code under test proves nothing. The check is quick and it is worth doing before trusting any test result.

Each fixture declares its provenance. Read the top-level keys:

```
python3 -c "import json;d=json.load(open('tests/rid_vectors.json'));print({k:d[k] for k in d if k!='vectors'})"
```

`tests/rid_vectors.json` and `tests/tx_vectors.json` both name `@sig-net/midnight 0.11.0` and the exact TypeScript function that produced them. `chain-signatures/crypto/tests/epsilon_vectors.json` does the same for the epsilon derivation. `tests/records/{5,20}-field.json` are captured contract state, and the sidecar's own committed golden output is what `state_node_parses_sidecar_golden` (`src/sidecar.rs`) parses.

What to be suspicious of: any expected value that is hand-authored, any fixture without provenance metadata, and any test that computes its expected value by calling the same function it is testing. The last one is the easy mistake. For an example of the honest form, `state_node_parses_sidecar_golden` reads a file the *other* language committed, and the payload pin in `assert_sign_request` takes its expected hash from `tx_vectors.json` rather than recomputing it, with a comment saying why.

`tx_vectors.json` claims its records are byte-identical to the same-named entries in `rid_vectors.json`. That claim is checked in-test per vector before any transaction bytes are compared, so a regenerated fixture that drifted fails on the join rather than producing confusing byte mismatches.

## Review by mutation, not by reading

This is the most efficient way to review this crate, and it is how the tests were built. Break something deliberately, run the suite, and see whether the failure is the one you expected. A mutation that survives is either a missing test or a piece of code that does nothing.

Restore each one before the next, and confirm with `git diff` that you did.

| break this | expect |
|---|---|
| make the gate at `reader.rs:281` always pass | `resolve_verified_record_drops_spoofed_filing` fails |
| derive epsilon from `record.sender` **and** delete the equality check at `convert.rs:62` | `to_sign_request_rejects_read_address_mismatch` fails |
| drop the `keccak` around the entropy in `convert.rs` | the full-chain oracle test fails |
| iterate the calldata words vector's length instead of `no_words` in `tx.rs` | the ethers golden fails on `unused-word-slot`, and passes on `minimal-1word` |
| swap `max_fee_per_gas` and `max_priority_fee_per_gas` in `tx.rs` | the ethers golden fails, because the vectors carry distinct fee values on purpose |
| propagate the `Err` from `to_sign_request` at `indexer.rs:609` instead of dropping | no test fails today, and that is the answer to a different question: see the gaps below |
| flip the watermark comparison at `indexer.rs` from `count < respondCount` to `>` | both watermark tests fail |
| change `RESPOND_COUNTER_FIELD` (`indexer.rs:275`) from 2 to 4 | `run_recovers_pruned_requests_via_watermark` fails |
| revert `StateNode` to `#[serde(untagged)]` in `sidecar.rs` | the reader's captured-state goldens fail |

That last row is worth understanding rather than just running. Field 2 is `respondCounterMap`, the phase-1 signature responses, which is what this indexer emits. Field 4 is `respondBidirectionalCounterMap`, the phase-2 execution outputs, which only exist after the destination-chain transaction has run. Using field 4 would re-emit every signed-but-not-yet-executed request on each degraded catchup. The contract's own comments settle which is which.

## Where I would attack it

An honest list of the weakest points, so review effort goes where it pays.

**Three tasks have no independent review.** The request-id gate, the indexer loop, and the watermark catchup were reviewed by the same agent that directed their implementation, and two of them only had specific claims spot-checked rather than a full review. Treat those three as unreviewed: `reader.rs`'s gate, and `indexer.rs` in full.

**The insert-only assumption.** The degraded catchup sets the processed block to the anchor after a watermark walk, and that is only safe because the notification map is append-only, so the latest state still contains every notification ever filed. That holds in the current contract, which contains no removal of any kind, but it is an assumption about contract evolution that no code can enforce. Re-check it on any `@sig-net/midnight` contract bump.

**Nothing bounds a response size.** `resp.json::<StateNode>()` in `sidecar.rs` reads an unbounded body, and the state it decodes originates from a caller-controlled contract. There is an atom-count cap inside `decode_record` (`reader.rs`) that bounds the capacity enumeration's CPU, but it fires after every atom has been hex-decoded, so it does not bound allocation. No layer above it does either.

**`/respond` is not exercised.** `tests/sidecar_live.rs` boots the real sidecar and drives the decode and health routes over HTTP, so those are covered end to end, but `/respond` needs a chain and is run on demand from `tests/respond-live.ts` instead.

**Drop counters are log labels, not metrics.** `ChainTelemetry` has no counter hook, so every per-reason drop is a structured `WARN` with a machine-countable `reason` field. Fine for a log pipeline, not a dashboard. Deliberate and recorded, not an oversight.

**A caller can manufacture drops at will**, by writing records with a mismatched sender, a reserved enum, or a non-UTF-8 path. That is why drops are `WARN` rather than `ERROR`: at `ERROR` an adversary gets a free way to page your on-call for the price of writing junk into their own contract. Check the level if you touch that code.

## Running it

```
cargo test -p mpc-chain-midnight                                    # 71 tests, 1 ignored
cargo test --workspace --exclude integration-tests --no-fail-fast   # 30 suites, 444 tests
cargo clippy --tests -- -Dclippy::all
cargo fmt --check
```

The ignored test needs a live Midnight node. Check the *content* of a workspace run rather than its exit code, since `--no-fail-fast` plus a wrapper script can mislead:

```
grep -E "FAILED|^failures:|^error" <output>
grep "test result:" <output> | grep -v "0 failed"
```

Both should print nothing.

Midnight is off unless its config is supplied, so a node without Midnight arguments never constructs any of this. Confirm that gate still holds if you touch `node/src/cli/mod.rs`.

## Things that look like bugs and are not

Worth knowing before filing them.

**`Maybe<T>` is not modelled as `Option<T>`.** Compact emits `Maybe<T>` as `{is_some, value}` where `value` carries a full default-valued `T` even when absent, so vector capacities stay inferable. The request-id hash depends on that: an `Option` would discard the inner value, emit a short preimage, and produce a wrong id for every plain-transfer request. Hence `CompactMaybe` in `records.rs`.

**Counts, never lengths.** `no_words`, `access_list_entry_count` and `storage_key_count` decide what reaches the transaction; the stored vectors are capacity and may be longer. Three golden vectors deliberately assemble to the same transaction hash from different records to pin exactly this.

**Provenance is advisory and must not gate signing.** The indexer tries to attribute a notification to a calling transaction, but a direct call to the notify entry point has no cross-contract-call frame at all, so requiring provenance would drop legitimate requests. `process_entry_signs_without_provenance` exists because this is the invariant a well-meaning contributor is most likely to "fix" into a fail-closed check.

**The empty atom is meaningful.** Atoms arrive trailing-zero-trimmed, so `""` is a legitimate zero value and a composite map key's first atom can vanish entirely. This is why map keys are arrays of per-atom hex rather than one joined string, and the sidecar's own captured golden shows a one-atom key and a two-atom key that concatenate identically.
