//! Decode a finalized Midnight block into notify inserts plus cross-contract-call
//! provenance, mirroring how `state.rs` decodes contract STATE.
//!
//! Mechanism only: no contract-address filtering, no request-id recompute, no
//! proof checks. Every contract call in every transaction is decoded and its raw
//! data returned; a separate crate owns the security semantics.
//!
//! Pipeline (all types pinned to the rc.4 ledger via `midnight-node-ledger-helpers`):
//!   ledger `Transaction` bytes
//!     -> `Transaction::calls()`              (all contract calls, both intent segments)
//!     -> per `ContractCall`, its two transcripts (guaranteed / fallible)
//!        -> `scan_map_inserts` over `Transcript.program`   (the Map-insert atoms)
//!        -> `Transcript.effects.claimed_contract_calls`     (Step 3, caller side)
//!        -> `ContractCall.communication_commitment`          (Step 3, callee side)
//!
//! The Map-insert scanner is a state-independent symbolic stack replay of the
//! transcript's `Op` program: it tracks each stack slot as either a concrete
//! literal (traced back to `Op::Push`) or opaque (produced by an opcode whose
//! result needs real chain state), using the VM's fixed per-opcode stack arities,
//! and reads off the (key, value) at each `Op::Ins`. See `scan_map_inserts`.

use anyhow::Context as _;
use midnight_node_ledger_helpers::fork::raw_block_data::RawTransaction;
use midnight_node_ledger_helpers::{
    ContractEffects, DefaultDB, Key, Op, ProofMarker, PureGeneratorPedersen, ResultModeVerify,
    Signature, StateValue, Transaction,
};

/// The rc.4 ledger transaction type, exactly as the toolkit's own
/// `show_transaction` deserializes `RawTransaction::Midnight(bytes)`.
type Tx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>;

/// One decoded notify: a single Map/Array insert recovered from a contract
/// call's transcript, tagged with the callee contract and cross-call provenance.
///
/// `insert_key` / `insert_value` are field-aligned hex atoms produced by the
/// same `state.rs` helpers that back `GET /state`, so both seams speak one atom
/// schema (each atom trailing-zero-trimmed; the consumer re-pads to field width).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockNotify {
    /// The contract whose state receives this insert (`ContractCall.address`), hex.
    pub address: String,
    /// Field-aligned hex atoms of the inserted key.
    pub insert_key: Vec<String>,
    /// Field-aligned hex atoms of the inserted value.
    pub insert_value: Vec<String>,
    /// Cross-contract-call provenance for this call, as a JSON string:
    /// `{"communication_commitment":"<hex>","claimed":[{"position",...}]}`.
    /// `communication_commitment` is this call's own commitment (callee side);
    /// `claimed` is the transcript's `claimed_contract_calls` effects set (caller
    /// side), sorted for determinism. `Option` per the response contract; a
    /// decoded call always carries a commitment, so in practice this is `Some`.
    pub claimed_contract_calls: Option<String>,
}

/// `GET /block` response: one entry per notify insert across the block's calls.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BlockResponse {
    pub calls: Vec<BlockNotify>,
}

/// Cross-call provenance payload serialized into `BlockNotify.claimed_contract_calls`.
#[derive(serde::Serialize)]
struct CallProvenance<'a> {
    communication_commitment: &'a str,
    claimed: Vec<ClaimedCall>,
}

/// One entry of a transcript's `claimed_contract_calls` effects set, raw-decoded.
#[derive(serde::Serialize)]
struct ClaimedCall {
    /// Position of the claimed call within the caller's transcript.
    position: u64,
    /// Callee contract address, hex.
    address: String,
    /// Callee entry-point hash, hex.
    entry_point: String,
    /// Callee `communication_commitment`, hex (little-endian `Fr` bytes).
    commitment: String,
}

/// One Map/Array/BoundedMerkleTree insert recovered from a transcript: the
/// concrete key and value a circuit pushed literally before an `Op::Ins`.
#[derive(Debug, Clone)]
pub struct MapInsert {
    pub key: StateValue<DefaultDB>,
    pub value: StateValue<DefaultDB>,
}

/// A symbolic stack slot during the replay.
#[derive(Clone)]
enum Sym<'a> {
    /// Traced back to a literal `Op::Push` (possibly via `Dup`/`Swap`).
    Concrete(&'a StateValue<DefaultDB>),
    /// Produced by an opcode whose result needs real chain state (`Idx`, `Root`,
    /// `Popeq`, arithmetic, `New`, ...). Not recoverable from the transcript alone.
    Opaque,
}

/// Pop that never panics: a stack underflow (only possible on a malformed
/// program) yields `Opaque` rather than aborting the whole `/block` request.
fn pop<'a>(stack: &mut Vec<Sym<'a>>) -> Sym<'a> {
    stack.pop().unwrap_or(Sym::Opaque)
}

/// Recover every literal Map/Array insert from a transcript's `Op` program by
/// symbolic stack replay.
///
/// Correctness rests on the VM's fixed, data-independent stack arities
/// (`onchain-vm/src/vm.rs`, the `stack_req` table plus each opcode's push count):
/// every op below pops and pushes the exact same count the real interpreter does,
/// so the symbolic stack stays depth-accurate. A slot is `Concrete` only when it
/// traces back to an `Op::Push` (directly, or cloned/reordered by `Dup`/`Swap`);
/// everything else is `Opaque`. At each `Op::Ins` the value and the first popped
/// key are the semantic leaf write (later iterations splice that subtree back up
/// through its parents), so we record it iff both are `Concrete`. This naturally
/// skips inserts whose key or value is chain-state-derived, and skips splice
/// continuations (their value is the `Opaque` result of the prior insert).
///
/// Forward `Jmp` is honored (skipped ops never execute); `Branch` cannot be
/// resolved statically, so we pop its condition and take the fall-through path.
/// Compiled circuits keep both branch arms stack-balanced, so depth stays
/// consistent at the merge point regardless.
pub(crate) fn scan_map_inserts<'a>(
    program: &[&'a Op<ResultModeVerify, DefaultDB>],
) -> Vec<MapInsert> {
    let mut stack: Vec<Sym<'a>> = Vec::new();
    let mut found = Vec::new();
    let mut pc = 0usize;

    while pc < program.len() {
        let op = program[pc];
        let mut advance = 1usize;

        match op {
            // Producer of a concrete literal (pop 0, push 1). `Push`'s value is a
            // literal `StateValue` baked into the transcript at proving time, even
            // in the on-chain `ResultModeVerify` program.
            Op::Push { value, .. } => stack.push(Sym::Concrete(value)),

            // Unconditional forward jump: the skipped ops never run.
            Op::Jmp { skip } => advance = 1 + *skip as usize,

            // Conditional we cannot resolve statically: pop the condition (arity 1)
            // and fall through (see the function-level note on branch balance).
            Op::Branch { .. } => {
                let _ = pop(&mut stack);
            }

            // No stack effect.
            Op::Noop { .. } | Op::Ckpt => {}

            // Pop 1, push 0.
            Op::Pop | Op::Log | Op::Popeq { .. } => {
                let _ = pop(&mut stack);
            }

            // Pop 1, push 1 opaque result.
            Op::Type
            | Op::Size
            | Op::New
            | Op::Neg
            | Op::Root
            | Op::Addi { .. }
            | Op::Subi { .. } => {
                let _ = pop(&mut stack);
                stack.push(Sym::Opaque);
            }

            // Pop 2, push 1 opaque result.
            Op::Lt
            | Op::Eq
            | Op::And
            | Op::Or
            | Op::Add
            | Op::Sub
            | Op::Concat { .. }
            | Op::Member
            | Op::Rem { .. } => {
                let _ = pop(&mut stack);
                let _ = pop(&mut stack);
                stack.push(Sym::Opaque);
            }

            // `dup n`: clone the slot `n` below the top onto the top (pop 0, push 1).
            Op::Dup { n } => {
                let n = *n as usize;
                let slot = stack
                    .len()
                    .checked_sub(n + 1)
                    .and_then(|i| stack.get(i).cloned())
                    .unwrap_or(Sym::Opaque);
                stack.push(slot);
            }

            // `swap n`: swap the top with the slot `n + 2` from the top (net 0).
            Op::Swap { n } => {
                let n = *n as usize;
                let len = stack.len();
                if len >= n + 2 {
                    stack.swap(len - 1, len - 2 - n);
                }
            }

            // `idx`: descend into a container. Pops one stack key per `Key::Stack`
            // in the path plus the base container. With `push_path`, leaves a
            // (container, key) breadcrumb pair per path element on the stack, then
            // the indexed result on top; without it, just the result. All pushes
            // are opaque: the descent needs chain state, and breadcrumbs are only
            // ever consumed as `Ins` splice continuations (i > 0), never as a
            // semantic leaf (i == 0), so their concreteness is irrelevant.
            Op::Idx {
                path, push_path, ..
            } => {
                let n_stack_keys = path.iter_deref().filter(|k| matches!(k, Key::Stack)).count();
                for _ in 0..n_stack_keys {
                    let _ = pop(&mut stack);
                }
                let _ = pop(&mut stack); // base container
                let pushes = if *push_path { 2 * path.len() + 1 } else { 1 };
                for _ in 0..pushes {
                    stack.push(Sym::Opaque);
                }
            }

            // `ins n`: write a leaf value up through `n` container levels. Pops
            // the value, then `n` (key, container) pairs; pushes the result.
            Op::Ins { n, .. } => {
                let value = pop(&mut stack);
                for i in 0..(*n as usize) {
                    let key = pop(&mut stack);
                    let _container = pop(&mut stack);
                    if i == 0 {
                        if let (Sym::Concrete(k), Sym::Concrete(v)) = (&key, &value) {
                            found.push(MapInsert {
                                key: (*k).clone(),
                                value: (*v).clone(),
                            });
                        }
                    }
                }
                stack.push(Sym::Opaque); // the resulting container
            }

            // `Op` is `#[non_exhaustive]`; rc.4 defines no other variants. A future
            // opcode of unknown arity is left as a no-op rather than guessed.
            _ => {}
        }

        pc = match pc.checked_add(advance) {
            Some(next) => next,
            None => break,
        };
    }

    found
}

/// Flatten a recovered key/value `StateValue` into field-aligned hex atoms,
/// reusing the `state.rs` decoder so `/block` and `/state` share one atom schema.
fn atoms_of(sv: &StateValue<DefaultDB>) -> anyhow::Result<Vec<String>> {
    match sv {
        // Common case: a flat cell (a struct's scalar fields in one AlignedValue).
        StateValue::Cell(av) => Ok(crate::state::value_atoms(av)),
        // Anything richer (array/map/null): walk it and collect leaf atoms in order.
        other => {
            let mut out = Vec::new();
            flatten_atoms(&crate::state::walk(other)?, &mut out);
            Ok(out)
        }
    }
}

/// Collect every cell atom (and map-key hex) of a walked node, in traversal order.
fn flatten_atoms(node: &crate::state::Node, out: &mut Vec<String>) {
    match node {
        crate::state::Node::Null => {}
        crate::state::Node::Cell { atoms } => out.extend(atoms.iter().cloned()),
        crate::state::Node::Array { children } => {
            for child in children {
                flatten_atoms(child, out);
            }
        }
        crate::state::Node::Map { entries } => {
            for entry in entries {
                out.push(entry.key.clone());
                flatten_atoms(&entry.value, out);
            }
        }
    }
}

/// Decode this transcript's cross-call provenance: the callee's own commitment
/// plus its `claimed_contract_calls` effects set (Step 3), as a JSON string.
fn provenance(
    effects: &ContractEffects<DefaultDB>,
    commitment_hex: &str,
) -> anyhow::Result<Option<String>> {
    let mut claimed = Vec::new();
    for entry in effects.claimed_contract_calls.iter() {
        // `iter()` yields `Arc<Sp<ClaimedContractCallsValue>>`; deref to the value.
        let c = &**entry;
        claimed.push(ClaimedCall {
            position: c.0,
            address: hex::encode(c.1 .0 .0),
            entry_point: hex::encode(c.2 .0),
            commitment: hex::encode(c.3.as_le_bytes()),
        });
    }
    // HashSet iteration order is unstable; sort for a deterministic response.
    claimed.sort_by(|a, b| {
        a.position
            .cmp(&b.position)
            .then_with(|| a.commitment.cmp(&b.commitment))
    });
    let payload = CallProvenance {
        communication_commitment: commitment_hex,
        claimed,
    };
    Ok(Some(
        serde_json::to_string(&payload).context("serialize call provenance")?,
    ))
}

/// Extract every notify insert from every contract call in a decoded transaction.
pub(crate) fn notifies_from_tx(tx: &Tx) -> anyhow::Result<Vec<BlockNotify>> {
    let mut notifies = Vec::new();
    for (_segment, call) in tx.calls() {
        let address = hex::encode(call.address.0 .0);
        let commitment = hex::encode(call.communication_commitment.as_le_bytes());
        for transcript in [
            call.guaranteed_transcript.as_deref(),
            call.fallible_transcript.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let claimed = provenance(&transcript.effects, &commitment)?;
            let program: Vec<&Op<ResultModeVerify, DefaultDB>> =
                transcript.program.iter_deref().collect();
            for insert in scan_map_inserts(&program) {
                notifies.push(BlockNotify {
                    address: address.clone(),
                    insert_key: atoms_of(&insert.key)?,
                    insert_value: atoms_of(&insert.value)?,
                    claimed_contract_calls: claimed.clone(),
                });
            }
        }
    }
    Ok(notifies)
}

/// Deserialize the tagged rc.4 ledger `Transaction` bytes (the `midnight_tx`
/// argument already unwrapped from the `send_mn_transaction` extrinsic).
pub(crate) fn decode_transaction(tx_bytes: &[u8]) -> anyhow::Result<Tx> {
    midnight_node_ledger_helpers::deserialize(tx_bytes)
        .context("tagged-deserialize ledger Transaction")
}

/// Convenience: deserialize then extract notifies from a single tx's bytes.
pub(crate) fn notifies_from_tx_bytes(tx_bytes: &[u8]) -> anyhow::Result<Vec<BlockNotify>> {
    notifies_from_tx(&decode_transaction(tx_bytes)?)
}

/// Decode a fetched block's transactions (Step 1 output) into a `BlockResponse`.
/// Only `Midnight` transactions carry ledger `Transaction` bytes; system
/// transactions are skipped.
pub(crate) fn decode_block(txs: &[RawTransaction]) -> anyhow::Result<BlockResponse> {
    let mut calls = Vec::new();
    for tx in txs {
        if let RawTransaction::Midnight(bytes) = tx {
            calls.extend(notifies_from_tx_bytes(bytes)?);
        }
    }
    Ok(BlockResponse { calls })
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_node_ledger_helpers::{AlignedValue, HashMapStorage, Sp};

    /// A concrete cell `StateValue` carrying a single little-endian u64 atom.
    fn cell(v: u64) -> StateValue<DefaultDB> {
        StateValue::Cell(Sp::new(AlignedValue::from(v)))
    }

    /// An empty map `StateValue`, used as a stand-in container in synthetic programs.
    fn empty_map() -> StateValue<DefaultDB> {
        StateValue::Map(HashMapStorage::new())
    }

    fn push(v: &StateValue<DefaultDB>) -> Op<ResultModeVerify, DefaultDB> {
        Op::Push {
            storage: false,
            value: v.clone(),
        }
    }

    fn scan(program: &[Op<ResultModeVerify, DefaultDB>]) -> Vec<MapInsert> {
        let refs: Vec<&Op<ResultModeVerify, DefaultDB>> = program.iter().collect();
        scan_map_inserts(&refs)
    }

    /// A flat `Map::insert(key, value)` (stack before `Ins`, top-down:
    /// value, key, container) is recovered as one insert with those atoms.
    #[test]
    fn scanner_recovers_flat_map_insert() {
        let container = empty_map();
        let key = cell(0x11);
        let value = cell(0x22);
        let program = [
            push(&container),
            push(&key),
            push(&value),
            Op::Ins {
                cached: false,
                n: 1,
            },
        ];
        let inserts = scan(&program);
        assert_eq!(inserts.len(), 1);
        assert_eq!(atoms_of(&inserts[0].key).unwrap(), vec!["11".to_string()]);
        assert_eq!(atoms_of(&inserts[0].value).unwrap(), vec!["22".to_string()]);
    }

    /// `Ins { n = 2 }` splices a written leaf up one container level in one op;
    /// only the innermost (first-popped) key/value is the semantic write.
    #[test]
    fn scanner_records_only_leaf_of_multi_level_ins() {
        let outer = empty_map();
        let outer_key = cell(0x01);
        let inner = empty_map();
        let inner_key = cell(0xaa);
        let value = cell(0xbb);
        let program = [
            push(&outer),
            push(&outer_key),
            push(&inner),
            push(&inner_key),
            push(&value),
            Op::Ins {
                cached: false,
                n: 2,
            },
        ];
        let inserts = scan(&program);
        assert_eq!(inserts.len(), 1, "only the leaf write is recorded");
        assert_eq!(atoms_of(&inserts[0].key).unwrap(), vec!["aa".to_string()]);
        assert_eq!(atoms_of(&inserts[0].value).unwrap(), vec!["bb".to_string()]);
    }

    /// A value produced by an opcode (not a literal `Push`) is chain-state-derived
    /// and must not be recorded. `New` pops its tag and pushes an opaque container.
    #[test]
    fn scanner_skips_opaque_value() {
        let container = empty_map();
        let key = cell(0x11);
        let seed = cell(0x02);
        let program = [
            push(&container),
            push(&key),
            push(&seed),
            Op::New, // pops seed, pushes an opaque fresh container
            Op::Ins {
                cached: false,
                n: 1,
            },
        ];
        assert!(
            scan(&program).is_empty(),
            "opaque (non-literal) value must not be recorded"
        );
    }

    /// `Dup` preserves concreteness: a duplicated literal is still recoverable.
    #[test]
    fn scanner_tracks_dup() {
        let container = empty_map();
        let kv = cell(0x33);
        let program = [
            push(&container),
            push(&kv),
            Op::Dup { n: 0 }, // duplicate top (kv); stack: container, kv, kv
            Op::Ins {
                cached: false,
                n: 1,
            }, // value = kv, key = kv, container = container
        ];
        let inserts = scan(&program);
        assert_eq!(inserts.len(), 1);
        assert_eq!(atoms_of(&inserts[0].key).unwrap(), vec!["33".to_string()]);
        assert_eq!(atoms_of(&inserts[0].value).unwrap(), vec!["33".to_string()]);
    }

    /// `Swap` reorders slots: swapping key/value before `Ins` swaps what is recorded.
    #[test]
    fn scanner_tracks_swap() {
        let container = empty_map();
        let x = cell(0x44);
        let y = cell(0x55);
        let program = [
            push(&container),
            push(&x), // becomes the key after swap
            push(&y), // becomes the value after swap
            Op::Swap { n: 0 }, // swap top two: stack now container, y, x
            Op::Ins {
                cached: false,
                n: 1,
            }, // value = x (top), key = y
        ];
        let inserts = scan(&program);
        assert_eq!(inserts.len(), 1);
        assert_eq!(atoms_of(&inserts[0].key).unwrap(), vec!["55".to_string()]);
        assert_eq!(atoms_of(&inserts[0].value).unwrap(), vec!["44".to_string()]);
    }

    /// A forward `Jmp` skips the ops it jumps over, so an `Ins` in the skipped
    /// region is not scanned.
    #[test]
    fn scanner_honors_forward_jmp() {
        let container = empty_map();
        let key = cell(0x11);
        let value = cell(0x22);
        let program = [
            push(&container),
            push(&key),
            push(&value),
            Op::Jmp { skip: 1 }, // advance by 1 + 1 = 2, skipping the Ins below
            Op::Ins {
                cached: false,
                n: 1,
            },
        ];
        assert!(
            scan(&program).is_empty(),
            "Ins jumped over must not be scanned"
        );
    }

    /// `Branch` pops its condition and falls through, so a following `Ins` still
    /// runs against the correctly-sized stack.
    #[test]
    fn scanner_branch_pops_condition_and_falls_through() {
        let container = empty_map();
        let key = cell(0x11);
        let value = cell(0x22);
        let cond = cell(0x01);
        let program = [
            push(&container),
            push(&key),
            push(&value),
            push(&cond),
            Op::Branch { skip: 5 }, // pop cond, fall through
            Op::Ins {
                cached: false,
                n: 1,
            },
        ];
        let inserts = scan(&program);
        assert_eq!(inserts.len(), 1, "fall-through Ins is scanned");
        assert_eq!(atoms_of(&inserts[0].key).unwrap(), vec!["11".to_string()]);
        assert_eq!(atoms_of(&inserts[0].value).unwrap(), vec!["22".to_string()]);
    }

    /// The rc.4 ledger-Transaction fixture must deserialize and run the full
    /// contract-call extraction (Step 2) plus the Step-3 `communication_commitment`
    /// and `claimed_contract_calls` decode without panic, yielding a well-formed
    /// (possibly empty) `BlockResponse`. This fixture predates SGN2, so it may
    /// carry zero contract calls; that is asserted-as-well-formed, not required.
    #[test]
    fn reference_tx_fixture_decodes_and_extracts() {
        let raw = std::fs::read_to_string("tests/fixtures/serialized_tx.mn").unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let hex_str = v["tx"]["Midnight"]
            .as_str()
            .expect("fixture has tx.Midnight hex");
        let bytes = hex::decode(hex_str).expect("valid hex");

        // Step 2 entry: tagged-deserialize the inner ledger Transaction.
        let tx = decode_transaction(&bytes).expect("deserialize ledger Transaction");

        // Explicitly exercise the contract-call extraction + Step-3 decode path,
        // so it is covered even when the fixture yields no map-insert notifies.
        let mut call_count = 0usize;
        for (_segment, call) in tx.calls() {
            call_count += 1;
            // Step 3, callee side: communication_commitment decode.
            let _commitment = hex::encode(call.communication_commitment.as_le_bytes());
            for transcript in [
                call.guaranteed_transcript.as_deref(),
                call.fallible_transcript.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                // Step 3, caller side: claimed_contract_calls decode.
                for entry in transcript.effects.claimed_contract_calls.iter() {
                    let c = &**entry;
                    let _ = (
                        c.0,
                        hex::encode(c.1 .0 .0),
                        hex::encode(c.2 .0),
                        hex::encode(c.3.as_le_bytes()),
                    );
                }
                // Step 2: scanner over the transcript program.
                let program: Vec<&Op<ResultModeVerify, DefaultDB>> =
                    transcript.program.iter_deref().collect();
                let _inserts = scan_map_inserts(&program);
            }
        }

        // Full pipeline yields a well-formed (possibly empty) BlockResponse.
        let response = BlockResponse {
            calls: notifies_from_tx_bytes(&bytes).expect("extract notifies"),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.starts_with("{\"calls\":"), "well-formed response: {json}");
        eprintln!(
            "reference tx fixture: {call_count} contract call(s), {} notify insert(s)",
            response.calls.len()
        );
    }

    /// The scanner's SGN2-specific correctness (which `Ins` in a real compiled
    /// notify circuit is the semantic insert, and how many container levels it
    /// splices) needs a REAL notify transcript, which does not exist until a live
    /// SGN2 deploy captures one. Ignored until `tests/fixtures/notify-tx.mn` lands.
    #[test]
    #[ignore = "pending a live SGN2 notify fixture"]
    fn notify_fixture_yields_expected_insert() {
        let raw = std::fs::read_to_string("tests/fixtures/notify-tx.mn").unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let bytes = hex::decode(v["tx"]["Midnight"].as_str().unwrap()).unwrap();
        let notifies = notifies_from_tx_bytes(&bytes).unwrap();
        assert!(
            !notifies.is_empty(),
            "a real SGN2 notify tx must yield at least one insert"
        );
    }
}
