//! Mirrors of the Midnight Signet contract's on-chain record types.
//!
//! Field declaration order is load-bearing. The contract's request id is a
//! keccak256 over `toBinaryRepr(record)`: every field re-padded to its
//! declared width and concatenated in declaration order, with no tags,
//! framing, or length prefixes. A reordering here fails no compile and no
//! decode; it silently changes every request id. The tests below pin the
//! field sets, the declaration order, and the fixed scalar widths. The
//! request-id twin and its golden vectors are the end-to-end authority.
//!
//! These are plain data mirrors: serialization, hashing, and decoding belong
//! to later layers. Nothing may assume Rust memory layout matches the wire
//! form, which is field by field at declared widths.
//!
//! Endianness splits by side and must not be over-generalised: every `Uint`
//! integer in these records (`request_nonce`, `key_version`, the
//! `EvmType2TxParams` integers, `no_words`, the count fields) is
//! little-endian zero-padded to its declared width in the preimage and on
//! the wire, while the big-endian rule documented on `AffinePoint` and
//! `Signature` applies only to those respond-side byte arrays.

/// One signing request, the contract's `SignBidirectionalEvent` record.
///
/// Named `Record` rather than `Event` because `mpc-primitives` already
/// exports a chain-agnostic `SignBidirectionalEvent` and both end up in
/// scope in the conversion layer.
///
/// The 12 fields are in keccak preimage order; `tx_params` expands in place
/// at its own declared widths.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalRecord {
    /// `ContractAddress { bytes: Bytes<32> }`, a single-field wrapper that
    /// contributes exactly 32 preimage bytes
    pub sender: [u8; 32],
    pub request_nonce: u64,
    /// `Uint<8>`: one byte in the preimage, not four
    pub key_version: u8,
    pub path: [u8; 32],
    /// `MPCSignatureAlgorithm` enum, one byte: ecdsa = 0, reserved = 1
    pub algo: u8,
    /// `MPCDestination` enum, one byte: unused = 0, reserved = 1
    pub dest: u8,
    pub params: [u8; 64],
    /// `TxParamType` enum, one byte: evmType2 = 0, reserved = 1
    pub tx_param_type: u8,
    pub tx_params: EvmType2TxParams,
    /// ASCII `Bytes<32>`, trailing-zero-trimmed on the wire and re-padded to
    /// 32 bytes in the preimage
    pub caip2_id: [u8; 32],
    /// `Bytes<LenOut>`, runtime width chosen per integrator
    pub output_deserialization_schema: Vec<u8>,
    /// `Bytes<LenResp>`, runtime width chosen per integrator
    pub respond_serialization_schema: Vec<u8>,
}

/// EIP-1559 transaction parameters in the contract's canonical payload
/// order, which is also the request-id hash order. The order is read off
/// the contract, not off how an EVM transaction usually reads: the priority
/// fee comes before the fee cap, `to` sits sixth, and `calldata` comes
/// before the access-list pair. Each count field sits directly before the
/// vector it bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct EvmType2TxParams {
    pub chain_id: u64,
    pub nonce: u64,
    /// Before `max_fee_per_gas`, backwards against EVM habit
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: [u8; 20],
    pub value: u128,
    /// Before the access-list pair, backwards against EVM habit
    pub calldata: CompactMaybe<EvmCalldata>,
    pub access_list_entry_count: u8,
    /// `Vector<maxAccessListEntries, _>`: always at capacity, unused slots
    /// zero-filled and still hashed
    pub access_list: Vec<EvmAccessListEntry>,
}

/// Compact's `Maybe<T>`. Not Rust's `Option<T>`: `value` carries a full
/// default-valued `T` even when `is_some` is false, so vector capacities
/// stay inferable from the record itself. Serializers must emit one
/// `is_some` byte then `T` at full declared width regardless of the flag;
/// an `Option`-based model would emit a short preimage and a wrong request
/// id for every request without calldata.
#[derive(Debug, Clone, PartialEq)]
pub struct CompactMaybe<T> {
    pub is_some: bool,
    pub value: T,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvmCalldata {
    pub selector: [u8; 4],
    /// `Uint<16>`: two bytes in the preimage, not one
    pub no_words: u16,
    /// `Vector<maxCalldataWords, Bytes<32>>`: always at capacity, unused
    /// slots zero-filled and still hashed
    pub words: Vec<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EvmAccessListEntry {
    pub address: [u8; 20],
    pub storage_key_count: u8,
    /// `Vector<maxStorageKeysPerEntry, Bytes<32>>`: always at capacity
    pub storage_keys: Vec<[u8; 32]>,
}

/// Entry of the central singleton's notification map.
///
/// The V1 payload is `caller_address(32)` then `requests_index_field(1)`
/// then `zeros(95)`, and names no decode selector. Decoders must fail
/// closed on an unrecognised `version`, never reinterpret the payload under
/// V1 offsets.
#[derive(Debug, Clone, PartialEq)]
pub struct SignBidirectionalEventNotification {
    pub version: u8,
    pub payload: [u8; 128],
}

/// Composite key of the central singleton's event maps: `count` first, then
/// `request_id`.
#[derive(Debug, Clone, PartialEq)]
pub struct SignetMapKey {
    pub count: u64,
    pub request_id: [u8; 32],
}

/// SEC1 affine point with big-endian coordinates.
#[derive(Debug, Clone, PartialEq)]
pub struct AffinePoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// The one canonical signature both respond events carry, field for field
/// the same as the EVM and Solana signet contracts' and the MPC's own. All
/// stored bytes are big-endian, SEC1 order; the contract re-encodes big to
/// little in-circuit on verification, so the MPC posts big-endian and must
/// not pre-reverse.
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub big_r: AffinePoint,
    pub s: [u8; 32],
    pub recovery_id: u8,
}

/// Entry of the central singleton's respond map.
#[derive(Debug, Clone, PartialEq)]
pub struct SignatureRespondedEvent {
    pub signature: Signature,
}

/// Entry of the central singleton's respond-bidirectional map.
#[derive(Debug, Clone, PartialEq)]
pub struct RespondBidirectionalEvent {
    /// Full 128-byte zero-padded output buffer; the attestation digest
    /// covers all 128 bytes
    pub serialized_output: [u8; 128],
    /// Not covered by the attestation digest; a consumer that treats it as
    /// attested must pin it itself
    pub output_len: u8,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of_val;

    /// The 12 record fields in keccak preimage order.
    const SIGN_BIDIRECTIONAL_RECORD_FIELDS: [&str; 12] = [
        "sender",
        "request_nonce",
        "key_version",
        "path",
        "algo",
        "dest",
        "params",
        "tx_param_type",
        "tx_params",
        "caip2_id",
        "output_deserialization_schema",
        "respond_serialization_schema",
    ];

    /// The contract's canonical payload order, which is the hash order.
    const EVM_TYPE2_TX_PARAMS_FIELDS: [&str; 10] = [
        "chain_id",
        "nonce",
        "max_priority_fee_per_gas",
        "max_fee_per_gas",
        "gas_limit",
        "to",
        "value",
        "calldata",
        "access_list_entry_count",
        "access_list",
    ];

    const COMPACT_MAYBE_FIELDS: [&str; 2] = ["is_some", "value"];
    const EVM_CALLDATA_FIELDS: [&str; 3] = ["selector", "no_words", "words"];
    const EVM_ACCESS_LIST_ENTRY_FIELDS: [&str; 3] =
        ["address", "storage_key_count", "storage_keys"];
    const SIGN_BIDIRECTIONAL_EVENT_NOTIFICATION_FIELDS: [&str; 2] = ["version", "payload"];
    const SIGNET_MAP_KEY_FIELDS: [&str; 2] = ["count", "request_id"];
    const AFFINE_POINT_FIELDS: [&str; 2] = ["x", "y"];
    const SIGNATURE_FIELDS: [&str; 3] = ["big_r", "s", "recovery_id"];
    const SIGNATURE_RESPONDED_EVENT_FIELDS: [&str; 1] = ["signature"];
    const RESPOND_BIDIRECTIONAL_EVENT_FIELDS: [&str; 3] =
        ["serialized_output", "output_len", "signature"];

    fn ascii_padded<const N: usize>(text: &[u8]) -> [u8; N] {
        let mut out = [0u8; N];
        out[..text.len()].copy_from_slice(text);
        out
    }

    fn ascii_padded_vec(text: &[u8], width: usize) -> Vec<u8> {
        let mut out = vec![0u8; width];
        out[..text.len()].copy_from_slice(text);
        out
    }

    /// A hand-built record at the smallest useful capacity tier: one calldata
    /// word of capacity, zero access-list entries, 34-byte schemas.
    fn minimal_record() -> SignBidirectionalRecord {
        SignBidirectionalRecord {
            sender: [0xab; 32],
            request_nonce: 7,
            key_version: 1,
            path: ascii_padded(b"caller-path"),
            algo: 0,
            dest: 0,
            params: [0; 64],
            tx_param_type: 0,
            tx_params: EvmType2TxParams {
                chain_id: 31337,
                nonce: 3,
                max_priority_fee_per_gas: 1,
                max_fee_per_gas: 2,
                gas_limit: 21000,
                to: [0xcd; 20],
                value: 5,
                calldata: CompactMaybe {
                    is_some: true,
                    value: EvmCalldata {
                        selector: [0xca, 0x11, 0xab, 0x1e],
                        no_words: 1,
                        words: vec![[0x11; 32]],
                    },
                },
                access_list_entry_count: 0,
                access_list: Vec::new(),
            },
            caip2_id: ascii_padded(b"eip155:31337"),
            output_deserialization_schema: ascii_padded_vec(b"uint256", 34),
            respond_serialization_schema: ascii_padded_vec(b"uint256", 34),
        }
    }

    fn sample_signature() -> Signature {
        Signature {
            big_r: AffinePoint {
                x: [0x01; 32],
                y: [0x02; 32],
            },
            s: [0x03; 32],
            recovery_id: 1,
        }
    }

    fn sample_access_list_entry() -> EvmAccessListEntry {
        EvmAccessListEntry {
            address: [0xee; 20],
            storage_key_count: 1,
            storage_keys: vec![[0x44; 32]],
        }
    }

    /// Top-level field labels of one struct's `{:#?}` output, in printed
    /// order. The struct's own fields sit at exactly one indent level;
    /// nested values sit deeper and closing brackets carry no `: `, so both
    /// drop out. Derived `Debug` prints fields in declaration order, which
    /// is what makes this the declaration order; the structs must keep
    /// `#[derive(Debug)]` for this pin to hold.
    fn top_level_debug_fields(pretty: &str) -> Vec<String> {
        pretty
            .lines()
            .filter_map(|line| {
                let unindented = line.strip_prefix("    ")?;
                if unindented.starts_with(' ') {
                    return None;
                }
                let (name, _) = unindented.split_once(": ")?;
                name.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    .then(|| name.to_string())
            })
            .collect()
    }

    fn assert_declaration_order(value: &impl std::fmt::Debug, expected: &[&str]) {
        let actual = top_level_debug_fields(&format!("{value:#?}"));
        assert_eq!(
            actual, expected,
            "declared field order changed; this reorders the keccak preimage and silently changes every request id"
        );
    }

    /// Declared wire width of a `Maybe<EvmCalldata>`: one flag byte then the
    /// full inner value regardless of the flag. Widths are read off the
    /// actual declared field types, so a type change fails the tests below.
    fn maybe_calldata_declared_width(maybe: &CompactMaybe<EvmCalldata>) -> usize {
        size_of_val(&maybe.is_some)
            + size_of_val(&maybe.value.selector)
            + size_of_val(&maybe.value.no_words)
            + maybe.value.words.iter().map(size_of_val).sum::<usize>()
    }

    #[test]
    fn declaration_order_matches_the_preimage_order() {
        let record = minimal_record();
        assert_declaration_order(&record, &SIGN_BIDIRECTIONAL_RECORD_FIELDS);
        assert_declaration_order(&record.tx_params, &EVM_TYPE2_TX_PARAMS_FIELDS);
        assert_declaration_order(&record.tx_params.calldata, &COMPACT_MAYBE_FIELDS);
        assert_declaration_order(&record.tx_params.calldata.value, &EVM_CALLDATA_FIELDS);
        assert_declaration_order(&sample_access_list_entry(), &EVM_ACCESS_LIST_ENTRY_FIELDS);

        let notification = SignBidirectionalEventNotification {
            version: 1,
            payload: [0; 128],
        };
        assert_declaration_order(&notification, &SIGN_BIDIRECTIONAL_EVENT_NOTIFICATION_FIELDS);

        let key = SignetMapKey {
            count: 7,
            request_id: [0x22; 32],
        };
        assert_declaration_order(&key, &SIGNET_MAP_KEY_FIELDS);

        let signature = sample_signature();
        assert_declaration_order(&signature.big_r, &AFFINE_POINT_FIELDS);
        assert_declaration_order(&signature, &SIGNATURE_FIELDS);
        assert_declaration_order(
            &SignatureRespondedEvent {
                signature: signature.clone(),
            },
            &SIGNATURE_RESPONDED_EVENT_FIELDS,
        );
        assert_declaration_order(
            &RespondBidirectionalEvent {
                serialized_output: [0; 128],
                output_len: 32,
                signature,
            },
            &RESPOND_BIDIRECTIONAL_EVENT_FIELDS,
        );
    }

    #[test]
    fn order_traps_that_read_backwards_against_habit() {
        let record = minimal_record();
        let tx_fields = top_level_debug_fields(&format!("{:#?}", record.tx_params));
        let idx = |name: &str| {
            tx_fields
                .iter()
                .position(|field| field == name)
                .unwrap_or_else(|| panic!("field {name} missing from EvmType2TxParams"))
        };
        assert!(
            idx("max_priority_fee_per_gas") < idx("max_fee_per_gas"),
            "max_priority_fee_per_gas must be declared before max_fee_per_gas: the contract's payload order is the hash order and reads backwards against EVM habit"
        );
        assert!(
            idx("calldata") < idx("access_list_entry_count"),
            "calldata must be declared before the access-list pair: a reordering silently changes every request id"
        );

        let key = SignetMapKey {
            count: 7,
            request_id: [0x22; 32],
        };
        let key_fields = top_level_debug_fields(&format!("{key:#?}"));
        assert_eq!(
            key_fields,
            ["count", "request_id"],
            "SignetMapKey encodes count before request_id"
        );
    }

    /// Atom count and total preimage width implied by the record's declared
    /// field types and runtime capacities, walked in declaration order: one
    /// `size_of_val` entry per fixed-width atom, vector lengths for the two
    /// runtime-width schema fields. For `u8/u16/u64/u128` and `[u8; N]` the
    /// Rust size equals the declared atom width, so the totals come off the
    /// real types, never a retyped table. The sum is order-insensitive by
    /// construction; order is `declaration_order_matches_the_preimage_order`'s
    /// job.
    fn declared_layout(record: &SignBidirectionalRecord) -> (usize, usize) {
        let tx = &record.tx_params;
        let mut widths = vec![
            size_of_val(&record.sender),
            size_of_val(&record.request_nonce),
            size_of_val(&record.key_version),
            size_of_val(&record.path),
            size_of_val(&record.algo),
            size_of_val(&record.dest),
            size_of_val(&record.params),
            size_of_val(&record.tx_param_type),
            size_of_val(&tx.chain_id),
            size_of_val(&tx.nonce),
            size_of_val(&tx.max_priority_fee_per_gas),
            size_of_val(&tx.max_fee_per_gas),
            size_of_val(&tx.gas_limit),
            size_of_val(&tx.to),
            size_of_val(&tx.value),
            size_of_val(&tx.calldata.is_some),
            size_of_val(&tx.calldata.value.selector),
            size_of_val(&tx.calldata.value.no_words),
        ];
        widths.extend(tx.calldata.value.words.iter().map(size_of_val));
        widths.push(size_of_val(&tx.access_list_entry_count));
        for entry in &tx.access_list {
            widths.push(size_of_val(&entry.address));
            widths.push(size_of_val(&entry.storage_key_count));
            widths.extend(entry.storage_keys.iter().map(size_of_val));
        }
        widths.push(size_of_val(&record.caip2_id));
        widths.push(record.output_deserialization_schema.len());
        widths.push(record.respond_serialization_schema.len());
        (widths.len(), widths.iter().sum())
    }

    #[test]
    fn declared_widths_sum_to_the_runtime_layout() {
        // 23 atoms and 372 bytes are the runtime's own numbers for the
        // one-word capacity tier (tests/rid_vectors.json, minimal-1word:
        // preimage_atoms and preimage_bytes). Any scalar-width drift in the
        // record or its nested structs (key_version widened to u32, no_words
        // narrowed to u8, a resized byte array) moves the sum and fails here.
        let (atoms, bytes) = declared_layout(&minimal_record());
        assert_eq!(atoms, 23, "atom count drifted from the runtime layout");
        assert_eq!(
            bytes, 372,
            "declared width sum drifted from the runtime layout"
        );
    }

    #[test]
    fn compact_maybe_none_still_carries_a_full_capacity_value() {
        // An Option-based model would drop the inner value for None and emit
        // one byte instead of 1 + 4 + 2 + 32 = 39 at the one-word tier,
        // shortening the preimage and changing the request id of every
        // request without calldata.
        let none = CompactMaybe {
            is_some: false,
            value: EvmCalldata {
                selector: [0; 4],
                no_words: 0,
                words: vec![[0; 32]],
            },
        };
        assert!(!none.is_some);
        assert_eq!(
            none.value.words.len(),
            1,
            "the value stays at capacity even when is_some is false"
        );
        assert_eq!(maybe_calldata_declared_width(&none), 39);

        let some = minimal_record().tx_params.calldata;
        assert!(some.is_some);
        assert_eq!(
            maybe_calldata_declared_width(&none),
            maybe_calldata_declared_width(&some),
            "the flag must not change the emitted width"
        );
    }

    #[test]
    fn field_sets_are_exhaustive() {
        // Exhaustive patterns with no `..`: adding, removing, or renaming
        // any field is a compile error here. Together with the order test
        // this pins the exact ordered field list of every struct.
        let SignBidirectionalRecord {
            sender: _,
            request_nonce: _,
            key_version: _,
            path: _,
            algo: _,
            dest: _,
            params: _,
            tx_param_type: _,
            tx_params,
            caip2_id: _,
            output_deserialization_schema: _,
            respond_serialization_schema: _,
        } = minimal_record();
        let EvmType2TxParams {
            chain_id: _,
            nonce: _,
            max_priority_fee_per_gas: _,
            max_fee_per_gas: _,
            gas_limit: _,
            to: _,
            value: _,
            calldata,
            access_list_entry_count: _,
            access_list: _,
        } = tx_params;
        let CompactMaybe { is_some: _, value } = calldata;
        let EvmCalldata {
            selector: _,
            no_words: _,
            words: _,
        } = value;
        let EvmAccessListEntry {
            address: _,
            storage_key_count: _,
            storage_keys: _,
        } = sample_access_list_entry();
        let SignBidirectionalEventNotification {
            version: _,
            payload: _,
        } = SignBidirectionalEventNotification {
            version: 1,
            payload: [0; 128],
        };
        let SignetMapKey {
            count: _,
            request_id: _,
        } = SignetMapKey {
            count: 0,
            request_id: [0; 32],
        };
        let RespondBidirectionalEvent {
            serialized_output: _,
            output_len: _,
            signature,
        } = RespondBidirectionalEvent {
            serialized_output: [0; 128],
            output_len: 0,
            signature: sample_signature(),
        };
        let SignatureRespondedEvent { signature: _ } = SignatureRespondedEvent {
            signature: signature.clone(),
        };
        let Signature {
            big_r,
            s: _,
            recovery_id: _,
        } = signature;
        let AffinePoint { x: _, y: _ } = big_r;
    }
}
