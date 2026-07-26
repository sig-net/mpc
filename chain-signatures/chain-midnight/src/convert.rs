//! Conversion of a verified record into the chain-agnostic
//! [`IndexedSignRequest`] the signing pipeline consumes.
//!
//! The security-critical rule of this module: epsilon's requester comes from
//! the address the record was READ FROM, never from `record.sender`. A
//! caller controls every byte of the record and the map key in its own
//! ledger, so the request-id gate proves internal consistency and says
//! nothing about whether `sender` names the true caller; deriving from
//! record bytes would let a caller write another contract's address into
//! `sender` and obtain a signature under that contract's derived key. The
//! two are asserted equal and a mismatch drops the request.
//!
//! The signing payload is built ONLY via [`crate::tx::serialized_transaction`],
//! which routes through `to_unsigned_tx` and therefore inherits B5a's two
//! record-level gates (the eip155 caip2 agreement and the `tx_param_type`
//! check). Nothing here re-implements or bypasses them.

use borsh::{BorshDeserialize, BorshSerialize};
use mpc_chain_integration_core::utils::hashing::hash_payload;
use mpc_primitives::{
    Chain, IndexedSignRequest, SignArgs, SignBidirectionalEvent, SignId, LATEST_MPC_KEY_VERSION,
};

use crate::records::SignBidirectionalRecord;
use crate::tx::{payload_scalar, serialized_transaction};

/// `MPCSignatureAlgorithm::ecdsa`, the only real variant (1 is reserved).
const ALGO_ECDSA: u8 = 0;
/// `MPCDestination::unused`, the only real variant (1 is reserved).
const DEST_UNUSED: u8 = 0;

/// Chain context carried through the request for the respond path: the
/// central singleton contract the response must be posted to. Mirrors
/// `CantonChainCtx` (`chain-canton/src/signing.rs`), Borsh-encoded like it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "borsh")]
pub struct MidnightChainCtx {
    /// 64-hex address of the central singleton contract, no `0x` prefix.
    pub central_address: String,
}

/// Converts a verified record into the [`IndexedSignRequest`] the signing
/// pipeline consumes (kind `SignBidirectional`).
///
/// `read_address` is the caller-contract address the record was READ FROM
/// (the notification's raw 32 bytes), and it, never `record.sender`, is
/// what the epsilon requester is rendered from; the two are asserted equal
/// and a mismatch drops the request. Taking bytes rather than a string
/// keeps exactly ONE render site (`hex::encode`, lowercase unprefixed),
/// pinned against the node side's `sender_string` by the parity test in
/// `node/src/sign_bidirectional.rs`.
pub fn to_sign_request(
    record: &SignBidirectionalRecord,
    read_address: &[u8; 32],
    central_address: &str,
    request_id: [u8; 32],
    indexed_ts: u64,
) -> anyhow::Result<IndexedSignRequest> {
    // The security gate, first: `sender` is caller-controlled record data,
    // so it may only CONFIRM the read address, never substitute for it.
    anyhow::ensure!(
        record.sender == *read_address,
        "record sender {} does not match the address it was read from {}: dropping the request",
        hex::encode(record.sender),
        hex::encode(read_address),
    );

    let key_version = u32::from(record.key_version);
    anyhow::ensure!(
        (1..=LATEST_MPC_KEY_VERSION).contains(&key_version),
        "unsupported key_version {key_version}: valid versions are 1..={LATEST_MPC_KEY_VERSION}"
    );
    let algo = match record.algo {
        ALGO_ECDSA => "ecdsa".to_string(),
        reserved => anyhow::bail!("unsupported algo {reserved}: only ecdsa (0) is real"),
    };
    let dest = match record.dest {
        DEST_UNUSED => String::new(),
        reserved => anyhow::bail!("unsupported dest {reserved}: only unused (0) is real"),
    };

    let path = render_padded_ascii(&record.path, "path")?;
    let caip2_id = render_padded_ascii(&record.caip2_id, "caip2_id")?;
    let params = render_padded_ascii(&record.params, "params")?;

    // The payload comes ONLY from B5a's gated path: `serialized_transaction`
    // routes through `to_unsigned_tx`, inheriting the caip2 agreement and
    // tx_param_type gates. Building it any other way would bypass them.
    let serialized = serialized_transaction(record)?;
    let payload = payload_scalar(&serialized)?;

    // The one render of the requester. The node side re-renders the event's
    // sender with the same `hex::encode` in `sender_string`; the parity test
    // pins the two against each other through the derivation.
    let requester = hex::encode(read_address);
    let epsilon = mpc_crypto::kdf::derive_epsilon_midnight(key_version, &requester, &path);
    let entropy = hash_payload(&request_id);
    // central_address is carried VERBATIM, and verbatim is canonical: B6's
    // decision made validate() REJECT non-lowercase central addresses, so
    // exactly one representation reaches every comparison site and no
    // normalisation belongs here.
    let chain_ctx = Some(
        borsh::to_vec(&MidnightChainCtx {
            central_address: central_address.to_string(),
        })
        .expect("MidnightChainCtx Borsh serialization is infallible"),
    );

    Ok(IndexedSignRequest::sign_bidirectional(
        SignId::new(request_id),
        SignArgs {
            entropy,
            epsilon,
            payload,
            path: path.clone(),
            key_version,
        },
        Chain::Midnight,
        indexed_ts,
        SignBidirectionalEvent {
            sender: *read_address,
            serialized_transaction: serialized,
            caip2_id,
            key_version,
            deposit: 0,
            path,
            algo,
            dest,
            params,
            output_deserialization_schema: record.output_deserialization_schema.clone(),
            respond_serialization_schema: record.respond_serialization_schema.clone(),
            chain: Chain::Midnight,
            chain_ctx,
        },
    ))
}

/// The `pad(N, "text")` convention every string-ish record field uses:
/// trailing NULs are padding and are trimmed; what remains must be UTF-8
/// with no interior NULs, else the request fails loudly with the field
/// named.
///
/// Decision D2, CLOSED, for `path` specifically: render it as NUL-trimmed
/// ASCII, failing closed. Never lossy, never a hex fallback, never content
/// sniffing: if the contract team later moves to raw identity-commitment
/// paths, those bytes are not valid UTF-8 and the node errors visibly
/// instead of silently deriving a different key. The chosen rendering is
/// anchored by the only executed derivation in the ecosystem (the caller
/// e2e stores `asciiPadded("caller-path", 32)` and derives from the literal
/// `"caller-path"`), pinned by the A9 epsilon golden.
fn render_padded_ascii(bytes: &[u8], field: &str) -> anyhow::Result<String> {
    let trimmed_len = bytes.len() - bytes.iter().rev().take_while(|byte| **byte == 0).count();
    let trimmed = &bytes[..trimmed_len];
    anyhow::ensure!(
        !trimmed.contains(&0),
        "{field} has an interior NUL: {}",
        hex::encode(bytes)
    );
    String::from_utf8(trimmed.to_vec()).map_err(|err| {
        anyhow::anyhow!("{field} is not valid UTF-8 ({err}): {}", hex::encode(bytes))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{CompactMaybe, EvmCalldata, EvmType2TxParams, SignBidirectionalRecord};
    use mpc_chain_integration_core::utils::hashing::hash_payload;
    use mpc_primitives::{Chain, SignId, SignKind};

    /// The A9 oracle fixture: the `e2e-caller-path` vector is the only
    /// end-to-end proven Midnight derivation in the ecosystem, and this
    /// record is built to its exact `(sender, path)` so the full
    /// record-to-epsilon chain pins against the oracle scalar.
    const EPSILON_VECTORS_JSON: &str = include_str!("../../crypto/tests/epsilon_vectors.json");

    const READ_ADDRESS: [u8; 32] = [0xab; 32];
    const REQUEST_ID: [u8; 32] = [0x77; 32];
    const INDEXED_TS: u64 = 1_753_000_000;

    fn central_address() -> String {
        "12".repeat(32)
    }

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

    /// A record shaped after the caller e2e: sender `0xab * 32`, path
    /// `"caller-path"`, one used calldata word, no access list.
    fn caller_record() -> SignBidirectionalRecord {
        SignBidirectionalRecord {
            sender: READ_ADDRESS,
            request_nonce: 7,
            key_version: 1,
            path: ascii_padded(b"caller-path"),
            algo: 0,
            dest: 0,
            params: ascii_padded(b"integrator-params"),
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

    /// The `(sender, path, epsilon_be)` triple of a named oracle vector.
    fn epsilon_vector(name: &str) -> (String, String, Vec<u8>) {
        let file: serde_json::Value =
            serde_json::from_str(EPSILON_VECTORS_JSON).expect("epsilon_vectors.json parses");
        let vector = file["vectors"]
            .as_array()
            .expect("fixture has a vectors array")
            .iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("no epsilon vector named {name}"));
        (
            vector["sender"].as_str().expect("sender").to_string(),
            vector["path"].as_str().expect("path").to_string(),
            hex::decode(vector["epsilon_be_hex"].as_str().expect("epsilon_be_hex"))
                .expect("epsilon_be_hex decodes"),
        )
    }

    #[test]
    fn full_chain_epsilon_and_args_match_the_oracle() {
        let record = caller_record();
        let request = to_sign_request(
            &record,
            &READ_ADDRESS,
            &central_address(),
            REQUEST_ID,
            INDEXED_TS,
        )
        .expect("the caller record converts");

        // The absolute anchor: this record was built to the oracle vector's
        // exact (sender, path), so the epsilon out of the FULL chain must be
        // the TS-generated scalar, not merely self-consistent.
        let (sender, path, epsilon_be) = epsilon_vector("e2e-caller-path");
        assert_eq!(
            sender,
            "ab".repeat(32),
            "fixture sanity: the vector's sender"
        );
        assert_eq!(path, "caller-path", "fixture sanity: the vector's path");
        assert_eq!(
            request.args.epsilon.to_bytes().as_slice(),
            epsilon_be.as_slice(),
            "record-to-epsilon must reproduce the oracle scalar"
        );

        assert_eq!(request.args.path, "caller-path");
        assert_eq!(request.args.key_version, 1);
        assert_eq!(request.args.entropy, hash_payload(&REQUEST_ID));
        assert_eq!(
            request.args.payload,
            payload_scalar(&serialized_transaction(&record).expect("assembles"))
                .expect("payload scalar"),
        );
        assert_eq!(request.chain, Chain::Midnight);
        assert_eq!(request.id, SignId::new(REQUEST_ID));
        assert_eq!(request.unix_timestamp_indexed, INDEXED_TS);
        assert!(
            matches!(request.kind, SignKind::SignBidirectional(_)),
            "the indexed kind is SignBidirectional"
        );
    }

    #[test]
    fn every_event_field_maps_per_the_table() {
        let record = caller_record();
        let request = to_sign_request(
            &record,
            &READ_ADDRESS,
            &central_address(),
            REQUEST_ID,
            INDEXED_TS,
        )
        .expect("the caller record converts");
        let SignKind::SignBidirectional(event) = request.kind else {
            panic!("expected SignBidirectional kind");
        };

        assert_eq!(
            event.serialized_transaction,
            serialized_transaction(&record).expect("assembles"),
            "the payload comes from B5a's gated path"
        );
        assert_eq!(event.caip2_id, "eip155:31337");
        assert_eq!(event.key_version, 1);
        assert_eq!(event.deposit, 0, "Midnight V1 has no payment");
        assert_eq!(event.path, "caller-path");
        assert_eq!(event.algo, "ecdsa");
        assert_eq!(event.dest, "", "dest 0 is `unused`, rendered empty");
        assert_eq!(event.params, "integrator-params");
        assert_eq!(
            event.output_deserialization_schema,
            record.output_deserialization_schema
        );
        assert_eq!(
            event.respond_serialization_schema,
            record.respond_serialization_schema
        );
        assert_eq!(event.chain, Chain::Midnight);
        assert_eq!(
            event.chain_ctx,
            Some(
                borsh::to_vec(&MidnightChainCtx {
                    central_address: central_address(),
                })
                .expect("borsh serializes")
            ),
        );
    }

    #[test]
    fn read_address_mismatch_drops() {
        // The security gate: a record whose `sender` differs from the
        // address it was read from must be dropped, because `sender` is
        // caller-controlled and the derived key space follows the requester.
        let record = caller_record();
        let elsewhere = [0xcd; 32];
        let err = to_sign_request(
            &record,
            &elsewhere,
            &central_address(),
            REQUEST_ID,
            INDEXED_TS,
        )
        .expect_err("a sender mismatch must drop the request")
        .to_string();
        assert!(
            err.contains(&"ab".repeat(32)) && err.contains(&"cd".repeat(32)),
            "the drop must name both addresses, got: {err}"
        );
    }

    #[test]
    fn reserved_enums_and_bad_key_versions_are_rejected() {
        let mut record = caller_record();
        record.algo = 1;
        let err = to_sign_request(
            &record,
            &READ_ADDRESS,
            &central_address(),
            REQUEST_ID,
            INDEXED_TS,
        )
        .expect_err("the reserved algo must be rejected")
        .to_string();
        assert!(err.contains("algo"), "err: {err}");

        let mut record = caller_record();
        record.dest = 1;
        let err = to_sign_request(
            &record,
            &READ_ADDRESS,
            &central_address(),
            REQUEST_ID,
            INDEXED_TS,
        )
        .expect_err("the reserved dest must be rejected")
        .to_string();
        assert!(err.contains("dest"), "err: {err}");

        let mut record = caller_record();
        record.key_version = 0;
        let err = to_sign_request(
            &record,
            &READ_ADDRESS,
            &central_address(),
            REQUEST_ID,
            INDEXED_TS,
        )
        .expect_err("key_version 0 must be rejected")
        .to_string();
        assert!(err.contains("key_version"), "err: {err}");

        let mut record = caller_record();
        record.key_version = 2;
        let err = to_sign_request(
            &record,
            &READ_ADDRESS,
            &central_address(),
            REQUEST_ID,
            INDEXED_TS,
        )
        .expect_err("a key_version above LATEST must be rejected")
        .to_string();
        assert!(err.contains("key_version"), "err: {err}");
    }

    #[test]
    fn path_render_fails_closed() {
        // D2's contract: NUL-trimmed ASCII, never lossy, never a hex
        // fallback. If the contract team moves to raw identity-commitment
        // paths those bytes are not valid UTF-8, and the node must error
        // visibly instead of silently deriving a different key.
        assert_eq!(
            render_padded_ascii(&ascii_padded::<32>(b"caller-path"), "path")
                .expect("ascii renders"),
            "caller-path"
        );
        // The oracle's empty-path vector derives with "", so all-NUL is legal.
        assert_eq!(
            render_padded_ascii(&[0u8; 32], "path").expect("empty renders"),
            ""
        );

        let err = render_padded_ascii(&[0xff; 32], "path")
            .expect_err("non-UTF-8 path bytes must fail closed")
            .to_string();
        assert!(err.contains("path"), "err: {err}");

        let err = render_padded_ascii(&ascii_padded::<32>(b"a\0b"), "path")
            .expect_err("an interior NUL must fail closed")
            .to_string();
        assert!(err.contains("interior NUL"), "err: {err}");
    }

    #[test]
    fn padded_ascii_fields_fail_closed_uniformly() {
        // caip2_id and params follow the same pad(N, "text") convention as
        // path (constants.ts documents it for every string-ish field), so
        // they render through the same fail-closed rule, each named in its
        // error.
        let mut record = caller_record();
        record.caip2_id = [0xff; 32];
        let err = to_sign_request(
            &record,
            &READ_ADDRESS,
            &central_address(),
            REQUEST_ID,
            INDEXED_TS,
        )
        .expect_err("non-UTF-8 caip2 bytes must fail closed")
        .to_string();
        assert!(err.contains("caip2_id"), "err: {err}");

        let mut record = caller_record();
        record.params = ascii_padded(b"p\0q");
        let err = to_sign_request(
            &record,
            &READ_ADDRESS,
            &central_address(),
            REQUEST_ID,
            INDEXED_TS,
        )
        .expect_err("interior-NUL params must fail closed")
        .to_string();
        assert!(err.contains("params"), "err: {err}");
    }
}
