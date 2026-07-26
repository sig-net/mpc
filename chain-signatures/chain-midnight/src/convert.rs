//! Conversion of a verified record into the chain-agnostic
//! [`IndexedSignRequest`] the signing pipeline consumes.
//!
//! The security-critical rule: epsilon's requester comes from the address the
//! record was read from, never from `record.sender`. A caller controls every
//! byte of its own ledger, so the request-id gate proves internal consistency
//! and says nothing about whether `sender` names the true caller. Deriving from
//! record bytes would let a caller write another contract's address into
//! `sender` and sign under that contract's key. The two are asserted equal.
//!
//! The payload is built only via [`crate::tx::serialized_transaction`], which
//! routes through `to_unsigned_tx` and so inherits its caip2 and
//! `tx_param_type` gates. Nothing here reimplements or bypasses them.

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

/// Chain context carried through the request for the respond path: the central
/// singleton the response must be posted to. Mirrors `CantonChainCtx`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "borsh")]
pub struct MidnightChainCtx {
    /// 64-hex address of the central singleton contract, no `0x` prefix.
    pub central_address: String,
}

/// Converts a verified record into the [`IndexedSignRequest`] the signing
/// pipeline consumes (kind `SignBidirectional`).
///
/// `read_address` is the caller-contract address the record was read from, the
/// notification's raw 32 bytes, and it rather than `record.sender` is what the
/// epsilon requester is rendered from. Taking bytes rather than a string keeps
/// exactly one render site, lowercase unprefixed hex, pinned against the node's
/// `sender_string` by the parity test in `node/src/sign_bidirectional.rs`.
pub fn to_sign_request(
    record: &SignBidirectionalRecord,
    read_address: &[u8; 32],
    central_address: &str,
    request_id: [u8; 32],
    indexed_ts: u64,
) -> anyhow::Result<IndexedSignRequest> {
    // The security gate, first: `sender` is caller-controlled record data, so
    // it may only confirm the read address, never substitute for it.
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

    // Only via the gated path: `serialized_transaction` routes through
    // `to_unsigned_tx` and inherits its gates. Any other route bypasses them.
    let serialized = serialized_transaction(record)?;
    let payload = payload_scalar(&serialized)?;

    // The one render of the requester. The node re-renders the event's sender
    // with the same `hex::encode`; the parity test pins the two through the
    // derivation.
    let requester = hex::encode(read_address);
    let epsilon = mpc_crypto::kdf::derive_epsilon_midnight(key_version, &requester, &path);
    let entropy = hash_payload(&request_id);
    // Verbatim is canonical: `validate()` rejects non-lowercase central
    // addresses, so one representation reaches every comparison site and no
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

/// The `pad(N, "text")` convention every string-ish record field uses: trailing
/// NULs are padding and are trimmed, and what remains must be UTF-8 with no
/// interior NULs.
///
/// Fails closed, never lossy and never a hex fallback. If the contract team
/// moves to raw identity-commitment paths those bytes are not valid UTF-8, and
/// the node must error visibly rather than silently derive a different key.
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

    /// Oracle fixture. `e2e-caller-path` is the only end-to-end proven Midnight
    /// derivation in the ecosystem, and the record below is built to its exact
    /// `(sender, path)`, so the whole record-to-epsilon chain pins against it.
    const EPSILON_VECTORS_JSON: &str = include_str!("../../crypto/tests/epsilon_vectors.json");
    const TX_VECTORS_JSON: &str = include_str!("../tests/tx_vectors.json");

    fn tx_vector_field(name: &str, field: &str) -> String {
        let file: serde_json::Value =
            serde_json::from_str(TX_VECTORS_JSON).expect("tx_vectors.json parses");
        file["vectors"]
            .as_array()
            .expect("fixture has a vectors array")
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap_or_else(|| panic!("no tx vector named {name}"))[field]
            .as_str()
            .unwrap_or_else(|| panic!("{field} is a string"))
            .trim_start_matches("0x")
            .to_string()
    }

    fn oracle_serialized(name: &str) -> String {
        tx_vector_field(name, "expected_unsigned_serialized_hex")
    }

    /// The scalar the MPC signs for a named oracle vector.
    fn oracle_scalar(name: &str) -> k256::Scalar {
        use mpc_primitives::ScalarExt as _;
        let hash: [u8; 32] = hex::decode(tx_vector_field(name, "expected_unsigned_hash_hex"))
            .expect("oracle hash decodes")
            .try_into()
            .expect("oracle hash is 32 bytes");
        k256::Scalar::from_bytes(hash).expect("oracle hash is in range")
    }

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
    fn to_sign_request_matches_epsilon_oracle() {
        let record = caller_record();
        let request = to_sign_request(
            &record,
            &READ_ADDRESS,
            &central_address(),
            REQUEST_ID,
            INDEXED_TS,
        )
        .expect("the caller record converts");

        // The record was built to the vector's exact (sender, path), so the
        // epsilon out of the full chain must be the TS-generated scalar rather
        // than merely self-consistent.
        let (_, _, epsilon_be) = epsilon_vector("e2e-caller-path");
        assert_eq!(
            request.args.epsilon.to_bytes().as_slice(),
            epsilon_be.as_slice(),
            "record-to-epsilon must reproduce the oracle scalar"
        );

        assert_eq!(request.args.path, "caller-path");
        assert_eq!(request.args.key_version, 1);
        assert_eq!(request.args.entropy, hash_payload(&REQUEST_ID));
        // Against the oracle rather than by re-running the production path:
        // caller_record() matches the minimal-1word vector in every field that
        // reaches the transaction, differing only in `params`, which does not.
        assert_eq!(
            request.args.payload,
            oracle_scalar("minimal-1word"),
            "the signed payload must be the oracle's hash, not merely self-consistent"
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
    fn to_sign_request_maps_every_event_field() {
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
            hex::encode(&event.serialized_transaction),
            oracle_serialized("minimal-1word"),
            "the event carries the oracle's unsigned transaction bytes"
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
    fn to_sign_request_rejects_read_address_mismatch() {
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
    fn to_sign_request_rejects_reserved_enums_and_key_versions() {
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
    fn render_padded_ascii_rejects_non_utf8_path() {
        // NUL-trimmed ASCII, never lossy and never a hex fallback. If the
        // contract team moves to raw identity-commitment paths those bytes are
        // not valid UTF-8, and the node must error visibly instead of silently
        // deriving a different key.
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
    fn render_padded_ascii_rejects_every_malformed_field() {
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
