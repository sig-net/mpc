//! Conversion of a verified record into the chain-agnostic [`IndexedSignRequest`] the
//! signing pipeline consumes.
//!
//! Epsilon's requester comes from the address the record was read from, never
//! from `record.sender`, which is caller-controlled: deriving from record bytes
//! would let a caller sign under another contract's key. The two are asserted
//! equal.

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

/// Converts a verified record into the [`IndexedSignRequest`] the signing pipeline
/// consumes (kind `SignBidirectional`).
pub fn generate_sign_request(
    record: &SignBidirectionalRecord,
    read_address: &[u8; 32],
    request_id: [u8; 32],
    indexed_ts: u64,
) -> anyhow::Result<IndexedSignRequest> {
    // The security gate, first: `sender` is caller-controlled record data, so it may
    // only confirm the read address, never substitute for it.
    anyhow::ensure!(
        record.sender == *read_address,
        "record sender {} does not match the address it was read from {}: dropping the request",
        hex::encode(record.sender),
        hex::encode(read_address),
    );

    // Upper bound only, matching Canton: version 0 is accepted and selects the legacy
    // comma-format derivation in `mpc_crypto::kdf`.
    let key_version = u32::from(record.key_version);
    anyhow::ensure!(
        key_version <= LATEST_MPC_KEY_VERSION,
        "unsupported key_version {key_version}: the latest is {LATEST_MPC_KEY_VERSION}"
    );
    let algo = match record.algo {
        ALGO_ECDSA => "ecdsa".to_string(),
        reserved => anyhow::bail!("unsupported algo {reserved}: only ecdsa (0) is real"),
    };
    let dest = match record.dest {
        DEST_UNUSED => String::new(),
        reserved => anyhow::bail!("unsupported dest {reserved}: only unused (0) is real"),
    };

    // The contract declares path as 32 opaque bytes (a raw commitment is the common
    // case), so the rendering must accept any of them: full-width lowercase hex, never
    // trimmed, or `0xab..00` and `0xab..` would derive the same key.
    let path = hex::encode(record.path);
    let caip2_id = render_padded_ascii(&record.caip2_id, "caip2_id")?;
    anyhow::ensure!(
        record.params == [0u8; 64],
        "params is reserved and must be blank, got {}",
        hex::encode(record.params)
    );

    // Only via the gated path: `serialized_transaction` routes through `to_unsigned_tx`
    // and inherits its gates.
    let serialized = serialized_transaction(record)?;
    let payload = payload_scalar(&serialized)?;

    // The one render of the requester.
    let requester = hex::encode(read_address);
    let epsilon = mpc_crypto::kdf::derive_epsilon_midnight(key_version, &requester, &path);
    let entropy = hash_payload(&request_id);

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
            params: String::new(),
            output_deserialization_schema: record.output_deserialization_schema.clone(),
            respond_serialization_schema: record.respond_serialization_schema.clone(),
            chain: Chain::Midnight,
            chain_ctx: None,
        },
    ))
}

/// The `pad(N, "text")` convention `caip2_id` uses: trailing NULs are padding and are
/// trimmed, and what remains must be UTF-8 with no interior NULs.
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
    use crate::records::SignBidirectionalRecord;
    use crate::test_utils::ascii_padded;
    use mpc_primitives::{Chain, SignKind};

    const READ_ADDRESS: [u8; 32] = [0xab; 32];
    const REQUEST_ID: [u8; 32] = [0x77; 32];
    const INDEXED_TS: u64 = 1_753_000_000;

    fn caller_record() -> SignBidirectionalRecord {
        crate::test_utils::sample_record()
    }

    #[test]
    fn generate_sign_request_maps_every_event_field() {
        let record = caller_record();
        let request = generate_sign_request(&record, &READ_ADDRESS, REQUEST_ID, INDEXED_TS)
            .expect("the caller record converts");
        let SignKind::SignBidirectional(event) = request.kind else {
            panic!("expected SignBidirectional kind");
        };

        assert_eq!(
            event.serialized_transaction,
            crate::tx::serialized_transaction(&record).expect("assembles"),
            "the event carries the record's own unsigned transaction bytes"
        );
        assert_eq!(event.caip2_id, "eip155:31337");
        assert_eq!(event.key_version, 1);
        assert_eq!(event.deposit, 0, "Midnight V1 has no payment");
        assert_eq!(
            event.path, "63616c6c65722d70617468000000000000000000000000000000000000000000",
            "the full 32 path bytes as lowercase hex, padding included"
        );
        assert_eq!(
            event.output_deserialization_schema,
            record.output_deserialization_schema
        );
        assert_eq!(
            event.respond_serialization_schema,
            record.respond_serialization_schema
        );
        assert_eq!(event.params, "", "params is reserved and travels blank");
        assert_eq!(event.chain, Chain::Midnight);
        assert_eq!(
            event.chain_ctx, None,
            "the respond target is config, so the request carries no per-chain blob"
        );
    }

    #[test]
    fn generate_sign_request_rejects_read_address_mismatch() {
        // The security gate: a record whose `sender` differs from the address it was
        // read from must be dropped, because `sender` is caller-controlled and the
        // derived key space follows the requester.
        let record = caller_record();
        let elsewhere = [0xcd; 32];
        let err = generate_sign_request(&record, &elsewhere, REQUEST_ID, INDEXED_TS)
            .expect_err("a sender mismatch must drop the request")
            .to_string();
        assert!(
            err.contains(&"ab".repeat(32)) && err.contains(&"cd".repeat(32)),
            "the drop must name both addresses, got: {err}"
        );
    }

    #[test]
    fn generate_sign_request_routes_and_bounds_key_versions() {
        // Version 0 is accepted, matching Canton, and routes through the legacy
        // derivation rather than the v2 caip2 one.
        let mut record = caller_record();
        record.key_version = 0;
        let legacy = generate_sign_request(&record, &READ_ADDRESS, REQUEST_ID, INDEXED_TS)
            .expect("key_version 0 is accepted");
        assert_eq!(
            legacy.args.epsilon,
            mpc_crypto::kdf::derive_epsilon_midnight(
                0,
                &"ab".repeat(32),
                &hex::encode(record.path)
            ),
            "version 0 must route through the legacy derivation"
        );

        let mut record = caller_record();
        record.key_version = 2;
        let err = generate_sign_request(&record, &READ_ADDRESS, REQUEST_ID, INDEXED_TS)
            .expect_err("a key_version above LATEST must be rejected")
            .to_string();
        assert!(err.contains("key_version"), "err: {err}");
    }

    #[test]
    fn generate_sign_request_hex_encodes_opaque_paths() {
        // A raw commitment hash is the common path; it must convert, not drop.
        let mut record = caller_record();
        record.path = [0xff; 32];
        let request = generate_sign_request(&record, &READ_ADDRESS, REQUEST_ID, INDEXED_TS)
            .expect("opaque path bytes convert");
        assert_eq!(request.args.path, "ff".repeat(32));

        // No trimming: an all-NUL path is 64 zeros, distinct from any trimmed twin.
        let mut record = caller_record();
        record.path = [0u8; 32];
        let request = generate_sign_request(&record, &READ_ADDRESS, REQUEST_ID, INDEXED_TS)
            .expect("all-NUL path converts");
        assert_eq!(request.args.path, "00".repeat(32));
    }

    #[test]
    fn render_padded_ascii_gates_caip2() {
        assert_eq!(
            render_padded_ascii(&ascii_padded::<32>(b"eip155:1"), "caip2_id").expect("renders"),
            "eip155:1"
        );
        for bytes in [[0xff; 32], ascii_padded::<32>(b"a\0b")] {
            let err = render_padded_ascii(&bytes, "caip2_id")
                .expect_err("malformed caip2 bytes must fail closed")
                .to_string();
            assert!(err.contains("caip2_id"), "err: {err}");
        }
    }

    #[test]
    fn generate_sign_request_requires_blank_params() {
        let mut record = caller_record();
        record.params[0] = 1;
        let err = generate_sign_request(&record, &READ_ADDRESS, REQUEST_ID, INDEXED_TS)
            .expect_err("params is reserved: non-blank bytes must fail closed")
            .to_string();
        assert!(err.contains("params"), "err: {err}");
    }
}
