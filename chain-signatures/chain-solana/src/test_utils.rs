//! Test-only fixtures shared by the unit tests.

use signet_program::SignBidirectionalEvent;

/// One `SignBidirectionalRequested` Anchor CPI event, base58-encoded as an
/// inner-instruction payload targeting `caip2_id`.

/// One entry of a `getSignaturesForAddress` response.
pub(crate) fn signature_entry(slot: u64, sig: &str) -> serde_json::Value {
    serde_json::json!({
        "signature": sig,
        "slot": slot,
        "err": null,
        "memo": null,
        "blockTime": null,
        "confirmationStatus": "confirmed"
    })
}

/// [`signature_entry`] with a fresh unique signature.
pub(crate) fn unique_signature_entry(slot: u64) -> serde_json::Value {
    signature_entry(
        slot,
        &solana_sdk::signature::Signature::new_unique().to_string(),
    )
}

/// A full `getSignaturesForAddress` JSON-RPC response body.
pub(crate) fn signatures_response(entries: &[serde_json::Value]) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": entries
    })
    .to_string()
}

pub(crate) fn sign_bidirectional_ix_data(caip2_id: &str) -> String {
    let event = SignBidirectionalEvent {
        sender: solana_sdk::pubkey::Pubkey::new_from_array([0x11; 32]),
        serialized_transaction: vec![1, 2, 3],
        caip2_id: caip2_id.to_string(),
        key_version: 0,
        deposit: 0,
        path: "path".to_string(),
        algo: "secp256k1".to_string(),
        dest: "dest".to_string(),
        params: String::new(),
        program_id: solana_sdk::pubkey::Pubkey::new_from_array([0x22; 32]),
        output_deserialization_schema: vec![],
        respond_serialization_schema: vec![],
    };
    let mut data = anchor_lang::event::EVENT_IX_TAG_LE.to_vec();
    data.extend(anchor_lang::Event::data(&event));
    solana_sdk::bs58::encode(data).into_string()
}
