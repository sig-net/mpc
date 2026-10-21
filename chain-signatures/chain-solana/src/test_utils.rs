//! Test-only JSON-RPC fixtures shared by the unit tests.

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
