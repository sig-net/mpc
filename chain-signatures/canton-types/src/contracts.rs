//! Typed structs for Daml contract payloads.
//!
//! These represent the JSON payloads inside `CreatedEvent.payload` for specific
//! Daml templates from `daml-signer` and `daml-vault`. Derived from the `.daml`
//! source files in `canton-mpc-poc/daml-packages/`.
//!
//! All fields are raw JSON types (strings). Conversion to internal types
//! (e.g., hex → `[u8; 32]`, DER → `Signature`) is the consumer's responsibility.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// From daml-vault/daml/Erc20Vault.daml — EvmTransactionParams record
// ---------------------------------------------------------------------------

/// EVM transaction parameters passed through the Vault contract.
/// All fields are hex-encoded strings (padded to 64 chars).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmTransactionParams {
    pub to: String,
    pub function_signature: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub value: String,
    pub nonce: String,
    pub gas_limit: String,
    pub max_fee_per_gas: String,
    /// Daml field name is `maxPriorityFee` (NOT `maxPriorityFeePerGas`).
    pub max_priority_fee: String,
    pub chain_id: String,
}

// ---------------------------------------------------------------------------
// From daml-signer/daml/Signer.daml — SignBidirectionalEvent
// ---------------------------------------------------------------------------

/// Payload of a `Signer:SignBidirectionalEvent` created event.
/// Emitted when a Vault exercises `RequestDeposit` → `Signer.SignBidirectional`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignBidirectionalRequestedEvent {
    pub operators: Vec<String>,
    pub sender: String,
    pub requester: String,
    pub sig_network: String,
    pub evm_tx_params: EvmTransactionParams,
    pub caip2_id: String,
    /// Canton sends this as either a number or a string.
    #[serde(deserialize_with = "deserialize_u32_lenient")]
    pub key_version: u32,
    pub path: String,
    pub algo: String,
    pub dest: String,
    #[serde(default)]
    pub params: String,
    pub nonce_cid_text: String,
    #[serde(default)]
    pub output_deserialization_schema: String,
    #[serde(default)]
    pub respond_serialization_schema: String,
}


// ---------------------------------------------------------------------------
// From daml-signer/daml/Signer.daml — SignatureRespondedEvent
// ---------------------------------------------------------------------------

/// Raw payload of a `Signer:SignatureRespondedEvent` created event.
/// Fields are hex strings; conversion to `[u8; 32]` / `Signature` is the
/// consumer's responsibility (avoiding a dependency on `mpc-primitives`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureRespondedEventPayload {
    /// Hex-encoded 32-byte request ID.
    pub request_id: String,
    pub responder: String,
    /// DER-encoded hex signature.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// From daml-signer/daml/Signer.daml — RespondBidirectionalEvent
// ---------------------------------------------------------------------------

/// Raw payload of a `Signer:RespondBidirectionalEvent` created event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RespondBidirectionalEventPayload {
    /// Hex-encoded 32-byte request ID.
    pub request_id: String,
    pub responder: String,
    /// Hex-encoded serialized output from the destination chain.
    pub serialized_output: String,
    /// DER-encoded hex signature.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deserialize a u32 from either a JSON number or a JSON string.
fn deserialize_u32_lenient<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct U32Visitor;
    impl<'de> de::Visitor<'de> for U32Visitor {
        type Value = u32;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a u32 as number or string")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u32, E> {
            u32::try_from(v).map_err(|_| E::custom(format!("u32 overflow: {v}")))
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<u32, E> {
            u32::try_from(v).map_err(|_| E::custom(format!("u32 overflow: {v}")))
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<u32, E> {
            if v.fract() != 0.0 || v < 0.0 || v > u32::MAX as f64 {
                return Err(E::custom(format!("invalid u32 float: {v}")));
            }
            Ok(v as u32)
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u32, E> {
            v.parse().map_err(|_| E::custom(format!("invalid u32 string: {v}")))
        }
    }
    deserializer.deserialize_any(U32Visitor)
}
