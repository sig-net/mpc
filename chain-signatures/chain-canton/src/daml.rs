//! Typed structs for Daml contract payloads.
//!
//! These represent the JSON payloads inside `CreatedEvent.payload` for specific
//! Daml templates from `signet-signer-v1`. Derived from the `.daml` source files in
//! the `sig-net/canton` repository (`daml-packages/signet-signer-v1/daml/`).

use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::deserialize_number_from_string;

/// EIP-2930/EIP-1559 access-list entry from the Signer contract.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmAccessListEntry {
    pub address: String,
    #[serde(default)]
    pub storage_keys: Vec<String>,
}

/// EVM transaction parameters from the Signer contract.
/// Address fields are 40-char hex (20 bytes); numeric fields are 64-char hex.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmType2TransactionParams {
    pub chain_id: String,
    pub nonce: String,
    pub max_priority_fee_per_gas: String,
    pub max_fee_per_gas: String,
    pub gas_limit: String,
    pub to: Option<String>,
    pub value: String,
    #[serde(default)]
    pub calldata: String,
    #[serde(default)]
    pub access_list: Vec<EvmAccessListEntry>,
}

/// Daml variant: `data TxParams = EvmType2TxParams EvmType2TransactionParams`
/// Canton JSON API serializes as `{"tag": "EvmType2TxParams", "value": {...}}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub enum TxParams {
    EvmType2TxParams(EvmType2TransactionParams),
}

/// Payload of a `Signer:SignBidirectionalEvent` created event.
/// Emitted when `Signer.RequestSignature` is exercised.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignBidirectionalRequestedEvent {
    pub operators: Vec<String>,
    pub sender: String,
    pub requester: String,
    pub sig_network: String,
    pub tx_params: TxParams,
    pub caip2_id: String,
    /// Canton sends this as either a number or a string.
    #[serde(
        deserialize_with = "deserialize_number_from_string",
        serialize_with = "serialize_number_to_string"
    )]
    pub key_version: u32,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub output_deserialization_schema: String,
    pub respond_serialization_schema: String,
}

// Signature types
// ---------------------------------------------------------------------------
//
// Why DER encoding?
// Daml lacks byte-manipulation libraries, so we can't convert between signature
// formats on-ledger. The built-in `secp256k1WithEcdsaOnly` function requires
// DER-encoded signatures, so we use DER throughout the Canton ↔ MPC interface.
//
// Why a union type?
// Future-proofs for EdDSA (Solana, Sui) and Schnorr (Bitcoin Taproot) without
// changing the wire format. Each variant carries algorithm-specific data.
// ---------------------------------------------------------------------------

/// ECDSA signature with DER encoding and recovery ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcdsaSigData {
    /// DER-encoded (r, s) as hex string.
    pub der: String,
    /// Recovery ID (0 or 1) — y-parity for EVM ecrecover.
    /// Canton serializes Daml `Int` as a JSON string on outbound events.
    #[serde(
        deserialize_with = "deserialize_number_from_string",
        serialize_with = "serialize_number_to_string"
    )]
    pub recovery_id: u8,
}

/// Signature union type matching Daml's `Signature` (see Signer.daml).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub enum CantonSignature {
    EcdsaSig(EcdsaSigData),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureRespondedEventPayload {
    pub request_id: String,
    pub responder: String,
    pub signature: CantonSignature,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RespondBidirectionalEventPayload {
    pub request_id: String,
    pub responder: String,
    pub serialized_output: String,
    pub signature: CantonSignature,
}

fn serialize_number_to_string<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: std::fmt::Display,
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}
