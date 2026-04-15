//! Typed structs for Daml contract payloads.
//!
//! These represent the JSON payloads inside `CreatedEvent.payload` for specific
//! Daml templates from `daml-signer` and `daml-evm-types`. Derived from the
//! `.daml` source files in `canton-mpc-poc/daml-packages/`.

use alloy::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

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

impl EvmTransactionParams {
    /// Canton pads addresses to 64 hex chars (32 bytes) — extracts the last 20 bytes.
    pub fn parse_to_address(&self) -> Address {
        let bytes = hex::decode(&self.to).unwrap_or_default();
        let start = bytes.len().saturating_sub(20);
        Address::from_slice(&bytes[start..])
    }

    pub fn parse_value(&self) -> U256 {
        U256::from_str_radix(&self.value, 16).unwrap_or(U256::ZERO)
    }

    pub fn parse_nonce(&self) -> u64 {
        u64::from_str_radix(&self.nonce, 16).unwrap_or(0)
    }

    pub fn parse_gas_limit(&self) -> u64 {
        u64::from_str_radix(&self.gas_limit, 16).unwrap_or(0)
    }

    pub fn parse_max_fee_per_gas(&self) -> u128 {
        u128::from_str_radix(&self.max_fee_per_gas, 16).unwrap_or(0)
    }

    pub fn parse_max_priority_fee(&self) -> u128 {
        u128::from_str_radix(&self.max_priority_fee, 16).unwrap_or(0)
    }

    pub fn parse_chain_id(&self) -> u64 {
        u64::from_str_radix(&self.chain_id, 16).unwrap_or(0)
    }

    pub fn parse_value_u256(&self) -> U256 {
        self.parse_value()
    }

    pub fn parse_nonce_u256(&self) -> U256 {
        U256::from_str_radix(&self.nonce, 16).unwrap_or(U256::ZERO)
    }

    pub fn parse_gas_limit_u256(&self) -> U256 {
        U256::from_str_radix(&self.gas_limit, 16).unwrap_or(U256::ZERO)
    }

    pub fn parse_max_fee_per_gas_u256(&self) -> U256 {
        U256::from_str_radix(&self.max_fee_per_gas, 16).unwrap_or(U256::ZERO)
    }

    pub fn parse_max_priority_fee_u256(&self) -> U256 {
        U256::from_str_radix(&self.max_priority_fee, 16).unwrap_or(U256::ZERO)
    }

    pub fn parse_chain_id_u256(&self) -> U256 {
        U256::from_str_radix(&self.chain_id, 16).unwrap_or(U256::ZERO)
    }
}

/// Daml variant: `data TxParams = EvmParams EvmTransactionParams`
/// Canton JSON API serializes as `{"tag": "EvmParams", "value": {...}}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub enum TxParams {
    EvmTxParams(EvmTransactionParams),
}

/// Payload of a `Signer:SignBidirectionalEvent` created event.
/// Emitted when a Vault exercises `RequestDeposit` → `Signer.SignBidirectional`.
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
    #[serde(deserialize_with = "deserialize_u32_lenient")]
    pub key_version: u32,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub nonce_cid_text: String,
    pub output_deserialization_schema: String,
    pub respond_serialization_schema: String,
}

// ---------------------------------------------------------------------------
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
    pub recovery_id: u8,
}

/// Signature union type matching Daml's `Signature` (see Signer.daml).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub enum CantonSignature {
    EcdsaSig(EcdsaSigData),
    // Future: EddsaSig(EddsaSigData), SchnorrSig(SchnorrSigData)
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

/// Deserialize a u32 from either a JSON number or a JSON string.
///
/// TODO(test): Canton sends key_version as either a JSON number or string.
/// If this deserializer breaks, sign requests silently fail to parse and get
/// dropped. Test with 42, "42", "0", overflow values.
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
        fn visit_str<E: de::Error>(self, v: &str) -> Result<u32, E> {
            v.parse()
                .map_err(|_| E::custom(format!("invalid u32 string: {v}")))
        }
    }
    deserializer.deserialize_any(U32Visitor)
}
