//! Typed structs for Daml contract payloads.
//!
//! These represent the JSON payloads inside `CreatedEvent.payload` for specific
//! Daml templates from `daml-signer` and `daml-evm-types`. Derived from the
//! `.daml` source files in `canton-mpc-poc/daml-packages/`.

use alloy::consensus::TxEip1559;
use alloy::primitives::{Address, Bytes, TxKind, U256};
use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::deserialize_number_from_string;

/// EVM transaction parameters from the Signer contract.
/// Address fields are 40-char hex (20 bytes); numeric fields are 64-char hex.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmTransactionParams {
    pub to: String,
    pub function_signature: String,
    #[serde(default)]
    pub encoded_args: String,
    pub value: String,
    pub nonce: String,
    pub gas_limit: String,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    pub chain_id: String,
}

impl EvmTransactionParams {
    pub fn parse_to_address(&self) -> anyhow::Result<Address> {
        Ok(format!("0x{}", self.to).parse()?)
    }

    pub fn parse_value(&self) -> anyhow::Result<U256> {
        U256::from_str_radix(&self.value, 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in 'value': {e}"))
    }

    pub fn parse_nonce(&self) -> anyhow::Result<u64> {
        u64::from_str_radix(&self.nonce, 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in 'nonce': {e}"))
    }

    pub fn parse_gas_limit(&self) -> anyhow::Result<u64> {
        u64::from_str_radix(&self.gas_limit, 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in 'gas_limit': {e}"))
    }

    pub fn parse_max_fee_per_gas(&self) -> anyhow::Result<u128> {
        u128::from_str_radix(&self.max_fee_per_gas, 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in 'max_fee_per_gas': {e}"))
    }

    pub fn parse_max_priority_fee_per_gas(&self) -> anyhow::Result<u128> {
        u128::from_str_radix(&self.max_priority_fee_per_gas, 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in 'max_priority_fee_per_gas': {e}"))
    }

    pub fn parse_chain_id(&self) -> anyhow::Result<u64> {
        u64::from_str_radix(&self.chain_id, 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in 'chain_id': {e}"))
    }
}

/// Convert Canton EvmTransactionParams to an alloy TxEip1559.
///
/// TODO(test): test address extraction from 32-byte padded hex (Canton format)
/// vs 20-byte unpadded hex. Test hex parsing of all numeric fields (chain_id,
/// nonce, gas_limit, fees, value) including edge cases like leading zeros.
impl TryFrom<&EvmTransactionParams> for TxEip1559 {
    type Error = anyhow::Error;

    fn try_from(p: &EvmTransactionParams) -> anyhow::Result<Self> {
        Ok(Self {
            chain_id: p.parse_chain_id()?,
            nonce: p.parse_nonce()?,
            gas_limit: p.parse_gas_limit()?,
            max_fee_per_gas: p.parse_max_fee_per_gas()?,
            max_priority_fee_per_gas: p.parse_max_priority_fee_per_gas()?,
            to: TxKind::Call(p.parse_to_address()?),
            value: p.parse_value()?,
            input: Bytes::from(super::calldata::build_calldata(
                &p.function_signature,
                &p.encoded_args,
            )?),
            access_list: Default::default(),
        })
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
/// Emitted when `Signer.SignBidirectional` is exercised.
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
    #[serde(deserialize_with = "deserialize_number_from_string")]
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
    /// Canton serializes Daml `Int` as a JSON string on outbound events.
    #[serde(deserialize_with = "deserialize_number_from_string")]
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
