//! Typed structs for Daml contract payloads.
//!
//! These represent the JSON payloads inside `CreatedEvent.payload` for specific
//! Daml templates from `daml-signer` and `daml-vault`. Derived from the
//! `.daml` source files in `canton-mpc-poc/daml-packages/`.

use alloy::consensus::TxEip1559;
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
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

fn parse_u256_hex(value: &str, field: &str) -> anyhow::Result<U256> {
    U256::from_str_radix(value, 16)
        .map_err(|e| anyhow::anyhow!("invalid hex uint256 in {field}: {e}"))
}

fn parse_u64_hex(value: &str, field: &str) -> anyhow::Result<u64> {
    u64::try_from(parse_u256_hex(value, field)?)
        .map_err(|_| anyhow::anyhow!("hex uint256 in {field} exceeds u64"))
}

fn parse_u128_hex(value: &str, field: &str) -> anyhow::Result<u128> {
    u128::try_from(parse_u256_hex(value, field)?)
        .map_err(|_| anyhow::anyhow!("hex uint256 in {field} exceeds u128"))
}

fn decode_fixed_hex<const N: usize>(value: &str, field: &str) -> anyhow::Result<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(value, &mut out)
        .map_err(|e| anyhow::anyhow!("invalid {N}-byte hex value in {field}: {e}"))?;
    Ok(out)
}

fn parse_access_list(entries: &[EvmAccessListEntry]) -> anyhow::Result<AccessList> {
    entries
        .iter()
        .map(|entry| {
            Ok(AccessListItem {
                address: Address::from(decode_fixed_hex::<20>(
                    &entry.address,
                    "accessList.address",
                )?),
                storage_keys: entry
                    .storage_keys
                    .iter()
                    .map(|key| {
                        Ok(B256::from(decode_fixed_hex::<32>(
                            key,
                            "accessList.storageKeys",
                        )?))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()
        .map(AccessList)
}

impl TryFrom<&EvmType2TransactionParams> for TxEip1559 {
    type Error = anyhow::Error;

    fn try_from(params: &EvmType2TransactionParams) -> anyhow::Result<Self> {
        let to = match params.to.as_deref() {
            Some(to) => TxKind::Call(Address::from(decode_fixed_hex::<20>(to, "to")?)),
            None => TxKind::Create,
        };

        Ok(Self {
            chain_id: parse_u64_hex(&params.chain_id, "chainId")?,
            nonce: parse_u64_hex(&params.nonce, "nonce")?,
            gas_limit: parse_u64_hex(&params.gas_limit, "gasLimit")?,
            max_fee_per_gas: parse_u128_hex(&params.max_fee_per_gas, "maxFeePerGas")?,
            max_priority_fee_per_gas: parse_u128_hex(
                &params.max_priority_fee_per_gas,
                "maxPriorityFeePerGas",
            )?,
            to,
            value: parse_u256_hex(&params.value, "value")?,
            access_list: parse_access_list(&params.access_list)?,
            input: Bytes::from(hex::decode(&params.calldata)?),
        })
    }
}

/// Daml variant: `data TxParams = EvmType2TxParams EvmType2TransactionParams`
/// Canton JSON API serializes as `{"tag": "EvmType2TxParams", "value": {...}}`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "tag", content = "value")]
pub enum TxParams {
    EvmType2TxParams(EvmType2TransactionParams),
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
    pub output_deserialization_schema: String,
    pub respond_serialization_schema: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRequestPayload {
    pub operators: Vec<String>,
    pub requester: String,
    pub sig_network: String,
    pub tx_params: TxParams,
    pub caip2_id: String,
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub key_version: u32,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
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
