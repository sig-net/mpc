//! All Canton signing primitives and logic.

use alloy::consensus::SignableTransaction;
use alloy::consensus::TxEip1559;
use alloy::eips::eip2930::{AccessList, AccessListItem};
use alloy::primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use alloy_sol_types::SolValue;
use borsh::{BorshDeserialize, BorshSerialize};
use k256::Scalar;
use mpc_chain_integration_core::utils::hashing::hash_payload;
use mpc_crypto::x_coordinate;
use mpc_primitives::{
    Chain, IndexedSignRequest, ScalarExt, SignArgs, SignBidirectionalEvent, SignId, Signature,
    LATEST_MPC_KEY_VERSION,
};

use crate::daml::{
    CantonSignature, EvmAccessListEntry, EvmType2TransactionParams,
    SignBidirectionalRequestedEvent, TxParams,
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "borsh")]
pub struct CantonChainCtx {
    pub sign_event_contract_id: String,
}

pub fn der_encode_signature(signature: &Signature) -> anyhow::Result<Vec<u8>> {
    let r_scalar = x_coordinate(&signature.big_r);
    let ecdsa_sig = k256::ecdsa::Signature::from_scalars(r_scalar, signature.s).map_err(|e| {
        anyhow::anyhow!("failed to create ECDSA signature from (r, s) scalars: {e}")
    })?;
    Ok(ecdsa_sig.to_der().to_bytes().to_vec())
}

/// Node-facing Canton sign event.
///
/// The raw Daml payload uses Canton-native shapes such as `Text` schemas and
/// transaction params. This type is created at the indexer boundary and carries
/// the byte fields expected by the shared bidirectional signing flow.
///
/// `RequestSignature` charges the Canton Coin fee atomically on-ledger (fail-closed),
/// so the indexer only sees already-charged requests. The fee never enters the event
/// payload, request id, KDF epsilon, or signed tx — the MPC neither sees nor verifies
/// it — so the bidirectional flow carries no Canton deposit (deposit = zero).
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CantonSignBidirectionalRequestedEvent {
    pub sign_event_contract_id: String,
    pub sender: [u8; 32],
    pub request_id: [u8; 32],
    pub serialized_transaction: Vec<u8>,
    pub caip2_id: String,
    pub key_version: u32,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub output_deserialization_schema: Vec<u8>,
    pub respond_serialization_schema: Vec<u8>,
}

impl CantonSignBidirectionalRequestedEvent {
    pub fn from_created(
        contract_id: String,
        raw: SignBidirectionalRequestedEvent,
    ) -> anyhow::Result<Self> {
        let request_id = compute_request_id(&raw)?;
        let serialized_transaction = match &raw.tx_params {
            TxParams::EvmType2TxParams(params) => {
                TxEip1559::try_from(params)?.encoded_for_signing()
            }
        };
        let mut sender = [0u8; 32];
        hex::decode_to_slice(&raw.sender, &mut sender)
            .map_err(|e| anyhow::anyhow!("invalid hex in sender: {e}"))?;

        Ok(Self {
            sign_event_contract_id: contract_id,
            sender,
            request_id,
            serialized_transaction,
            caip2_id: raw.caip2_id,
            key_version: raw.key_version,
            path: raw.path,
            algo: raw.algo,
            dest: raw.dest,
            params: raw.params,
            output_deserialization_schema: raw.output_deserialization_schema.into_bytes(),
            respond_serialization_schema: raw.respond_serialization_schema.into_bytes(),
        })
    }

    pub fn generate_request_id(&self) -> [u8; 32] {
        self.request_id
    }

    pub fn generate_sign_request(
        &self,
        entropy: [u8; 32],
        timestamp: u64,
    ) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("found canton event: {:?}", self);

        if self.key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!("unsupported key version: {}", self.key_version);
            anyhow::bail!("unsupported key version");
        }

        let request_id = self.request_id;

        let epsilon = mpc_crypto::kdf::derive_epsilon_canton(
            self.key_version,
            &self.sender_string(),
            &self.path,
        );

        let unsigned_tx_hash = hash_payload(&self.serialized_transaction);

        let Some(payload) = Scalar::from_bytes(unsigned_tx_hash) else {
            anyhow::bail!("failed to convert unsigned_tx_hash to scalar: {unsigned_tx_hash:?}");
        };

        let sign_id = SignId::new(request_id);
        tracing::info!(?sign_id, "canton signature requested");

        let ctx = CantonChainCtx {
            sign_event_contract_id: self.sign_event_contract_id.clone(),
        };
        let chain_ctx =
            Some(borsh::to_vec(&ctx).expect("CantonChainCtx Borsh serialization is infallible"));

        Ok(IndexedSignRequest::sign_bidirectional(
            sign_id,
            SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            Chain::Canton,
            timestamp,
            SignBidirectionalEvent {
                sender: self.sender,
                serialized_transaction: self.serialized_transaction.clone(),
                caip2_id: self.caip2_id.clone(),
                key_version: self.key_version,
                deposit: 0,
                path: self.path.clone(),
                algo: self.algo.clone(),
                dest: self.dest.clone(),
                params: self.params.clone(),
                output_deserialization_schema: self.output_deserialization_schema.clone(),
                respond_serialization_schema: self.respond_serialization_schema.clone(),
                chain: Chain::Canton,
                chain_ctx,
            },
        ))
    }

    pub fn sender_string(&self) -> String {
        hex::encode(self.sender)
    }
}

pub fn parse_canton_signature(sig: &CantonSignature) -> anyhow::Result<Signature> {
    match sig {
        CantonSignature::EcdsaSig(data) => {
            parse_der_signature_with_recovery(&data.der, data.recovery_id)
        }
    }
}

/// Parse a DER-encoded ECDSA signature with known recovery ID.
pub fn parse_der_signature_with_recovery(
    hex_str: &str,
    recovery_id: u8,
) -> anyhow::Result<Signature> {
    use k256::elliptic_curve::{point::DecompressPoint, subtle::Choice};

    let sig = k256::ecdsa::Signature::from_der(&hex::decode(hex_str)?)?;
    let (r, s) = sig.split_scalars();

    anyhow::ensure!(
        recovery_id <= 1,
        "invalid recovery_id {recovery_id}: expected 0 or 1"
    );
    let parity = Choice::from(recovery_id);

    Ok(Signature {
        big_r: k256::AffinePoint::decompress(&r.to_bytes(), parity)
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("invalid r"))?,
        s: <k256::Scalar as ScalarExt>::from_bytes(s.to_bytes().into())
            .ok_or_else(|| anyhow::anyhow!("invalid s"))?,
        recovery_id,
    })
}

pub fn compute_request_id(event: &SignBidirectionalRequestedEvent) -> anyhow::Result<[u8; 32]> {
    let key_version = U256::from(event.key_version);

    let mut buf = Vec::with_capacity(8 * 32);
    buf.extend_from_slice(event.sender.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(&hash_tx_params(&event.tx_params)?);
    buf.extend_from_slice(event.caip2_id.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(key_version.eip712_data_word().as_slice());
    buf.extend_from_slice(event.path.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(event.algo.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(event.dest.as_str().eip712_data_word().as_slice());
    buf.extend_from_slice(event.params.as_str().eip712_data_word().as_slice());
    Ok(keccak256(&buf).into())
}

fn hash_tx_params(cp: &TxParams) -> anyhow::Result<[u8; 32]> {
    match cp {
        TxParams::EvmType2TxParams(p) => hash_evm_type2_params(p),
    }
}

fn hash_evm_type2_params(p: &EvmType2TransactionParams) -> anyhow::Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(9 * 32);

    for value in [
        &p.chain_id,
        &p.nonce,
        &p.max_priority_fee_per_gas,
        &p.max_fee_per_gas,
        &p.gas_limit,
    ] {
        extend_eip712_u256(&mut buf, value)?;
    }
    match &p.to {
        Some(address) => {
            let address: Address = format!("0x{address}").parse()?;
            buf.extend_from_slice(address.eip712_data_word().as_slice());
        }
        None => {
            let empty_hash: [u8; 32] = keccak256([]).into();
            buf.extend_from_slice(&empty_hash);
        }
    }
    extend_eip712_u256(&mut buf, &p.value)?;
    buf.extend_from_slice(keccak256(hex::decode(&p.calldata)?).as_slice());
    buf.extend_from_slice(&hash_access_list(&p.access_list)?);

    Ok(keccak256(&buf).into())
}

fn extend_eip712_u256(buf: &mut Vec<u8>, hex: &str) -> anyhow::Result<()> {
    let value = U256::from_str_radix(hex, 16)?;
    buf.extend_from_slice(value.eip712_data_word().as_slice());
    Ok(())
}

fn hash_access_list(access_list: &[EvmAccessListEntry]) -> anyhow::Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(access_list.len() * 32);
    for entry in access_list {
        buf.extend_from_slice(&hash_access_list_entry(entry)?);
    }
    Ok(keccak256(&buf).into())
}

fn hash_access_list_entry(entry: &EvmAccessListEntry) -> anyhow::Result<[u8; 32]> {
    let address: Address = format!("0x{}", entry.address).parse()?;

    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(address.eip712_data_word().as_slice());
    buf.extend_from_slice(&hash_storage_keys(&entry.storage_keys)?);
    Ok(keccak256(&buf).into())
}

fn hash_storage_keys(storage_keys: &[String]) -> anyhow::Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(storage_keys.len() * 32);
    for storage_key in storage_keys {
        buf.extend(hex::decode(storage_key)?);
    }
    Ok(keccak256(&buf).into())
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
