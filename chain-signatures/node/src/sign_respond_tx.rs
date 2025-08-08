use crate::protocol::SignRequestType;
use crate::rpc::PublishAction;
use crate::storage::sign_respond_tx_storage::SignRespondTxStorage;
use alloy::primitives::{Address, Bytes, B256};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_rlp::Decodable;
use anchor_lang::prelude::Pubkey;
use ethers_core::types::U256;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{AffinePoint, Scalar};
use mpc_crypto::derive_key;
use mpc_primitives::Signature;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Copy)]
pub struct SignRespondTxId(pub B256);

impl From<B256> for SignRespondTxId {
    fn from(b256: B256) -> Self {
        SignRespondTxId(b256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
struct AbiField {
    name: String,
    #[serde(rename = "type")]
    typ: String,
}

#[derive(Debug, Clone, Hash, serde::Serialize, serde::Deserialize)]
pub struct SignRespondTx {
    pub id: SignRespondTxId,
    pub sender: Pubkey,
    pub transaction_data: Vec<u8>,
    pub slip44_chain_id: u32,
    pub key_version: u32,
    pub deposit: u64,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub explorer_deserialization_format: u8,
    pub explorer_deserialization_schema: Vec<u8>,
    pub callback_serialization_format: u8,
    pub callback_serialization_schema: Vec<u8>,
    pub request_id: [u8; 32],
    pub from_address: Address,
    pub nonce: u64,
}

impl SignRespondTx {
    pub fn new(publish_action: PublishAction, signature: Signature) -> anyhow::Result<Self> {
        let SignRequestType::SignRespond(sign_respond_event) =
            publish_action.request.indexed.sign_request_type.clone()
        else {
            anyhow::bail!("sign request is not a sign respond");
        };

        let rlp_data = sign_respond_event.transaction_data.clone();
        let is_eip1559 = rlp_data[0] == 0x02;
        let tx_type = if is_eip1559 { 0x02 } else { 0x00 };
        let decoded = decode_rlp(rlp_data, is_eip1559)?;
        let nonce_index = if is_eip1559 { 1 } else { 0 };
        let nonce = u64::from_be_bytes(
            decoded[nonce_index][..8]
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid nonce bytes"))?,
        );

        let signed_transaction_hash = calculate_signed_transaction_hash(
            decoded,
            signature,
            is_eip1559,
            sign_respond_event.slip44_chain_id as u64,
            tx_type,
        );

        let from_address = derive_user_address(
            publish_action.public_key,
            publish_action.request.indexed.args.epsilon,
        );

        Ok(Self {
            id: SignRespondTxId(signed_transaction_hash),
            sender: sign_respond_event.sender,
            transaction_data: sign_respond_event.transaction_data,
            slip44_chain_id: sign_respond_event.slip44_chain_id,
            key_version: sign_respond_event.key_version,
            deposit: sign_respond_event.deposit,
            path: sign_respond_event.path,
            algo: sign_respond_event.algo,
            dest: sign_respond_event.dest,
            params: sign_respond_event.params,
            explorer_deserialization_format: sign_respond_event.explorer_deserialization_format,
            explorer_deserialization_schema: sign_respond_event.explorer_deserialization_schema,
            callback_serialization_format: sign_respond_event.callback_serialization_format,
            callback_serialization_schema: sign_respond_event.callback_serialization_schema,
            request_id: publish_action.request.indexed.id.request_id,
            from_address,
            nonce,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Output(pub HashMap<String, DynSolValue>);

impl Output {
    pub fn is_function_call(&self) -> bool {
        self.0
            .get("is_function_call")
            .is_some_and(|v| v.as_bool().unwrap_or(false))
    }

    pub fn serialize(&self, format: u8, schema: &[u8]) -> anyhow::Result<Vec<u8>> {
        if format == 1 {
            self.serialize_abi(schema)
        } else {
            Err(anyhow::anyhow!(
                "Unsupported serialization format: {format}"
            ))
        }
    }

    fn serialize_abi(&self, schema: &[u8]) -> anyhow::Result<Vec<u8>> {
        let schema: Vec<AbiField> = serde_json::from_slice(schema)
            .map_err(|e| anyhow::anyhow!("Failed to get abi fields from schema: {e:?}"))?;

        let mut data_to_encode = self.clone();
        if !self.is_function_call() {
            data_to_encode = create_abi_data(schema.clone())?;
        }

        let values = schema
            .iter()
            .map(|field| match data_to_encode.0.get(&field.name) {
                Some(value) => Ok(value.clone()),
                None => Err(anyhow::anyhow!(
                    "Missing required field '{}' in output",
                    field.name
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;

        encode_abi_values(&schema, &values)
    }
}

#[derive(Debug)]
pub struct TransactionOutput {
    pub success: bool,
    pub output: Output,
}

impl TransactionOutput {
    pub fn non_function_call_output() -> Self {
        Self {
            success: true,
            output: Output(HashMap::new()),
        }
    }

    pub fn from_call_result(schema_json: &[u8], call_result: &Bytes) -> anyhow::Result<Self> {
        let schema: Vec<AbiField> = serde_json::from_slice(schema_json)
            .map_err(|e| anyhow::anyhow!("Failed to get abi fields from schema: {e:?}"))?;

        let types: Vec<DynSolType> = schema
            .iter()
            .map(|f| f.typ.parse()) // calls DynSolType::parse via FromStr
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse eth transaction types: {e:?}"))?;

        // Build a single tuple DynSolType
        let tuple_type = DynSolType::Tuple(types);

        // Decode the whole result as a tuple
        let DynSolValue::Tuple(values) = tuple_type
            .abi_decode(call_result)
            .map_err(|e| anyhow::anyhow!("Failed to tuple types: {e:?}"))?
        else {
            return Err(anyhow::anyhow!("Can't decode to tuple type"));
        };

        // Map to named output
        let mut output_map = HashMap::new();
        for (field, value) in schema.into_iter().zip(values.into_iter()) {
            output_map.insert(field.name, value);
        }

        Ok(TransactionOutput {
            success: true,
            output: Output(output_map),
        })
    }
}

pub fn hash_rlp_data(rlp_data: Vec<u8>) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(&rlp_data);
    hasher.finalize().into()
}

pub fn decode_rlp(rlp_data: Vec<u8>, is_eip1559: bool) -> anyhow::Result<Vec<Bytes>> {
    let payload = if is_eip1559 {
        &rlp_data[1..]
    } else {
        &rlp_data
    };

    let mut stream = payload;
    let decoded: Vec<Bytes> = Vec::<Bytes>::decode(&mut stream)
        .map_err(|e| anyhow::anyhow!("Failed to decode RLP list: {e:?}"))?;

    Ok(decoded)
}

pub fn to_eip155_v(recovery_id: u8, chain_id: u64) -> u64 {
    (recovery_id as u64) + 35 + chain_id * 2
}

fn to_be_bytes_fixed(value: U256, width: usize) -> Bytes {
    let mut buf = vec![0u8; width];
    value.to_big_endian(&mut buf[width.saturating_sub(value.bits() / 8)..]);
    Bytes::from(buf)
}

fn calculate_signed_transaction_hash(
    mut decoded: Vec<Bytes>,
    signature: Signature,
    is_eip1559: bool,
    chain_id: u64,
    tx_type: u8,
) -> B256 {
    let ethers_r = ethers_core::types::U256::from_big_endian(&signature.big_r.x());
    let ethers_s = ethers_core::types::U256::from_big_endian(signature.s.to_bytes().as_slice());
    let ethers_v: U256 = to_eip155_v(signature.recovery_id, chain_id).into();

    // Convert U256 → Bytes
    let to_bytes = |val: U256| {
        let mut buf = [0u8; 32];
        val.to_big_endian(&mut buf);
        Bytes::copy_from_slice(&buf)
    };

    let (r_bytes, s_bytes) = (to_bytes(ethers_r), to_bytes(ethers_s));
    // Append v, r, s
    decoded.push(to_be_bytes_fixed(ethers_v, 1));
    decoded.push(s_bytes);
    decoded.push(r_bytes);

    // Step 3: RLP encode all fields
    let rlp_encoded = alloy_rlp::encode(&decoded);

    // Step 4: Handle EIP-1559 typed transaction
    let signed_tx: Bytes = match is_eip1559 {
        true => {
            let mut tx = vec![tx_type];
            tx.extend_from_slice(&rlp_encoded);
            tx.into()
        }
        false => rlp_encoded.into(),
    };

    // Step 5: Hash the signed transaction
    let hash_bytes: [u8; 32] = Keccak256::digest(&signed_tx).into();
    B256::from(hash_bytes)
}

/// Get the x coordinate of a point, as a scalar
fn x_coordinate<C: cait_sith::CSCurve>(point: &C::AffinePoint) -> C::Scalar {
    <C::Scalar as k256::elliptic_curve::ops::Reduce<<C as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(&point.x())
}

fn public_key_to_address(public_key: &secp256k1::PublicKey) -> Address {
    let public_key = public_key.serialize_uncompressed();

    debug_assert_eq!(public_key[0], 0x04);
    let hash: [u8; 32] = *alloy::primitives::keccak256(&public_key[1..]);

    Address::from_slice(&hash[12..])
}

fn derive_user_address(mpc_pk: mpc_crypto::PublicKey, derivation_epsilon: Scalar) -> Address {
    let user_pk: AffinePoint = derive_key(mpc_pk, derivation_epsilon);
    let parity = match user_pk.y_is_odd().unwrap_u8() {
        0 => secp256k1::Parity::Even,
        1 => secp256k1::Parity::Odd,
        _ => unreachable!(),
    };

    let x_coord = x_coordinate::<k256::Secp256k1>(&user_pk);
    let x_only = secp256k1::XOnlyPublicKey::from_slice(&x_coord.to_bytes()).unwrap();
    let secp_pk = secp256k1::PublicKey::from_x_only_public_key(x_only, parity);

    public_key_to_address(&secp_pk)
}

pub async fn process_sign_responded_requests(
    mut sign_respond_responded_rx: mpsc::Receiver<(PublishAction, Signature)>,
    sign_respond_tx_storage: SignRespondTxStorage,
    max_attempts: u8,
) {
    while let Some((publish_action, signature)) = sign_respond_responded_rx.recv().await {
        let sign_respond_tx = match SignRespondTx::new(publish_action.clone(), signature.clone()) {
            Ok(tx) => tx,
            Err(_) => {
                tracing::error!(sign_id = ?publish_action.request.indexed.id, "failed to create sign respond tx");
                continue;
            }
        };

        for attempt in 1..=max_attempts {
            if sign_respond_tx_storage
                .insert(sign_respond_tx.id, sign_respond_tx.clone())
                .await
            {
                tracing::info!(sign_id = ?sign_respond_tx.id, "inserted sign respond tx into storage");
                break;
            } else if attempt == max_attempts {
                tracing::error!(sign_id = ?sign_respond_tx.id, "failed to insert after {max_attempts} attempts");
            }
        }
    }
}

fn create_abi_data(schema: Vec<AbiField>) -> anyhow::Result<Output> {
    let mut data = HashMap::new();
    for field in schema {
        if field.typ == "string" {
            data.insert(
                field.name,
                DynSolValue::String("non_function_call_success".to_string()),
            );
        } else if field.typ == "bool" {
            data.insert(field.name, DynSolValue::Bool(true));
        } else {
            return Err(anyhow::anyhow!(
                "Cannot serialize non-function call success as type {}",
                field.typ
            ));
        }
    }

    Ok(Output(data))
}

fn encode_abi_values(schema: &[AbiField], values: &[DynSolValue]) -> anyhow::Result<Vec<u8>> {
    if schema.len() != values.len() {
        return Err(anyhow::anyhow!(
            "Schema and values length mismatch: {} != {}",
            schema.len(),
            values.len()
        ));
    }
    for (f, v) in schema.iter().zip(values.iter()) {
        let ty: DynSolType = f.typ.parse()?;
        if !ty.matches(v) {
            return Err(anyhow::anyhow!(
                "Value {v:?} doesn't match Solidity type {}",
                f.typ
            ));
        }
    }
    // Encode each value and concatenate
    let mut combined = Vec::new();
    for v in values {
        combined.extend(v.abi_encode());
    }

    Ok(combined)
}
