use crate::checkpoint::{Chain, CheckpointManager};
use crate::protocol::signature::SignRequest;
use crate::protocol::SignRequestType;
use alloy::primitives::{keccak256, Address, Bytes, B256, I256, U256};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use anchor_lang::prelude::Pubkey;
use borsh::BorshSerialize;
use cait_sith::protocol::Participant;
use cait_sith::FullSignature;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{AffinePoint, Scalar, Secp256k1};
use mpc_crypto::derive_key;
use mpc_primitives::Signature;
use rlp::{Rlp, RlpStream};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::io::Write;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Copy)]
pub struct SignRespondTxId(pub B256);

pub type RequestId = [u8; 32];

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

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SignRespondTxStatus {
    Pending,
    Failed,
    Success,
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
    pub participants: Vec<Participant>,
    pub status: SignRespondTxStatus,
}

impl SignRespondTx {
    pub fn new(sign_respond_signature: SignRespondSignature) -> anyhow::Result<Self> {
        let SignRequestType::SignRespond(sign_respond_event) = sign_respond_signature
            .request
            .indexed
            .sign_request_type
            .clone()
        else {
            anyhow::bail!("sign request is not a sign respond");
        };

        let unsigned_rlp_data = &sign_respond_event.transaction_data;

        let (signed_transaction_hash, nonce) =
            sign_and_hash_transaction(unsigned_rlp_data, sign_respond_signature.signature)?;

        tracing::info!(signed_transaction_hash = ?signed_transaction_hash, "signed_transaction_hash");

        let from_address = derive_user_address(
            sign_respond_signature.public_key,
            sign_respond_signature.request.indexed.args.epsilon,
        );

        tracing::info!(from_address = ?from_address, "from_address");

        Ok(Self {
            id: SignRespondTxId(signed_transaction_hash.into()),
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
            request_id: sign_respond_signature.request.indexed.id.request_id,
            from_address,
            nonce,
            participants: sign_respond_signature.participants,
            status: SignRespondTxStatus::Pending,
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
            self.serialize_borsh(schema)
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

    /// Serialize `Output` to Borsh using the **order from `schema_json_bytes`**
    /// Schema is a JSON array like: `[{"name":"...", "type":"..."}, ...]`
    pub fn serialize_borsh(&self, schema_json_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let fields: Vec<AbiField> = parse_borsh_schema_fields(schema_json_bytes)?;

        tracing::info!("serialize borsh schema: {fields:?}");

        let mut buf = Vec::with_capacity(128);

        assert!(fields.len() == 1);
        let val = self
            .0
            .get(&fields[0].name)
            .ok_or_else(|| anyhow::anyhow!("missing value for field '{}'", fields[0].name))?;
        serialize_dynsol(&mut buf, val)?;

        Ok(buf)
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

    let rlp = rlp::Rlp::new(payload);

    if !rlp.is_list() {
        anyhow::bail!("Input is not a valid RLP list");
    }

    let mut result = Vec::new();

    for i in 0..rlp.item_count()? {
        let item = rlp.at(i)?;
        result.push(Bytes::copy_from_slice(item.data()?));
    }

    Ok(result)
}

fn sign_and_hash_transaction(
    unsigned_rlp: &[u8],
    signature: Signature,
) -> anyhow::Result<([u8; 32], u64)> {
    let r = signature.big_r.x().as_slice().to_vec();
    let s = signature.s.to_bytes().as_slice().to_vec();
    let y_parity = signature.recovery_id == 1;

    if is_eip1559(unsigned_rlp) {
        sign_and_hash_eip1559_from_unsigned(unsigned_rlp, &r, &s, y_parity)
    } else {
        sign_and_hash_legacy_from_unsigned(unsigned_rlp, Some(60), &r, &s, y_parity)
    }
}

fn is_eip1559(unsigned_rlp: &[u8]) -> bool {
    unsigned_rlp[0] == 0x02
}

pub fn sign_and_hash_eip1559_from_unsigned(
    unsigned: &[u8], // may be 0x02||RLP(body) or just RLP(body)
    r: &[u8],
    s: &[u8],
    y_parity: bool,
) -> anyhow::Result<([u8; 32], u64)> {
    // Strip optional type prefix
    let (_, body) = match unsigned.first().copied() {
        Some(0x02) => (true, &unsigned[1..]),
        _ => (false, unsigned),
    };

    // Decode the 9-field unsigned body
    let rlp = Rlp::new(body);
    anyhow::ensure!(rlp.is_list(), "unsigned 1559 payload must be an RLP list");
    anyhow::ensure!(
        rlp.item_count()? == 9,
        "unexpected 1559 unsigned field count"
    );

    let nonce: u64 = rlp.val_at::<u64>(1)?;

    // Re-encode with signature fields appended
    let mut srlp = RlpStream::new_list(12);
    for i in 0..9 {
        srlp.append_raw(rlp.at(i)?.as_raw(), 1);
    }
    let y: u8 = if y_parity { 1 } else { 0 };
    srlp.append(&y);
    srlp.append(&r);
    srlp.append(&s);

    let srlp_body = srlp.as_raw(); // &[u8]
    let mut signed_bytes = Vec::with_capacity(1 + srlp_body.len());
    signed_bytes.push(0x02);
    signed_bytes.extend_from_slice(srlp_body);

    let hash = keccak256(&signed_bytes);
    Ok((hash.into(), nonce))
}

pub fn sign_and_hash_legacy_from_unsigned(
    unsigned_rlp: &[u8], // the exact preimage you hashed (… , chainId, 0, 0)
    chain_id: Option<u64>,
    r: &[u8],
    s: &[u8],
    y_parity: bool,
) -> anyhow::Result<([u8; 32], u64)> {
    let rlp = Rlp::new(unsigned_rlp);
    anyhow::ensure!(rlp.is_list(), "unsigned legacy must be an RLP list");
    anyhow::ensure!(
        rlp.item_count()? >= 9,
        "unexpected legacy unsigned field count"
    );

    let nonce: u64 = rlp.val_at::<u64>(0)?;
    let mut out = RlpStream::new_list(9);
    for i in 0..6 {
        out.append_raw(rlp.at(i)?.as_raw(), 1);
    }
    let v: u64 = 35 + 2 * chain_id.unwrap_or(0) + if y_parity { 1 } else { 0 };
    out.append(&v);
    out.append(&r);
    out.append(&s);

    let signed_bytes = out.out().to_vec();
    let hash = alloy_primitives::keccak256(&signed_bytes);
    Ok((hash.into(), nonce))
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

/* ---------- DynSolValue -> Borsh serializer (runtime) ---------- */

fn serialize_dynsol<W: Write>(w: &mut W, v: &DynSolValue) -> anyhow::Result<()> {
    use DynSolValue::*;
    match v {
        // -------- Primitives --------
        Bool(b) => {
            // Borsh bool is u8 (0/1) via BorshSerialize on bool
            b.serialize(w)?;
        }
        Address(a) => a.serialize(w)?,
        Uint(u, size) => write_u256(w, *u, *size)?,
        Int(i, size) => write_i256(w, *i, *size)?,

        // -------- Bytes-like --------
        // Fixed bytes -> raw bytes (no length)
        FixedBytes(b, _) => w.write_all(b.as_slice())?,
        // Dynamic bytes -> Vec<u8> (u32 length + bytes)
        Bytes(b) => b.serialize(w)?,

        // -------- Strings --------
        String(s) => s.serialize(w)?,

        // -------- Arrays --------
        // Dynamic array -> Borsh Vec<T>: u32 length + elements
        Array(xs) => {
            (xs.len() as u32).serialize(w)?;
            for x in xs {
                serialize_dynsol(w, x)?;
            }
        }
        // Fixed array -> elements inline (no length)
        FixedArray(xs) => {
            for x in xs {
                serialize_dynsol(w, x)?;
            }
        }

        // -------- Tuple --------
        // Concatenate members
        Tuple(xs) => {
            for x in xs {
                serialize_dynsol(w, x)?;
            }
        }

        // Add more variants if you use them (e.g., custom types).
        other => anyhow::bail!("unsupported DynSolValue variant: {other:?}"),
    }
    Ok(())
}

/* ------------------ helpers using borsh where possible ------------------ */

fn write_u256<W: Write>(w: &mut W, x: U256, size: usize) -> anyhow::Result<()> {
    // Use the size parameter to determine how many bytes to write
    let le = x.to_le_bytes::<{ U256::BYTES }>();
    w.write_all(&le[..size.min(U256::BYTES)])
        .map_err(Into::into)
}

fn write_i256<W: Write>(w: &mut W, x: I256, size: usize) -> anyhow::Result<()> {
    // Use the size parameter to determine how many bytes to write
    let le = x.to_le_bytes::<{ I256::BYTES }>();
    w.write_all(&le[..size.min(I256::BYTES)])
        .map_err(Into::into)
}

fn parse_borsh_schema_fields(schema_json_bytes: &[u8]) -> anyhow::Result<Vec<AbiField>> {
    let v: Value = serde_json::from_slice(schema_json_bytes)
        .map_err(|e| anyhow::anyhow!("schema JSON parse failed: {e:?}"))?;

    Ok(match v {
        Value::Array(arr) => arr
            .into_iter()
            .map(|item| {
                serde_json::from_value(item)
                    .map_err(|e| anyhow::anyhow!("invalid field in array: {e:?}"))
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?,
        Value::Object(obj) => {
            vec![serde_json::from_value(Value::Object(obj))
                .map_err(|e| anyhow::anyhow!("invalid single object schema: {e:?}"))?]
        }
        Value::String(s) => vec![AbiField {
            name: String::new(),
            typ: s,
        }],
        other => anyhow::bail!("unsupported schema JSON shape: {other}"),
    })
}

#[derive(Clone)]
pub struct SignRespondSignature {
    pub public_key: mpc_crypto::PublicKey,
    pub request: SignRequest,
    pub signature: Signature,
    pub participants: Vec<Participant>,
}

#[derive(Clone)]
pub struct SignRespondSignatureChannel {
    tx: mpsc::Sender<(Chain, SignRespondSignature)>,
}

impl SignRespondSignatureChannel {
    pub fn send(
        &self,
        chain: Chain,
        public_key: mpc_crypto::PublicKey,
        request: SignRequest,
        output: FullSignature<Secp256k1>,
        participants: Vec<Participant>,
    ) {
        let tx = self.tx.clone();
        let expected_public_key = mpc_crypto::derive_key(public_key, request.indexed.args.epsilon);
        let Ok(signature) = crate::kdf::into_eth_sig(
            &expected_public_key,
            &output.big_r,
            &output.s,
            request.indexed.args.payload,
        ) else {
            tracing::error!(
                sign_id = ?request.indexed.id,
                "failed to generate a recovery id; trashing publish request",
            );
            return;
        };
        tokio::spawn(async move {
            if let Err(err) = tx
                .send((
                    chain,
                    SignRespondSignature {
                        public_key,
                        request,
                        signature,
                        participants,
                    },
                ))
                .await
            {
                tracing::error!(%err, "failed to send sign respond signature");
            }
        });
    }
}

pub struct SignRespondSignatureProcessor {
    sign_respond_signature_rx: mpsc::Receiver<(Chain, SignRespondSignature)>,
}

const MAX_CONCURRENT_SIGN_RESPOND_SIGNATURE_REQUESTS: usize = 1024;

impl SignRespondSignatureProcessor {
    pub fn new() -> (SignRespondSignatureChannel, Self) {
        let (tx, rx) = mpsc::channel(MAX_CONCURRENT_SIGN_RESPOND_SIGNATURE_REQUESTS);
        (
            SignRespondSignatureChannel { tx },
            Self {
                sign_respond_signature_rx: rx,
            },
        )
    }

    pub async fn run(mut self, checkpoint: CheckpointManager, max_attempts: u8) {
        while let Some((chain, sign_respond_signature)) =
            self.sign_respond_signature_rx.recv().await
        {
            let sign_respond_tx = match SignRespondTx::new(sign_respond_signature.clone()) {
                Ok(tx) => tx,
                Err(err) => {
                    tracing::error!(sign_id = ?sign_respond_signature.request.indexed.id, "failed to create sign respond tx: {err:?}");
                    continue;
                }
            };

            for attempt in 1..=max_attempts {
                if checkpoint
                    .insert_or_update_tx(chain, sign_respond_tx.id, sign_respond_tx.clone())
                    .await
                {
                    tracing::info!(sign_id = ?sign_respond_tx.id, "inserted sign respond tx into map");
                    break;
                } else if attempt == max_attempts {
                    tracing::error!(sign_id = ?sign_respond_tx.id, "failed to insert sign respond tx into map after {max_attempts} attempts");
                }
            }
        }
    }
}
