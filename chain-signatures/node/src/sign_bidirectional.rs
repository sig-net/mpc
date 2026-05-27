use crate::protocol::{Chain, IndexedSignRequest};
use alloy::primitives::{keccak256, Address, Bytes, B256, I256, U256};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use borsh::BorshSerialize;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::{AffinePoint, Scalar};
use mpc_crypto::derive_key;
use mpc_primitives::{SerDeserFormat, Signature};
use rlp::{Rlp, RlpStream};
use serde_json::Value;
use sha3::{Digest, Keccak256};

use std::collections::HashMap;
use std::io::Write;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Copy)]
pub struct BidirectionalTxId(pub B256);

pub type RequestId = [u8; 32];

impl From<B256> for BidirectionalTxId {
    fn from(b256: B256) -> Self {
        BidirectionalTxId(b256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
struct AbiField {
    name: String,
    #[serde(rename = "type")]
    typ: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SignStatus {
    /// Request has been received on the source chain and is waiting for a `respond`
    /// transaction to be observed.
    AwaitingResponse,
    /// Request has been responded to and the derived transaction is now waiting to
    /// execute on the destination chain.
    PendingExecution,
    /// Execution was confirmed and final respond request is waiting to be signed.
    AwaitingResponseBidirectional,
}

#[derive(Debug, Clone, Hash, serde::Serialize, serde::Deserialize)]
pub struct BidirectionalTx {
    pub id: BidirectionalTxId,
    pub sender: [u8; 32],
    pub serialized_transaction: Vec<u8>,
    pub source_chain: Chain,
    pub target_chain: Chain,
    // mainnet caip2_id of the target chain where the signed transaction will be sent
    // This must be a supported chain in the Chain enum in primitives.
    pub caip2_id: String,
    pub key_version: u32,
    pub deposit: u64,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub output_deserialization_schema: Vec<u8>,
    pub respond_serialization_schema: Vec<u8>,
    pub request_id: [u8; 32],
    pub from_address: Address,
    pub nonce: u64,
}

impl BidirectionalTx {
    pub(crate) fn sender_string(&self) -> anyhow::Result<String> {
        if self.source_chain == Chain::Canton {
            return Ok(hex::encode(self.sender));
        }
        crate::stream::ops::sender_string(self.sender, self.source_chain)
    }

    pub(crate) fn epsilon(&self, path: &str) -> anyhow::Result<Scalar> {
        match self.source_chain {
            Chain::Solana => Ok(mpc_crypto::kdf::derive_epsilon_sol(
                self.key_version,
                &self.sender_string()?,
                path,
            )),
            Chain::Hydration => Ok(mpc_crypto::kdf::derive_epsilon_hydration(
                self.key_version,
                &self.sender_string()?,
                path,
            )),
            Chain::Canton => Ok(mpc_crypto::kdf::derive_epsilon_canton(
                self.key_version,
                &self.sender_string()?,
                path,
            )),
            _ => anyhow::bail!("Unsupported chain: {}", self.source_chain),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Output {
    fields: HashMap<String, DynSolValue>,
    /// `true` when this `Output` was built from a real ETH contract-call return
    /// (via `TransactionOutput::from_call_result`); `false` for the
    /// `non_contract_call_output()` path (plain transfers). Drives whether
    /// `serialize` encodes real data or synthesizes per-schema defaults.
    from_contract_call: bool,
}

impl Output {
    pub fn is_contract_call(&self) -> bool {
        self.from_contract_call
    }

    /// Encode this output for the given format using `schema_json_bytes` as
    /// the field shape. For non-contract-call outputs (plain transfers),
    /// synthesizes per-field default values from the schema. Real decoded
    /// data from `from_call_result` flows through unchanged.
    pub fn serialize(
        &self,
        format: SerDeserFormat,
        schema_json_bytes: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let schema = parse_schema_fields(schema_json_bytes)?;
        let data_owned;
        let data = if self.is_contract_call() {
            self
        } else {
            data_owned = default_output_for_non_contract_call(&schema)?;
            &data_owned
        };
        match format {
            SerDeserFormat::Abi => encode_abi(data, &schema),
            SerDeserFormat::Borsh => encode_borsh(data, &schema),
        }
    }
}

fn encode_abi(data: &Output, schema: &[AbiField]) -> anyhow::Result<Vec<u8>> {
    let values = schema
        .iter()
        .map(|field| match data.fields.get(&field.name) {
            Some(value) => Ok(value.clone()),
            None => Err(anyhow::anyhow!(
                "Missing required field '{}' in output",
                field.name
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    encode_abi_values(schema, &values)
}

fn encode_borsh(data: &Output, schema: &[AbiField]) -> anyhow::Result<Vec<u8>> {
    assert!(
        schema.len() == 1,
        "borsh schema must have exactly one field"
    );
    let val = data
        .fields
        .get(&schema[0].name)
        .ok_or_else(|| anyhow::anyhow!("missing value for field '{}'", schema[0].name))?;
    let mut buf = Vec::with_capacity(128);
    serialize_dynsol(&mut buf, val)?;
    Ok(buf)
}

#[derive(Debug)]
pub struct TransactionOutput {
    pub success: bool,
    pub output: Output,
}

impl TransactionOutput {
    pub fn non_contract_call_output() -> Self {
        Self {
            success: true,
            output: Output {
                fields: HashMap::new(),
                from_contract_call: false,
            },
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
            anyhow::bail!("Can't decode to tuple type");
        };

        // Map to named output
        let mut output_map = HashMap::new();
        for (field, value) in schema.into_iter().zip(values) {
            output_map.insert(field.name, value);
        }

        Ok(TransactionOutput {
            success: true,
            output: Output {
                fields: output_map,
                from_contract_call: true,
            },
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

pub fn sign_and_hash_transaction(
    unsigned_rlp: &[u8],
    signature: Signature,
) -> anyhow::Result<([u8; 32], u64)> {
    let r = signature.big_r.x().as_slice().to_vec();
    let s = signature.s.to_bytes().as_slice().to_vec();
    let y_parity = signature.recovery_id == 1;

    if is_eip1559(unsigned_rlp) {
        sign_and_hash_eip1559_from_unsigned(unsigned_rlp, &r, &s, y_parity)
    } else {
        // Extract chain_id from the unsigned RLP (it's the 7th field in legacy transactions)
        // In legacy Ethereum transactions with EIP-155, there are 9 fields:
        // [nonce, gasPrice, gasLimit, to, value, data, chain_id, 0, 0]
        // The chain_id is the 7th field (index 6, 0-based).
        // We check for at least 9 fields to ensure chain_id is present.
        let rlp = Rlp::new(unsigned_rlp);
        let chain_id = if rlp.item_count().unwrap_or(0) >= 9 {
            rlp.val_at::<u64>(6).ok()
        } else {
            None
        };
        sign_and_hash_legacy_from_unsigned(unsigned_rlp, chain_id, &r, &s, y_parity)
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
    let mut srlp = EthereumTxRlp::new_list(12);
    for i in 0..9 {
        srlp.append_raw_field(rlp.at(i)?.as_raw());
    }
    let y: u8 = if y_parity { 1 } else { 0 };
    srlp.append_u8(y);
    srlp.append_uint_bytes(r);
    srlp.append_uint_bytes(s);

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
    let mut out = EthereumTxRlp::new_list(9);
    for i in 0..6 {
        out.append_raw_field(rlp.at(i)?.as_raw());
    }
    let v: u64 = 35 + 2 * chain_id.unwrap_or(0) + if y_parity { 1 } else { 0 };
    out.append_u64(v);
    out.append_uint_bytes(r);
    out.append_uint_bytes(s);

    let signed_bytes = out.into_vec();
    let hash = alloy_primitives::keccak256(&signed_bytes);
    Ok((hash.into(), nonce))
}

struct EthereumTxRlp {
    stream: RlpStream,
}

impl EthereumTxRlp {
    fn new_list(len: usize) -> Self {
        Self {
            stream: RlpStream::new_list(len),
        }
    }

    fn append_raw_field(&mut self, raw: &[u8]) {
        self.stream.append_raw(raw, 1);
    }

    fn append_u8(&mut self, value: u8) {
        self.stream.append(&value);
    }

    fn append_u64(&mut self, value: u64) {
        self.stream.append(&value);
    }

    fn append_uint_bytes(&mut self, value: &[u8]) {
        let first_nonzero = value
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(value.len());
        if first_nonzero == value.len() {
            self.stream.append_empty_data();
            return;
        }

        self.stream.append(&value[first_nonzero..].to_vec());
    }

    fn as_raw(&self) -> &[u8] {
        self.stream.as_raw()
    }

    fn into_vec(self) -> Vec<u8> {
        self.stream.out().to_vec()
    }
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

pub fn derive_user_address(mpc_pk: mpc_crypto::PublicKey, derivation_epsilon: Scalar) -> Address {
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

/// Synthesize per-field default values for an `Output` whose source tx was
/// not a contract function call. The destination chain's contract still needs
/// shaped bytes back, so we fill defaults from the schema: `bool` → `true`,
/// `string` → `"non_function_call_success"`. Other field types are unsupported.
fn default_output_for_non_contract_call(schema: &[AbiField]) -> anyhow::Result<Output> {
    let mut data = HashMap::new();
    for field in schema {
        match field.typ.as_str() {
            "string" => {
                data.insert(
                    field.name.clone(),
                    DynSolValue::String("non_function_call_success".to_string()),
                );
            }
            "bool" => {
                data.insert(field.name.clone(), DynSolValue::Bool(true));
            }
            other => anyhow::bail!(
                "cannot synthesize default for non-function-call output of type {other}"
            ),
        }
    }
    Ok(Output {
        fields: data,
        from_contract_call: false,
    })
}

fn encode_abi_values(schema: &[AbiField], values: &[DynSolValue]) -> anyhow::Result<Vec<u8>> {
    if schema.len() != values.len() {
        anyhow::bail!(
            "Schema and values length mismatch: {} != {}",
            schema.len(),
            values.len()
        );
    }
    for (f, v) in schema.iter().zip(values.iter()) {
        let ty: DynSolType = f.typ.parse()?;
        if !ty.matches(v) {
            anyhow::bail!("Value {v:?} doesn't match Solidity type {}", f.typ);
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

/// Parse a schema JSON describing the response shape. Accepts a JSON array of
/// `{name, type}` objects (canonical form), a single object (treated as a
/// one-field schema), or a bare string (treated as a single typed field with
/// an empty name).
fn parse_schema_fields(schema_json_bytes: &[u8]) -> anyhow::Result<Vec<AbiField>> {
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
pub struct SignBidirectionalSignature {
    pub public_key: mpc_crypto::PublicKey,
    pub indexed: IndexedSignRequest,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::sign_and_hash_eip1559_from_unsigned;
    use alloy::consensus::{SignableTransaction, TxEip1559};
    use alloy::eips::eip2718::Encodable2718;
    use alloy::primitives::{Bytes, FixedBytes, Signature, TxKind, U256};

    #[test]
    fn eip1559_hash_matches_alloy_for_create_with_leading_zero_r() {
        let tx = TxEip1559 {
            chain_id: 31_337,
            nonce: 3,
            gas_limit: 100_000,
            max_fee_per_gas: 100_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Create,
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::new(),
        };
        let unsigned = tx.encoded_for_signing();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r[31] = 1;
        s[31] = 2;

        let (hash, nonce) = sign_and_hash_eip1559_from_unsigned(&unsigned, &r, &s, true).unwrap();

        let signed = tx
            .into_signed(Signature::from_scalars_and_parity(
                FixedBytes::from_slice(&r),
                FixedBytes::from_slice(&s),
                true,
            ))
            .encoded_2718();
        let expected_hash: [u8; 32] = alloy::primitives::keccak256(&signed).into();

        assert_eq!(hash, expected_hash);
        assert_eq!(nonce, 3);
    }
}
