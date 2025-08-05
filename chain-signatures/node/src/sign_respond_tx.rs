use alloy::primitives::Bytes;
use alloy::primitives::B256;
use alloy_dyn_abi::{DynSolType, DynSolValue};
use anchor_lang::prelude::Pubkey;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Copy)]
pub struct SignRespondTxId(pub B256);

impl From<B256> for SignRespondTxId {
    fn from(b256: B256) -> Self {
        SignRespondTxId(b256)
    }
}

#[derive(Debug, Deserialize, Clone)]
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
    pub requqest_id: String,
    pub from_address: String,
    pub nonce: u64,
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
