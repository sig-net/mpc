use alloy::primitives::{Bytes, I256, U256};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use borsh::BorshSerialize;
use mpc_primitives::SerDeserFormat;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;

// Use Abi as this is what we are using for ethereum
const OUTPUT_DESERIALIZATION_FORMAT: SerDeserFormat = SerDeserFormat::Abi;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
struct AbiField {
    name: String,
    #[serde(rename = "type")]
    typ: String,
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

#[derive(Debug)]
pub struct TransactionOutput {
    // TODO: consider if we need this field or use Output alone
    #[allow(dead_code)]
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
            .map(|f| f.typ.parse())
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse eth transaction types: {e:?}"))?;

        let tuple_type = DynSolType::Tuple(types);

        let DynSolValue::Tuple(values) = tuple_type
            .abi_decode(call_result)
            .map_err(|e| anyhow::anyhow!("Failed to tuple types: {e:?}"))?
        else {
            anyhow::bail!("Can't decode to tuple type");
        };

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

/// Decode a transaction's output and re-serialize it for the respond chain.
///
/// `trace_output` is the `debug_traceTransaction` return data, required when
/// `is_contract_call` is true.
pub fn build_serialized_output(
    is_contract_call: bool,
    output_deserialization_schema: &[u8],
    trace_output: Option<&Bytes>,
    respond_serialization_format: SerDeserFormat,
    respond_serialization_schema: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let transaction_output = match OUTPUT_DESERIALIZATION_FORMAT {
        SerDeserFormat::Abi if is_contract_call => {
            let trace_output = trace_output.ok_or_else(|| {
                anyhow::anyhow!("contract-call output extraction requires trace output")
            })?;
            TransactionOutput::from_call_result(output_deserialization_schema, trace_output)?
        }
        _ => TransactionOutput::non_contract_call_output(),
    };

    transaction_output
        .output
        .serialize(respond_serialization_format, respond_serialization_schema)
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
    let mut combined = Vec::new();
    for v in values {
        combined.extend(v.abi_encode());
    }
    Ok(combined)
}

fn serialize_dynsol<W: Write>(w: &mut W, v: &DynSolValue) -> anyhow::Result<()> {
    use DynSolValue::*;
    match v {
        Bool(b) => {
            b.serialize(w)?;
        }
        Address(a) => a.serialize(w)?,
        Uint(u, size) => write_u256(w, *u, *size)?,
        Int(i, size) => write_i256(w, *i, *size)?,
        FixedBytes(b, _) => w.write_all(b.as_slice())?,
        Bytes(b) => b.serialize(w)?,
        String(s) => s.serialize(w)?,
        Array(xs) => {
            (xs.len() as u32).serialize(w)?;
            for x in xs {
                serialize_dynsol(w, x)?;
            }
        }
        FixedArray(xs) => {
            for x in xs {
                serialize_dynsol(w, x)?;
            }
        }
        Tuple(xs) => {
            for x in xs {
                serialize_dynsol(w, x)?;
            }
        }
        other => anyhow::bail!("unsupported DynSolValue variant: {other:?}"),
    }
    Ok(())
}

fn write_u256<W: Write>(w: &mut W, x: U256, size: usize) -> anyhow::Result<()> {
    let le = x.to_le_bytes::<{ U256::BYTES }>();
    w.write_all(&le[..size.min(U256::BYTES)])
        .map_err(Into::into)
}

fn write_i256<W: Write>(w: &mut W, x: I256, size: usize) -> anyhow::Result<()> {
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

/// Synthesize per-field default values for an `Output` whose source tx was
/// not a contract function call.
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

#[cfg(test)]
mod tests {
    use super::*;

    const UINT256_SCHEMA: &[u8] = br#"[{"name":"amount","type":"uint256"}]"#;

    /// ABI-encoded `uint256` (32-byte big-endian).
    fn abi_uint256(value: u64) -> Bytes {
        let mut buf = [0u8; 32];
        buf[24..].copy_from_slice(&value.to_be_bytes());
        Bytes::from(buf.to_vec())
    }

    #[test]
    fn build_serialized_output_decodes_contract_call() {
        // A contract-call tx whose function returned `uint256` 12345; `trace`
        // is that ABI-encoded return value from debug_traceTransaction.
        let trace = abi_uint256(12_345);
        let out = build_serialized_output(
            true,
            UINT256_SCHEMA,
            Some(&trace),
            SerDeserFormat::Abi,
            UINT256_SCHEMA,
        )
        .unwrap();
        assert_eq!(out, trace.to_vec());
    }

    #[test]
    fn build_serialized_output_non_contract_call_uses_defaults() {
        // `default_output_for_non_contract_call` only supports `bool`/`string`.
        let bool_schema: &[u8] = br#"[{"name":"ok","type":"bool"}]"#;
        let out =
            build_serialized_output(false, bool_schema, None, SerDeserFormat::Abi, bool_schema)
                .unwrap();
        // A plain transfer synthesizes a default: bool -> true, ABI-encoded as
        // a 32-byte word.
        let mut expected = vec![0u8; 32];
        expected[31] = 1;
        assert_eq!(out, expected);
    }

    #[test]
    fn build_serialized_output_requires_trace_for_contract_call() {
        let err = build_serialized_output(
            true,
            UINT256_SCHEMA,
            None,
            SerDeserFormat::Abi,
            UINT256_SCHEMA,
        );
        assert!(
            err.is_err(),
            "contract call without trace output must error"
        );
    }
}
