use alloy::dyn_abi::{DynSolType, DynSolValue};
use alloy::primitives::Bytes;
use borsh::BorshSerialize;
use mpc_midnight_respond_codec::{executed_output, validate_output_schema, TracedReturn};
use mpc_primitives::SerDeserFormat;
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;

use crate::event_parsing::is_contract_call;

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
        let encode: fn(&Output, &[AbiField]) -> anyhow::Result<Vec<u8>> = match format {
            SerDeserFormat::Abi => encode_abi,
            SerDeserFormat::Borsh => encode_borsh,
            SerDeserFormat::Fab => anyhow::bail!(
                "Midnight responses derive from the output schema; use build_serialized_output"
            ),
        };
        let schema = parse_schema_fields(schema_json_bytes)?;
        let data_owned;
        let data = if self.is_contract_call() {
            self
        } else {
            data_owned = default_output_for_non_contract_call(&schema)?;
            &data_owned
        };
        encode(data, &schema)
    }
}

#[derive(Debug)]
pub struct TransactionOutput {
    pub output: Output,
}

impl TransactionOutput {
    pub fn non_contract_call_output() -> Self {
        Self {
            output: Output {
                fields: HashMap::new(),
                from_contract_call: false,
            },
        }
    }

    pub fn from_call_result(schema_json: &[u8], call_result: &Bytes) -> anyhow::Result<Self> {
        anyhow::ensure!(
            call_result.len() <= MAX_RETURN_DATA_BYTES,
            "return data of {} bytes exceeds {MAX_RETURN_DATA_BYTES}",
            call_result.len()
        );
        let schema = parse_output_schema_fields(schema_json)?;
        let tuple_type = parse_schema_type(&schema)?;

        // Return values form an ABI parameter sequence, without an outer tuple offset.
        let DynSolValue::Tuple(values) = tuple_type
            .abi_decode_params(call_result)
            .map_err(|e| anyhow::anyhow!("Failed to tuple types: {e:?}"))?
        else {
            anyhow::bail!("Can't decode to tuple type");
        };

        let mut output_map = HashMap::new();
        for (field, value) in schema.into_iter().zip(values) {
            output_map.insert(field.name, value);
        }

        Ok(TransactionOutput {
            output: Output {
                fields: output_map,
                from_contract_call: true,
            },
        })
    }
}

#[derive(Debug, Clone)]
pub enum TraceOutput {
    NotTraced,
    Output(Bytes),
    NoReturnData,
}

impl From<TraceOutput> for TracedReturn {
    fn from(trace: TraceOutput) -> Self {
        match trace {
            TraceOutput::NotTraced => Self::NotTraced,
            TraceOutput::NoReturnData => Self::Returned(Bytes::new()),
            TraceOutput::Output(data) => Self::Returned(data),
        }
    }
}

/// Decode a transaction's output and re-serialize it for the respond chain.
///
/// Contract calls require a `debug_traceTransaction` result. Void-returning
/// calls may have no return data; in that case, this follows the existing
/// plain-transfer behavior and synthesizes response defaults from
/// `respond_serialization_schema` (for example, `bool true`).
///
/// Midnight responses derive their encoding from the output schema alone and
/// ignore `respond_serialization_schema`; plain transfers and void calls attest
/// an empty output.
pub fn build_serialized_output(
    is_contract_call: bool,
    output_deserialization_schema: &[u8],
    trace_output: TraceOutput,
    respond_serialization_format: SerDeserFormat,
    respond_serialization_schema: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if respond_serialization_format == SerDeserFormat::Fab {
        return executed_output(
            is_contract_call,
            output_deserialization_schema,
            trace_output.into(),
        );
    }
    let transaction_output = match OUTPUT_DESERIALIZATION_FORMAT {
        SerDeserFormat::Abi if is_contract_call => {
            let expects_no_output = output_schema_is_empty(output_deserialization_schema)?;
            match trace_output {
                TraceOutput::Output(trace_output) if trace_output.is_empty() && expects_no_output => {
                    TransactionOutput::non_contract_call_output()
                }
                TraceOutput::Output(_) if expects_no_output => anyhow::bail!(
                    "contract-call trace returned output but output schema declares no return values"
                ),
                TraceOutput::Output(trace_output) => TransactionOutput::from_call_result(
                    output_deserialization_schema,
                    &trace_output,
                )?,
                TraceOutput::NoReturnData if expects_no_output => {
                    TransactionOutput::non_contract_call_output()
                }
                TraceOutput::NoReturnData => {
                    anyhow::bail!("contract-call trace has no return data for non-empty output schema")
                }
                TraceOutput::NotTraced => {
                    anyhow::bail!("contract-call output extraction requires trace output")
                }
            }
        }
        _ => TransactionOutput::non_contract_call_output(),
    };

    transaction_output
        .output
        .serialize(respond_serialization_format, respond_serialization_schema)
}

/// Refuse, before signing, what [`build_serialized_output`] refuses on the schemas
/// alone, by running it on all-zero return data, which decodes for every output type.
/// Refusals that depend on the real return data stay with extraction.
pub fn validate_schemas(
    calldata: &[u8],
    output_deserialization_schema: &[u8],
    respond_serialization_format: SerDeserFormat,
    respond_serialization_schema: &[u8],
) -> anyhow::Result<()> {
    let is_contract_call = is_contract_call(&Bytes::copy_from_slice(calldata));
    if respond_serialization_format == SerDeserFormat::Fab {
        return validate_output_schema(is_contract_call, output_deserialization_schema);
    }
    let trace = if is_contract_call && !output_schema_is_empty(output_deserialization_schema)? {
        let schema = parse_output_schema_fields(output_deserialization_schema)?;
        let words = parse_schema_type(&schema)?.minimum_words();
        let bytes = words
            .checked_mul(32)
            .ok_or_else(|| anyhow::anyhow!("output schema needs {words} words"))?;
        TraceOutput::Output(vec![0; bytes].into())
    } else {
        TraceOutput::NoReturnData
    };
    build_serialized_output(
        is_contract_call,
        output_deserialization_schema,
        trace,
        respond_serialization_format,
        respond_serialization_schema,
    )
    .map(drop)
}

fn output_schema_is_empty(schema_json: &[u8]) -> anyhow::Result<bool> {
    Ok(schema_json.is_empty() || parse_output_schema_fields(schema_json)?.is_empty())
}

fn encode_abi(data: &Output, schema: &[AbiField]) -> anyhow::Result<Vec<u8>> {
    let tuple_type = parse_schema_type(schema)?;
    let values = schema
        .iter()
        .map(|field| {
            data.fields
                .get(&field.name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Missing required field '{}' in output", field.name))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    // One tuple, mirroring `abi_decode_params`, so dynamic-field offsets are shared.
    let values = DynSolValue::Tuple(values);
    anyhow::ensure!(
        tuple_type.matches(&values),
        "output values don't match Solidity types {tuple_type}"
    );
    let encoded = values.abi_encode_params();
    anyhow::ensure!(
        encoded.len() <= MAX_RETURN_DATA_BYTES,
        "output of {} bytes exceeds {MAX_RETURN_DATA_BYTES}",
        encoded.len()
    );
    Ok(encoded)
}

fn encode_borsh(data: &Output, schema: &[AbiField]) -> anyhow::Result<Vec<u8>> {
    if schema.len() != 1 {
        anyhow::bail!("borsh schema must have exactly one field");
    }
    let val = data
        .fields
        .get(&schema[0].name)
        .ok_or_else(|| anyhow::anyhow!("missing value for field '{}'", schema[0].name))?;
    let mut buf = Vec::with_capacity(128);
    serialize_dynsol(&mut buf, val)?;
    Ok(buf)
}

fn serialize_dynsol<W: Write>(w: &mut W, v: &DynSolValue) -> anyhow::Result<()> {
    use DynSolValue::*;
    match v {
        Bool(b) => {
            b.serialize(w)?;
        }
        Address(a) => a.serialize(w)?,
        // Integer sizes are in bits; Borsh writes the native little-endian width.
        Uint(u, bits) => w.write_all(&u.to_le_bytes::<32>()[..bits / 8])?,
        Int(i, bits) => w.write_all(&i.to_le_bytes::<32>()[..bits / 8])?,
        FixedBytes(b, size) => w.write_all(&b[..*size])?,
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

/// The longest return data decoded, and the longest ABI output encoded from it.
const MAX_RETURN_DATA_BYTES: usize = 256 * 1024;

/// Bounds a field type before it is parsed, and with it the parser's nesting.
const MAX_TYPE_BYTES: usize = 32;

const MAX_FIELDS: usize = 32;

const MAX_FIXED_ARRAY_LEN: usize = 256;

/// Parse a schema's field types into the tuple every decode and encode uses, accepting
/// at most [`MAX_FIELDS`] fields, each an [`allowed`] type of at most [`MAX_TYPE_BYTES`].
///
/// Decoding pre-allocates at most [`MAX_FIELDS`] times [`MAX_FIXED_ARRAY_LEN`] values, and
/// each dynamic field reads at most the return data, so decoding is linear in the return
/// data. The largest schema, 32 fields of `uint256[256]`, fills [`MAX_RETURN_DATA_BYTES`].
fn parse_schema_type(schema: &[AbiField]) -> anyhow::Result<DynSolType> {
    anyhow::ensure!(
        schema.len() <= MAX_FIELDS,
        "schema has more than {MAX_FIELDS} fields"
    );
    let types = schema
        .iter()
        .map(|field| {
            anyhow::ensure!(
                field.typ.len() <= MAX_TYPE_BYTES,
                "field '{}' has a type longer than {MAX_TYPE_BYTES} bytes",
                field.name
            );
            let ty = field
                .typ
                .parse()
                .map_err(|e| anyhow::anyhow!("Failed to parse eth transaction types: {e:?}"))?;
            anyhow::ensure!(
                allowed(&ty),
                "field '{}' has unsupported type {ty}",
                field.name
            );
            Ok(ty)
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(DynSolType::Tuple(types))
}

/// A scalar, `bytes`, `string`, or an array of scalars at most [`MAX_FIXED_ARRAY_LEN`]
/// long when fixed.
fn allowed(ty: &DynSolType) -> bool {
    use DynSolType::*;
    let scalar = |ty: &DynSolType| matches!(ty, Bool | Address | Int(_) | Uint(_) | FixedBytes(_));
    match ty {
        Bytes | String => true,
        Array(element) => scalar(element),
        FixedArray(element, len) => scalar(element) && *len <= MAX_FIXED_ARRAY_LEN,
        _ => scalar(ty),
    }
}

fn parse_output_schema_fields(schema_json_bytes: &[u8]) -> anyhow::Result<Vec<AbiField>> {
    serde_json::from_slice(schema_json_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to get abi fields from schema: {e:?}"))
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
    use alloy::primitives::{I256, U256};

    const UINT256_SCHEMA: &[u8] = br#"[{"name":"amount","type":"uint256"}]"#;

    /// ABI-encoded `uint256` (32-byte big-endian).
    fn abi_uint256(value: u64) -> Bytes {
        let mut buf = [0u8; 32];
        buf[24..].copy_from_slice(&value.to_be_bytes());
        Bytes::from(buf.to_vec())
    }

    fn abi_bool(value: bool) -> Bytes {
        abi_uint256(u64::from(value))
    }

    /// Admission refuses exactly the schemas extraction refuses on real return data.
    #[test]
    fn validate_schemas_agrees_with_extraction() {
        use SerDeserFormat::{Abi, Borsh, Fab};
        let call = [0xa9, 0x05, 0x9c, 0xbb];
        let bool_schema: &[u8] = br#"[{"name":"ok","type":"bool"}]"#;
        let string_schema: &[u8] = br#"[{"name":"s","type":"string"}]"#;
        let uint64_schema: &[u8] = br#"[{"name":"n","type":"uint64"}]"#;
        let function_schema: &[u8] = br#"[{"name":"f","type":"function"}]"#;
        let string_output = Bytes::from(
            DynSolValue::Tuple(vec![DynSolValue::String("hi".into())]).abi_encode_params(),
        );
        let traced = |data: Bytes| TraceOutput::Output(data);
        // Calldata, output schema, format, respond schema, trace, accepted.
        type Case<'a> = (
            &'a [u8],
            &'a [u8],
            SerDeserFormat,
            &'a [u8],
            TraceOutput,
            bool,
        );
        #[rustfmt::skip]
        let cases: [Case; 15] = [
            (&call, bool_schema, Abi, bool_schema, traced(abi_bool(true)), true),
            (&call, string_schema, Abi, string_schema, traced(string_output), true),
            (&call, b"{", Abi, bool_schema, traced(abi_bool(true)), false),
            (&call, bool_schema, Abi, string_schema, traced(abi_bool(true)), false),
            (&[], b"{", Abi, bool_schema, TraceOutput::NotTraced, true),
            (&[], b"", Abi, UINT256_SCHEMA, TraceOutput::NotTraced, false),
            (&call, uint64_schema, Borsh, uint64_schema, traced(abi_uint256(7)), true),
            (&call, b"[]", Borsh, bool_schema, TraceOutput::NoReturnData, true),
            (&call, function_schema, Borsh, function_schema, traced(abi_uint256(0)), false),
            (&[], b"", Borsh, b"", TraceOutput::NotTraced, false),
            (&call, bool_schema, Borsh, b"{", traced(abi_bool(true)), false),
            (&call, bool_schema, Fab, b"", traced(abi_bool(true)), true),
            (&[], b"", Fab, b"", TraceOutput::NotTraced, true),
            (&call, string_schema, Fab, b"", traced(abi_bool(true)), false),
            (&[], bool_schema, Fab, b"", TraceOutput::NotTraced, false),
        ];
        for (calldata, output, format, respond, trace, accepted) in cases {
            let case = format!("{format:?} {calldata:?} {output:?} {respond:?}");
            let is_contract_call = is_contract_call(&Bytes::copy_from_slice(calldata));
            let extracted =
                build_serialized_output(is_contract_call, output, trace, format, respond);
            assert_eq!(extracted.is_ok(), accepted, "{case}: {extracted:?}");
            let admitted = validate_schemas(calldata, output, format, respond);
            assert_eq!(admitted.is_ok(), accepted, "{case}: {admitted:?}");
        }
    }

    #[test]
    fn parse_schema_type_accepts_only_allowed_types() {
        let parse = |types: &[&str]| {
            let schema: Vec<_> = types
                .iter()
                .map(|typ| AbiField {
                    name: "a".into(),
                    typ: typ.to_string(),
                })
                .collect();
            parse_schema_type(&schema)
        };
        let max_fields = vec!["uint256[256]"; MAX_FIELDS];
        let over_max_fields = vec!["bool"; MAX_FIELDS + 1];
        // `uint8[0..01]`, padded with zeros to the given length.
        let padded = |len: usize| format!("uint8[{}1]", "0".repeat(len - 8));
        let (max_bytes, over_max_bytes) = (padded(MAX_TYPE_BYTES), padded(MAX_TYPE_BYTES + 1));
        let cases: [(&[&str], bool); 24] = [
            (&["uint256"], true),
            (&["bool"], true),
            (&["address"], true),
            (&["bytes32"], true),
            (&["bytes"], true),
            (&["string"], true),
            (&["uint8[256]"], true),
            (&["uint256[]"], true),
            (&max_fields, true),
            (&[&max_bytes], true),
            (&["uint8[257]"], false),
            (&["uint256[][]"], false),
            (&["uint256[2][]"], false),
            (&["bytes[]"], false),
            (&["string[]"], false),
            (&["(uint256,bool)"], false),
            (&["(bool)[]"], false),
            (&["function"], false),
            (&["bytes[2]"], false),
            (&["string[2]"], false),
            (&["uint8[2][2]"], false),
            (&["(bool)[2]"], false),
            (&[&over_max_bytes], false),
            (&over_max_fields, false),
        ];
        for (types, accepted) in cases {
            assert_eq!(parse(types).is_ok(), accepted, "{types:?}");
        }
    }

    #[test]
    fn from_call_result_refuses_oversized_return_data() {
        let decode = |len: usize| {
            TransactionOutput::from_call_result(UINT256_SCHEMA, &Bytes::from(vec![0; len]))
        };
        assert!(decode(MAX_RETURN_DATA_BYTES).is_ok());
        let err = decode(MAX_RETURN_DATA_BYTES + 1).expect_err("return data over the cap");
        assert!(format!("{err}").contains("return data of"), "{err}");

        let largest = AbiField {
            name: "a".into(),
            typ: "uint256[256]".into(),
        };
        let largest_schema = serde_json::to_vec(&vec![largest; MAX_FIELDS]).unwrap();
        let zeros = Bytes::from(vec![0; MAX_RETURN_DATA_BYTES]);
        assert!(TransactionOutput::from_call_result(&largest_schema, &zeros).is_ok());
    }

    /// A respond schema naming one output field several times re-encodes it each time.
    #[test]
    fn encode_abi_refuses_output_over_the_cap() {
        let output_schema: &[u8] = br#"[{"name":"b","type":"bytes"}]"#;
        let blob = DynSolValue::Bytes(vec![1; 100 * 1024]);
        let return_data = Bytes::from(DynSolValue::Tuple(vec![blob]).abi_encode_params());
        let extract = |respond_schema: &[u8]| {
            build_serialized_output(
                true,
                output_schema,
                TraceOutput::Output(return_data.clone()),
                SerDeserFormat::Abi,
                respond_schema,
            )
        };
        assert!(extract(output_schema).is_ok());
        let tripled = br#"[{"name":"b","type":"bytes"},{"name":"b","type":"bytes"},{"name":"b","type":"bytes"}]"#;
        let err = extract(tripled).expect_err("output over the cap");
        assert!(format!("{err}").contains("output of"), "{err}");
    }

    #[test]
    fn build_serialized_output_midnight_rejects_output_types_it_cannot_carry() {
        let output_schema = br#"[{"name":"message","type":"string"}]"#;
        let trace = Bytes::from(
            DynSolValue::Tuple(vec![DynSolValue::String("hello".to_string())]).abi_encode_params(),
        );

        let abi_result = build_serialized_output(
            true,
            output_schema,
            TraceOutput::Output(trace.clone()),
            SerDeserFormat::Abi,
            output_schema,
        );
        let fab_result = build_serialized_output(
            true,
            output_schema,
            TraceOutput::Output(trace),
            SerDeserFormat::Fab,
            b"",
        );

        assert!(abi_result.is_ok());
        let err = fab_result.expect_err("Midnight responses carry no string outputs");
        assert!(format!("{err}").contains("unsupported ABI output types"));
    }

    #[test]
    fn build_serialized_output_midnight_contract_bool() {
        let bool_schema = br#"[{"name":"ok","type":"bool"}]"#;
        let out = build_serialized_output(
            true,
            bool_schema,
            TraceOutput::Output(abi_bool(true)),
            SerDeserFormat::Fab,
            b"",
        )
        .unwrap();

        assert_eq!(out, vec![1]);
    }

    #[test]
    fn build_serialized_output_midnight_ignores_the_respond_schema() {
        let output_schema = br#"[{"name":"ok","type":"bool"}]"#;
        for respond_schema in [&b""[..], b"[]", br#"{"struct":{"ok":"u8"}}"#] {
            let out = build_serialized_output(
                true,
                output_schema,
                TraceOutput::Output(abi_bool(true)),
                SerDeserFormat::Fab,
                respond_schema,
            )
            .unwrap();
            assert_eq!(out, vec![1]);
        }
    }

    #[test]
    fn build_serialized_output_midnight_plain_transfer_attests_empty_output() {
        let out = build_serialized_output(
            false,
            b"[]",
            TraceOutput::NotTraced,
            SerDeserFormat::Fab,
            br#"[{"name":"ok","type":"bool"}]"#,
        )
        .unwrap();
        assert!(out.is_empty());

        let err = build_serialized_output(
            false,
            br#"[{"name":"ok","type":"bool"}]"#,
            TraceOutput::NotTraced,
            SerDeserFormat::Fab,
            br#"[{"name":"ok","type":"bool"}]"#,
        )
        .expect_err("a plain transfer cannot fill a non-empty output schema");
        assert!(format!("{err}").contains("plain transfer returns nothing"));
    }

    #[test]
    fn build_serialized_output_midnight_void_call_attests_empty_output() {
        let out = build_serialized_output(
            true,
            b"[]",
            TraceOutput::NoReturnData,
            SerDeserFormat::Fab,
            br#"[{"name":"ok","type":"bool"}]"#,
        )
        .unwrap();

        assert!(out.is_empty());
    }

    #[test]
    fn build_serialized_output_decodes_contract_call() {
        // `trace` is the function's ABI-encoded return value from debug_traceTransaction.
        let schema = br#"[{"name":"n","type":"uint256"},{"name":"s","type":"string"},{"name":"b","type":"bytes"}]"#;
        let trace = Bytes::from(
            DynSolValue::Tuple(vec![
                DynSolValue::Uint(U256::from(12_345), 256),
                DynSolValue::String("hi".to_string()),
                DynSolValue::Bytes(vec![1, 2, 3]),
            ])
            .abi_encode_params(),
        );
        let out = build_serialized_output(
            true,
            schema,
            TraceOutput::Output(trace.clone()),
            SerDeserFormat::Abi,
            schema,
        )
        .unwrap();
        assert_eq!(out, trace.to_vec());
    }

    #[test]
    fn build_serialized_output_non_contract_call_uses_defaults() {
        // `default_output_for_non_contract_call` only supports `bool`/`string`.
        let bool_schema: &[u8] = br#"[{"name":"ok","type":"bool"}]"#;
        let out = build_serialized_output(
            false,
            bool_schema,
            TraceOutput::NotTraced,
            SerDeserFormat::Abi,
            bool_schema,
        )
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
            TraceOutput::NotTraced,
            SerDeserFormat::Abi,
            UINT256_SCHEMA,
        );
        assert!(
            err.is_err(),
            "contract call without trace output must error"
        );
    }

    #[test]
    fn build_serialized_output_accepts_missing_trace_output_for_empty_schema() {
        let empty_schema = b"[]";
        let bool_schema: &[u8] = br#"[{"name":"ok","type":"bool"}]"#;
        let out = build_serialized_output(
            true,
            empty_schema,
            TraceOutput::NoReturnData,
            SerDeserFormat::Abi,
            bool_schema,
        )
        .unwrap();
        let mut expected = vec![0u8; 32];
        expected[31] = 1;
        assert_eq!(out, expected);
    }

    #[test]
    fn build_serialized_output_accepts_missing_trace_output_for_empty_schema_bytes() {
        let bool_schema: &[u8] = br#"[{"name":"ok","type":"bool"}]"#;
        let out = build_serialized_output(
            true,
            b"",
            TraceOutput::NoReturnData,
            SerDeserFormat::Abi,
            bool_schema,
        )
        .unwrap();
        let mut expected = vec![0u8; 32];
        expected[31] = 1;
        assert_eq!(out, expected);
    }

    #[test]
    fn build_serialized_output_void_return_borsh_response() {
        let bool_schema: &[u8] = br#"[{"name":"ok","type":"bool"}]"#;
        let out = build_serialized_output(
            true,
            b"",
            TraceOutput::NoReturnData,
            SerDeserFormat::Borsh,
            bool_schema,
        )
        .unwrap();
        assert_eq!(out, vec![1u8]);
    }

    #[test]
    fn build_serialized_output_borsh_uses_native_widths() {
        let bytes4 = alloy::primitives::B256::right_padding_from(&[0xde, 0xad, 0xbe, 0xef]);
        let cases = [
            (
                "uint8",
                DynSolValue::Uint(U256::from(7), 8),
                borsh::to_vec(&7u8),
            ),
            (
                "uint64",
                DynSolValue::Uint(U256::from(7), 64),
                borsh::to_vec(&7u64),
            ),
            (
                "int32",
                DynSolValue::Int(I256::MINUS_ONE, 32),
                borsh::to_vec(&-1i32),
            ),
            (
                "bytes4",
                DynSolValue::FixedBytes(bytes4, 4),
                borsh::to_vec(&[0xdeu8, 0xad, 0xbe, 0xef]),
            ),
            (
                "uint64[]",
                DynSolValue::Array(vec![DynSolValue::Uint(U256::from(7), 64)]),
                borsh::to_vec(&vec![7u64]),
            ),
        ];
        for (ty, value, expected) in cases {
            let schema = format!(r#"[{{"name":"v","type":"{ty}"}}]"#);
            let trace = Bytes::from(DynSolValue::Tuple(vec![value]).abi_encode_params());
            let out = build_serialized_output(
                true,
                schema.as_bytes(),
                TraceOutput::Output(trace),
                SerDeserFormat::Borsh,
                schema.as_bytes(),
            )
            .unwrap();
            assert_eq!(out, expected.unwrap(), "{ty}");
        }
    }

    #[test]
    fn build_serialized_output_accepts_explicit_empty_trace_output_for_empty_schema() {
        let trace = Bytes::default();
        let bool_schema: &[u8] = br#"[{"name":"ok","type":"bool"}]"#;
        let out = build_serialized_output(
            true,
            b"",
            TraceOutput::Output(trace),
            SerDeserFormat::Abi,
            bool_schema,
        )
        .unwrap();
        let mut expected = vec![0u8; 32];
        expected[31] = 1;
        assert_eq!(out, expected);
    }

    #[test]
    fn build_serialized_output_rejects_missing_trace_output_for_non_empty_schema() {
        let err = build_serialized_output(
            true,
            UINT256_SCHEMA,
            TraceOutput::NoReturnData,
            SerDeserFormat::Abi,
            UINT256_SCHEMA,
        )
        .expect_err("missing trace output should fail for non-empty schema");
        assert!(format!("{err}").contains("no return data for non-empty output schema"));
    }

    #[test]
    fn build_serialized_output_rejects_empty_borsh_response_schema() {
        let err = build_serialized_output(
            true,
            b"",
            TraceOutput::NoReturnData,
            SerDeserFormat::Borsh,
            b"[]",
        )
        .expect_err("empty borsh response schema should fail");
        assert!(format!("{err}").contains("borsh schema must have exactly one field"));
    }

    #[test]
    fn build_serialized_output_rejects_empty_byte_response_schema() {
        let err = build_serialized_output(
            true,
            b"",
            TraceOutput::NoReturnData,
            SerDeserFormat::Abi,
            b"",
        )
        .expect_err("empty response schema bytes should fail");
        assert!(format!("{err}").contains("schema JSON parse failed"));
    }

    #[test]
    fn build_serialized_output_rejects_output_when_schema_declares_no_values() {
        let trace = abi_uint256(1);
        let err = build_serialized_output(
            true,
            b"",
            TraceOutput::Output(trace),
            SerDeserFormat::Abi,
            UINT256_SCHEMA,
        )
        .expect_err("output with an empty output schema should fail");
        assert!(format!("{err}").contains("schema declares no return values"));
    }
}
