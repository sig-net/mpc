use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use alloy::dyn_abi::DynSolValue;
use alloy::primitives::U256;
use anyhow::Context as _;
use signet_midnight_serde::{Descriptor, Value, U256 as MidnightU256};

use super::Output;

const MAX_RESPOND_PACKED_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RawSchemaField {
    name: String,
    typ: String,
    max_bytes: Option<usize>,
    max_items: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FixedCarrier {
    Bool,
    Uint { bits: u32 },
    Field,
    Address,
    Bytes { length: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RespondFieldKind {
    Fixed(FixedCarrier),
    String {
        max_bytes: usize,
    },
    Bytes {
        max_bytes: usize,
    },
    Array {
        element: FixedCarrier,
        max_items: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RespondField {
    name: String,
    kind: RespondFieldKind,
}

struct MidnightRespondPlan {
    fields: Vec<RespondField>,
    descriptor: Descriptor,
    packed_size: usize,
}

impl MidnightRespondPlan {
    fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        let raw_fields = parse_raw_schema(bytes, "respond schema")?;
        if raw_fields.is_empty() {
            anyhow::bail!("respond schema must contain at least one field");
        }

        let fields = raw_fields
            .into_iter()
            .map(normalize_respond_field)
            .collect::<anyhow::Result<Vec<_>>>()?;
        let descriptor = Descriptor::Struct {
            fields: fields
                .iter()
                .map(|field| (field.name.clone(), descriptor_for_kind(&field.kind)))
                .collect(),
        };
        let packed_size = signet_midnight_serde::serialized_size(&descriptor)
            .context("failed to size Midnight respond schema")?;
        if packed_size > MAX_RESPOND_PACKED_BYTES {
            anyhow::bail!(
                "Midnight respond schema packs to {packed_size} bytes, above the {MAX_RESPOND_PACKED_BYTES}-byte ceiling"
            );
        }

        Ok(Self {
            fields,
            descriptor,
            packed_size,
        })
    }

    fn value_for(&self, output: &Output) -> anyhow::Result<Value> {
        let mut fields = Vec::with_capacity(self.fields.len());
        for field in &self.fields {
            let value = if output.is_contract_call() {
                let raw = output.fields.get(&field.name).ok_or_else(|| {
                    anyhow::anyhow!("Midnight respond output is missing field '{}'", field.name)
                })?;
                value_for_kind(raw, &field.kind, &field.name).with_context(|| {
                    format!(
                        "failed to convert Midnight respond field '{}' from {} producer",
                        field.name,
                        source_variant(raw)
                    )
                })?
            } else {
                default_value_for_kind(&field.kind, &field.name)?
            };
            fields.push((field.name.clone(), value));
        }
        Ok(Value::Struct(fields))
    }
}

fn decode_schema_text(bytes: &[u8]) -> Cow<'_, str> {
    let text = String::from_utf8_lossy(bytes);
    if !text.starts_with('\u{feff}') {
        return text;
    }
    match text {
        Cow::Borrowed(text) => Cow::Borrowed(text.strip_prefix('\u{feff}').unwrap()),
        Cow::Owned(text) => Cow::Owned(text.strip_prefix('\u{feff}').unwrap().to_owned()),
    }
}

fn trim_ecmascript_whitespace(text: &str) -> &str {
    // ECMAScript trims BOM (U+FEFF) but not NEL (U+0085); Rust's `str::trim`
    // does the reverse, so both schema parsing and BigInt coercion use this set.
    text.trim_matches(|character: char| {
        character == '\u{feff}' || (character.is_whitespace() && character != '\u{0085}')
    })
}

pub(super) fn serialize(output: &Output, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let plan = MidnightRespondPlan::parse(bytes)?;
    let value = plan.value_for(output)?;
    let serialized = signet_midnight_serde::serialize(&plan.descriptor, &value, None)
        .context("failed to serialize Midnight respond output")?;
    debug_assert_eq!(serialized.len(), plan.packed_size);
    Ok(serialized)
}

fn parse_optional_capacity(raw: &str) -> Option<usize> {
    if let Ok(value) = raw.parse::<u64>() {
        return usize::try_from(value).ok();
    }
    let value = raw.parse::<f64>().ok()?;
    (value.is_finite() && value >= 0.0 && value.fract() == 0.0).then_some(value as usize)
}

fn parse_raw_schema(bytes: &[u8], label: &str) -> anyhow::Result<Vec<RawSchemaField>> {
    let text = decode_schema_text(bytes);
    let objects: Vec<HashMap<String, Box<serde_json::value::RawValue>>> =
        serde_json::from_str(&text)
            .with_context(|| format!("{label} must be a JSON array of fields"))?;
    let fields = objects
        .into_iter()
        .enumerate()
        .map(|(index, mut object)| {
            let name = parse_string_property(&mut object, "name", index, label)?;
            let typ = parse_string_property(&mut object, "type", index, label)?;
            let max_bytes = object
                .remove("maxBytes")
                .and_then(|raw| parse_optional_capacity(raw.get()));
            let max_items = object
                .remove("maxItems")
                .and_then(|raw| parse_optional_capacity(raw.get()));
            Ok(RawSchemaField {
                name,
                typ,
                max_bytes,
                max_items,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut names = HashSet::with_capacity(fields.len());
    for (index, field) in fields.iter().enumerate() {
        if field.name.is_empty() {
            anyhow::bail!("{label} field {index} has a blank name");
        }
        if field.name == "__proto__" {
            anyhow::bail!("{label} field name '__proto__' is not supported");
        }
        if field.typ.is_empty() {
            anyhow::bail!("{label} field '{}' has a blank type", field.name);
        }
        if !names.insert(field.name.as_str()) {
            anyhow::bail!("{label} contains duplicate field name '{}'", field.name);
        }
    }
    Ok(fields)
}

fn parse_string_property(
    object: &mut HashMap<String, Box<serde_json::value::RawValue>>,
    property: &str,
    index: usize,
    label: &str,
) -> anyhow::Result<String> {
    let raw = object
        .remove(property)
        .ok_or_else(|| anyhow::anyhow!("{label} field {index} is missing '{property}'"))?;
    serde_json::from_str(raw.get())
        .with_context(|| format!("{label} field {index} '{property}' must be a string"))
}

fn normalize_respond_field(raw: RawSchemaField) -> anyhow::Result<RespondField> {
    let kind = match raw.typ.as_str() {
        "string" => RespondFieldKind::String {
            max_bytes: required_capacity(raw.max_bytes, &raw.name, "string", "maxBytes")?,
        },
        "bytes" => RespondFieldKind::Bytes {
            max_bytes: required_capacity(raw.max_bytes, &raw.name, "bytes", "maxBytes")?,
        },
        typ if typ.ends_with("[]") => RespondFieldKind::Array {
            element: classify_fixed_carrier(&typ[..typ.len() - 2], &raw.name)?,
            max_items: required_capacity(raw.max_items, &raw.name, typ, "maxItems")?,
        },
        typ => RespondFieldKind::Fixed(classify_fixed_carrier(typ, &raw.name)?),
    };
    Ok(RespondField {
        name: raw.name,
        kind,
    })
}

fn required_capacity(
    capacity: Option<usize>,
    field_name: &str,
    typ: &str,
    capacity_name: &str,
) -> anyhow::Result<usize> {
    match capacity {
        Some(capacity) if capacity > 0 => Ok(capacity),
        Some(_) => anyhow::bail!(
            "Midnight respond field '{field_name}' ({typ}) requires positive {capacity_name}"
        ),
        None => {
            anyhow::bail!("Midnight respond field '{field_name}' ({typ}) requires {capacity_name}")
        }
    }
}

fn classify_fixed_carrier(typ: &str, field_name: &str) -> anyhow::Result<FixedCarrier> {
    match typ {
        "bool" => return Ok(FixedCarrier::Bool),
        "uint256" | "field" => return Ok(FixedCarrier::Field),
        "address" => return Ok(FixedCarrier::Address),
        _ => {}
    }

    if let Some(digits) = typ.strip_prefix("uint") {
        if let Ok(bits) = digits.parse::<u32>() {
            if typ == format!("uint{bits}") && (8..=248).contains(&bits) && bits % 8 == 0 {
                return Ok(FixedCarrier::Uint { bits });
            }
        }
    }
    if let Some(digits) = typ.strip_prefix("bytes") {
        if let Ok(length) = digits.parse::<usize>() {
            if typ == format!("bytes{length}") && (1..=32).contains(&length) {
                return Ok(FixedCarrier::Bytes { length });
            }
        }
    }

    anyhow::bail!("Midnight respond field '{field_name}' has unsupported type '{typ}'")
}

fn descriptor_for_kind(kind: &RespondFieldKind) -> Descriptor {
    match kind {
        RespondFieldKind::Fixed(carrier) => descriptor_for_fixed(carrier),
        RespondFieldKind::String { max_bytes } | RespondFieldKind::Bytes { max_bytes } => {
            Descriptor::Struct {
                fields: vec![
                    ("len".to_string(), Descriptor::UintBits { bits: 64 }),
                    ("data".to_string(), Descriptor::Bytes { length: *max_bytes }),
                ],
            }
        }
        RespondFieldKind::Array { element, max_items } => Descriptor::Struct {
            fields: vec![
                ("len".to_string(), Descriptor::UintBits { bits: 64 }),
                (
                    "items".to_string(),
                    Descriptor::Vector {
                        length: *max_items,
                        element: Box::new(descriptor_for_fixed(element)),
                    },
                ),
            ],
        },
    }
}

fn descriptor_for_fixed(carrier: &FixedCarrier) -> Descriptor {
    match carrier {
        FixedCarrier::Bool => Descriptor::Boolean,
        FixedCarrier::Uint { bits } => Descriptor::UintBits { bits: *bits },
        FixedCarrier::Field | FixedCarrier::Address => Descriptor::Field,
        FixedCarrier::Bytes { length } => Descriptor::Bytes { length: *length },
    }
}

fn value_for_kind(
    raw: &DynSolValue,
    kind: &RespondFieldKind,
    label: &str,
) -> anyhow::Result<Value> {
    match kind {
        RespondFieldKind::Fixed(carrier) => fixed_value(raw, carrier, label),
        RespondFieldKind::String { max_bytes } => {
            let text = as_text(raw, label)?;
            dynamic_bytes_value(text.into_bytes(), *max_bytes, label)
        }
        RespondFieldKind::Bytes { max_bytes } => {
            dynamic_bytes_value(as_bytes(raw, label)?, *max_bytes, label)
        }
        RespondFieldKind::Array { element, max_items } => {
            let raw_items = as_sequence(raw, label)?;
            if raw_items.len() > *max_items {
                anyhow::bail!(
                    "Midnight respond field '{label}' has {} items, above maxItems {max_items}",
                    raw_items.len()
                );
            }
            let mut items = Vec::with_capacity(*max_items);
            for (index, raw_item) in raw_items.iter().enumerate() {
                items.push(fixed_value(
                    raw_item,
                    element,
                    &format!("{label}[{index}]"),
                )?);
            }
            items.resize_with(*max_items, || zero_for_fixed(element));
            Ok(Value::Struct(vec![
                (
                    "len".to_string(),
                    Value::Uint(MidnightU256::from(raw_items.len() as u64)),
                ),
                ("items".to_string(), Value::Vector(items)),
            ]))
        }
    }
}

fn dynamic_bytes_value(payload: Vec<u8>, max_bytes: usize, label: &str) -> anyhow::Result<Value> {
    if payload.len() > max_bytes {
        anyhow::bail!(
            "Midnight respond field '{label}' is {} bytes, above maxBytes {max_bytes}",
            payload.len()
        );
    }
    let payload_len = payload.len();
    let mut data = vec![0u8; max_bytes];
    data[..payload_len].copy_from_slice(&payload);
    Ok(Value::Struct(vec![
        (
            "len".to_string(),
            Value::Uint(MidnightU256::from(payload_len as u64)),
        ),
        ("data".to_string(), Value::Bytes(data)),
    ]))
}

fn fixed_value(raw: &DynSolValue, carrier: &FixedCarrier, label: &str) -> anyhow::Result<Value> {
    match carrier {
        FixedCarrier::Bool => match raw {
            DynSolValue::Bool(value) => Ok(Value::Bool(*value)),
            _ => anyhow::bail!(
                "Midnight respond field '{label}' expects bool, got {} producer",
                source_variant(raw)
            ),
        },
        FixedCarrier::Uint { .. } => Ok(Value::Uint(to_midnight_u256(as_integer(raw, label)?))),
        FixedCarrier::Field => Ok(Value::Field(to_midnight_u256(as_integer(raw, label)?))),
        FixedCarrier::Address => {
            let value = as_integer(raw, label)?;
            if value >= (U256::from(1u8) << 160) {
                anyhow::bail!("Midnight respond field '{label}' exceeds the 160-bit address bound");
            }
            Ok(Value::Field(to_midnight_u256(value)))
        }
        FixedCarrier::Bytes { length } => {
            let bytes = as_bytes(raw, label)?;
            if bytes.len() != *length {
                anyhow::bail!(
                    "Midnight respond field '{label}' expects {length} bytes, got {}",
                    bytes.len()
                );
            }
            Ok(Value::Bytes(bytes))
        }
    }
}

fn default_value_for_kind(kind: &RespondFieldKind, label: &str) -> anyhow::Result<Value> {
    match kind {
        RespondFieldKind::Fixed(FixedCarrier::Bool) => Ok(Value::Bool(true)),
        RespondFieldKind::String { max_bytes } => {
            dynamic_bytes_value(b"non_function_call_success".to_vec(), *max_bytes, label)
        }
        _ => anyhow::bail!(
            "cannot synthesize Midnight non-contract-call default for field '{label}'"
        ),
    }
}

fn zero_for_fixed(carrier: &FixedCarrier) -> Value {
    match carrier {
        FixedCarrier::Bool => Value::Bool(false),
        FixedCarrier::Uint { .. } => Value::Uint(MidnightU256::ZERO),
        FixedCarrier::Field | FixedCarrier::Address => Value::Field(MidnightU256::ZERO),
        FixedCarrier::Bytes { length } => Value::Bytes(vec![0u8; *length]),
    }
}

fn as_integer(value: &DynSolValue, label: &str) -> anyhow::Result<U256> {
    match value {
        DynSolValue::Uint(value, _) => Ok(*value),
        DynSolValue::Int(value, _) if !value.is_negative() => Ok(value.into_raw()),
        DynSolValue::Address(value) => integer_from_be_bytes(value.as_slice(), label, value),
        DynSolValue::FixedBytes(word, size) => {
            let bytes = fixed_bytes_slice(word.as_slice(), *size, label)?;
            integer_from_be_bytes(bytes, label, value)
        }
        DynSolValue::Bytes(bytes) => integer_from_be_bytes(bytes, label, value),
        DynSolValue::Function(value) => integer_from_be_bytes(value.as_slice(), label, value),
        DynSolValue::String(text) => parse_integer_text(text).with_context(|| {
            format!(
                "Midnight respond field '{label}' cannot read String producer '{text}' as an integer"
            )
        }),
        _ => anyhow::bail!(
            "Midnight respond field '{label}' expects an integer-compatible value, got {} producer",
            source_variant(value)
        ),
    }
}

fn integer_from_be_bytes(
    bytes: &[u8],
    label: &str,
    source: impl std::fmt::Debug,
) -> anyhow::Result<U256> {
    if bytes.is_empty() {
        anyhow::bail!("Midnight respond field '{label}' integer producer {source:?} has no bytes");
    }
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[][..], |first| &bytes[first..]);
    if significant.len() > 32 {
        anyhow::bail!(
            "Midnight respond field '{label}' integer producer {source:?} exceeds 256 bits"
        );
    }
    Ok(U256::from_be_slice(significant))
}

fn parse_integer_text(text: &str) -> anyhow::Result<U256> {
    let text = trim_ecmascript_whitespace(text);
    if text.is_empty() {
        return Ok(U256::ZERO);
    }

    let (digits, radix, negative) = if let Some(digits) = text.strip_prefix('+') {
        (digits, 10, false)
    } else if let Some(digits) = text.strip_prefix('-') {
        (digits, 10, true)
    } else if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        (digits, 16, false)
    } else if let Some(digits) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
        (digits, 8, false)
    } else if let Some(digits) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        (digits, 2, false)
    } else {
        (text, 10, false)
    };
    if digits.is_empty() {
        anyhow::bail!("integer text has no digits");
    }
    if digits.contains('_') {
        anyhow::bail!("integer text contains an underscore separator");
    }
    let value = U256::from_str_radix(digits, radix)?;
    if negative && !value.is_zero() {
        anyhow::bail!("integer text is negative");
    }
    Ok(value)
}

fn as_bytes(value: &DynSolValue, label: &str) -> anyhow::Result<Vec<u8>> {
    match value {
        DynSolValue::FixedBytes(word, size) => {
            Ok(fixed_bytes_slice(word.as_slice(), *size, label)?.to_vec())
        }
        DynSolValue::Bytes(bytes) => Ok(bytes.clone()),
        DynSolValue::Address(value) => Ok(value.as_slice().to_vec()),
        DynSolValue::Function(value) => Ok(value.as_slice().to_vec()),
        DynSolValue::String(text) => parse_hex_bytes(text).with_context(|| {
            format!("Midnight respond field '{label}' cannot read String producer as 0x bytes")
        }),
        _ => anyhow::bail!(
            "Midnight respond field '{label}' expects a bytes-compatible value, got {} producer",
            source_variant(value)
        ),
    }
}

fn as_text(value: &DynSolValue, label: &str) -> anyhow::Result<String> {
    match value {
        DynSolValue::String(text) => Ok(text.clone()),
        DynSolValue::Address(value) => Ok(value.to_checksum(None)),
        DynSolValue::FixedBytes(word, size) => {
            Ok(hex_text(fixed_bytes_slice(word.as_slice(), *size, label)?))
        }
        DynSolValue::Bytes(bytes) => Ok(hex_text(bytes)),
        DynSolValue::Function(value) => Ok(hex_text(value.as_slice())),
        _ => anyhow::bail!(
            "Midnight respond field '{label}' expects a text-compatible value, got {} producer",
            source_variant(value)
        ),
    }
}

fn as_sequence<'a>(value: &'a DynSolValue, label: &str) -> anyhow::Result<&'a [DynSolValue]> {
    match value {
        DynSolValue::Array(values)
        | DynSolValue::FixedArray(values)
        | DynSolValue::Tuple(values) => Ok(values),
        _ => anyhow::bail!(
            "Midnight respond field '{label}' expects an array-compatible value, got {} producer",
            source_variant(value)
        ),
    }
}

fn fixed_bytes_slice<'a>(word: &'a [u8], size: usize, label: &str) -> anyhow::Result<&'a [u8]> {
    word.get(..size).ok_or_else(|| {
        anyhow::anyhow!(
            "Midnight respond field '{label}' has invalid FixedBytes declared size {size}"
        )
    })
}

fn parse_hex_bytes(text: &str) -> anyhow::Result<Vec<u8>> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .ok_or_else(|| anyhow::anyhow!("hex bytes require a 0x prefix"))?;
    hex::decode(digits).map_err(Into::into)
}

fn hex_text(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn to_midnight_u256(value: U256) -> MidnightU256 {
    MidnightU256::from_le_bytes(&value.to_le_bytes::<32>())
}

fn source_variant(value: &DynSolValue) -> &'static str {
    match value {
        DynSolValue::Bool(_) => "Bool",
        DynSolValue::Int(_, _) => "Int",
        DynSolValue::Uint(_, _) => "Uint",
        DynSolValue::FixedBytes(_, _) => "FixedBytes",
        DynSolValue::Address(_) => "Address",
        DynSolValue::Function(_) => "Function",
        DynSolValue::Bytes(_) => "Bytes",
        DynSolValue::String(_) => "String",
        DynSolValue::Array(_) => "Array",
        DynSolValue::FixedArray(_) => "FixedArray",
        DynSolValue::Tuple(_) => "Tuple",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy::dyn_abi::{DynSolType, DynSolValue};
    use serde::Deserialize;

    use super::serialize;
    use crate::respond_bidirectional::{AbiField, Output};

    #[derive(Deserialize)]
    struct OracleFixture {
        vectors: Vec<OracleVector>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleVector {
        name: String,
        output_schema_hex: String,
        respond_schema_hex: String,
        call_result_hex: String,
        expected_output_hex: Option<String>,
        expected_reject: Option<bool>,
    }

    #[test]
    fn replays_every_typescript_oracle_vector() {
        let fixture: OracleFixture = serde_json::from_str(include_str!(
            "../../tests/fixtures/midnight_respond_vectors.json"
        ))
        .unwrap();
        assert!(!fixture.vectors.is_empty());

        for vector in fixture.vectors {
            let output_schema: Vec<AbiField> =
                serde_json::from_slice(&hex::decode(&vector.output_schema_hex).unwrap()).unwrap();
            let respond_schema = hex::decode(&vector.respond_schema_hex).unwrap();
            let call_result = hex::decode(&vector.call_result_hex).unwrap();
            let types = output_schema
                .iter()
                .map(|field| field.typ.parse())
                .collect::<Result<Vec<DynSolType>, _>>()
                .unwrap();
            let DynSolValue::Tuple(values) = DynSolType::Tuple(types)
                .abi_decode_params(&call_result)
                .unwrap()
            else {
                panic!("{}: test setup did not decode a tuple", vector.name);
            };
            let output = Output {
                fields: output_schema
                    .into_iter()
                    .zip(values)
                    .map(|(field, value)| (field.name, value))
                    .collect::<HashMap<_, _>>(),
                from_contract_call: true,
            };
            let result = serialize(&output, &respond_schema);

            if vector.expected_reject == Some(true) {
                assert!(
                    result.is_err(),
                    "{}: response-serialization rejection row was accepted",
                    vector.name
                );
                continue;
            }

            let actual = result.unwrap_or_else(|error| {
                panic!("{}: valid row was rejected: {error:#}", vector.name)
            });
            let expected = hex::decode(vector.expected_output_hex.as_ref().unwrap()).unwrap();
            assert_eq!(actual, expected, "{}: output bytes differ", vector.name);
        }
    }
}
