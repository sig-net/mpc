use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

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

impl RawSchemaField {
    fn parse(bytes: &[u8]) -> anyhow::Result<Vec<Self>> {
        let label = "respond schema";
        let objects: Vec<HashMap<String, Box<serde_json::value::RawValue>>> =
            serde_json::from_str(&decode_schema_text(bytes))
                .with_context(|| format!("{label} must be a JSON array of fields"))?;
        let fields = objects
            .into_iter()
            .enumerate()
            .map(|(index, mut object)| {
                let name = Self::string_property(&mut object, "name", index, label)?;
                let typ = Self::string_property(&mut object, "type", index, label)?;
                let max_bytes = object
                    .remove("maxBytes")
                    .and_then(|raw| Self::optional_capacity(raw.get()));
                let max_items = object
                    .remove("maxItems")
                    .and_then(|raw| Self::optional_capacity(raw.get()));
                Ok(Self {
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

    fn string_property(
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

    /// Capacities may be written as integers or whole-number floats (`64` or `64.0`).
    fn optional_capacity(raw: &str) -> Option<usize> {
        if let Ok(value) = raw.parse::<u64>() {
            return usize::try_from(value).ok();
        }
        let value = raw.parse::<f64>().ok()?;
        (value.is_finite() && value >= 0.0 && value.fract() == 0.0).then_some(value as usize)
    }
}

impl TryFrom<RawSchemaField> for RespondField {
    type Error = anyhow::Error;

    fn try_from(raw: RawSchemaField) -> anyhow::Result<Self> {
        let RawSchemaField {
            name,
            typ,
            max_bytes,
            max_items,
        } = raw;
        let kind = match typ.as_str() {
            "string" => RespondFieldKind::String {
                max_bytes: required_capacity(max_bytes, "string", "maxBytes")?,
            },
            "bytes" => RespondFieldKind::Bytes {
                max_bytes: required_capacity(max_bytes, "bytes", "maxBytes")?,
            },
            typ if typ.ends_with("[]") => RespondFieldKind::Array {
                element: typ[..typ.len() - 2].parse()?,
                max_items: required_capacity(max_items, typ, "maxItems")?,
            },
            typ => RespondFieldKind::Fixed(typ.parse()?),
        };
        Ok(Self { name, kind })
    }
}

impl RespondField {
    /// Resolve this field against the decoded output: the coerced producer
    /// value for a contract call, a synthesized default otherwise.
    fn resolve(&self, output: &Output) -> anyhow::Result<Value> {
        if !output.is_contract_call() {
            return self.kind.default_value();
        }
        let raw = output
            .fields
            .get(&self.name)
            .ok_or_else(|| anyhow::anyhow!("missing from decoded output"))?;
        self.kind
            .coerce(raw)
            .with_context(|| format!("failed to convert from {} producer", source_variant(raw)))
    }
}

impl FromStr for FixedCarrier {
    type Err = anyhow::Error;

    fn from_str(typ: &str) -> anyhow::Result<Self> {
        match typ {
            "bool" => Ok(FixedCarrier::Bool),
            "uint256" | "field" => Ok(FixedCarrier::Field),
            "address" => Ok(FixedCarrier::Address),
            _ => typ
                .strip_prefix("uint")
                .and_then(parse_canonical_uint_bits)
                .map(|bits| FixedCarrier::Uint { bits })
                .or_else(|| {
                    typ.strip_prefix("bytes")
                        .and_then(parse_canonical_bytes_length)
                        .map(|length| FixedCarrier::Bytes { length })
                })
                .ok_or_else(|| anyhow::anyhow!("unsupported type '{typ}'")),
        }
    }
}

/// Canonical decimal form only, so `uint08`, `uint+8` or `uint 8` never classify.
fn canonical_digits(digits: &str) -> bool {
    digits.bytes().all(|byte| byte.is_ascii_digit()) && !digits.starts_with('0')
}

fn parse_canonical_uint_bits(digits: &str) -> Option<u32> {
    if !canonical_digits(digits) {
        return None;
    }
    let bits = digits.parse().ok()?;
    ((8..=248).contains(&bits) && bits % 8 == 0).then_some(bits)
}

fn parse_canonical_bytes_length(digits: &str) -> Option<usize> {
    if !canonical_digits(digits) {
        return None;
    }
    let length = digits.parse().ok()?;
    (1..=32).contains(&length).then_some(length)
}

impl FixedCarrier {
    fn coerce(&self, raw: &DynSolValue) -> anyhow::Result<Value> {
        match self {
            FixedCarrier::Bool => match raw {
                DynSolValue::Bool(value) => Ok(Value::Bool(*value)),
                _ => incompatible("bool", raw),
            },
            FixedCarrier::Uint { .. } => Ok(Value::Uint(to_midnight_u256(as_integer(raw)?))),
            FixedCarrier::Field => Ok(Value::Field(to_midnight_u256(as_integer(raw)?))),
            FixedCarrier::Address => {
                let value = as_integer(raw)?;
                if value >= (U256::from(1u8) << 160) {
                    anyhow::bail!("exceeds the 160-bit address bound");
                }
                Ok(Value::Field(to_midnight_u256(value)))
            }
            FixedCarrier::Bytes { length } => {
                let bytes = as_bytes(raw)?;
                if bytes.len() != *length {
                    anyhow::bail!("expects {length} bytes, got {}", bytes.len());
                }
                Ok(Value::Bytes(bytes))
            }
        }
    }

    /// The zero element used to right-pad fixed-capacity arrays.
    fn zero_value(&self) -> Value {
        match self {
            FixedCarrier::Bool => Value::Bool(false),
            FixedCarrier::Uint { .. } => Value::Uint(MidnightU256::ZERO),
            FixedCarrier::Field | FixedCarrier::Address => Value::Field(MidnightU256::ZERO),
            FixedCarrier::Bytes { length } => Value::Bytes(vec![0u8; *length]),
        }
    }
}

impl RespondFieldKind {
    fn coerce(&self, raw: &DynSolValue) -> anyhow::Result<Value> {
        match self {
            RespondFieldKind::Fixed(carrier) => carrier.coerce(raw),
            RespondFieldKind::String { max_bytes } => {
                Self::dynamic_bytes(as_text(raw)?.into_bytes(), *max_bytes)
            }
            RespondFieldKind::Bytes { max_bytes } => {
                Self::dynamic_bytes(as_bytes(raw)?, *max_bytes)
            }
            RespondFieldKind::Array { element, max_items } => {
                Self::coerce_array(raw, element, *max_items)
            }
        }
    }

    fn default_value(&self) -> anyhow::Result<Value> {
        match self {
            RespondFieldKind::Fixed(FixedCarrier::Bool) => Ok(Value::Bool(true)),
            RespondFieldKind::String { max_bytes } => {
                Self::dynamic_bytes(b"non_function_call_success".to_vec(), *max_bytes)
            }
            _ => anyhow::bail!("cannot synthesize a non-contract-call default"),
        }
    }

    /// Right-pad `payload` with zeros to `max_bytes`, prefixing its length.
    fn dynamic_bytes(payload: Vec<u8>, max_bytes: usize) -> anyhow::Result<Value> {
        if payload.len() > max_bytes {
            anyhow::bail!("{} bytes, above maxBytes {max_bytes}", payload.len());
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

    /// Coerce an array producer into a fixed-capacity `{len, items}` struct,
    /// right-padding with the element's zero value.
    fn coerce_array(
        raw: &DynSolValue,
        element: &FixedCarrier,
        max_items: usize,
    ) -> anyhow::Result<Value> {
        let raw_items = as_sequence(raw)?;
        if raw_items.len() > max_items {
            anyhow::bail!("{} items, above maxItems {max_items}", raw_items.len());
        }
        let mut items = raw_items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                element
                    .coerce(item)
                    .with_context(|| format!("item {index}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        items.resize_with(max_items, || element.zero_value());
        Ok(Value::Struct(vec![
            (
                "len".to_string(),
                Value::Uint(MidnightU256::from(raw_items.len() as u64)),
            ),
            ("items".to_string(), Value::Vector(items)),
        ]))
    }
}

impl From<&RespondFieldKind> for Descriptor {
    fn from(kind: &RespondFieldKind) -> Self {
        match kind {
            RespondFieldKind::Fixed(carrier) => Descriptor::from(carrier),
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
                            element: Box::new(Descriptor::from(element)),
                        },
                    ),
                ],
            },
        }
    }
}

impl From<&FixedCarrier> for Descriptor {
    fn from(carrier: &FixedCarrier) -> Self {
        match carrier {
            FixedCarrier::Bool => Descriptor::Boolean,
            FixedCarrier::Uint { bits } => Descriptor::UintBits { bits: *bits },
            FixedCarrier::Field | FixedCarrier::Address => Descriptor::Field,
            FixedCarrier::Bytes { length } => Descriptor::Bytes { length: *length },
        }
    }
}

impl TryFrom<&[u8]> for MidnightRespondPlan {
    type Error = anyhow::Error;

    fn try_from(schema_bytes: &[u8]) -> anyhow::Result<Self> {
        let fields = RawSchemaField::parse(schema_bytes)?
            .into_iter()
            .map(|raw| {
                let label = format!("respond schema field '{}'", raw.name);
                RespondField::try_from(raw).with_context(move || label)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if fields.is_empty() {
            anyhow::bail!("respond schema must contain at least one field");
        }

        let descriptor = Descriptor::Struct {
            fields: fields
                .iter()
                .map(|field| (field.name.clone(), Descriptor::from(&field.kind)))
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
}

impl MidnightRespondPlan {
    fn value_for(&self, output: &Output) -> anyhow::Result<Value> {
        self.fields
            .iter()
            .map(|field| {
                let value = field
                    .resolve(output)
                    .with_context(|| format!("Midnight respond field '{}'", field.name))?;
                Ok((field.name.clone(), value))
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .map(Value::Struct)
    }
}

pub(super) fn serialize(output: &Output, respond_schema: &[u8]) -> anyhow::Result<Vec<u8>> {
    let plan = MidnightRespondPlan::try_from(respond_schema)?;
    let value = plan.value_for(output)?;
    let serialized = signet_midnight_serde::serialize(&plan.descriptor, &value, None)
        .context("failed to serialize Midnight respond output")?;
    debug_assert_eq!(serialized.len(), plan.packed_size);
    Ok(serialized)
}

fn required_capacity(
    capacity: Option<usize>,
    typ: &str,
    capacity_name: &str,
) -> anyhow::Result<usize> {
    match capacity {
        Some(capacity) if capacity > 0 => Ok(capacity),
        Some(_) => anyhow::bail!("type '{typ}' requires positive {capacity_name}"),
        None => anyhow::bail!("type '{typ}' requires {capacity_name}"),
    }
}

fn decode_schema_text(bytes: &[u8]) -> Cow<'_, str> {
    let text = String::from_utf8_lossy(bytes);
    match text.strip_prefix('\u{feff}') {
        Some(stripped) => Cow::Owned(stripped.to_owned()),
        None => text,
    }
}

fn trim_ecmascript_whitespace(text: &str) -> &str {
    // ECMAScript trims BOM (U+FEFF) but not NEL (U+0085); Rust's `str::trim`
    // does the reverse, so both schema parsing and BigInt coercion use this set.
    text.trim_matches(|character: char| {
        character == '\u{feff}' || (character.is_whitespace() && character != '\u{0085}')
    })
}

const RADIX_PREFIXES: [(&str, u64); 6] = [
    ("0x", 16),
    ("0X", 16),
    ("0o", 8),
    ("0O", 8),
    ("0b", 2),
    ("0B", 2),
];

fn parse_integer_text(text: &str) -> anyhow::Result<U256> {
    let text = trim_ecmascript_whitespace(text);
    if text.is_empty() {
        return Ok(U256::ZERO);
    }

    if let Some(digits) = text.strip_prefix('+') {
        return unsigned_integer(digits, 10);
    }
    if let Some(digits) = text.strip_prefix('-') {
        let value = unsigned_integer(digits, 10)?;
        if !value.is_zero() {
            anyhow::bail!("integer text is negative");
        }
        return Ok(value);
    }
    let (digits, radix) = RADIX_PREFIXES
        .into_iter()
        .find_map(|(prefix, radix)| Some((text.strip_prefix(prefix)?, radix)))
        .unwrap_or((text, 10));
    unsigned_integer(digits, radix)
}

fn unsigned_integer(digits: &str, radix: u64) -> anyhow::Result<U256> {
    if digits.is_empty() {
        anyhow::bail!("integer text has no digits");
    }
    if digits.contains('_') {
        anyhow::bail!("integer text contains an underscore separator");
    }
    U256::from_str_radix(digits, radix).map_err(Into::into)
}

fn incompatible<T>(expected: &str, value: &DynSolValue) -> anyhow::Result<T> {
    anyhow::bail!("expects {expected}, got {} producer", source_variant(value))
}

fn as_integer(value: &DynSolValue) -> anyhow::Result<U256> {
    match value {
        DynSolValue::Uint(value, _) => Ok(*value),
        DynSolValue::Int(value, _) if !value.is_negative() => Ok(value.into_raw()),
        DynSolValue::Address(value) => integer_from_be_bytes(value.as_slice(), value),
        DynSolValue::FixedBytes(word, size) => {
            integer_from_be_bytes(fixed_bytes_slice(word.as_slice(), *size)?, value)
        }
        DynSolValue::Bytes(bytes) => integer_from_be_bytes(bytes, bytes),
        DynSolValue::Function(value) => integer_from_be_bytes(value.as_slice(), value),
        DynSolValue::String(text) => parse_integer_text(text)
            .with_context(|| format!("cannot read String producer '{text}' as an integer")),
        _ => incompatible("an integer-compatible value", value),
    }
}

fn integer_from_be_bytes(bytes: &[u8], source: impl std::fmt::Debug) -> anyhow::Result<U256> {
    if bytes.is_empty() {
        anyhow::bail!("integer producer {source:?} has no bytes");
    }
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[][..], |first| &bytes[first..]);
    if significant.len() > 32 {
        anyhow::bail!("integer producer {source:?} exceeds 256 bits");
    }
    Ok(U256::from_be_slice(significant))
}

fn as_bytes(value: &DynSolValue) -> anyhow::Result<Vec<u8>> {
    match value {
        DynSolValue::FixedBytes(word, size) => {
            Ok(fixed_bytes_slice(word.as_slice(), *size)?.to_vec())
        }
        DynSolValue::Bytes(bytes) => Ok(bytes.clone()),
        DynSolValue::Address(value) => Ok(value.as_slice().to_vec()),
        DynSolValue::Function(value) => Ok(value.as_slice().to_vec()),
        DynSolValue::String(text) => parse_hex_bytes(text)
            .with_context(|| format!("cannot read String producer '{text}' as 0x bytes")),
        _ => incompatible("a bytes-compatible value", value),
    }
}

fn as_text(value: &DynSolValue) -> anyhow::Result<String> {
    match value {
        DynSolValue::String(text) => Ok(text.clone()),
        DynSolValue::Address(value) => Ok(value.to_checksum(None)),
        DynSolValue::FixedBytes(word, size) => {
            Ok(hex_text(fixed_bytes_slice(word.as_slice(), *size)?))
        }
        DynSolValue::Bytes(bytes) => Ok(hex_text(bytes)),
        DynSolValue::Function(value) => Ok(hex_text(value.as_slice())),
        _ => incompatible("a text-compatible value", value),
    }
}

fn as_sequence<'a>(value: &'a DynSolValue) -> anyhow::Result<&'a [DynSolValue]> {
    match value {
        DynSolValue::Array(values)
        | DynSolValue::FixedArray(values)
        | DynSolValue::Tuple(values) => Ok(values),
        _ => incompatible("an array-compatible value", value),
    }
}

fn fixed_bytes_slice<'a>(word: &'a [u8], size: usize) -> anyhow::Result<&'a [u8]> {
    word.get(..size)
        .ok_or_else(|| anyhow::anyhow!("invalid FixedBytes declared size {size}"))
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
    use alloy::primitives::{Address, I256, U256};
    use serde::Deserialize;

    use super::serialize;
    use crate::respond_bidirectional::{AbiField, Output};

    const FIXTURE_ADDRESS: [u8; 20] = [
        0x8b, 0xa1, 0xf1, 0x09, 0x55, 0x1b, 0xd4, 0x32, 0x80, 0x30, 0x12, 0x64, 0x5a, 0xc1, 0x36,
        0xdd, 0xd6, 0x4d, 0xba, 0x72,
    ];

    fn contract_output(fields: &[(&str, DynSolValue)]) -> Output {
        Output {
            fields: fields
                .iter()
                .map(|(name, value)| (name.to_string(), value.clone()))
                .collect(),
            from_contract_call: true,
        }
    }

    fn le64(value: u64) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn serialize_with(schema: &str, output: &Output) -> anyhow::Result<Vec<u8>> {
        serialize(output, schema.as_bytes())
    }

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

    #[test]
    fn non_canonical_widths_never_classify() {
        let output = Output {
            fields: HashMap::new(),
            from_contract_call: true,
        };
        for typ in ["uint08", "uint+8", "uint 8", "bytes032"] {
            let schema = format!(r#"[{{"name":"v","type":"{typ}"}}]"#);
            let err = serialize(&output, schema.as_bytes()).unwrap_err();
            assert!(
                format!("{err:#}").contains("unsupported type"),
                "{typ} must not classify"
            );
        }
    }

    #[test]
    fn signed_int_producers_only_coerce_to_numeric_kinds() {
        let out = serialize_with(
            r#"[{"name":"v","type":"uint8"}]"#,
            &contract_output(&[("v", DynSolValue::Int(I256::from_dec_str("9").unwrap(), 256))]),
        )
        .unwrap();
        assert_eq!(out, vec![9]);

        let err = serialize_with(
            r#"[{"name":"v","type":"uint8"}]"#,
            &contract_output(&[(
                "v",
                DynSolValue::Int(I256::from_dec_str("-5").unwrap(), 256),
            )]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("integer-compatible"));

        assert!(serialize_with(
            r#"[{"name":"v","type":"string","maxBytes":4}]"#,
            &contract_output(&[("v", DynSolValue::Int(I256::from_dec_str("5").unwrap(), 256),)]),
        )
        .is_err());
    }

    #[test]
    fn incompatible_producer_variants_are_rejected() {
        let cases: &[(&str, DynSolValue)] = &[
            (
                r#"[{"name":"v","type":"bool"}]"#,
                DynSolValue::Uint(U256::from(1u64), 256),
            ),
            (r#"[{"name":"v","type":"uint8"}]"#, DynSolValue::Bool(true)),
            (
                r#"[{"name":"v","type":"uint8"}]"#,
                DynSolValue::Array(vec![DynSolValue::Bool(true)]),
            ),
            (
                r#"[{"name":"v","type":"string","maxBytes":4}]"#,
                DynSolValue::Uint(U256::from(1u64), 256),
            ),
            (
                r#"[{"name":"v","type":"bytes4"}]"#,
                DynSolValue::String("0x00".to_string()),
            ),
        ];
        for (schema, value) in cases {
            assert!(
                serialize_with(schema, &contract_output(&[("v", value.clone())])).is_err(),
                "schema {schema} must reject the producer variant"
            );
        }
    }

    #[test]
    fn error_contexts_name_the_field_and_item() {
        let err = serialize_with(
            r#"[{"name":"values","type":"bool[]","maxItems":2}]"#,
            &contract_output(&[(
                "values",
                DynSolValue::Array(vec![
                    DynSolValue::Bool(true),
                    DynSolValue::Uint(U256::from(1u64), 256),
                ]),
            )]),
        )
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("Midnight respond field 'values'"));
        assert!(message.contains("item 1"));
        assert!(message.contains("expects bool"));

        let err = serialize_with(
            r#"[{"name":"x","type":"uint8"}]"#,
            &contract_output(&[("y", DynSolValue::Uint(U256::from(1u64), 8))]),
        )
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("Midnight respond field 'x'"));
        assert!(message.contains("missing from decoded output"));
    }

    #[test]
    fn address_producer_serializes_as_raw_bytes() {
        let out = serialize_with(
            r#"[{"name":"to","type":"bytes20"}]"#,
            &contract_output(&[("to", DynSolValue::Address(Address::from(FIXTURE_ADDRESS)))]),
        )
        .unwrap();
        assert_eq!(out, FIXTURE_ADDRESS.to_vec());
    }

    #[test]
    fn bytes_producers_coerce_to_text_and_integer() {
        let out = serialize_with(
            r#"[{"name":"tag","type":"string","maxBytes":8}]"#,
            &contract_output(&[("tag", DynSolValue::Bytes(vec![0xde, 0xad].into()))]),
        )
        .unwrap();
        let mut expected = le64(6);
        expected.extend_from_slice(b"0xdead".as_slice());
        expected.extend_from_slice(&[0u8; 2]);
        assert_eq!(out, expected);

        let schema = r#"[{"name":"v","type":"uint8"}]"#;
        let out = serialize_with(
            schema,
            &contract_output(&[("v", DynSolValue::Bytes(vec![0, 5].into()))]),
        )
        .unwrap();
        assert_eq!(out, vec![5]);

        let err = serialize_with(
            schema,
            &contract_output(&[("v", DynSolValue::Bytes(vec![1u8; 33].into()))]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("exceeds 256 bits"));
    }

    #[test]
    fn tuple_producer_coerces_as_array() {
        let out = serialize_with(
            r#"[{"name":"values","type":"uint8[]","maxItems":1}]"#,
            &contract_output(&[(
                "values",
                DynSolValue::Tuple(vec![DynSolValue::Uint(U256::from(9u64), 8)]),
            )]),
        )
        .unwrap();
        let mut expected = le64(1);
        expected.push(9);
        assert_eq!(out, expected);
    }

    #[test]
    fn fixed_bytes_declared_size_truncates() {
        let mut word = [0u8; 32];
        word[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        word[4] = 0xff;
        let out = serialize_with(
            r#"[{"name":"salt","type":"bytes4"}]"#,
            &contract_output(&[("salt", DynSolValue::FixedBytes(word.into(), 4))]),
        )
        .unwrap();
        assert_eq!(out, vec![0xde, 0xad, 0xbe, 0xef]);

        let err = serialize_with(
            r#"[{"name":"salt","type":"bytes4"}]"#,
            &contract_output(&[("salt", DynSolValue::Bytes(vec![0xaa, 0xbb, 0xcc].into()))]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("expects 4 bytes"));
    }

    #[test]
    fn string_to_bytes_requires_hex_prefix() {
        assert!(serialize_with(
            r#"[{"name":"payload","type":"bytes","maxBytes":4}]"#,
            &contract_output(&[("payload", DynSolValue::String("deadbeef".to_string()),)]),
        )
        .is_err());
    }

    #[test]
    fn non_contract_call_synthesizes_string_default_only() {
        let output = Output {
            fields: HashMap::new(),
            from_contract_call: false,
        };

        let out = serialize_with(
            r#"[{"name":"status","type":"string","maxBytes":32}]"#,
            &output,
        )
        .unwrap();
        let mut expected = le64(25);
        expected.extend_from_slice(b"non_function_call_success".as_slice());
        expected.extend_from_slice(&[0u8; 7]);
        assert_eq!(out, expected);

        assert!(serialize_with(r#"[{"name":"v","type":"uint8"}]"#, &output).is_err());
    }

    #[test]
    fn whole_float_capacities_are_accepted() {
        let out = serialize_with(
            r#"[{"name":"v","type":"uint8[]","maxItems":3.0}]"#,
            &contract_output(&[(
                "v",
                DynSolValue::Array(vec![DynSolValue::Uint(U256::from(9u64), 8)]),
            )]),
        )
        .unwrap();
        let mut expected = le64(1);
        expected.extend_from_slice(&[9, 0, 0]);
        assert_eq!(out, expected);
    }

    #[test]
    fn schema_requires_named_typed_fields() {
        let output = Output {
            fields: HashMap::new(),
            from_contract_call: true,
        };
        let rejected = [
            br#"[{"name":"","type":"bool"}]"#.as_slice(),
            br#"[{"name":"v","type":""}]"#,
            br#"[{"type":"bool"}]"#,
            br#"[{"name":"v"}]"#,
        ];
        for schema in rejected {
            assert!(
                serialize(&output, schema).is_err(),
                "schema {schema:?} must be rejected"
            );
        }
    }
}
