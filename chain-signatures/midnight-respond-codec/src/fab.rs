//! Coercion and packing of decoded execution outputs into Midnight's FAB
//! (Compact) layout, driven by the Midnight respond schema: a JSON array of
//! `{name, type, maxBytes?, maxItems?}` fields. Values are coerced the same
//! way the TypeScript oracle would coerce them (text as BigInt, `0x`-hex text
//! as bytes, bytes as a big-endian integer).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use anyhow::Context as _;
use signet_midnight_serde::{Descriptor, Value, U256 as MidnightU256};

use crate::{DecodedOutput, DecodedValue};

/// Largest packed respond payload a respond schema may produce.
const MAX_RESPOND_PACKED_BYTES: usize = 65_536;

/// A schema field before validation; capacities are still optional and unchecked.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RawSchemaField {
    name: String,
    typ: String,
    max_bytes: Option<usize>,
    max_items: Option<usize>,
}

/// Fixed-width Compact carriers a respond field can be classified into.
#[derive(Clone, Debug, PartialEq, Eq)]
enum FixedCarrier {
    Bool,
    Uint { bits: u32 },
    Field,
    Address,
    Bytes { length: usize },
}

/// A classified respond field; the dynamic kinds carry their schema capacity.
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

/// A parsed respond schema: classified fields plus the derived Compact
/// descriptor and its exact packed size.
struct MidnightRespondPlan {
    fields: Vec<RespondField>,
    descriptor: Descriptor,
    packed_size: usize,
}

impl MidnightRespondPlan {
    /// Parse and fully validate the schema, sizing it before any value is seen.
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

    /// Build the respond value: decoded fields for a contract call,
    /// synthesized defaults otherwise.
    fn value_for(&self, output: &DecodedOutput) -> anyhow::Result<Value> {
        let mut fields = Vec::with_capacity(self.fields.len());
        for field in &self.fields {
            let value = if output.is_contract_call() {
                let raw = output.field(&field.name).ok_or_else(|| {
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

/// Schema JSON may arrive with a UTF-8 BOM glued to the front.
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

/// Validate `output` against the Midnight respond schema in `bytes` and pack
/// it in the Compact layout.
pub fn serialize(output: &DecodedOutput, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let plan = MidnightRespondPlan::parse(bytes)?;
    let value = plan.value_for(output)?;
    let serialized = signet_midnight_serde::serialize(&plan.descriptor, &value, None)
        .context("failed to serialize Midnight respond output")?;
    debug_assert_eq!(serialized.len(), plan.packed_size);
    Ok(serialized)
}

/// Capacities may be written as integers or whole-number floats (`64` or `64.0`).
fn parse_optional_capacity(raw: &str) -> Option<usize> {
    if let Ok(value) = raw.parse::<u64>() {
        return usize::try_from(value).ok();
    }
    let value = raw.parse::<f64>().ok()?;
    (value.is_finite() && value >= 0.0 && value.fract() == 0.0).then_some(value as usize)
}

/// Parse the raw field list, keeping unknown JSON properties out of the way
/// (`RawValue` so duplicate keys resolve last-wins during map insertion).
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

/// Classify a field and require the capacities its type demands.
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

/// `uint{8..=248 step 8}` and `bytes{1..=32}` only; `uint256`/`field` map to
/// the 32-byte Field carrier, `address` to a range-checked Field.
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

/// Dynamic kinds encode as `{len, data}` / `{len, items}` structs: a u64
/// little-endian length plus the payload right-padded to the declared
/// capacity, because Compact has no variable-width types.
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

/// Coerce a decoded value into one respond field's expected shape.
fn value_for_kind(
    raw: &DecodedValue,
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

/// Right-pad `payload` with zeros to `max_bytes`, prefixing its length.
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

fn fixed_value(raw: &DecodedValue, carrier: &FixedCarrier, label: &str) -> anyhow::Result<Value> {
    match carrier {
        FixedCarrier::Bool => match raw {
            DecodedValue::Bool(value) => Ok(Value::Bool(*value)),
            _ => anyhow::bail!(
                "Midnight respond field '{label}' expects bool, got {} producer",
                source_variant(raw)
            ),
        },
        FixedCarrier::Uint { .. } => Ok(Value::Uint(as_integer(raw, label)?)),
        FixedCarrier::Field => Ok(Value::Field(as_integer(raw, label)?)),
        FixedCarrier::Address => {
            let value = as_integer(raw, label)?;
            if value >= MidnightU256::pow2(160) {
                anyhow::bail!("Midnight respond field '{label}' exceeds the 160-bit address bound");
            }
            Ok(Value::Field(value))
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

/// Only `bool` and `string` have a meaningful "the tx succeeded" default.
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

// Coercions below accept any producer variant the target kind can read
// losslessly, matching the TypeScript oracle's loose typing.

fn as_integer(value: &DecodedValue, label: &str) -> anyhow::Result<MidnightU256> {
    match value {
        DecodedValue::Uint(value) => Ok(*value),
        DecodedValue::Bytes(bytes) => integer_from_be_bytes(bytes, label, value),
        DecodedValue::Text(text) => parse_integer_text(text).with_context(|| {
            format!(
                "Midnight respond field '{label}' cannot read Text producer '{text}' as an integer"
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
) -> anyhow::Result<MidnightU256> {
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
    Ok(u256_from_be(significant))
}

/// JavaScript `BigInt()` grammar: optional sign, `0x`/`0o`/`0b` prefixes,
/// decimal otherwise; blank text is 0. Rejects negatives and `_` separators.
fn parse_integer_text(text: &str) -> anyhow::Result<MidnightU256> {
    let text = trim_ecmascript_whitespace(text);
    if text.is_empty() {
        return Ok(MidnightU256::ZERO);
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
    let mut be = [0u8; 32];
    for character in digits.chars() {
        let digit = character
            .to_digit(radix)
            .ok_or_else(|| anyhow::anyhow!("integer text has a digit outside radix {radix}"))?;
        if !be_mul_add(&mut be, radix as u8, digit as u8) {
            anyhow::bail!("integer text exceeds 256 bits");
        }
    }
    let value = u256_from_be(&be);
    if negative && !value.is_zero() {
        anyhow::bail!("integer text is negative");
    }
    Ok(value)
}

/// `significant` is the big-endian, leading-zero-stripped form (at most 32 bytes).
fn u256_from_be(significant: &[u8]) -> MidnightU256 {
    let mut le = [0u8; 32];
    for (index, byte) in significant.iter().rev().enumerate() {
        le[index] = *byte;
    }
    MidnightU256::from_le_bytes(&le)
}

/// `be = be * radix + digit` on a big-endian accumulator; false on overflow
/// past 2^256. `radix` is at most 16, so a u16 never overflows per byte.
fn be_mul_add(be: &mut [u8; 32], radix: u8, digit: u8) -> bool {
    let mut carry = digit as u16;
    for byte in be.iter_mut().rev() {
        let product = (*byte as u16) * (radix as u16) + carry;
        *byte = product as u8;
        carry = product >> 8;
    }
    carry == 0
}

fn as_bytes(value: &DecodedValue, label: &str) -> anyhow::Result<Vec<u8>> {
    match value {
        DecodedValue::Bytes(bytes) => Ok(bytes.clone()),
        DecodedValue::Text(text) => parse_hex_bytes(text).with_context(|| {
            format!(
                "Midnight respond field '{label}' cannot read Text producer as 0x bytes"
            )
        }),
        _ => anyhow::bail!(
            "Midnight respond field '{label}' expects a bytes-compatible value, got {} producer",
            source_variant(value)
        ),
    }
}

fn as_text(value: &DecodedValue, label: &str) -> anyhow::Result<String> {
    match value {
        DecodedValue::Text(text) => Ok(text.clone()),
        DecodedValue::Bytes(bytes) => Ok(hex_text(bytes)),
        _ => anyhow::bail!(
            "Midnight respond field '{label}' expects a text-compatible value, got {} producer",
            source_variant(value)
        ),
    }
}

fn as_sequence<'a>(value: &'a DecodedValue, label: &str) -> anyhow::Result<&'a [DecodedValue]> {
    match value {
        DecodedValue::Array(values) => Ok(values),
        _ => anyhow::bail!(
            "Midnight respond field '{label}' expects an array-compatible value, got {} producer",
            source_variant(value)
        ),
    }
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

fn source_variant(value: &DecodedValue) -> &'static str {
    match value {
        DecodedValue::Bool(_) => "Bool",
        DecodedValue::Uint(_) => "Uint",
        DecodedValue::Bytes(_) => "Bytes",
        DecodedValue::Text(_) => "Text",
        DecodedValue::Array(_) => "Array",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn output(fields: &[(&str, DecodedValue)]) -> DecodedOutput {
        DecodedOutput::contract_call(
            fields
                .iter()
                .map(|(name, value)| (name.to_string(), value.clone()))
                .collect(),
        )
    }

    fn uint_from_be(bytes: &[u8]) -> DecodedValue {
        let mut le = [0u8; 32];
        for (index, byte) in bytes.iter().rev().enumerate() {
            le[index] = *byte;
        }
        DecodedValue::Uint(MidnightU256::from_le_bytes(&le))
    }

    fn le64(value: u64) -> Vec<u8> {
        value.to_le_bytes().to_vec()
    }

    fn serialize_with(schema: &str, output: &DecodedOutput) -> anyhow::Result<Vec<u8>> {
        serialize(output, schema.as_bytes())
    }

    #[test]
    fn bool_serializes_single_byte() {
        let schema = r#"[{"name":"ok","type":"bool"}]"#;
        let out = serialize_with(schema, &output(&[("ok", DecodedValue::Bool(true))])).unwrap();
        assert_eq!(out, vec![1]);
        let out = serialize_with(schema, &output(&[("ok", DecodedValue::Bool(false))])).unwrap();
        assert_eq!(out, vec![0]);
    }

    #[test]
    fn uint_carrier_narrows_to_little_endian() {
        let out = serialize_with(
            r#"[{"name":"amount","type":"uint128"}]"#,
            &output(&[("amount", uint_from_be(&[1, 2, 3, 4, 5, 6, 7, 8]))]),
        )
        .unwrap();
        let mut expected = vec![8, 7, 6, 5, 4, 3, 2, 1];
        expected.extend_from_slice(&[0u8; 8]);
        assert_eq!(out, expected);
    }

    #[test]
    fn field_carrier_is_32_little_endian_bytes() {
        let out = serialize_with(
            r#"[{"name":"f","type":"field"}]"#,
            &output(&[("f", uint_from_be(&[7]))]),
        )
        .unwrap();
        let mut expected = vec![7u8];
        expected.extend_from_slice(&[0u8; 31]);
        assert_eq!(out, expected);
    }

    #[test]
    fn address_carrier_serializes_numeric_little_endian() {
        let address = [
            0x8b, 0xa1, 0xf1, 0x09, 0x55, 0x1b, 0xd4, 0x32, 0x80, 0x30, 0x12, 0x64, 0x5a, 0xc1,
            0x36, 0xdd, 0xd6, 0x4d, 0xba, 0x72,
        ];
        let out = serialize_with(
            r#"[{"name":"to","type":"address"}]"#,
            &output(&[("to", uint_from_be(&address))]),
        )
        .unwrap();
        let mut expected = address.iter().rev().copied().collect::<Vec<_>>();
        expected.extend_from_slice(&[0u8; 12]);
        assert_eq!(out, expected);
    }

    #[test]
    fn address_carrier_rejects_two_pow_160() {
        let mut producer = vec![0x01u8];
        producer.extend_from_slice(&[0u8; 20]);
        let err = serialize_with(
            r#"[{"name":"to","type":"address"}]"#,
            &output(&[("to", uint_from_be(&producer))]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("160-bit address bound"));
    }

    #[test]
    fn field_carrier_rejects_field_modulus() {
        let err = serialize_with(
            r#"[{"name":"f","type":"field"}]"#,
            &output(&[("f", DecodedValue::Uint(signet_midnight_serde::FIELD_MODULUS))]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("failed to serialize Midnight respond output"));
    }

    #[test]
    fn uint_carrier_enforces_declared_width() {
        let schema = r#"[{"name":"v","type":"uint8"}]"#;
        let out = serialize_with(schema, &output(&[("v", uint_from_be(&[255]))])).unwrap();
        assert_eq!(out, vec![255]);
        assert!(serialize_with(schema, &output(&[("v", uint_from_be(&[1, 0]))])).is_err());
    }

    #[test]
    fn fixed_bytes_are_verbatim() {
        let schema = r#"[{"name":"salt","type":"bytes4"}]"#;
        let out = serialize_with(
            schema,
            &output(&[("salt", DecodedValue::Bytes(vec![0xaa, 0xbb, 0xcc, 0xdd]))]),
        )
        .unwrap();
        assert_eq!(out, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        let err = serialize_with(
            schema,
            &output(&[("salt", DecodedValue::Bytes(vec![0xaa, 0xbb, 0xcc]))]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("expects 4 bytes"));
    }

    #[test]
    fn string_uses_byte_length_and_capacity() {
        let out = serialize_with(
            r#"[{"name":"message","type":"string","maxBytes":24}]"#,
            &output(&[("message", DecodedValue::Text("Midnight 🌙".to_string()))]),
        )
        .unwrap();
        let mut expected = le64(13);
        expected.extend_from_slice("Midnight \u{1f319}".as_bytes());
        expected.extend_from_slice(&[0u8; 11]);
        assert_eq!(out.len(), 32);
        assert_eq!(out, expected);
    }

    #[test]
    fn dynamic_bytes_pad_to_max_bytes() {
        let schema = r#"[{"name":"payload","type":"bytes","maxBytes":4}]"#;
        let out = serialize_with(
            schema,
            &output(&[("payload", DecodedValue::Bytes(b"ab".to_vec()))]),
        )
        .unwrap();
        let mut expected = le64(2);
        expected.extend_from_slice(b"ab".as_slice());
        expected.extend_from_slice(&[0u8; 2]);
        assert_eq!(out, expected);

        let err = serialize_with(
            schema,
            &output(&[("payload", DecodedValue::Bytes(vec![1u8; 5]))]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("above maxBytes 4"));
    }

    #[test]
    fn text_to_integer_follows_bigint_grammar() {
        let schema = r#"[{"name":"v","type":"uint8"}]"#;
        let accepted = [
            ("+7", 7u8),
            ("0x1f", 31),
            ("0X1F", 31),
            ("0b101", 5),
            ("0o17", 15),
            ("\u{feff} 42 \u{feff}", 42),
            ("", 0),
            ("-0", 0),
            ("0x0", 0),
        ];
        for (text, value) in accepted {
            let out = serialize_with(
                schema,
                &output(&[("v", DecodedValue::Text(text.to_string()))]),
            )
            .with_context(|| format!("accepted case {text:?}"))
            .unwrap();
            assert_eq!(out, vec![value], "case {text:?}");
        }

        let rejected = ["+", "0x", "-1", "1_0", "\u{0085}42", "0xg", "12 34"];
        for text in rejected {
            assert!(
                serialize_with(schema, &output(&[("v", DecodedValue::Text(text.to_string()))]))
                    .is_err(),
                "case {text:?} must be rejected"
            );
        }
    }

    #[test]
    fn text_to_bytes_requires_hex_prefix() {
        let schema = r#"[{"name":"payload","type":"bytes","maxBytes":4}]"#;
        let out = serialize_with(
            schema,
            &output(&[("payload", DecodedValue::Text("0xdeadbeef".to_string()))]),
        )
        .unwrap();
        let mut expected = le64(4);
        expected.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(out, expected);

        let out = serialize_with(
            schema,
            &output(&[("payload", DecodedValue::Text("0XDE".to_string()))]),
        )
        .unwrap();
        let mut expected = le64(1);
        expected.extend_from_slice(&[0xde, 0, 0, 0]);
        assert_eq!(out, expected);

        assert!(serialize_with(
            schema,
            &output(&[("payload", DecodedValue::Text("deadbeef".to_string()))]),
        )
        .is_err());
    }

    #[test]
    fn bytes_to_text_renders_hex() {
        let out = serialize_with(
            r#"[{"name":"tag","type":"string","maxBytes":8}]"#,
            &output(&[("tag", DecodedValue::Bytes(vec![0xde, 0xad]))]),
        )
        .unwrap();
        let mut expected = le64(6);
        expected.extend_from_slice(b"0xdead".as_slice());
        expected.extend_from_slice(&[0u8; 2]);
        assert_eq!(out, expected);
    }

    #[test]
    fn bytes_to_integer_strips_leading_zeros() {
        let schema = r#"[{"name":"v","type":"uint8"}]"#;
        let out = serialize_with(
            schema,
            &output(&[("v", DecodedValue::Bytes(vec![0, 5]))]),
        )
        .unwrap();
        assert_eq!(out, vec![5]);

        let err = serialize_with(schema, &output(&[("v", DecodedValue::Bytes(Vec::new()))]))
            .unwrap_err();
        assert!(format!("{err:#}").contains("has no bytes"));

        let err = serialize_with(
            schema,
            &output(&[("v", DecodedValue::Bytes(vec![1u8; 33]))]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("exceeds 256 bits"));
    }

    #[test]
    fn array_pads_to_max_items() {
        let schema = r#"[{"name":"values","type":"uint64[]","maxItems":3}]"#;
        let out = serialize_with(
            schema,
            &output(&[(
                "values",
                DecodedValue::Array(vec![uint_from_be(&[7]), uint_from_be(&[8])]),
            )]),
        )
        .unwrap();
        let mut expected = le64(2);
        expected.extend_from_slice(&le64(7));
        expected.extend_from_slice(&le64(8));
        expected.extend_from_slice(&le64(0));
        assert_eq!(out, expected);

        let err = serialize_with(
            schema,
            &output(&[(
                "values",
                DecodedValue::Array(vec![
                    uint_from_be(&[1]),
                    uint_from_be(&[2]),
                    uint_from_be(&[3]),
                    uint_from_be(&[4]),
                ]),
            )]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("above maxItems 3"));
    }

    #[test]
    fn non_contract_call_synthesizes_defaults() {
        let out =
            serialize_with(r#"[{"name":"ok","type":"bool"}]"#, &DecodedOutput::non_contract_call())
                .unwrap();
        assert_eq!(out, vec![1]);

        let out = serialize_with(
            r#"[{"name":"status","type":"string","maxBytes":32}]"#,
            &DecodedOutput::non_contract_call(),
        )
        .unwrap();
        let mut expected = le64(25);
        expected.extend_from_slice(b"non_function_call_success".as_slice());
        expected.extend_from_slice(&[0u8; 7]);
        assert_eq!(out, expected);

        assert!(serialize_with(
            r#"[{"name":"v","type":"uint8"}]"#,
            &DecodedOutput::non_contract_call(),
        )
        .is_err());
    }

    #[test]
    fn respond_fields_reorder_and_subset_decoded_values() {
        let out = serialize_with(
            r#"[{"name":"c","type":"uint8"},{"name":"a","type":"uint8"}]"#,
            &output(&[
                ("a", uint_from_be(&[1])),
                ("b", uint_from_be(&[2])),
                ("c", uint_from_be(&[3])),
            ]),
        )
        .unwrap();
        assert_eq!(out, vec![3, 1]);
    }

    #[test]
    fn missing_decoded_field_is_rejected() {
        let err = serialize_with(
            r#"[{"name":"x","type":"uint8"}]"#,
            &output(&[("y", uint_from_be(&[1]))]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("missing field 'x'"));
    }

    #[test]
    fn incompatible_producer_variants_are_rejected() {
        let cases = [
            (r#"[{"name":"v","type":"bool"}]"#, DecodedValue::Uint(MidnightU256::from(1u64))),
            (r#"[{"name":"v","type":"uint8"}]"#, DecodedValue::Bool(true)),
            (r#"[{"name":"v","type":"uint8"}]"#, DecodedValue::Array(vec![DecodedValue::Bool(true)])),
            (r#"[{"name":"v","type":"bytes4"}]"#, DecodedValue::Text("0x00".to_string())),
            (r#"[{"name":"v","type":"string","maxBytes":4}]"#, DecodedValue::Uint(MidnightU256::from(1u64))),
            (r#"[{"name":"v","type":"bool[]","maxItems":1}]"#, DecodedValue::Uint(MidnightU256::from(1u64))),
        ];
        for (schema, value) in cases {
            assert!(
                serialize_with(schema, &output(&[("v", value)])).is_err(),
                "schema {schema} must reject the producer variant"
            );
        }
    }

    #[test]
    fn schema_validation_rejects_invalid_shapes() {
        let decoded = output(&[("v", DecodedValue::Bool(true))]);
        let rejected = [
            b"[]".as_slice(),
            b"{}",
            br#"[{"name":"a","type":"bool"},{"name":"a","type":"bool"}]"#,
            br#"[{"name":"__proto__","type":"bool"}]"#,
            br#"[{"name":"v","type":""}]"#,
            br#"[{"name":"","type":"bool"}]"#,
            br#"[{"type":"bool"}]"#,
            br#"[{"name":"v"}]"#,
            br#"[{"name":"v","type":"int8"}]"#,
            br#"[{"name":"v","type":"uint252"}]"#,
            br#"[{"name":"v","type":"uint249"}]"#,
            br#"[{"name":"v","type":"uint12"}]"#,
            br#"[{"name":"v","type":"bytes33"}]"#,
            br#"[{"name":"v","type":"bytes0"}]"#,
            br#"[{"name":"v","type":"string"}]"#,
            br#"[{"name":"v","type":"string","maxBytes":0}]"#,
            br#"[{"name":"v","type":"uint8[]"}]"#,
            br#"[{"name":"v","type":"uint8[]","maxItems":0}]"#,
            br#"[{"name":"v","type":"uint8[]","maxItems":2.5}]"#,
        ];
        for schema in rejected {
            assert!(serialize(&decoded, schema).is_err(), "schema {schema:?} must be rejected");
        }
    }

    #[test]
    fn whole_float_capacities_are_accepted() {
        let out = serialize_with(
            r#"[{"name":"v","type":"uint8[]","maxItems":3.0}]"#,
            &output(&[("v", DecodedValue::Array(vec![uint_from_be(&[9])]))]),
        )
        .unwrap();
        let mut expected = le64(1);
        expected.extend_from_slice(&[9, 0, 0]);
        assert_eq!(out, expected);
    }

    #[test]
    fn irrelevant_capacities_are_ignored_for_fixed_carriers() {
        let out = serialize_with(
            r#"[{"name":"v","type":"bool","maxBytes":0,"maxItems":-1}]"#,
            &output(&[("v", DecodedValue::Bool(true))]),
        )
        .unwrap();
        assert_eq!(out, vec![1]);
    }

    #[test]
    fn duplicate_json_properties_use_the_last_value() {
        let out = serialize_with(
            r#"[{"name":"s","type":"string","maxBytes":0,"maxBytes":8}]"#,
            &output(&[("s", DecodedValue::Text("ok".to_string()))]),
        )
        .unwrap();
        let mut expected = le64(2);
        expected.extend_from_slice(b"ok".as_slice());
        expected.extend_from_slice(&[0u8; 6]);
        assert_eq!(out, expected);
    }

    #[test]
    fn schema_strips_one_leading_bom() {
        let mut schema = vec![0xef, 0xbb, 0xbf];
        schema.extend_from_slice(br#"[{"name":"ok","type":"bool"}]"#);
        let out = serialize(&output(&[("ok", DecodedValue::Bool(true))]), &schema).unwrap();
        assert_eq!(out, vec![1]);
    }

    #[test]
    fn packed_size_ceiling_is_enforced() {
        let at_ceiling = serialize(
            &DecodedOutput::non_contract_call(),
            br#"[{"name":"s","type":"string","maxBytes":65528}]"#,
        )
        .unwrap();
        assert_eq!(at_ceiling.len(), 65_536);

        let err = serialize(
            &DecodedOutput::non_contract_call(),
            br#"[{"name":"s","type":"string","maxBytes":65529}]"#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("65536-byte ceiling"));
    }
}
