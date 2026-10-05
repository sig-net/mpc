//! The respond output a Midnight request attests for an executed EVM transaction.
//!
//! Mirrors `executedEvmRespondOutput` in `@sig-net/midnight`: the bytes are the Borsh
//! encoding of a struct with one member per output-schema field, in schema order, so the
//! encoding derives from the output schema alone and the request's respond schema is
//! ignored. Byte-level behavior is pinned by the TypeScript oracle corpus in
//! `tests/fixtures/midnight_respond_vectors.json`.

use std::collections::HashSet;

use alloy::json_abi::Param;
use alloy::primitives::Bytes;
use anyhow::Context as _;
use signet_midnight_serde::BorshSerialize;

const ABI_WORD_BYTES: usize = 32;
const EVM_ADDRESS_BYTES: usize = 20;

/// The traced return data an attestation derives from
#[derive(Debug, Clone)]
pub(super) enum TracedReturn {
    NotTraced,
    Returned(Bytes),
}

/// The ABI output types a Midnight response can carry. Each is one static ABI word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutputKind {
    /// Borsh `bool`, Compact `Boolean`.
    Bool,
    /// Borsh `[u8; 32]` holding the value little-endian, Compact `Bytes<32>`.
    Uint256,
    /// Borsh `[u8; 20]`, Compact `Bytes<20>`.
    Address,
    /// `bytes1` to `bytes32`: Borsh `[u8; N]`, Compact `Bytes<N>`.
    FixedBytes(usize),
}

impl OutputKind {
    /// Matches the raw type string, so `uint` is unsupported although ABI libraries read it
    /// as `uint256`.
    fn classify(typ: &str) -> Option<Self> {
        match typ {
            "bool" => return Some(Self::Bool),
            "uint256" => return Some(Self::Uint256),
            "address" => return Some(Self::Address),
            _ => {}
        }
        // Canonical spellings only: `bytes1` to `bytes32`, no sign or leading zero.
        let digits = typ.strip_prefix("bytes")?;
        if digits.starts_with('0') || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let length = digits.parse::<usize>().ok()?;
        (1..=ABI_WORD_BYTES)
            .contains(&length)
            .then_some(Self::FixedBytes(length))
    }

    fn width(self) -> usize {
        match self {
            Self::Bool => 1,
            Self::Uint256 => ABI_WORD_BYTES,
            Self::Address => EVM_ADDRESS_BYTES,
            Self::FixedBytes(length) => length,
        }
    }

    /// Whether `word` is the canonical ABI encoding of a value of this type.
    fn is_canonical(self, word: &[u8; ABI_WORD_BYTES]) -> bool {
        let zero = |bytes: &[u8]| bytes.iter().all(|byte| *byte == 0);
        match self {
            Self::Bool => zero(&word[..ABI_WORD_BYTES - 1]) && word[ABI_WORD_BYTES - 1] <= 1,
            Self::Uint256 => true,
            Self::Address => zero(&word[..ABI_WORD_BYTES - EVM_ADDRESS_BYTES]),
            Self::FixedBytes(length) => zero(&word[length..]),
        }
    }
}

#[derive(Debug)]
struct OutputField {
    name: String,
    kind: OutputKind,
}

/// The canonical form of one schema field: exactly these keys, in this order.
#[derive(serde::Serialize)]
struct CanonicalField<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    typ: &'a str,
}

/// Build the attested output of an executed transaction from its output schema, whether it
/// was a contract call, and its traced return data.
///
/// An empty schema with no return data (a plain transfer, or a call that returned nothing)
/// attests an empty output. A non-empty schema with canonical return data encodes every
/// field. Any other combination, a non-canonical schema, or an unsupported type is refused.
pub(super) fn executed_output(
    is_contract_call: bool,
    output_schema: &[u8],
    trace: TracedReturn,
) -> anyhow::Result<Vec<u8>> {
    let fields = parse_output_schema(output_schema)?;
    let expects_output = !fields.is_empty();
    if !is_contract_call {
        anyhow::ensure!(
            !expects_output,
            "a plain transfer returns nothing, but the output schema declares return values"
        );
        return Ok(Vec::new());
    }
    let return_data = match trace {
        TracedReturn::NotTraced => {
            anyhow::bail!("contract-call output extraction requires trace output")
        }
        TracedReturn::Returned(data) => data,
    };
    if return_data.is_empty() {
        anyhow::ensure!(
            !expects_output,
            "the contract call returned no data, but the output schema declares return values"
        );
        return Ok(Vec::new());
    }
    anyhow::ensure!(
        expects_output,
        "the contract call returned data, but the output schema declares no return values"
    );
    encode(&fields, &return_data)
}

/// Check that the return data is canonical ABI for the declared fields, then append each
/// field's Borsh encoding in schema order. Words past the declared fields are not checked.
fn encode(fields: &[OutputField], return_data: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        return_data.len().is_multiple_of(ABI_WORD_BYTES),
        "return data of {} bytes is not whole ABI words",
        return_data.len()
    );
    let words: Vec<&[u8; ABI_WORD_BYTES]> = return_data
        .chunks_exact(ABI_WORD_BYTES)
        .map(|word| word.try_into().expect("chunks are whole words"))
        .collect();
    anyhow::ensure!(
        words.len() >= fields.len(),
        "return data holds {} words but the output schema declares {} fields",
        words.len(),
        fields.len()
    );
    let width = fields.iter().map(|field| field.kind.width()).sum();
    let mut out = Vec::with_capacity(width);
    for (field, word) in fields.iter().zip(words) {
        anyhow::ensure!(
            field.kind.is_canonical(word),
            "output field '{}' word 0x{} is not canonical ABI",
            field.name,
            hex::encode(word)
        );
        match field.kind {
            OutputKind::Bool => (word[ABI_WORD_BYTES - 1] == 1).serialize(&mut out)?,
            OutputKind::Uint256 => {
                let mut little_endian = *word;
                little_endian.reverse();
                little_endian.serialize(&mut out)?;
            }
            OutputKind::Address => {
                <[u8; EVM_ADDRESS_BYTES]>::try_from(&word[ABI_WORD_BYTES - EVM_ADDRESS_BYTES..])?
                    .serialize(&mut out)?;
            }
            // A Borsh `[u8; N]` is its N bytes.
            OutputKind::FixedBytes(length) => {
                for byte in &word[..length] {
                    byte.serialize(&mut out)?;
                }
            }
        }
    }
    debug_assert_eq!(out.len(), width);
    Ok(out)
}

/// Parse an output schema in its canonical on-chain form: the bytes before the first NUL
/// are exactly the compact JSON of `[{"name":..,"type":..},..]`, and every byte from the
/// first NUL on is NUL. No bytes at all, or `[]`, is the empty schema. Names are unique,
/// non-empty Solidity identifiers other than `__proto__`, and every type is a supported
/// [`OutputKind`].
fn parse_output_schema(bytes: &[u8]) -> anyhow::Result<Vec<OutputField>> {
    let body_len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let (body, padding) = bytes.split_at(body_len);
    anyhow::ensure!(
        padding.iter().all(|byte| *byte == 0),
        "output schema bytes after the first NUL must all be NUL"
    );
    if body.is_empty() {
        return Ok(Vec::new());
    }
    // `Param` requires every non-empty name to be a Solidity identifier.
    let params: Vec<Param> =
        serde_json::from_slice(body).context("output schema must be a JSON array of ABI fields")?;
    let canonical = serde_json::to_vec(
        &params
            .iter()
            .map(|param| CanonicalField {
                name: &param.name,
                typ: &param.ty,
            })
            .collect::<Vec<_>>(),
    )?;
    anyhow::ensure!(
        canonical == body,
        "output schema is not canonical: expected exactly {}",
        String::from_utf8_lossy(&canonical)
    );

    let mut names = HashSet::with_capacity(params.len());
    let mut fields = Vec::with_capacity(params.len());
    let mut unsupported = Vec::new();
    for param in params {
        anyhow::ensure!(
            !param.name.is_empty(),
            "output schema field names must not be empty"
        );
        // The SDK collects decoded values in a plain JS object, where this name is the
        // prototype accessor.
        anyhow::ensure!(
            param.name != "__proto__",
            "output schema field name '__proto__' is refused"
        );
        anyhow::ensure!(
            names.insert(param.name.clone()),
            "output schema contains duplicate field name '{}'",
            param.name
        );
        match OutputKind::classify(&param.ty) {
            Some(kind) => fields.push(OutputField {
                name: param.name,
                kind,
            }),
            None => unsupported.push(format!("'{}' ({})", param.name, param.ty)),
        }
    }
    anyhow::ensure!(
        unsupported.is_empty(),
        "unsupported ABI output types {}: Midnight responses carry bool, uint256, address and bytes1 to bytes32 only",
        unsupported.join(", ")
    );
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use alloy::primitives::Bytes;
    use serde::Deserialize;

    use super::{executed_output, TracedReturn};

    #[derive(Deserialize)]
    struct OracleFixture {
        vectors: Vec<OracleVector>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleVector {
        name: String,
        output_schema_hex: String,
        is_contract_call: bool,
        trace: OracleTrace,
        expected_output_hex: Option<String>,
        expected_reject: Option<bool>,
    }

    #[derive(Deserialize)]
    #[serde(tag = "kind")]
    enum OracleTrace {
        NotTraced,
        NoReturnData,
        Output {
            #[serde(rename = "returnDataHex")]
            return_data_hex: String,
        },
    }

    fn respond(
        is_contract_call: bool,
        output_schema: &[u8],
        trace: OracleTrace,
    ) -> anyhow::Result<Vec<u8>> {
        let trace = match trace {
            OracleTrace::NotTraced => TracedReturn::NotTraced,
            OracleTrace::NoReturnData => TracedReturn::Returned(Bytes::new()),
            OracleTrace::Output { return_data_hex } => {
                TracedReturn::Returned(hex::decode(return_data_hex).unwrap().into())
            }
        };
        executed_output(is_contract_call, output_schema, trace)
    }

    #[test]
    fn replays_every_typescript_oracle_vector() {
        let fixture: OracleFixture = serde_json::from_str(include_str!(
            "../../tests/fixtures/midnight_respond_vectors.json"
        ))
        .unwrap();
        assert!(!fixture.vectors.is_empty());

        for vector in fixture.vectors {
            let output_schema = hex::decode(&vector.output_schema_hex).unwrap();
            let result = respond(vector.is_contract_call, &output_schema, vector.trace);

            if vector.expected_reject == Some(true) {
                assert!(
                    result.is_err(),
                    "{}: rejection row was accepted as {}",
                    vector.name,
                    hex::encode(result.unwrap())
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
