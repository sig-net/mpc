//! Contract-state decoding over the ledger's own deserializer.

use anyhow::Context as _;
use midnight_onchain_state::state::{ContractState, StateValue};
use midnight_storage::DefaultDB;

/// Decode the bytes `midnight_contractState` returns, down to the ledger root. The
/// ledger's tag is checked by `tagged_deserialize`, so a chain that moved past this
/// build fails here by name rather than as a parse error on good bytes.
pub fn decode_contract_state(bytes: &[u8]) -> anyhow::Result<StateValue<DefaultDB>> {
    let contract: ContractState<DefaultDB> =
        midnight_serialize::tagged_deserialize(&mut &bytes[..])
            .context("contract state did not deserialize")?;
    Ok(contract.data.get_ref().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use midnight_base_crypto::fab::{AlignmentAtom, AlignmentSegment};

    const STATE_1366: &[u8] = include_bytes!("../fixtures/singleton-post-state-1366.mn");
    const GOLDEN_1366: &str = include_str!("../fixtures/golden-state-singleton-1366.json");
    const STATE_1365: &[u8] = include_bytes!("../fixtures/singleton-pre-state-1365.mn");
    const GOLDEN_1365: &str = include_str!("../fixtures/golden-state-singleton-1365.json");

    /// The JSON shape the goldens are written in, rendered from the native types so a
    /// decode can be compared against one byte for byte.
    fn as_golden_json(value: &StateValue<DefaultDB>) -> String {
        match value {
            StateValue::Null => "{\"kind\":\"null\"}".to_string(),
            StateValue::Cell(cell) => format!(
                "{{\"kind\":\"cell\",\"atoms\":[{}],\"alignment\":[{}]}}",
                cell.value
                    .0
                    .iter()
                    .map(|atom| format!("\"{}\"", hex::encode(&atom.0)))
                    .collect::<Vec<_>>()
                    .join(","),
                cell.alignment
                    .0
                    .iter()
                    .map(segment_json)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            StateValue::Array(children) => format!(
                "{{\"kind\":\"array\",\"children\":[{}]}}",
                children
                    .iter_deref()
                    .map(as_golden_json)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            StateValue::Map(map) => {
                let mut entries: Vec<(String, String)> = map
                    .iter()
                    .map(|entry| {
                        let (key, value) = &*entry;
                        (
                            key.value
                                .0
                                .iter()
                                .map(|atom| hex::encode(&atom.0))
                                .collect::<Vec<_>>()
                                .join("\",\""),
                            as_golden_json(value),
                        )
                    })
                    .collect();
                // Byte order on the joined key, the order the goldens are written in.
                entries.sort_by_key(|entry| entry.0.replace("\",\"", ""));
                format!(
                    "{{\"kind\":\"map\",\"entries\":[{}]}}",
                    entries
                        .iter()
                        .map(|(key, value)| format!("{{\"key\":[\"{key}\"],\"value\":{value}}}"))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            }
            other => panic!("unsupported state variant: {other:?}"),
        }
    }

    fn segment_json(segment: &AlignmentSegment) -> String {
        match segment {
            AlignmentSegment::Atom(AlignmentAtom::Bytes { length }) => {
                format!("{{\"tag\":\"atom\",\"value\":{{\"tag\":\"bytes\",\"length\":{length}}}}}")
            }
            AlignmentSegment::Atom(AlignmentAtom::Compress) => {
                "{\"tag\":\"atom\",\"value\":{\"tag\":\"compress\"}}".to_string()
            }
            AlignmentSegment::Atom(AlignmentAtom::Field) => {
                "{\"tag\":\"atom\",\"value\":{\"tag\":\"field\"}}".to_string()
            }
            AlignmentSegment::Option(_) => unimplemented!("no signet type declares an option"),
        }
    }

    /// The goldens were minted by an independently written decoder, so reproducing them
    /// byte for byte is evidence this decode is right rather than merely self-consistent.
    /// Only the post-notify capture carries cells; the pre-notify one is six empty maps,
    /// so every atom and alignment comparison here rests on 1366.
    #[test]
    fn native_decode_matches_the_committed_golden() {
        for (name, bytes, golden) in [
            ("singleton-post-state-1366", STATE_1366, GOLDEN_1366),
            ("singleton-pre-state-1365", STATE_1365, GOLDEN_1365),
        ] {
            let root = decode_contract_state(bytes).unwrap_or_else(|err| panic!("{name}: {err:#}"));
            assert_eq!(
                as_golden_json(&root),
                golden.trim(),
                "{name}: the native decode diverges from the committed golden"
            );
        }
    }
}
