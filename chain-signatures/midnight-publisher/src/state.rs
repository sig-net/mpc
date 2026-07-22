//! Decode a Midnight contract's on-chain `StateValue` tree into the pinned SGN2
//! state-fixture JSON schema (`kind`/`atoms`/`entries`). The same schema backs
//! both the committed `chain-midnight` state-fixtures and the live
//! `GET /state` reads, so `chain-midnight` gets ONE parser for both.

use anyhow::Context as _;
use midnight_node_ledger_helpers::{AlignedValue, ContractState, DefaultDB, StateValue};

/// One node of the decoded contract-state tree.
///
/// Serializes to the state-fixture schema, internally tagged on `kind`:
/// - `{"kind":"null"}`
/// - `{"kind":"cell","atoms":["<hex>",...]}` — one atom per field-aligned value
///   segment, trailing-zero-trimmed exactly as the runtime stores it (the
///   consumer re-pads to each field width).
/// - `{"kind":"array","children":[<Node>,...]}`
/// - `{"kind":"map","entries":[{"key":"<hex>","value":<Node>},...]}` — entries
///   sorted by key hex.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Node {
    Null,
    Cell { atoms: Vec<String> },
    Array { children: Vec<Node> },
    Map { entries: Vec<MapEntry> },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MapEntry {
    pub key: String,
    pub value: Node,
}

/// Deserialize the tagged `contract-state[v8]` bytes (as written by the toolkit
/// `contract-state` command, or returned hex-decoded by the node's
/// `midnight_contractState` RPC) and walk the ledger `StateValue` tree.
pub fn decode_contract_state(raw: &[u8]) -> anyhow::Result<Node> {
    let state: ContractState<DefaultDB> = midnight_node_ledger_helpers::deserialize(raw)
        .context("deserialize ContractState (contract-state[v8])")?;
    walk(state.data.get_ref())
}

/// The field-aligned atoms of a cell/key value, hex-encoded. Each atom is stored
/// trailing-zero-trimmed by the runtime; we pass that through untouched (empty
/// string means zero/default) — the consumer re-pads to the declared width.
fn value_atoms(av: &AlignedValue) -> Vec<String> {
    av.value.0.iter().map(|atom| hex::encode(&atom.0)).collect()
}

fn walk(sv: &StateValue<DefaultDB>) -> anyhow::Result<Node> {
    match sv {
        StateValue::Null => Ok(Node::Null),
        StateValue::Cell(av) => Ok(Node::Cell {
            atoms: value_atoms(av),
        }),
        StateValue::Array(arr) => {
            let mut children = Vec::with_capacity(arr.len());
            for child in arr.iter_deref() {
                children.push(walk(child)?);
            }
            Ok(Node::Array { children })
        }
        StateValue::Map(map) => {
            let mut entries = Vec::new();
            for kv in map.iter() {
                let (key, value) = &*kv;
                entries.push(MapEntry {
                    key: value_atoms(key).concat(),
                    value: walk(value)?,
                });
            }
            // Schema pins map entries sorted by key hex.
            entries.sort_by(|a, b| a.key.cmp(&b.key));
            Ok(Node::Map { entries })
        }
        // BoundedMerkleTree (and any future non-exhaustive variant) never occurs
        // in the signet contracts' ledgers.
        other => {
            anyhow::bail!("unsupported StateValue variant in signet contract state: {other:?}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_reference_state_fixture_to_atom_tree() {
        let raw = std::fs::read("tests/fixtures/reference-state.mn").unwrap();
        let tree = decode_contract_state(&raw).unwrap();
        let json = serde_json::to_value(&tree).unwrap();

        // Top level is the reference integrator's ordinal array (6 ledger fields).
        assert_eq!(json["kind"], "array");
        let children = json["children"].as_array().unwrap();
        assert!(
            children.len() >= 5,
            "reference integrator has >=5 top-level ordinals, got {}",
            children.len()
        );

        // Ordinal 0 is the configured hub contract address — independent oracle:
        // the deployed SGN2 hub address pinned in the sandbox README.
        assert_eq!(children[0]["kind"], "cell");
        assert_eq!(
            children[0]["atoms"][0],
            "1ff6b01828eaff69181037f78de6ef97fb4e179c082302633f6f99c39790c476"
        );

        // Ordinal 1 is the MPC attestation Secp256k1Point — independent oracle:
        // its field-aligned atoms match the cross-language golden state-fixture
        // (chain-midnight tests/goldens/sgn2/state-fixtures/reference-state.json),
        // proving the trailing-zero-trimmed, declaration-order atom extraction.
        assert_eq!(
            children[1]["atoms"],
            serde_json::json!([
                "c54fb75de1cf50d52c6aa024b979dcbcf11306595fa23489",
                "430667daa96f76bd",
                "aaa4d27b044ee6320f8d8269caebba009de81c8d143d4ade",
                "cb49972244d665fe",
                ""
            ])
        );

        // Ordinals 3 & 4 are the signBiRequests / signRequests maps.
        assert_eq!(children[3]["kind"], "map");
        assert_eq!(children[4]["kind"], "map");
    }

    /// The live signet maps are currently empty, so exercise the schema's
    /// "entries sorted by key hex" rule on a synthetic `StateValue::Map` walked
    /// through the real decoder (keys are little-endian u64 atoms: 1 -> "01").
    #[test]
    fn map_entries_are_sorted_by_key_hex() {
        use midnight_node_ledger_helpers::HashMapStorage;

        let map = HashMapStorage::<AlignedValue, StateValue<DefaultDB>, DefaultDB>::new()
            .insert(AlignedValue::from(2u64), StateValue::Null)
            .insert(AlignedValue::from(1u64), StateValue::Null)
            .insert(AlignedValue::from(3u64), StateValue::Null);

        let node = walk(&StateValue::Map(map)).unwrap();
        let json = serde_json::to_value(&node).unwrap();
        let keys: Vec<&str> = json["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["key"].as_str().unwrap())
            .collect();
        assert_eq!(keys, ["01", "02", "03"]);
    }
}
