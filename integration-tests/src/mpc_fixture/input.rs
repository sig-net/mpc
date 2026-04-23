use cait_sith::protocol::Participant;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::state::NodeKeyInfo;
use mpc_node::storage::triple_storage::TriplePair;
use std::collections::BTreeMap;

#[derive(serde::Deserialize, serde::Serialize)]
pub struct FixtureInput {
    /// Output of test_basic_generate_keys
    pub keys: BTreeMap<Participant, NodeKeyInfo>,
    /// Output of test_basic_generate_triples
    pub triples: BTreeMap<Participant, BTreeMap<Participant, Vec<TriplePair>>>,
    /// Output of test_basic_generate_presignature
    pub presignatures: BTreeMap<Participant, BTreeMap<Participant, Vec<Presignature>>>,
}

impl FixtureInput {
    pub fn load(num_nodes: u32, threshold: usize) -> Self {
        let data = match (num_nodes, threshold) {
            (3, 2) => include_str!("./3_nodes_2_threshold.json"),
            (5, 4) => include_str!("./5_nodes_4_threshold.json"),
            _ => panic!("No fixture available for num_nodes={num_nodes}, threshold={threshold}"),
        };

        serde_json::from_str(data).expect("parsing failed")
    }
}
