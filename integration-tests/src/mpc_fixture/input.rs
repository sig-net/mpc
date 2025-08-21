use cait_sith::protocol::Participant;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::state::NodeKeyInfo;
use mpc_node::protocol::triple::Triple;
use std::collections::BTreeMap;

#[derive(serde::Deserialize, serde::Serialize)]
pub struct FixtureInput {
    /// Output of test_basic_generate_keys
    pub keys: BTreeMap<Participant, NodeKeyInfo>,
    /// Output of test_basic_generate_triples
    pub triples: BTreeMap<Participant, BTreeMap<Participant, Vec<Triple>>>,
    /// Output of test_basic_generate_presignature
    pub presignatures: BTreeMap<Participant, BTreeMap<Participant, Vec<Presignature>>>,
}

impl FixtureInput {
    pub fn load(num_nodes: u32) -> Self {
        let data = match num_nodes {
            3 => include_str!("./3_nodes.json"),
            5 => include_str!("./5_nodes.json"),
            other => panic!("No fixture input for {other} nodes available"),
        };

        serde_json::from_str(data).expect("parsing failed")
    }
}
