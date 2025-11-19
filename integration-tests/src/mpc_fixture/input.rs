use cait_sith::protocol::Participant;
use cait_sith::triples::{TriplePub, TripleShare};
use k256::Secp256k1;
use mpc_node::protocol::presignature::Presignature;
use mpc_node::protocol::state::NodeKeyInfo;
use mpc_node::protocol::triple::Triple;
use std::collections::BTreeMap;

#[derive(serde::Deserialize, serde::Serialize)]
pub struct FixtureTriple {
    pub id: u64,
    pub share: TripleShare<Secp256k1>,
    pub public: TriplePub<Secp256k1>,
}

impl From<FixtureTriple> for Triple {
    fn from(f: FixtureTriple) -> Self {
        Triple {
            share: f.share,
            public: f.public,
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct FixtureInput {
    /// Output of test_basic_generate_keys
    pub keys: BTreeMap<Participant, NodeKeyInfo>,
    /// Output of test_basic_generate_triples
    pub triples: BTreeMap<Participant, BTreeMap<Participant, Vec<FixtureTriple>>>,
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
