mod impls;

use borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};

/// Protocol parameters every node reads from the contract.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ProtocolConfig {
    /// Per-node floor: each node generates triple pairs until it owns at least
    /// this many. One pair builds one presignature.
    pub min_mine_triple_pairs: u32,
    /// Per-node floor: each node generates presignatures until it owns at least
    /// this many.
    pub min_mine_presignatures: u32,
    /// Per-node cap on triple and presignature generations in flight at once:
    /// proposals awaiting acceptance plus running protocols the node owns.
    pub max_mine_generations: u32,
}

#[cfg(test)]
mod tests {
    use crate::config::ProtocolConfig;

    #[test]
    fn test_load_config() {
        let config_macro = serde_json::json!({
            "min_mine_triple_pairs": 10,
            "min_mine_presignatures": 20,
            "max_mine_generations": 3
        });

        let config: ProtocolConfig = serde_json::from_value(config_macro).unwrap();
        assert_eq!(config.min_mine_triple_pairs, 10);
        assert_eq!(config.min_mine_presignatures, 20);
        assert_eq!(config.max_mine_generations, 3);
    }
}
