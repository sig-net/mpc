#[deprecated(
    since = "1.23.0",
    note = "Kept for backward compatibility with pre-1.23 nodes; use config::ProtocolConfig instead"
)]
pub mod deprecated;
mod impls;

#[allow(deprecated)]
pub use deprecated::{
    PresignatureConfig as DeprecatedPresignatureConfig, ProtocolConfig as DeprecatedProtocolConfig,
    SignatureConfig as DeprecatedSignatureConfig, TripleConfig as DeprecatedTripleConfig,
};

use borsh::{self, BorshDeserialize, BorshSerialize};

/// Protocol parameters every node reads from the contract.
#[allow(deprecated)]
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
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
    /// Deprecated protocol configuration retained for backward compatibility with <=1.22 nodes.
    /// Skipped in contract Borsh storage so on-chain state remains unchanged.
    #[borsh(skip)]
    #[deprecated(
        since = "1.23.0",
        note = "Kept for backward compatibility with pre-1.23 nodes; use top-level floors instead"
    )]
    pub protocol: deprecated::ProtocolConfig,
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

    #[test]
    fn test_load_config_from_legacy_protocol_field() {
        let legacy_json = serde_json::json!({
            "protocol": {
                "message_timeout": 300000,
                "garbage_timeout": 7200000,
                "max_concurrent_introduction": 4,
                "max_concurrent_generation": 128,
                "triple": {
                    "min_triples": 15,
                    "max_triples": 500,
                    "generation_timeout": 600000
                },
                "presignature": {
                    "min_presignatures": 25,
                    "max_presignatures": 500,
                    "generation_timeout": 45000
                },
                "signature": {
                    "generation_timeout": 45000,
                    "generation_timeout_total": 200000,
                    "garbage_timeout": 86400000
                }
            }
        });

        let config: ProtocolConfig = serde_json::from_value(legacy_json).unwrap();
        assert_eq!(config.min_mine_triple_pairs, 15);
        assert_eq!(config.min_mine_presignatures, 25);
        assert_eq!(config.max_mine_generations, 4);
    }

    #[test]
    fn test_serialized_output_has_both_formats() {
        let config = ProtocolConfig::new(16, 32, 2);
        let val = serde_json::to_value(&config).unwrap();

        assert_eq!(val["min_mine_triple_pairs"], 16);
        assert_eq!(val["min_mine_presignatures"], 32);
        assert_eq!(val["max_mine_generations"], 2);

        // Verify old nodes will find protocol with synchronized floors
        let protocol = &val["protocol"];
        assert!(protocol.is_object());
        assert_eq!(protocol["triple"]["min_triples"], 16);
        assert_eq!(protocol["presignature"]["min_presignatures"], 32);
        assert_eq!(protocol["max_concurrent_introduction"], 2);
        assert_eq!(protocol["message_timeout"], 300000);
    }
}
