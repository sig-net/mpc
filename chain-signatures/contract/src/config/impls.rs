use super::ProtocolConfig;

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            min_mine_triple_pairs: 512,
            min_mine_presignatures: 512,
            max_mine_generations: 16,
        }
    }
}
