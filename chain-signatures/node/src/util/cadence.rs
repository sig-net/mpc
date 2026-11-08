use enum_map::EnumMap;
use mpc_chain_ethereum::IndexerConfig;
use mpc_primitives::{Chain, ChainConfig};
use std::default::Default;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Cadence {
    organize_posit_timeout: Duration, // round 0 posit timeout
    round_timeout_ceiling: Duration,  // longest later round
    eth_refresh: Duration,            // Ethereum indexer poll
    checkpoint_intervals: EnumMap<Chain, Option<u64>>,
}

impl Default for Cadence {
    fn default() -> Self {
        Self {
            organize_posit_timeout: Duration::from_secs(20),
            round_timeout_ceiling: Duration::from_secs(600),
            eth_refresh: IndexerConfig::default().refresh_interval,
            checkpoint_intervals: EnumMap::from_fn(|chain: Chain| chain.checkpoint_interval()),
        }
    }
}

#[cfg(any(test, feature = "test-feature"))]
impl Cadence {
    pub fn test() -> Self {
        let mut checkpoint_intervals =
            EnumMap::from_fn(|chain: Chain| chain.checkpoint_interval().map(|_| 5));
        checkpoint_intervals[Chain::Ethereum] = Some(2);
        Self {
            organize_posit_timeout: Duration::from_secs(5),
            round_timeout_ceiling: Duration::from_secs(30),
            eth_refresh: Duration::from_millis(100),
            checkpoint_intervals,
        }
    }
}

impl Cadence {
    pub fn organize_posit_timeout(&self) -> Duration {
        self.organize_posit_timeout
    }

    pub fn eth_refresh(&self) -> Duration {
        self.eth_refresh
    }

    pub fn round_timeout_ceiling(&self) -> Duration {
        self.round_timeout_ceiling
    }

    pub fn checkpoint_interval(&self, chain: Chain) -> Option<u64> {
        self.checkpoint_intervals[chain]
    }
}
