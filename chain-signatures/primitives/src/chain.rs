use crate::Chain;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SerDeserFormat {
    Borsh,
    Abi,
    Fab,
}

/// Node-side per-chain configuration (intervals, finality expectations,
/// response serialization). Kept out of `signet-primitives` on purpose:
/// these are operational knobs of this node implementation, not part of the
/// public interface.
pub trait ChainConfig {
    fn checkpoint_interval(&self) -> Option<u64>;
    fn checkpoint_env_vars() -> Vec<(&'static str, &'static str)>;
    /// `ChainEvent::Block` silence budget before the supervisor restarts
    /// the indexer.
    fn stall_timeout_secs(&self) -> u64;
    /// Budget for the chain-local feed detector (Canton: WS silence;
    /// Solana: frozen anchor).
    fn feed_stall_timeout_secs(&self) -> u64;
    fn expected_finality_time_secs(&self) -> u64;
    /// From publishing a response until it is final on chain.
    fn expected_observe_latency_secs(&self) -> u64;
    fn expected_response_time_secs(&self) -> u64;
    fn respond_serialization_format(&self) -> SerDeserFormat;
    /// Whether bidirectional requests can target this chain.
    fn supports_bidirectional_signing(&self) -> bool;
}

impl ChainConfig for Chain {
    fn checkpoint_interval(&self) -> Option<u64> {
        let (key, default) = match self {
            Chain::NEAR | Chain::Bitcoin | Chain::Tron => return None,
            Chain::Ethereum => ("CHECKPOINT_INTERVAL_ETHEREUM", 20),
            Chain::Solana => ("CHECKPOINT_INTERVAL_SOLANA", 1200),
            Chain::Hydration => ("CHECKPOINT_INTERVAL_HYDRATION", 240),
            Chain::Canton => ("CHECKPOINT_INTERVAL_CANTON", 50),
            Chain::Midnight => ("CHECKPOINT_INTERVAL_MIDNIGHT", 120),
        };

        let interval = std::env::var(key)
            .map(|param| param.parse::<u64>().unwrap_or(default))
            .unwrap_or(default);

        Some(interval)
    }

    fn checkpoint_env_vars() -> Vec<(&'static str, &'static str)> {
        vec![
            ("CHECKPOINT_INTERVAL_ETHEREUM", "2"),
            ("CHECKPOINT_INTERVAL_SOLANA", "5"),
            ("CHECKPOINT_INTERVAL_HYDRATION", "5"),
            ("CHECKPOINT_INTERVAL_CANTON", "5"),
            ("CHECKPOINT_INTERVAL_MIDNIGHT", "5"),
        ]
    }

    fn stall_timeout_secs(&self) -> u64 {
        const FLOOR_SECS: u64 = 300;
        const BUFFER_SECS: u64 = 300;
        // Conservative default: finality cadence + buffer, floored. Streams
        // that can legitimately go quiet (Canton) keep this; their feed
        // detector is the fast path.
        let derived = self
            .expected_finality_time_secs()
            .saturating_add(BUFFER_SECS)
            .max(FLOOR_SECS);
        match self {
            // ~20 missed blocks at ~6s cadence; headroom for slow catchup
            // blocks (large contract-state reads).
            Chain::Midnight => 120,
            // ~10x the 12s finality cadence.
            Chain::Hydration => 120,
            _ => derived,
        }
    }

    fn feed_stall_timeout_secs(&self) -> u64 {
        60
    }

    fn expected_finality_time_secs(&self) -> u64 {
        match self {
            Chain::NEAR => 3,
            Chain::Ethereum => 30 * 60,
            // The indexer waits for finalized (supermajority-epoch) blocks: the
            // finalized pointer advances in ~32-slot batches, trailing the tip
            // by up to ~13s.
            Chain::Solana => 15,
            Chain::Bitcoin => 60 * 60 + 20 * 60, // 6 confirmations at 10 minutes each, plus some buffer
            Chain::Hydration => 12,
            Chain::Canton => 15,
            Chain::Midnight => 15,
            // Tron solidification: >=19 active SRs at/above a height, ~1 min
            // on mainnet.
            Chain::Tron => 60,
        }
    }

    fn expected_observe_latency_secs(&self) -> u64 {
        match self {
            // Proves twice before submitting, then waits for finality.
            Chain::Midnight => 105,
            _ => self.expected_finality_time_secs(),
        }
    }

    fn expected_response_time_secs(&self) -> u64 {
        // Finality of the request event + observe latency of the response
        self.expected_finality_time_secs() + self.expected_observe_latency_secs() + 5
        // + Buffer time
    }

    fn respond_serialization_format(&self) -> SerDeserFormat {
        match self {
            Chain::Midnight => SerDeserFormat::Fab,
            Chain::Canton => SerDeserFormat::Abi,
            // Solana and Hydration use Borsh for bidirectional responses.
            _ => SerDeserFormat::Borsh,
        }
    }

    fn supports_bidirectional_signing(&self) -> bool {
        matches!(self, Chain::Ethereum | Chain::Tron)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the cadence-derived defaults
    #[test]
    fn stall_timeouts_track_block_cadence() {
        assert_eq!(Chain::Midnight.stall_timeout_secs(), 120);
        assert_eq!(Chain::Hydration.stall_timeout_secs(), 120);
        assert_eq!(Chain::Canton.stall_timeout_secs(), 315);
        assert_eq!(Chain::Solana.stall_timeout_secs(), 315);
        assert_eq!(Chain::Ethereum.stall_timeout_secs(), 30 * 60 + 300);
        // Finality-derived default for the non-indexed chains.
        assert_eq!(Chain::NEAR.stall_timeout_secs(), 3 + 300);
        assert_eq!(Chain::Tron.stall_timeout_secs(), 60 + 300);
    }

    #[test]
    fn feed_stall_timeouts_pin_the_fast_signal_budgets() {
        assert_eq!(Chain::Canton.feed_stall_timeout_secs(), 60);
        assert_eq!(Chain::Solana.feed_stall_timeout_secs(), 60);
    }
}
