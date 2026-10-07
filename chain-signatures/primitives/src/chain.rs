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
    /// Watchdog budget (seconds) without a `ChainEvent::Block` before the
    /// stream supervisor restarts the chain's indexer. Must stay well above
    /// the chain's block cadence; a false fire costs only one cheap
    /// supervised restart. Env-overridable for indexed chains.
    fn stall_timeout_secs(&self) -> u64;
    fn expected_finality_time_secs(&self) -> u64;
    fn expected_response_time_secs(&self) -> u64;
    fn respond_serialization_format(&self) -> SerDeserFormat;
    /// Whether bidirectional requests can target this chain.
    fn has_execution_watcher(&self) -> bool;
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
        // Finality-derived default, kept conservative for chains whose
        // streams can legitimately go quiet (e.g. Canton's party-filtered
        // updates — its 60s transport signal already catches silent
        // connections).
        let derived = self
            .expected_finality_time_secs()
            .saturating_add(BUFFER_SECS)
            .max(FLOOR_SECS);
        let (key, default) = match self {
            // ~20 missed blocks at Midnight's ~6s cadence, with headroom for a
            // slow catchup block (large contract-state reads).
            Chain::Midnight => ("STALL_TIMEOUT_MIDNIGHT", 120),
            // ~10x Hydration's 12s finality cadence.
            Chain::Hydration => ("STALL_TIMEOUT_HYDRATION", 120),
            Chain::Canton => ("STALL_TIMEOUT_CANTON", derived),
            Chain::Ethereum => ("STALL_TIMEOUT_ETHEREUM", derived),
            Chain::Solana => ("STALL_TIMEOUT_SOLANA", derived),
            Chain::NEAR | Chain::Bitcoin | Chain::Tron => return derived,
        };

        std::env::var(key)
            .map(|param| param.parse::<u64>().unwrap_or(default))
            .unwrap_or(default)
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

    fn expected_response_time_secs(&self) -> u64 {
        // finality time * 2 = finality time of sign/sign_bidirectional event + finality time of respond event
        self.expected_finality_time_secs() * 2 + 5 // + Buffer time
    }

    fn respond_serialization_format(&self) -> SerDeserFormat {
        match self {
            Chain::Midnight => SerDeserFormat::Fab,
            Chain::Canton => SerDeserFormat::Abi,
            // Solana and Hydration use Borsh for bidirectional responses.
            _ => SerDeserFormat::Borsh,
        }
    }

    fn has_execution_watcher(&self) -> bool {
        matches!(self, Chain::Ethereum)
    }
}
