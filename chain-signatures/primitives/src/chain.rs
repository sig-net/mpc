use crate::Chain;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SerDeserFormat {
    Borsh,
    Abi,
}

/// Node-side per-chain configuration (intervals, finality expectations,
/// response serialization). Kept out of `signet-primitives` on purpose:
/// these are operational knobs of this node implementation, not part of the
/// public interface.
pub trait ChainConfig {
    fn checkpoint_interval(&self) -> Option<u64>;
    fn checkpoint_env_vars() -> Vec<(&'static str, &'static str)>;
    fn expected_finality_time_secs(&self) -> u64;
    fn expected_response_time_secs(&self) -> u64;
    fn respond_serialization_format(&self) -> SerDeserFormat;
}

impl ChainConfig for Chain {
    fn checkpoint_interval(&self) -> Option<u64> {
        let (key, default) = match self {
            Chain::NEAR | Chain::Bitcoin => return None,
            Chain::Ethereum => ("CHECKPOINT_INTERVAL_ETHEREUM", 20),
            Chain::Solana => ("CHECKPOINT_INTERVAL_SOLANA", 120),
            Chain::Hydration => ("CHECKPOINT_INTERVAL_HYDRATION", 240),
            Chain::Canton => ("CHECKPOINT_INTERVAL_CANTON", 50),
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
        ]
    }

    fn expected_finality_time_secs(&self) -> u64 {
        match self {
            Chain::NEAR => 3,
            Chain::Ethereum => 30 * 60,
            Chain::Solana => 3,
            Chain::Bitcoin => 60 * 60 + 20 * 60, // 6 confirmations at 10 minutes each, plus some buffer
            Chain::Hydration => 12,
            Chain::Canton => 15,
        }
    }

    fn expected_response_time_secs(&self) -> u64 {
        // finality time * 2 = finality time of sign/sign_bidirectional event + finality time of respond event
        self.expected_finality_time_secs() * 2 + 5 // + Buffer time
    }

    fn respond_serialization_format(&self) -> SerDeserFormat {
        match self {
            Chain::Canton => SerDeserFormat::Abi,
            // Solana and Hydration use Borsh for bidirectional responses.
            _ => SerDeserFormat::Borsh,
        }
    }
}
