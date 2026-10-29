use std::time::Duration;

use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke;
use tokio::sync::watch;

#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Protocol parameters mirrored from the contract.
    pub protocol: ProtocolConfig,
    /// Protocol timeouts. Fixed in production; the in-process test fixture
    /// shortens them.
    pub timeouts: Timeouts,
    /// This node's own keys, never shared with anyone else.
    pub network: NetworkConfig,
}

/// How long each protocol waits before giving up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeouts {
    /// Any protocol message sent over the wire.
    pub message: Duration,
    pub triple_generation: Duration,
    pub presignature_generation: Duration,
    pub signature_generation: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            message: Duration::from_secs(5 * 60),
            triple_generation: Duration::from_secs(10 * 60),
            presignature_generation: Duration::from_secs(45),
            signature_generation: Duration::from_secs(45),
        }
    }
}

impl Config {
    pub fn channel(network: NetworkConfig) -> (watch::Sender<Self>, watch::Receiver<Self>) {
        let config = Self::new(network);
        watch::channel(config)
    }

    pub fn new(network: NetworkConfig) -> Self {
        Self {
            protocol: ProtocolConfig::default(),
            timeouts: Timeouts::default(),
            network,
        }
    }

    /// Returns whether the protocol config actually changed, so that the
    /// surrounding `watch::Sender::send_if_modified` only notifies receivers on
    /// real changes instead of every contract poll.
    pub fn update(&mut self, contract: ProtocolConfig) -> bool {
        if self.protocol == contract {
            return false;
        }
        self.protocol = contract;
        true
    }
}

#[derive(Clone)]
pub struct NetworkConfig {
    pub sign_sk: near_crypto::SecretKey,
    pub cipher_sk: hpke::SecretKey,
}

/// Custom Debug implementation to avoid printing the secret keys in logs.
/// Underlying crates probably redact already, but it's better to be 100% sure
impl std::fmt::Debug for NetworkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkConfig")
            .field("sign_sk", &"<hidden>")
            .field("cipher_sk", &"<hidden>")
            .finish()
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            sign_sk: near_crypto::SecretKey::from_seed(
                near_crypto::KeyType::ED25519,
                "test-entropy",
            ),
            cipher_sk: hpke::SecretKey::from_bytes(&[0; 32]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, NetworkConfig};
    use mpc_contract::config::ProtocolConfig;

    #[test]
    fn test_update_returns_whether_protocol_changed() {
        let mut config = Config::new(NetworkConfig::default());

        // Same config as current => no change, no notification.
        assert!(!config.update(ProtocolConfig::default()));

        // An actual change => updated and notified.
        let mut changed = ProtocolConfig::default();
        changed.min_mine_presignatures += 1;
        assert!(config.update(changed.clone()));
        assert_eq!(
            config.protocol.min_mine_presignatures,
            changed.min_mine_presignatures
        );

        // The same value again => no change.
        assert!(!config.update(changed));
    }
}
