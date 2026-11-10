use std::collections::HashMap;

use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke;
use serde_json::Value;
use tokio::sync::watch;

/// The contract's config is a dynamic representation of all configurations possible.
pub type ContractConfig = HashMap<String, Value>;

#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Protocol parameters mirrored from the contract.
    pub protocol: ProtocolConfig,
    /// This node's own keys, never shared with anyone else.
    pub network: NetworkConfig,
}

impl Config {
    pub fn channel(network: NetworkConfig) -> (watch::Sender<Self>, watch::Receiver<Self>) {
        let config = Self::new(network);
        watch::channel(config)
    }

    pub fn new(network: NetworkConfig) -> Self {
        Self {
            protocol: ProtocolConfig::default(),
            network,
        }
    }

    /// Returns whether the protocol config actually changed, so that the
    /// surrounding `watch::Sender::send_if_modified` only notifies receivers on
    /// real changes instead of every contract poll.
    pub fn update(&mut self, mut contract: ContractConfig) -> bool {
        let Some(protocol) = contract.remove("protocol") else {
            tracing::warn!("unable to find protocol in contract config");
            return false;
        };
        let Ok(protocol) = serde_json::from_value(protocol) else {
            tracing::warn!("unable to parse protocol in contract config");
            return false;
        };
        if self.protocol == protocol {
            return false;
        }
        self.protocol = protocol;
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
    use super::{Config, ContractConfig, NetworkConfig};
    use mpc_contract::config::ProtocolConfig;

    fn contract_config(protocol: &ProtocolConfig) -> ContractConfig {
        ContractConfig::from([(
            "protocol".to_string(),
            serde_json::to_value(protocol).unwrap(),
        )])
    }

    #[test]
    fn test_update_returns_whether_protocol_changed() {
        let mut config = Config::new(NetworkConfig::default());

        // Same config as current => no change, no notification.
        assert!(!config.update(contract_config(&ProtocolConfig::default())));

        // An actual change => updated and notified.
        let mut changed = ProtocolConfig::default();
        changed.message_timeout += 1;
        assert!(config.update(contract_config(&changed)));
        assert_eq!(config.protocol.message_timeout, changed.message_timeout);

        // The same value again => no change.
        assert!(!config.update(contract_config(&changed)));

        // Missing protocol section => rejected, no change.
        assert!(!config.update(ContractConfig::new()));
    }
}
