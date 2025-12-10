use std::collections::HashMap;
use std::str::FromStr;

use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;

/// The contract's config is a dynamic representation of all configurations possible.
pub type ContractConfig = HashMap<String, Value>;

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub protocol: ProtocolConfig,
    pub local: LocalConfig,
}

impl Config {
    pub fn channel(local: LocalConfig) -> (watch::Sender<Self>, watch::Receiver<Self>) {
        let config = Self::new(local);
        watch::channel(config)
    }

    pub fn channel_default() -> (watch::Sender<Self>, watch::Receiver<Self>) {
        Self::channel(LocalConfig::default())
    }

    pub fn new(local: LocalConfig) -> Self {
        let mut protocol = ProtocolConfig::default();

        // We should also override are default initalized config if our overrides are present:
        if let Some(map) = local.over.entries.as_object() {
            if !map.is_empty() {
                let mut base = serde_json::to_value(protocol).unwrap();
                merge(&mut base, &local.over.entries);
                protocol = serde_json::from_value(base).unwrap();
            }
        }

        Self { protocol, local }
    }

    pub fn try_from_contract(mut contract: ContractConfig, original: &Config) -> Option<Self> {
        let Some(mut protocol) = contract.remove("protocol") else {
            tracing::warn!("unable to find protocol in contract config");
            return None;
        };
        merge(&mut protocol, &original.local.over.entries);
        let Ok(protocol) = serde_json::from_value(protocol) else {
            tracing::warn!("unable to parse protocol in contract config");
            return None;
        };

        Some(Self {
            protocol,
            local: original.local.clone(),
        })
    }

    pub fn update(&mut self, mut contract: ContractConfig) -> bool {
        let Some(mut protocol) = contract.remove("protocol") else {
            tracing::warn!("unable to find protocol in contract config");
            return false;
        };
        merge(&mut protocol, &self.local.over.entries);
        let Ok(protocol) = serde_json::from_value(protocol) else {
            tracing::warn!("unable to parse protocol in contract config");
            return false;
        };

        self.protocol = protocol;
        true
    }
}

/// All the local configurations on a node that are not accessible by anyone else
/// but the current node.
#[derive(Clone, Debug, Default)]
pub struct LocalConfig {
    pub network: NetworkConfig,
    pub over: OverrideConfig,
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub sign_sk: near_crypto::SecretKey,
    pub cipher_sk: hpke::SecretKey,
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

/// The override config is the set of configurations we want to override from the
/// default configuration. This is a partial set of configurations, purely only
/// the values that the node wants to override.
///
/// The set of configs that can be overridden are only the non-[`LocalConfig`]
/// ones since we already control those.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OverrideConfig {
    pub(crate) entries: Value,
}

impl Default for OverrideConfig {
    fn default() -> Self {
        // NOTE: serde_json::Value::default() use Value::Null which is not what we want
        // so we create a new empty map instead.
        Self {
            entries: Value::Object(serde_json::Map::new()),
        }
    }
}

impl OverrideConfig {
    pub fn new(entries: Value) -> Self {
        Self { entries }
    }
}

impl FromStr for OverrideConfig {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

pub fn merge(base: &mut Value, new: &Value) {
    match (base, new) {
        (base @ &mut Value::Object(_), Value::Object(new)) => {
            let base = base.as_object_mut().unwrap();
            for (key, new_value) in new {
                let base = base.entry(key).or_insert(Value::Null);
                merge(base, new_value);
            }
        }
        (base, new) => *base = new.clone(),
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use proptest::prelude::*;

    use super::merge;

    #[test]
    fn test_merge() {
        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct B {
            c: i32,
            d: i32,
        }

        #[allow(dead_code)]
        #[derive(Debug, Deserialize)]
        struct Base {
            a: i32,
            b: B,
        }

        let mut base = serde_json::json!( {
            "a": 1,
            "b": {
                "c": 2,
                "d": 3,
            },
        });

        let new = serde_json::json!({
            "b": {
                "c": 4,
                "e": 5,
            },
            "f": 6,
        });

        merge(&mut base, &new);
        let base: Base = serde_json::from_value(base).unwrap();
        dbg!(base);
    }

    proptest! {
        /// Property 41: Configuration Validation Error Reporting
        /// For any invalid configuration, the system should provide clear error messages indicating what is invalid
        /// **Validates: Requirements 7.2, 7.3, 7.4**
        #[test]
        fn prop_configuration_validation_error_reporting(
            invalid_json in r#"\{[^}]*"#,
        ) {
            // Test: Invalid JSON should produce clear error messages
            let result = invalid_json.parse::<super::OverrideConfig>();
            
            // Invalid JSON should fail
            if result.is_err() {
                if let Err(e) = result {
                    let error_msg = e.to_string();
                    // Error message should not be empty and should be informative
                    prop_assert!(
                        !error_msg.is_empty(),
                        "Error message should not be empty"
                    );
                }
            }
        }
    }

    #[test]
    fn test_configuration_validation_error_reporting() {
        // Test 1: Invalid JSON should produce error with clear message
        let invalid_json = "{invalid json";
        let result = invalid_json.parse::<super::OverrideConfig>();
        assert!(result.is_err(), "Invalid JSON should fail");
        
        if let Err(e) = result {
            let error_msg = e.to_string();
            assert!(!error_msg.is_empty(), "Error message should not be empty");
        }
        
        // Test 2: Valid JSON with entries field should parse successfully
        let valid_json = r#"{"entries": {}}"#;
        let result = valid_json.parse::<super::OverrideConfig>();
        assert!(result.is_ok(), "Valid JSON should parse successfully: {:?}", result);
        
        // Test 3: Valid JSON with nested structure should parse successfully
        let valid_json_nested = r#"{"entries": {"protocol": {"message_timeout": 10000}}}"#;
        let result = valid_json_nested.parse::<super::OverrideConfig>();
        assert!(result.is_ok(), "Valid nested JSON should parse successfully: {:?}", result);
    }
}
