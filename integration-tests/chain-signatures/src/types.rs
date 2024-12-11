use std::fmt;

use mpc_contract::config::{PresignatureConfig, ProtocolConfig, TripleConfig};
use mpc_keys::hpke;
use near_workspaces::Account;

use crate::containers::RedisLoad;
use crate::utils::pick_unused_port;

pub const SEED_SIGN_SK: &str = "sign-sk-seed";

#[derive(Clone)]
pub struct Secrets {
    pub cipher_pk: hpke::PublicKey,
    pub cipher_sk: hpke::SecretKey,
    pub sign_sk: near_crypto::SecretKey,
}

impl Default for Secrets {
    fn default() -> Self {
        let (cipher_sk, cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, SEED_SIGN_SK);
        Self {
            cipher_pk,
            cipher_sk,
            sign_sk,
        }
    }
}

#[derive(Clone)]
pub struct NodeConfig {
    pub load: RedisLoad,
    pub nodes: usize,
    pub threshold: usize,
    pub protocol: ProtocolConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            load: RedisLoad::Full,
            nodes: 3,
            threshold: 2,
            protocol: ProtocolConfig {
                triple: TripleConfig {
                    min_triples: 8,
                    max_triples: 80,
                    ..Default::default()
                },
                presignature: PresignatureConfig {
                    min_presignatures: 2,
                    max_presignatures: 100,
                    ..Default::default()
                },
                ..Default::default()
            },
        }
    }
}

impl fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeConfig")
            .field("nodes", &self.nodes)
            .field("threshold", &self.threshold)
            .field("protocol", &self.protocol)
            .finish()
    }
}

/// Set of configurations for starting or spawning a new node or one that has
/// been stopped before.
pub struct NodeSpawnConfig {
    pub cfg: NodeConfig,
    pub account: Account,
    pub secrets: Secrets,
    pub web_port: u16,
}

impl NodeSpawnConfig {
    pub async fn new(cfg: &NodeConfig, account: &Account) -> Self {
        let web_port = pick_unused_port().await.unwrap();
        Self {
            account: account.clone(),
            cfg: cfg.clone(),
            secrets: Secrets::default(),
            web_port,
        }
    }

    pub fn address(&self) -> String {
        format!("http://127.0.0.1:{}", self.web_port)
    }
}

/// Set of configurations for the current running node.
pub struct NodeEnvConfig {
    pub web_port: u16,
    pub account: Account,
    pub secrets: Secrets,
    pub cfg: NodeConfig,
    // near rpc address, after proxy
    pub near_rpc: String,
}

impl fmt::Debug for NodeEnvConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeConfig")
            .field("web_port", &self.web_port)
            .field("account", &self.account)
            .field("cfg", &self.cfg)
            .field("near_rpc", &self.near_rpc)
            .finish()
    }
}
