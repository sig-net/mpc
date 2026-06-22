use std::fmt;
use std::path::PathBuf;

use crate::{execute, utils, NodeConfig};

use crate::execute::executable;
use anyhow::Context;
use async_process::Child;
use mpc_keys::hpke;
use mpc_node::cli::{CantonArgs, Cli, EthArgs, HydrationArgs, SolArgs};
use mpc_node::config::OverrideConfig;
use near_workspaces::Account;
use shell_escape::escape;

pub struct Node {
    pub address: String,
    pub account: Account,
    pub sign_sk: near_crypto::SecretKey,
    pub cipher_sk: hpke::SecretKey,
    cfg: NodeConfig,
    web_port: u16,
    // process held so it's not dropped. Once dropped, process will be killed.
    process: Child,
    // near rpc address, after proxy
    pub near_rpc: String,
}

pub struct NodeEnvConfig {
    pub web_port: u16,
    pub account: Account,
    pub cipher_sk: hpke::SecretKey,
    pub sign_sk: near_crypto::SecretKey,
    pub cfg: NodeConfig,
    // near rpc address, after proxy
    pub near_rpc: String,
    /// Optional custom binary path to use instead of the default target/release
    pub binary_path: Option<PathBuf>,
}

impl fmt::Debug for NodeEnvConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeConfig")
            .field("web_port", &self.web_port)
            .field("account", &self.account)
            .field("cipher_pk", &self.cipher_sk.public_key())
            .field("cfg", &self.cfg)
            .field("near_rpc", &self.near_rpc)
            .field("binary_path", &self.binary_path)
            .finish()
    }
}

impl Node {
    pub async fn dry_run(
        ctx: &super::Context,
        account: &Account,
        cfg: &NodeConfig,
    ) -> anyhow::Result<NodeEnvConfig> {
        let account_id = account.id();
        let account_sk = account.secret_key();
        let web_port = utils::pick_unused_port().await?;
        let (cipher_sk, _cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");

        let indexer_options = mpc_node::indexer::Options {
            running_threshold: 120,
        };
        let eth = EthArgs::from_config(cfg.eth.clone());
        let sol = SolArgs::from_config(cfg.sol.clone());
        let hydration = HydrationArgs::from_config(cfg.hydration.clone());
        let canton = CantonArgs::from_config(cfg.canton.clone());
        let near_rpc = ctx.worker.rpc_addr();
        let mpc_contract_id = ctx.mpc_contract.id().clone();
        let cli = Cli::Start {
            near_rpc: near_rpc.clone(),
            mpc_contract_id: mpc_contract_id.clone(),
            account_id: account_id.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port: Some(web_port),
            cipher_sk: hex::encode(cipher_sk.to_bytes()),
            sign_sk: Some(sign_sk.clone()),
            eth,
            sol,
            hydration,
            canton,
            indexer_options,
            my_address: None,
            storage_options: ctx.storage_options.clone(),
            log_options: ctx.log_options.clone(),
            override_config: Some(OverrideConfig::new(serde_json::to_value(
                cfg.protocol.clone(),
            )?)),
            client_header_referer: None,
            mesh_options: ctx.mesh_options.clone(),
            message_options: ctx.message_options.clone(),
        };

        let cmd = executable(ctx.release, crate::execute::PACKAGE_MULTICHAIN)
            .with_context(|| "could not find target dir for mpc-node")?;
        let args = cli.into_str_args();
        let escaped_args: Vec<_> = args
            .iter()
            .map(|arg| escape(arg.clone().into()).to_string())
            .collect();
        println!(
            "\nCommand to run node {}:\n {} {}",
            account_id,
            cmd.to_str().unwrap(),
            escaped_args.join(" ")
        );
        let node_config = NodeEnvConfig {
            web_port,
            account: account.clone(),
            cipher_sk,
            sign_sk,
            cfg: cfg.clone(),
            near_rpc,
            binary_path: None,
        };
        Ok(node_config)
    }

    pub async fn run(
        ctx: &super::Context,
        cfg: &NodeConfig,
        account: &Account,
    ) -> anyhow::Result<Self> {
        Self::run_with_binary(ctx, cfg, account, None).await
    }

    pub async fn run_with_binary(
        ctx: &super::Context,
        cfg: &NodeConfig,
        account: &Account,
        binary_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let web_port = utils::pick_unused_port().await?;
        let (cipher_sk, _cipher_pk) = hpke::generate();
        let sign_sk =
            near_crypto::SecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");
        let near_rpc = ctx.worker.rpc_addr();

        let mut cfg = cfg.clone();
        if let Some(ref mut eth_config) = cfg.eth {
            eth_config.helios_data_path =
                format!("{}_{}", eth_config.helios_data_path, account.id());
        }

        Self::spawn(
            ctx,
            NodeEnvConfig {
                web_port,
                account: account.clone(),
                cipher_sk,
                sign_sk,
                cfg: cfg.clone(),
                near_rpc,
                binary_path,
            },
        )
        .await
    }

    pub async fn spawn(ctx: &super::Context, config: NodeEnvConfig) -> anyhow::Result<Self> {
        let web_port = config.web_port;
        let indexer_options = mpc_node::indexer::Options {
            running_threshold: 120,
        };

        let eth = EthArgs::from_config(config.cfg.eth.clone());
        let sol = SolArgs::from_config(config.cfg.sol.clone());
        let hydration = HydrationArgs::from_config(config.cfg.hydration.clone());
        let canton = CantonArgs::from_config(config.cfg.canton.clone());
        let cli = Cli::Start {
            near_rpc: config.near_rpc.clone(),
            mpc_contract_id: ctx.mpc_contract.id().clone(),
            account_id: config.account.id().clone(),
            account_sk: config.account.secret_key().to_string().parse()?,
            web_port: Some(web_port),
            cipher_sk: hex::encode(config.cipher_sk.to_bytes()),
            sign_sk: Some(config.sign_sk.clone()),
            eth,
            sol,
            hydration,
            canton,
            indexer_options,
            my_address: None,
            storage_options: ctx.storage_options.clone(),
            log_options: ctx.log_options.clone(),
            override_config: Some(OverrideConfig::new(serde_json::to_value(
                config.cfg.protocol.clone(),
            )?)),
            client_header_referer: None,
            mesh_options: ctx.mesh_options.clone(),
            message_options: ctx.message_options.clone(),
        };

        let mpc_node_id = format!("multichain/{}", config.account.id());
        let process = execute::spawn_node_with_binary(
            config.binary_path.clone(),
            ctx.release,
            &mpc_node_id,
            cli,
        )?;
        let address = format!("http://127.0.0.1:{web_port}");
        tracing::info!("node is starting at {address}");
        utils::ping_until_ok(&address, 120).await?;
        tracing::info!(node_account_id = %config.account.id(), ?address, "node started");

        Ok(Self {
            address,
            account: config.account,
            sign_sk: config.sign_sk,
            cipher_sk: config.cipher_sk,
            near_rpc: config.near_rpc,
            cfg: config.cfg,
            web_port,
            process,
        })
    }

    pub fn kill(self) -> NodeEnvConfig {
        // NOTE: process gets killed after this function completes via the drop, due to taking ownership of self.

        tracing::info!(id = %self.account.id(), ?self.address, "node killed");
        NodeEnvConfig {
            web_port: self.web_port,
            account: self.account.clone(),
            cipher_sk: self.cipher_sk.clone(),
            sign_sk: self.sign_sk.clone(),
            cfg: self.cfg.clone(),
            near_rpc: self.near_rpc.clone(),
            binary_path: None, // Don't preserve binary_path on restart
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // Give the process a brief moment to clean up connections gracefully
        // before we forcefully kill it. This reduces flaky test failures
        // during teardown when nodes are trying to write to Redis.
        std::thread::sleep(std::time::Duration::from_millis(100));
        self.process.kill().unwrap();
    }
}
