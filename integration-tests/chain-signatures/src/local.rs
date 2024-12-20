use crate::types::{NodeEnvConfig, NodeSpawnConfig, Secrets};
use crate::{execute, utils, NodeConfig};

use crate::containers::LakeIndexer;
use anyhow::Context;
use async_process::Child;
use mpc_node::config::OverrideConfig;
use near_workspaces::Account;
use shell_escape::escape;

pub struct Node {
    pub address: String,
    pub account: Account,
    pub secrets: Secrets,
    cfg: NodeConfig,
    web_port: u16,

    // process held so it's not dropped. Once dropped, process will be killed.
    process: Child,
    // near rpc address, after proxy
    pub near_rpc: String,
}

impl Node {
    pub async fn dry_run(
        ctx: &super::Context,
        spawn_cfg: NodeSpawnConfig,
    ) -> anyhow::Result<NodeEnvConfig> {
        let account_id = spawn_cfg.account.id();
        let account_sk = spawn_cfg.account.secret_key();

        let indexer_options = mpc_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            running_threshold: 120,
            behind_threshold: 120,
        };
        let near_rpc = ctx.lake_indexer.rpc_host_address.clone();
        let mpc_contract_id = ctx.mpc_contract.id().clone();
        let cli = mpc_node::cli::Cli::Start {
            near_rpc: near_rpc.clone(),
            mpc_contract_id: mpc_contract_id.clone(),
            account_id: account_id.clone(),
            account_sk: account_sk.to_string().parse()?,
            web_port: spawn_cfg.web_port,
            cipher_pk: hex::encode(spawn_cfg.secrets.cipher_pk.to_bytes()),
            cipher_sk: hex::encode(spawn_cfg.secrets.cipher_sk.to_bytes()),
            sign_sk: Some(spawn_cfg.secrets.sign_sk.clone()),
            indexer_options,
            my_address: None,
            storage_options: ctx.storage_options.clone(),
            override_config: Some(OverrideConfig::new(serde_json::to_value(
                &spawn_cfg.cfg.protocol,
            )?)),
            client_header_referer: None,
            mesh_options: ctx.mesh_options.clone(),
            message_options: ctx.message_options.clone(),
        };

        let cmd = execute::node_executable(ctx.release)
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
            web_port: spawn_cfg.web_port,
            secrets: spawn_cfg.secrets,
            account: spawn_cfg.account,
            cfg: spawn_cfg.cfg,
            near_rpc,
        };
        Ok(node_config)
    }

    pub async fn run(ctx: &super::Context, spawn_cfg: NodeSpawnConfig) -> anyhow::Result<Self> {
        let near_rpc = ctx.lake_indexer.rpc_host_address.clone();

        let proxy_name = format!("rpc_from_node_{}", spawn_cfg.account.id());
        let rpc_port_proxied = utils::pick_unused_port().await?;
        let rpc_address_proxied = format!("http://127.0.0.1:{}", rpc_port_proxied);
        let address = spawn_cfg.address();
        tracing::info!(
            "Proxy RPC address {} accessed by node@{} to {}",
            near_rpc,
            address,
            rpc_address_proxied
        );
        LakeIndexer::populate_proxy(&proxy_name, true, &rpc_address_proxied, &near_rpc).await?;

        Self::spawn(
            ctx,
            NodeEnvConfig {
                web_port: spawn_cfg.web_port,
                secrets: spawn_cfg.secrets,
                account: spawn_cfg.account,
                cfg: spawn_cfg.cfg,
                near_rpc: rpc_address_proxied,
            },
        )
        .await
    }

    pub async fn spawn(ctx: &super::Context, config: NodeEnvConfig) -> anyhow::Result<Self> {
        let web_port = config.web_port;
        let indexer_options = mpc_node::indexer::Options {
            s3_bucket: ctx.localstack.s3_bucket.clone(),
            s3_region: ctx.localstack.s3_region.clone(),
            s3_url: Some(ctx.localstack.s3_host_address.clone()),
            running_threshold: 120,
            behind_threshold: 120,
        };
        let cli = mpc_node::cli::Cli::Start {
            near_rpc: config.near_rpc.clone(),
            mpc_contract_id: ctx.mpc_contract.id().clone(),
            account_id: config.account.id().clone(),
            account_sk: config.account.secret_key().to_string().parse()?,
            web_port,
            cipher_pk: hex::encode(config.secrets.cipher_pk.to_bytes()),
            cipher_sk: hex::encode(config.secrets.cipher_sk.to_bytes()),
            sign_sk: Some(config.secrets.sign_sk.clone()),
            indexer_options,
            my_address: None,
            storage_options: ctx.storage_options.clone(),
            override_config: Some(OverrideConfig::new(serde_json::to_value(
                config.cfg.protocol.clone(),
            )?)),
            client_header_referer: None,
            mesh_options: ctx.mesh_options.clone(),
            message_options: ctx.message_options.clone(),
        };

        let mpc_node_id = format!("multichain/{}", config.account.id());
        let process = execute::spawn_node(ctx.release, &mpc_node_id, cli)?;
        let address = format!("http://127.0.0.1:{web_port}");
        tracing::info!("node is starting at {address}");
        utils::ping_until_ok(&address, 60).await?;
        tracing::info!(node_account_id = %config.account.id(), ?address, "node started");

        Ok(Self {
            address,
            secrets: config.secrets,
            account: config.account,
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
            secrets: self.secrets.clone(),
            account: self.account.clone(),
            cfg: self.cfg.clone(),
            near_rpc: self.near_rpc.clone(),
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.process.kill().unwrap();
    }
}
