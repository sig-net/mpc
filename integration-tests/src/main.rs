use std::fs::File;
use std::io::Write;
use std::str::FromStr;
use std::vec;

use clap::Parser;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::NodeConfig;
use mpc_node::indexer_eth::EthConfig;
use near_account_id::AccountId;
use near_crypto::PublicKey;
use serde_json::json;
use tokio::signal;
use tracing_subscriber::EnvFilter;

mod commands;

#[derive(Parser, Debug)]
enum Cli {
    /// Spin up dependent services and mpc nodes
    SetupEnv {
        #[arg(short, long, default_value_t = 3)]
        nodes: usize,
        #[arg(short, long, default_value_t = 2)]
        threshold: usize,
        #[arg(long, default_value = "http://localhost:8545")]
        eth_consensus_rpc_http_url: String,
        #[arg(long, default_value = "http://localhost:8545")]
        eth_execution_rpc_http_url: String,
        #[arg(long, default_value = "e7f1725E7734CE288F8367e1Bb143E90bb3F0512")]
        eth_contract_address: String,
        #[arg(
            long,
            default_value = "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
        )]
        eth_account_sk: String,
        #[arg(long, default_value = "sepolia")]
        eth_network: String,
        #[arg(long, default_value = "/tmp/data")]
        eth_helios_data_path: String,
        #[arg(long, default_value = "10000")]
        eth_refresh_finalized_interval: u64,
        #[arg(long, default_value = "1200")]
        eth_total_timeout: u64,
    },
    /// Spin up dependent services but not mpc nodes
    DepServices,
    /// Generate example commands to interact with the contract
    ContractCommands,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(EnvFilter::from_default_env());
    subscriber.init();

    match Cli::parse() {
        Cli::SetupEnv {
            nodes,
            threshold,
            eth_consensus_rpc_http_url,
            eth_execution_rpc_http_url,
            eth_contract_address,
            eth_account_sk,
            eth_network,
            eth_helios_data_path,
            eth_refresh_finalized_interval,
            eth_total_timeout,
        } => {
            println!("Setting up an environment with {nodes} nodes, {threshold} threshold ...");
            let config = NodeConfig {
                nodes,
                threshold,
                eth: Some(EthConfig {
                    account_sk: eth_account_sk,
                    consensus_rpc_http_url: eth_consensus_rpc_http_url,
                    execution_rpc_http_url: eth_execution_rpc_http_url,
                    contract_address: eth_contract_address,
                    network: eth_network,
                    helios_data_path: eth_helios_data_path,
                    refresh_finalized_interval: eth_refresh_finalized_interval,
                    total_timeout: eth_total_timeout,
                }),
                ..Default::default()
            };
            println!("Full config: {config:?}");
            let mut spawner = ClusterSpawner::default()
                .config(config)
                .init_network()
                .await?;

            let nodes = spawner.run().await?;
            let ctx = nodes.ctx();
            let urls: Vec<_> = (0..spawner.cfg.nodes).map(|i| nodes.url(i)).collect();
            let near_accounts = nodes.near_accounts();

            println!("\nEnvironment is ready:");
            println!("  docker-network: {}", ctx.docker_network);
            println!("  release:        {}", ctx.release);

            println!("\nExternal services:");
            println!("  lake_indexer:  {}", ctx.lake_indexer.rpc_host_address);
            println!("  redis:  {}", ctx.redis.internal_address);

            println!("\nNodes:");
            for i in 0..urls.len() {
                println!("  Node {i}");
                println!("    Url: {}", urls[i]);
                let account_id = near_accounts[i].id();
                println!("    Account: {account_id}");
                let sk = near_accounts[i].secret_key();
                println!("    Secret Key: {sk}");
                let pk = sk.public_key();
                println!("    Public Key: {pk}");
            }

            signal::ctrl_c().await.expect("Failed to listen for event");
            println!("Received Ctrl-C");
            println!("Clean up finished");
        }
        Cli::DepServices => {
            println!("Setting up dependency services");
            let mut spawner = ClusterSpawner::default().init_network().await?;
            let _ctx = spawner.dry_run().await?;

            println!("Press Ctrl-C to stop dependency services");
            signal::ctrl_c().await.expect("Failed to listen for event");
            println!("Received Ctrl-C");
            println!("Stopped dependency services");
        }
        Cli::ContractCommands => {
            println!("Building a doc with example commands");
            let path = "../chain-signatures/contract/EXAMPLE.md";
            let mut file = File::create(path)?;
            let mut doc: Vec<String> = vec![];
            let contract_account_id = AccountId::from_str("dev.sig-net.testnet")?;
            let caller_account_id = AccountId::from_str("caller.testnet")?;
            let public_key: PublicKey =
                "ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae".parse()?;

            doc.push(
                "# Iteracting with contract using NEAR CLI\nAll data is fake and used for example purposes\nIt's necessary to update script after contract API changes\n## User contract API"
                .to_string()
            );

            doc.push(commands::sign_command(
                &contract_account_id,
                &caller_account_id,
            )?);
            doc.push(format!("near view {contract_account_id} public_key"));

            doc.push(format!(
                "near view {contract_account_id} derived_public_key {}",
                serde_json::to_string(&json!({"path": "test","predecessor": caller_account_id}))?
            ));

            doc.push(format!(
                "near view {contract_account_id} latest_key_version"
            ));

            doc.push(format!(
                "near view {contract_account_id} experimental_signature_deposit"
            ));

            doc.push(format!(
                "\n## Node API\n\n{}\n\n{}",
                commands::respond_command(&contract_account_id, &caller_account_id,)?,
                commands::join_command(&contract_account_id, &caller_account_id,)?
            ));

            doc.push(format!(
                "near call {contract_account_id} vote_join '{{\"candidate\":\"{caller_account_id}\"}}' --accountId {caller_account_id} --gas 300000000000000"
            ));

            doc.push(format!(
                "near call {contract_account_id} vote_leave '{{\"kick\":\"{caller_account_id}\"}}' --accountId {caller_account_id} --gas 300000000000000"
            ));

            doc.push(format!(
                "near call {contract_account_id} vote_pk '{{\"public_key\": {public_key}}}' --accountId {caller_account_id} --gas 300000000000000"
            ));

            doc.push(format!(
                "near call {contract_account_id} vote_reshared '{{\"epoch\": 1}}' --accountId {caller_account_id} --gas 300000000000000"
            ));

            doc.push(commands::proposed_updates_command(
                &contract_account_id,
                &caller_account_id,
            )?);

            doc.push(format!(
                "near call {contract_account_id} vote_update '{{\"id\": 0}}' --accountId {caller_account_id} --gas 300000000000000"
            ));

            doc.push(format!(
                "\n## Contract developer helper API\n\n{}\n\n{}",
                commands::init_command(&contract_account_id, &caller_account_id,)?,
                commands::init_running_command(&contract_account_id, &caller_account_id,)?
            ));

            doc.push(format!("near view {contract_account_id} migrate"));

            doc.push(format!("near view {contract_account_id} state"));

            doc.push(format!("near view {contract_account_id} config"));

            doc.push(format!("near view {contract_account_id} version"));

            for arg in doc {
                file.write_all(arg.as_bytes())?;
                file.write_all("\n\n".as_bytes())?;
            }
        }
    }

    Ok(())
}
