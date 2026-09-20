use std::fs::File;
use std::io::Write;
use std::str::FromStr;
use std::vec;

use anyhow::Context as _;
use clap::Parser;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::gcs::GcsEmulator;
use integration_tests::midnight::{ExternalMidnight, MidnightContext, MidnightEndpoints};
use integration_tests::NodeConfig;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use mpc_chain_ethereum::EthConfig;
use mpc_chain_midnight::MidnightConfig;
use near_account_id::AccountId;
use near_crypto::PublicKey;
use serde_json::json;
use tokio::signal;

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
        #[arg(long, default_value = "anvil")]
        eth_network: String,
        #[arg(long, default_value = "/tmp/data")]
        eth_helios_data_path: String,
        #[arg(long, default_value = "10000")]
        eth_refresh_finalized_interval: u64,
        #[command(flatten)]
        midnight: Box<MidnightSetup>,
    },
    /// Spin up dependent services but not mpc nodes
    DepServices,
    /// Generate example commands to interact with the contract
    ContractCommands,
}

#[derive(clap::Args, Debug)]
struct MidnightSetup {
    /// Start a local Midnight node, indexer and proof server, fund its
    /// wallets, and deploy a central contract plus a test caller contract
    #[arg(long, conflicts_with = "midnight_node_url")]
    midnight: bool,
    /// HTTP RPC URL of a running Midnight node whose central contract the
    /// nodes respond on
    #[arg(
        long,
        requires_all = [
            "midnight_indexer_url",
            "midnight_indexer_ws_url",
            "midnight_proof_server_url",
            "midnight_central_address",
            "midnight_funding_seed",
        ]
    )]
    midnight_node_url: Option<String>,
    #[arg(long, requires = "midnight_node_url")]
    midnight_indexer_url: Option<String>,
    #[arg(long, requires = "midnight_node_url")]
    midnight_indexer_ws_url: Option<String>,
    #[arg(long, requires = "midnight_node_url")]
    midnight_proof_server_url: Option<String>,
    /// Address of the deployed central contract: 64 hex characters
    #[arg(long, requires = "midnight_node_url")]
    midnight_central_address: Option<String>,
    /// Hex seed of a DUST-funded wallet that pays for respond transactions
    #[arg(long, env("MPC_MIDNIGHT_FUNDING_SEED"), hide_env_values = true)]
    midnight_funding_seed: Option<String>,
}

impl MidnightSetup {
    fn external(&self) -> Option<ExternalMidnight> {
        Some(ExternalMidnight {
            endpoints: MidnightEndpoints {
                node_http_url: self.midnight_node_url.clone()?,
                indexer_url: self.midnight_indexer_url.clone()?,
                indexer_ws_url: self.midnight_indexer_ws_url.clone()?,
                proof_server_url: self.midnight_proof_server_url.clone()?,
            },
            central_address: self
                .midnight_central_address
                .clone()?
                .trim_start_matches("0x")
                .to_string(),
            funding_seed: self.midnight_funding_seed.clone()?,
        })
    }
}

/// What a Midnight client needs to talk to this environment's MPC.
fn print_midnight(
    config: &MidnightConfig,
    root_public_key: mpc_crypto::PublicKey,
    output_storage: &GcsEmulator,
    caller_address: Option<&str>,
) {
    println!("\nMidnight:");
    println!("  node:             {}", config.node_url);
    println!("  indexer:          {}", config.publisher.indexer_url);
    println!("  indexer ws:       {}", config.publisher.indexer_ws_url);
    println!("  proof server:     {}", config.publisher.proof_server_url);
    println!("  central contract: {}", config.central_address.to_hex());
    if let Some(caller_address) = caller_address {
        println!("  caller contract:  {caller_address}");
    }
    println!(
        "  mpc root public key (compressed secp256k1): 0x{}",
        hex::encode(root_public_key.to_encoded_point(true).as_bytes())
    );
    if let Some(storage) = &config.publisher.output_storage {
        println!(
            "  output cache:     {}",
            output_storage.public_url(&storage.prefix)
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    integration_tests::utils::init_tracing_log();

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
            midnight,
        } => {
            println!("Setting up an environment with {nodes} nodes, {threshold} threshold ...");
            let config = NodeConfig {
                nodes,
                threshold,
                eth: Some(EthConfig {
                    account_sk: eth_account_sk
                        .parse()
                        .map_err(|e| anyhow::anyhow!("invalid eth account sk: {e}"))?,
                    consensus_rpc_http_url: eth_consensus_rpc_http_url,
                    execution_rpc_http_url: eth_execution_rpc_http_url
                        .parse()
                        .map_err(|e| anyhow::anyhow!("invalid eth execution rpc url: {e}"))?,
                    contract_address: eth_contract_address
                        .parse()
                        .map_err(|e| anyhow::anyhow!("invalid eth contract address: {e}"))?,
                    optimistic_requests: eth_network == "anvil",
                    network: eth_network,
                    helios_data_path: eth_helios_data_path,
                    refresh_finalized_interval: eth_refresh_finalized_interval,
                    light_client: false,
                    gas: Default::default(),
                    indexer: Default::default(),
                    publisher: Default::default(),
                    rpc: Default::default(),
                }),
                ..Default::default()
            };
            println!("Full config: {config:?}");
            let mut spawner = ClusterSpawner::default()
                .config(config)
                .init_network()
                .await?;

            // Both Midnight resources hold containers that must outlive the nodes.
            let mut midnight_context = None;
            let mut midnight_output_storage = None;
            if midnight.midnight || midnight.midnight_node_url.is_some() {
                let root_public_key = spawner.pregenerated_keys.public_key().context(
                    "Midnight needs pregenerated MPC keys, which exist for 3 nodes with threshold 2 and 5 nodes with threshold 4",
                )?;
                let (output_storage, caller_address) = if let Some(external) = midnight.external() {
                    let output_storage = GcsEmulator::run().await?;
                    spawner.cfg.midnight = Some(external.node_config(&output_storage)?);
                    (&*midnight_output_storage.insert(output_storage), None)
                } else {
                    let context = MidnightContext::run(&spawner, root_public_key).await?;
                    spawner.cfg.midnight = Some(context.config.clone());
                    let context = &*midnight_context.insert(context);
                    (
                        &context.output_storage,
                        Some(context.caller_address.as_str()),
                    )
                };
                let config = spawner.cfg.midnight.as_ref().expect("set above");
                print_midnight(config, root_public_key, output_storage, caller_address);
            }

            let nodes = spawner.run().await?;
            let ctx = nodes.ctx();
            let urls: Vec<_> = (0..spawner.cfg.nodes).map(|i| nodes.url(i)).collect();
            let near_accounts = nodes.near_accounts();

            println!("\nEnvironment is ready:");
            println!("  docker-network: {}", ctx.docker_network);
            println!("  release:        {}", ctx.release);

            println!("\nExternal services:");
            println!("  near sandbox rpc:  {}", ctx.worker.rpc_addr());
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
            drop(midnight_context);
            drop(midnight_output_storage);
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
