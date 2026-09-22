use clap::Parser;
use integration_tests::cluster::spawner::ClusterSpawner;
use integration_tests::NodeConfig;
use mpc_chain_ethereum::EthConfig;
use tokio::signal;

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
    },
    /// Spin up dependent services but not mpc nodes
    DepServices,
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
    }

    Ok(())
}
