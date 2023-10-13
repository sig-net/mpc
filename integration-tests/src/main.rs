use clap::Parser;
use mpc_recovery_integration_tests::env;
use mpc_recovery_integration_tests::env::containers::DockerClient;
use tokio::io::{stdin, AsyncReadExt};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
enum Cli {
    SetupEnv { nodes: usize },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(EnvFilter::from_default_env());
    subscriber.init();
    match Cli::parse() {
        Cli::SetupEnv { nodes } => {
            tracing::info!("Setting up an environment with {} nodes", nodes);
            let docker_client = DockerClient::default();
            let nodes = env::run(nodes, &docker_client).await?;
            let ctx = nodes.ctx();

            tracing::info!("");
            tracing::info!("Environment is ready");
            tracing::info!("  Docker network: {}", ctx.docker_network);
            tracing::info!("  GCP project id: {}", ctx.gcp_project_id);
            tracing::info!("  Audience id: {}", ctx.audience_id);

            tracing::info!("Datastore address: {}", nodes.datastore_addr());
            tracing::info!("Sandbox address: {}", ctx.relayer_ctx.sandbox.local_address);
            tracing::info!(
                "Sandbox root account: {}",
                ctx.relayer_ctx.worker.root_account()?.id()
            );
            tracing::info!("Relayer address: {}", ctx.relayer_ctx.relayer.local_address);
            tracing::info!(
                "Relayer creator account: {}",
                ctx.relayer_ctx.creator_account.id()
            );
            tracing::info!("OidcProvider address: {}", ctx.oidc_provider.jwt_local_url);
            tracing::info!(
                "Signer node URLs:\n{:#?}",
                nodes
                    .signer_apis()
                    .iter()
                    .map(|n| n.address.as_str())
                    .collect::<Vec<_>>()
            );
            tracing::info!("pk set: {:?}", nodes.pk_set());
            tracing::info!("Leader node address: {}", nodes.leader_api().address);
            tracing::info!("Press any button to exit and destroy all containers...");

            while stdin().read(&mut [0]).await? == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }
    };

    Ok(())
}
