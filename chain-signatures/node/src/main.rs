use clap::Parser;
use mpc_node::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mpc_node::cli::run(Cli::parse()).await
}
