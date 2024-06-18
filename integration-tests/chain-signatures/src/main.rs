use tracing_subscriber::EnvFilter;

#[derive(Debug)]
enum Cli {
    SetupEnv { nodes: usize },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(EnvFilter::from_default_env());
    subscriber.init();

    Ok(())
}
