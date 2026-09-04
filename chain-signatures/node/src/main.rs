use clap::Parser;
use mpc_node::cli::Cli;

fn main() -> anyhow::Result<()> {
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // Ensure at least 4 worker threads if CPU cores < 4
    let worker_threads = std::cmp::max(num_cpus, 4);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    rt.block_on(mpc_node::cli::run(Cli::parse()))
}
