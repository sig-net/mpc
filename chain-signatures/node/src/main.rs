use clap::Parser;
use mpc_node::cli::Cli;

fn main() -> anyhow::Result<()> {
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // Ensure at least 4 worker threads if CPU cores < 4
    let worker_threads = std::cmp::max(num_cpus, 4);

    // Default for tokio is 512, but that gets dangerously close to starvation when
    // triple generation ramps up significantly. We do the following limit for now
    // such that `spawn_blocking` on triples do not starve the rest of the system.
    // Why is this number not lower? Because we have system metrics and other parts
    // like tokio::net that relies on the blocking pool as well, so limiting much
    // lower would bottleneck us there.
    let blocking_threads = 64;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .max_blocking_threads(blocking_threads)
        .enable_all()
        .build()?;

    rt.block_on(mpc_node::cli::run(Cli::parse()))
}
