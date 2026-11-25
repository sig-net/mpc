//! MPC Node Binary Entrypoint.
//!
//! See [`mpc_node::alloc`] for global allocator details and container configuration.

#[cfg(all(
    feature = "jemalloc",
    not(target_env = "msvc"),
    not(target_arch = "wasm32")
))]
#[global_allocator]
static GLOBAL: mpc_node::alloc::Jemalloc = mpc_node::alloc::Jemalloc;

use mpc_node::cli::Cli;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse_redacted();
    mpc_node::alloc::verify_configuration()?;

    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // Ensure at least 4 worker threads if CPU cores < 4
    let worker_threads = std::cmp::max(num_cpus, 4);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    let result = rt.block_on(mpc_node::cli::run(cli));
    // Dropping the runtime would wait for blocking tasks such as the system
    // metrics loop, which never ends. Detach them so the process can exit.
    rt.shutdown_background();
    result
}
