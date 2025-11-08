use clap::Parser;
use mpc_node::cli::Cli;
use tokio::signal;

fn main() -> anyhow::Result<()> {
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    // Ensure at least 4 worker threads if CPU cores < 4
    let worker_threads = std::cmp::max(num_cpus, 4);

    // Parse CLI early to get account ID for timing reports
    let cli = Cli::parse();
    let account_id = extract_account_id(&cli);

    // Set account ID for timing reports
    if let Some(ref id) = account_id {
        mpc_node::timings::set_account_id(id.clone());
    }

    // Set up panic hook to print timing report on panic
    let default_panic = std::panic::take_hook();
    let account_id_clone = account_id.clone();
    std::panic::set_hook(Box::new(move |panic_info| {
        eprintln!("\nPanic occurred, printing timing report...");
        if let Some(ref id) = account_id_clone {
            mpc_node::timings::print_timing_report_now_with_account_id(Some(id));
        } else {
            mpc_node::timings::print_timing_report_now();
        }
        default_panic(panic_info);
    }));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()?;

    // Spawn a task to handle shutdown signals
    let account_id_clone2 = account_id.clone();
    rt.spawn(async move {
        // Handle both SIGINT (Ctrl+C) and SIGTERM
        tokio::select! {
            _ = signal::ctrl_c() => {
                eprintln!("\nReceived SIGINT, printing timing report...");
            },
            _ = async {
                loop {
                    match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                        Ok(mut stream) => {
                            stream.recv().await;
                            break;
                        }
                        Err(_) => tokio::time::sleep(tokio::time::Duration::from_secs(1)).await,
                    }
                }
            } => {
                eprintln!("\nReceived SIGTERM, printing timing report...");
            }
        }
        if let Some(ref id) = account_id_clone2 {
            mpc_node::timings::print_timing_report_now_with_account_id(Some(id));
        } else {
            mpc_node::timings::print_timing_report_now();
        }
        std::process::exit(0);
    });

    rt.block_on(mpc_node::cli::run(cli))?;
    if let Some(ref id) = account_id {
        mpc_node::timings::print_timing_report_with_account_id(Some(id));
    } else {
        mpc_node::timings::print_timing_report();
    }
    Ok(())
}

fn extract_account_id(cli: &Cli) -> Option<String> {
    match cli {
        Cli::Start { account_id, .. } => Some(account_id.to_string()),
    }
}
