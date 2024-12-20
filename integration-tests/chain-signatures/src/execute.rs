use std::io;

use anyhow::Context as _;
use async_process::Child;

pub(crate) const PACKAGE_NODE: &str = "mpc-node";

pub fn node_executable(release: bool) -> io::Result<std::path::PathBuf> {
    forge::executable(release, PACKAGE_NODE)
}

pub fn spawn_node(release: bool, node: &str, cli: mpc_node::cli::Cli) -> anyhow::Result<Child> {
    let executable = node_executable(release)
        .with_context(|| format!("could not find target dir while starting {node} node"))?;

    async_process::Command::new(&executable)
        .args(cli.into_str_args())
        .env("RUST_LOG", "mpc_node=INFO")
        .envs(std::env::vars())
        .stdout(async_process::Stdio::inherit())
        .stderr(async_process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to run {node} node: {}", executable.display()))
}
