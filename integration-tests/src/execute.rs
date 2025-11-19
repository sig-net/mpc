use anyhow::Context;
use async_process::Child;
use mpc_primitives::Chain;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

pub(crate) const PACKAGE_MULTICHAIN: &str = "mpc-node";
const COMPAT_SUBDIR: &str = "compat";
const COMPAT_VERSIONS_JSON: &str = include_str!("../../scripts/prod-compat-versions.json");

static COMPAT_VERSIONS: OnceLock<HashMap<String, String>> = OnceLock::new();

fn compatibility_versions() -> &'static HashMap<String, String> {
    COMPAT_VERSIONS.get_or_init(|| {
        serde_json::from_str(COMPAT_VERSIONS_JSON)
            .expect("invalid prod-compat-versions.json format")
    })
}

fn compatibility_version(channel: &str) -> anyhow::Result<String> {
    compatibility_versions()
        .get(channel)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("unknown compatibility channel '{channel}'"))
}

/// Returns the compiled binary for the requested production channel (mainnet/testnet).
/// Binaries are expected under target/compat/<channel>/<version>/release/mpc-node.
pub fn compatibility_binary(channel: &str) -> anyhow::Result<PathBuf> {
    let version = compatibility_version(channel)?;
    let target_dir = target_dir().ok_or_else(|| {
        anyhow::anyhow!("could not locate target directory for compatibility binary")
    })?;

    let binary_path = target_dir
        .join(COMPAT_SUBDIR)
        .join(channel)
        .join(&version)
        .join("release")
        .join(PACKAGE_MULTICHAIN);

    if !binary_path.exists() {
        anyhow::bail!(
            "compatibility binary for {channel} ({version}) not found at {}. Run scripts/build-compat-binaries.sh to build it.",
            binary_path.display()
        );
    }

    Ok(binary_path)
}

pub fn target_dir() -> Option<std::path::PathBuf> {
    // CARGO_TARGET_DIR can be set explicitly.
    // https://doc.rust-lang.org/cargo/reference/environment-variables.html
    if let Ok(out_dir) = std::env::var("CARGO_TARGET_DIR") {
        return Some(out_dir.into());
    };

    // If CARGO_TARGET_DIR is not set, search for the default the target
    // directory in the parents of the build artifact output directory.
    let mut out_dir = std::path::Path::new(std::env!("OUT_DIR"));
    loop {
        if out_dir.ends_with("target") {
            break Some(out_dir.to_path_buf());
        }

        match out_dir.parent() {
            Some(parent) => out_dir = parent,
            None => break None, // We've reached the root directory and didn't find "target"
        }
    }
}

pub fn executable(release: bool, executable: &str) -> Option<std::path::PathBuf> {
    let executable = target_dir()?
        .join(if release { "release" } else { "debug" })
        .join(executable);
    Some(executable)
}

pub fn spawn_node(release: bool, node: &str, cli: mpc_node::cli::Cli) -> anyhow::Result<Child> {
    spawn_node_with_binary(None, release, node, cli)
}

pub fn spawn_node_with_binary(
    binary_path: Option<PathBuf>,
    release: bool,
    node: &str,
    cli: mpc_node::cli::Cli,
) -> anyhow::Result<Child> {
    let executable = match binary_path {
        Some(path) => path,
        None => executable(release, PACKAGE_MULTICHAIN)
            .with_context(|| format!("could not find target dir while starting {node} node"))?,
    };

    async_process::Command::new(&executable)
        .args(cli.into_str_args())
        .env("RUST_LOG", "info,workspaces=warn")
        .envs(Chain::checkpoint_env_vars())
        .envs(std::env::vars())
        .stdout(async_process::Stdio::inherit())
        .stderr(async_process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to run {node} node: {}", executable.display()))
}
