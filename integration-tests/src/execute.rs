use anyhow::Context;
use async_process::Child;
use mpc_primitives::Chain;
use std::path::PathBuf;

pub(crate) const PACKAGE_MULTICHAIN: &str = "mpc-node";
const ARTIFACTS_DIR: &str = "artifacts";
const ARTIFACT_PREFIX: &str = "mpc-node.";

/// Finds the binary with the highest semantic version in the given directory.
/// Expects binaries to be named like "mpc-node.1.10.1"
pub fn find_highest_semver_binary(dir: &str) -> anyhow::Result<PathBuf> {
    let artifacts_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("could not find parent dir"))?
        .join(ARTIFACTS_DIR)
        .join(dir);

    if !artifacts_dir.exists() {
        anyhow::bail!(
            "artifacts directory does not exist: {}",
            artifacts_dir.display()
        );
    }

    let mut highest_version: Option<(semver::Version, PathBuf)> = None;

    for entry in std::fs::read_dir(&artifacts_dir)
        .with_context(|| format!("failed to read directory: {}", artifacts_dir.display()))?
    {
        let entry = entry?;
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        // Check if it starts with ARTIFACT_PREFIX and extract version
        if let Some(version_str) = file_name_str.strip_prefix(ARTIFACT_PREFIX) {
            if let Ok(version) = semver::Version::parse(version_str) {
                let path = entry.path();
                match &highest_version {
                    None => highest_version = Some((version, path)),
                    Some((current_highest, _)) => {
                        if version > *current_highest {
                            highest_version = Some((version, path));
                        }
                    }
                }
            }
        }
    }

    highest_version.map(|(_, path)| path).ok_or_else(|| {
        anyhow::anyhow!(
            "no valid mpc-node binary found in {}",
            artifacts_dir.display()
        )
    })
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
