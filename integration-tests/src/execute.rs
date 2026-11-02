use anyhow::Context;
use async_process::Child;
use std::path::PathBuf;

pub(crate) const PACKAGE_MULTICHAIN: &str = "mpc-node";

/// Returns the mpc-node binary of the latest release tag, built by
/// `just build compat` under target/compat/latest/release/mpc-node.
pub fn latest_release_binary() -> anyhow::Result<PathBuf> {
    let target_dir = target_dir().ok_or_else(|| {
        anyhow::anyhow!("could not locate target directory for compatibility binary")
    })?;

    let binary_path = target_dir
        .join("compat")
        .join("latest")
        .join("release")
        .join(PACKAGE_MULTICHAIN);

    if !binary_path.exists() {
        anyhow::bail!(
            "latest release binary not found at {}. Run `just build compat` to build it.",
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

pub fn spawn_node_with_binary(
    binary_path: Option<PathBuf>,
    release: bool,
    node: &str,
    args: Vec<String>,
) -> anyhow::Result<Child> {
    let executable = match binary_path {
        Some(path) => path,
        None => executable(release, PACKAGE_MULTICHAIN)
            .with_context(|| format!("could not find target dir while starting {node} node"))?,
    };

    async_process::Command::new(&executable)
        .args(args)
        .env("RUST_LOG", "info,workspaces=warn")
        .envs(std::env::vars())
        .stdout(async_process::Stdio::inherit())
        .stderr(async_process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to run {node} node: {}", executable.display()))
}
