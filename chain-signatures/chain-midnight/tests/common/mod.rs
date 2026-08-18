//! Shared setup for the ignored end-to-end tests.

use std::path::{Path, PathBuf};

use mpc_chain_midnight::{MidnightConfig, PublisherConfig};

fn publisher_package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../midnight-publisher-ts")
}

fn path_arg(path: &Path) -> String {
    path.to_str()
        .unwrap_or_else(|| panic!("{} is not valid UTF-8", path.display()))
        .to_string()
}

fn node_executable() -> String {
    let output = std::process::Command::new("node")
        .args(["--print", "process.execPath"])
        .output()
        .expect("node must be installed to run the ignored TypeScript seam tests");
    assert!(
        output.status.success(),
        "resolving the Node executable failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = String::from_utf8(output.stdout).expect("Node's executable path must be UTF-8");
    let path = path.trim();
    assert!(
        Path::new(path).is_absolute(),
        "Node returned a non-absolute executable path: {path}"
    );
    path.to_string()
}

/// The compiled builder used by the ignored seam tests. A missing entry point exits
/// `node` at boot, reading like a protocol fault instead of an unbuilt package.
pub fn base_live_config() -> MidnightConfig {
    let package = publisher_package();
    let entry = package.join("dist/main.js");
    assert!(
        entry.is_file(),
        "{} is missing: run `npm ci && npm run build` in {}",
        entry.display(),
        package.display()
    );
    MidnightConfig {
        node_ws_url: "ws://127.0.0.1:9944".to_string(),
        central_address: "ab".repeat(32),
        publisher: PublisherConfig {
            intent_gen_command: vec![node_executable(), path_arg(&entry)],
            funding_seed: "ab".repeat(32),
            proof_server_url: "http://127.0.0.1:6300".to_string(),
            indexer_url: "http://127.0.0.1:8088/api/v3/graphql".to_string(),
            indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".to_string(),
            ..Default::default()
        },
        rpc: Default::default(),
        indexer: Default::default(),
    }
}
