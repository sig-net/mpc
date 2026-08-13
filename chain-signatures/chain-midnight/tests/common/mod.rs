//! Shared setup for the ignored end-to-end tests.

use std::path::{Path, PathBuf};

use mpc_chain_midnight::PublisherConfig;

fn publisher_package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../midnight-publisher-ts")
}

fn path_arg(path: &Path) -> String {
    path.to_str()
        .unwrap_or_else(|| panic!("{} is not valid UTF-8", path.display()))
        .to_string()
}

/// The builder as the node runs it in production. Checked here because a missing entry
/// point exits `node` at boot, reading like a protocol fault instead of an unbuilt package.
pub fn base_live_config() -> PublisherConfig {
    let package = publisher_package();
    let entry = package.join("dist/main.js");
    assert!(
        entry.is_file(),
        "{} is missing: run `npm ci && npm run build` in {}",
        entry.display(),
        package.display()
    );
    PublisherConfig {
        intent_gen_command: vec!["node".to_string(), path_arg(&entry)],
        funding_seed: "ab".repeat(32),
        node_ws_url: "ws://127.0.0.1:9944".to_string(),
        proof_server_url: "http://127.0.0.1:6300".to_string(),
        indexer_url: "http://127.0.0.1:8088/api/v3/graphql".to_string(),
        indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".to_string(),
        ..Default::default()
    }
}
