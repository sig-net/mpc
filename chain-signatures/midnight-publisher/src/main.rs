//! Isolated Midnight respond publisher.
//!
//! Quarantines the `midnight-node-toolkit` dependency universe from the main
//! mpc workspace. `mpc-chain-midnight`'s `MidnightClient` POSTs respond
//! requests here; this service drives the toolkit CLI (contract-state →
//! generate-intent → send-intent) exactly like the Phase-3 driver scripts.

mod service;
mod state;

fn main() -> anyhow::Result<()> {
    let cfg = service::Config::from_env()?;
    service::serve(cfg)
}

#[cfg(test)]
mod smoke {
    /// Keeps the toolkit git-dep exercised so `cargo build -p
    /// midnight-node-toolkit` remains valid from this lockfile.
    #[test]
    fn toolkit_links() {
        let _ = midnight_node_toolkit::hash_to_str(Default::default());
    }
}
