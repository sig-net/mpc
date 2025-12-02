pub mod builder;
pub mod config;
pub mod node;

pub use builder::MpcEnvBuilder;
pub use config::MpcEnvConfig;
pub use node::{MpcEnvNode, InProcessNode, ExternalNode};

use crate::deadman_switch::DeadmanSwitch;

/// Runtime environment for tests. This is a small, forward-compatible
/// abstraction that will be expanded in later phases. For now this is a
/// placeholder container that will be populated by the builder.
pub struct MpcEnv {
    pub config: MpcEnvConfig,

    /// If the environment uses in-process nodes (MpcFixture), it will be present
    pub fixture: Option<crate::mpc_fixture::MpcFixture>,

    /// If the environment was built as a full cluster using real nodes, the
    /// cluster will be stored here and can be converted with `into_cluster`.
    pub cluster: Option<crate::cluster::Cluster>,

    /// Deadman switch for automatic cleanup of orphaned processes.
    /// Active unless `MPC_KEEP_ENV=1` is set.
    deadman_switch: Option<DeadmanSwitch>,
}

impl MpcEnv {
    /// Convert the environment into a full cluster (later phases). For now
    /// this is a placeholder and will panic if used.
    pub fn into_cluster(self) -> crate::cluster::Cluster {
        self.cluster
            .expect("MpcEnv was not built with a real cluster; enable_real_nodes = true")
    }

    /// Consume the environment and return the in-process MpcFixture if it
    /// exists. This makes migration of tests easier: they can build an
    /// MpcEnv and convert it back into the old fixture type until tests are
    /// migrated fully to the new API.
    pub fn into_fixture(self) -> crate::mpc_fixture::MpcFixture {
        self.fixture
            .expect("MpcEnv was not built as in-process fixture; enable_real_nodes = false")
    }

    /// Convenience wrapper for in-process fixtures: wait for triples.
    pub async fn wait_for_triples(&self, threshold_per_node: usize) {
        if let Some(f) = &self.fixture {
            f.wait_for_triples(threshold_per_node).await;
        } else {
            panic!("wait_for_triples only available for in-process fixtures");
        }
    }

    /// Convenience wrapper for in-process fixtures: wait for presignatures.
    pub async fn wait_for_presignatures(&self, threshold_per_node: usize) {
        if let Some(f) = &self.fixture {
            f.wait_for_presignatures(threshold_per_node).await;
        } else {
            panic!("wait_for_presignatures only available for in-process fixtures");
        }
    }

    /// Convenience wrapper for in-process fixtures: wait for RPC actions
    pub async fn wait_for_actions(&self, threshold: usize) -> std::collections::HashSet<String> {
        if let Some(f) = &self.fixture {
            f.wait_for_actions(threshold).await
        } else {
            panic!("wait_for_actions only available for in-process fixtures");
        }
    }

    /// Register process IDs with the deadman switch for monitoring.
    pub async fn watch_pids(&self, pids: &[u32]) -> anyhow::Result<()> {
        if let Some(ref switch) = self.deadman_switch {
            switch.watch_pids(pids).await?;
        }
        Ok(())
    }

    /// Register container IDs with the deadman switch for monitoring.
    pub async fn watch_containers(&self, containers: &[String]) -> anyhow::Result<()> {
        if let Some(ref switch) = self.deadman_switch {
            switch.watch_containers(containers).await?;
        }
        Ok(())
    }

    /// Check if the deadman switch is active.
    pub fn has_deadman_switch(&self) -> bool {
        self.deadman_switch.as_ref().map(|s| s.is_active()).unwrap_or(false)
    }
}
