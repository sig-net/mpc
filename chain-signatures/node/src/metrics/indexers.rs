use mpc_indexer_core::ChainTelemetry;
use mpc_primitives::Chain;
use prometheus::IntGaugeVec;
use std::sync::LazyLock;

use super::{
    requests::{record_indexing_step_reached, record_request_latency_since, SignRequestStep},
    try_create_int_gauge_vec_with_node_account_id,
};

/// Possible status options:
///     - "indexed" - latest block number seen by the indexer
///     - "finalized" - latest block number seen as finalized by the indexer
///     - "checkpoint" - latest block number for which a checkpoint was created
static LATEST_BLOCK_NUMBER: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_latest_block_number",
        "Latest block number seen by the node",
        &["chain", "status"],
    )
    .unwrap()
});

#[derive(Clone)]
pub struct PrometheusChainTelemetry {
    chain: Chain,
}

impl PrometheusChainTelemetry {
    pub fn new(chain: Chain) -> Self {
        Self { chain }
    }
}

impl ChainTelemetry for PrometheusChainTelemetry {
    fn block_indexed(&self, block_number: u64) {
        LATEST_BLOCK_NUMBER
            .with_label_values(&[self.chain.as_str(), "indexed"])
            .set(block_number as i64);
    }

    fn block_finalized(&self, block_number: u64) {
        LATEST_BLOCK_NUMBER
            .with_label_values(&[self.chain.as_str(), "finalized"])
            .set(block_number as i64);
    }

    fn checkpoint_created(&self, block_number: u64) {
        LATEST_BLOCK_NUMBER
            .with_label_values(&[self.chain.as_str(), "checkpoint"])
            .set(block_number as i64);
    }

    fn request_indexed_at(&self, block_timestamp: u64) {
        record_request_latency_since(self.chain, SignRequestStep::Indexing, "ok", block_timestamp);
    }

    fn request_indexed(&self) {
        record_indexing_step_reached(self.chain);
    }
}
