use mpc_chain_integration_core::{ChainTelemetry, PublishAction, PublisherTelemetry};
use mpc_primitives::Chain;

use super::{
    indexers::LATEST_BLOCK_NUMBER,
    requests::{record_indexing_step_reached, record_request_latency_since, SignRequestStep},
};

/// NodeTelemetry is a struct that implements the PublisherTelemetry and ChainTelemetry traits for recording telemetry data related to publishing signatures and indexing blocks on a blockchain.
#[derive(Clone)]
pub struct NodeTelemetry {
    chain: Chain,
}

impl NodeTelemetry {
    pub fn new(chain: Chain) -> Self {
        Self { chain }
    }
}

impl PublisherTelemetry for NodeTelemetry {
    fn record_publish_metrics(&self, action: &PublishAction) {
        let chain = action.indexed.chain;
        let elapsed_secs =
            crate::util::unix_elapsed(action.indexed.unix_timestamp_indexed).as_secs();

        if elapsed_secs <= chain.expected_response_time_secs() {
            record_request_latency_since(
                chain,
                SignRequestStep::Total,
                "in_time",
                action.indexed.unix_timestamp_indexed,
            );
        } else {
            record_request_latency_since(
                chain,
                SignRequestStep::Total,
                "expired",
                action.indexed.unix_timestamp_indexed,
            );
        }
        record_request_latency_since(chain, SignRequestStep::Responding, "ok", action.timestamp);
    }
}

impl ChainTelemetry for NodeTelemetry {
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
