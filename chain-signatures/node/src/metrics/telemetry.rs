use mpc_chain_integration_core::{
    ChainTelemetry, ExtractionFailureKind, PublishAction, PublisherTelemetry,
};
use mpc_primitives::{Chain, ChainConfig as _, RequestKind};
use mpc_utils::time::unix_elapsed;

use super::{
    indexers::{BIDIRECTIONAL_EXTRACTION_FAILURES, LATEST_BLOCK_NUMBER},
    publishers::{FUNDING_WALLET_BALANCE, PUBLISH_REFUSALS},
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
        let chain = action.request.chain;
        let kind = action.request.request_kind();
        let elapsed_secs = unix_elapsed(action.request.unix_timestamp_indexed).as_secs();

        if elapsed_secs <= chain.expected_response_time_secs() {
            record_request_latency_since(
                chain,
                SignRequestStep::Total,
                "in_time",
                kind,
                action.request.unix_timestamp_indexed,
            );
        } else {
            record_request_latency_since(
                chain,
                SignRequestStep::Total,
                "expired",
                kind,
                action.request.unix_timestamp_indexed,
            );
        }
        record_request_latency_since(
            chain,
            SignRequestStep::Responding,
            "ok",
            kind,
            action.timestamp,
        );
    }

    fn funding_wallet_observed(&self, balance: f64) {
        FUNDING_WALLET_BALANCE
            .with_label_values(&[self.chain.as_str()])
            .set(balance);
    }

    fn publish_refused(&self, code: &str) {
        PUBLISH_REFUSALS
            .with_label_values(&[self.chain.as_str(), code])
            .inc();
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

    fn request_indexed_at(&self, block_timestamp: u64, kind: RequestKind) {
        record_request_latency_since(
            self.chain,
            SignRequestStep::Indexing,
            "ok",
            kind,
            block_timestamp,
        );
    }

    fn request_indexed(&self, kind: RequestKind) {
        record_indexing_step_reached(self.chain, kind);
    }

    fn bidirectional_extraction_failed(&self, kind: ExtractionFailureKind) {
        BIDIRECTIONAL_EXTRACTION_FAILURES
            .with_label_values(&[self.chain.as_str(), kind.as_str()])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funding_wallet_balance_and_publish_refusals_are_labelled_by_chain() {
        let telemetry = NodeTelemetry::new(Chain::Midnight);
        let chain = Chain::Midnight.as_str();

        telemetry.funding_wallet_observed(4.21);
        telemetry.publish_refused("wallet_unfunded");
        telemetry.publish_refused("wallet_unfunded");

        assert_eq!(
            FUNDING_WALLET_BALANCE.with_label_values(&[chain]).get(),
            4.21
        );
        assert_eq!(
            PUBLISH_REFUSALS
                .with_label_values(&[chain, "wallet_unfunded"])
                .get(),
            2.0
        );
    }
}
