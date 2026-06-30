use crate::metrics::requests::{record_request_latency_since, SignRequestStep};
use mpc_chain_integration_core::{PublishAction, PublisherTelemetry};

/// Standard node implementation of publisher telemetry using Prometheus metrics
#[derive(Clone)]
pub struct NodePublisherTelemetry;

impl PublisherTelemetry for NodePublisherTelemetry {
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
