use super::PublishAction;

/// Interface for the Indexer to report telemetry data.
pub trait ChainTelemetry: Send + Sync + Clone + 'static {
    /// Records that a block was parsed at the live tip
    fn block_indexed(&self, block_number: u64);

    /// Records that a block has reached finality/consensus
    fn block_finalized(&self, block_number: u64);

    /// Records that a checkpoint was created
    fn checkpoint_created(&self, block_number: u64);

    /// Report that a request was indexed at the given block timestamp (currently used for Ethereum due to ~15 min finality delay)
    fn request_indexed_at(&self, block_timestamp: u64);

    /// Report that a request was indexed without a block timestamp (faster chains, e.g. for Solana, Canton, or Hydration)
    fn request_indexed(&self);
}

/// No-op implementation for tests
#[derive(Clone, Default)]
pub struct NoopChainTelemetry;

impl ChainTelemetry for NoopChainTelemetry {
    fn block_indexed(&self, _block_number: u64) {}
    fn block_finalized(&self, _block_number: u64) {}
    fn checkpoint_created(&self, _block_number: u64) {}
    fn request_indexed_at(&self, _block_timestamp: u64) {}
    fn request_indexed(&self) {}
}

/// Interface for the chain clients to record telemetry data during publishing signatures to the chain.
pub trait PublisherTelemetry: Send + Sync + 'static {
    /// Records metrics related to publishing a signature to the chain.
    fn record_publish_metrics(&self, action: &PublishAction);
}

/// No-op implementation for tests
#[derive(Clone, Default)]
pub struct NoopPublisherTelemetry;

impl PublisherTelemetry for NoopPublisherTelemetry {
    fn record_publish_metrics(&self, _action: &PublishAction) {}
}
