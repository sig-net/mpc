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

    /// Reports whether this chain's catchup is running DEGRADED (state
    /// unavailable at historical blocks, e.g. a pruned Midnight node forcing
    /// watermark catchup) as state rather than as a log event, so an
    /// operator sees it on a dashboard instead of in a log search. Called
    /// with `false` when a supervised run starts healthy, `true` when it
    /// degrades. Default no-op so existing implementations are unaffected.
    ///
    /// Deliberately NOT the precedent for per-reason drop counters: one
    /// boolean per run is a gauge with no design surface, while a family of
    /// labeled counters needs a label taxonomy and cardinality decision that
    /// belongs to the telemetry follow-up, not to a chain task.
    fn catchup_degraded(&self, _degraded: bool) {}
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
