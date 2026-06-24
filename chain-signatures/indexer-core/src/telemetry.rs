/// Interface for the Indexer to report telemetry data.
pub trait ChainTelemetry: Send + Sync + Clone + 'static {
    /// Records that a block was parsed at the live tip
    fn block_indexed(&self, block_number: u64);

    /// Records that a block has reached finality/consensus
    fn block_finalized(&self, block_number: u64);

    /// Records that a checkpoint was created
    fn checkpoint_created(&self, block_number: u64);
}

/// No-op implementation for tests
#[derive(Clone, Default)]
pub struct NoopChainTelemetry;

impl ChainTelemetry for NoopChainTelemetry {
    fn block_indexed(&self, _block_number: u64) {}
    fn block_finalized(&self, _block_number: u64) {}
    fn checkpoint_created(&self, _block_number: u64) {}
}
