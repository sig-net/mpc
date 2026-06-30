//! This crate provides the core traits and types for implementing chain indexers and streams for different blockchains.

mod indexer;
mod publish;
mod state;
mod telemetry;
pub mod utils;

pub use indexer::{ChainIndexer, ChainStream};
pub use publish::{ChainPublisher, PublishAction};
pub use state::StateManager;
pub use telemetry::{
    ChainTelemetry, NoopChainTelemetry, NoopPublisherTelemetry, PublisherTelemetry,
};

// Re-export backon because `retry_rpc!` uses `Retryable` trait internally
#[doc(hidden)]
pub use ::backon;
