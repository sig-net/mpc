//! Midnight chain integration for the MPC node.
//!
//! Discovery joins status events attached to `Phase::ApplyExtrinsic`. A root-scheduled
//! `Midnight::send_mn_transaction` dispatched in `Phase::Initialization` is outside
//! this scanner's discovery surface.

#![cfg_attr(test, allow(clippy::disallowed_methods))]

mod attestation;
#[cfg(test)]
mod chain_mock;
mod config;
mod convert;
mod dust_feed;
pub mod emissions;
mod funding;
mod hashing;
mod indexer;
mod intent;
mod landing_watch;
mod native;
mod output_storage;
mod publisher;
mod reader;
pub mod records;
mod rpc;
mod source;
mod state;
mod submit_error;
#[cfg(test)]
mod test_utils;
mod tx;
pub(crate) mod types;

pub use attestation::validate_attestation_response;
pub use config::{IndexerConfig, MidnightConfig, OutputStorageConfig, PublisherConfig, RpcConfig};
pub use funding::DustCheckpointStore;
pub use indexer::MidnightIndexer;
pub use publisher::{RecoveringMidnightPublisher, ResponseAwaiter};
#[cfg(feature = "sandbox")]
pub use rpc::reads::probe_network_id;
pub use types::{MidnightAddress, NetworkId, UnsupportedNetwork};
