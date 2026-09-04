//! Midnight chain integration for the MPC node.
//!
//! Discovery joins status events attached to `Phase::ApplyExtrinsic`. A root-scheduled
//! `Midnight::send_mn_transaction` dispatched in `Phase::Initialization` is outside
//! this scanner's discovery surface.

mod config;
mod convert;
pub mod emissions;
mod indexer;
mod intent_gen;
mod publisher;
mod reader;
pub mod records;
mod request_id;
mod rpc;
mod source;
mod state;
#[cfg(test)]
mod test_utils;
mod tx;

pub use config::{IndexerConfig, MidnightAddress, MidnightConfig, PublisherConfig, RpcConfig};
pub use indexer::MidnightIndexer;
pub use intent_gen::{IntentGen, IntentRequest, WirePoint, WireSignature};
pub use publisher::MidnightPublisher;
#[cfg(feature = "sandbox")]
pub use rpc::probe_network_id;
