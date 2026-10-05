#![doc = include_str!("../README.md")]

pub mod abi;
#[cfg(feature = "bench")]
pub mod bench;
mod client;
mod config;
mod event_parsing;
mod execution_watcher;
mod finalized_head;
mod indexer;
pub mod publisher;
mod respond_bidirectional;
mod rpc;
#[cfg(test)]
mod test_utils;
pub mod utils;

pub use client::{CatchupItem, MaybeBlock};
pub use config::{EthConfig, GasConfig, IndexerConfig, PublisherConfig, RpcConfig};
pub use event_parsing::generate_request_id;
pub use indexer::EthereumIndexer;
