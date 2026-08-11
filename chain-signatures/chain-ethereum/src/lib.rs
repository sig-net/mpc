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
mod indexer_eth_direct_rpc;
#[cfg(feature = "helios")]
pub mod indexer_eth_helios;
pub mod publisher;
mod respond_bidirectional;
#[cfg(test)]
mod test_utils;

pub use client::{CatchupItem, MaybeBlock};
pub use config::{EthConfig, GasConfig, IndexerConfig, PublisherConfig, RpcConfig};
pub use event_parsing::generate_request_id;
pub use indexer::EthereumIndexer;
