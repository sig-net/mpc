#![doc = include_str!("../README.md")]

pub mod abi;
#[cfg(feature = "bench")]
pub mod bench;
mod client;
mod config;
mod event_parsing;
mod indexer;
mod indexer_eth_direct_rpc;
#[cfg(feature = "helios")]
pub mod indexer_eth_helios;
pub mod publisher;
mod respond_bidirectional;
#[cfg(test)]
mod test_utils;
mod util;

pub use client::MaybeBlock;
pub use config::{EthConfig, GasConfig, IndexerConfig, PublisherConfig, RpcConfig};
pub use indexer::EthereumStream;
