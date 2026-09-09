#![doc = include_str!("../README.md")]

#[cfg(feature = "bench")]
pub mod bench;
mod client;
mod config;
mod events;
mod indexer;
#[cfg(test)]
mod test_utils;
mod utils;

pub use anchor_lang::prelude::Pubkey;
pub use client::{SolanaCatchupBlock, SolanaClient};
pub use config::{SolConfig, SolIndexerConfig};
pub use indexer::SolanaIndexer;
