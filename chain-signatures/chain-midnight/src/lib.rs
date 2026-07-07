//! Midnight chain integration (workspace-member half).
//!
//! Light-dependency crate: the indexer (contractEvents GraphQL subscription over
//! tokio-tungstenite) and the `ChainPublisher` client, which forwards respond
//! requests over HTTP to the isolated `midnight-publisher` service (that service owns
//! the heavy `midnight-node-toolkit` dependency universe — see the pins doc).
//!
//! Wire format: `doc/signet-midnight-events.md` (SGN1), pinned by the golden
//! vectors in `tests/goldens/` (generated in the midnight-erc20-vault repo).

mod client;
mod config;
pub(crate) mod convert;
pub(crate) mod finality;
pub mod graphql;
mod indexer;
pub(crate) mod reassembly;
pub mod requests;
pub mod wire;

#[cfg(test)]
pub(crate) mod test_goldens;

pub use client::{MidnightClient, MidnightRespondRequest};
pub use config::MidnightConfig;
pub use graphql::{MidnightGraphql, RawContractEvent};
pub use indexer::MidnightStream;
