//! Midnight chain integration for the MPC node.

mod config;
mod convert;
mod indexer;
mod publisher;
mod reader;
pub mod records;
mod request_id;
mod rpc;
mod sidecar;
mod state;
#[cfg(test)]
mod test_utils;
mod tx;

pub use config::{IndexerConfig, MidnightConfig, RpcConfig, SidecarConfig};
pub use convert::{to_sign_request, MidnightChainCtx};
pub use indexer::MidnightIndexer;
pub use publisher::MidnightPublisher;
pub use sidecar::{
    ClaimedCall, DecodedCall, DecodedTransaction, DecodedTransactions, Health, LedgerTags,
    SidecarClient,
};
pub use state::decode_contract_state;
