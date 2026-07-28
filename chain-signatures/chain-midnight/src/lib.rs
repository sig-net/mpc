//! Midnight chain integration for the MPC node.

mod config;
mod convert;
mod indexer;
mod intent_gen;
mod publisher;
mod reader;
pub mod records;
mod request_id;
mod rpc;
mod state;
#[cfg(test)]
mod test_utils;
mod tx;
mod tx_decode;

pub use config::{IndexerConfig, MidnightConfig, PublisherConfig, RpcConfig};
pub use convert::{to_sign_request, MidnightChainCtx};
pub use indexer::MidnightIndexer;
pub use intent_gen::{IntentGen, IntentRequest, WirePoint, WireSignature};
pub use publisher::MidnightPublisher;
pub use rpc::MidnightRpc;
pub use state::decode_contract_state;
pub use tx_decode::{ClaimedCall, DecodedCall, DecodedTransaction, DecodedTransactions};
