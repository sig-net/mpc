//! Midnight chain integration for the MPC node.

mod config;
mod indexer;
mod publisher;
pub mod records;
mod request_id;
mod rpc;
mod sidecar;

pub use config::{IndexerConfig, MidnightConfig, RpcConfig, SidecarConfig};
pub use indexer::MidnightIndexer;
pub use publisher::MidnightPublisher;
pub use records::{
    CompactMaybe, EvmType2TxParams, RespondBidirectionalEvent, SignBidirectionalEventNotification,
    SignBidirectionalRecord, SignatureRespondedEvent, SignetMapKey,
};
pub use request_id::compute_request_id;
pub use rpc::{FinalizedBlock, MidnightRpc};
pub use sidecar::{
    ClaimedCall, DecodedCall, DecodedTransaction, DecodedTransactions, Health, LedgerTags,
    MapEntry, RespondReceipt, RespondRequest, SidecarClient, StateNode, WirePoint, WireSignature,
};
