//! Midnight chain integration for the MPC node.

mod config;
mod indexer;
mod publisher;
mod reader;
pub mod records;
mod request_id;
mod rpc;
mod sidecar;
#[cfg(test)]
mod test_fixtures;

pub use config::{IndexerConfig, MidnightConfig, RpcConfig, SidecarConfig};
pub use indexer::{select_catchup_mode, MidnightIndexer};
pub use publisher::MidnightPublisher;
pub use reader::{
    decode_notification, decode_record, signet_field_node, unpack_notification_v1, NotificationV1,
    REQUEST_FIXED_VALUE_ATOMS,
};
pub use records::{
    CompactMaybe, EvmType2TxParams, RespondBidirectionalEvent, SignBidirectionalEventNotification,
    SignBidirectionalRecord, SignatureRespondedEvent, SignetMapKey,
};
pub use request_id::compute_request_id;
pub use rpc::{ArchiveState, FinalizedBlock, MidnightRpc};
pub use sidecar::{
    ClaimedCall, DecodedCall, DecodedTransaction, DecodedTransactions, Health, LedgerTags,
    MapEntry, RespondReceipt, RespondRequest, SidecarClient, StateNode, WirePoint, WireSignature,
};
