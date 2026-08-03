//! Node-internal primitives. Public interface types (used by contracts and
//! clients) live in `signet-primitives` and are re-exported here so node code
//! can keep a single import path.

/// Protocol 85 (nearcore 2.13.x) is required for contracts compiled with
/// near-sdk 5.29+ which use host functions like `chain_id` and `p256_verify`.
pub const SANDBOX_VERSION: &str = "2.13.1";

mod backlog;
mod bidirectional;
mod chain;
mod crypto;
mod events;
mod requests;

pub use signet_primitives::*;

pub use backlog::{Checkpoint, CheckpointDigest, ConsensusCheckpointDigest, PendingTx};
pub use bidirectional::{
    BidirectionalTx, RespondBidirectionalEvent, RespondBidirectionalTx, SignBidirectionalEvent,
};
pub use chain::{ChainConfig, SerDeserFormat};
pub use crypto::{cbor_scalar, SignArgs};
pub use events::{ChainEvent, ExecutionOutcome, SignatureRespondedEvent};
pub use requests::{IndexedSignRequest, SignCommand, SignKind};
