/// Version of the protocol (triples, presignatures, signatures) messages
/// that the node can currently work with.
///
/// Bump this whenever the peer wire format changes. The mesh marks any peer
/// reporting a different version as `Offline`, which is what keeps a mixed
/// version deployment from half-working: without a bump, a node speaking the new
/// `/sync` envelope to an old node would just fail to decode on every round, and
/// the peer would sit in `need_sync` (and out of `active`) indefinitely with only
/// a decode warning to show for it.
///
/// - 2: `/sync` carries a signed, sealed envelope instead of a bare `SyncUpdate`.
pub const PROTOCOL_VERSION: u64 = 2;
/// Version of the checkpoint data that the node can work with.
pub const CHECKPOINT_VERSION: u64 = 0;
/// Redis namespace version for persisted checkpoints.
pub(crate) const CHECKPOINT_STORAGE_VERSION: &str = "v13";

pub mod backlog;
pub mod cli;
pub mod config;
pub mod gcp;
pub mod indexer_hydration;
pub mod logs;
pub mod mesh;
pub mod metrics;
pub mod node_client;
pub mod protocol;
pub mod respond_bidirectional;
pub mod rpc;
pub mod sign_bidirectional;
pub mod storage;
pub mod stream;
pub mod types;
pub mod util;
pub mod web;
