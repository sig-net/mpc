/// Version of the protocol (triples, presignatures, signatures) messages
/// that the node can currently work with.
pub const PROTOCOL_VERSION: u64 = 1;
/// Version of the checkpoint data that the node can work with.
pub const CHECKPOINT_VERSION: u64 = 0;
/// Redis namespace version for persisted checkpoints.
pub(crate) const CHECKPOINT_STORAGE_VERSION: &str = "v13";

pub mod backlog;
pub mod cli;
pub mod config;
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
