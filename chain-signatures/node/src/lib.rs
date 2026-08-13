/// Version of the protocol (triples, presignatures, signatures) messages
/// that the node can currently work with.
pub const PROTOCOL_VERSION: u64 = 1;
/// Version of the checkpoint data that the node can work with.
pub const CHECKPOINT_VERSION: u64 = 0;
/// Redis namespace version for persisted checkpoints.
pub(crate) const CHECKPOINT_STORAGE_VERSION: &str = "v13";
/// Default maximum size of a `/checkpoint` response payload that a node
/// will fetch from a peer.
///
/// A checkpoint carries the full backlog entry for every pending request
/// (including serialized transactions), so a large backlog produces a
/// multi-megabyte payload. Servers stream checkpoints regardless of size;
/// this bound protects the fetching node from a peer sending an unbounded
/// body, so it must stay generous enough to accept legitimate checkpoints.
const CHECKPOINT_MAX_PAYLOAD_SIZE_DEFAULT: usize = 1024 * 1024 * 1024;

/// Maximum size of a `/checkpoint` response payload a node will fetch, in bytes.
///
/// Overridable via the `CHECKPOINT_MAX_PAYLOAD_SIZE` environment variable.
pub fn checkpoint_max_payload_size() -> usize {
    std::env::var("CHECKPOINT_MAX_PAYLOAD_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(CHECKPOINT_MAX_PAYLOAD_SIZE_DEFAULT)
}

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
