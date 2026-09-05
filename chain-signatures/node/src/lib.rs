/// Version of the protocol (triples, presignatures, signatures) messages
/// that the node can currently work with.
pub const PROTOCOL_VERSION: u64 = 1;
/// Version of the checkpoint data that the node can work with.
pub const CHECKPOINT_VERSION: u64 = 0;
/// Redis namespace version for persisted checkpoints.
pub(crate) const CHECKPOINT_STORAGE_VERSION: &str = "v14";

/// Polyfill for `std::assert_matches`. Once contract and CI use Rust 1.96+,
/// this macro can be removed in favor of `std::assert_matches`.
#[macro_export]
macro_rules! assert_matches {
    ($expression:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {
        match $expression {
            $pattern $(if $guard)? => {}
            ref e => panic!(
                "assertion failed: `{:?}` does not match `{}`",
                e,
                stringify!($pattern $(if $guard)?)
            ),
        }
    };
    ($expression:expr, $pattern:pat $(if $guard:expr)?, $($arg:tt)+) => {
        match $expression {
            $pattern $(if $guard)? => {}
            ref e => panic!($($arg)+),
        }
    };
}

pub mod backlog;
pub mod cli;
pub mod config;
pub mod gcp;
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
