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
#[cfg(test)]
mod test_fixtures;
mod tx;

// Exactly what is consumed from outside this crate, and nothing else.
//
// Consumers are the node AND `tests/sidecar_live.rs`, which links the crate as
// an external user and therefore reads this list exactly as the node does.
// `records` is `pub mod` because the node builds records directly.
// `MidnightChainCtx` is exported because the node's stream layer Borsh-decodes
// the chain_ctx, the same reason `CantonChainCtx` is exported.
//
// The sidecar group is the live suite's surface: it names `SidecarClient`,
// `StateNode`, `DecodedTransactions` and the config structs, and the rest of
// that group appears in the public signatures or public fields of those, so
// leaving any of it unexported would export a client whose own return types
// cannot be named.
pub use config::{IndexerConfig, MidnightConfig, RpcConfig, SidecarConfig};
pub use convert::{to_sign_request, MidnightChainCtx};
pub use indexer::MidnightIndexer;
pub use publisher::MidnightPublisher;
pub use sidecar::{
    ClaimedCall, DecodedCall, DecodedTransaction, DecodedTransactions, Health, LedgerTags,
    MapEntry, SidecarClient, StateNode,
};
