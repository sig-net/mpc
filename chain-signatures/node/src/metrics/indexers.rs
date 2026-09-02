use prometheus::{CounterVec, IntGaugeVec};
use std::sync::LazyLock;

use super::{
    try_create_counter_vec_with_node_account_id, try_create_int_gauge_vec_with_node_account_id,
};

/// Possible status options:
///     - "indexed" - latest block number seen by the indexer
///     - "finalized" - latest block number seen as finalized by the indexer
///     - "checkpoint" - latest block number for which a checkpoint was created
pub static LATEST_BLOCK_NUMBER: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_latest_block_number",
        "Latest block number seen by the node",
        &["chain", "status"],
    )
    .unwrap()
});

/// Failed attempts to extract the output of a bidirectional execution on the
/// target chain, labelled by `kind`:
///     - "retryable" - node-local failure (RPC transport, missing trace support,
///       malformed provider response); the watcher stays pending and is retried
///     - "terminal" - deterministic failure of on-chain data against the
///       request schemas; the execution is resolved as failed
///
/// Counts attempts, not transactions: one retryable transaction increments this
/// once per retry, so a rising "retryable" rate with no matching resolution is
/// the signal that a node's RPC endpoint cannot extract outputs.
pub static BIDIRECTIONAL_EXTRACTION_FAILURES: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_bidirectional_extraction_failures",
        "Failed bidirectional execution output extraction attempts",
        &["chain", "kind"],
    )
    .unwrap()
});
