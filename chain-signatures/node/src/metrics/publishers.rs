use prometheus::{CounterVec, GaugeVec};
use std::sync::LazyLock;

use super::{
    try_create_counter_vec_with_node_account_id, try_create_gauge_vec_with_node_account_id,
};

/// Spendable balance of the publisher's funding wallet in the chain's fee unit (DUST on
/// Midnight), read before its last landed publish; it holds while publishes fail.
pub(crate) static FUNDING_WALLET_BALANCE: LazyLock<GaugeVec> = LazyLock::new(|| {
    try_create_gauge_vec_with_node_account_id(
        "multichain_funding_wallet_balance",
        "Spendable balance of the publisher's funding wallet in the chain's fee unit, read before its last landed publish",
        &["chain"],
    )
    .unwrap()
});

/// Requests the chain's publisher answered with an error code, e.g. `wallet_unfunded`
/// or `ambiguous_submit`, by code.
pub(crate) static PUBLISH_REFUSALS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_publish_refusals",
        "Publishes the chain's publisher refused, by error code",
        &["chain", "code"],
    )
    .unwrap()
});
