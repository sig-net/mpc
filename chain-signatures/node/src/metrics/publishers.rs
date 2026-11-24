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

/// Counts restarts, not drops: reported whenever one of the five causes below
/// restarts the replay from the first event, including when the wallet never
/// held a checkpoint; first-event replays by other paths report nothing. Only
/// Midnight's wallet (`mpc_chain_midnight::funding`) reports these today.
pub(crate) static FUNDING_WALLET_REPLAY_RESTARTS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_funding_wallet_replay_restarts",
        "Funding wallet replay restarts from the first event, by cause (strikes, stuck, resume_timeout, checkpoint_mismatch, replay_failed — first-event replays by other paths are not counted); each drops the wallet's checkpoint where it held one, and strikes and stuck also clear the stored one",
        &["chain", "cause"],
    )
    .unwrap()
});
