//! Metrics for the mesh's view of peer liveness.
//!
//! Every wait in the signing path is gated on the size of the active set, and
//! those waits are unbounded, so "why is this node not signing" is almost always
//! "how big was the active set, and why". Without these, that question can only
//! be answered from logs.

use std::sync::LazyLock;

use prometheus::{CounterVec, IntGaugeVec};

use super::{
    try_create_counter_vec_with_node_account_id, try_create_int_gauge_vec_with_node_account_id,
};

/// Size of each mesh participant set. Label `state` is `active` or `need_sync`.
pub(crate) static MESH_PARTICIPANTS: LazyLock<IntGaugeVec> = LazyLock::new(|| {
    try_create_int_gauge_vec_with_node_account_id(
        "multichain_mesh_participants",
        "number of participants in each mesh set as seen by this node",
        &["state"],
    )
    .unwrap()
});

/// Peer status transitions observed by this node, labelled by the new status.
pub(crate) static MESH_STATUS_TRANSITIONS: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_mesh_status_transitions_total",
        "peer connection status transitions observed by this node",
        &["status"],
    )
    .unwrap()
});

/// Why a peer was marked offline.
///
/// Both reasons collapse to [`NodeStatus::Offline`] because neither is usable in
/// a protocol, but they call for opposite responses: `version_mismatch` across a
/// rollout is expected and self-resolving, `unreachable` is not. The status alone
/// cannot tell an operator which one they are looking at.
///
/// [`NodeStatus::Offline`]: crate::mesh::connection::NodeStatus::Offline
pub(crate) static MESH_PEER_OFFLINE: LazyLock<CounterVec> = LazyLock::new(|| {
    try_create_counter_vec_with_node_account_id(
        "multichain_mesh_peer_offline_total",
        "times a peer was marked offline, by reason",
        &["reason"],
    )
    .unwrap()
});

pub(crate) const OFFLINE_UNREACHABLE: &str = "unreachable";
pub(crate) const OFFLINE_VERSION_MISMATCH: &str = "version_mismatch";
