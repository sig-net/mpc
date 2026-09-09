//! Tasks running for the MPC network fixture, simulating things like message
//! passing between nodes and updates to the governance smart contract.

use crate::mpc_fixture::fixture_interface::SharedOutput;
use crate::mpc_fixture::mock_chain::MockChain;
use crate::mpc_fixture::mock_stream::{MockIndexer, MockStream};
use cait_sith::protocol::Participant;
use mpc_chain_integration_core::NoopChainTelemetry;
use mpc_keys::hpke::Ciphered;
use mpc_node::config::Config;
use mpc_node::mesh::MeshState;
use mpc_node::protocol::message::{MessageOutbox, SendMessage, SignedMessage};
use mpc_node::rpc::RpcAction;
use mpc_node::stream::{supervisor::run_supervised, StreamContext};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub type MessageFilter = Box<dyn FnMut(&SendMessage) -> bool + Send>;

#[allow(clippy::too_many_arguments)]
pub(super) fn test_mock_network(
    routing_table: HashMap<Participant, Sender<Ciphered>>,
    shared_output: &SharedOutput,
    mut outbox: MessageOutbox,
    mut rpc_rx: Receiver<RpcAction>,
    mesh: watch::Sender<MeshState>,
    config: watch::Sender<Config>,
    mut filter: MessageFilter,
    mock_chain: Option<MockChain>,
) -> JoinHandle<()> {
    let msg_log = Arc::clone(&shared_output.msg_log);
    let rpc_actions = Arc::clone(&shared_output.rpc_actions);
    let actions_changed = Arc::clone(&shared_output.actions_changed);
    let publishes = Arc::clone(&shared_output.publishes);
    // Participant info as of network start, consulted for recipient's encryption key
    let initial_participants = mesh.borrow().active().clone();

    tokio::spawn(async move {
        tracing::debug!(target: "mock_network", "Test message executor started");
        loop {
            tokio::select! {
                Some(send_message) = outbox.intercept_outgoing_messages().recv() => {
                    let passes_filter = filter(&send_message);
                    msg_log.lock().await.observe_message(&send_message, passes_filter);
                    if !passes_filter {
                        continue;
                    }

                    // directly send out single message, no batching
                    // (might want to add MessageOutbox, too, but for now this is easier)
                    let config = config.borrow().clone();
                    let participants = mesh.borrow().active().clone();
                    let SendMessage { message: msg, from, to, .. } = &send_message;
                    let receiver_info = participants
                        .get(to)
                        .or_else(|| initial_participants.get(to))
                        .unwrap_or_else(|| panic!("no participant info for recipient {to:?}"));
                    match SignedMessage::encrypt(
                        &[msg],
                        *from,
                        &config.local.network.sign_sk,
                        &receiver_info.cipher_pk,
                    ) {
                        Ok(ciphered) => {
                            if let Some(tx) = routing_table.get(to) {
                                if let Err(e) = tx.send(ciphered).await {
                                    tracing::warn!(target: "mock_network", ?e, "Failed to forward encrypted message to {to:?}");
                                }
                            } else {
                                tracing::error!(target: "mock_network", "Test setup bug: No route to participant {:?}", to);
                            }
                        }
                        Err(e) => {
                            tracing::error!(target: "mock_network", ?e, "Encryption failed");
                        }
                    }
                }

                Some(rpc) = rpc_rx.recv() => {
                    // `None` for anything that is not an action on a chain: the log is
                    // what tests count responses with, so bookkeeping must stay out of it.
                    let action_str = match &rpc {
                        RpcAction::Publish(publish_action) => {
                            publishes.fetch_add(1, Ordering::Relaxed);
                            Some(format!(
                                "RpcAction::Publish({:?})",
                                publish_action.request,
                            ))
                        },
                        RpcAction::VoteCheckpoint { checkpoint, .. } => {
                            Some(format!("RpcAction::VoteCheckpoint({checkpoint:?})"))
                        },
                        RpcAction::AbortCheckpoints(chain) => {
                            Some(format!("RpcAction::AbortCheckpoints({chain:?})"))
                        }
                    };
                    if let Some(action_str) = action_str {
                        tracing::info!(target: "mock_network", ?action_str, "Received RPC action");
                        let mut actions_log = rpc_actions.lock().await;
                        actions_log.insert(action_str);
                        drop(actions_log);
                        actions_changed.notify_one();
                    }

                    if let Some(chain) = &mock_chain {
                        chain.on_rpc_publish(&rpc).await;
                    }
                }

                else => {
                    tracing::info!(target: "mock_network", "All channels closed, exiting handler loop for one node");
                    break;
                }
            }
        }
        tracing::info!(target: "mock_network", "Test mock network task exited");
    })
}

/// Supervise one chain indexer per mock stream. `make_ctx` builds a fresh
/// [`StreamContext`] per stream, so the caller decides what the streams share
/// without every dependency travelling through this signature.
pub(super) fn start_mock_stream_tasks(
    mock_streams: &[MockStream],
    make_ctx: impl Fn() -> StreamContext,
) {
    for stream in mock_streams {
        tokio::spawn(run_supervised(
            MockIndexer::from_stream(stream),
            make_ctx(),
            NoopChainTelemetry,
        ));
    }
}
