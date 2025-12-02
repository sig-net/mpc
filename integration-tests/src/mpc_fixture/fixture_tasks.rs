//! Tasks running for the MPC network fixture, simulating things like message
//! passing between nodes and updates to the governance smart contract.

use crate::mpc_fixture::fixture_interface::SharedOutput;
use cait_sith::protocol::Participant;
use mpc_keys::hpke::Ciphered;
use mpc_node::config::Config;
use mpc_node::mesh::MeshState;
use mpc_node::protocol;
use mpc_node::protocol::message::{MessageOutbox, SendMessage, SignedMessage};
use mpc_node::protocol::Sign;
use mpc_node::rpc::RpcAction;
use mpc_primitives::SignId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::watch;
use tokio::task::JoinHandle;

pub type MessageFilter = Box<dyn FnMut(&SendMessage) -> bool + Send>;

pub(super) fn test_mock_network(
    routing_table: HashMap<Participant, Sender<Ciphered>>,
    shared_output: &SharedOutput,
    mut outbox: MessageOutbox,
    mut rpc_rx: Receiver<RpcAction>,
    mesh: watch::Sender<MeshState>,
    config: watch::Sender<Config>,
    mut filter: MessageFilter,
    sign_tx: Sender<Sign>,
    completion_tx: broadcast::Sender<SignId>,
    mut completion_rx: broadcast::Receiver<SignId>,
) -> JoinHandle<()> {
    let msg_log = Arc::clone(&shared_output.msg_log);
    let rpc_actions = Arc::clone(&shared_output.rpc_actions);

    tokio::spawn(async move {
        tracing::debug!(target: "mock_network", "Test message executor started");
        loop {
            tokio::select! {
                Some(send_message) = outbox.intercept_outgoing_messages().recv() => {
                    let (msg, (from, to, ts)) = &send_message;

                    tracing::debug!(target: "mock_network", ?to, ?ts, "Received MPC message");

                    let log_msg = match msg {
                        protocol::Message::Posit(_) => "Posit",
                        protocol::Message::Generating(_) => "Generating",
                        protocol::Message::Ready(_) => "Ready",
                        protocol::Message::Resharing(_) => "Resharing",
                        protocol::Message::Triple(_) => "Triple",
                        protocol::Message::Presignature(_) => "Presignature",
                        protocol::Message::Signature(_) => "Signature",
                        protocol::Message::Unknown(_) => "Unknown",
                    };
                    msg_log.lock().await.push(format!("{log_msg} from {from:?} to {to:?}"));

                    if !filter(&send_message) {
                        tracing::info!("Dropping a message because it didn't pass the test's filter");
                        continue;
                    }


                    // directly send out single message, no batching
                    // (might want to add MessageOutbox, too, but for now this is easier)
                    let config = config.borrow().clone();
                    let participants = mesh.borrow().active.clone();
                    let receiver_info = participants.get(to).expect("TODO: support sending to non-active participants in tests");
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
                    let (action_str, sign_id) = match rpc {
                        RpcAction::Publish(ref publish_action) => {
                            (format!(
                                "RpcAction::Publish({:?})",
                                publish_action.indexed,
                            ), publish_action.indexed.id.clone())
                        },
                    };
                    tracing::info!(target: "mock_network", ?action_str, "Received RPC action, broadcasting completion");
                    let mut actions_log = rpc_actions.lock().await;
                    actions_log.insert(action_str);

                    // Broadcast completion to all nodes
                    if let Err(e) = completion_tx.send(sign_id) {
                        tracing::warn!(target: "mock_network", ?e, "Failed to broadcast completion");
                    }
                }

                Ok(sign_id) = completion_rx.recv() => {
                    // Received a completion from another node, forward to our sign_tx
                    tracing::info!(target: "mock_network", ?sign_id, "Received completion broadcast, forwarding to sign channel");
                    if let Err(e) = sign_tx.send(Sign::Completion(sign_id)).await {
                        tracing::warn!(target: "mock_network", ?e, "Failed to send completion to sign channel");
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
