//! Tasks running for the MPC network fixture, simulating things like message
//! passing between nodes and updates to the governance smart contract.

use crate::mpc_fixture::fixture_interface::SharedOutput;
use crate::mpc_fixture::mock_chain::MockChain;
use crate::mpc_fixture::mock_stream::MockStream;
use cait_sith::protocol::Participant;
use mpc_keys::hpke::Ciphered;
use mpc_node::backlog::Backlog;
use mpc_node::config::Config;
use mpc_node::mesh::MeshState;
use mpc_node::node_client::NodeClient;
use mpc_node::protocol::message::{MessageOutbox, SendMessage, SignedMessage};
use mpc_node::protocol::Sign;
use mpc_node::rpc::{ContractStateWatcher, RpcAction, RpcChannel};
use mpc_node::stream::run_stream;
use mpc_primitives::{CheckpointDigest, NoopChainTelemetry};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc::{self, Receiver, Sender};
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
                    let (msg, (from, to, _ts)) = &send_message;
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
                    let action_str = match &rpc {
                        RpcAction::Publish(publish_action) => {
                            format!(
                                "RpcAction::Publish({:?})",
                                publish_action.indexed,
                            )
                        },
                    };
                    tracing::info!(target: "mock_network", ?action_str, "Received RPC action");
                    let mut actions_log = rpc_actions.lock().await;
                    actions_log.insert(action_str);
                    drop(actions_log);

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

pub(super) fn start_mock_stream_tasks(
    mock_streams: &[MockStream],
    sign_tx: mpsc::Sender<Sign>,
    rpc: RpcChannel,
    backlog: Backlog,
    contract_watcher: ContractStateWatcher,
    mesh_state: &watch::Receiver<MeshState>,
    checkpoints_rx: watch::Receiver<CheckpointDigest>,
) {
    for stream in mock_streams {
        tokio::spawn(run_stream(
            stream.clone(),
            sign_tx.clone(),
            rpc.clone(),
            backlog.clone(),
            NoopChainTelemetry,
            contract_watcher.clone(),
            mesh_state.clone(),
            // Only used for backlog recovery - not implemented in component tests yet
            NodeClient::new(&Default::default()),
            checkpoints_rx.clone(),
        ));
    }
}
