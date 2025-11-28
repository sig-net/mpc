//! WebSocket support for persistent bidirectional connections between MPC nodes.
//!
//! This module provides WebSocket endpoints and handlers for the MPC node server.
//! WebSocket connections offer significant performance improvements over HTTP:
//! - Single TCP connection per node pair (always open)
//! - Minimal framing overhead (~2 bytes vs ~200-500 bytes for HTTP headers)
//! - Bidirectional communication without polling
//! - Lower latency (no request/response cycle)

use crate::metrics::WEB_ENDPOINT_LATENCY;
use crate::protocol::MessageChannel;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::WebSocketUpgrade;
use axum::response::IntoResponse;
use axum::Extension;
use futures_util::{SinkExt, StreamExt};
use mpc_keys::hpke::Ciphered;
use near_account_id::AccountId;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// State shared with the WebSocket handler
pub struct WsState {
    pub msg_channel: MessageChannel,
    pub my_account_id: AccountId,
}

/// WebSocket upgrade handler for the `/ws` endpoint.
///
/// This handler upgrades HTTP connections to WebSocket connections,
/// enabling persistent bidirectional communication between nodes.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Extension(state): Extension<Arc<WsState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_connection(socket, state))
}

/// Handle an established WebSocket connection.
///
/// This function:
/// 1. Splits the socket into sender and receiver halves
/// 2. Spawns a task to handle outgoing messages (future enhancement)
/// 3. Processes incoming binary messages as encrypted Ciphered batches
/// 4. Forwards decrypted messages to the inbox channel
async fn handle_ws_connection(socket: WebSocket, state: Arc<WsState>) {
    let (mut sender, mut receiver) = socket.split();

    // Channel for sending messages back through the WebSocket (for future bidirectional use)
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Vec<u8>>(256);

    // Spawn task to handle outgoing messages
    let sender_task = tokio::spawn(async move {
        while let Some(data) = outgoing_rx.recv().await {
            if sender.send(Message::Binary(data.into())).await.is_err() {
                break;
            }
        }
    });

    let msg_channel = state.msg_channel.clone();
    let my_account_id = state.my_account_id.clone();

    // Process incoming messages
    while let Some(result) = receiver.next().await {
        let start = Instant::now();

        let msg = match result {
            Ok(msg) => msg,
            Err(err) => {
                tracing::warn!(?err, "websocket receive error");
                break;
            }
        };

        match msg {
            Message::Binary(data) => {
                // Deserialize the batch of encrypted messages
                let data_slice: &[u8] = data.as_ref();
                match ciborium::from_reader::<Vec<Ciphered>, _>(data_slice) {
                    Ok(encrypted_batch) => {
                        for encrypted in encrypted_batch {
                            let msg_channel = msg_channel.clone();
                            tokio::spawn(async move {
                                if let Err(err) = msg_channel.inbox.send(encrypted).await {
                                    tracing::error!(
                                        ?err,
                                        "failed to forward websocket message to inbox"
                                    );
                                }
                            });
                        }
                    }
                    Err(err) => {
                        tracing::warn!(?err, "failed to deserialize websocket message");
                    }
                }

                WEB_ENDPOINT_LATENCY
                    .with_label_values(&["ws_msg", my_account_id.as_str()])
                    .observe(start.elapsed().as_millis() as f64);
            }
            Message::Ping(data) => {
                // Respond to ping with pong - handled automatically by tungstenite
                // but we can log it for debugging
                tracing::trace!(len = data.len(), "received websocket ping");
            }
            Message::Pong(_) => {
                // Pong received, connection is alive
                tracing::trace!("received websocket pong");
            }
            Message::Close(_) => {
                tracing::debug!("websocket connection closed by peer");
                break;
            }
            Message::Text(_) => {
                // We don't expect text messages in our protocol
                tracing::warn!("received unexpected text message on websocket");
            }
        }
    }

    // Clean up the sender task
    drop(outgoing_tx);
    sender_task.abort();

    tracing::debug!("websocket connection handler finished");
}

#[cfg(test)]
mod tests {
    // Basic unit tests would go here
    // Integration tests with actual WebSocket connections would be in integration-tests
}
