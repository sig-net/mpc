//! WebSocket client pool for persistent connections to other MPC nodes.
//!
//! This module manages a pool of WebSocket connections to peer nodes,
//! providing efficient message delivery without HTTP overhead.

use crate::protocol::message::cbor_to_bytes;

use cait_sith::protocol::Participant;
use futures_util::{SinkExt, StreamExt};
use mpc_keys::hpke::Ciphered;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::connect_async;
use url::Url;

/// Error types for WebSocket operations
#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("connection failed: {0}")]
    ConnectionFailed(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("send failed: {0}")]
    SendFailed(String),
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
    #[error("connection not found for participant {0:?}")]
    ConnectionNotFound(Participant),
    #[error("connection closed")]
    ConnectionClosed,
}

/// A single WebSocket connection to a peer node
struct WsConnection {
    /// The sender half of the WebSocket connection
    tx: mpsc::Sender<Vec<u8>>,
    /// When the connection was established
    connected_at: Instant,
    /// URL of the peer
    url: Url,
    /// Task handle for the connection writer
    _writer_handle: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for WsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsConnection")
            .field("connected_at", &self.connected_at)
            .field("url", &self.url)
            .field("is_alive", &!self.tx.is_closed())
            .finish_non_exhaustive()
    }
}

impl WsConnection {
    /// Create a new WebSocket connection to the given URL
    async fn connect(url: Url) -> Result<Self, WsError> {
        let ws_url = Self::http_to_ws_url(&url)?;
        tracing::debug!(?ws_url, "connecting websocket");

        let (ws_stream, _) = connect_async(&ws_url).await?;
        let (mut write, mut read) = ws_stream.split();

        // Channel for sending messages to the WebSocket
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);

        // Spawn writer task
        let writer_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(data) = rx.recv() => {
                        if let Err(err) = write.send(Message::Binary(data)).await {
                            tracing::warn!(?err, "websocket send failed");
                            break;
                        }
                    }
                    // Also handle incoming messages (pings, etc.)
                    msg = read.next() => {
                        match msg {
                            Some(Ok(Message::Ping(data))) => {
                                if let Err(err) = write.send(Message::Pong(data)).await {
                                    tracing::warn!(?err, "failed to send pong");
                                    break;
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => {
                                tracing::debug!("websocket connection closed");
                                break;
                            }
                            Some(Err(err)) => {
                                tracing::warn!(?err, "websocket read error");
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        });

        Ok(Self {
            tx,
            connected_at: Instant::now(),
            url,
            _writer_handle: writer_handle,
        })
    }

    /// Convert HTTP URL to WebSocket URL
    fn http_to_ws_url(url: &Url) -> Result<String, WsError> {
        let scheme = match url.scheme() {
            "http" => "ws",
            "https" => "wss",
            s => s,
        };
        let host = url.host_str().unwrap_or("localhost");
        let port = url.port().map(|p| format!(":{}", p)).unwrap_or_default();
        Ok(format!("{}://{}{}/ws", scheme, host, port))
    }

    /// Send a batch of encrypted messages
    async fn send(&self, messages: &[&Ciphered]) -> Result<(), WsError> {
        let data =
            cbor_to_bytes(messages).map_err(|e| WsError::SerializationFailed(e.to_string()))?;

        self.tx
            .send(data)
            .await
            .map_err(|_| WsError::ConnectionClosed)
    }

    /// Check if the connection is still alive
    fn is_alive(&self) -> bool {
        !self.tx.is_closed()
    }

    /// Get connection age
    fn age(&self) -> Duration {
        self.connected_at.elapsed()
    }
}

/// Pool of WebSocket connections to peer nodes
#[derive(Debug)]
pub struct WsPool {
    /// Connections indexed by Participant ID
    connections: Arc<RwLock<HashMap<Participant, WsConnection>>>,
    /// Connections indexed by URL (for cases where we don't have a Participant)
    url_connections: Arc<RwLock<HashMap<String, WsConnection>>>,
    /// Maximum age of a connection before it should be refreshed
    max_connection_age: Duration,
}

impl Default for WsPool {
    fn default() -> Self {
        Self::new()
    }
}

impl WsPool {
    /// Create a new WebSocket pool
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            url_connections: Arc::new(RwLock::new(HashMap::new())),
            max_connection_age: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a new WebSocket pool with custom settings
    pub fn with_max_age(max_connection_age: Duration) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            url_connections: Arc::new(RwLock::new(HashMap::new())),
            max_connection_age,
        }
    }

    /// Get or create a connection to a participant
    async fn get_or_connect(&self, participant: Participant, url: &Url) -> Result<(), WsError> {
        // First, check if we have a valid connection
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&participant) {
                if conn.is_alive() && conn.age() < self.max_connection_age {
                    return Ok(());
                }
            }
        }

        // Need to create or refresh connection
        let conn = WsConnection::connect(url.clone()).await?;
        {
            let mut connections = self.connections.write().await;
            connections.insert(participant, conn);
        }
        Ok(())
    }

    /// Send messages to a participant via WebSocket
    ///
    /// Returns Ok(true) if sent via WebSocket, Ok(false) if WebSocket unavailable
    pub async fn send(
        &self,
        participant: Participant,
        url: &Url,
        messages: &[&Ciphered],
    ) -> Result<bool, WsError> {
        // Try to get or create connection
        if let Err(err) = self.get_or_connect(participant, url).await {
            tracing::debug!(?participant, ?err, "websocket connection unavailable, falling back to HTTP");
            return Ok(false);
        }

        // Send the messages
        let connections = self.connections.read().await;
        if let Some(conn) = connections.get(&participant) {
            match conn.send(messages).await {
                Ok(()) => Ok(true),
                Err(err) => {
                    tracing::warn!(?participant, ?err, "websocket send failed");
                    // Connection is bad, remove it
                    drop(connections);
                    self.remove(participant).await;
                    Ok(false)
                }
            }
        } else {
            Ok(false)
        }
    }

    /// Remove a connection from the pool
    pub async fn remove(&self, participant: Participant) {
        let mut connections = self.connections.write().await;
        connections.remove(&participant);
    }

    /// Send messages to a URL via WebSocket (without needing a Participant ID)
    ///
    /// Returns Ok(true) if sent via WebSocket, Ok(false) if WebSocket unavailable
    pub async fn send_to_url(&self, url: &Url, messages: &[&Ciphered]) -> Result<bool, WsError> {
        let url_key = url.to_string();

        // Try to get or create connection
        if let Err(err) = self.get_or_connect_url(url).await {
            tracing::debug!(?url, ?err, "websocket connection unavailable");
            return Ok(false);
        }

        // Send the messages
        let connections = self.url_connections.read().await;
        if let Some(conn) = connections.get(&url_key) {
            match conn.send(messages).await {
                Ok(()) => Ok(true),
                Err(err) => {
                    tracing::warn!(?url, ?err, "websocket send failed");
                    drop(connections);
                    self.remove_url(url).await;
                    Ok(false)
                }
            }
        } else {
            Ok(false)
        }
    }

    /// Get or create a connection to a URL
    async fn get_or_connect_url(&self, url: &Url) -> Result<(), WsError> {
        let url_key = url.to_string();

        // First, check if we have a valid connection
        {
            let connections = self.url_connections.read().await;
            if let Some(conn) = connections.get(&url_key) {
                if conn.is_alive() && conn.age() < self.max_connection_age {
                    return Ok(());
                }
            }
        }

        // Need to create or refresh connection
        let conn = WsConnection::connect(url.clone()).await?;
        {
            let mut connections = self.url_connections.write().await;
            connections.insert(url_key, conn);
        }
        Ok(())
    }

    /// Remove a URL-based connection from the pool
    pub async fn remove_url(&self, url: &Url) {
        let mut connections = self.url_connections.write().await;
        connections.remove(&url.to_string());
    }

    /// Close all connections
    pub async fn close_all(&self) {
        {
            let mut connections = self.connections.write().await;
            connections.clear();
        }
        {
            let mut url_connections = self.url_connections.write().await;
            url_connections.clear();
        }
    }

    /// Get the number of active connections
    pub async fn connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        let url_connections = self.url_connections.read().await;
        connections.values().filter(|c| c.is_alive()).count()
            + url_connections.values().filter(|c| c.is_alive()).count()
    }

    /// Clean up stale connections
    pub async fn cleanup_stale(&self) {
        {
            let mut connections = self.connections.write().await;
            connections.retain(|_, conn| conn.is_alive() && conn.age() < self.max_connection_age);
        }
        {
            let mut url_connections = self.url_connections.write().await;
            url_connections
                .retain(|_, conn| conn.is_alive() && conn.age() < self.max_connection_age);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_to_ws_url() {
        let http_url = Url::parse("http://localhost:8080").unwrap();
        let ws_url = WsConnection::http_to_ws_url(&http_url).unwrap();
        assert_eq!(ws_url, "ws://localhost:8080/ws");

        let https_url = Url::parse("https://example.com:443").unwrap();
        let wss_url = WsConnection::http_to_ws_url(&https_url).unwrap();
        // Port 443 is omitted for HTTPS URLs since it's the default
        assert_eq!(wss_url, "wss://example.com/ws");

        let https_url_custom_port = Url::parse("https://example.com:8443").unwrap();
        let wss_url_custom = WsConnection::http_to_ws_url(&https_url_custom_port).unwrap();
        assert_eq!(wss_url_custom, "wss://example.com:8443/ws");
    }

    #[tokio::test]
    async fn test_pool_creation() {
        let pool = WsPool::new();
        assert_eq!(pool.connection_count().await, 0);
    }
}
