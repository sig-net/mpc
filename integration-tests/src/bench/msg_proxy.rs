//! Message Proxy for benchmarking MPC node message throughput
//!
//! This proxy sits between MPC nodes and intercepts all `/msg` traffic,
//! recording metrics before forwarding messages to their destinations.
//! This allows non-invasive benchmarking without modifying node code.

use axum::body::Bytes;
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use mpc_keys::hpke::Ciphered;
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

/// Metrics collected for a specific protocol type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolMetrics {
    pub message_count: usize,
    pub bytes_sent: usize,
    pub latencies: Vec<Duration>,
}

/// Complete message throughput metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageMetrics {
    /// Total number of message batches sent through proxy
    pub batches_sent: usize,
    /// Total number of individual messages
    pub messages_sent: usize,
    /// Total bytes sent
    pub bytes_sent: usize,
    /// Latencies for each message batch forwarding
    pub latencies: Vec<Duration>,
    /// When metrics collection started
    pub start_time: Option<Instant>,
    /// When metrics collection ended
    pub end_time: Option<Instant>,
    /// Messages per destination node
    pub per_node: HashMap<String, usize>,
}

impl MessageMetrics {
    /// Calculate messages per second
    pub fn messages_per_second(&self) -> f64 {
        if let (Some(start), Some(end)) = (self.start_time, self.end_time) {
            let duration = end.duration_since(start).as_secs_f64();
            if duration > 0.0 {
                return self.messages_sent as f64 / duration;
            }
        }
        0.0
    }

    /// Calculate bytes per second
    pub fn bytes_per_second(&self) -> f64 {
        if let (Some(start), Some(end)) = (self.start_time, self.end_time) {
            let duration = end.duration_since(start).as_secs_f64();
            if duration > 0.0 {
                return self.bytes_sent as f64 / duration;
            }
        }
        0.0
    }

    /// Get average latency in milliseconds
    pub fn avg_latency_ms(&self) -> f64 {
        if self.latencies.is_empty() {
            return 0.0;
        }
        let sum: Duration = self.latencies.iter().sum();
        sum.as_millis() as f64 / self.latencies.len() as f64
    }

    /// Get p95 latency in milliseconds
    pub fn p95_latency_ms(&self) -> f64 {
        if self.latencies.is_empty() {
            return 0.0;
        }
        let mut sorted = self.latencies.clone();
        sorted.sort();
        let idx = (sorted.len() as f64 * 0.95) as usize;
        sorted.get(idx).unwrap_or(&Duration::ZERO).as_millis() as f64
    }

    /// Get p99 latency in milliseconds
    pub fn p99_latency_ms(&self) -> f64 {
        if self.latencies.is_empty() {
            return 0.0;
        }
        let mut sorted = self.latencies.clone();
        sorted.sort();
        let idx = (sorted.len() as f64 * 0.99) as usize;
        sorted.get(idx).unwrap_or(&Duration::ZERO).as_millis() as f64
    }
}

/// Internal state shared between proxy handlers
struct ProxyState {
    /// Mapping from node account_id to their actual URL
    node_routes: HashMap<AccountId, Url>,
    /// HTTP client for forwarding requests
    client: reqwest::Client,
    /// Collected metrics
    metrics: RwLock<MessageMetrics>,
}

/// Message proxy that intercepts and measures node-to-node messages
pub struct MessageProxy {
    /// Address the proxy server is listening on
    pub addr: SocketAddr,
    /// Shared state
    state: Arc<ProxyState>,
    /// Handle to the server task
    server_handle: Option<tokio::task::JoinHandle<()>>,
}

impl MessageProxy {
    /// Create a new message proxy
    ///
    /// # Arguments
    /// * `node_routes` - Map of AccountId to actual node URL for routing
    /// * `bind_addr` - Address to bind the proxy server to (e.g., "127.0.0.1:0")
    pub async fn new(
        node_routes: HashMap<AccountId, Url>,
        bind_addr: impl Into<String>,
    ) -> anyhow::Result<Self> {
        let state = Arc::new(ProxyState {
            node_routes,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
            metrics: RwLock::new(MessageMetrics::default()),
        });

        // Build the router
        let app = Router::new()
            .route("/msg/:node_id", post(handle_msg))
            .layer(Extension(state.clone()));

        // Bind to a socket
        let bind_addr = bind_addr.into();
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        let addr = listener.local_addr()?;

        // Spawn the server
        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        Ok(Self {
            addr,
            state,
            server_handle: Some(server_handle),
        })
    }

    /// Get the proxy's base URL
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Get the proxy URL for a specific node
    pub fn msg_url(&self, node_id: &AccountId) -> String {
        format!("{}/msg/{}", self.url(), node_id)
    }

    /// Reset metrics (e.g., before starting a new benchmark iteration)
    pub async fn reset_metrics(&self) {
        let mut metrics = self.state.metrics.write().await;
        *metrics = MessageMetrics {
            start_time: Some(Instant::now()),
            ..Default::default()
        };
    }

    /// Finalize metrics collection (sets end_time)
    pub async fn finalize_metrics(&self) {
        let mut metrics = self.state.metrics.write().await;
        metrics.end_time = Some(Instant::now());
    }

    /// Get a snapshot of current metrics
    pub async fn metrics(&self) -> MessageMetrics {
        self.state.metrics.read().await.clone()
    }

    /// Shutdown the proxy server
    pub async fn shutdown(mut self) {
        if let Some(handle) = self.server_handle.take() {
            handle.abort();
        }
    }
}

/// Handler for /msg/:node_id endpoint
async fn handle_msg(
    Path(node_id): Path<String>,
    Extension(state): Extension<Arc<ProxyState>>,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    let start = Instant::now();

    // Parse node_id
    let node_id: AccountId = node_id
        .parse()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Look up the real node URL
    let node_url = state
        .node_routes
        .get(&node_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    // Decode the message to count individual messages in the batch
    let message_count = match ciborium::from_reader::<Vec<Ciphered>, _>(body.as_ref()) {
        Ok(batch) => batch.len(),
        Err(_) => {
            // If we can't decode, just count as 1
            1
        }
    };

    let bytes_sent = body.len();

    // Forward the message to the real node
    let mut target_url = node_url.clone();
    target_url.set_path("msg");

    let forward_result = state
        .client
        .post(target_url)
        .header("content-type", "application/cbor")
        .body(body)
        .send()
        .await;

    let latency = start.elapsed();

    // Update metrics
    {
        let mut metrics = state.metrics.write().await;
        metrics.batches_sent += 1;
        metrics.messages_sent += message_count;
        metrics.bytes_sent += bytes_sent;
        metrics.latencies.push(latency);
        *metrics.per_node.entry(node_id.to_string()).or_insert(0) += message_count;
    }

    // Return the result
    match forward_result {
        Ok(resp) if resp.status().is_success() => Ok(StatusCode::OK),
        Ok(resp) => {
            tracing::warn!(
                "failed to forward message to {}: status {}",
                node_id,
                resp.status()
            );
            Err(StatusCode::BAD_GATEWAY)
        }
        Err(err) => {
            tracing::error!("failed to forward message to {}: {}", node_id, err);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_creation() {
        let routes = HashMap::new();
        let proxy = MessageProxy::new(routes, "127.0.0.1:0")
            .await
            .expect("Failed to create proxy");

        assert!(proxy.addr.port() > 0);
        proxy.shutdown().await;
    }

    #[tokio::test]
    async fn test_metrics_reset() {
        let routes = HashMap::new();
        let proxy = MessageProxy::new(routes, "127.0.0.1:0")
            .await
            .expect("Failed to create proxy");

        proxy.reset_metrics().await;
        let metrics = proxy.metrics().await;
        assert!(metrics.start_time.is_some());
        assert_eq!(metrics.messages_sent, 0);

        proxy.shutdown().await;
    }
}
