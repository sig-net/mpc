//! Message Proxy for benchmarking MPC node message throughput
//!
//! This proxy sits between MPC nodes and intercepts all traffic,
//! recording metrics for `/msg` while transparently forwarding
//! `/state` and `/status` requests. This allows non-invasive
//! benchmarking without modifying node code.
//!
//! Architecture: Multi-port proxy where each node gets its own listening port.
//! This avoids path manipulation issues with Url::set_path().

use axum::body::Bytes;
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use mpc_keys::hpke::Ciphered;
use near_account_id::AccountId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

/// Metrics collected for a specific protocol type
#[derive(Debug, Clone, Default)]
pub struct ProtocolMetrics {
    pub message_count: usize,
    pub bytes_sent: usize,
    pub latencies: Vec<Duration>,
}

/// Complete message throughput metrics
#[derive(Debug, Clone, Default)]
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

/// Internal state for a single node's proxy instance
struct NodeProxyState {
    /// The node being proxied
    node_id: AccountId,
    /// The actual backend URL for this node
    backend_url: Url,
    /// HTTP client for forwarding requests
    client: reqwest::Client,
    /// Shared metrics across all node proxies
    metrics: Arc<RwLock<MessageMetrics>>,
}

/// Message proxy that intercepts and measures node-to-node messages
/// Uses one listening port per node to avoid URL path manipulation issues
pub struct MessageProxy {
    /// Mapping from node_id to their proxy port
    pub node_ports: HashMap<AccountId, u16>,
    /// Shared metrics
    state: Arc<RwLock<MessageMetrics>>,
    /// Server task handles (one per node)
    _servers: Vec<tokio::task::JoinHandle<()>>,
}

impl MessageProxy {
    /// Spawn proxy with empty routes (to be populated after nodes start)
    pub async fn spawn() -> anyhow::Result<Self> {
        let state = Arc::new(RwLock::new(MessageMetrics {
            start_time: Some(Instant::now()),
            ..Default::default()
        }));

        Ok(Self {
            node_ports: HashMap::new(),
            state,
            _servers: vec![],
        })
    }

    /// Add a node to the proxy by spawning a dedicated port for it
    pub async fn add_node(
        &mut self,
        node_id: AccountId,
        backend_url: Url,
    ) -> anyhow::Result<u16> {
        let client = reqwest::Client::new();

        let node_state = Arc::new(NodeProxyState {
            node_id: node_id.clone(),
            backend_url,
            client,
            metrics: self.state.clone(),
        });

        // Create router for this node
        let app = Router::new()
            .route("/msg", post(handle_msg))
            .route("/state", get(handle_passthrough))
            .route("/status", get(handle_passthrough))
            .layer(Extension(node_state));

        // Bind to any available port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let port = addr.port();

        // Spawn server task
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("proxy server failed");
        });

        self.node_ports.insert(node_id, port);
        self._servers.push(server);

        Ok(port)
    }

    /// Get the proxy port for a specific node
    pub fn port_for_node(&self, node_id: &AccountId) -> Option<u16> {
        self.node_ports.get(node_id).copied()
    }

    /// Mark the start of metrics collection
    pub async fn start_collection(&self) {
        let mut metrics = self.state.write().await;
        metrics.start_time = Some(Instant::now());
    }

    /// Collect and finalize metrics
    pub async fn collect_metrics(&self) -> MessageMetrics {
        let mut metrics = self.state.write().await;
        metrics.end_time = Some(Instant::now());
        metrics.clone()
    }
}

/// Handler for POST /msg requests (with metrics)
async fn handle_msg(
    Extension(state): Extension<Arc<NodeProxyState>>,
    body: Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    let start = Instant::now();

    // Decode the message to count individual messages in the batch
    let message_count = match ciborium::from_reader::<Vec<Ciphered>, _>(body.as_ref()) {
        Ok(batch) => batch.len(),
        Err(_) => 1,
    };

    let bytes_sent = body.len();

    // Forward the message to the real node
    let mut target_url = state.backend_url.clone();
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
        *metrics
            .per_node
            .entry(state.node_id.to_string())
            .or_insert(0) += message_count;
    }

    // Return the result
    match forward_result {
        Ok(resp) if resp.status().is_success() => {
            Ok(axum::response::Response::new(axum::body::Body::empty()))
        }
        Ok(resp) => {
            tracing::warn!(
                "failed to forward message to {}: status {}",
                state.node_id,
                resp.status()
            );
            Err(StatusCode::BAD_GATEWAY)
        }
        Err(err) => {
            tracing::error!("failed to forward message to {}: {}", state.node_id, err);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

/// Handler for GET /state and /status requests (transparent passthrough)
async fn handle_passthrough(
    Extension(state): Extension<Arc<NodeProxyState>>,
    uri: axum::http::Uri,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Get the path (e.g., "state" or "status")
    let path = uri.path().trim_start_matches('/');

    // Forward the request to the real node
    let mut target_url = state.backend_url.clone();
    target_url.set_path(path);

    let forward_result = state.client.get(target_url).send().await;

    // Forward the response
    match forward_result {
        Ok(resp) if resp.status().is_success() => {
            let json = resp.json::<serde_json::Value>().await.map_err(|err| {
                tracing::error!(
                    "failed to parse {} response from {}: {}",
                    path,
                    state.node_id,
                    err
                );
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            Ok(Json(json))
        }
        Ok(resp) => {
            tracing::warn!(
                "failed to forward {} request to {}: status {}",
                path,
                state.node_id,
                resp.status()
            );
            Err(StatusCode::BAD_GATEWAY)
        }
        Err(err) => {
            tracing::error!(
                "failed to forward {} request to {}: {}",
                path,
                state.node_id,
                err
            );
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proxy_basics() {
        let mut proxy = MessageProxy::spawn().await.unwrap();
        let node_id: AccountId = "test-node".parse().unwrap();
        let backend_url: Url = "http://127.0.0.1:8080".parse().unwrap();

        let port = proxy.add_node(node_id.clone(), backend_url).await.unwrap();
        assert!(port > 0);
        assert_eq!(proxy.port_for_node(&node_id), Some(port));
    }
}
