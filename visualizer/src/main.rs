use axum::{
    extract::State,
    http::{Method, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SignRequestStatus {
    InPosits,
    Generating,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SignRequestType {
    Sign,
    SignBidirectional,
    RespondBidirectional,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequestView {
    pub sign_id: String,
    pub sign_request_type: SignRequestType,
    pub status: SignRequestStatus,
    pub time_in_status_ms: u64,
    pub time_since_last_action_ms: u64,
    pub messages_sent: usize,
    pub messages_received: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedSignRequestView {
    pub sign_id: String,
    pub sign_request_type: SignRequestType,
    pub total_time_ms: u64,
    pub messages_sent: usize,
    pub messages_received: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeSignRequests {
    pub node_id: String,
    pub active: Vec<SignRequestView>,
    pub completed: Vec<CompletedSignRequestView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterView {
    pub nodes: Vec<NodeSignRequests>,
}

#[derive(Clone)]
struct AppState {
    node_urls: Vec<String>,
    cache: Arc<RwLock<ClusterView>>,
}

impl AppState {
    fn new(node_urls: Vec<String>) -> Self {
        Self {
            node_urls,
            cache: Arc::new(RwLock::new(ClusterView { nodes: vec![] })),
        }
    }

    async fn poll_nodes(&self) {
        let client = reqwest::Client::new();
        let mut nodes = Vec::new();

        for (idx, url) in self.node_urls.iter().enumerate() {
            let node_id = format!("node-{}", idx);
            
            let active = match client
                .get(format!("{}/visualizer/active", url))
                .timeout(Duration::from_secs(2))
                .send()
                .await
            {
                Ok(response) => response.json::<Vec<SignRequestView>>().await.unwrap_or_default(),
                Err(e) => {
                    tracing::warn!("Failed to fetch active requests from {}: {}", url, e);
                    vec![]
                }
            };

            let completed = match client
                .get(format!("{}/visualizer/completed", url))
                .timeout(Duration::from_secs(2))
                .send()
                .await
            {
                Ok(response) => response
                    .json::<Vec<CompletedSignRequestView>>()
                    .await
                    .unwrap_or_default(),
                Err(e) => {
                    tracing::warn!("Failed to fetch completed requests from {}: {}", url, e);
                    vec![]
                }
            };

            nodes.push(NodeSignRequests {
                node_id,
                active,
                completed,
            });
        }

        let view = ClusterView { nodes };
        *self.cache.write().await = view;
    }
}

async fn get_cluster_view(State(state): State<AppState>) -> impl IntoResponse {
    let view = state.cache.read().await.clone();
    Json(view)
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn polling_task(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    loop {
        interval.tick().await;
        state.poll_nodes().await;
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "visualizer=debug,tower_http=debug".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    
    let node_urls: Vec<String> = args.iter().skip(2).map(|s| s.to_string()).collect();
    
    if node_urls.is_empty() {
        eprintln!("Usage: visualizer <port> <node_url1> <node_url2> ...");
        std::process::exit(1);
    }

    tracing::info!("Starting visualizer on port {} with nodes: {:?}", port, node_urls);

    let state = AppState::new(node_urls);
    
    // Start polling task
    let poll_state = state.clone();
    tokio::spawn(async move {
        polling_task(poll_state).await;
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET])
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(health))
        .route("/api/cluster", get(get_cluster_view))
        .nest_service("/ui", ServeDir::new("visualizer/frontend/dist"))
        .layer(cors)
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("Visualizer listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}
