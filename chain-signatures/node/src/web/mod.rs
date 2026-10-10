mod cbor;
mod error;
#[cfg(test)]
pub mod mock;

#[cfg(feature = "debug-page")]
pub mod debug;

use self::error::Error;
use crate::backlog::{Backlog, Checkpoint};
use crate::metrics::messaging::WEB_ENDPOINT_LATENCY;
use crate::protocol::state::{NodeStateWatcher, NodeStatus};
use crate::protocol::sync::SyncChannel;
use crate::protocol::{Chain, MessageChannel};
use crate::storage::{PresignatureStorage, TripleStorage};
use crate::web::cbor::Cbor;
use crate::web::error::Result;

use anyhow::Context;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_extra::extract::WithRejection;
use mpc_keys::hpke::Ciphered;
use near_account_id::AccountId;
use prometheus::{Encoder, TextEncoder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::Instrument;

const MAX_CONCURRENT_CHECKPOINT_REQUESTS: usize = 8;
const CHECKPOINT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Each peer keeps at most one `/sync` in flight to us, so this leaves
/// headroom above the participant count while bounding unauthenticated work.
const MAX_CONCURRENT_SYNC_REQUESTS: usize = 16;

struct AxumState {
    node: NodeStateWatcher,
    /// Only used by the debug page.
    #[cfg_attr(not(feature = "debug-page"), allow(dead_code))]
    triple_storage: TripleStorage,
    #[cfg_attr(not(feature = "debug-page"), allow(dead_code))]
    presignature_storage: PresignatureStorage,
    sync_channel: SyncChannel,
    msg_channel: MessageChannel,
    /// Only used to label the debug page.
    #[cfg_attr(not(feature = "debug-page"), allow(dead_code))]
    my_account_id: AccountId,
    backlog: Backlog,
    /// Bounds concurrent `/checkpoint` lookups so the endpoint cannot starve
    /// the Redis pool the protocol shares.
    checkpoint_permits: Semaphore,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    port: u16,
    msg_channel: MessageChannel,
    node: NodeStateWatcher,
    triple_storage: TripleStorage,
    presignature_storage: PresignatureStorage,
    sync_channel: SyncChannel,
    my_account_id: AccountId,
    backlog: Backlog,
) {
    tracing::info!("starting web server");
    let axum_state = AxumState {
        msg_channel,
        node,
        triple_storage,
        presignature_storage,
        sync_channel,
        my_account_id,
        backlog,
        checkpoint_permits: Semaphore::new(MAX_CONCURRENT_CHECKPOINT_REQUESTS),
    };

    // Sync can be a large payload, so we set a higher limit for payload.
    // The concurrency limit runs before the body is read, so rejected
    // requests never buffer their payload.
    let sync = Router::new()
        .route("/sync", post(sync))
        .layer(DefaultBodyLimit::max(20 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            Arc::new(Semaphore::new(MAX_CONCURRENT_SYNC_REQUESTS)),
            limit_concurrency,
        ));

    let mut router = Router::new()
        // healthcheck endpoint
        .route(
            "/",
            get(|| async move {
                tracing::info!("node is ready to accept connections");
                StatusCode::OK
            }),
        )
        .route("/msg", post(msg))
        .route("/status", get(status))
        .route("/metrics", get(metrics))
        .route("/checkpoint", get(checkpoint))
        .route("/debug", get(debug::page))
        .merge(sync);

    if cfg!(feature = "bench") {
        router = router.route("/bench/metrics", get(bench_metrics));
    }

    let app = router
        .layer(middleware::from_fn(request_id_middleware))
        .layer(Extension(Arc::new(axum_state)));

    let addr = format!("0.0.0.0:{port}");
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(?addr, ?err, "failed to bind web server");
            return;
        }
    };

    tracing::info!(?addr, "starting http server");
    if let Err(err) = axum::serve(listener, app).await {
        tracing::error!(?addr, ?err, "web server exited with an error");
    }
}

/// Rejects the request with 503 when all `permits` are taken, holding one
/// for the whole request otherwise.
async fn limit_concurrency(
    State(permits): State<Arc<Semaphore>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let Ok(_permit) = permits.try_acquire() else {
        return Error::Busy.into_response();
    };
    next.run(req).await
}

async fn request_id_middleware(mut req: Request<Body>, next: Next) -> Response {
    let header_name = HeaderName::from_static("x-request-id");
    let request_id = req
        .headers()
        .get(&header_name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .unwrap_or_else(|| hex::encode(rand::random::<u128>().to_be_bytes()));

    req.extensions_mut().insert(request_id.clone());

    let span = tracing::info_span!("request", %request_id);
    let mut response = next.run(req).instrument(span).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(header_name, value);
    }
    response
}

#[tracing::instrument(level = "debug", skip_all)]
async fn msg(
    Extension(state): Extension<Arc<AxumState>>,
    WithRejection(Cbor(encrypted), _): WithRejection<Cbor<Vec<Ciphered>>, Error>,
) {
    let start = Instant::now();
    for encrypted in encrypted.into_iter() {
        let msg_channel = state.msg_channel.clone();
        tokio::spawn(async move {
            msg_channel.send_inbox(encrypted).await;
        });
    }
    WEB_ENDPOINT_LATENCY
        .with_label_values(&["msg"])
        .observe(start.elapsed().as_millis() as f64);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointResponse {
    #[serde(default)]
    pub version: u64,
    pub checkpoints: HashMap<Chain, Checkpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: NodeStatus,
    #[serde(default)]
    pub protocol_version: u64,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn status(Extension(web): Extension<Arc<AxumState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        status: web.node.status(),
        protocol_version: crate::PROTOCOL_VERSION,
    })
}

#[tracing::instrument(level = "debug", skip_all)]
async fn metrics() -> (StatusCode, String) {
    let grab_metrics = || {
        let encoder = TextEncoder::new();
        let mut buffer = vec![];
        encoder
            .encode(&prometheus::gather(), &mut buffer)
            .context("failed to encode metrics")?;

        let response =
            String::from_utf8(buffer).with_context(|| "failed to convert bytes to string")?;

        Ok::<String, anyhow::Error>(response)
    };

    match grab_metrics() {
        Ok(response) => (StatusCode::OK, response),
        Err(err) => {
            tracing::error!("failed to generate prometheus metrics: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to generate prometheus metrics".to_string(),
            )
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchMetrics {
    pub sig_gen: Vec<f64>,
    pub presig_gen: Vec<f64>,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn bench_metrics() -> Json<BenchMetrics> {
    Json(BenchMetrics {
        sig_gen: crate::metrics::protocols::SIGN_GENERATION_LATENCY.exact(),
        presig_gen: crate::metrics::protocols::PRESIGNATURE_LATENCY.exact(),
    })
}

#[tracing::instrument(level = "debug", skip_all)]
async fn sync(
    Extension(state): Extension<Arc<AxumState>>,
    WithRejection(Cbor(update), _): WithRejection<Cbor<Ciphered>, Error>,
) -> Result<Cbor<Ciphered>> {
    let start = Instant::now();
    let response = state.sync_channel.request_update(update).await?;
    WEB_ENDPOINT_LATENCY
        .with_label_values(&["sync"])
        .observe(start.elapsed().as_millis() as f64);
    Ok(Cbor(response))
}

type ChainAndDigest = (Chain, Option<[u8; 32]>);

#[derive(Debug, Deserialize)]
pub struct CheckpointQuery {
    /// Combined chain selection and digest filter. Entries are separated by commas.
    /// Examples:
    /// - `"Ethereum"` -> latest Ethereum checkpoint
    /// - `"Solana:0x<64 hex chars>"` -> specific Solana checkpoint by digest
    /// - `"Solana:0x...,Ethereum"` -> mix of filters
    #[serde(default)]
    query: Option<String>,
}

impl CheckpointQuery {
    #[allow(clippy::result_large_err)]
    fn parse(self) -> Result<Vec<ChainAndDigest>, Error> {
        let Some(query) = self.query else {
            return Ok(Chain::iter()
                .into_iter()
                .map(|chain| (chain, None))
                .collect());
        };

        let mut selections = Vec::new();
        for entry in query.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                return Err(Error::InvalidParameters(
                    "query parameter contains an empty segment".to_string(),
                ));
            }

            let mut parts = entry.splitn(2, ':');
            let chain_part = parts
                .next()
                .expect("splitn(2) always returns at least one part")
                .trim();
            let chain = chain_part.parse::<Chain>().map_err(|e| {
                Error::InvalidParameters(format!("Invalid chain '{}': {}", chain_part, e))
            })?;
            // One storage lookup per entry: cap the work a single request can trigger.
            if selections.iter().any(|(selected, _)| *selected == chain) {
                return Err(Error::InvalidParameters(format!(
                    "chain '{}' appears more than once",
                    chain_part
                )));
            }

            let digest = match parts.next() {
                Some(suffix) => {
                    let suffix = suffix.trim();
                    let hex = suffix.strip_prefix("0x").ok_or_else(|| {
                        Error::InvalidParameters(format!(
                            "Digest for '{}' must start with '0x' (got '{}').",
                            chain_part, suffix
                        ))
                    })?;
                    if hex.len() != 64 {
                        return Err(Error::InvalidParameters(format!(
                            "Digest for '{}' must be 64 hex chars, got {}.",
                            chain_part,
                            hex.len()
                        )));
                    }
                    let mut bytes = [0u8; 32];
                    hex::decode_to_slice(hex, &mut bytes).map_err(|e| {
                        Error::InvalidParameters(format!(
                            "Invalid hex digest for '{}': {}",
                            chain_part, e
                        ))
                    })?;
                    Some(bytes)
                }
                None => None,
            };

            selections.push((chain, digest));
        }

        Ok(selections)
    }
}

#[tracing::instrument(level = "debug", skip_all)]
async fn checkpoint(
    Extension(state): Extension<Arc<AxumState>>,
    Query(query): Query<CheckpointQuery>,
) -> Result<Cbor<CheckpointResponse>> {
    let start = Instant::now();

    let selections = query.parse()?;
    let _permit = state
        .checkpoint_permits
        .try_acquire()
        .map_err(|_| Error::Busy)?;

    let lookups = async {
        let mut resp = HashMap::new();
        for (chain, digest) in selections {
            let checkpoint = if let Some(digest) = digest {
                state.backlog.checkpoints().find(chain, digest).await
            } else {
                state
                    .backlog
                    .checkpoints()
                    .latest(chain)
                    .await
                    .ok()
                    .flatten()
            };

            let Some(checkpoint) = checkpoint else {
                tracing::debug!(?chain, ?digest, "unable to find checkpoint");
                continue;
            };

            resp.insert(chain, checkpoint);
        }
        resp
    };
    let resp = tokio::time::timeout(CHECKPOINT_REQUEST_TIMEOUT, lookups)
        .await
        .map_err(|_| Error::Busy)?;

    WEB_ENDPOINT_LATENCY
        .with_label_values(&["checkpoint"])
        .observe(start.elapsed().as_millis() as f64);

    Ok(Cbor(CheckpointResponse {
        version: crate::CHECKPOINT_VERSION,
        checkpoints: resp,
    }))
}

#[cfg(not(feature = "debug-page"))]
mod debug {
    pub async fn page() -> axum::response::Html<String> {
        "<html><body>Debug page disabled. Compile the node with --features=debug-page to show useful information here.</bod></html>".to_string().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(query: &str) -> Result<Vec<ChainAndDigest>, Error> {
        CheckpointQuery {
            query: Some(query.to_string()),
        }
        .parse()
    }

    #[test]
    fn checkpoint_query_rejects_repeated_chain() {
        assert!(parse("Ethereum,Solana").is_ok());
        assert!(parse("Ethereum,Ethereum").is_err());
        let digest = format!("0x{}", "00".repeat(32));
        assert!(parse(&format!("Solana:{digest},Solana")).is_err());
    }

    #[tokio::test]
    async fn limit_concurrency_rejects_over_limit() {
        use tokio::sync::Notify;

        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let handler = {
            let (started, release) = (started.clone(), release.clone());
            move || async move {
                started.notify_one();
                release.notified().await;
            }
        };
        let app = Router::new()
            .route("/", post(handler))
            .layer(middleware::from_fn_with_state(
                Arc::new(Semaphore::new(1)),
                limit_concurrency,
            ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();

        // The first request takes the only permit and blocks in the handler.
        let first = tokio::spawn(client.post(&url).send());
        started.notified().await;

        let resp = client.post(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        release.notify_one();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);

        // The permit is returned once the first request completes.
        release.notify_one();
        let resp = client.post(&url).send().await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
