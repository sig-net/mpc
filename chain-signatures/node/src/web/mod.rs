mod cbor;
mod error;
#[cfg(test)]
pub mod mock;

#[cfg(feature = "debug-page")]
pub mod debug;

use self::error::Error;
use crate::backlog::{Backlog, Checkpoint};
use crate::metrics::messaging::WEB_ENDPOINT_LATENCY;
use crate::protocol::state::{NodeStateWatcher, NodeStatus, ResharingStatus};
use crate::protocol::sync::{SyncChannel, SyncUpdate};
use crate::protocol::{Chain, MessageChannel};
use crate::storage::{PresignatureStorage, TripleStorage};
use crate::web::cbor::Cbor;
use crate::web::error::Result;

use anyhow::Context;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Query};
use axum::http::{HeaderName, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_extra::extract::WithRejection;
use cait_sith::protocol::Participant;
use mpc_keys::hpke::Ciphered;
use near_account_id::AccountId;
use near_primitives::types::BlockHeight;
use prometheus::{Encoder, TextEncoder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::Instrument;

struct AxumState {
    node: NodeStateWatcher,
    triple_storage: TripleStorage,
    presignature_storage: PresignatureStorage,
    sync_channel: SyncChannel,
    msg_channel: MessageChannel,
    #[allow(dead_code)] // used by debug-page
    my_account_id: AccountId,
    backlog: Backlog,
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
    };

    // Sync can be a large payload, so we set a higher limit for payload.
    let sync = Router::new()
        .route("/sync", post(sync))
        .layer(DefaultBodyLimit::max(20 * 1024 * 1024));

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
        .route("/state", get(state))
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StateView {
    Running {
        participants: Vec<Participant>,
        triple_count: usize,
        triple_mine_count: usize,
        triple_potential_count: usize,
        presignature_count: usize,
        presignature_mine_count: usize,
        presignature_potential_count: usize,
        latest_block_height: BlockHeight,
    },
    Resharing {
        old_participants: Vec<Participant>,
        new_participants: Vec<Participant>,
        latest_block_height: BlockHeight,
        phase: ResharingStatus,
    },
    Joining {
        participants: Vec<Participant>,
        latest_block_height: BlockHeight,
    },
    NotRunning,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn state(Extension(web): Extension<Arc<AxumState>>) -> Result<Json<StateView>> {
    let start = Instant::now();
    tracing::debug!("fetching state");

    // TODO: decide whether to keep latest_block_height in /state or not. We could use it for showing
    // whatever block height our governance chain is on but with multiple chains, it doesn't have much
    // of a use.
    let latest_block_height = 0;

    let result = match web.node.status() {
        NodeStatus::Running {
            me,
            participants,
            ongoing_triple_gen,
            ongoing_presignature_gen,
        } => {
            let triple_count = web.triple_storage.len_generated().await;
            let triple_mine_count = web.triple_storage.len_by_owner(me).await;
            let triple_potential_count = triple_count + ongoing_triple_gen;
            let presignature_count = web.presignature_storage.len_generated().await;
            let presignature_mine_count = web.presignature_storage.len_by_owner(me).await;
            let presignature_potential_count = presignature_count + ongoing_presignature_gen;

            Ok(Json(StateView::Running {
                participants: participants.clone(),
                triple_count,
                triple_mine_count,
                triple_potential_count,
                presignature_count,
                presignature_mine_count,
                presignature_potential_count,
                latest_block_height,
            }))
        }
        NodeStatus::Resharing {
            old_participants,
            new_participants,
            phase,
        } => Ok(Json(StateView::Resharing {
            old_participants: old_participants.clone(),
            new_participants: new_participants.clone(),
            latest_block_height,
            phase,
        })),
        NodeStatus::Joining { participants } => Ok(Json(StateView::Joining {
            participants: participants.clone(),
            latest_block_height,
        })),
        NodeStatus::Generating { .. }
        | NodeStatus::WaitingForConsensus { .. }
        | NodeStatus::Started
        | NodeStatus::Starting => {
            tracing::debug!("not running, state unavailable");
            Ok(Json(StateView::NotRunning))
        }
    };
    WEB_ENDPOINT_LATENCY
        .with_label_values(&["state"])
        .observe(start.elapsed().as_millis() as f64);
    result
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
    WithRejection(Cbor(update), _): WithRejection<Cbor<SyncUpdate>, Error>,
) -> Result<Cbor<SyncUpdate>> {
    let start = Instant::now();
    let response = state.sync_channel.request_update(update).await?;
    WEB_ENDPOINT_LATENCY
        .with_label_values(&["sync"])
        .observe(start.elapsed().as_millis() as f64);
    Ok(Cbor(response))
}

#[derive(Debug, Deserialize)]
pub struct CheckpointQuery {
    /// Combined chain selection and hash filter. Entries are separated by commas.
    /// Examples:
    /// - "Ethereum" -> latest Ethereum checkpoint
    /// - "Solana:1234" -> specific Solana checkpoint by hash
    /// - "Solana:1234,Ethereum" -> mix of filters
    #[serde(default)]
    query: Option<String>,
}

impl CheckpointQuery {
    #[allow(clippy::result_large_err)]
    fn parse(self) -> Result<Vec<(Chain, Option<u64>)>, Error> {
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

            let hash = match parts.next() {
                Some(hash_part) => {
                    let hash_part = hash_part.trim();
                    if hash_part.is_empty() {
                        return Err(Error::InvalidParameters(format!(
                            "Invalid hash format for '{}'. Expected 'chain:hash'",
                            chain_part
                        )));
                    }

                    Some(hash_part.parse::<u64>().map_err(|e| {
                        Error::InvalidParameters(format!("Invalid hash '{}': {}", hash_part, e))
                    })?)
                }
                None => None,
            };

            selections.push((chain, hash));
        }

        Ok(selections)
    }
}

#[tracing::instrument(level = "debug", skip_all)]
async fn checkpoint(
    Extension(state): Extension<Arc<AxumState>>,
    Query(query): Query<CheckpointQuery>,
) -> Result<Cbor<HashMap<Chain, Checkpoint>>> {
    let start = Instant::now();
    let selections = query.parse()?;
    let mut resp = HashMap::new();
    for (chain, hash) in selections {
        let checkpoint = if let Some(hash) = hash {
            state.backlog.find_checkpoint_by_hash(chain, hash).await
        } else {
            state.backlog.latest_checkpoint(chain).await
        };

        let Some(checkpoint) = checkpoint else {
            tracing::warn!(?chain, ?hash, "unable to find checkpoint");
            continue;
        };

        resp.insert(chain, checkpoint);
    }

    WEB_ENDPOINT_LATENCY
        .with_label_values(&["checkpoint"])
        .observe(start.elapsed().as_millis() as f64);

    Ok(Cbor(resp))
}

#[cfg(not(feature = "debug-page"))]
mod debug {
    pub async fn page() -> axum::response::Html<String> {
        "<html><body>Debug page disabled. Compile the node with --features=debug-page to show useful information here.</bod></html>".to_string().into()
    }
}
