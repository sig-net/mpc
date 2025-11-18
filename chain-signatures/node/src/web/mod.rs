mod cbor;
mod error;
#[cfg(test)]
pub mod mock;

#[cfg(feature = "debug-page")]
pub mod debug;

use self::error::Error;
use crate::backlog::{Backlog, Checkpoint};
use crate::indexer::NearIndexer;
use crate::metrics::WEB_ENDPOINT_LATENCY;
use crate::protocol::state::{NodeStateWatcher, NodeStatus, ResharingStatus};
use crate::protocol::sync::{SyncChannel, SyncUpdate};
use crate::protocol::{Chain, MessageChannel};
use crate::storage::{PresignatureStorage, TripleStorage};
use crate::web::cbor::Cbor;
use crate::web::error::Result;

use anyhow::Context;
use axum::extract::{DefaultBodyLimit, Query};
use axum::http::StatusCode;
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

struct AxumState {
    node: NodeStateWatcher,
    indexer: Option<NearIndexer>,
    triple_storage: TripleStorage,
    presignature_storage: PresignatureStorage,
    sync_channel: SyncChannel,
    msg_channel: MessageChannel,
    my_account_id: AccountId,
    backlog: Backlog,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    port: u16,
    msg_channel: MessageChannel,
    node: NodeStateWatcher,
    indexer: Option<NearIndexer>,
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
        indexer,
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

    let app = router.layer(Extension(Arc::new(axum_state)));

    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!(?addr, "starting http server");
    axum::serve(listener, app).await.unwrap();
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
            if let Err(err) = msg_channel.inbox.send(encrypted).await {
                tracing::error!(?err, "failed to forward an encrypted protocol message");
            }
        });
    }
    WEB_ENDPOINT_LATENCY
        .with_label_values(&["msg", state.my_account_id.as_str()])
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

    // TODO: remove once we have integration tests built using other chains
    let latest_block_height = if let Some(indexer) = &web.indexer {
        indexer.last_processed_block().await.unwrap_or(0)
    } else {
        0
    };

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
        .with_label_values(&["state", web.my_account_id.as_str()])
        .observe(start.elapsed().as_millis() as f64);
    result
}

#[tracing::instrument(level = "debug", skip_all)]
async fn status(Extension(web): Extension<Arc<AxumState>>) -> Json<NodeStatus> {
    Json(web.node.status())
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
    pub sig_respond: Vec<f64>,
    pub presig_gen: Vec<f64>,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn bench_metrics() -> Json<BenchMetrics> {
    Json(BenchMetrics {
        sig_gen: crate::metrics::SIGN_GENERATION_LATENCY.exact(),
        sig_respond: crate::metrics::SIGN_RESPOND_LATENCY.exact(),
        presig_gen: crate::metrics::PRESIGNATURE_LATENCY.exact(),
    })
}

#[tracing::instrument(level = "debug", skip_all)]
async fn sync(
    Extension(state): Extension<Arc<AxumState>>,
    WithRejection(Cbor(update), _): WithRejection<Cbor<SyncUpdate>, Error>,
) -> Result<Json<()>> {
    let start = Instant::now();
    state.sync_channel.request_update(update).await;
    WEB_ENDPOINT_LATENCY
        .with_label_values(&["sync", state.my_account_id.as_str()])
        .observe(start.elapsed().as_millis() as f64);
    Ok(Json(()))
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
        .with_label_values(&["checkpoint", state.my_account_id.as_str()])
        .observe(start.elapsed().as_millis() as f64);

    Ok(Cbor(resp))
}

#[cfg(not(feature = "debug-page"))]
mod debug {
    pub async fn page() -> axum::response::Html<String> {
        format!("<html><body>Debug page disabled. Compile the node with --features=debug-page to show useful information here.</bod></html>").into()
    }
}
