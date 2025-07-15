mod error;

use self::error::Error;
use crate::indexer::NearIndexer;
use crate::protocol::state::{NodeStateWatcher, NodeStatus};
use crate::protocol::sync::{SyncChannel, SyncUpdate};
use crate::storage::{PresignatureStorage, TripleStorage};
use crate::web::error::Result;

use anyhow::Context;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use axum_extra::extract::WithRejection;
use cait_sith::protocol::Participant;
use mpc_keys::hpke::Ciphered;
use near_primitives::types::BlockHeight;
use prometheus::{Encoder, TextEncoder};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::mpsc::Sender;

struct AxumState {
    sender: Sender<Ciphered>,
    node: NodeStateWatcher,
    indexer: Option<NearIndexer>,
    triple_storage: TripleStorage,
    presignature_storage: PresignatureStorage,
    sync_channel: SyncChannel,
}

pub async fn run(
    port: u16,
    sender: Sender<Ciphered>,
    node: NodeStateWatcher,
    indexer: Option<NearIndexer>,
    triple_storage: TripleStorage,
    presignature_storage: PresignatureStorage,
    sync_channel: SyncChannel,
) {
    tracing::info!("starting web server");
    let axum_state = AxumState {
        sender,
        node,
        indexer,
        triple_storage,
        presignature_storage,
        sync_channel,
    };

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
        .route("/metrics", get(metrics))
        .route("/sync", post(sync));

    if cfg!(feature = "bench") {
        router = router.route("/bench/metrics", get(bench_metrics));
    }

    let app = router.layer(Extension(Arc::new(axum_state)));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[tracing::instrument(level = "debug", skip_all)]
async fn msg(
    Extension(state): Extension<Arc<AxumState>>,
    WithRejection(Json(encrypted), _): WithRejection<Json<Vec<Ciphered>>, Error>,
) -> Result<()> {
    for encrypted in encrypted.into_iter() {
        if let Err(err) = state.sender.send(encrypted).await {
            tracing::error!(?err, "failed to forward an encrypted protocol message");
            return Err(Error::Internal(
                "failed to forward an encrypted protocol message",
            ));
        }
    }
    Ok(())
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
    },
    Joining {
        participants: Vec<Participant>,
        latest_block_height: BlockHeight,
    },
    NotRunning,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn state(Extension(web): Extension<Arc<AxumState>>) -> Result<Json<StateView>> {
    tracing::debug!("fetching state");

    // TODO: remove once we have integration tests built using other chains
    let latest_block_height = if let Some(indexer) = &web.indexer {
        indexer.last_processed_block().await.unwrap_or(0)
    } else {
        0
    };

    match web.node.status() {
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
        } => Ok(Json(StateView::Resharing {
            old_participants: old_participants.clone(),
            new_participants: new_participants.clone(),
            latest_block_height,
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
    }
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
    WithRejection(Json(update), _): WithRejection<Json<SyncUpdate>, Error>,
) -> Result<Json<()>> {
    state.sync_channel.request_update(update).await;
    Ok(Json(()))
}
