mod error;

use self::error::Error;
use crate::indexer::Indexer;
use crate::protocol::NodeState;
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
use tokio::sync::{mpsc::Sender, RwLock};

struct AxumState {
    sender: Sender<Ciphered>,
    protocol_state: Arc<RwLock<NodeState>>,
    indexer: Indexer,
}

pub async fn run(
    port: u16,
    sender: Sender<Ciphered>,
    protocol_state: Arc<RwLock<NodeState>>,
    indexer: Indexer,
) -> anyhow::Result<()> {
    tracing::info!("running a node");
    let axum_state = AxumState {
        sender,
        protocol_state,
        indexer,
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
        .route("/metrics", get(metrics));

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

    Ok(())
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
        is_stable: bool,
    },
    Resharing {
        old_participants: Vec<Participant>,
        new_participants: Vec<Participant>,
        latest_block_height: BlockHeight,
        is_stable: bool,
    },
    Joining {
        participants: Vec<Participant>,
        latest_block_height: BlockHeight,
    },
    NotRunning,
}

#[tracing::instrument(level = "debug", skip_all)]
async fn state(Extension(state): Extension<Arc<AxumState>>) -> Result<Json<StateView>> {
    tracing::debug!("fetching state");
    // TODO: rename to last_processed_block when making other breaking changes
    let latest_block_height = state.indexer.last_processed_block().await.unwrap_or(0);
    let is_stable = state.indexer.is_stable().await;
    let protocol_state = state.protocol_state.read().await;

    match &*protocol_state {
        NodeState::Running(state) => {
            let triple_potential_count = state.triple_manager.len_potential().await;
            let triple_count = state.triple_manager.len_generated().await;
            let triple_mine_count = state.triple_manager.len_mine().await;
            let presignature_read = state.presignature_manager.read().await;
            let presignature_count = presignature_read.len_generated().await;
            let presignature_mine_count = presignature_read.len_mine().await;
            let presignature_potential_count = presignature_read.len_potential().await;
            let participants = state.participants.keys_vec();

            Ok(Json(StateView::Running {
                participants,
                triple_count,
                triple_mine_count,
                triple_potential_count,
                presignature_count,
                presignature_mine_count,
                presignature_potential_count,
                latest_block_height,
                is_stable,
            }))
        }
        NodeState::Resharing(state) => {
            let old_participants = state.old_participants.keys_vec();
            let new_participants = state.new_participants.keys_vec();
            Ok(Json(StateView::Resharing {
                old_participants,
                new_participants,
                latest_block_height,
                is_stable,
            }))
        }
        NodeState::Joining(state) => {
            let participants = state.participants.keys_vec();
            Ok(Json(StateView::Joining {
                participants,
                latest_block_height,
            }))
        }
        _ => {
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
