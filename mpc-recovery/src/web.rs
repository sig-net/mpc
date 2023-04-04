use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use ractor::{concurrency::Duration, rpc::CallResult, ActorRef};
use serde::Deserialize;
use std::net::SocketAddr;

use crate::{
    actor::{NodeActor, NodeMessage},
    NodeId,
};

#[tracing::instrument(level = "debug", skip(node_actor))]
pub async fn serve(id: NodeId, port: u16, node_actor: ActorRef<NodeActor>) {
    let state = AppState { id, node_actor };

    let app = Router::new()
        .route("/submit", post(submit))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!(?addr, "starting a web server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Deserialize)]
struct SubmitPayload {
    payload: String,
}

#[derive(Clone)]
struct AppState {
    id: NodeId,
    node_actor: ActorRef<NodeActor>,
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.id))]
async fn submit(
    State(state): State<AppState>,
    Json(payload): Json<SubmitPayload>,
) -> (StatusCode, Json<String>) {
    tracing::info!(payload = payload.payload, "submit request");

    match state
        .node_actor
        .call(
            |tx| NodeMessage::NewRequest(payload.payload.bytes().collect(), tx),
            Some(Duration::from_millis(2000)),
        )
        .await
    {
        Ok(call_result) => match call_result {
            CallResult::Success(sig_response) => (
                StatusCode::OK,
                Json(hex::encode(sig_response.sig.to_bytes())),
            ),
            CallResult::Timeout => {
                tracing::error!("failed due to timeout");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json("timeout".to_string()),
                )
            }
            CallResult::SenderError => {
                tracing::error!("failed due to sender error (did not get a response)");
                (StatusCode::INTERNAL_SERVER_ERROR, Json("error".to_string()))
            }
        },
        Err(e) => {
            tracing::error!("failed due to messaging error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json("error".to_string()))
        }
    }
}
