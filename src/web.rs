use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use ractor::{concurrency::Duration, ActorRef};
use serde::Deserialize;
use std::net::SocketAddr;

use crate::actor::{NodeActor, NodeMessage};

pub async fn start(port: u16, node_actor: ActorRef<NodeActor>) {
    let state = AppState { node_actor };

    // build our application with a route
    let app = Router::new()
        .route("/submit", post(submit))
        .with_state(state);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// the input to our `submit` handler
#[derive(Deserialize)]
struct SubmitPayload {
    payload: String,
}

#[derive(Clone)]
struct AppState {
    node_actor: ActorRef<NodeActor>,
}

async fn submit(
    State(state): State<AppState>,
    // this argument tells axum to parse the request body
    // as JSON into a `CreateUser` type
    Json(payload): Json<SubmitPayload>,
) -> (StatusCode, Json<String>) {
    let sig_response = state
        .node_actor
        .call(
            |tx| NodeMessage::NewRequest(payload.payload.bytes().collect(), tx),
            Some(Duration::from_millis(2000)),
        )
        .await
        .unwrap()
        .unwrap();

    // this will be converted into a JSON response
    // with a status code of `201 Created`
    (
        StatusCode::OK,
        Json(hex::encode(sig_response.sig.to_bytes())),
    )
}
