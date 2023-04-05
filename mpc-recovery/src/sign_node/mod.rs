use crate::msg::{SigShareRequest, SigShareResponse};
use crate::NodeId;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use std::net::SocketAddr;
use threshold_crypto::{PublicKeySet, SecretKeyShare};

#[tracing::instrument(level = "debug", skip(pk_set, sk_share))]
pub async fn run(id: NodeId, pk_set: PublicKeySet, sk_share: SecretKeyShare, port: u16) {
    tracing::debug!("running a sign node");

    if pk_set.public_key_share(id) != sk_share.public_key_share() {
        tracing::error!("provided secret share does not match the node id");
        return;
    }

    let state = SignNodeState {
        id,
        pk_set,
        sk_share,
    };

    let app = Router::new().route("/sign", post(sign)).with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Clone)]
struct SignNodeState {
    id: NodeId,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.id))]
async fn sign(
    State(state): State<SignNodeState>,
    Json(request): Json<SigShareRequest>,
) -> (StatusCode, Json<SigShareResponse>) {
    tracing::info!(payload = request.payload, "sign request");

    // TODO: run some check that the payload makes sense, fail if not
    tracing::debug!("approved");

    let response = SigShareResponse {
        node_id: state.id,
        sig_share: state.sk_share.sign(request.payload),
    };
    (StatusCode::OK, Json(response))
}
