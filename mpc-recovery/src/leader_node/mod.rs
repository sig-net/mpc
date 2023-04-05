use crate::msg::{LeaderRequest, LeaderResponse, SigShareRequest, SigShareResponse};
use crate::NodeId;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use futures::TryFutureExt;
use hyper::{Body, Client, Method, Request};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use threshold_crypto::{PublicKeySet, SecretKeyShare};

#[tracing::instrument(level = "debug", skip(pk_set, sk_share, sign_nodes))]
pub async fn run(
    id: NodeId,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
    port: u16,
    sign_nodes: Vec<String>,
) {
    tracing::debug!(?sign_nodes, "running a leader node");

    if pk_set.public_key_share(id) != sk_share.public_key_share() {
        tracing::error!("provided secret share does not match the node id");
        return;
    }

    let state = LeaderState {
        id,
        pk_set,
        sk_share,
        sign_nodes,
    };

    let app = Router::new()
        .route("/submit", post(submit))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Clone)]
struct LeaderState {
    id: NodeId,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
    sign_nodes: Vec<String>,
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.id))]
async fn submit(
    State(state): State<LeaderState>,
    Json(request): Json<LeaderRequest>,
) -> (StatusCode, Json<LeaderResponse>) {
    tracing::info!(payload = request.payload, "submit request");

    // TODO: run some check that the payload makes sense, fail if not
    tracing::debug!("approved");

    let sig_share_request = SigShareRequest {
        payload: request.payload.clone(),
    };
    let payload_json = match serde_json::to_string(&sig_share_request) {
        Ok(payload_json) => payload_json,
        Err(err) => {
            tracing::error!(?err, "failed to convert payload back to json");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(LeaderResponse::Err));
        }
    };

    let mut response_futures = Vec::new();
    for sign_node in state.sign_nodes {
        let req = match Request::builder()
            .method(Method::POST)
            .uri(format!("{}/sign", sign_node))
            .header("content-type", "application/json")
            .body(Body::from(payload_json.clone()))
        {
            Ok(req) => req,
            Err(err) => {
                tracing::error!(?err, "failed to construct a compute request");
                continue;
            }
        };

        let client = Client::new();
        response_futures.push(
            client
                .request(req)
                .and_then(|r| hyper::body::to_bytes(r.into_body())),
        );
    }

    let responses = futures::future::join_all(response_futures).await;
    tracing::debug!("got {} total responses back", responses.len());

    let successful_responses = responses
        .into_iter()
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    tracing::debug!("got {} successful responses", successful_responses.len());

    let mut sig_shares = BTreeMap::new();
    sig_shares.insert(state.id, state.sk_share.sign(&request.payload));
    for response in successful_responses {
        let response: SigShareResponse = match serde_json::from_slice(&response) {
            Ok(response) => response,
            Err(err) => {
                tracing::error!(
                    ?err,
                    "failed to parse HTTP response as a valid SigShareResponse"
                );
                continue;
            }
        };
        if state
            .pk_set
            .public_key_share(response.node_id)
            .verify(&response.sig_share, &request.payload)
        {
            match sig_shares.entry(response.node_id) {
                Entry::Vacant(e) => {
                    e.insert(response.sig_share);
                }
                Entry::Occupied(e) if e.get() == &response.sig_share => {
                    tracing::error!(
                        node_id = response.node_id,
                        sig_share = ?e.get(),
                        "received a duplicate share"
                    );
                }
                Entry::Occupied(e) => {
                    tracing::error!(
                        node_id = response.node_id,
                        sig_share_1 = ?e.get(),
                        sig_share_2 = ?response.sig_share,
                        "received two different valid shares for the same node (should be impossible)"
                    );
                }
            }
        } else {
            tracing::error!(?response, "received invalid signature",);
        }
    }
    let sig_shares_num = sig_shares.len();
    tracing::debug!("got {} valid signature shares", sig_shares_num);

    if let Ok(signature) = state.pk_set.combine_signatures(&sig_shares) {
        tracing::debug!(?signature, "replying with full signature");
        (StatusCode::OK, Json(LeaderResponse::Ok { signature }))
    } else {
        tracing::error!(
            "expected to get at least {} shares, but only got {}",
            state.pk_set.threshold() + 1,
            sig_shares_num
        );
        (StatusCode::INTERNAL_SERVER_ERROR, Json(LeaderResponse::Err))
    }
}
