use crate::client::NearRpcAndRelayerClient;
use crate::key_recovery::{get_user_recovery_pk, get_user_recovery_sk};
use crate::msg::{
    AddKeyRequest, AddKeyResponse, LeaderRequest, LeaderResponse, NewAccountRequest,
    NewAccountResponse, SigShareRequest, SigShareResponse,
};
use crate::oauth::{IdTokenClaims, OAuthTokenVerifier, UniversalTokenVerifier};
use crate::primitives::InternalAccountId;
use crate::transaction::{
    get_add_key_delegate_action, get_create_account_delegate_action, get_signed_delegated_action,
};
use crate::NodeId;
use axum::http::HeaderValue;
use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use futures::stream::FuturesUnordered;
use hyper::client::ResponseFuture;
use hyper::{Body, Client, Method, Request};
use near_crypto::{PublicKey, SecretKey};
use near_primitives::types::AccountId;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use threshold_crypto::{PublicKeySet, SecretKeyShare};
use tower_http::cors::Any;

pub struct Config {
    pub id: NodeId,
    pub pk_set: PublicKeySet,
    pub sk_share: SecretKeyShare,
    pub port: u16,
    pub sign_nodes: Vec<String>,
    pub near_rpc: String,
    pub relayer_url: String,
    pub account_creator_id: AccountId,
    // TODO: temporary solution
    pub account_creator_sk: SecretKey,
}

pub async fn run(config: Config) {
    let Config {
        id,
        pk_set,
        sk_share,
        port,
        sign_nodes,
        near_rpc,
        relayer_url,
        account_creator_id,
        account_creator_sk,
    } = config;
    let _span = tracing::debug_span!("run", id, port);
    tracing::debug!(?sign_nodes, "running a leader node");

    if pk_set.public_key_share(id) != sk_share.public_key_share() {
        tracing::error!("provided secret share does not match the node id");
        return;
    }

    let client = NearRpcAndRelayerClient::connect(&near_rpc, relayer_url);
    client
        .register_account_with_relayer(account_creator_id.clone())
        .await
        .unwrap();

    let state = LeaderState {
        id,
        pk_set,
        sk_share,
        sign_nodes,
        client,
        account_creator_id,
        account_creator_sk,
    };

    let cors_layer = tower_http::cors::CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap()) //TODO: now secure, allow only for testnet
        .allow_origin(
            "https://near-discovery-asq5uacgk-near-developer-console.vercel.app/"
                .parse::<HeaderValue>()
                .unwrap(),
        )
        .allow_origin("https://alpha.near.org/".parse::<HeaderValue>().unwrap())
        .allow_origin("https://near.org/".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::POST])
        .allow_headers(Any); // TODO: doublecheck what can be allowed here

    let app = Router::new()
        .route("/submit", post(submit::<UniversalTokenVerifier>))
        .route("/new_account", post(new_account::<UniversalTokenVerifier>))
        .route("/add_key", post(add_key::<UniversalTokenVerifier>))
        .layer(Extension(state))
        .layer(cors_layer);

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
    client: NearRpcAndRelayerClient,
    account_creator_id: AccountId,
    // TODO: temporary solution
    account_creator_sk: SecretKey,
}

async fn parse(response_future: ResponseFuture) -> anyhow::Result<SigShareResponse> {
    let response = response_future.await?;
    let response_body = hyper::body::to_bytes(response.into_body()).await?;
    Ok(serde_json::from_slice(&response_body)?)
}

async fn process_new_account(
    state: &LeaderState,
    request: &NewAccountRequest,
    internal_acc_id: InternalAccountId,
) -> anyhow::Result<(StatusCode, Json<NewAccountResponse>)> {
    // Get nonce and recent block hash
    let nonce = state
        .client
        .access_key_nonce(
            state.account_creator_id.clone(),
            state.account_creator_sk.public_key(),
        )
        .await?;
    let block_height = state.client.latest_block_height().await?;

    // Create a transaction to create new NEAR account
    let new_user_account_pk: PublicKey = request.public_key.clone().parse()?;
    let new_user_account_id: AccountId = request.near_account_id.clone().parse()?;

    let delegate_action = get_create_account_delegate_action(
        state.account_creator_id.clone(),
        state.account_creator_sk.public_key(),
        new_user_account_id.clone(),
        get_user_recovery_pk(internal_acc_id),
        new_user_account_pk,
        crate::transaction::NetworkType::Testnet,
        nonce + 1,
        block_height + 100,
    )?;
    let signed_delegate_action = get_signed_delegated_action(
        delegate_action,
        state.account_creator_id.clone(),
        state.account_creator_sk.clone(),
    );

    state
        .client
        .register_account_with_relayer(new_user_account_id)
        .await?;

    state
        .client
        .send_tx_via_relayer(signed_delegate_action)
        .await?;

    Ok((StatusCode::OK, Json(NewAccountResponse::Ok)))
}

pub fn get_internal_account_id(claims: IdTokenClaims) -> InternalAccountId {
    format!("{}:{}", claims.iss, claims.sub)
}

#[tracing::instrument(level = "info", skip_all, fields(id = state.id))]
async fn new_account<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<NewAccountRequest>,
) -> (StatusCode, Json<NewAccountResponse>) {
    tracing::info!(
        access_token = format!("{:.5}...", request.oidc_token),
        "new request"
    );

    match T::verify_token(&request.oidc_token).await {
        Ok(claims) => {
            tracing::info!("access token is valid");
            match process_new_account(&state, &request, get_internal_account_id(claims)).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!(err = ?e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(NewAccountResponse::Err {
                            msg: format!("failed to process new account: {}", e),
                        }),
                    )
                }
            }
        }
        Err(e) => {
            tracing::error!("access token verification failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(NewAccountResponse::Err {
                    msg: format!("access token verification failed: {}", e),
                }),
            )
        }
    }
}

async fn process_add_key(
    state: &LeaderState,
    request: &AddKeyRequest,
    internal_acc_id: InternalAccountId,
) -> anyhow::Result<(StatusCode, Json<AddKeyResponse>)> {
    let user_account_id: AccountId = request.near_account_id.parse()?;

    // Get nonce and recent block hash
    let nonce = state
        .client
        .access_key_nonce(
            user_account_id.clone(),
            get_user_recovery_pk(internal_acc_id.clone()).clone(),
        )
        .await?;
    let block_height = state.client.latest_block_height().await?;

    // Create a transaction to create a new account
    let new_public_key: PublicKey = request.public_key.clone().parse()?;

    let max_block_height: u64 = block_height + 100;

    let delegate_action = get_add_key_delegate_action(
        user_account_id.clone(),
        get_user_recovery_pk(internal_acc_id.clone()),
        new_public_key,
        nonce + 1,
        max_block_height,
    )?;
    let signed_delegate_action = get_signed_delegated_action(
        delegate_action,
        user_account_id,
        get_user_recovery_sk(internal_acc_id),
    );

    state
        .client
        .send_tx_via_relayer(signed_delegate_action)
        .await?;

    Ok((StatusCode::OK, Json(AddKeyResponse::Ok)))
}

#[tracing::instrument(level = "info", skip_all, fields(id = state.id))]
async fn add_key<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<AddKeyRequest>,
) -> (StatusCode, Json<AddKeyResponse>) {
    tracing::info!(
        access_token = format!("{:.5}...", request.oidc_token),
        public_key = hex::encode(request.public_key.clone()),
        "new request"
    );

    match T::verify_token(&request.oidc_token).await {
        Ok(claims) => {
            tracing::info!("access token is valid");
            match process_add_key(&state, &request, get_internal_account_id(claims)).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!(err = ?e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(AddKeyResponse::Err {
                            msg: "internal error".to_string(),
                        }),
                    )
                }
            }
        }
        Err(_) => {
            tracing::error!("access token verification failed");
            (
                StatusCode::UNAUTHORIZED,
                Json(AddKeyResponse::Err {
                    msg: "access token verification failed".into(),
                }),
            )
        }
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.id))]
async fn submit<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<LeaderRequest>,
) -> (StatusCode, Json<LeaderResponse>) {
    tracing::info!(payload = request.payload, "submit request");

    // TODO: extract access token from payload
    let access_token = "validToken";
    match T::verify_token(access_token).await {
        Ok(_) => {
            tracing::info!("access token is valid");
            // continue execution
        }
        Err(_) => {
            tracing::error!("access token verification failed");
            return (StatusCode::UNAUTHORIZED, Json(LeaderResponse::Err));
        }
    }

    let sig_share_request = SigShareRequest {
        payload: request.payload.clone(),
    };
    let payload_json = match serde_json::to_string(&sig_share_request) {
        Ok(payload_json) => payload_json,
        Err(err) => {
            tracing::error!(%err, "failed to convert payload back to json");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(LeaderResponse::Err));
        }
    };

    let response_futures = FuturesUnordered::new();
    for sign_node in state.sign_nodes {
        let req = match Request::builder()
            .method(Method::POST)
            .uri(format!("{}/sign", sign_node))
            .header("content-type", "application/json")
            .body(Body::from(payload_json.clone()))
        {
            Ok(req) => req,
            Err(err) => {
                tracing::error!(%err, "failed to construct a compute request");
                continue;
            }
        };

        let client = Client::new();
        response_futures.push(client.request(req));
    }

    let mut sig_shares = BTreeMap::new();
    sig_shares.insert(state.id, state.sk_share.sign(&request.payload));
    for response_future in response_futures {
        let (node_id, sig_share) = match parse(response_future).await {
            Ok(response) => match response {
                SigShareResponse::Ok { node_id, sig_share } => (node_id, sig_share),
                SigShareResponse::Err => {
                    tracing::error!("Received an error response");
                    continue;
                }
            },
            Err(err) => {
                tracing::error!(%err, "Failed to get response");
                continue;
            }
        };

        if state
            .pk_set
            .public_key_share(node_id)
            .verify(&sig_share, &request.payload)
        {
            match sig_shares.entry(node_id) {
                Entry::Vacant(e) => {
                    tracing::debug!(?sig_share, "received valid signature share");
                    e.insert(sig_share);
                }
                Entry::Occupied(e) if e.get() == &sig_share => {
                    tracing::error!(
                        node_id,
                        sig_share = ?e.get(),
                        "received a duplicate share"
                    );
                }
                Entry::Occupied(e) => {
                    tracing::error!(
                        node_id = node_id,
                        sig_share_1 = ?e.get(),
                        sig_share_2 = ?sig_share,
                        "received two different valid shares for the same node (should be impossible)"
                    );
                }
            }
        } else {
            tracing::error!("received invalid signature",);
        }

        if sig_shares.len() > state.pk_set.threshold() {
            tracing::debug!(
                "received {} valid signature shares, not waiting for the rest",
                sig_shares.len()
            );
            break;
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
