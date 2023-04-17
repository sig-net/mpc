use crate::client::NearRpcClient;
use crate::key_recovery::{get_user_recovery_pk, get_user_recovery_sk};
use crate::msg::{
    AddKeyRequest, AddKeyResponse, LeaderRequest, LeaderResponse, NewAccountRequest,
    NewAccountResponse, SigShareRequest, SigShareResponse,
};
use crate::oauth::{OAuthTokenVerifier, UniversalTokenVerifier};
use crate::primitives::InternalAccountId;
use crate::transaction::{
    get_add_key_delegate_action, get_create_account_delegate_action, get_signed_delegated_action,
};
use crate::NodeId;
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

#[tracing::instrument(level = "debug", skip(pk_set, sk_share, sign_nodes, root_secret_key))]
pub async fn run(
    id: NodeId,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
    port: u16,
    sign_nodes: Vec<String>,
    // TODO: temporary solution
    root_secret_key: ed25519_dalek::SecretKey,
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
        client: NearRpcClient::testnet(),
        root_secret_key,
    };

    let app = Router::new()
        .route("/submit", post(submit::<UniversalTokenVerifier>))
        .route("/new_account", post(new_account::<UniversalTokenVerifier>))
        .route("/add_key", post(add_key::<UniversalTokenVerifier>))
        .layer(Extension(state));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

struct LeaderState {
    id: NodeId,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
    sign_nodes: Vec<String>,
    client: NearRpcClient,
    // TODO: temporary solution
    root_secret_key: ed25519_dalek::SecretKey,
}

impl Clone for LeaderState {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            pk_set: self.pk_set.clone(),
            sk_share: self.sk_share.clone(),
            sign_nodes: self.sign_nodes.clone(),
            client: self.client.clone(),
            root_secret_key: ed25519_dalek::SecretKey::from_bytes(self.root_secret_key.as_bytes())
                .unwrap(),
        }
    }
}

async fn parse(response_future: ResponseFuture) -> anyhow::Result<SigShareResponse> {
    let response = response_future.await?;
    let response_body = hyper::body::to_bytes(response.into_body()).await?;
    Ok(serde_json::from_slice(&response_body)?)
}

async fn process_new_account(
    state: &LeaderState,
    request: &NewAccountRequest,
) -> anyhow::Result<(StatusCode, Json<NewAccountResponse>)> {
    // This is the account that is doing the function calls to creates new accounts.
    // TODO: Create such an account for testnet and mainnet in a secure way
    // TODO: Store this account secret key in GCP Secret Manager
    let account_creator_id: AccountId = "tmp_acount_creator.serhii.testnet".parse().unwrap();
    let account_creator_sk: SecretKey = "ed25519:5pFJN3czPAHFWHZYjD4oTtnJE7PshLMeTkSU7CmWkvLaQWchCLgXGF1wwcJmh2AQChGH85EwcL5VW7tUavcAZDSG".parse().unwrap();
    let account_creator_pk: PublicKey = "ed25519:3BUQYE4ZfQ6A94CqCtAbdLURxo4eHv2L8JjC2KiXXdFn"
        .parse()
        .unwrap();

    // Get nonce and recent block hash
    let nonce = state
        .client
        .access_key_nonce(account_creator_id.clone(), account_creator_pk.clone())
        .await?;
    let block_height = state.client.latest_block_height().await?;

    // Create a transaction to create new NEAR account
    let new_user_account_id: AccountId = request.account_id.clone().parse().unwrap();
    let internal_user_id: InternalAccountId = "tmp".parse().unwrap(); // TODO:get real user id from ID token

    let delegate_action = get_create_account_delegate_action(
        account_creator_id.clone(),
        account_creator_pk,
        new_user_account_id.clone(),
        get_user_recovery_pk(internal_user_id),
        crate::transaction::NetworkType::Testnet,
        nonce,
        block_height + 100,
    );
    let signed_delegate_action =
        get_signed_delegated_action(delegate_action, account_creator_id, account_creator_sk);

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

#[tracing::instrument(level = "info", skip_all, fields(id = state.id))]
async fn new_account<T: OAuthTokenVerifier>(
    Extension(state): Extension<LeaderState>,
    Json(request): Json<NewAccountRequest>,
) -> (StatusCode, Json<NewAccountResponse>) {
    tracing::info!(
        access_token = format!("{:.5}...", request.id_token),
        "new request"
    );

    match T::verify_token(&request.id_token).await {
        Ok(_) => {
            tracing::info!("access token is valid");
            match process_new_account(&state, &request).await {
                Ok(result) => result,
                Err(e) => {
                    tracing::error!(err = ?e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(NewAccountResponse::Err {
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
                Json(NewAccountResponse::Err {
                    msg: "access token verification failed".into(),
                }),
            )
        }
    }
}

async fn process_add_key(
    state: &LeaderState,
    request: &AddKeyRequest,
) -> anyhow::Result<(StatusCode, Json<AddKeyResponse>)> {
    let user_account_id: AccountId = request.account_id.parse().unwrap();
    let internal_user_id: InternalAccountId = "tmp".parse().unwrap(); // TODO:get real user id from ID token

    // Get nonce and recent block hash
    let nonce = state
        .client
        .access_key_nonce(
            user_account_id.clone(),
            get_user_recovery_pk(internal_user_id.clone()).clone(),
        )
        .await?;
    let block_height = state.client.latest_block_height().await?;

    // Create a transaction to create a new account
    let new_user_pk: PublicKey = request.public_key.clone().parse().unwrap();

    let max_block_height: u64 = block_height + 100;

    let delegate_action = get_add_key_delegate_action(
        user_account_id.clone(),
        new_user_pk,
        nonce,
        max_block_height,
    );
    let signed_delegate_action = get_signed_delegated_action(
        delegate_action,
        user_account_id,
        get_user_recovery_sk(internal_user_id.clone()),
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
        access_token = format!("{:.5}...", request.id_token),
        public_key = hex::encode(request.public_key.clone()),
        "new request"
    );

    match T::verify_token(&request.id_token).await {
        Ok(_) => {
            tracing::info!("access token is valid");
            match process_add_key(&state, &request).await {
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
