use crate::msg::{
    LeaderRequest, LeaderResponse, NewAccountRequest, NewAccountResponse, AddKeyRequest,
    AddKeyResponse, SigShareRequest, SigShareResponse,
};
use crate::oauth::{OAuthTokenVerifier, UniversalTokenVerifier};
use crate::transaction::{
    new_add_fa_key_transaction, new_create_account_transaction, sign_transaction,
};
use crate::NodeId;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use futures::stream::FuturesUnordered;
use hyper::client::ResponseFuture;
use hyper::{Body, Client, Method, Request};
use near_crypto::{PublicKey, SecretKey};
use near_primitives::hash::CryptoHash;
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
        root_secret_key,
    };

    let app = Router::new()
        .route("/submit", post(submit::<UniversalTokenVerifier>))
        .route("/new_account", post(new_account::<UniversalTokenVerifier>))
        .route("/add_key", post(add_key::<UniversalTokenVerifier>))
        .with_state(state);

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

#[tracing::instrument(level = "debug", skip_all, fields(id = state.id))]
async fn new_account<T: OAuthTokenVerifier>(
    State(state): State<LeaderState>,
    Json(request): Json<NewAccountRequest>,
) -> (StatusCode, Json<NewAccountResponse>) {
    tracing::info!(
        access_token = format!("{:.5}...", request.id_token),
        "new request"
    );

    match T::verify_token(&request.id_token).await {
        Ok(_) => {
            // This is the account that is doing the function calls to creates new accounts.
            // TODO: the private key from this acc should be stored in GCP Secret Manager
            let account_creator_id: AccountId = "account_creator.testnet".parse().unwrap();
            let account_creator_sk: SecretKey = "secret_key".parse().unwrap();
            let account_creator_pk: PublicKey = "public_key".parse().unwrap();

            tracing::info!("access token is valid");
            // Get nonce and recent block hash
            let nonce = 0; // TODO: get real nonce
            let block_hash: CryptoHash = "".parse().unwrap(); // TODO: get real block hash
                                                              // Create/generate a public key for the new user
            let new_user_pk: PublicKey = "".parse().unwrap(); // TODO: generate real user pk
                                                              // Create a transaction to create a new account
            let new_user_account_id: AccountId = request.account_id.clone().parse().unwrap();
            let create_acc_tx = new_create_account_transaction(
                new_user_account_id,
                new_user_pk,
                account_creator_id.clone(),
                account_creator_pk,
                nonce,
                block_hash,
                crate::transaction::NetworkType::Testnet,
            );
            // Sign the transaction
            let _signed_create_acc_tx =
                sign_transaction(create_acc_tx, account_creator_id, account_creator_sk);
            //TODO: Send transaction to the relayer
            (StatusCode::OK, Json(NewAccountResponse::Ok))
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

#[tracing::instrument(level = "debug", skip_all, fields(id = state.id))]
async fn add_key<T: OAuthTokenVerifier>(
    State(state): State<LeaderState>,
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
            // Get nonce and recent block hash
            let nonce = 0; // TODO: get real nonce
            let block_hash: CryptoHash = "".parse().unwrap(); // TODO: get real block hash
                                                              // Create/generate a public key for the new user
            let new_user_pk: PublicKey = request.public_key.clone().parse().unwrap();
            let user_recovery_pk: PublicKey = "pk".parse().unwrap(); // TODO: generate real user pk
                                                                     // Create a transaction to create a new account
            let user_account_id: AccountId = request.account_id.parse().unwrap();
            let add_key_tx = new_add_fa_key_transaction(
                user_account_id.clone(),
                user_recovery_pk,
                new_user_pk,
                nonce,
                block_hash,
            );
            // Sign the transaction
            let user_reocvery_sk: SecretKey = "".parse().unwrap(); // TODO: get real user recovery sk
            let _signed_add_key_tx =
                sign_transaction(add_key_tx, user_account_id, user_reocvery_sk);
            //TODO: Send transaction to the relayer
            (StatusCode::OK, Json(AddKeyResponse::Ok))
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
    State(state): State<LeaderState>,
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
