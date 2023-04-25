use self::aggregate_signer::{NodeInfo, Reveal, SignedCommitment, SigningState};
use self::check_signatures::{
    add_key_digest, check_signature, claim_oidc_request_digest, claim_oidc_response_digest,
    oidc_digest, HashSalt,
};
use self::oidc_digest::OidcDigest;
use self::user_credentials::EncryptedUserCredentials;
use self::user_credentials::UserCredentials;
use crate::gcp::GcpService;
use crate::msg::{AcceptNodePublicKeysRequest, SigShareRequest};
use crate::msg::{AddKey, ClaimOidcRequest, SigShareRequest};
use crate::oauth::OAuthTokenVerifier;
use crate::oauth::{OAuthTokenVerifier, UniversalTokenVerifier};
use crate::primitives::InternalAccountId;
use crate::sign_node::pk_set::SignerNodePkSet;
use crate::transaction::get_add_key_delegate_action;
use crate::NodeId;
use aes_gcm::Aes256Gcm;
use axum::routing::get;
use anyhow::Context;
use axum::{http::StatusCode, routing::post, Extension, Json, Router};
use curv::elliptic::curves::{Ed25519, Point};
use ed25519_dalek::{Digest, Sha512};
use multi_party_eddsa::protocols::{self, ExpandedKeyPair};
use near_crypto::{ParseKeyError, PublicKey, Signature};
use near_primitives::account::id::ParseAccountError;
use near_primitives::borsh::BorshSerialize;
use near_primitives::hash::hash;
use near_primitives::types::AccountId;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod aggregate_signer;
pub mod check_signatures;
pub mod oidc_digest;
pub mod pk_set;
pub mod user_credentials;

pub struct Config {
    pub gcp_service: GcpService,
    pub our_index: NodeId,
    pub node_key: ExpandedKeyPair,
    pub cipher: Aes256Gcm,
    pub port: u16,
    pub pagoda_firebase_audience_id: String,
}

pub async fn run<T: OAuthTokenVerifier + 'static>(config: Config) {
    tracing::debug!("running a sign node");
    let Config {
        gcp_service,
        our_index,
        node_key,
        cipher,
        port,
        pagoda_firebase_audience_id,
    } = config;
    let our_index = usize::try_from(our_index).expect("This index is way to big");

    let pk_set = gcp_service
        .get::<_, SignerNodePkSet>(format!("{}/{}", our_index, pk_set::MAIN_KEY))
        .await
        .unwrap_or_default();

    let signing_state = Arc::new(RwLock::new(SigningState::new()));
    let state = SignNodeState {
        gcp_service,
        node_key,
        cipher,
        signing_state,
        pagoda_firebase_audience_id,
        node_info: NodeInfo::new(our_index, pk_set.map(|set| set.public_keys)),
    };

    let app = Router::new()
        // healthcheck endpoint
        .route(
            "/",
            get(|| async move {
                tracing::info!("node is ready to accept connections");
                StatusCode::OK
            }),
        )
        .route("/commit", post(commit::<T>))
        .route("/reveal", post(reveal))
        .route("/signature_share", post(signature_share))
        .route("/public_key", post(public_key))
        .route("/public_key_node", post(public_key_node))
        .route("/accept_pk_set", post(accept_pk_set))
        .layer(Extension(state));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::debug!(?addr, "starting http server");
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[derive(Clone)]
struct SignNodeState {
    gcp_service: GcpService,
    pagoda_firebase_audience_id: String,
    node_key: ExpandedKeyPair,
    cipher: Aes256Gcm,
    signing_state: Arc<RwLock<SigningState>>,
    node_info: NodeInfo,
}

#[derive(thiserror::Error, Debug)]
pub enum CommitError {
    #[error("malformed account id: {0}")]
    MalformedAccountId(String, ParseAccountError),
    #[error("malformed public key {0}: {1}")]
    MalformedPublicKey(String, ParseKeyError),
    #[error("failed to verify oidc token: {0}")]
    OidcVerificationFailed(anyhow::Error),
    #[error("failed to verify signature: {0}")]
    SignatureVerificationFailed(anyhow::Error),
    #[error("oidc token already claimed by another public key: {0:?}")]
    OidcTokenAlreadyClaimed(OidcDigest),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

async fn get_or_generate_user_creds(
    state: &SignNodeState,
    internal_account_id: InternalAccountId,
) -> anyhow::Result<EncryptedUserCredentials> {
    match state
        .gcp_service
        .get::<_, EncryptedUserCredentials>(format!(
            "{}/{}",
            state.node_info.our_index, internal_account_id
        ))
        .await
    {
        Ok(Some(user_credentials)) => {
            tracing::debug!(internal_account_id, "found an existing user");
            Ok(user_credentials)
        }
        Ok(None) => {
            let user_credentials = EncryptedUserCredentials::random(
                state.node_info.our_index,
                internal_account_id.clone(),
                &state.cipher,
            )?;
            tracing::debug!(
                internal_account_id,
                public_key = ?user_credentials.public_key,
                "generating credentials for a new user"
            );
            state.gcp_service.insert(user_credentials.clone()).await?;
            Ok(user_credentials)
        }
        Err(e) => Err(e),
    }
}

async fn process_add_key_commit<T: OAuthTokenVerifier>(
    state: SignNodeState,
    add_key: AddKey,
) -> Result<SignedCommitment, CommitError> {
    let AddKey {
        user_recovery_pk,
        max_block_height,
        nonce,
        near_account_id,
        oidc_token,
        user_local_pk: public_key,
        signature,
        ..
    } = &add_key;
    let oidc_digest = oidc_digest(&oidc_token);
    // Fetch the public key associated with the oidc key digest from the store
    // Only this public key is allowed to take actions with this token
    match state
        .gcp_service
        .get::<_, OidcDigest>(format!(
            "{}/{}",
            state.node_info.our_index,
            hex::encode(oidc_digest)
        ))
        .await
    {
        // The oidc key has been claimed
        Ok(Some(user_credentials)) => {
            match signature {
                // If the user doesn't sign their message they might be frontrunning
                None => {
                    return Err(CommitError::OidcVerificationFailed(anyhow::anyhow!(
                    "Oidc token has been claimed, please prove ownership by attaching a signature"
                )))
                }
                Some(signature) => {
                    // Check the signature matches the public key the hash was registered to
                    let digest = add_key_digest(&add_key)?;
                    check_signature(&user_credentials.public_key, signature, &digest)?
                }
            }
        }
        // The oidc key hasn't been claimed
        Ok(None) => {
            match signature {
                // The user doesn't sign their message because they're using the old version of the API
                // Turn this into an error ASAP
                None => tracing::debug!("A user is using the non front running resistant API"),
                // The user is signing their messages but not registering their token, something has gone wrong
                Some(_) => {
                    return Err(CommitError::Other(anyhow::anyhow!(
                        "You must call the oidc_claim endpoint first"
                    )))
                }
            }
            // return Err(CommitError::OidcVerificationFailed(anyhow::anyhow!(
            //     "Oidc token has not been claimed"
            // )))
        }
        Err(e) => return Err(CommitError::Other(anyhow::anyhow!(e))),
    };

    let oidc_token_claims = T::verify_token(&oidc_token, &state.pagoda_firebase_audience_id)
        .await
        .map_err(CommitError::OidcVerificationFailed)?;

    let internal_account_id = oidc_token_claims.get_internal_account_id();

    let user_credentials = get_or_generate_user_creds(&state, internal_account_id).await?;

    let new_public_key: PublicKey = public_key
        .parse()
        .map_err(|e| CommitError::MalformedPublicKey(public_key.clone(), e))?;

    let user_account_id: AccountId = near_account_id
        .parse()
        .map_err(|e| CommitError::MalformedAccountId(near_account_id.clone(), e))?;

    // Create a transaction to add a new key
    let delegate_action = get_add_key_delegate_action(
        user_account_id.clone(),
        user_recovery_pk.clone(),
        new_public_key.clone(),
        *nonce,
        *max_block_height,
    )?;

    let bytes = delegate_action
        .try_to_vec()
        .map_err(|e| anyhow::anyhow!(e))?;

    let hash = hash(&bytes);

    state
        .signing_state
        .write()
        .await
        .get_commitment(&user_credentials.key_pair, &state.node_key, hash.into())
        .map_err(|e| CommitError::Other(anyhow::anyhow!(e)))
}

async fn process_claim_oidc_commit(
    state: SignNodeState,
    req: ClaimOidcRequest,
) -> Result<SignedCommitment, CommitError> {
    let digest = claim_oidc_request_digest(&req)?;
    let public_key: PublicKey = req
        .public_key
        .parse()
        .map_err(|e| CommitError::MalformedPublicKey(req.public_key.clone(), e))?;

    check_signature(&public_key, &req.signature, &digest)?;

    let oidc_digest = OidcDigest {
        node_id: state.node_info.our_index,
        digest: <[u8; 32]>::try_from(digest).expect("Hash was wrong size"),
        public_key,
    };

    // Only allow the associated public key to use the oidc key
    match state
        .gcp_service
        .get::<_, OidcDigest>(oidc_digest.to_name())
        .await
    {
        Ok(Some(stored_digest)) => {
            // If the public key matches the one that controls this oidc then just sign it again
            if stored_digest != oidc_digest {
                return Err(CommitError::OidcTokenAlreadyClaimed(oidc_digest));
            }
        }
        Err(e) => return Err(CommitError::Other(e)),
        Ok(None) => state.gcp_service.insert(oidc_digest).await?,
    };

    let response_digest = claim_oidc_response_digest(&req)?;
    state
        .signing_state
        .write()
        .await
        // This will be signed by the nodes combined Ed22519 signature
        .get_commitment(&state.node_key, &state.node_key, response_digest)
        .map_err(|e| CommitError::Other(anyhow::anyhow!(e)))
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn commit<T: OAuthTokenVerifier>(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<SigShareRequest>,
) -> (StatusCode, Json<Result<SignedCommitment, String>>) {
    if let Err(msg) = check_if_ready(&state).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Err(msg)));
    }

    if let Err(err_msg) = request.verify_signature(todo!()) {
        return fail(err_msg);
    }

    let response = match request {
        SigShareRequest::Add(add_key) => process_add_key_commit::<T>(state, add_key).await,
        SigShareRequest::Claim(claim_oidc) => process_claim_oidc_commit(state, claim_oidc).await,
    };
    match response {
        Ok(signed_commitment) => (StatusCode::OK, Json(Ok(signed_commitment))),
        Err(ref e @ CommitError::OidcVerificationFailed(ref err_msg)) => {
            return fail(format!("failed to verify oidc token: {}", err_msg))
        }
        Err(e) => return fail(format!("commit failed: {}", e)),
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn reveal(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<Vec<SignedCommitment>>,
) -> (StatusCode, Json<Result<Reveal, String>>) {
    if let Err(msg) = check_if_ready(&state).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Err(msg)));
    }

    match state
        .signing_state
        .write()
        .await
        .get_reveal(state.node_info, request)
        .await
    {
        Ok(r) => {
            tracing::debug!("Successful reveal");
            (StatusCode::OK, Json(Ok(r)))
        }
        Err(e) => {
            tracing::error!("Reveal failed: {}", e);
            (StatusCode::BAD_REQUEST, Json(Err(e)))
        }
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn signature_share(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<Vec<Reveal>>,
) -> (StatusCode, Json<Result<protocols::Signature, String>>) {
    if let Err(msg) = check_if_ready(&state).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Err(msg)));
    }

    match state
        .signing_state
        .write()
        .await
        .get_signature_share(state.node_info, request)
    {
        Ok(r) => {
            tracing::debug!("Successful signature share");
            (StatusCode::OK, Json(Ok(r)))
        }
        Err(e) => {
            tracing::error!("Signature share failed: {}", e);
            (StatusCode::BAD_REQUEST, Json(Err(e)))
        }
    }
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn public_key(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<InternalAccountId>,
) -> (StatusCode, Json<Result<Point<Ed25519>, String>>) {
    match get_or_generate_user_creds(&state, request).await {
        Ok(user_credentials) => (
            StatusCode::OK,
            Json(Ok(user_credentials.public_key().clone())),
        ),
        Err(err) => {
            tracing::error!(?err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Err(format!(
                    "failed to fetch/generate a public key for given account: {}",
                    err,
                ))),
            )
        }
    }
}

// TODO: remove type complexity
#[allow(clippy::type_complexity)]
#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn public_key_node(
    Extension(state): Extension<SignNodeState>,
    Json(_): Json<()>,
) -> (StatusCode, Json<Result<(usize, Point<Ed25519>), String>>) {
    (
        StatusCode::OK,
        Json(Ok((state.node_info.our_index, state.node_key.public_key))),
    )
}

#[tracing::instrument(level = "debug", skip_all, fields(id = state.node_info.our_index))]
async fn accept_pk_set(
    Extension(state): Extension<SignNodeState>,
    Json(request): Json<AcceptNodePublicKeysRequest>,
) -> (StatusCode, Json<Result<String, String>>) {
    let index = state.node_info.our_index;
    if request.public_keys.get(index) != Some(&state.node_key.public_key) {
        tracing::error!("provided secret share does not match the node id");
        return (StatusCode::BAD_REQUEST, Json(Err(format!(
            "Sign node could not accept the public keys: current node index={index} does not match up"))));
    }

    let mut public_keys = state.node_info.nodes_public_keys.write().await;
    if public_keys.is_some() {
        return (
            StatusCode::BAD_REQUEST,
            Json(Err(
                "This node is already initialized with public keys".to_string()
            )),
        );
    }
    tracing::debug!("Setting node public keys => {:?}", request.public_keys);
    public_keys.replace(request.public_keys.clone());
    match state
        .gcp_service
        .insert(SignerNodePkSet {
            node_id: state.node_info.our_index,
            public_keys: request.public_keys,
        })
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(Ok("Successfully set node public keys".to_string())),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Ok("failed to save the keys".to_string())),
        ),
    }
}

/// Validate whether the current state of the sign node is useable or not.
async fn check_if_ready(state: &SignNodeState) -> Result<(), String> {
    let public_keys = state.node_info.nodes_public_keys.read().await;
    if public_keys.is_none() {
        return Err(
            "Sign node is not ready yet: waiting on all public keys from leader node".into(),
        );
    }

    Ok(())
}

fn fail(err_msg: String) -> (StatusCode, Json<Result<SignedCommitment, String>>) {
    tracing::error!(err = ?err_msg);
    (StatusCode::BAD_REQUEST, Json(Err(err_msg)))
}
