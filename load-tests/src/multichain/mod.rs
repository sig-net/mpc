use std::{env, time::Duration};

use goose::goose::{GooseMethod, GooseRequest, GooseUser, TransactionResult};
use goose_eggs::{validate_and_load_static_assets, Validate};
use near_crypto::{InMemorySigner, Signer};
use near_jsonrpc_client::JsonRpcClient;
use near_primitives::{
    transaction::{Action, FunctionCallAction, Transaction, TransactionV0},
    types::AccountId,
};
use near_workspaces::types::NearToken;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

use crate::common::primitives::UserSession;

#[derive(Serialize, Deserialize, Debug)]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

pub async fn multichain_sign(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("multichain_sign");

    // Config
    let multichain_contract_id =
        env::var("MULTICHAIN_CONTRACT_ID").unwrap_or_else(|_| "v1.signer-dev.testnet".to_string());
    let multichain_contract_id = AccountId::try_from(multichain_contract_id)
        .expect("Failed to parse MULTICHAIN_CONTRACT_ID");
    let testnet_rpc_url = user.config.host.clone();
    let deposit = NearToken::from_millinear(50).as_yoctonear();
    let expected_log = "Signature is ready."; // This is a log that we are expecting to see in the successful response

    let session = user
        .get_session_data::<UserSession>()
        .expect("Session Data must be set");

    let signer = InMemorySigner {
        account_id: session.near_account_id.clone(),
        public_key: session.fa_sk.public_key(),
        secret_key: session.fa_sk.clone(),
    };

    let connector = JsonRpcClient::new_client();
    let jsonrpc_client = connector.connect(&testnet_rpc_url);
    let rpc_client = near_fetch::Client::from_client(jsonrpc_client.clone());

    let (nonce, block_hash, _) = rpc_client
        .fetch_nonce(&signer.account_id, &signer.public_key)
        .await
        .unwrap();

    let payload_hashed: [u8; 32] = rand::rng().random();
    tracing::info!("requesting signature for: {:?}", payload_hashed);

    let request = SignRequest {
        payload: payload_hashed,
        path: "test".to_string(),
        key_version: 0,
    };

    let transaction = Transaction::V0(TransactionV0 {
        signer_id: session.near_account_id.clone(),
        public_key: session.fa_sk.public_key(),
        nonce,
        receiver_id: multichain_contract_id,
        block_hash,
        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: "sign".to_string(),
            args: serde_json::to_vec(&serde_json::json!({
                "request": request,
            }))
            .unwrap(),
            gas: 300_000_000_000_000,
            deposit,
        }))],
    });

    let signed_transaction = transaction.sign(&Signer::InMemory(signer));

    let encoded_transaction =
        near_primitives::serialize::to_base64(&borsh::to_vec(&signed_transaction).unwrap());

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "dontcare",
        "method": "broadcast_tx_commit",
        "params": [
            encoded_transaction
        ]
    });

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let request_builder = user
        .get_request_builder(&GooseMethod::Post, "")?
        .json(&payload)
        .headers(headers)
        .timeout(Duration::from_secs(50));

    let goose_request = GooseRequest::builder()
        .set_request_builder(request_builder)
        .build();

    let goose_response = user.request(goose_request).await?;

    // let text = goose_response.response.unwrap().text().await.unwrap();
    // tracing::info!("goose_response: {:?}", text);

    let rsp = goose_response.response.as_ref().unwrap();

    tracing::info!("goose_response: {:?}", rsp);

    let validate = &Validate::builder()
        .status(200)
        .text(expected_log) // Naive check if the request is successful
        .build();
    validate_and_load_static_assets(user, goose_response, validate).await?;

    Ok(())
}
