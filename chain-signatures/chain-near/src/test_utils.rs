//! Wire fixtures for NEAR boundary tests: envelopes built by serializing the
//! vendor types, so a mock answers exactly what the client's own deserializer
//! reads. Behind `test-support` so none of it ships.

use mockito::{Matcher, Mock, ServerGuard};
use near_account_id::AccountId;
use near_crypto::{InMemorySigner, KeyType, PublicKey, Signer};
use near_fetch::ops::FunctionCallTransaction;
use near_jsonrpc_primitives::errors::{RpcError, RpcErrorKind};
use near_jsonrpc_primitives::types::query::{QueryResponseKind, RpcQueryResponse};
use near_jsonrpc_primitives::types::transactions::RpcTransactionResponse;
use near_primitives::errors::InvalidTxError;
use near_primitives::hash::CryptoHash;
use near_primitives::views::{
    AccessKeyPermissionView, AccessKeyView, BlockHeaderView, BlockView, CallResult,
    ExecutionOutcomeView, ExecutionOutcomeWithIdView, ExecutionStatusView,
    FinalExecutionOutcomeView, FinalExecutionOutcomeViewEnum, FinalExecutionStatus,
    SignedTransactionView, TxExecutionStatus,
};

use crate::gates::NearRpcGates;
use mpc_chain_integration_core::utils::retry::SharedBackoff;

pub fn account_id() -> AccountId {
    "node.testnet".parse().unwrap()
}

pub fn contract_id() -> AccountId {
    "contract.testnet".parse().unwrap()
}

/// Transaction views in the fixtures embed this signer's public key.
pub fn signer() -> InMemorySigner {
    match InMemorySigner::from_seed(account_id(), KeyType::ED25519, "test") {
        Signer::InMemory(signer) => signer,
        _ => unreachable!(),
    }
}

pub fn public_key() -> PublicKey {
    signer().public_key
}

/// Wraps `result` in a JSON-RPC 2.0 reply.
pub fn envelope(result: serde_json::Value) -> String {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "result": result,
    }))
    .unwrap()
}

/// The access-key `query` reply a fresh client fetches before its first send.
pub fn access_key_envelope() -> String {
    envelope(
        serde_json::to_value(RpcQueryResponse {
            kind: QueryResponseKind::AccessKey(AccessKeyView {
                nonce: 1,
                permission: AccessKeyPermissionView::FullAccess,
            }),
            block_height: 1,
            block_hash: CryptoHash([0; 32]),
        })
        .unwrap(),
    )
}

/// The `block` reply a warm client fetches for its block hash before every
/// later send.
pub fn block_envelope() -> String {
    envelope(
        serde_json::to_value(BlockView {
            author: account_id(),
            header: BlockHeaderView {
                height: 1,
                hash: CryptoHash([0; 32]),
                ..Default::default()
            },
            chunks: vec![],
        })
        .unwrap(),
    )
}

/// Builds a 200 envelope whose view bytes fail decoding at "column 401",
/// terminal to the text fallback in `retry::classify::is_retryable`.
pub fn malformed_view_envelope() -> String {
    let mut bytes = vec![b' '; 400];
    bytes.push(b'x');
    envelope(
        serde_json::to_value(RpcQueryResponse {
            kind: QueryResponseKind::CallResult(CallResult {
                result: bytes,
                logs: vec![],
            }),
            block_height: 1,
            block_hash: CryptoHash([0; 32]),
        })
        .unwrap(),
    )
}

/// The outcome of a call that returned `value`.
pub fn success(value: Vec<u8>) -> FinalExecutionStatus {
    FinalExecutionStatus::SuccessValue(value)
}

/// A `respond` call shaped like `publisher::NearClient::call_respond`'s.
pub fn respond<'a>(
    client: &'a near_fetch::Client,
    signer: &'a InMemorySigner,
) -> FunctionCallTransaction<'a> {
    client
        .call(signer, &contract_id(), "respond")
        .args_json(serde_json::json!({ "sign_id": 0 }))
        .max_gas()
}

/// A `send_tx` reply carrying `status`.
pub fn outcome_envelope(status: FinalExecutionStatus) -> String {
    let outcome_status = match &status {
        FinalExecutionStatus::Failure(tx_error) => ExecutionStatusView::Failure(tx_error.clone()),
        _ => ExecutionStatusView::SuccessValue(Vec::new()),
    };
    let response = RpcTransactionResponse {
        final_execution_outcome: Some(FinalExecutionOutcomeViewEnum::FinalExecutionOutcome(
            FinalExecutionOutcomeView {
                status,
                transaction: SignedTransactionView {
                    signer_id: account_id(),
                    public_key: public_key(),
                    nonce: 1,
                    receiver_id: contract_id(),
                    actions: vec![],
                    _priority_fee: 0,
                    signature: near_crypto::Signature::empty(KeyType::ED25519),
                    hash: CryptoHash([0; 32]),
                    nonce_index: None,
                    nonce_mode: None,
                },
                transaction_outcome: ExecutionOutcomeWithIdView {
                    proof: vec![],
                    block_hash: CryptoHash([0; 32]),
                    id: CryptoHash([0; 32]),
                    outcome: ExecutionOutcomeView {
                        status: outcome_status,
                        logs: vec![],
                        receipt_ids: vec![],
                        gas_burnt: Default::default(),
                        tokens_burnt: Default::default(),
                        executor_id: contract_id(),
                        metadata: Default::default(),
                    },
                },
                receipts_outcome: vec![],
            },
        )),
        final_execution_status: TxExecutionStatus::ExecutedOptimistic,
    };
    envelope(serde_json::to_value(response).unwrap())
}

/// A `send_tx` reply answering HTTP 200 with a JSON-RPC handler error. The
/// cause is hand-shaped: `RpcTransactionError::InvalidTransaction`'s `context`
/// is `#[serde(skip_serializing)]`, so the vendor type cannot round-trip the
/// field its own deserializer requires.
pub fn handler_error_envelope(context: InvalidTxError) -> String {
    let cause = serde_json::json!({
        "name": "INVALID_TRANSACTION",
        "info": { "context": serde_json::to_value(context).unwrap() }
    });
    let error = serde_json::to_value(RpcError {
        error_struct: Some(RpcErrorKind::HandlerError(Box::new(cause))),
        code: -32000,
        message: "Validation error".into(),
        data: None,
    })
    .unwrap();
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": error,
    }))
    .unwrap()
}

/// Mocks a JSON-RPC `method` answering `status`/`body` `hits` times; a body
/// is ignored for a refusal, and `hits` of 0 pins the request never arriving.
pub async fn method_mock(
    server: &mut ServerGuard,
    method: &str,
    status: usize,
    body: &str,
    hits: usize,
) -> Mock {
    server
        .mock("POST", "/")
        .match_body(Matcher::PartialJson(serde_json::json!({
            "method": method
        })))
        .with_status(status)
        .with_header("content-type", "application/json")
        .with_body(body)
        .expect(hits)
        .create_async()
        .await
}

/// A client whose nonce cache is warm, as the node's shared client is after
/// its first transaction: every later send starts with a `block` query, not
/// an access-key query (near-fetch 0.12.0 `fetch_nonce` → `cached_nonce`).
/// Sends must be signed with [`signer`]: the cache is keyed by its public key.
pub async fn warm_client(server: &mut ServerGuard) -> near_fetch::Client {
    method_mock(server, "query", 200, &access_key_envelope(), 1).await;
    method_mock(
        server,
        "send_tx",
        200,
        &outcome_envelope(success(b"null".to_vec())),
        1,
    )
    .await;
    let client = near_fetch::Client::new(&server.url());
    NearRpcGates::new(SharedBackoff::new())
        .transact(respond(&client, &signer()))
        .await
        .expect("the warm-up send lands");
    client
}
