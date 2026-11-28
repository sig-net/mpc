//! Typed verdicts for NEAR RPC failures, attached where the node's calls
//! leave `near_fetch` so chain-walking classifiers never read rendered text.

use http::StatusCode;
use mpc_chain_integration_core::utils::retry::RpcFailure;
use near_fetch::Error as NearFetchError;
use near_jsonrpc_client::errors::{
    JsonRpcError, JsonRpcServerError, JsonRpcServerResponseStatusError,
};
use near_jsonrpc_primitives::types::blocks::RpcBlockError;
use near_jsonrpc_primitives::types::query::RpcQueryError;
use std::error::Error as StdError;

/// The carrier for a refused call. Its message is the near error's chain
/// render — call sites match contract-panic text on it — and its verdict is
/// the typed status under `partition`, or statusless retryable: carrier
/// presence alone suppresses the text fallback in `is_provider_throttled`.
fn status_carrier(
    error: NearFetchError,
    partition: fn(StatusCode, String) -> RpcFailure,
) -> RpcFailure {
    let render = render_chain(&error);
    match near_status(&error) {
        Some(status) => partition(status, render),
        None => RpcFailure::retryable(render),
    }
}

pub(crate) fn send_failure(error: NearFetchError) -> anyhow::Error {
    anyhow::Error::new(status_carrier(error, RpcFailure::send_status))
}

pub(crate) fn read_failure(error: NearFetchError) -> anyhow::Error {
    anyhow::Error::new(status_carrier(error, RpcFailure::read_status))
}

/// The refusal status the jsonrpc transport typed: `JsonRpcClient::call`
/// (near-jsonrpc-client 0.22.0) maps every non-200 status to a
/// `ResponseStatusError` variant but 500, which becomes `InternalError` and
/// carries no status. Matched on concrete variants, not the source chain:
/// thiserror's `#[error(transparent)]` forwards `source()` to the field's own
/// source, so wrapper levels never chain.
fn near_status(error: &NearFetchError) -> Option<StatusCode> {
    match error {
        // `send_tx_once`: the method's error, via near-fetch's `From`.
        NearFetchError::RpcTransactionError(e) => jsonrpc_status(e),
        // `Client::access_key`: a fresh client's nonce fetch.
        NearFetchError::RpcQueryError(e) => jsonrpc_status(e),
        // `Query::into_future` boxes the method's error: `view` calls carry
        // `RpcQueryError`; `view_block`, every send after the first, `RpcBlockError`.
        NearFetchError::Rpc(e) => e
            .downcast_ref::<JsonRpcError<RpcQueryError>>()
            .and_then(jsonrpc_status)
            .or_else(|| {
                e.downcast_ref::<JsonRpcError<RpcBlockError>>()
                    .and_then(jsonrpc_status)
            }),
        // No node path produces these: `view_block` boxes, and `view_chunk` /
        // `send_tx_async` are unused. Kept so the match stays total over the
        // vendored enum's status-bearing members.
        NearFetchError::RpcBlockError(e) => jsonrpc_status(e),
        NearFetchError::RpcChunkError(e) => jsonrpc_status(e),
        NearFetchError::RpcTransactionAsyncError(e) => jsonrpc_status(e),
        // Deliberate: every other member — transport failure, pending or
        // undecodable reply, the executed outcome — carries no status.
        _ => None,
    }
}

fn jsonrpc_status<E>(error: &JsonRpcError<E>) -> Option<StatusCode> {
    match error {
        JsonRpcError::ServerError(JsonRpcServerError::ResponseStatusError(status)) => {
            Some(match status {
                JsonRpcServerResponseStatusError::Unauthorized => StatusCode::UNAUTHORIZED,
                JsonRpcServerResponseStatusError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
                JsonRpcServerResponseStatusError::BadRequest => StatusCode::BAD_REQUEST,
                JsonRpcServerResponseStatusError::TimeoutError => StatusCode::REQUEST_TIMEOUT,
                JsonRpcServerResponseStatusError::ServiceUnavailable => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                JsonRpcServerResponseStatusError::Unexpected { status } => *status,
            })
        }
        _ => None,
    }
}

/// Std errors ignore the `#` format flag, so the carrier's message must
/// build the chain render itself.
fn render_chain(error: &NearFetchError) -> String {
    let mut render = error.to_string();
    let mut cause = error.source();
    while let Some(err) = cause {
        render.push_str(": ");
        render.push_str(&err.to_string());
        cause = err.source();
    }
    render
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::{view_json, NearRpcGates};
    use crate::publisher::NearClient;
    use crate::test_utils::{
        access_key_envelope, block_envelope, contract_id, handler_error_envelope,
        malformed_view_envelope, method_mock, respond, signer, warm_client,
    };
    use mockito::{Mock, Server, ServerGuard};
    use mpc_chain_integration_core::utils::retry::{
        http_status_read_retryable, http_status_retryable, is_provider_throttled, is_retryable,
        is_throttle_status, SharedBackoff,
    };
    use mpc_chain_integration_core::utils::test::make_publish_action;
    use mpc_chain_integration_core::{ChainPublisher as _, NoopPublisherTelemetry};
    use mpc_primitives::{Chain, SignId, SignKind};
    use near_jsonrpc_client::errors::{JsonRpcError, JsonRpcServerError};
    use near_jsonrpc_client::methods::send_tx::RpcTransactionError;
    use near_jsonrpc_primitives::types::query::RpcQueryError;
    use near_primitives::errors::{InvalidTxError, TxExecutionError};
    use near_primitives::hash::CryptoHash;
    use std::sync::Arc;
    use std::time::Duration;

    /// The shapes each boundary meets, by the producer named in `near_status`.
    fn refused_send(status: JsonRpcServerResponseStatusError) -> NearFetchError {
        NearFetchError::RpcTransactionError(Box::new(JsonRpcError::ServerError(
            JsonRpcServerError::ResponseStatusError(status),
        )))
    }

    fn refused_nonce_query(status: JsonRpcServerResponseStatusError) -> NearFetchError {
        NearFetchError::RpcQueryError(Box::new(JsonRpcError::ServerError(
            JsonRpcServerError::ResponseStatusError(status),
        )))
    }

    fn refused_block(status: JsonRpcServerResponseStatusError) -> NearFetchError {
        NearFetchError::Rpc(Box::new(JsonRpcError::<RpcBlockError>::ServerError(
            JsonRpcServerError::ResponseStatusError(status),
        )))
    }

    fn refused_view(status: JsonRpcServerResponseStatusError) -> NearFetchError {
        NearFetchError::Rpc(Box::new(JsonRpcError::<RpcQueryError>::ServerError(
            JsonRpcServerError::ResponseStatusError(status),
        )))
    }

    fn carrier(err: &anyhow::Error) -> RpcFailure {
        err.chain()
            .find_map(|cause| cause.downcast_ref::<RpcFailure>())
            .expect("the carrier rides the chain")
            .clone()
    }

    type Variant = fn() -> JsonRpcServerResponseStatusError;

    fn typed_variants() -> Vec<(Variant, StatusCode)> {
        use JsonRpcServerResponseStatusError::*;
        vec![
            ((|| Unauthorized) as Variant, StatusCode::UNAUTHORIZED),
            (
                (|| TooManyRequests) as Variant,
                StatusCode::TOO_MANY_REQUESTS,
            ),
            ((|| BadRequest) as Variant, StatusCode::BAD_REQUEST),
            ((|| TimeoutError) as Variant, StatusCode::REQUEST_TIMEOUT),
            (
                (|| ServiceUnavailable) as Variant,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ]
    }

    #[test]
    fn typed_refusal_statuses_classify_under_the_send_partition() {
        for (variant, status) in typed_variants() {
            for err in [
                send_failure(refused_send(variant())),
                send_failure(refused_nonce_query(variant())),
                send_failure(refused_block(variant())),
            ] {
                assert_eq!(carrier(&err).status(), Some(status));
                assert_eq!(is_retryable(&err), http_status_retryable(status));
                assert_eq!(is_provider_throttled(&err), is_throttle_status(status));
            }
        }
    }

    #[test]
    fn typed_refusal_statuses_classify_under_the_read_partition() {
        for (variant, status) in typed_variants() {
            let err = read_failure(refused_view(variant()));
            assert_eq!(carrier(&err).status(), Some(status));
            assert_eq!(is_retryable(&err), http_status_read_retryable(status));
            assert_eq!(is_provider_throttled(&err), is_throttle_status(status));
        }
    }

    /// `Unexpected` is `JsonRpcClient::call`'s arm for every status the five
    /// named variants do not (near-jsonrpc-client 0.22.0).
    #[test]
    fn the_full_status_domain_classifies_under_the_send_partition() {
        for code in 100u16..=599 {
            let status = StatusCode::from_u16(code).unwrap();
            let unexpected = || JsonRpcServerResponseStatusError::Unexpected { status };
            for err in [
                send_failure(refused_send(unexpected())),
                send_failure(refused_nonce_query(unexpected())),
                send_failure(refused_block(unexpected())),
            ] {
                assert_eq!(carrier(&err).status(), Some(status), "status {code}");
                assert_eq!(
                    is_retryable(&err),
                    http_status_retryable(status),
                    "verdict for {code}"
                );
                assert_eq!(
                    is_provider_throttled(&err),
                    is_throttle_status(status),
                    "throttle for {code}"
                );
            }
        }
    }

    #[test]
    fn the_full_status_domain_classifies_under_the_read_partition() {
        for code in 100u16..=599 {
            let status = StatusCode::from_u16(code).unwrap();
            let err = read_failure(refused_view(JsonRpcServerResponseStatusError::Unexpected {
                status,
            }));
            assert_eq!(
                is_retryable(&err),
                http_status_read_retryable(status),
                "verdict for {code}"
            );
            assert_eq!(
                is_provider_throttled(&err),
                is_throttle_status(status),
                "throttle for {code}"
            );
        }
    }

    fn throttled<E>() -> JsonRpcError<E> {
        JsonRpcError::ServerError(JsonRpcServerError::ResponseStatusError(
            JsonRpcServerResponseStatusError::TooManyRequests,
        ))
    }

    /// Every `near_fetch::Error` member (0.12.0), `Rpc` in both shapes it
    /// takes: the status-bearing yield their status, the rest are statusless
    /// by the default arm.
    #[test]
    fn every_near_fetch_error_member_yields_its_status_or_none() {
        let with_status = [
            NearFetchError::RpcBlockError(Box::new(throttled())),
            NearFetchError::RpcQueryError(Box::new(throttled())),
            NearFetchError::RpcChunkError(Box::new(throttled())),
            NearFetchError::RpcTransactionError(Box::new(throttled())),
            NearFetchError::RpcTransactionAsyncError(Box::new(throttled())),
            NearFetchError::Rpc(Box::new(throttled::<RpcQueryError>())),
            NearFetchError::Rpc(Box::new(throttled::<RpcBlockError>())),
        ];
        let statusless = [
            NearFetchError::RpcTransactionPending,
            NearFetchError::RpcReturnedInvalidData("x".into()),
            NearFetchError::Rpc(Box::new(std::io::Error::other("x"))),
            NearFetchError::TxExecution(Box::new(TxExecutionError::InvalidTxError(
                InvalidTxError::InvalidNonce {
                    tx_nonce: 1,
                    ak_nonce: 2,
                },
            ))),
            NearFetchError::TxStatus("Started"),
            NearFetchError::Serialization(serde_json::from_str::<()>("x").unwrap_err()),
            NearFetchError::Base64(base64::DecodeError::InvalidByte(0, b'x')),
            NearFetchError::Io(std::io::Error::other("x")),
            NearFetchError::InvalidArgs("x"),
        ];
        assert_eq!(
            with_status.len() + statusless.len(),
            16,
            "the vendored family gained a member"
        );
        for error in &with_status {
            assert_eq!(
                near_status(error),
                Some(StatusCode::TOO_MANY_REQUESTS),
                "{error}"
            );
        }
        for error in &statusless {
            assert_eq!(near_status(error), None, "{error}");
        }
    }

    /// The shape `JsonRpcClient::call` builds for a 500 (near-jsonrpc-client
    /// 0.22.0): an `InternalError` `near_status` cannot type — retryable either way.
    #[test]
    fn internal_errors_are_statusless_and_retryable() {
        let err = send_failure(NearFetchError::RpcTransactionError(Box::new(
            JsonRpcError::<RpcTransactionError>::ServerError(JsonRpcServerError::InternalError {
                info: Some("Internal server error".into()),
            }),
        )));
        assert_eq!(carrier(&err).status(), None);
        assert!(is_retryable(&err));
        assert!(!is_provider_throttled(&err));
    }

    #[test]
    fn statusless_failures_are_retryable_and_never_throttle_on_text() {
        let statusless =
            NearFetchError::RpcReturnedInvalidData("upstream said 429 but typed nothing".into());
        let err = send_failure(statusless);
        assert!(is_retryable(&err));
        assert!(!is_provider_throttled(&err));
    }

    /// The render is the carrier message, once: a wrapper level would print
    /// it twice in every `{err:#}` line.
    #[test]
    fn the_near_error_keeps_the_outermost_render() {
        let err = send_failure(refused_send(
            JsonRpcServerResponseStatusError::TooManyRequests,
        ));
        assert_eq!(err.to_string(), "this client has exceeded the rate limit");
        assert_eq!(
            format!("{err:#}")
                .matches("exceeded the rate limit")
                .count(),
            1
        );
    }

    #[test]
    fn every_rpc_transaction_error_member_stays_retryable() {
        let handler_errors = [
            RpcTransactionError::InvalidTransaction {
                context: near_primitives::errors::InvalidTxError::InvalidNonce {
                    tx_nonce: 401,
                    ak_nonce: 429,
                },
            },
            RpcTransactionError::DoesNotTrackShard,
            RpcTransactionError::RequestRouted {
                transaction_hash: CryptoHash([0; 32]),
            },
            RpcTransactionError::UnknownTransaction {
                requested_transaction_hash: CryptoHash([0; 32]),
            },
            RpcTransactionError::InternalError {
                debug_info: "at line 1 column 401 of 429".into(),
            },
            RpcTransactionError::TimeoutError,
        ];
        assert_eq!(
            handler_errors.len(),
            6,
            "the vendored family gained a member"
        );
        for error in &handler_errors {
            let err = send_failure(NearFetchError::RpcTransactionError(Box::new(
                JsonRpcError::ServerError(JsonRpcServerError::HandlerError(error.clone())),
            )));
            assert!(is_retryable(&err), "{error}");
            assert!(!is_provider_throttled(&err), "{error}");
        }
    }

    #[tokio::test]
    async fn a_malformed_view_is_retryable_and_never_throttles() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(malformed_view_envelope())
            .expect(1)
            .create_async()
            .await;
        let client = near_fetch::Client::new(&server.url());

        let err = view_json::<u64>(
            client
                .view(&contract_id(), "read")
                .args_json(serde_json::json!({ "reads": [] })),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("column 401"), "{err:#}");
        assert!(is_retryable(&err), "the serde text is not a status");
        assert!(!is_provider_throttled(&err));
        mock.assert_async().await;
    }

    fn publisher(client: near_fetch::Client, gate: SharedBackoff) -> NearClient {
        NearClient::new(
            client,
            &contract_id(),
            signer(),
            NearRpcGates::new(gate),
            Arc::new(NoopPublisherTelemetry),
        )
    }

    fn action() -> mpc_chain_integration_core::PublishAction {
        make_publish_action(Chain::NEAR, SignKind::Sign, SignId::new([0u8; 32]))
    }

    /// One gated send through a warm client, after a `block` refusal.
    async fn warm_send(
        server: &mut ServerGuard,
        block_status: usize,
    ) -> (anyhow::Error, Mock, Mock) {
        let client = warm_client(server).await;
        let block = method_mock(server, "block", block_status, "", 1).await;
        let send = method_mock(server, "send_tx", 200, "", 0).await;
        let signer = signer();
        let err = NearRpcGates::new(SharedBackoff::new())
            .transact(respond(&client, &signer))
            .await
            .unwrap_err();
        (err, block, send)
    }

    #[tokio::test]
    async fn a_warm_cache_block_throttle_engages_the_gate_before_the_send() {
        let mut server = Server::new_async().await;
        let (err, block, send) = warm_send(&mut server, 429).await;
        assert!(is_retryable(&err), "the block 429 stays retryable");
        assert!(is_provider_throttled(&err), "the block 429 throttles");
        block.assert_async().await;
        send.assert_async().await;
    }

    #[tokio::test]
    async fn a_warm_cache_block_unauthorized_is_terminal_before_the_send() {
        let mut server = Server::new_async().await;
        let (err, block, send) = warm_send(&mut server, 401).await;
        assert!(!is_retryable(&err), "the block 401 is terminal");
        assert!(!is_provider_throttled(&err));
        block.assert_async().await;
        send.assert_async().await;
    }

    #[tokio::test]
    async fn real_send_refusals_follow_the_send_partition() {
        for (status, retryable, throttled) in [
            (400, false, false),
            (401, false, false),
            (402, true, true),
            (409, false, false),
            (429, true, true),
            // `JsonRpcClient::call` wraps a 500 as `InternalError`, which carries no status.
            (500, true, false),
            (503, true, false),
        ] {
            let mut server = Server::new_async().await;
            let client = warm_client(&mut server).await;
            let block = method_mock(&mut server, "block", 200, &block_envelope(), 1).await;
            let send = method_mock(&mut server, "send_tx", status, "", 1).await;

            let signer = signer();
            let err = NearRpcGates::new(SharedBackoff::new())
                .transact(respond(&client, &signer))
                .await
                .unwrap_err();

            assert_eq!(is_retryable(&err), retryable, "verdict for {status}");
            assert_eq!(
                is_provider_throttled(&err),
                throttled,
                "throttle for {status}"
            );
            block.assert_async().await;
            send.assert_async().await;
        }
    }

    /// The vendor's 429 render carries no digits, so only the typed status
    /// can engage the gate here. Paused clock: the gate's waits fast-forward,
    /// while `remaining()` keeps its real 5 s window for the assertion.
    #[tokio::test(start_paused = true)]
    async fn a_throttled_publisher_call_engages_the_gate_and_stays_retryable() {
        let mut server = Server::new_async().await;
        let client = warm_client(&mut server).await;
        let block = method_mock(&mut server, "block", 429, "", 4).await;
        let send = method_mock(&mut server, "send_tx", 200, "", 0).await;

        let gate = SharedBackoff::with_cooldowns(Duration::from_secs(5), Duration::from_secs(60));
        let near = publisher(client, gate.clone());

        let err = near.publish_signature(&action()).await.unwrap_err();
        assert!(is_retryable(&err), "429 stays retryable");
        assert!(is_provider_throttled(&err), "the typed 429 throttles");
        assert!(!gate.remaining().is_zero(), "the shared gate engaged");
        block.assert_async().await;
        send.assert_async().await;
    }

    #[tokio::test]
    async fn an_unauthorized_publisher_call_is_terminal_after_one_attempt() {
        let mut server = Server::new_async().await;
        let client = warm_client(&mut server).await;
        let block = method_mock(&mut server, "block", 401, "", 1).await;
        let send = method_mock(&mut server, "send_tx", 200, "", 0).await;

        let gate = SharedBackoff::with_cooldowns(Duration::from_secs(5), Duration::from_secs(60));
        let near = publisher(client, gate.clone());

        let err = near.publish_signature(&action()).await.unwrap_err();
        assert!(!is_retryable(&err), "401 is terminal");
        assert!(!is_provider_throttled(&err));
        assert!(gate.remaining().is_zero(), "no gate engagement");
        block.assert_async().await;
        send.assert_async().await;
    }

    /// The validation refusal over HTTP 200: nonce digits must not flip
    /// verdicts or throttle. Each refusal invalidates the nonce cache, so only
    /// the first attempt takes the warm path's `block` query.
    #[tokio::test]
    async fn a_digit_bearing_handler_rejection_stays_retryable() {
        let mut server = Server::new_async().await;
        let client = warm_client(&mut server).await;
        let block = method_mock(&mut server, "block", 200, &block_envelope(), 1).await;
        let query = method_mock(&mut server, "query", 200, &access_key_envelope(), 3).await;
        let send = method_mock(
            &mut server,
            "send_tx",
            200,
            &handler_error_envelope(near_primitives::errors::InvalidTxError::InvalidNonce {
                tx_nonce: 401,
                ak_nonce: 429,
            }),
            4,
        )
        .await;

        let gate = SharedBackoff::new();
        let near = publisher(client, gate.clone());

        let err = near.publish_signature(&action()).await.unwrap_err();
        assert!(
            is_retryable(&err),
            "the retry budget is spent, not cut short"
        );
        assert!(
            !is_provider_throttled(&err),
            "nonce digits are not statuses"
        );
        assert!(gate.remaining().is_zero());
        block.assert_async().await;
        query.assert_async().await;
        send.assert_async().await;
    }
}
