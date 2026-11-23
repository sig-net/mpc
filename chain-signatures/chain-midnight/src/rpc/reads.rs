//! Finalized reads with retry: the read-partition verdict, the contract-state
//! wire policy, and the network-id decode boundary.

use std::time::Duration;

use anyhow::Context as _;
use http::StatusCode;
use jsonrpsee::core::client::Error as JsonrpseeClientError;
use jsonrpsee::types::error::{INVALID_PARAMS_CODE, OVERSIZED_RESPONSE_CODE};
use mpc_chain_integration_core::utils::retry::{exhausted, RetryConfig};
use subxt::backend::legacy::rpc_methods::{BlockDetails, NumberOrHex};
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::ext::codec::DecodeAll as _;
use subxt::ext::subxt_rpcs::{rpc_params, Error as RawRpcError, UserError};
use subxt::utils::H256;
use subxt::SubstrateConfig;

use super::publisher_rpc::read_verdict;
#[cfg(feature = "sandbox")]
use super::transport::connect_http_endpoint;
use super::transport::{MAX_CALLER_STATE_BYTES, MAX_RESPONSE_SIZE, MIN_PROVING_RESPONSE_CAP};
#[cfg(feature = "sandbox")]
use crate::config::RpcConfig;
use crate::types::{BlockHash, MidnightAddress, NetworkId};

const STATE_TOO_LARGE: &str = "midnight contract state exceeds the protocol limit";

/// What produced an [`OversizedContractState`] marker. The publish path treats
/// The connected runtime is the canonical owner of the wallet network identity.
pub(super) const NETWORK_ID_ENTRY: &str = "MidnightRuntimeApi_get_network_id";

/// only a client-cap refusal as terminal, because [`MAX_RESPONSE_SIZE`] is a
/// compile-time constant.
#[derive(Debug)]
enum OversizedContractStateSource {
    /// The jsonrpsee HTTP client refused the response before reading it.
    ClientCap,
    /// An RPC node returned [`OVERSIZED_RESPONSE_CODE`] with a cap at least as
    /// large as [`MIN_PROVING_RESPONSE_CAP`].
    NodeCap,
    /// The decoded state exceeded [`MAX_CALLER_STATE_BYTES`]. Used by the
    /// indexer admission path.
    DecodedLimit,
}

#[derive(Debug)]
struct OversizedContractState {
    detail: String,
    source: Option<RawRpcError>,
    provenance: OversizedContractStateSource,
}

impl std::fmt::Display for OversizedContractState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{STATE_TOO_LARGE}: {}", self.detail)
    }
}

impl std::error::Error for OversizedContractState {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

pub(crate) fn oversized_contract_state(detail: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(OversizedContractState {
        detail: detail.into(),
        source: None,
        provenance: OversizedContractStateSource::DecodedLimit,
    })
}

pub(crate) fn is_oversized_contract_state(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.is::<OversizedContractState>())
}
fn decode_network_id(answer: &[u8]) -> anyhow::Result<NetworkId> {
    let mut payload = answer;
    let reported = String::decode_all(&mut payload)
        .context("midnight runtime returned a malformed network id")?;
    NetworkId::try_from(reported.as_str()).context("the midnight node reported an unknown network")
}

/// The network id of the node at `node_http_url` once it has imported block 1, or
/// `None` while it has not; an unlisted id is an error naming it, never a reported
/// value. Dials afresh on every call, so a sandbox that is still booting answers with
/// a connection error and the caller keeps polling.
#[cfg(feature = "sandbox")]
pub async fn probe_network_id(node_http_url: &str) -> anyhow::Result<Option<NetworkId>> {
    let rpc = connect_http_endpoint(node_http_url, &RpcConfig::default())?;
    let legacy = LegacyRpcMethods::<SubstrateConfig>::new(rpc);
    let block_one = legacy
        .chain_get_block_hash(Some(NumberOrHex::Number(1)))
        .await
        .context("fetching the hash of midnight block 1")?;
    if block_one.is_none() {
        return Ok(None);
    }
    network_id(&legacy).await.map(Some)
}

/// The `midnight_contractState` parameters: the address as 64 bare hex characters
/// — the one wire surface that takes it without `0x` — beside the `0x`-prefixed
/// block hash.
pub(super) async fn network_id(
    legacy: &LegacyRpcMethods<SubstrateConfig>,
) -> anyhow::Result<NetworkId> {
    let finalized = legacy
        .chain_get_finalized_head()
        .await
        .context("failed to fetch the midnight finalized head")?;
    let answer = legacy
        .state_call(NETWORK_ID_ENTRY, Some(&[]), Some(finalized))
        .await
        .context("failed to fetch the midnight network id")?;
    decode_network_id(&answer)
}

fn contract_state_params(
    address: &MidnightAddress,
    at_block_hash: &BlockHash,
) -> subxt::ext::subxt_rpcs::client::RpcParams {
    rpc_params![address.to_hex(), at_block_hash.to_string()]
}

pub(super) async fn publisher_contract_state(
    rpc: &RpcClient,
    address: &MidnightAddress,
    at_block_hash: &BlockHash,
) -> anyhow::Result<Option<Vec<u8>>> {
    let response = rpc
        .request::<String>(
            "midnight_contractState",
            contract_state_params(address, at_block_hash),
        )
        .await;

    match classify_contract_state_reply(response)? {
        ContractStateReply::State(state) => Ok(state),
        // Only the client-cap refusal is terminal on the publish path: the cap
        // is a compile-time constant, so retry cannot help. A node-cap refusal
        // is retryable because the operator can raise the node's response cap.
        ContractStateReply::TooLarge(marker)
            if matches!(marker.provenance, OversizedContractStateSource::ClientCap) =>
        {
            Err(anyhow::Error::new(marker)
                .context("the responder's state was refused by the client's own cap"))
        }
        ContractStateReply::TooLarge(marker) => {
            let err = marker.source.unwrap_or_else(|| {
                RawRpcError::User(UserError {
                    code: OVERSIZED_RESPONSE_CODE,
                    message: "response too large".into(),
                    data: None,
                })
            });
            Err(anyhow::Error::new(err).context("midnight_contractState failed"))
        }
        ContractStateReply::Other(err) => {
            Err(anyhow::Error::new(err).context("midnight_contractState failed"))
        }
    }
}

/// One `midnight_contractState` answer, classified once for both transports. The node
/// builds every rpc error as invalid-params with the reason only in the text, so
/// contract absence stays a text match under the code gate.
enum ContractStateReply {
    /// The state bytes, or `None` when the contract is not present at that block.
    State(Option<Vec<u8>>),
    /// State over [`MAX_CALLER_STATE_BYTES`]: definitive, since retrying cannot
    /// shrink a contract's state.
    TooLarge(OversizedContractState),
    /// Anything else; the transport's own policy decides.
    Other(RawRpcError),
}

fn classify_contract_state_reply(
    response: Result<String, RawRpcError>,
) -> anyhow::Result<ContractStateReply> {
    Ok(match response {
        Ok(state_hex) => ContractStateReply::State(Some(
            hex::decode(state_hex.trim_start_matches("0x"))
                .context("midnight_contractState returned non-hex state")?,
        )),
        Err(RawRpcError::User(reply))
            if reply.code == INVALID_PARAMS_CODE
                && reply.message.contains("Contract not present") =>
        {
            ContractStateReply::State(None)
        }
        // The client refuses a response over MAX_RESPONSE_SIZE before it sees the
        // bytes; that is over 16 MiB of state, so over the limit on every node.
        Err(err) if is_response_too_large(&err) => {
            ContractStateReply::TooLarge(OversizedContractState {
                detail: format!("response over the client cap of {MAX_RESPONSE_SIZE} bytes"),
                source: Some(err),
                provenance: OversizedContractStateSource::ClientCap,
            })
        }
        // The RPC node refused the response for its size. Under a cap that fits every
        // admissible state the state is over the limit on every node; under a
        // smaller cap the verdict would be that node's configuration, so the block
        // is held like any other read failure.
        Err(RawRpcError::User(reply)) if reply.code == OVERSIZED_RESPONSE_CODE => {
            match server_response_cap(&reply) {
                Some(cap) if cap >= MIN_PROVING_RESPONSE_CAP => {
                    ContractStateReply::TooLarge(OversizedContractState {
                        detail: format!("response over the rpc node's cap of {cap} bytes"),
                        source: Some(RawRpcError::User(reply)),
                        provenance: OversizedContractStateSource::NodeCap,
                    })
                }
                cap => {
                    if let Some(count) = mpc_utils::throttle::check("midnight:rpc-cap-refusal") {
                        tracing::warn!(
                            count,
                            ?cap,
                            min_cap = MIN_PROVING_RESPONSE_CAP,
                            "the midnight rpc node's response cap refused a contract state"
                        );
                    }
                    ContractStateReply::Other(RawRpcError::User(reply))
                }
            }
        }
        Err(err) => ContractStateReply::Other(err),
    })
}

/// The cap a jsonrpsee server names in its oversized-response error, whose data is
/// the string `Exceeded max limit of <bytes>` (jsonrpsee-core 0.24.10,
/// `server/method_response.rs`).
fn server_response_cap(reply: &UserError) -> Option<usize> {
    let data: String = serde_json::from_str(reply.data.as_ref()?.get()).ok()?;
    data.strip_prefix("Exceeded max limit of ")?.parse().ok()
}

/// The indexer's limit on a caller state it did receive. The publisher reads the
/// responder through the same classifier and is not bound by it.
fn admit_caller_state(state: Option<Vec<u8>>) -> anyhow::Result<Option<Vec<u8>>> {
    match state {
        Some(state) if state.len() > MAX_CALLER_STATE_BYTES => Err(oversized_contract_state(
            format!("{} bytes, limit {MAX_CALLER_STATE_BYTES}", state.len()),
        )),
        state => Ok(state),
    }
}

/// Whether the jsonrpsee HTTP transport refused the response body for its size:
/// up front on a `Content-Length` over the cap, or while streaming a body without
/// one.
fn is_response_too_large(error: &RawRpcError) -> bool {
    use jsonrpsee::core::http_helpers::HttpError;

    let RawRpcError::Client(client_error) = error else {
        return false;
    };
    let Some(JsonrpseeClientError::Transport(transport_error)) =
        client_error.downcast_ref::<JsonrpseeClientError>()
    else {
        return false;
    };
    match transport_error.downcast_ref::<jsonrpsee::http_client::transport::Error>() {
        Some(jsonrpsee::http_client::transport::Error::Http(HttpError::TooLarge)) => true,
        Some(jsonrpsee::http_client::transport::Error::Http(HttpError::Stream(stream))) => {
            stream.is::<http_body_util::LengthLimitError>()
        }
        _ => false,
    }
}

/// The bare payload of the ledger-parameters `Result<Vec<u8>, _>` runtime-API answer
/// at `MidnightRuntimeApi` version 2 (node 2.0.0-rc.4). `None` is the `Err` variant:
/// only its discriminant is decoded, so an unseen ledger error stays `Err`.
pub(super) fn unwrap_runtime_api_result(answer: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    let (variant, mut payload) = answer
        .split_first()
        .context("runtime api returned an empty Result envelope")?;
    match *variant {
        0 => Ok(Some(
            Vec::<u8>::decode_all(&mut payload)
                .context("runtime api Ok payload is not a SCALE Vec<u8>")?,
        )),
        1 => Ok(None),
        other => anyhow::bail!("runtime api returned Result variant {other}"),
    }
}

/// The one-shot reads over an explicit transport, so offline tests can drive them.
pub(super) struct Reads {
    rpc: RpcClient,
    legacy: LegacyRpcMethods<SubstrateConfig>,
    pub(super) request_timeout: Duration,
    pub(super) retry: RetryConfig,
}

/// The HTTP status a transport rejection in `error`'s chain carries, if any.
/// jsonrpsee stores a parsed `StatusCode` as u16 (jsonrpsee-http-client 0.24.10
/// transport.rs:337), so `from_u16` cannot fail on what it produces.
pub(crate) fn rejected_http_status(error: &anyhow::Error) -> Option<StatusCode> {
    error.chain().find_map(|cause| {
        let RawRpcError::Client(client_error) = cause.downcast_ref::<RawRpcError>()? else {
            return None;
        };
        let JsonrpseeClientError::Transport(transport_error) =
            client_error.downcast_ref::<JsonrpseeClientError>()?
        else {
            return None;
        };
        let jsonrpsee::http_client::transport::Error::Rejected { status_code } =
            transport_error.downcast_ref::<jsonrpsee::http_client::transport::Error>()?
        else {
            return None;
        };
        StatusCode::from_u16(*status_code).ok()
    })
}

/// The indexer loop's bool form of the publisher reads' verdict
/// ([`read_verdict`]): one partition, one derivation.
fn is_read_retryable(error: &anyhow::Error) -> bool {
    !read_verdict(error).is_terminal()
}

pub(super) async fn retry_read<T, F, Fut>(
    timeout: Duration,
    retry: RetryConfig,
    operation: &'static str,
    mut attempt: F,
) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let mut retry_count = 0u32;
    let operation_call = || {
        let future = attempt();
        async move {
            match tokio::time::timeout(timeout, future).await {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("operation timed out after {timeout:?}")),
            }
        }
    };
    use mpc_chain_integration_core::backon::Retryable as _;
    operation_call
        .retry(&retry.build())
        .when(is_read_retryable)
        .notify(|error, retry_in| {
            retry_count += 1;
            tracing::warn!(
                operation,
                attempt = retry_count,
                error = %format_args!("{error:#}"),
                ?retry_in,
                "RPC call failed, retrying"
            );
        })
        .await
        .map_err(|error| exhausted(error, retry_count))
}

impl Reads {
    pub(super) fn new(rpc: RpcClient, request_timeout: Duration, retry: RetryConfig) -> Self {
        Self {
            legacy: LegacyRpcMethods::<SubstrateConfig>::new(rpc.clone()),
            rpc,
            request_timeout,
            retry,
        }
    }

    pub(super) async fn finalized_head(&self) -> anyhow::Result<H256> {
        retry_read(
            self.request_timeout,
            self.retry,
            "midnight_finalized_head",
            || async {
                self.legacy
                    .chain_get_finalized_head()
                    .await
                    .map_err(anyhow::Error::new)
                    .context("failed to fetch the midnight finalized head")
            },
        )
        .await
    }

    pub(super) async fn header(
        &self,
        hash: H256,
    ) -> anyhow::Result<Option<<SubstrateConfig as subxt::Config>::Header>> {
        retry_read(
            self.request_timeout,
            self.retry,
            "midnight_header",
            || async {
                self.legacy
                    .chain_get_header(Some(hash))
                    .await
                    .map_err(anyhow::Error::new)
                    .context("failed to fetch a block header")
            },
        )
        .await
    }

    /// Header and body in one call: `chain_getBlock` carries the header.
    pub(super) async fn block(
        &self,
        hash: H256,
    ) -> anyhow::Result<Option<BlockDetails<SubstrateConfig>>> {
        self.block_with(hash, self.retry).await
    }

    /// [`block`](Self::block) in a single attempt.
    pub(super) async fn block_once(
        &self,
        hash: H256,
    ) -> anyhow::Result<Option<BlockDetails<SubstrateConfig>>> {
        let once = RetryConfig {
            max_times: 0,
            ..self.retry
        };
        self.block_with(hash, once).await
    }

    async fn block_with(
        &self,
        hash: H256,
        retry: RetryConfig,
    ) -> anyhow::Result<Option<BlockDetails<SubstrateConfig>>> {
        retry_read(self.request_timeout, retry, "midnight_block", || async {
            self.legacy
                .chain_get_block(Some(hash))
                .await
                .map_err(anyhow::Error::new)
                .context("failed to fetch a midnight block")
        })
        .await
    }

    pub(super) async fn block_hash_at(&self, number: u64) -> anyhow::Result<Option<H256>> {
        retry_read(
            self.request_timeout,
            self.retry,
            "midnight_block_hash_at",
            || async {
                self.legacy
                    .chain_get_block_hash(Some(NumberOrHex::Number(number)))
                    .await
                    .map_err(anyhow::Error::new)
                    .context("failed to fetch a block hash by number")
            },
        )
        .await
    }

    pub(super) async fn contract_state(
        &self,
        address: &MidnightAddress,
        at_block_hash: &BlockHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        retry_read(
            self.request_timeout,
            self.retry,
            "midnight_contractState",
            || async {
                let response: Result<String, _> = self
                    .rpc
                    .request(
                        "midnight_contractState",
                        contract_state_params(address, at_block_hash),
                    )
                    .await;

                match classify_contract_state_reply(response)? {
                    ContractStateReply::State(state) => admit_caller_state(state),
                    ContractStateReply::TooLarge(err) => Err(anyhow::Error::new(err)),
                    ContractStateReply::Other(err) => {
                        Err(anyhow::Error::new(err).context("midnight_contractState failed"))
                    }
                }
            },
        )
        .await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::support::*;

    use crate::rpc::publisher_rpc::attach_read_carrier;
    use crate::rpc::transport::connect_http;
    use crate::rpc::MidnightPublisherRpc;
    use crate::submit_error::SubmitError;
    use jsonrpsee::server::ServerBuilder;
    use jsonrpsee::RpcModule;
    use mpc_chain_integration_core::utils::retry::RpcFailure;
    use mpc_chain_integration_core::utils::retry::{is_provider_throttled, is_retryable};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use subxt::backend::rpc::RawValue;
    use subxt::ext::codec::Encode as _;
    use subxt::ext::subxt_rpcs::UserError;

    #[tokio::test]
    async fn real_http_statuses_follow_the_read_partition() {
        // 409 retries on purpose: another LB backend may serve the read fine
        for (status, reason, expected_attempts) in [
            (403, "Forbidden", 1),
            (409, "Conflict", 3),
            (429, "Too Many Requests", 3),
            (402, "Payment Required", 3),
            (500, "Internal Server Error", 3),
        ] {
            let (address, calls, server) = http_status_server(status, reason).await;
            let config = http_config(address);
            let reads = Reads::new(
                connect_http(&config).expect("build request-only client"),
                Duration::from_secs(1),
                attempts(2),
            );

            let err = tokio::time::timeout(Duration::from_secs(1), reads.finalized_head())
                .await
                .expect("bounded retry policy timed out")
                .expect_err("an HTTP rejection must fail the read");
            server.abort();
            let _ = server.await;

            assert_eq!(
                rejected_http_status(&err),
                Some(StatusCode::from_u16(status).unwrap()),
                "status {status} was lost from the typed error chain: {err:#}"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                expected_attempts,
                "HTTP {status} used the wrong retry policy"
            );
        }
    }

    /// jsonrpsee's `Rejected` wire shape (jsonrpsee-http-client 0.24.10
    /// transport.rs:376), as a raw HTTP status fails these reads.
    fn rejected_read(status: u16) -> anyhow::Error {
        let transport = jsonrpsee::http_client::transport::Error::Rejected {
            status_code: status,
        };
        let client = JsonrpseeClientError::Transport(Box::new(transport));
        anyhow::Error::new(RawRpcError::Client(Box::new(client)))
            .context("failed to fetch the midnight finalized head")
    }

    #[test]
    fn every_http_status_classifies_under_the_read_partition() {
        // Every status jsonrpsee can report — parsed StatusCode, so 100..=599
        // (jsonrpsee-http-client 0.24.10 transport.rs:337) — at both call
        // sites of the shared derivation.
        for code in 100..=599u16 {
            let read = attach_read_carrier(rejected_read(code));
            let node = SubmitError::Node {
                source: rejected_read(code),
            }
            .into_publish_error();
            for error in [&read, &node] {
                assert_eq!(
                    is_retryable(error),
                    !matches!(code, 400 | 401 | 403 | 404 | 405),
                    "{code}: {error:#}"
                );
                assert_eq!(
                    is_provider_throttled(error),
                    matches!(code, 402 | 429),
                    "{code}: {error:#}"
                );
            }
            // The indexer loop's bool form, on the raw error `retry_read` sees.
            assert_eq!(
                is_read_retryable(&rejected_read(code)),
                !matches!(code, 400 | 401 | 403 | 404 | 405),
                "{code}"
            );
        }
    }

    #[test]
    fn a_statusless_read_failure_is_retryable_and_never_throttled() {
        // No typed status means no gate, however status-like the render.
        let node_answer = RawRpcError::User(UserError {
            code: 4000,
            message: "429 Too Many Requests".into(),
            data: None,
        });
        let error = attach_read_carrier(
            anyhow::Error::new(node_answer).context("midnight_contractState failed"),
        );
        assert!(is_retryable(&error), "{error:#}");
        assert!(!is_provider_throttled(&error), "{error:#}");
    }

    #[test]
    fn upstream_carriers_win_over_the_read_derivation() {
        let terminal = attach_read_carrier(
            anyhow::Error::new(RpcFailure::terminal("upstream refused".to_string()))
                .context("a read"),
        );
        assert!(!is_retryable(&terminal), "{terminal:#}");

        // The carrier's verdict wins over the read partition its status implies.
        let retryable = attach_read_carrier(
            anyhow::Error::new(RpcFailure::retryable_with_status(
                StatusCode::FORBIDDEN,
                "upstream retry".to_string(),
            ))
            .context("a read"),
        );
        assert!(is_retryable(&retryable), "{retryable:#}");
        assert!(!is_provider_throttled(&retryable), "{retryable:#}");
    }

    /// fits every admissible state that proves the state is over the limit; under
    /// a smaller cap it is the node's configuration, so the read is retried.
    #[tokio::test]
    async fn server_response_cap_refusal_is_a_drop_only_under_an_admissible_cap() {
        for (server_cap, state_bytes, expected_drop, expected_attempts) in [
            (15 * 1024 * 1024, 8 * 1024 * 1024, true, 1),
            (64 * 1024, 100 * 1024, false, 3),
        ] {
            let server = ServerBuilder::default()
                .max_response_body_size(server_cap)
                .build("127.0.0.1:0")
                .await
                .expect("bind HTTP rpc server");
            let address = server.local_addr().expect("HTTP rpc server address");
            let mut module = RpcModule::new(());
            module
                .register_method("midnight_contractState", move |_, _, _| {
                    "ab".repeat(state_bytes)
                })
                .expect("register state method");
            let _handle = server.start(module);

            let config = http_config(address);
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = CountingRpc {
                inner: connect_http(&config).expect("build transport"),
                calls: calls.clone(),
            };
            let reads = Reads::new(RpcClient::new(counted), READ_TIMEOUT, attempts(2));
            let err = reads
                .contract_state(&test_address(), &test_at_hash())
                .await
                .expect_err("the server refuses the response");
            assert_eq!(
                is_oversized_contract_state(&err),
                expected_drop,
                "cap {server_cap}: {err:#}"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                expected_attempts,
                "cap {server_cap}"
            );
        }
    }

    /// A state both caps let through is still bounded by the decoded length.
    #[tokio::test]
    async fn a_state_over_the_limit_but_under_both_caps_is_a_drop() {
        let server = ServerBuilder::default()
            .max_response_body_size(MAX_RESPONSE_SIZE)
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_method("midnight_contractState", |_, _, _| {
                "ab".repeat(MAX_CALLER_STATE_BYTES + 1)
            })
            .expect("register state method");
        let _handle = server.start(module);

        let calls = Arc::new(AtomicUsize::new(0));
        let counted = CountingRpc {
            inner: connect_http(&http_config(address)).expect("build transport"),
            calls: calls.clone(),
        };
        let reads = Reads::new(RpcClient::new(counted), READ_TIMEOUT, attempts(2));
        let err = reads
            .contract_state(&test_address(), &test_at_hash())
            .await
            .expect_err("one byte over the limit");
        assert!(is_oversized_contract_state(&err), "{err:#}");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a drop is not retried");
    }

    #[test]
    fn contract_state_limit_is_on_the_decoded_length() {
        let at_limit = vec![0xab; MAX_CALLER_STATE_BYTES];
        assert_eq!(
            admit_caller_state(Some(at_limit.clone()))
                .expect("a state at the limit is admitted")
                .map(|state| state.len()),
            Some(MAX_CALLER_STATE_BYTES)
        );
        assert_eq!(admit_caller_state(None).expect("absence is a value"), None);

        let mut over = at_limit;
        over.push(0xcd);
        let err = admit_caller_state(Some(over)).expect_err("one byte over is too large");
        assert!(is_oversized_contract_state(&err));
    }

    const NOT_PRESENT_MSG: &str = "Contract not present at the requested address";
    const UNSERVABLE_MSG: &str = "Unable to get requested contract state";

    fn stub_reads(reply: Canned, retry: RetryConfig) -> (Reads, Arc<AtomicUsize>) {
        let (rpc, calls) = stub_rpc(reply);
        (Reads::new(rpc, READ_TIMEOUT, retry), calls)
    }

    /// Pins the wire pair both transports send: the address bare 64-hex, the block
    /// hash `0x`-prefixed — the one seam where the two conventions meet.
    #[tokio::test]
    async fn contract_state_params_pin_the_bare_address_and_prefixed_hash() {
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_method("midnight_contractState", |params, _, _| {
                assert_eq!(
                    params.parse::<Vec<String>>().unwrap(),
                    [ADDRESS, AT_HASH],
                    "the address must be bare 64-hex and the block hash 0x-prefixed"
                );
                "0xcafe"
            })
            .expect("register state method");
        let _handle = server.start(module);

        let rpc = connect_http(&http_config(address)).expect("build transport");
        let reads = Reads::new(rpc.clone(), READ_TIMEOUT, attempts(1));
        reads
            .contract_state(&test_address(), &test_at_hash())
            .await
            .expect("the reader must succeed against the stub")
            .expect("the stub serves a state");
        publisher_contract_state(&rpc, &test_address(), &test_at_hash())
            .await
            .expect("the publisher must succeed against the stub")
            .expect("the stub serves a state");
    }

    #[tokio::test]
    async fn contract_state_reply_policy_is_typed_and_budgeted() {
        const DATA: &str = r#"{"detail":"recover me"}"#;
        let (publisher_rpc, _) = stub_rpc(Canned::UserWithData(
            INVALID_PARAMS_CODE,
            UNSERVABLE_MSG,
            DATA,
        ));
        let publisher_error =
            publisher_contract_state(&publisher_rpc, &test_address(), &test_at_hash())
                .await
                .expect_err("the node reply is a publisher read failure");
        let publisher_cause = publisher_error
            .chain()
            .find_map(|cause| cause.downcast_ref::<RawRpcError>())
            .expect("the publisher must retain the structured RPC cause");
        let RawRpcError::User(publisher_user) = publisher_cause else {
            panic!("unexpected publisher cause: {publisher_cause:?}");
        };
        assert_eq!(publisher_user.code, INVALID_PARAMS_CODE);
        assert_eq!(publisher_user.message, UNSERVABLE_MSG);
        assert_eq!(
            publisher_user.data.as_deref().map(RawValue::get),
            Some(DATA)
        );

        let (reads, calls) = stub_reads(
            Canned::User(INVALID_PARAMS_CODE, NOT_PRESENT_MSG),
            attempts(2),
        );
        assert_eq!(
            reads
                .contract_state(&test_address(), &test_at_hash())
                .await
                .expect("contract-not-present is a value"),
            None
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        for (reply, expected_class, expected_attempts) in [
            (
                Canned::UserWithData(INVALID_PARAMS_CODE, UNSERVABLE_MSG, DATA),
                false,
                3,
            ),
            // a refusal that does not name its cap is held
            (
                Canned::UserWithData(
                    OVERSIZED_RESPONSE_CODE,
                    "state exceeds the response limit",
                    DATA,
                ),
                false,
                3,
            ),
            (Canned::UserWithData(12345, STATE_TOO_LARGE, DATA), false, 3),
            // the cap the refusal names decides: admissible cap proves the size
            (
                Canned::UserWithData(
                    OVERSIZED_RESPONSE_CODE,
                    "Response is too big",
                    r#""Exceeded max limit of 15728640""#,
                ),
                true,
                1,
            ),
            (
                Canned::UserWithData(
                    OVERSIZED_RESPONSE_CODE,
                    "Response is too big",
                    r#""Exceeded max limit of 65536""#,
                ),
                false,
                3,
            ),
            (Canned::ClientErr, false, 3),
            (Canned::ClientTooLarge, true, 1),
        ] {
            let (reads, calls) = stub_reads(reply, attempts(2));
            let err = reads
                .contract_state(&test_address(), &test_at_hash())
                .await
                .expect_err("the canned node answer is a failure");

            assert_eq!(is_oversized_contract_state(&err), expected_class, "{err:#}");
            let cause = err
                .chain()
                .find_map(|cause| cause.downcast_ref::<RawRpcError>())
                .expect("retry must retain the structured RPC cause");
            match (reply, cause) {
                (Canned::UserWithData(code, message, data), RawRpcError::User(user)) => {
                    assert_eq!(user.code, code);
                    assert_eq!(user.message, message);
                    assert_eq!(user.data.as_deref().map(RawValue::get), Some(data));
                }
                (Canned::ClientErr | Canned::ClientTooLarge, RawRpcError::Client(_)) => {}
                _ => panic!("unexpected structured cause: {cause:?}"),
            }
            assert_eq!(
                calls.load(Ordering::SeqCst),
                expected_attempts,
                "classification changed the retry policy"
            );
        }
    }

    #[test]
    fn network_id_decoder_consumes_the_whole_scale_value() {
        let encoded = "preview".to_string().encode();
        assert_eq!(decode_network_id(&encoded).unwrap(), NetworkId::Preview);

        let mut trailing = encoded;
        trailing.push(0xff);
        let err = decode_network_id(&trailing)
            .expect_err("a trailing byte must make the network id malformed");
        assert!(
            err.to_string()
                .contains("midnight runtime returned a malformed network id"),
            "the decoder boundary must identify the malformed network id: {err:#}"
        );
    }

    #[test]
    fn an_unknown_network_id_fails_the_decode_boundary_with_the_reported_id() {
        let err = decode_network_id(&"devnet".to_string().encode())
            .expect_err("the publisher builds for no unknown network");
        assert!(
            format!("{err:#}").contains("'devnet'"),
            "the refusal must name the node's answer: {err:#}"
        );
    }

    #[tokio::test]
    async fn connect_refuses_a_node_on_an_unlisted_network() {
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_method("chain_getFinalizedHead", |_, _, _| hash_of_byte(0x43))
            .expect("register finalized-head method");
        let devnet = "devnet".to_string().encode();
        module
            .register_method("state_call", move |params, _, _| {
                let (method, _, _) = params.parse::<(String, String, String)>().unwrap();
                assert_eq!(method, NETWORK_ID_ENTRY);
                format!("0x{}", hex::encode(&devnet))
            })
            .expect("register state-call method");
        let _handle = server.start(module);

        let error = MidnightPublisherRpc::connect(&http_config(address))
            .await
            .err()
            .expect("a node on an unlisted network must not connect");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("'devnet'"), "{rendered}");
        assert!(rendered.contains("unknown network"), "{rendered}");
    }

    /// An unlisted id errors naming it — deterministic, unlike `None`, which is
    /// reserved for a node that has not imported block 1 yet.
    #[cfg(feature = "sandbox")]
    #[tokio::test]
    async fn probing_a_node_on_an_unlisted_network_errors_with_the_reported_id() {
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_method("chain_getBlockHash", |_, _, _| hash_of_byte(0x43))
            .expect("register block-hash method");
        module
            .register_method("chain_getFinalizedHead", |_, _, _| hash_of_byte(0x43))
            .expect("register finalized-head method");
        let devnet = "devnet".to_string().encode();
        module
            .register_method("state_call", move |params, _, _| {
                let (method, _, _) = params.parse::<(String, String, String)>().unwrap();
                assert_eq!(method, NETWORK_ID_ENTRY);
                format!("0x{}", hex::encode(&devnet))
            })
            .expect("register state-call method");
        let _handle = server.start(module);

        let error = probe_network_id(&format!("http://{address}"))
            .await
            .expect_err("an unlisted network is a probe error, never a reported id");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("'devnet'"), "{rendered}");
        assert!(rendered.contains("unknown network"), "{rendered}");
    }

    #[test]
    fn runtime_api_result_envelope_unwraps_ok_err_and_garbage() {
        // Ok(vec![0xaa, 0xbb]): discriminant 0, then a SCALE Vec<u8>.
        let mut ok = vec![0u8];
        ok.extend(vec![0xaau8, 0xbb].encode());
        assert_eq!(
            unwrap_runtime_api_result(&ok).unwrap(),
            Some(vec![0xaa, 0xbb])
        );
        // Err(anything): discriminant 1; the error payload is never decoded.
        assert_eq!(unwrap_runtime_api_result(&[1u8, 0xff]).unwrap(), None);
        // An empty answer and an unknown discriminant are decode faults, not values.
        assert!(unwrap_runtime_api_result(&[]).is_err());
        assert!(unwrap_runtime_api_result(&[2u8]).is_err());
        // Trailing bytes after the Ok payload are a fault: the envelope must consume
        // the whole answer or the read is not what this decoder thinks it is.
        let mut trailing = vec![0u8];
        trailing.extend(vec![0xaau8].encode());
        trailing.push(0x99);
        let err = unwrap_runtime_api_result(&trailing)
            .expect_err("a trailing byte must make the runtime API payload malformed");
        assert!(
            err.to_string()
                .contains("runtime api Ok payload is not a SCALE Vec<u8>"),
            "the decoder boundary must identify the malformed payload: {err:#}"
        );
    }
}
