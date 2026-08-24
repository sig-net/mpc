//! Midnight node RPC: the read transport everything in the read path goes through.

use std::time::Duration;

use anyhow::Context as _;
use jsonrpsee::core::client::{ClientT as _, Error as JsonrpseeClientError};
use jsonrpsee::core::traits::ToRpcParams;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::types::error::{INVALID_PARAMS_CODE, OVERSIZED_RESPONSE_CODE};
use mpc_chain_integration_core::utils::retry::{is_retryable, RetryConfig};
use subxt::backend::legacy::rpc_methods::NumberOrHex;
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::{RawRpcFuture, RawRpcSubscription, RawValue, RpcClient, RpcClientT};
use subxt::ext::codec::DecodeAll as _;
use subxt::ext::subxt_rpcs::{rpc_params, Error as RawRpcError, UserError};
use subxt::utils::H256;
use subxt::SubstrateConfig;

use crate::config::MidnightConfig;

const HTTP_SUBSCRIPTIONS_UNSUPPORTED: &str =
    "midnight HTTP RPC transport does not support subscriptions";

/// Runtime API name from Midnight node 2.0.0-rc.4 metadata.
const LEDGER_PARAMETERS_ENTRY: &str = "MidnightRuntimeApi_get_ledger_parameters";
/// The connected runtime is the canonical owner of the wallet network identity.
const NETWORK_ID_ENTRY: &str = "MidnightRuntimeApi_get_network_id";

/// The classified contract-state read failures. The marker survives retry context;
/// the underlying RPC error remains in the cause chain for diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadFailure {
    /// Pruned or unknown hash: no number of retries makes the node serve it.
    Unservable,
    /// State beyond the rpc response cap: definitive (retrying cannot shrink a
    /// contract's state) and the contract's own property, so reads of it charge
    /// the caller.
    TooLarge,
}

#[derive(Debug)]
struct ClassifiedReadFailure {
    class: ReadFailure,
    source: RawRpcError,
}

impl std::fmt::Display for ClassifiedReadFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.class.marker(), self.source)
    }
}

impl std::error::Error for ClassifiedReadFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl ReadFailure {
    /// The marker text errors of this class carry.
    pub(crate) const fn marker(self) -> &'static str {
        match self {
            Self::Unservable => {
                "midnight node cannot serve contract state at that block (pruned or unknown hash)"
            }
            Self::TooLarge => "midnight contract state exceeds the rpc response cap",
        }
    }

    /// An error of this class whose original RPC error remains its source.
    pub(crate) fn err(self, source: RawRpcError) -> anyhow::Error {
        anyhow::Error::new(ClassifiedReadFailure {
            class: self,
            source,
        })
    }

    /// The class `err` carries, if any.
    pub(crate) fn of(err: &anyhow::Error) -> Option<Self> {
        err.chain().find_map(|cause| {
            cause
                .downcast_ref::<ClassifiedReadFailure>()
                .map(|classified| classified.class)
        })
    }
}

struct Params(Option<Box<RawValue>>);

impl ToRpcParams for Params {
    fn to_rpc_params(self) -> Result<Option<Box<RawValue>>, serde_json::Error> {
        Ok(self.0)
    }
}

/// Request-only jsonrpsee HTTP transport behind Subxt's raw client seam.
#[derive(Clone)]
struct HttpRpcClient {
    inner: HttpClient,
}

impl HttpRpcClient {
    fn from_config(config: &MidnightConfig) -> anyhow::Result<Self> {
        let inner = HttpClientBuilder::default()
            .max_response_size(config.rpc.max_response_size)
            .request_timeout(config.rpc.request_timeout)
            .build(&config.node_url)
            .context("failed to build the midnight HTTP RPC client")?;
        Ok(Self { inner })
    }
}

fn map_jsonrpsee_error(error: JsonrpseeClientError) -> RawRpcError {
    match error {
        JsonrpseeClientError::Call(error) => RawRpcError::User(UserError {
            code: error.code(),
            message: error.message().to_owned(),
            data: error.data().map(ToOwned::to_owned),
        }),
        error => RawRpcError::Client(Box::new(error)),
    }
}

impl RpcClientT for HttpRpcClient {
    fn request_raw<'a>(
        &'a self,
        method: &'a str,
        params: Option<Box<RawValue>>,
    ) -> RawRpcFuture<'a, Box<RawValue>> {
        Box::pin(async move {
            self.inner
                .request(method, Params(params))
                .await
                .map_err(map_jsonrpsee_error)
        })
    }

    fn subscribe_raw<'a>(
        &'a self,
        _sub: &'a str,
        _params: Option<Box<RawValue>>,
        _unsub: &'a str,
    ) -> RawRpcFuture<'a, RawRpcSubscription> {
        Box::pin(async {
            Err(RawRpcError::Client(Box::new(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                HTTP_SUBSCRIPTIONS_UNSUPPORTED,
            ))))
        })
    }
}

/// One finalized block as plain data: the number plus the `0x`-prefixed hashes
/// `midnight_contractState` takes, detached from any subxt handle so fixtures can mint
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRef {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
}

pub(crate) fn ensure_requested_height(requested: u64, returned: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        returned == requested,
        "midnight block lookup requested height {requested} but returned height {returned}"
    );
    Ok(())
}

fn hex_0x(hash: H256) -> String {
    format!("0x{}", hex::encode(hash.as_bytes()))
}

/// The `0x`-prefixed 32-byte block hash every pinned read is addressed by.
fn parse_block_hash(at_block_hash_0x: &str) -> anyhow::Result<H256> {
    let bare = at_block_hash_0x
        .strip_prefix("0x")
        .context("block hash is not 0x-prefixed")?;
    let bytes: [u8; 32] = hex::decode(bare)
        .context("block hash is not hex")?
        .try_into()
        .map_err(|got: Vec<u8>| anyhow::anyhow!("block hash is {} bytes, not 32", got.len()))?;
    Ok(H256(bytes))
}

fn connect_http(config: &MidnightConfig) -> anyhow::Result<RpcClient> {
    Ok(RpcClient::new(HttpRpcClient::from_config(config)?))
}

pub(crate) struct MidnightRpc {
    reads: Reads,
}

impl MidnightRpc {
    /// Builds the request-only client for the node named by `config.node_url`.
    pub async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        let rpc = connect_http(config)?;
        Ok(Self {
            reads: Reads::new(rpc, config.rpc.request_timeout, config.rpc.retry),
        })
    }

    /// Raw contract state of `address_64hex` (64 hex chars, no `0x`) at
    /// `at_block_hash_0x` (`0x`-prefixed), via the `midnight_contractState` JSON-RPC.
    pub async fn contract_state(
        &self,
        address_64hex: &str,
        at_block_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        self.reads
            .contract_state(address_64hex, at_block_hash_0x)
            .await
    }

    /// The finalized head as a [`BlockRef`]: the head hash, then its header for the
    /// number and parent, each read on the ordinary retry budget.
    pub async fn finalized_block_ref(&self) -> anyhow::Result<BlockRef> {
        let hash = self.reads.finalized_head().await?;
        let header = self
            .reads
            .header(hash)
            .await?
            .context("midnight node returned no header for its own finalized head")?;
        Ok(BlockRef {
            number: u64::from(header.number),
            hash: hex_0x(hash),
            parent_hash: hex_0x(header.parent_hash),
        })
    }

    /// The block at `number` as a [`BlockRef`], for the catchup range walk.
    pub async fn block_ref_at(&self, number: u64) -> anyhow::Result<BlockRef> {
        let hash = self
            .reads
            .block_hash_at(number)
            .await?
            .with_context(|| format!("midnight node has no block hash for height {number}"))?;
        let header = self
            .reads
            .header(hash)
            .await?
            .with_context(|| format!("midnight node has no header for height {number}"))?;
        let returned_number = u64::from(header.number);
        ensure_requested_height(number, returned_number)?;
        Ok(BlockRef {
            number: returned_number,
            hash: hex_0x(hash),
            parent_hash: hex_0x(header.parent_hash),
        })
    }
}

/// Finalized request-only reads for the Midnight publisher.
pub(crate) struct MidnightPublisherRpc {
    rpc: RpcClient,
    legacy: LegacyRpcMethods<SubstrateConfig>,
    network_id: String,
}

impl MidnightPublisherRpc {
    pub async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        let (rpc, legacy, network_id) = tokio::time::timeout(config.rpc.connect_timeout, async {
            let rpc = connect_http(config)?;
            let legacy = LegacyRpcMethods::<SubstrateConfig>::new(rpc.clone());
            let network_id = network_id(&legacy).await?;
            anyhow::Ok((rpc, legacy, network_id))
        })
        .await
        .context("timed out fetching the midnight network id")??;

        Ok(Self {
            rpc,
            legacy,
            network_id,
        })
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }
}

/// Finalized reads used by the publisher and its in-process tests. Every read is
/// addressed by the `0x`-prefixed hash `finalized_head` answers with.
#[async_trait::async_trait]
pub(crate) trait PinnedReads: Send + Sync {
    async fn finalized_head(&self) -> anyhow::Result<String>;
    /// The two node surfaces disagree about `0x`; both are decoded to bytes here, so
    /// nothing above this trait may reintroduce the distinction.
    async fn contract_state(
        &self,
        address_64hex: &str,
        at_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    async fn ledger_parameters(&self, at_hash_0x: &str) -> anyhow::Result<Vec<u8>>;
}

#[async_trait::async_trait]
impl PinnedReads for MidnightPublisherRpc {
    async fn finalized_head(&self) -> anyhow::Result<String> {
        let finalized = self
            .legacy
            .chain_get_finalized_head()
            .await
            .context("failed to fetch the midnight finalized head")?;
        Ok(hex_0x(finalized))
    }

    async fn contract_state(
        &self,
        address_64hex: &str,
        at_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        publisher_contract_state(&self.rpc, address_64hex, at_hash_0x).await
    }

    async fn ledger_parameters(&self, at_hash_0x: &str) -> anyhow::Result<Vec<u8>> {
        let at = parse_block_hash(at_hash_0x)?;
        let answer = self
            .legacy
            .state_call(LEDGER_PARAMETERS_ENTRY, Some(&[]), Some(at))
            .await
            .context("failed to fetch midnight ledger parameters")?;
        unwrap_runtime_api_result(&answer)?
            .with_context(|| format!("midnight node has no ledger parameters at {at_hash_0x}"))
    }
}

async fn network_id(legacy: &LegacyRpcMethods<SubstrateConfig>) -> anyhow::Result<String> {
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

fn decode_network_id(answer: &[u8]) -> anyhow::Result<String> {
    let mut payload = answer;
    String::decode_all(&mut payload).context("midnight runtime returned a malformed network id")
}

async fn publisher_contract_state(
    rpc: &RpcClient,
    address_64hex: &str,
    at_block_hash_0x: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let response = rpc
        .request::<String>(
            "midnight_contractState",
            rpc_params![address_64hex, at_block_hash_0x],
        )
        .await;

    match classify_contract_state_reply(response)? {
        ContractStateReply::State(state) => Ok(state),
        ContractStateReply::Unservable(err)
        | ContractStateReply::TooLarge(err)
        | ContractStateReply::Other(err) => {
            Err(anyhow::Error::new(err).context("midnight_contractState failed"))
        }
    }
}

/// One `midnight_contractState` answer, classified once for both transports. The node
/// builds every rpc error as invalid-params with the reason only in the text, so its
/// two definitive answers stay text matches under the code gate.
enum ContractStateReply {
    /// The state bytes, or `None` when the contract is not present at that block.
    State(Option<Vec<u8>>),
    /// Pruned or unknown hash: no number of retries makes the node serve it.
    Unservable(RawRpcError),
    /// State beyond the rpc response cap, reachable because our cap sits above the
    /// server's: definitive, since retrying cannot shrink a contract's state.
    TooLarge(RawRpcError),
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
        Err(RawRpcError::User(reply))
            if reply.code == INVALID_PARAMS_CODE
                && reply
                    .message
                    .contains("Unable to get requested contract state") =>
        {
            ContractStateReply::Unservable(RawRpcError::User(reply))
        }
        Err(RawRpcError::User(reply)) if reply.code == OVERSIZED_RESPONSE_CODE => {
            ContractStateReply::TooLarge(RawRpcError::User(reply))
        }
        Err(err) => ContractStateReply::Other(err),
    })
}

/// The bare payload of the ledger-parameters `Result<Vec<u8>, _>` runtime-API answer
/// at `MidnightRuntimeApi` version 2 (node 2.0.0-rc.4). `None` is the `Err` variant:
/// only its discriminant is decoded, so an unseen ledger error stays `Err`.
fn unwrap_runtime_api_result(answer: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
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
struct Reads {
    rpc: RpcClient,
    legacy: LegacyRpcMethods<SubstrateConfig>,
    request_timeout: Duration,
    retry: RetryConfig,
}

/// A read's definitive outcomes, routed through `Ok` so the retry budget is spent
/// only on faults a retry can change.
enum Fetched<T> {
    Value(T),
    TooLarge(RawRpcError),
}

fn rejected_http_status(error: &anyhow::Error) -> Option<u16> {
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
        Some(*status_code)
    })
}

fn is_read_retryable(error: &anyhow::Error) -> bool {
    if let Some(status) = rejected_http_status(error) {
        return is_retryable(&anyhow::anyhow!("HTTP status {status}"));
    }
    if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<RawRpcError>(),
            Some(RawRpcError::User(_))
        )
    }) {
        return true;
    }
    is_retryable(error)
}

async fn retry_read<T, F, Fut>(
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
                error = %error,
                ?retry_in,
                "RPC call failed, retrying"
            );
        })
        .await
        .map_err(|error| error.context(format!("exhausted after {} attempts", retry_count + 1)))
}

impl Reads {
    fn new(rpc: RpcClient, request_timeout: Duration, retry: RetryConfig) -> Self {
        Self {
            legacy: LegacyRpcMethods::<SubstrateConfig>::new(rpc.clone()),
            rpc,
            request_timeout,
            retry,
        }
    }

    fn resolve<T>(fetched: Fetched<T>) -> anyhow::Result<T> {
        match fetched {
            Fetched::Value(value) => Ok(value),
            Fetched::TooLarge(source) => Err(ReadFailure::TooLarge.err(source)),
        }
    }

    async fn finalized_head(&self) -> anyhow::Result<H256> {
        let fetched = retry_read(
            self.request_timeout,
            self.retry,
            "midnight_finalized_head",
            || async {
                self.legacy
                    .chain_get_finalized_head()
                    .await
                    .map(Fetched::Value)
                    .map_err(anyhow::Error::new)
                    .context("failed to fetch the midnight finalized head")
            },
        )
        .await?;
        Self::resolve(fetched)
    }

    async fn header(
        &self,
        hash: H256,
    ) -> anyhow::Result<Option<<SubstrateConfig as subxt::Config>::Header>> {
        let fetched = retry_read(
            self.request_timeout,
            self.retry,
            "midnight_header",
            || async {
                self.legacy
                    .chain_get_header(Some(hash))
                    .await
                    .map(Fetched::Value)
                    .map_err(anyhow::Error::new)
                    .context("failed to fetch a block header")
            },
        )
        .await?;
        Self::resolve(fetched)
    }

    async fn block_hash_at(&self, number: u64) -> anyhow::Result<Option<H256>> {
        let fetched = retry_read(
            self.request_timeout,
            self.retry,
            "midnight_block_hash_at",
            || async {
                self.legacy
                    .chain_get_block_hash(Some(NumberOrHex::Number(number)))
                    .await
                    .map(Fetched::Value)
                    .map_err(anyhow::Error::new)
                    .context("failed to fetch a block hash by number")
            },
        )
        .await?;
        Self::resolve(fetched)
    }

    async fn contract_state(
        &self,
        address_64hex: &str,
        at_block_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let fetched = retry_read(
            self.request_timeout,
            self.retry,
            "midnight_contractState",
            || async {
                let response: Result<String, _> = self
                    .rpc
                    .request(
                        "midnight_contractState",
                        rpc_params![address_64hex, at_block_hash_0x],
                    )
                    .await;

                match classify_contract_state_reply(response)? {
                    ContractStateReply::State(state) => Ok(Fetched::Value(state)),
                    // Spends the retry budget like any other `Err`; only the class escapes.
                    ContractStateReply::Unservable(err) => Err(ReadFailure::Unservable.err(err)),
                    ContractStateReply::TooLarge(err) => Ok(Fetched::TooLarge(err)),
                    ContractStateReply::Other(err) => {
                        Err(anyhow::Error::new(err).context("midnight_contractState failed"))
                    }
                }
            },
        )
        .await?;
        Self::resolve(fetched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::server::{ServerBuilder, ServerHandle};
    use jsonrpsee::types::ErrorObjectOwned;
    use jsonrpsee::RpcModule;
    use serde_json::json;
    use std::collections::{HashMap, VecDeque};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use subxt::backend::rpc::{RawRpcFuture, RawRpcSubscription, RawValue, RpcClientT};
    use subxt::ext::subxt_rpcs::UserError;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn http_config(address: SocketAddr) -> crate::config::MidnightConfig {
        crate::config::MidnightConfig {
            node_url: format!("http://{address}"),
            central_address: "ab".repeat(32),
            publisher: Default::default(),
            rpc: Default::default(),
            indexer: Default::default(),
        }
    }

    async fn http_method_server(
        address: impl tokio::net::ToSocketAddrs,
        calls: Arc<AtomicUsize>,
    ) -> (ServerHandle, SocketAddr) {
        let server = ServerBuilder::default()
            .build(address)
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_method("probe", move |_, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                "ok"
            })
            .expect("register probe method");
        (server.start(module), address)
    }

    async fn http_status_server(
        status: u16,
        reason: &'static str,
    ) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind raw HTTP status server");
        let address = listener.local_addr().expect("raw HTTP server address");
        let calls = Arc::new(AtomicUsize::new(0));
        let server_calls = calls.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept HTTP request");
                let mut request_start = [0; 1];
                stream
                    .read_exact(&mut request_start)
                    .await
                    .expect("read HTTP request");
                server_calls.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write HTTP status response");
            }
        });
        (address, calls, server)
    }

    #[tokio::test]
    async fn real_http_statuses_follow_the_shared_retry_partition() {
        for (status, reason, expected_attempts) in [
            (400, "Bad Request", 1),
            (401, "Unauthorized", 1),
            (403, "Forbidden", 1),
            (404, "Not Found", 1),
            (405, "Method Not Allowed", 1),
            (408, "Request Timeout", 3),
            (429, "Too Many Requests", 3),
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
                Some(status),
                "status {status} was lost from the typed error chain: {err:#}"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                expected_attempts,
                "HTTP {status} used the wrong retry policy"
            );
        }
    }

    #[tokio::test]
    async fn http_adapter_drives_legacy_state_and_raw_requests() {
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_method("chain_getFinalizedHead", |_, _, _| hash_of_byte(0x55))
            .expect("register finalized head");
        module
            .register_method("chain_getHeader", |_, _, _| {
                json!({
                    "parentHash": hash_of_byte(0x44),
                    "number": "0x2a",
                    "stateRoot": hash_of_byte(0x66),
                    "extrinsicsRoot": hash_of_byte(0x77),
                    "digest": { "logs": [] }
                })
            })
            .expect("register header");
        module
            .register_method("chain_getBlockHash", |_, _, _| hash_of_byte(0x55))
            .expect("register block hash");
        module
            .register_method("state_call", |_, _, _| "0x0102")
            .expect("register state call");
        module
            .register_method("midnight_contractState", |_, _, _| "0xcafe")
            .expect("register contract state");
        let _handle = server.start(module);

        let transport =
            HttpRpcClient::from_config(&http_config(address)).expect("build HTTP transport");
        let rpc = RpcClient::new(transport);
        let legacy = LegacyRpcMethods::<SubstrateConfig>::new(rpc.clone());
        let finalized = legacy
            .chain_get_finalized_head()
            .await
            .expect("finalized head");
        assert_eq!(finalized, H256([0x55; 32]));
        let header = legacy
            .chain_get_header(Some(finalized))
            .await
            .expect("header")
            .expect("header present");
        assert_eq!(u64::from(header.number), 42);
        assert_eq!(header.parent_hash, H256([0x44; 32]));
        assert_eq!(
            legacy
                .chain_get_block_hash(Some(NumberOrHex::Number(42)))
                .await
                .expect("block hash"),
            Some(finalized)
        );
        assert_eq!(
            legacy
                .state_call(NETWORK_ID_ENTRY, Some(&[]), Some(finalized))
                .await
                .expect("state call"),
            vec![1, 2]
        );
        let state: String = rpc
            .request("midnight_contractState", rpc_params![ADDRESS, AT_HASH])
            .await
            .expect("raw contract-state request");
        assert_eq!(state, "0xcafe");
    }

    #[tokio::test]
    async fn block_ref_at_rejects_a_header_at_a_different_height() {
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_method("chain_getBlockHash", |_, _, _| hash_of_byte(0x55))
            .expect("register block hash");
        module
            .register_method("chain_getHeader", |_, _, _| {
                json!({
                    "parentHash": hash_of_byte(0x44),
                    "number": "0x3c",
                    "stateRoot": hash_of_byte(0x66),
                    "extrinsicsRoot": hash_of_byte(0x77),
                    "digest": { "logs": [] }
                })
            })
            .expect("register header");
        let _handle = server.start(module);
        let rpc = MidnightRpc::connect(&http_config(address))
            .await
            .expect("connect request-only RPC");

        let err = rpc
            .block_ref_at(6)
            .await
            .expect_err("height 6 must not accept a header claiming height 60");
        let diagnostic = format!("{err:#}");
        assert!(diagnostic.contains("requested height 6"), "{diagnostic}");
        assert!(diagnostic.contains("returned height 60"), "{diagnostic}");
    }

    #[tokio::test]
    async fn http_adapter_preserves_user_error_code_message_and_data() {
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_method("fails", |_, _, _| -> Result<(), ErrorObjectOwned> {
                Err(ErrorObjectOwned::owned(
                    -32042,
                    "kept message",
                    Some(json!({"detail": "kept data"})),
                ))
            })
            .expect("register failing method");
        let _handle = server.start(module);
        let rpc = RpcClient::new(
            HttpRpcClient::from_config(&http_config(address)).expect("build HTTP transport"),
        );

        let err = rpc
            .request::<String>("fails", rpc_params![])
            .await
            .expect_err("server user error must escape");
        let RawRpcError::User(user) = err else {
            panic!("expected Subxt user error, got {err:?}");
        };
        assert_eq!(user.code, -32042);
        assert_eq!(user.message, "kept message");
        assert_eq!(
            user.data.as_deref().map(RawValue::get),
            Some(r#"{"detail":"kept data"}"#)
        );
    }

    #[tokio::test]
    async fn http_adapter_enforces_request_timeout_and_response_cap() {
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_async_method("park", |_, _, _| async {
                std::future::pending::<String>().await
            })
            .expect("register parked method");
        module
            .register_method("large", |_, _, _| "x".repeat(4096))
            .expect("register large method");
        let _handle = server.start(module);

        let mut timeout_config = http_config(address);
        timeout_config.rpc.request_timeout = Duration::from_millis(25);
        let timeout_rpc = RpcClient::new(
            HttpRpcClient::from_config(&timeout_config).expect("build timeout transport"),
        );
        let timeout_error = tokio::time::timeout(
            Duration::from_millis(250),
            timeout_rpc.request::<String>("park", rpc_params![]),
        )
        .await
        .expect("transport did not enforce its request timeout")
        .expect_err("parked request must time out");
        assert!(
            timeout_error.to_string().contains("Request timeout"),
            "unexpected timeout error: {timeout_error}"
        );

        let mut capped_config = http_config(address);
        capped_config.rpc.max_response_size = 128;
        let capped_rpc = RpcClient::new(
            HttpRpcClient::from_config(&capped_config).expect("build capped transport"),
        );
        let capped_error = capped_rpc
            .request::<String>("large", rpc_params![])
            .await
            .expect_err("oversized response must be refused");
        let capped_detail = format!("{capped_error:#}").to_ascii_lowercase();
        assert!(
            capped_detail.contains("too big")
                || capped_detail.contains("too large")
                || capped_detail.contains("limit"),
            "unexpected response cap error: {capped_error:#}"
        );
    }

    #[tokio::test]
    async fn http_adapter_rejects_subscriptions_immediately() {
        let transport = HttpRpcClient::from_config(&http_config(
            "127.0.0.1:9".parse().expect("socket address"),
        ))
        .expect("building an HTTP client does not dial");

        let result = tokio::time::timeout(
            Duration::from_millis(50),
            transport.subscribe_raw(
                "chain_subscribeFinalizedHeads",
                None,
                "chain_unsubscribeFinalizedHeads",
            ),
        )
        .await
        .expect("subscription rejection was not immediate");
        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("HTTP subscriptions must be rejected"),
        };
        assert!(
            err.to_string().contains(HTTP_SUBSCRIPTIONS_UNSUPPORTED),
            "unexpected subscription error: {err}"
        );
    }

    #[tokio::test]
    async fn http_client_recovers_after_server_rebind_without_reconstruction() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let (first_server, address) = http_method_server("127.0.0.1:0", first_calls.clone()).await;
        let mut config = http_config(address);
        config.rpc.request_timeout = Duration::from_millis(100);
        let rpc = RpcClient::new(
            HttpRpcClient::from_config(&config).expect("build persistent HTTP client"),
        );
        assert_eq!(
            rpc.request::<String>("probe", rpc_params![])
                .await
                .expect("first server answers"),
            "ok"
        );
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);

        first_server.stop().expect("stop first server");
        first_server.stopped().await;
        tokio::time::timeout(
            Duration::from_millis(250),
            rpc.request::<String>("probe", rpc_params![]),
        )
        .await
        .expect("failed request exceeded the configured bound")
        .expect_err("request while stopped must fail");

        let second_calls = Arc::new(AtomicUsize::new(0));
        let (_second_server, rebound) = http_method_server(address, second_calls.clone()).await;
        assert_eq!(rebound, address);
        assert_eq!(
            rpc.request::<String>("probe", rpc_params![])
                .await
                .expect("same client answers after rebind"),
            "ok"
        );
        assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    }

    fn hash_of_byte(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    #[tokio::test]
    async fn publisher_startup_is_bounded_if_the_endpoint_dies_during_initialization() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind bootstrap endpoint");
        let address = listener.local_addr().expect("bootstrap endpoint address");
        let server = tokio::spawn(async move {
            let (_stream, _) = listener
                .accept()
                .await
                .expect("accept publisher connection");
            std::future::pending::<()>().await;
        });
        let mut config = crate::config::MidnightConfig {
            node_url: format!("http://{address}"),
            central_address: "ab".repeat(32),
            publisher: Default::default(),
            rpc: Default::default(),
            indexer: Default::default(),
        };
        config.rpc.connect_timeout = Duration::from_millis(75);
        config.rpc.request_timeout = Duration::from_secs(5);

        let result = tokio::time::timeout(
            Duration::from_millis(750),
            MidnightPublisherRpc::connect(&config),
        )
        .await;
        server.abort();

        let error = match result.expect("publisher startup outlived its connection budget") {
            Ok(_) => panic!("publisher initialized after its endpoint vanished"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("midnight"),
            "startup error has no RPC context: {error:#}"
        );
    }

    // Contract-state reads over an in-process JSON-RPC stub.

    /// One canned reply for a stubbed JSON-RPC method.
    #[derive(Clone)]
    enum Canned {
        User(i32, &'static str),
        UserWithData(i32, &'static str, &'static str),
        ClientErr,
    }

    /// In-process JSON-RPC node: canned per-method replies consumed in order with the
    /// last one sticky, and every call recorded so tests can pin exactly what was
    /// asked, at which height, with which hash.
    #[derive(Clone)]
    struct StubNode {
        state: Arc<StubState>,
    }

    struct StubState {
        replies: Mutex<HashMap<&'static str, VecDeque<Canned>>>,
        calls: Mutex<Vec<(String, String)>>,
    }

    impl StubNode {
        fn new(replies: impl IntoIterator<Item = (&'static str, Vec<Canned>)>) -> Self {
            Self {
                state: Arc::new(StubState {
                    replies: Mutex::new(
                        replies
                            .into_iter()
                            .map(|(method, queue)| (method, VecDeque::from(queue)))
                            .collect(),
                    ),
                    calls: Mutex::new(Vec::new()),
                }),
            }
        }

        /// Serialized params of every call to `method`, in call order.
        fn calls_to(&self, method: &str) -> Vec<String> {
            self.state
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(m, _)| m == method)
                .map(|(_, params)| params.clone())
                .collect()
        }
    }

    impl RpcClientT for StubNode {
        fn request_raw<'a>(
            &'a self,
            method: &'a str,
            params: Option<Box<RawValue>>,
        ) -> RawRpcFuture<'a, Box<RawValue>> {
            let params_json = params
                .map(|p| p.get().to_string())
                .unwrap_or_else(|| "null".to_string());
            Box::pin(async move {
                self.state
                    .calls
                    .lock()
                    .unwrap()
                    .push((method.to_string(), params_json));
                let canned = {
                    let mut replies = self.state.replies.lock().unwrap();
                    let queue = replies
                        .get_mut(method)
                        .unwrap_or_else(|| panic!("unexpected rpc method {method}"));
                    if queue.len() > 1 {
                        queue.pop_front().expect("len checked")
                    } else {
                        queue.front().expect("stub queues are never empty").clone()
                    }
                };
                match canned {
                    Canned::User(code, message) => Err(RawRpcError::User(UserError {
                        code,
                        message: message.to_string(),
                        data: None,
                    })),
                    Canned::UserWithData(code, message, data) => {
                        Err(RawRpcError::User(UserError {
                            code,
                            message: message.to_string(),
                            data: Some(
                                RawValue::from_string(data.to_string())
                                    .expect("canned user-error data is JSON"),
                            ),
                        }))
                    }
                    Canned::ClientErr => Err(RawRpcError::Client(Box::new(
                        JsonrpseeClientError::Transport("connection reset by peer".into()),
                    ))),
                }
            })
        }

        fn subscribe_raw<'a>(
            &'a self,
            _sub: &'a str,
            _params: Option<Box<RawValue>>,
            _unsub: &'a str,
        ) -> RawRpcFuture<'a, RawRpcSubscription> {
            Box::pin(async { panic!("these tests never subscribe") })
        }
    }

    const ADDRESS: &str = "abababababababababababababababababababababababababababababababab";
    const AT_HASH: &str = "0x5555555555555555555555555555555555555555555555555555555555555555";
    const READ_TIMEOUT: Duration = Duration::from_secs(5);
    const NOT_PRESENT_MSG: &str = "Contract not present at the requested address";
    const UNSERVABLE_MSG: &str = "Unable to get requested contract state";

    /// A budget of `max_times` retries with near-zero delays, so tests pin attempt
    /// counts without waiting out production backoff.
    fn attempts(max_times: usize) -> RetryConfig {
        RetryConfig {
            min_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(2),
            max_times,
            jitter: false,
        }
    }

    /// A [`Reads`] over the stub, with the given retry budget.
    fn stub_reads(node: &StubNode, retry: RetryConfig) -> Reads {
        Reads::new(RpcClient::new(node.clone()), READ_TIMEOUT, retry)
    }

    #[tokio::test]
    async fn publisher_contract_state_preserves_raw_failures_without_indexer_markers() {
        for (code, message) in [
            (INVALID_PARAMS_CODE, UNSERVABLE_MSG),
            (OVERSIZED_RESPONSE_CODE, "state exceeds the response limit"),
        ] {
            let node = StubNode::new(vec![(
                "midnight_contractState",
                vec![Canned::User(code, message)],
            )]);
            let rpc = RpcClient::new(node);

            let err = publisher_contract_state(&rpc, ADDRESS, AT_HASH)
                .await
                .expect_err("the node reply is a publisher read failure");

            assert_eq!(
                ReadFailure::of(&err),
                None,
                "publisher errors must not acquire indexer policy markers: {err:#}"
            );
            assert!(
                format!("{err:#}").contains(message),
                "the original node diagnostic must remain in the error chain: {err:#}"
            );
        }
    }

    #[tokio::test]
    async fn contract_state_definitive_answers_spend_no_retries() {
        // The oversized refusal classifies by its code, whatever the server words it as.
        let node = StubNode::new(vec![(
            "midnight_contractState",
            vec![Canned::User(
                OVERSIZED_RESPONSE_CODE,
                "however the server words it",
            )],
        )]);
        let err = stub_reads(&node, attempts(2))
            .contract_state(ADDRESS, AT_HASH)
            .await
            .expect_err("an oversized state is a failure, definitively");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::TooLarge),
            "{err:#}"
        );
        assert_eq!(
            node.calls_to("midnight_contractState").len(),
            1,
            "an oversized refusal must not be retried"
        );

        // The words without their signal are not a verdict: node replies that merely
        // CONTAIN the texts spend the ordinary budget, unclassified.
        for (code, message) in [
            (INVALID_PARAMS_CODE, "Response is too big"),
            (-32000, "restart required, please"),
        ] {
            let node = StubNode::new(vec![(
                "midnight_contractState",
                vec![Canned::User(code, message)],
            )]);
            let err = stub_reads(&node, attempts(2))
                .contract_state(ADDRESS, AT_HASH)
                .await
                .expect_err("still a failure");
            assert_eq!(
                ReadFailure::of(&err),
                None,
                "the bare text {message:?} must not classify: {err:#}"
            );
            assert_eq!(
                node.calls_to("midnight_contractState").len(),
                3,
                "{message:?} spends the budget"
            );
        }

        // A boxed transport fault that is NOT the restart signature stays retryable.
        let node = StubNode::new(vec![("midnight_contractState", vec![Canned::ClientErr])]);
        let err = stub_reads(&node, attempts(2))
            .contract_state(ADDRESS, AT_HASH)
            .await
            .expect_err("a transport fault is a failure");
        assert_eq!(ReadFailure::of(&err), None, "{err:#}");
        assert_eq!(node.calls_to("midnight_contractState").len(), 3);
    }

    #[tokio::test]
    async fn classified_contract_state_failures_retain_structured_rpc_causes() {
        const DATA: &str = r#"{"detail":"recover me"}"#;
        for (code, message, expected_class, expected_attempts) in [
            (
                INVALID_PARAMS_CODE,
                UNSERVABLE_MSG,
                ReadFailure::Unservable,
                3,
            ),
            (
                OVERSIZED_RESPONSE_CODE,
                "state exceeds the response limit",
                ReadFailure::TooLarge,
                1,
            ),
        ] {
            let node = StubNode::new(vec![(
                "midnight_contractState",
                vec![Canned::UserWithData(code, message, DATA)],
            )]);
            let err = stub_reads(&node, attempts(2))
                .contract_state(ADDRESS, AT_HASH)
                .await
                .expect_err("the classified node answer remains a failure");

            assert_eq!(ReadFailure::of(&err), Some(expected_class), "{err:#}");
            let cause = err
                .chain()
                .find_map(|cause| cause.downcast_ref::<RawRpcError>())
                .expect("classification must retain the structured RPC cause");
            let RawRpcError::User(user) = cause else {
                panic!("expected a user error cause, got {cause:?}");
            };
            assert_eq!(user.code, code);
            assert_eq!(user.message, message);
            assert_eq!(user.data.as_deref().map(RawValue::get), Some(DATA));
            assert_eq!(
                node.calls_to("midnight_contractState").len(),
                expected_attempts,
                "classification changed the retry policy"
            );
        }
    }

    #[tokio::test]
    async fn ordinary_user_errors_cannot_spoof_read_failure_markers() {
        const DATA: &str = r#"{"detail":"ordinary provider failure"}"#;
        for marker in [
            ReadFailure::Unservable.marker(),
            ReadFailure::TooLarge.marker(),
        ] {
            let node = StubNode::new(vec![(
                "midnight_contractState",
                vec![Canned::UserWithData(12345, marker, DATA)],
            )]);
            let err = stub_reads(&node, attempts(2))
                .contract_state(ADDRESS, AT_HASH)
                .await
                .expect_err("an ordinary provider error remains a failure");

            assert_eq!(
                ReadFailure::of(&err),
                None,
                "provider prose must not select local policy: {err:#}"
            );
            let cause = err
                .chain()
                .find_map(|cause| cause.downcast_ref::<RawRpcError>())
                .expect("ordinary failure must retain its structured RPC cause");
            let RawRpcError::User(user) = cause else {
                panic!("expected a user error cause, got {cause:?}");
            };
            assert_eq!(user.code, 12345);
            assert_eq!(user.data.as_deref().map(RawValue::get), Some(DATA));
            assert_eq!(
                node.calls_to("midnight_contractState").len(),
                3,
                "ordinary errors must spend the configured retry budget"
            );
        }
    }

    #[tokio::test]
    async fn ordinary_client_faults_share_the_configured_retry_budget() {
        let node = StubNode::new(vec![
            ("chain_getFinalizedHead", vec![Canned::ClientErr]),
            ("chain_getBlockHash", vec![Canned::ClientErr]),
            ("chain_getHeader", vec![Canned::ClientErr]),
        ]);

        let err = stub_reads(&node, attempts(2))
            .finalized_head()
            .await
            .expect_err("a client fault is a failure");
        assert_eq!(ReadFailure::of(&err), None, "{err:#}");
        assert!(
            err.chain()
                .any(|cause| cause.downcast_ref::<RawRpcError>().is_some()),
            "the exhausted retry must retain its original RPC cause: {err:#}"
        );
        assert_eq!(
            node.calls_to("chain_getFinalizedHead").len(),
            3,
            "ordinary HTTP faults spend the retry budget"
        );

        let err = stub_reads(&node, attempts(2))
            .block_hash_at(7)
            .await
            .expect_err("a client fault is a failure");
        assert_eq!(ReadFailure::of(&err), None, "{err:#}");
        assert_eq!(node.calls_to("chain_getBlockHash").len(), 3);

        let err = stub_reads(&node, attempts(2))
            .header(H256::zero())
            .await
            .expect_err("a client fault is a failure");
        assert_eq!(ReadFailure::of(&err), None, "{err:#}");
        assert_eq!(node.calls_to("chain_getHeader").len(), 3);
    }

    #[tokio::test]
    async fn contract_state_pruned_answer_spends_one_budget() {
        // Both node answers arrive as -32602 and are told apart only by message, so
        // pin each: "not present" is a definitive Ok(None) that must not be retried,
        // while the pruned-or-unknown-hash answer is an error the budget spends on.
        let node = StubNode::new(vec![(
            "midnight_contractState",
            vec![Canned::User(INVALID_PARAMS_CODE, NOT_PRESENT_MSG)],
        )]);
        let absent = stub_reads(&node, attempts(2))
            .contract_state(ADDRESS, AT_HASH)
            .await
            .expect("contract-not-present is an answer, not a failure");
        assert_eq!(absent, None);
        assert_eq!(node.calls_to("midnight_contractState").len(), 1);

        let node = StubNode::new(vec![(
            "midnight_contractState",
            vec![Canned::User(INVALID_PARAMS_CODE, UNSERVABLE_MSG)],
        )]);
        let err = stub_reads(&node, attempts(2))
            .contract_state(ADDRESS, AT_HASH)
            .await
            .expect_err("a pruned or unknown hash is a failure");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::Unservable),
            "{err:#}"
        );
        assert_eq!(node.calls_to("midnight_contractState").len(), 3);
    }

    #[test]
    fn network_id_decoder_consumes_the_whole_scale_value() {
        use subxt::ext::codec::Encode as _;

        let encoded = "preview".to_string().encode();
        assert_eq!(decode_network_id(&encoded).unwrap(), "preview");

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
    fn runtime_api_result_envelope_unwraps_ok_err_and_garbage() {
        use subxt::ext::codec::Encode as _;
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
