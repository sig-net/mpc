//! Midnight node RPC: the read transport everything in the read path goes through.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use futures_util::{Stream, StreamExt};
use mpc_chain_integration_core::utils::retry::{retry_rpc, RetryConfig};
use mpc_utils::task::{retry_until_some, AbortOnDrop};
use subxt::backend::legacy::rpc_methods::NumberOrHex;
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::reconnecting_rpc_client::RpcClient as ReconnectingRpcClient;
use subxt::backend::rpc::RpcClient;
use subxt::backend::BackendExt as _;
use subxt::client::OnlineClient;
use subxt::ext::jsonrpsee::client_transport::ws::{Url as WsUrl, WsTransportClientBuilder};
use subxt::ext::jsonrpsee::core::client::async_client::PingConfig;
use subxt::ext::jsonrpsee::core::client::{Client as RawWsClient, Error as JsonrpseeClientError};
use subxt::ext::jsonrpsee::types::error::{INVALID_PARAMS_CODE, OVERSIZED_RESPONSE_CODE};
use subxt::ext::subxt_rpcs::{rpc_params, Error as RawRpcError};
use subxt::utils::H256;
use subxt::SubstrateConfig;
use tokio_util::sync::CancellationToken;

use crate::config::MidnightConfig;

const WATCHDOG_TICK: Duration = Duration::from_secs(5);

/// Runtime API name from Midnight node 2.0.0-rc.4 metadata.
const LEDGER_PARAMETERS_ENTRY: &str = "MidnightRuntimeApi_get_ledger_parameters";
/// The connected runtime is the canonical owner of the wallet network identity.
const NETWORK_ID_ENTRY: &str = "MidnightRuntimeApi_get_network_id";
const TIMESTAMP_PALLET: &str = "Timestamp";
const TIMESTAMP_NOW: &str = "Now";

/// Read failures carried as marker text because `retry_rpc!` flattens error chains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadFailure {
    /// Pruned or unknown hash: no number of retries makes the node serve it.
    Unservable,
    /// State beyond the RPC response cap.
    TooLarge,
    /// The client's background task is gone and requires reconnecting.
    ClientClosed,
}

impl ReadFailure {
    pub(crate) const fn marker(self) -> &'static str {
        match self {
            Self::Unservable => {
                "midnight node cannot serve contract state at that block (pruned or unknown hash)"
            }
            Self::TooLarge => "midnight contract state exceeds the rpc response cap",
            Self::ClientClosed => "midnight rpc client closed; a reconnect is required",
        }
    }

    fn err(self, detail: impl std::fmt::Display) -> anyhow::Error {
        anyhow::anyhow!("{}: {detail}", self.marker())
    }

    pub(crate) fn of(err: &anyhow::Error) -> Option<Self> {
        let text = err.to_string();
        [Self::Unservable, Self::TooLarge, Self::ClientClosed]
            .into_iter()
            .find(|class| text.contains(class.marker()))
    }
}

/// Websocket liveness when an error's type is inconclusive.
type Liveness = Arc<dyn Fn() -> bool + Send + Sync>;

/// Finalized block data detached from its Subxt handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRef {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
}

impl BlockRef {
    fn from_block(
        block: &subxt::blocks::Block<SubstrateConfig, OnlineClient<SubstrateConfig>>,
    ) -> Self {
        Self {
            number: u64::from(block.number()),
            hash: hex_0x(block.hash()),
            parent_hash: hex_0x(block.header().parent_hash),
        }
    }
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

async fn connect_bounded(
    config: &MidnightConfig,
) -> anyhow::Result<(OnlineClient<SubstrateConfig>, RpcClient, Liveness)> {
    let connect_timeout = config.rpc.connect_timeout;
    let url = config.node_ws_url.as_str();

    // Equivalent to `RpcClient::from_url`, with a configurable response cap.
    let ws_client = tokio::time::timeout(connect_timeout, async {
        let target = WsUrl::parse(url).context("the midnight node ws url does not parse")?;
        let (sender, receiver) = WsTransportClientBuilder::default()
            .max_response_size(config.rpc.max_response_size)
            .build(target)
            .await
            .context("failed to connect to the midnight node rpc")?;
        anyhow::Ok(
            RawWsClient::builder()
                // Pings are off by default, leaving a blackholed connection
                // (no FIN or RST) undetectable; the heartbeat surfaces it as
                // RestartNeeded, i.e. the ClientClosed reconnect path.
                .enable_ws_ping(PingConfig::default())
                .max_buffer_capacity_per_subscription(4096)
                .build_with_tokio(sender, receiver),
        )
    })
    .await
    .context("timed out connecting to the midnight node rpc")??;
    let ws = Arc::new(ws_client);
    let rpc = RpcClient::new(ws.clone());
    let alive: Liveness = Arc::new(move || ws.is_connected());
    let client = tokio::time::timeout(
        connect_timeout,
        OnlineClient::<SubstrateConfig>::from_rpc_client(rpc.clone()),
    )
    .await
    .context("timed out initialising the midnight subxt client")?
    .context("failed to initialise the midnight subxt client")?;

    Ok((client, rpc, alive))
}

pub(crate) struct MidnightRpc {
    client: OnlineClient<SubstrateConfig>,
    reads: Reads,
    connect_timeout: Duration,
    stall_timeout: Duration,
    /// Keeps subxt metadata current across runtime upgrades; aborted when this client
    /// drops.
    _runtime_updater: AbortOnDrop,
}

impl MidnightRpc {
    /// Dials the node named by `config.node_ws_url`.
    pub async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        let (client, rpc, alive) = connect_bounded(config).await?;

        Ok(Self {
            _runtime_updater: spawn_runtime_updater(client.clone()),
            client,
            reads: Reads::new(rpc, config.rpc.request_timeout, config.rpc.retry, alive),
            connect_timeout: config.rpc.connect_timeout,
            stall_timeout: config.indexer.stall_timeout,
        })
    }

    /// Stream of finalized blocks.
    pub async fn subscribe_finalized(
        &self,
    ) -> anyhow::Result<impl Stream<Item = BlockRef> + Send + Unpin + 'static> {
        let sub = tokio::time::timeout(
            self.connect_timeout,
            self.client.blocks().subscribe_finalized(),
        )
        .await
        .context("timed out subscribing to finalized midnight blocks")?
        .context("failed to subscribe to finalized midnight blocks")?;
        let stall_timeout = self.stall_timeout;

        Ok(futures_util::stream::unfold(
            (sub, Instant::now()),
            move |(mut sub, last_block_time)| async move {
                let mut watchdog = tokio::time::interval(WATCHDOG_TICK);
                loop {
                    tokio::select! {
                        maybe = sub.next() => match maybe {
                            Some(Ok(block)) => {
                                return Some((BlockRef::from_block(&block), (sub, Instant::now())));
                            }
                            Some(Err(err)) => {
                                tracing::warn!("midnight block stream failed: {err}; ending stream");
                                return None;
                            }
                            None => {
                                tracing::warn!("midnight block stream ended");
                                return None;
                            }
                        },
                        _ = watchdog.tick() => {
                            if last_block_time.elapsed() > stall_timeout {
                                tracing::warn!(
                                    "midnight block subscription stalled: no block for {stall_timeout:?}; ending stream"
                                );
                                return None;
                            }
                        }
                    }
                }
            },
        )
        .boxed())
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
        Ok(BlockRef {
            number: u64::from(header.number),
            hash: hex_0x(hash),
            parent_hash: hex_0x(header.parent_hash),
        })
    }
}

/// Finalized reads for the Midnight publisher. Subxt owns connection recovery;
/// callers keep one instance instead of rebuilding or retrying a dead transport.
pub(crate) struct MidnightPublisherRpc {
    client: OnlineClient<SubstrateConfig>,
    rpc: RpcClient,
    network_id: String,
    /// Keeps subxt metadata current across runtime upgrades; aborted when this client
    /// drops.
    _runtime_updater: AbortOnDrop,
}

impl MidnightPublisherRpc {
    pub async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        // Fetch the immutable client state over the bounded transport before the
        // persistent reconnect worker exists. The persistent client can then be
        // initialized synchronously, without leaving cancelled calls in its queue.
        let (bootstrap, _, _) = connect_bounded(config).await?;
        let network_id = tokio::time::timeout(config.rpc.connect_timeout, network_id(&bootstrap))
            .await
            .context("timed out fetching the midnight network id")??;
        let genesis_hash = bootstrap.genesis_hash();
        let runtime_version = bootstrap.runtime_version();
        let metadata = bootstrap.metadata();
        drop(bootstrap);

        let rpc = connect_publisher_transport(config).await?;
        let client = OnlineClient::<SubstrateConfig>::from_rpc_client_with(
            genesis_hash,
            runtime_version,
            metadata,
            rpc.clone(),
        )
        .context("failed to initialise the midnight publisher subxt client")?;

        Ok(Self {
            _runtime_updater: spawn_runtime_updater(client.clone()),
            client,
            rpc,
            network_id,
        })
    }

    pub async fn finalized_head_0x(&self) -> anyhow::Result<String> {
        let finalized = self
            .client
            .backend()
            .latest_finalized_block_ref()
            .await
            .context("failed to fetch the midnight finalized head")?;
        Ok(hex_0x(finalized.hash()))
    }

    pub(crate) async fn block_timestamp_seconds(
        &self,
        at_block_hash_0x: &str,
    ) -> anyhow::Result<u64> {
        let at = parse_block_hash(at_block_hash_0x)?;
        let address = subxt::dynamic::storage(
            TIMESTAMP_PALLET,
            TIMESTAMP_NOW,
            Vec::<subxt::dynamic::Value>::new(),
        );
        let key = self
            .client
            .storage()
            .address_bytes(&address)
            .context("midnight runtime metadata has no Timestamp.Now storage entry")?;
        let encoded = self
            .client
            .backend()
            .storage_fetch_value(key, at)
            .await
            .context("failed to fetch midnight runtime storage")?
            .with_context(|| format!("midnight block {at_block_hash_0x} has no timestamp"))?;
        decode_timestamp_seconds(&encoded)
    }

    pub async fn contract_state(
        &self,
        address_64hex: &str,
        at_block_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        publisher_contract_state(&self.rpc, address_64hex, at_block_hash_0x).await
    }

    pub async fn ledger_parameters(&self, at_block_hash_0x: &str) -> anyhow::Result<Vec<u8>> {
        let at = parse_block_hash(at_block_hash_0x)?;
        let answer = self
            .client
            .backend()
            .call(LEDGER_PARAMETERS_ENTRY, Some(&[]), at)
            .await
            .context("failed to fetch midnight ledger parameters")?;
        unwrap_runtime_api_result(&answer)?.with_context(|| {
            format!("midnight node has no ledger parameters at {at_block_hash_0x}")
        })
    }

    pub fn network_id(&self) -> &str {
        &self.network_id
    }
}

async fn network_id(client: &OnlineClient<SubstrateConfig>) -> anyhow::Result<String> {
    use subxt::ext::codec::Decode as _;

    let finalized = client
        .backend()
        .latest_finalized_block_ref()
        .await
        .context("failed to fetch the midnight finalized head")?;
    let answer = client
        .backend()
        .call(NETWORK_ID_ENTRY, Some(&[]), finalized.hash())
        .await
        .context("failed to fetch the midnight network id")?;
    let mut payload = &answer[..];
    let network_id =
        String::decode(&mut payload).context("midnight runtime returned a malformed network id")?;
    anyhow::ensure!(
        payload.is_empty(),
        "midnight runtime network id has {} trailing bytes",
        payload.len()
    );
    Ok(network_id)
}

async fn connect_publisher_transport(config: &MidnightConfig) -> anyhow::Result<RpcClient> {
    let connect = ReconnectingRpcClient::builder()
        .max_response_size(config.rpc.max_response_size)
        .request_timeout(config.rpc.request_timeout)
        .connection_timeout(config.rpc.connect_timeout)
        .build(&config.node_ws_url);
    let client = tokio::time::timeout(config.rpc.connect_timeout, connect)
        .await
        .context("timed out connecting to the midnight node rpc")?
        .context("failed to connect to the midnight node rpc")?;
    Ok(RpcClient::new(client))
}

async fn publisher_contract_state(
    rpc: &RpcClient,
    address_64hex: &str,
    at_block_hash_0x: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let response = subxt::backend::utils::retry(|| async {
        match rpc
            .request::<String>(
                "midnight_contractState",
                rpc_params![address_64hex, at_block_hash_0x],
            )
            .await
        {
            Err(err @ RawRpcError::DisconnectedWillReconnect(_)) => Err(err.into()),
            answer => Ok(answer),
        }
    })
    .await
    .context("midnight_contractState reconnect failed")?;

    match response {
        Ok(state_hex) => Ok(Some(
            hex::decode(state_hex.trim_start_matches("0x"))
                .context("midnight_contractState returned non-hex state")?,
        )),
        Err(RawRpcError::User(reply))
            if reply.code == INVALID_PARAMS_CODE
                && reply.message.contains("Contract not present") =>
        {
            Ok(None)
        }
        Err(RawRpcError::User(reply))
            if reply.code == INVALID_PARAMS_CODE
                && reply
                    .message
                    .contains("Unable to get requested contract state") =>
        {
            Err(ReadFailure::Unservable.err(RawRpcError::User(reply)))
        }
        Err(RawRpcError::User(reply)) if reply.code == OVERSIZED_RESPONSE_CODE => {
            Err(ReadFailure::TooLarge.err(reply))
        }
        Err(err) => Err(anyhow::Error::new(err).context("midnight_contractState failed")),
    }
}

/// The bare payload of the ledger-parameters `Result<Vec<u8>, _>` runtime-API answer
/// at `MidnightRuntimeApi` version 2 (node 2.0.0-rc.4). `None` is the `Err` variant:
/// only its discriminant is decoded, so an unseen ledger error stays `Err`.
fn unwrap_runtime_api_result(answer: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    use subxt::ext::codec::Decode as _;
    let (variant, mut payload) = answer
        .split_first()
        .context("runtime api returned an empty Result envelope")?;
    match *variant {
        0 => {
            let value = Vec::<u8>::decode(&mut payload)
                .context("runtime api Ok payload is not a SCALE Vec<u8>")?;
            anyhow::ensure!(
                payload.is_empty(),
                "runtime api Ok payload has {} trailing bytes",
                payload.len()
            );
            Ok(Some(value))
        }
        1 => Ok(None),
        other => anyhow::bail!("runtime api returned Result variant {other}"),
    }
}

fn decode_timestamp_seconds(encoded: &[u8]) -> anyhow::Result<u64> {
    use subxt::ext::codec::Decode as _;

    let mut payload = encoded;
    let timestamp_millis =
        u64::decode(&mut payload).context("midnight block timestamp is not a SCALE-encoded u64")?;
    anyhow::ensure!(
        payload.is_empty(),
        "midnight block timestamp has {} trailing bytes",
        payload.len()
    );
    Ok(timestamp_millis / 1_000)
}

/// The one-shot reads over explicit transports, so the offline tests can drive
/// them without an `OnlineClient`, whose construction fetches metadata and
/// therefore needs a whole node.
struct Reads {
    rpc: RpcClient,
    legacy: LegacyRpcMethods<SubstrateConfig>,
    request_timeout: Duration,
    retry: RetryConfig,
    alive: Liveness,
}

/// A read's definitive outcomes, routed through `Ok` so the retry budget is spent
/// only on faults a retry can change.
enum Fetched<T> {
    Value(T),
    TooLarge(String),
    ClientClosed(String),
}

impl Reads {
    fn new(rpc: RpcClient, request_timeout: Duration, retry: RetryConfig, alive: Liveness) -> Self {
        Self {
            legacy: LegacyRpcMethods::<SubstrateConfig>::new(rpc.clone()),
            rpc,
            request_timeout,
            retry,
            alive,
        }
    }

    /// Routes a read's dead-client failures out of the retry budget; everything
    /// else stays a retryable `Err`.
    fn classify<T>(
        &self,
        res: Result<T, RawRpcError>,
        what: &'static str,
    ) -> anyhow::Result<Fetched<T>> {
        match res {
            Ok(value) => Ok(Fetched::Value(value)),
            // subxt boxes the concrete jsonrpsee failure, which makes the downcast sound.
            Err(RawRpcError::Client(client_err))
                if matches!(
                    client_err.downcast_ref::<JsonrpseeClientError>(),
                    Some(JsonrpseeClientError::RestartNeeded(_))
                ) =>
            {
                Ok(Fetched::ClientClosed(client_err.to_string()))
            }
            // Whatever an unclassified error's shape hides (e.g. the dead-client
            // race surfacing as jsonrpsee's Custom placeholder), a down socket is
            // definitive: reconnect, and never charge the entry that observed it.
            Err(err) if !(self.alive)() => Ok(Fetched::ClientClosed(format!(
                "connection is down behind an unclassified error: {err}"
            ))),
            Err(err) => Err(anyhow::Error::new(err).context(what)),
        }
    }

    fn resolve<T>(fetched: Fetched<T>) -> anyhow::Result<T> {
        match fetched {
            Fetched::Value(value) => Ok(value),
            Fetched::TooLarge(detail) => Err(ReadFailure::TooLarge.err(detail)),
            Fetched::ClientClosed(detail) => Err(ReadFailure::ClientClosed.err(detail)),
        }
    }

    async fn finalized_head(&self) -> anyhow::Result<H256> {
        let fetched = retry_rpc!(
            self.request_timeout,
            self.retry,
            "midnight_finalized_head",
            {
                self.classify(
                    self.legacy.chain_get_finalized_head().await,
                    "failed to fetch the midnight finalized head",
                )
            }
        )?;
        Self::resolve(fetched)
    }

    async fn header(
        &self,
        hash: H256,
    ) -> anyhow::Result<Option<<SubstrateConfig as subxt::Config>::Header>> {
        let fetched = retry_rpc!(self.request_timeout, self.retry, "midnight_header", {
            self.classify(
                self.legacy.chain_get_header(Some(hash)).await,
                "failed to fetch a block header",
            )
        })?;
        Self::resolve(fetched)
    }

    async fn block_hash_at(&self, number: u64) -> anyhow::Result<Option<H256>> {
        let fetched = retry_rpc!(
            self.request_timeout,
            self.retry,
            "midnight_block_hash_at",
            {
                self.classify(
                    self.legacy
                        .chain_get_block_hash(Some(NumberOrHex::Number(number)))
                        .await,
                    "failed to fetch a block hash by number",
                )
            }
        )?;
        Self::resolve(fetched)
    }

    async fn contract_state(
        &self,
        address_64hex: &str,
        at_block_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let fetched = retry_rpc!(
            self.request_timeout,
            self.retry,
            "midnight_contractState",
            {
                let response: Result<String, _> = self
                    .rpc
                    .request(
                        "midnight_contractState",
                        rpc_params![address_64hex, at_block_hash_0x],
                    )
                    .await;

                match response {
                    Ok(state_hex) => {
                        let state = hex::decode(state_hex.trim_start_matches("0x"))
                            .context("midnight_contractState returned non-hex state")?;
                        Ok(Fetched::Value(Some(state)))
                    }
                    // The node builds every rpc error as invalid-params with the reason
                    // only in the text, so its two answers stay text matches under the
                    // code gate.
                    Err(RawRpcError::User(reply))
                        if reply.code == INVALID_PARAMS_CODE
                            && reply.message.contains("Contract not present") =>
                    {
                        Ok(Fetched::Value(None))
                    }
                    Err(RawRpcError::User(reply))
                        if reply.code == INVALID_PARAMS_CODE
                            && reply
                                .message
                                .contains("Unable to get requested contract state") =>
                    {
                        Err(anyhow::Error::new(RawRpcError::User(reply))
                            .context(ReadFailure::Unservable.marker()))
                    }
                    // Reachable because our response cap sits above the server's.
                    Err(RawRpcError::User(reply)) if reply.code == OVERSIZED_RESPONSE_CODE => {
                        Ok(Fetched::TooLarge(reply.to_string()))
                    }
                    Err(err) => self.classify(Err(err), "midnight_contractState failed"),
                }
            }
        )?;
        Self::resolve(fetched)
    }
}

fn spawn_runtime_updater(client: OnlineClient<SubstrateConfig>) -> AbortOnDrop {
    AbortOnDrop(tokio::spawn(async move {
        let cancel = CancellationToken::new();
        retry_until_some(
            &cancel,
            Duration::from_secs(1),
            "midnight runtime updater",
            || {
                let updater = client.updater();
                async move {
                    match updater.perform_runtime_updates().await {
                        Ok(()) => Ok(None::<()>),
                        Err(error) => Err(anyhow::Error::new(error)),
                    }
                }
            },
        )
        .await;
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::server::{ServerBuilder, ServerHandle};
    use jsonrpsee::RpcModule;
    use std::collections::{HashMap, VecDeque};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use subxt::backend::rpc::{RawRpcFuture, RawRpcSubscription, RawValue, RpcClientT};
    use subxt::ext::subxt_rpcs::UserError;

    async fn contract_state_server(
        address: impl tokio::net::ToSocketAddrs,
        calls: Arc<AtomicUsize>,
    ) -> (ServerHandle, SocketAddr) {
        let server = ServerBuilder::default()
            .build(address)
            .await
            .expect("bind contract-state server");
        let address = server.local_addr().expect("contract-state server address");
        let mut module = RpcModule::new(());
        module
            .register_method("midnight_contractState", move |_, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                "0xcafe"
            })
            .expect("register contract-state method");
        (server.start(module), address)
    }

    #[tokio::test]
    async fn publisher_startup_is_bounded_if_the_endpoint_dies_during_initialization() {
        use futures_util::StreamExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind bootstrap endpoint");
        let address = listener.local_addr().expect("bootstrap endpoint address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("accept publisher connection");
            let mut websocket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("complete publisher websocket handshake");
            websocket
                .next()
                .await
                .expect("publisher sent no initialization request")
                .expect("read publisher initialization request");
        });
        let mut config = crate::config::MidnightConfig {
            node_ws_url: format!("ws://{address}"),
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
        server.await.expect("bootstrap endpoint task failed");

        let error = match result.expect("publisher startup outlived its connection budget") {
            Ok(_) => panic!("publisher initialized after its endpoint vanished"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("midnight"),
            "startup error has no RPC context: {error:#}"
        );
    }

    #[tokio::test]
    async fn publisher_contract_state_waits_for_reconnect_without_duplicate_calls() {
        let first_calls = Arc::new(AtomicUsize::new(0));
        let (first_server, address) =
            contract_state_server("127.0.0.1:0", first_calls.clone()).await;
        let config = crate::config::MidnightConfig {
            node_ws_url: format!("ws://{address}"),
            central_address: "ab".repeat(32),
            publisher: Default::default(),
            rpc: Default::default(),
            indexer: Default::default(),
        };
        let rpc = connect_publisher_transport(&config)
            .await
            .expect("connect publisher transport");

        let state = publisher_contract_state(&rpc, ADDRESS, AT_HASH)
            .await
            .expect("read contract state before restart");
        assert_eq!(state, Some(vec![0xca, 0xfe]));
        assert_eq!(first_calls.load(Ordering::SeqCst), 1);

        first_server.stop().expect("stop first server");
        first_server.stopped().await;

        // Make one reconnect attempt fail before the replacement server starts.
        // This distinguishes a persistent reconnect loop from a single redial.
        let reject_listener = tokio::net::TcpListener::bind(address)
            .await
            .expect("bind one-shot rejecting listener");
        let rejector = tokio::spawn(async move {
            let (stream, _) = reject_listener
                .accept()
                .await
                .expect("accept reconnect attempt");
            drop(stream);
        });
        tokio::time::timeout(Duration::from_secs(1), rejector)
            .await
            .expect("publisher made no reconnect attempt")
            .expect("rejecting listener task failed");

        let pending_rpc = rpc.clone();
        let mut pending =
            tokio::spawn(
                async move { publisher_contract_state(&pending_rpc, ADDRESS, AT_HASH).await },
            );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut pending)
                .await
                .is_err(),
            "a publisher read must wait while the endpoint is unavailable"
        );

        let second_calls = Arc::new(AtomicUsize::new(0));
        let (_second_server, rebound) = contract_state_server(address, second_calls.clone()).await;
        assert_eq!(rebound, address);

        let state = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .expect("publisher transport did not reconnect before the deadline")
            .expect("publisher read task failed")
            .expect("publisher contract-state read failed after reconnect");
        assert_eq!(state, Some(vec![0xca, 0xfe]));
        assert_eq!(
            second_calls.load(Ordering::SeqCst),
            1,
            "one logical read must produce one request after reconnect"
        );
    }

    #[tokio::test]
    #[ignore = "requires a local midnight node"]
    async fn live_finalized_subscription_yields_a_block() {
        use futures_util::StreamExt as _;

        let config = crate::config::MidnightConfig {
            node_ws_url: "ws://127.0.0.1:9944".to_string(),
            central_address: "ab".repeat(32),
            publisher: Default::default(),
            rpc: Default::default(),
            indexer: Default::default(),
        };
        let rpc = MidnightRpc::connect(&config).await.expect("connect");

        let head = rpc.finalized_block_ref().await.expect("finalized head");
        assert_ne!(head.hash, hex_0x(subxt::utils::H256::zero()));

        let mut blocks = rpc
            .subscribe_finalized()
            .await
            .expect("subscribe finalized");
        let block = blocks.next().await.expect("one finalized block");
        assert!(block.number > 0);
        assert_ne!(block.hash, block.parent_hash);
    }

    // Contract-state reads over an in-process JSON-RPC stub.

    /// One canned reply for a stubbed JSON-RPC method: a value, a JSON-RPC error
    /// response, or one of the client-side failure shapes subxt exposes.
    #[derive(Clone)]
    enum Canned {
        Value(&'static str),
        User(i32, &'static str),
        Reconnecting,
        ClientDead,
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
                    Canned::Value(value) => Ok(RawValue::from_string(
                        serde_json::to_string(value).expect("serialize canned value"),
                    )
                    .expect("canned value is valid JSON")),
                    Canned::User(code, message) => Err(RawRpcError::User(UserError {
                        code,
                        message: message.to_string(),
                        data: None,
                    })),
                    Canned::Reconnecting => Err(RawRpcError::DisconnectedWillReconnect(
                        "stub reconnect".to_string(),
                    )),
                    Canned::ClientDead => Err(RawRpcError::Client(Box::new(
                        JsonrpseeClientError::RestartNeeded(std::sync::Arc::new(
                            JsonrpseeClientError::Transport("stub ws died".into()),
                        )),
                    ))),
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

    /// A [`Reads`] over the stub, with the given retry budget and liveness answer.
    fn stub_reads(node: &StubNode, retry: RetryConfig, alive: bool) -> Reads {
        Reads::new(
            RpcClient::new(node.clone()),
            READ_TIMEOUT,
            retry,
            Arc::new(move || alive),
        )
    }

    #[tokio::test]
    async fn publisher_contract_state_retries_the_reconnect_signal() {
        let node = StubNode::new(vec![(
            "midnight_contractState",
            vec![Canned::Reconnecting, Canned::Value("0xcafe")],
        )]);
        let rpc = RpcClient::new(node.clone());

        let state = publisher_contract_state(&rpc, ADDRESS, AT_HASH)
            .await
            .expect("the interrupted call is retried");

        assert_eq!(state, Some(vec![0xca, 0xfe]));
        assert_eq!(node.calls_to("midnight_contractState").len(), 2);
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
        let err = stub_reads(&node, attempts(2), true)
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

        // A dead client classifies by type: subxt boxes jsonrpsee's RestartNeeded.
        let node = StubNode::new(vec![("midnight_contractState", vec![Canned::ClientDead])]);
        let err = stub_reads(&node, attempts(2), true)
            .contract_state(ADDRESS, AT_HASH)
            .await
            .expect_err("a dead client is a failure");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "{err:#}"
        );
        assert_eq!(node.calls_to("midnight_contractState").len(), 1);

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
            let err = stub_reads(&node, attempts(2), true)
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
        let err = stub_reads(&node, attempts(2), true)
            .contract_state(ADDRESS, AT_HASH)
            .await
            .expect_err("a transport fault is a failure");
        assert_eq!(ReadFailure::of(&err), None, "{err:#}");
        assert_eq!(node.calls_to("midnight_contractState").len(), 3);
    }

    #[tokio::test]
    async fn legacy_reads_classify_a_dead_client_without_retries() {
        // The dead-client class must not be private to contract_state: the anchor
        // and catchup reads observe the same dead client and must escape their
        // retry loops through the same marker, spending no budget on it.
        let node = StubNode::new(vec![
            ("chain_getFinalizedHead", vec![Canned::ClientDead]),
            ("chain_getBlockHash", vec![Canned::ClientDead]),
            ("chain_getHeader", vec![Canned::ClientDead]),
        ]);

        let err = stub_reads(&node, attempts(2), true)
            .finalized_head()
            .await
            .expect_err("a dead client is a failure");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "{err:#}"
        );
        assert_eq!(
            node.calls_to("chain_getFinalizedHead").len(),
            1,
            "a dead client must not be retried"
        );

        let err = stub_reads(&node, attempts(2), true)
            .block_hash_at(7)
            .await
            .expect_err("a dead client is a failure");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "{err:#}"
        );
        assert_eq!(node.calls_to("chain_getBlockHash").len(), 1);

        let err = stub_reads(&node, attempts(2), true)
            .header(H256::zero())
            .await
            .expect_err("a dead client is a failure");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "{err:#}"
        );
        assert_eq!(node.calls_to("chain_getHeader").len(), 1);
    }

    #[tokio::test]
    async fn unclassified_errors_on_a_dead_connection_classify_client_closed() {
        // The dead-client race can surface as a shape the downcast misses (e.g.
        // jsonrpsee's Custom placeholder): the liveness probe catches whatever
        // the error shape hides, so a dead connection is never charged as a
        // generic fault, and never retried.
        let node = StubNode::new(vec![("midnight_contractState", vec![Canned::ClientErr])]);
        let err = stub_reads(&node, attempts(2), false)
            .contract_state(ADDRESS, AT_HASH)
            .await
            .expect_err("a dead connection is a failure");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "{err:#}"
        );
        assert_eq!(
            node.calls_to("midnight_contractState").len(),
            1,
            "a dead connection must not be retried"
        );

        // The legacy reads share the gate.
        let node = StubNode::new(vec![("chain_getFinalizedHead", vec![Canned::ClientErr])]);
        let err = stub_reads(&node, attempts(2), false)
            .finalized_head()
            .await
            .expect_err("a dead connection is a failure");
        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "{err:#}"
        );
        assert_eq!(node.calls_to("chain_getFinalizedHead").len(), 1);
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
        let absent = stub_reads(&node, attempts(2), true)
            .contract_state(ADDRESS, AT_HASH)
            .await
            .expect("contract-not-present is an answer, not a failure");
        assert_eq!(absent, None);
        assert_eq!(node.calls_to("midnight_contractState").len(), 1);

        let node = StubNode::new(vec![(
            "midnight_contractState",
            vec![Canned::User(INVALID_PARAMS_CODE, UNSERVABLE_MSG)],
        )]);
        let err = stub_reads(&node, attempts(2), true)
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
        assert!(unwrap_runtime_api_result(&trailing).is_err());
    }

    #[test]
    fn block_timestamp_matches_the_ledger_s_second_floor() {
        use subxt::ext::codec::Encode as _;

        assert_eq!(decode_timestamp_seconds(&1_000u64.encode()).unwrap(), 1);
        assert_eq!(decode_timestamp_seconds(&1_999u64.encode()).unwrap(), 1);

        let mut trailing = 1_000u64.encode();
        trailing.push(0xff);
        assert!(decode_timestamp_seconds(&trailing).is_err());
    }
}
