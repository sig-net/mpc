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
use subxt::client::OnlineClient;
use subxt::ext::codec::DecodeAll as _;
use subxt::ext::codec::Encode as _;
use subxt::ext::jsonrpsee::client_transport::ws::{Url as WsUrl, WsTransportClientBuilder};
use subxt::ext::jsonrpsee::core::client::async_client::PingConfig;
use subxt::ext::jsonrpsee::core::client::{Client as RawWsClient, Error as JsonrpseeClientError};
use subxt::ext::jsonrpsee::types::error::{INVALID_PARAMS_CODE, OVERSIZED_RESPONSE_CODE};
use subxt::ext::scale_decode::DecodeAsType;
use subxt::ext::subxt_rpcs::{rpc_params, Error as RawRpcError};
use subxt::utils::H256;
use subxt::SubstrateConfig;
use tokio_util::sync::CancellationToken;

use crate::config::MidnightConfig;
use crate::emissions::{emissions_in, DecodedTransaction};
use crate::indexer::Hold;
use crate::source::{BlockEmissions, BlockProofSeed, CandidateTransactionEmissions};

const WATCHDOG_TICK: Duration = Duration::from_secs(5);

/// Runtime API name from Midnight node 2.0.0-rc.4 metadata.
const LEDGER_PARAMETERS_ENTRY: &str = "MidnightRuntimeApi_get_ledger_parameters";
/// The connected runtime is the canonical owner of the wallet network identity.
const NETWORK_ID_ENTRY: &str = "MidnightRuntimeApi_get_network_id";

#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
struct SendMnTransaction {
    midnight_tx: Vec<u8>,
}

impl subxt::blocks::StaticExtrinsic for SendMnTransaction {
    const PALLET: &'static str = "Midnight";
    const CALL: &'static str = "send_mn_transaction";
}

#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
struct TxAppliedDetails {
    tx_hash: [u8; 32],
}

#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
struct TxApplied(TxAppliedDetails);

impl subxt::events::StaticEvent for TxApplied {
    const PALLET: &'static str = "Midnight";
    const EVENT: &'static str = "TxApplied";
}

#[derive(DecodeAsType)]
#[decode_as_type(crate_path = "subxt::ext::scale_decode")]
struct TxPartialSuccess(TxAppliedDetails);

impl subxt::events::StaticEvent for TxPartialSuccess {
    const PALLET: &'static str = "Midnight";
    const EVENT: &'static str = "TxPartialSuccess";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SegmentStatus {
    Applied,
    GuaranteedOnly,
}

const fn fallible_allowed(status: SegmentStatus) -> bool {
    matches!(status, SegmentStatus::Applied)
}

fn hold(reason: &'static str, height: u64, cause: impl Into<anyhow::Error>) -> anyhow::Error {
    Hold {
        reason,
        height,
        cause: cause.into(),
    }
    .into()
}

/// The classified read failures, travelling as marker text because `retry_rpc!`
/// flattens error chains to their message; when the retry layer preserves sources,
/// [`of`](Self::of) becomes a downcast and call sites stay put.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadFailure {
    /// Pruned or unknown hash: no number of retries makes the node serve it.
    Unservable,
    /// State beyond the rpc response cap: definitive (retrying cannot shrink a
    /// contract's state) and the contract's own property, so reads of it charge
    /// the caller.
    TooLarge,
    /// The client's background task is gone: every call fails until reconnect, so
    /// this ends `run()` and is never charged to the entry that observed it.
    ClientClosed,
}

impl ReadFailure {
    /// The marker text errors of this class carry.
    pub(crate) const fn marker(self) -> &'static str {
        match self {
            Self::Unservable => {
                "midnight node cannot serve contract state at that block (pruned or unknown hash)"
            }
            Self::TooLarge => "midnight contract state exceeds the rpc response cap",
            Self::ClientClosed => "midnight rpc client closed; a reconnect is required",
        }
    }

    /// An error of this class: the marker, then the detail.
    fn err(self, detail: impl std::fmt::Display) -> anyhow::Error {
        anyhow::anyhow!("{}: {detail}", self.marker())
    }

    /// The class `err` carries, if any.
    pub(crate) fn of(err: &anyhow::Error) -> Option<Self> {
        let text = err.to_string();
        [Self::Unservable, Self::TooLarge, Self::ClientClosed]
            .into_iter()
            .find(|class| text.contains(class.marker()))
    }
}

/// Whether the websocket is still up, consulted when an error's shape alone
/// cannot say; wraps the raw client's own `is_connected` in live code.
type Liveness = Arc<dyn Fn() -> bool + Send + Sync>;

/// One finalized block as plain data: the number plus the `0x`-prefixed hashes
/// `midnight_contractState` takes, detached from any subxt handle so fixtures can mint
/// them.
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

    // `RpcClient::from_url` with the one knob it does not expose, the response
    // cap (`RpcConfig::max_response_size`): the same transport, client and
    // subscription buffer, through subxt's own jsonrpsee re-export.
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
    // `is_connected` is the liveness answer catching dead-client shapes
    // the error types hide.
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

    pub(crate) async fn block_emissions(
        &self,
        block_ref: &BlockRef,
        singleton: &[u8; 32],
    ) -> anyhow::Result<Option<BlockEmissions>> {
        let hash = parse_block_hash(&block_ref.hash)?;
        let block = retry_rpc!(
            self.reads.request_timeout,
            self.reads.retry,
            "midnight_block",
            {
                self.reads.classify_subxt(
                    self.client.blocks().at(hash).await,
                    "failed to fetch a midnight block",
                )
            }
        )?;
        let block = Reads::resolve(block)?;
        let extrinsics = retry_rpc!(
            self.reads.request_timeout,
            self.reads.retry,
            "midnight_block_body",
            {
                self.reads.classify_subxt(
                    block.extrinsics().await,
                    "failed to fetch a midnight block body",
                )
            }
        )?;
        let extrinsics = Reads::resolve(extrinsics)?;

        let mut candidates = Vec::new();
        for found in extrinsics.find::<SendMnTransaction>() {
            let found = found.map_err(|err| {
                hold(
                    "emission-schema-hold",
                    u64::from(block.number()),
                    anyhow::Error::new(err).context("send_mn_transaction did not match metadata"),
                )
            })?;
            if memchr::memmem::find(&found.value.midnight_tx, singleton).is_some() {
                candidates.push(found);
            }
        }
        if candidates.is_empty() {
            return Ok(None);
        }

        let height = u64::from(block.number());
        let mut decoded_candidates = Vec::with_capacity(candidates.len());
        let mut scale_system_events = None;
        for found in candidates {
            let events = retry_rpc!(
                self.reads.request_timeout,
                self.reads.retry,
                "midnight_block_events",
                {
                    self.reads.classify_subxt(
                        found.details.events().await,
                        "failed to fetch midnight block events",
                    )
                }
            )?;
            let events = Reads::resolve(events)?;
            scale_system_events
                .get_or_insert_with(|| events.all_events_in_block().bytes().to_vec());

            let applied = events.find_first::<TxApplied>().map_err(|err| {
                hold(
                    "emission-schema-hold",
                    height,
                    anyhow::Error::new(err).context("TxApplied did not match metadata"),
                )
            })?;
            let (status, _ledger_tx_hash) = if let Some(TxApplied(details)) = applied {
                (SegmentStatus::Applied, details.tx_hash)
            } else {
                match events.find_first::<TxPartialSuccess>().map_err(|err| {
                    hold(
                        "emission-schema-hold",
                        height,
                        anyhow::Error::new(err).context("TxPartialSuccess did not match metadata"),
                    )
                })? {
                    Some(TxPartialSuccess(details)) => {
                        (SegmentStatus::GuaranteedOnly, details.tx_hash)
                    }
                    None => {
                        return Err(hold(
                            "singleton-tx-without-status",
                            height,
                            anyhow::anyhow!(
                                "candidate extrinsic {} has no Midnight status event",
                                found.details.index()
                            ),
                        ));
                    }
                }
            };

            let tx: DecodedTransaction = midnight_serialize::tagged_deserialize(
                &mut &found.value.midnight_tx[..],
            )
            .map_err(|err| {
                hold(
                    "singleton-tx-undecodable",
                    height,
                    anyhow::Error::new(err).context(format!(
                        "candidate extrinsic {} ledger transaction",
                        found.details.index()
                    )),
                )
            })?;
            let calls = emissions_in(&tx, singleton, fallible_allowed(status)).map_err(|err| {
                hold(
                    "emission-schema-hold",
                    height,
                    err.context(format!(
                        "candidate extrinsic {} singleton emissions",
                        found.details.index()
                    )),
                )
            })?;
            decoded_candidates.push(CandidateTransactionEmissions {
                extrinsic_index: found.details.index(),
                calls,
            });
        }

        Ok(Some(BlockEmissions {
            proof_seed: BlockProofSeed {
                reported_genesis_hash: *self.client.genesis_hash().as_fixed_bytes(),
                reported_block_number: height,
                reported_block_hash: *block.hash().as_fixed_bytes(),
                singleton_address: *singleton,
                scale_header: block.header().encode(),
                scale_body: extrinsics
                    .iter()
                    .map(|extrinsic| extrinsic.bytes().to_vec())
                    .collect(),
                scale_system_events: scale_system_events
                    .expect("a prefiltered candidate always fetched block events"),
            },
            candidates: decoded_candidates,
        }))
    }
}

/// Finalized reads for the Midnight publisher. Subxt owns connection recovery;
/// callers keep one instance instead of rebuilding or retrying a dead transport.
pub struct MidnightPublisherRpc {
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
            .client
            .backend()
            .latest_finalized_block_ref()
            .await
            .context("failed to fetch the midnight finalized head")?;
        Ok(hex_0x(finalized.hash()))
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
            .client
            .backend()
            .call(LEDGER_PARAMETERS_ENTRY, Some(&[]), at)
            .await
            .context("failed to fetch midnight ledger parameters")?;
        unwrap_runtime_api_result(&answer)?
            .with_context(|| format!("midnight node has no ledger parameters at {at_hash_0x}"))
    }
}

async fn network_id(client: &OnlineClient<SubstrateConfig>) -> anyhow::Result<String> {
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
    decode_network_id(&answer)
}

fn decode_network_id(answer: &[u8]) -> anyhow::Result<String> {
    let mut payload = answer;
    String::decode_all(&mut payload).context("midnight runtime returned a malformed network id")
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

    /// Applies the same dead-client policy to Subxt's higher-level read errors.
    fn classify_subxt<T>(
        &self,
        res: Result<T, subxt::Error>,
        what: &'static str,
    ) -> anyhow::Result<Fetched<T>> {
        match res {
            Ok(value) => Ok(Fetched::Value(value)),
            Err(subxt::Error::Rpc(subxt::error::RpcError::ClientError(RawRpcError::Client(
                client_err,
            )))) if matches!(
                client_err.downcast_ref::<JsonrpseeClientError>(),
                Some(JsonrpseeClientError::RestartNeeded(_))
            ) =>
            {
                Ok(Fetched::ClientClosed(client_err.to_string()))
            }
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

                match classify_contract_state_reply(response)? {
                    ContractStateReply::State(state) => Ok(Fetched::Value(state)),
                    // Spends the retry budget like any other `Err`; only the class escapes.
                    ContractStateReply::Unservable(err) => Err(ReadFailure::Unservable.err(err)),
                    ContractStateReply::TooLarge(err) => Ok(Fetched::TooLarge(err.to_string())),
                    ContractStateReply::Other(err) => {
                        self.classify(Err(err), "midnight_contractState failed")
                    }
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
    use std::io::Write as _;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use subxt::backend::rpc::{RawRpcFuture, RawRpcSubscription, RawValue, RpcClientT};
    use subxt::ext::scale_decode::DecodeAsType;
    use subxt::ext::subxt_rpcs::UserError;

    #[test]
    fn applied_status_scans_fallible_transcripts() {
        assert!(fallible_allowed(SegmentStatus::Applied));
    }

    #[test]
    fn partial_success_scans_only_guaranteed_transcripts() {
        assert!(!fallible_allowed(SegmentStatus::GuaranteedOnly));
    }

    #[derive(DecodeAsType)]
    #[decode_as_type(crate_path = "subxt::ext::scale_decode")]
    struct CaptureCallDetails {
        tx_hash: [u8; 32],
        contract_address: Vec<u8>,
    }

    #[derive(DecodeAsType)]
    #[decode_as_type(crate_path = "subxt::ext::scale_decode")]
    struct CaptureContractCall(CaptureCallDetails);

    impl subxt::events::StaticEvent for CaptureContractCall {
        const PALLET: &'static str = "Midnight";
        const EVENT: &'static str = "ContractCall";
    }

    fn capture_output_dir(value: &str) -> anyhow::Result<PathBuf> {
        anyhow::ensure!(
            !value.is_empty(),
            "MIDNIGHT_CAPTURE_OUT_DIR must not be empty"
        );
        Ok(PathBuf::from(value))
    }

    fn write_new_capture(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?
            .write_all(bytes)
    }

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

    fn fresh_capture_test_dir() -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "mpc-chain-midnight-capture-path-test-{}",
            std::process::id()
        ));
        for suffix in 0..1024 {
            let candidate = base.with_extension(suffix.to_string());
            match std::fs::create_dir(&candidate) {
                Ok(()) => return candidate,
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create capture path test directory: {err}"),
            }
        }
        panic!("could not allocate a capture path test directory");
    }

    #[test]
    fn capture_path_rejects_an_empty_output_directory() {
        let err = capture_output_dir("").expect_err("an empty output path must be rejected");

        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected empty-path error: {err:#}"
        );
    }

    #[test]
    fn capture_path_refuses_an_existing_target_without_changing_it() {
        let output_dir = fresh_capture_test_dir();
        let target = output_dir.join("tx-42-7.mn");
        let original = b"existing capture that must survive";
        std::fs::write(&target, original).expect("seed existing capture");

        let err = write_new_capture(&target, b"replacement")
            .expect_err("an existing capture target must be refused");

        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&target).expect("read preserved capture"),
            original
        );
        std::fs::remove_file(&target).expect("remove capture path test file");
        std::fs::remove_dir(&output_dir).expect("remove capture path test directory");
    }

    #[tokio::test]
    #[ignore = "capture tool: MIDNIGHT_NODE_WS_URL, MIDNIGHT_CAPTURE_BLOCK, MIDNIGHT_CAPTURE_SINGLETON, MIDNIGHT_CAPTURE_OUT_DIR"]
    async fn capture_block_fixtures() {
        let node_ws_url = std::env::var("MIDNIGHT_NODE_WS_URL")
            .expect("MIDNIGHT_NODE_WS_URL must name the capture node websocket");
        let height = std::env::var("MIDNIGHT_CAPTURE_BLOCK")
            .expect("MIDNIGHT_CAPTURE_BLOCK must name one capture height")
            .parse::<u64>()
            .expect("MIDNIGHT_CAPTURE_BLOCK must be a u64");
        let singleton_hex = std::env::var("MIDNIGHT_CAPTURE_SINGLETON")
            .expect("MIDNIGHT_CAPTURE_SINGLETON must be 32 bytes of hex")
            .trim_start_matches("0x")
            .to_ascii_lowercase();
        let singleton: [u8; 32] = hex::decode(&singleton_hex)
            .expect("MIDNIGHT_CAPTURE_SINGLETON must be hex")
            .try_into()
            .expect("MIDNIGHT_CAPTURE_SINGLETON must be exactly 32 bytes");
        let output_dir = capture_output_dir(
            &std::env::var("MIDNIGHT_CAPTURE_OUT_DIR")
                .expect("MIDNIGHT_CAPTURE_OUT_DIR must name the fixture output directory"),
        )
        .expect("MIDNIGHT_CAPTURE_OUT_DIR must name a non-empty fixture output directory");
        std::fs::create_dir_all(&output_dir).expect("create capture output directory");

        let config = crate::config::MidnightConfig {
            node_ws_url,
            central_address: singleton_hex.clone(),
            publisher: Default::default(),
            rpc: Default::default(),
            indexer: Default::default(),
        };
        let rpc = MidnightRpc::connect(&config)
            .await
            .expect("connect to capture node");
        let block_ref = rpc
            .block_ref_at(height)
            .await
            .expect("resolve capture block");
        let block_hash = parse_block_hash(&block_ref.hash).expect("parse capture block hash");
        let block = rpc
            .client
            .blocks()
            .at(block_hash)
            .await
            .expect("read capture block");
        let extrinsics = block.extrinsics().await.expect("read capture block body");

        let mut captured = 0usize;
        for found in extrinsics.find::<SendMnTransaction>() {
            let found = found.expect("decode send_mn_transaction from live metadata");
            if !found
                .value
                .midnight_tx
                .windows(singleton.len())
                .any(|window| window == singleton)
            {
                continue;
            }

            let extrinsic_index = found.details.index();
            let path = output_dir.join(format!("tx-{height}-{extrinsic_index}.mn"));
            let events = found.details.events().await.expect("read extrinsic events");
            let applied = events
                .find_first::<TxApplied>()
                .expect("decode TxApplied from live metadata");
            let partial = events
                .find_first::<TxPartialSuccess>()
                .expect("decode TxPartialSuccess from live metadata");
            let (status, status_hash) = match (applied, partial) {
                (Some(TxApplied(details)), None) => ("TxApplied", details.tx_hash),
                (None, Some(TxPartialSuccess(details))) => ("TxPartialSuccess", details.tx_hash),
                (None, None) => panic!("capture candidate has no Midnight status event"),
                (Some(_), Some(_)) => panic!("capture candidate has both Midnight status events"),
            };
            let contract_calls = events
                .find::<CaptureContractCall>()
                .map(|call| {
                    let CaptureContractCall(details) =
                        call.expect("decode ContractCall from live metadata");
                    assert_eq!(
                        details.tx_hash, status_hash,
                        "ContractCall and status must name the same ledger transaction"
                    );
                    format!("0x{}", hex::encode(details.contract_address))
                })
                .collect::<Vec<_>>();
            write_new_capture(&path, &found.value.midnight_tx)
                .expect("create new transaction fixture without replacing an existing capture");

            println!(
                "capture block={height} hash={} extrinsic_index={extrinsic_index} \
                 status={status} tx_hash=0x{} contract_calls={contract_calls:?} file={}",
                block_ref.hash,
                hex::encode(status_hash),
                path.display()
            );
            captured += 1;
        }
        assert!(
            captured > 0,
            "capture block contains no singleton candidate"
        );

        if let Ok(caller_hex) = std::env::var("MIDNIGHT_CAPTURE_CALLER") {
            let caller_hex = caller_hex.trim_start_matches("0x").to_ascii_lowercase();
            let caller: [u8; 32] = hex::decode(&caller_hex)
                .expect("MIDNIGHT_CAPTURE_CALLER must be hex")
                .try_into()
                .expect("MIDNIGHT_CAPTURE_CALLER must be exactly 32 bytes");
            let caller_hex = hex::encode(caller);
            let caller_state = rpc
                .contract_state(&caller_hex, &block_ref.hash)
                .await
                .expect("read caller state at capture block")
                .expect("caller contract must exist at capture block");
            let caller_path = output_dir.join(format!("caller-post-state-{height}.mn"));

            let singleton_state = rpc
                .contract_state(&singleton_hex, &block_ref.hash)
                .await
                .expect("read singleton state at capture block")
                .expect("singleton contract must exist at capture block");
            let singleton_path = output_dir.join(format!("singleton-state-{height}.mn"));
            write_new_capture(&caller_path, &caller_state)
                .expect("create new caller state fixture without replacing an existing capture");
            write_new_capture(&singleton_path, &singleton_state)
                .expect("create new singleton state fixture without replacing an existing capture");

            println!(
                "capture block={height} caller_state={} singleton_state={}",
                caller_path.display(),
                singleton_path.display()
            );
        }
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

    fn subxt_restart_needed() -> subxt::Error {
        subxt::Error::Rpc(subxt::error::RpcError::ClientError(RawRpcError::Client(
            Box::new(JsonrpseeClientError::RestartNeeded(Arc::new(
                JsonrpseeClientError::Transport("stub ws died".into()),
            ))),
        )))
    }

    #[tokio::test]
    async fn subxt_restart_needed_classifies_client_closed_without_retries() {
        let node = StubNode::new(Vec::<(&str, Vec<Canned>)>::new());
        let reads = stub_reads(&node, attempts(2), true);
        let calls = AtomicUsize::new(0);

        let fetched = retry_rpc!(READ_TIMEOUT, attempts(2), "subxt_test", {
            calls.fetch_add(1, Ordering::SeqCst);
            reads.classify_subxt::<()>(
                Err(subxt_restart_needed()),
                "failed to perform a Subxt read",
            )
        })
        .expect("a closed client is a definitive classified outcome");
        let err = Reads::resolve(fetched).expect_err("a closed client is a failure");

        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "{err:#}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn any_subxt_error_on_a_dead_connection_classifies_without_retries() {
        let node = StubNode::new(Vec::<(&str, Vec<Canned>)>::new());
        let reads = stub_reads(&node, attempts(2), false);
        let calls = AtomicUsize::new(0);

        let fetched = retry_rpc!(READ_TIMEOUT, attempts(2), "subxt_test", {
            calls.fetch_add(1, Ordering::SeqCst);
            reads.classify_subxt::<()>(
                Err(subxt::Error::Other("unclassified Subxt fault".to_string())),
                "failed to perform a Subxt read",
            )
        })
        .expect("a dead connection is a definitive classified outcome");
        let err = Reads::resolve(fetched).expect_err("a dead connection is a failure");

        assert_eq!(
            ReadFailure::of(&err),
            Some(ReadFailure::ClientClosed),
            "{err:#}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ordinary_live_subxt_errors_remain_retryable_and_unclassified() {
        let node = StubNode::new(Vec::<(&str, Vec<Canned>)>::new());
        let reads = stub_reads(&node, attempts(2), true);
        let calls = AtomicUsize::new(0);

        let result = retry_rpc!(READ_TIMEOUT, attempts(2), "subxt_test", {
            calls.fetch_add(1, Ordering::SeqCst);
            reads.classify_subxt::<()>(
                Err(subxt::Error::Other("ordinary Subxt fault".to_string())),
                "failed to perform a Subxt read",
            )
        });
        let err = match result {
            Ok(_) => panic!("a live Subxt fault must remain retryable"),
            Err(err) => err,
        };

        assert_eq!(ReadFailure::of(&err), None, "{err:#}");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
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
