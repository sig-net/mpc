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
use subxt::client::OnlineClient;
use subxt::ext::codec::DecodeAll as _;
use subxt::ext::codec::Encode as _;
use subxt::ext::scale_decode::DecodeAsType;
use subxt::ext::subxt_rpcs::{rpc_params, Error as RawRpcError, UserError};
use subxt::utils::H256;
use subxt::SubstrateConfig;

use crate::config::{MidnightConfig, RpcConfig};
use crate::emissions::{emissions_in, DecodedTransaction};
use crate::indexer::BlockHold;
use crate::source::{BlockEmissions, BlockProofSeed, CandidateTransactionEmissions};

/// Runtime API name from Midnight node 2.0.0-rc.4 metadata.
const LEDGER_PARAMETERS_ENTRY: &str = "MidnightRuntimeApi_get_ledger_parameters";
/// The connected runtime is the canonical owner of the wallet network identity.
const NETWORK_ID_ENTRY: &str = "MidnightRuntimeApi_get_network_id";

pub(crate) const STATE_TOO_LARGE: &str = "midnight contract state exceeds the rpc response cap";

#[derive(Debug)]
struct OversizedContractState(RawRpcError);

impl std::fmt::Display for OversizedContractState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{STATE_TOO_LARGE}: {}", self.0)
    }
}

impl std::error::Error for OversizedContractState {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

pub(crate) fn oversized_contract_state(source: RawRpcError) -> anyhow::Error {
    anyhow::Error::new(OversizedContractState(source))
}

pub(crate) fn is_oversized_contract_state(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.is::<OversizedContractState>())
}

struct Params(Option<Box<RawValue>>);

impl ToRpcParams for Params {
    fn to_rpc_params(self) -> Result<Option<Box<RawValue>>, serde_json::Error> {
        Ok(self.0)
    }
}

/// Request-only jsonrpsee HTTP transport behind Subxt's raw client seam.
#[derive(Clone)]
struct HttpRpcClient(HttpClient);

impl RpcClientT for HttpRpcClient {
    fn request_raw<'a>(
        &'a self,
        method: &'a str,
        params: Option<Box<RawValue>>,
    ) -> RawRpcFuture<'a, Box<RawValue>> {
        Box::pin(async move {
            self.0
                .request(method, Params(params))
                .await
                .map_err(|error| match error {
                    JsonrpseeClientError::Call(error) => RawRpcError::User(UserError {
                        code: error.code(),
                        message: error.message().to_owned(),
                        data: error.data().map(ToOwned::to_owned),
                    }),
                    error => RawRpcError::Client(Box::new(error)),
                })
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
                "midnight HTTP RPC transport does not support subscriptions",
            ))))
        })
    }
}

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

/// Accept only one unambiguous full-success status from this extrinsic.
/// These are RPC-reported events; this check does not verify their inclusion.
fn fully_applied_hash(
    events: &subxt::blocks::ExtrinsicEvents<SubstrateConfig>,
) -> anyhow::Result<Option<[u8; 32]>> {
    let mut applied = None;
    let mut partial = None;
    for event in events.iter() {
        let event = event.context("Midnight status events did not match metadata")?;
        if let Some(TxApplied(details)) = event.as_event::<TxApplied>()? {
            anyhow::ensure!(
                applied.replace(details.tx_hash).is_none(),
                "duplicate TxApplied status"
            );
        }
        if let Some(TxPartialSuccess(details)) = event.as_event::<TxPartialSuccess>()? {
            anyhow::ensure!(
                partial.replace(details.tx_hash).is_none(),
                "duplicate TxPartialSuccess status"
            );
        }
    }
    anyhow::ensure!(
        applied.is_none() || partial.is_none(),
        "conflicting Midnight statuses"
    );
    Ok(applied)
}

fn decode_applied_transaction(
    bytes: &[u8],
    expected_hash: [u8; 32],
) -> anyhow::Result<DecodedTransaction> {
    let tx: DecodedTransaction = midnight_serialize::tagged_deserialize(&mut &bytes[..])
        .context("candidate ledger transaction did not decode")?;
    anyhow::ensure!(
        tx.transaction_hash().0 .0 == expected_hash,
        "TxApplied hash does not match the candidate ledger transaction"
    );
    Ok(tx)
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
    connect_http_endpoint(&config.node_url, &config.rpc)
}

fn connect_http_endpoint(node_url: &str, config: &RpcConfig) -> anyhow::Result<RpcClient> {
    let client = HttpClientBuilder::default()
        .max_response_size(config.max_response_size)
        .request_timeout(config.request_timeout)
        .build(node_url)
        .context("failed to build the midnight HTTP RPC client")?;
    Ok(RpcClient::new(HttpRpcClient(client)))
}

pub(crate) struct MidnightRpc {
    client: OnlineClient<SubstrateConfig>,
    reads: Reads,
}

impl MidnightRpc {
    /// Builds Subxt over the request-only HTTP client named by `config.node_url`.
    pub async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        let rpc = connect_http(config)?;
        let client = tokio::time::timeout(
            config.rpc.connect_timeout,
            OnlineClient::<SubstrateConfig>::from_rpc_client(rpc.clone()),
        )
        .await
        .context("timed out initialising the midnight subxt client")?
        .context("failed to initialise the midnight subxt client")?;

        Ok(Self {
            client,
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
        anyhow::ensure!(
            returned_number == number,
            "midnight block lookup requested height {number} but returned height {returned_number}"
        );
        Ok(BlockRef {
            number: returned_number,
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
        let block = retry_read(
            self.reads.request_timeout,
            self.reads.retry,
            "midnight_block",
            || async {
                self.client
                    .blocks()
                    .at(hash)
                    .await
                    .map_err(anyhow::Error::new)
                    .context("failed to fetch a midnight block")
            },
        )
        .await?;
        let extrinsics = retry_read(
            self.reads.request_timeout,
            self.reads.retry,
            "midnight_block_body",
            || async {
                block
                    .extrinsics()
                    .await
                    .map_err(anyhow::Error::new)
                    .context("failed to fetch a midnight block body")
            },
        )
        .await?;

        let mut candidates = Vec::new();
        for found in extrinsics.find::<SendMnTransaction>() {
            let found = found.map_err(|err| {
                BlockHold::new(
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
            let events = retry_read(
                self.reads.request_timeout,
                self.reads.retry,
                "midnight_block_events",
                || async {
                    found
                        .details
                        .events()
                        .await
                        .map_err(anyhow::Error::new)
                        .context("failed to fetch midnight block events")
                },
            )
            .await?;
            scale_system_events
                .get_or_insert_with(|| events.all_events_in_block().bytes().to_vec());

            let applied = fully_applied_hash(&events)
                .map_err(|err| BlockHold::new("emission-schema-hold", height, err))?;
            let Some(ledger_tx_hash) = applied else {
                tracing::warn!(
                    reason = "unsupported-midnight-status",
                    height,
                    extrinsic_index = found.details.index(),
                    "midnight transaction skipped: only TxApplied is supported"
                );
                continue;
            };
            let tx = decode_applied_transaction(&found.value.midnight_tx, ledger_tx_hash).map_err(
                |err| {
                    BlockHold::new(
                        "singleton-tx-undecodable",
                        height,
                        err.context(format!(
                            "candidate extrinsic {} ledger transaction",
                            found.details.index()
                        )),
                    )
                },
            )?;
            // TxApplied covers both logical phases. Partial results cannot identify
            // committed fallible segments through this node's status events.
            let calls = emissions_in(&tx, singleton).map_err(|err| {
                BlockHold::new(
                    "emission-schema-hold",
                    height,
                    err.context(format!(
                        "candidate extrinsic {} singleton emissions",
                        found.details.index()
                    )),
                )
            })?;
            decoded_candidates.push(CandidateTransactionEmissions {
                ledger_tx_hash,
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

/// The network id of the node at `node_http_url` once it has imported block 1, or `None`
/// while it has not. Dials afresh on every call, so a sandbox that is still booting
/// answers with a connection error and the caller keeps polling.
#[cfg(feature = "sandbox")]
pub async fn probe_network_id(node_http_url: &str) -> anyhow::Result<Option<String>> {
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
        ContractStateReply::TooLarge(err) | ContractStateReply::Other(err) => {
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
    if is_oversized_contract_state(error) {
        return false;
    }
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

    async fn finalized_head(&self) -> anyhow::Result<H256> {
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

    async fn header(
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

    async fn block_hash_at(&self, number: u64) -> anyhow::Result<Option<H256>> {
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

    async fn contract_state(
        &self,
        address_64hex: &str,
        at_block_hash_0x: &str,
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
                        rpc_params![address_64hex, at_block_hash_0x],
                    )
                    .await;

                match classify_contract_state_reply(response)? {
                    ContractStateReply::State(state) => Ok(state),
                    ContractStateReply::TooLarge(err) => Err(oversized_contract_state(err)),
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
    use jsonrpsee::server::ServerBuilder;
    use jsonrpsee::types::ErrorObjectOwned;
    use jsonrpsee::RpcModule;
    use serde_json::json;
    use std::io::Write as _;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use subxt::ext::scale_decode::DecodeAsType;
    use subxt::ext::subxt_rpcs::UserError;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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

    fn captured_status_events(
        bytes: Vec<u8>,
        extrinsic: u32,
    ) -> subxt::blocks::ExtrinsicEvents<SubstrateConfig> {
        let metadata = subxt::Metadata::decode_all(
            &mut &include_bytes!("../fixtures/fallible-block-432-metadata.scale")[..],
        )
        .expect("captured node metadata");
        subxt::blocks::ExtrinsicEvents::new(
            H256::zero(),
            extrinsic,
            subxt::events::Events::decode_from(bytes, metadata),
        )
    }

    fn encode_status_records(records: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = subxt::ext::codec::Compact(records.len() as u32).encode();
        for record in records {
            bytes.extend_from_slice(record);
        }
        bytes
    }

    #[test]
    fn full_success_gate_uses_the_captured_extrinsic_status() {
        let raw = include_bytes!("../fixtures/fallible-block-432-events.scale").to_vec();
        let events = captured_status_events(raw.clone(), 4);
        let hash = fully_applied_hash(&events)
            .expect("valid status")
            .expect("TxApplied");
        let tx = decode_applied_transaction(
            include_bytes!("../fixtures/fallible-deposit-tx-432.mn"),
            hash,
        )
        .expect("captured transaction matches status");
        let singleton = crate::test_utils::hex_32(
            "4daa9701226222a9db302dfb6f347f48c947278a4dc93812a79494f4086a0172",
        );
        let calls = emissions_in(&tx, &singleton).expect("successful fallible transcript decodes");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].phase, crate::emissions::TranscriptPhase::Fallible);
        assert_eq!(calls[0].physical_segment, 49592);
        assert_eq!(calls[0].emissions.len(), 1);
        assert_eq!(
            fully_applied_hash(&captured_status_events(raw, 0)).unwrap(),
            None
        );
        let mut wrong_hash = hash;
        wrong_hash[0] ^= 1;
        assert!(decode_applied_transaction(
            include_bytes!("../fixtures/fallible-deposit-tx-432.mn"),
            wrong_hash,
        )
        .unwrap_err()
        .to_string()
        .contains("hash does not match"));
    }

    #[test]
    fn full_success_gate_rejects_partial_and_ambiguous_statuses() {
        let events = captured_status_events(
            include_bytes!("../fixtures/fallible-block-432-events.scale").to_vec(),
            4,
        );
        let applied = events
            .iter()
            .map(Result::unwrap)
            .find(|event| event.as_event::<TxApplied>().unwrap().is_some())
            .expect("capture has TxApplied");
        let mut partial = applied.bytes().to_vec();
        // Synthetic status cases retain the captured producer's SCALE layout:
        // ApplyExtrinsic(u32), Midnight pallet, then its event discriminant.
        assert_eq!(&partial[..7], &[0, 4, 0, 0, 0, 5, 2]);
        partial[6] = 7; // TxPartialSuccess in the captured metadata.
        assert!(
            captured_status_events(encode_status_records(&[partial.clone()]), 4)
                .find_first::<TxPartialSuccess>()
                .unwrap()
                .is_some()
        );
        assert_eq!(
            fully_applied_hash(&captured_status_events(
                encode_status_records(&[partial.clone()]),
                4,
            ))
            .unwrap(),
            None
        );
        assert_eq!(
            fully_applied_hash(&captured_status_events(encode_status_records(&[]), 4,)).unwrap(),
            None
        );
        for records in [
            vec![applied.bytes().to_vec(), partial.clone()],
            vec![applied.bytes().to_vec(), applied.bytes().to_vec()],
            vec![partial.clone(), partial],
        ] {
            assert!(
                fully_applied_hash(&captured_status_events(encode_status_records(&records), 4,))
                    .is_err(),
                "ambiguous outcome must hold"
            );
        }
        assert!(
            fully_applied_hash(&captured_status_events(
                encode_status_records(&[applied.bytes()[..12].to_vec()]),
                4,
            ))
            .is_err(),
            "truncated outcome must hold"
        );
    }

    async fn read_fallible_capture(events: Vec<u8>) -> anyhow::Result<Option<BlockEmissions>> {
        let metadata = subxt::Metadata::decode_all(
            &mut &include_bytes!("../fixtures/fallible-block-432-metadata.scale")[..],
        )?;
        let server = ServerBuilder::default().build("127.0.0.1:0").await?;
        let mut config = http_config(server.local_addr()?);
        config.rpc.retry = attempts(0);
        let transport = connect_http(&config)?;
        // The header and extrinsic wrappers are synthetic, encoded against captured
        // metadata. The ledger transaction and successful events are captured bytes;
        // negative cases alter status records explicitly. This is not an inclusion proof.
        let client = OnlineClient::<SubstrateConfig>::from_rpc_client_with(
            H256([0x11; 32]),
            subxt::client::RuntimeVersion {
                spec_version: 1,
                transaction_version: 1,
            },
            metadata,
            transport.clone(),
        )?;
        let filler = client.tx().create_unsigned(&subxt::dynamic::tx(
            "System",
            "remark",
            vec![subxt::dynamic::Value::from_bytes([])],
        ))?;
        let candidate = client.tx().create_unsigned(&subxt::dynamic::tx(
            "Midnight",
            "send_mn_transaction",
            vec![subxt::dynamic::Value::from_bytes(include_bytes!(
                "../fixtures/fallible-deposit-tx-432.mn"
            ))],
        ))?;
        // Preserve the captured candidate's extrinsic index, including preceding
        // unrelated calls, so status association is exercised by Subxt itself.
        let mut body = vec![format!("0x{}", hex::encode(filler.encoded())); 4];
        body.push(format!("0x{}", hex::encode(candidate.encoded())));
        let header = json!({
            "parentHash": hash_of_byte(0x42),
            "number": "0x1b0",
            "stateRoot": hash_of_byte(0x44),
            "extrinsicsRoot": hash_of_byte(0x45),
            "digest": { "logs": [] }
        });
        let mut module = RpcModule::new(());
        let response_header = header.clone();
        module.register_method("chain_getHeader", move |params, _, _| {
            assert_eq!(params.parse::<Vec<String>>().unwrap(), [hash_of_byte(0x43)]);
            response_header.clone()
        })?;
        module.register_method("chain_getBlock", move |params, _, _| {
            assert_eq!(params.parse::<Vec<String>>().unwrap(), [hash_of_byte(0x43)]);
            json!({ "block": { "header": header, "extrinsics": body }, "justifications": null })
        })?;
        let events_key = client.storage().address_bytes(&subxt::dynamic::storage(
            "System",
            "Events",
            Vec::<subxt::dynamic::Value>::new(),
        ))?;
        module.register_method("state_getStorage", move |params, _, _| {
            assert_eq!(
                params.parse::<Vec<String>>().unwrap(),
                [
                    format!("0x{}", hex::encode(&events_key)),
                    hash_of_byte(0x43)
                ]
            );
            format!("0x{}", hex::encode(&events))
        })?;
        let handle = server.start(module);
        let rpc = MidnightRpc {
            client,
            reads: Reads::new(transport, config.rpc.request_timeout, config.rpc.retry),
        };
        let block = BlockRef {
            number: 432,
            hash: hash_of_byte(0x43),
            parent_hash: hash_of_byte(0x42),
        };
        let singleton = crate::test_utils::hex_32(
            "4daa9701226222a9db302dfb6f347f48c947278a4dc93812a79494f4086a0172",
        );
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            rpc.block_emissions(&block, &singleton),
        )
        .await;
        handle.stop()?;
        handle.stopped().await;
        result.context("block reader timed out")?
    }

    #[tokio::test]
    async fn block_reader_extracts_captured_applied_fallible_notification() {
        let events = include_bytes!("../fixtures/fallible-block-432-events.scale").to_vec();
        let block = read_fallible_capture(events.clone())
            .await
            .expect("read captured fallible transaction")
            .expect("block contains a singleton candidate");
        assert_eq!(block.proof_seed.reported_block_number, 432);
        assert_eq!(block.proof_seed.reported_block_hash, [0x43; 32]);
        assert_eq!(block.proof_seed.scale_body.len(), 5);
        assert_eq!(block.proof_seed.scale_system_events, events);
        assert_eq!(block.candidates.len(), 1);
        let candidate = &block.candidates[0];
        assert_eq!(candidate.extrinsic_index, 4);
        assert_eq!(
            candidate.ledger_tx_hash,
            crate::test_utils::hex_32(
                "ba41ac43f2cfa97e32357877b85210a7f2105f4930b60515e19aa9ec00bb0f5d"
            )
        );
        assert_eq!(candidate.calls.len(), 1);
        let call = &candidate.calls[0];
        assert_eq!(call.call_index, 1);
        assert_eq!(call.physical_segment, 49592);
        assert_eq!(call.phase, crate::emissions::TranscriptPhase::Fallible);
        assert_eq!(call.emissions.len(), 1);
        assert_eq!(
            call.emissions[0].kind,
            crate::emissions::EmissionKind::SignBidirectional
        );
        assert_eq!(
            call.emissions[0].payload[1..33],
            crate::test_utils::hex_32(
                "ee3385dda706877d30e802a0df57c228310016889104b8fb361c830a58d1e500"
            )
        );
    }

    fn captured_applied_status_record() -> Vec<u8> {
        captured_status_events(
            include_bytes!("../fixtures/fallible-block-432-events.scale").to_vec(),
            4,
        )
        .iter()
        .map(Result::unwrap)
        .find(|event| event.as_event::<TxApplied>().unwrap().is_some())
        .expect("captured applied status")
        .bytes()
        .to_vec()
    }

    #[tokio::test]
    async fn block_reader_skips_partial_success_and_other_extrinsics_statuses() {
        let applied = captured_applied_status_record();
        assert_eq!(&applied[..7], &[0, 4, 0, 0, 0, 5, 2]);
        let mut partial = applied.clone();
        partial[6] = 7; // TxPartialSuccess in the captured metadata.
        let mut other_extrinsic = applied;
        other_extrinsic[1..5].copy_from_slice(&0u32.to_le_bytes());
        for records in [vec![partial.clone()], vec![other_extrinsic, partial]] {
            let block = read_fallible_capture(encode_status_records(&records))
                .await
                .expect("unsupported outcome is skipped")
                .expect("candidate is present in the block body");
            assert!(block.candidates.is_empty());
        }
    }

    #[tokio::test]
    async fn block_reader_holds_when_applied_hash_does_not_match_transaction() {
        let mut applied = captured_applied_status_record();
        assert_eq!(&applied[..7], &[0, 4, 0, 0, 0, 5, 2]);
        applied[7] ^= 1; // First byte of TxAppliedDetails.tx_hash.
        let err = read_fallible_capture(encode_status_records(&[applied]))
            .await
            .expect_err("a different transaction's status must hold the block");
        let hold = err.downcast_ref::<BlockHold>().expect("typed block hold");
        assert_eq!(hold.height, 432);
        assert_eq!(hold.reason, "singleton-tx-undecodable");
        assert!(format!("{:#}", hold.cause).contains("hash does not match"));
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
    #[ignore = "capture tool: MIDNIGHT_NODE_URL, MIDNIGHT_CAPTURE_BLOCK, MIDNIGHT_CAPTURE_SINGLETON, MIDNIGHT_CAPTURE_OUT_DIR"]
    async fn capture_block_fixtures() {
        let node_url = std::env::var("MIDNIGHT_NODE_URL")
            .expect("MIDNIGHT_NODE_URL must name the capture node HTTP endpoint");
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
            node_url,
            central_address: crate::config::MidnightAddress::from_bytes(singleton),
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
            let TxApplied(details) =
                applied.expect("capture candidate must have a supported TxApplied status");
            let status = "TxApplied";
            let status_hash = details.tx_hash;
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

            write_new_capture(&caller_path, &caller_state)
                .expect("create new caller state fixture without replacing an existing capture");

            println!(
                "capture block={height} caller_state={}",
                caller_path.display()
            );
        }
    }

    fn http_config(address: SocketAddr) -> crate::config::MidnightConfig {
        crate::config::MidnightConfig {
            node_url: format!("http://{address}"),
            central_address: crate::config::MidnightAddress::from_bytes([0xab; 32]),
            publisher: Default::default(),
            rpc: Default::default(),
            indexer: Default::default(),
        }
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
            (403, "Forbidden", 1),
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

        let rpc = connect_http(&http_config(address)).expect("build HTTP transport");
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
        let timeout_rpc = connect_http(&timeout_config).expect("build timeout transport");
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
        let capped_rpc = connect_http(&capped_config).expect("build capped transport");
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
            central_address: crate::config::MidnightAddress::from_bytes([0xab; 32]),
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

    #[derive(Clone, Copy)]
    enum Canned {
        User(i32, &'static str),
        UserWithData(i32, &'static str, &'static str),
        ClientErr,
    }

    impl Canned {
        fn into_error(self) -> RawRpcError {
            match self {
                Self::User(code, message) => RawRpcError::User(UserError {
                    code,
                    message: message.to_string(),
                    data: None,
                }),
                Self::UserWithData(code, message, data) => RawRpcError::User(UserError {
                    code,
                    message: message.to_string(),
                    data: Some(
                        RawValue::from_string(data.to_string())
                            .expect("canned user-error data is JSON"),
                    ),
                }),
                Self::ClientErr => RawRpcError::Client(Box::new(JsonrpseeClientError::Transport(
                    "connection reset by peer".into(),
                ))),
            }
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

    #[derive(Clone)]
    struct StubRpc {
        reply: Canned,
        calls: Arc<AtomicUsize>,
    }

    impl RpcClientT for StubRpc {
        fn request_raw<'a>(
            &'a self,
            method: &'a str,
            _params: Option<Box<RawValue>>,
        ) -> RawRpcFuture<'a, Box<RawValue>> {
            assert_eq!(method, "midnight_contractState");
            self.calls.fetch_add(1, Ordering::SeqCst);
            let reply = self.reply;
            Box::pin(async move { Err(reply.into_error()) })
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

    fn stub_rpc(reply: Canned) -> (RpcClient, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let node = StubRpc {
            reply,
            calls: calls.clone(),
        };
        (RpcClient::new(node), calls)
    }

    fn stub_reads(reply: Canned, retry: RetryConfig) -> (Reads, Arc<AtomicUsize>) {
        let (rpc, calls) = stub_rpc(reply);
        (Reads::new(rpc, READ_TIMEOUT, retry), calls)
    }

    #[tokio::test]
    async fn contract_state_reply_policy_is_typed_and_budgeted() {
        const DATA: &str = r#"{"detail":"recover me"}"#;
        let (publisher_rpc, _) = stub_rpc(Canned::UserWithData(
            INVALID_PARAMS_CODE,
            UNSERVABLE_MSG,
            DATA,
        ));
        let publisher_error = publisher_contract_state(&publisher_rpc, ADDRESS, AT_HASH)
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
                .contract_state(ADDRESS, AT_HASH)
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
            (
                Canned::UserWithData(
                    OVERSIZED_RESPONSE_CODE,
                    "state exceeds the response limit",
                    DATA,
                ),
                true,
                1,
            ),
            (Canned::UserWithData(12345, STATE_TOO_LARGE, DATA), false, 3),
            (Canned::ClientErr, false, 3),
        ] {
            let (reads, calls) = stub_reads(reply, attempts(2));
            let err = reads
                .contract_state(ADDRESS, AT_HASH)
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
                (Canned::ClientErr, RawRpcError::Client(_)) => {}
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
