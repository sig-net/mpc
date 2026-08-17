//! Midnight node RPC: the read transport everything in the read path goes through.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use futures_util::{Stream, StreamExt};
use mpc_chain_integration_core::utils::retry::{retry_rpc, RetryConfig};
use mpc_utils::task::AbortOnDrop;
use subxt::backend::legacy::rpc_methods::NumberOrHex;
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::client::OnlineClient;
use subxt::ext::jsonrpsee::client_transport::ws::{Url as WsUrl, WsTransportClientBuilder};
use subxt::ext::jsonrpsee::core::client::async_client::PingConfig;
use subxt::ext::jsonrpsee::core::client::{Client as RawWsClient, Error as JsonrpseeClientError};
use subxt::ext::jsonrpsee::types::error::{INVALID_PARAMS_CODE, OVERSIZED_RESPONSE_CODE};
use subxt::ext::subxt_rpcs::{rpc_params, Error as RawRpcError};
use subxt::utils::H256;
use subxt::SubstrateConfig;

use crate::config::MidnightConfig;

const WATCHDOG_TICK: Duration = Duration::from_secs(5);

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

pub struct MidnightRpc {
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
        let client = tokio::time::timeout(
            connect_timeout,
            OnlineClient::<SubstrateConfig>::from_rpc_client(rpc.clone()),
        )
        .await
        .context("timed out initialising the midnight subxt client")?
        .context("failed to initialise the midnight subxt client")?;
        // `is_connected` is the liveness answer catching dead-client shapes
        // the error types hide.
        let alive: Liveness = Arc::new(move || ws.is_connected());

        Ok(Self {
            _runtime_updater: spawn_runtime_updater(client.clone()),
            client,
            reads: Reads::new(rpc, config.rpc.request_timeout, config.rpc.retry, alive),
            connect_timeout,
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
    let updater = client.updater();
    AbortOnDrop(tokio::spawn(async move {
        if let Err(err) = updater.perform_runtime_updates().await {
            tracing::error!("midnight runtime updater stopped: {err}");
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use subxt::backend::rpc::{RawRpcFuture, RawRpcSubscription, RawValue, RpcClientT};
    use subxt::ext::subxt_rpcs::UserError;

    #[tokio::test]
    #[ignore = "requires a local midnight node"]
    async fn live_finalized_subscription_yields_a_block() {
        use futures_util::StreamExt as _;

        let config = crate::config::MidnightConfig {
            node_ws_url: "ws://127.0.0.1:9944".to_string(),
            central_address: "ab".repeat(32),
            publisher: None,
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

    /// One canned reply for a stubbed JSON-RPC method: a JSON-RPC error response as
    /// the node sends it, or the two client-side failure shapes subxt boxes.
    #[derive(Clone)]
    enum Canned {
        User(i32, &'static str),
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
                Err(match canned {
                    Canned::User(code, message) => RawRpcError::User(UserError {
                        code,
                        message: message.to_string(),
                        data: None,
                    }),
                    Canned::ClientDead => RawRpcError::Client(Box::new(
                        JsonrpseeClientError::RestartNeeded(std::sync::Arc::new(
                            JsonrpseeClientError::Transport("stub ws died".into()),
                        )),
                    )),
                    Canned::ClientErr => RawRpcError::Client(Box::new(
                        JsonrpseeClientError::Transport("connection reset by peer".into()),
                    )),
                })
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
}
