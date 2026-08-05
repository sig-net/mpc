//! Midnight node RPC: the read transport everything in the read path goes through.

use std::time::{Duration, Instant};

use anyhow::Context as _;
use futures_util::{Stream, StreamExt};
use mpc_chain_integration_core::utils::retry::{retry_rpc, RetryConfig};
use mpc_chain_integration_core::utils::task::AbortOnDrop;
use subxt::backend::legacy::rpc_methods::NumberOrHex;
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::client::OnlineClient;
use subxt::ext::jsonrpsee::client_transport::ws::{Url as WsUrl, WsTransportClientBuilder};
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
    legacy: LegacyRpcMethods<SubstrateConfig>,
    rpc: RpcClient,
    connect_timeout: Duration,
    request_timeout: Duration,
    stall_timeout: Duration,
    /// Retry budget for the one-shot reads.
    retry: RetryConfig,
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
                    .max_buffer_capacity_per_subscription(4096)
                    .build_with_tokio(sender, receiver),
            )
        })
        .await
        .context("timed out connecting to the midnight node rpc")??;
        let rpc = RpcClient::new(ws_client);
        let client = tokio::time::timeout(
            connect_timeout,
            OnlineClient::<SubstrateConfig>::from_rpc_client(rpc.clone()),
        )
        .await
        .context("timed out initialising the midnight subxt client")?
        .context("failed to initialise the midnight subxt client")?;
        let legacy = LegacyRpcMethods::<SubstrateConfig>::new(rpc.clone());

        Ok(Self {
            _runtime_updater: spawn_runtime_updater(client.clone()),
            client,
            legacy,
            rpc,
            connect_timeout,
            request_timeout: config.rpc.request_timeout,
            stall_timeout: config.indexer.stall_timeout,
            retry: config.rpc.retry,
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

    /// The node's current finalized head hash.
    pub async fn finalized_head(&self) -> anyhow::Result<H256> {
        retry_rpc!(
            self.request_timeout,
            self.retry,
            "midnight_finalized_head",
            {
                self.legacy
                    .chain_get_finalized_head()
                    .await
                    .context("failed to fetch the midnight finalized head")
            }
        )
    }

    /// Raw contract state of `address_64hex` (64 hex chars, no `0x`) at
    /// `at_block_hash_0x` (`0x`-prefixed), via the `midnight_contractState` JSON-RPC.
    pub async fn contract_state(
        &self,
        address_64hex: &str,
        at_block_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        contract_state_with(
            &self.rpc,
            self.request_timeout,
            self.retry,
            address_64hex,
            at_block_hash_0x,
        )
        .await
    }

    /// The finalized head as a [`BlockRef`]: the head hash, then its header for the
    /// number and parent, each read on the ordinary retry budget.
    pub async fn finalized_block_ref(&self) -> anyhow::Result<BlockRef> {
        let hash = self.finalized_head().await?;
        let header = retry_rpc!(self.request_timeout, self.retry, "midnight_head_header", {
            self.legacy
                .chain_get_header(Some(hash))
                .await
                .context("failed to fetch the finalized head header")
        })?
        .context("midnight node returned no header for its own finalized head")?;
        Ok(BlockRef {
            number: u64::from(header.number),
            hash: hex_0x(hash),
            parent_hash: hex_0x(header.parent_hash),
        })
    }

    /// The block at `number` as a [`BlockRef`], for the catchup range walk.
    pub async fn block_ref_at(&self, number: u64) -> anyhow::Result<BlockRef> {
        let hash = retry_rpc!(
            self.request_timeout,
            self.retry,
            "midnight_block_hash_at",
            {
                self.legacy
                    .chain_get_block_hash(Some(NumberOrHex::Number(number)))
                    .await
                    .context("failed to fetch a block hash by number")
            }
        )?
        .with_context(|| format!("midnight node has no block hash for height {number}"))?;
        let header = retry_rpc!(self.request_timeout, self.retry, "midnight_header_at", {
            self.legacy
                .chain_get_header(Some(hash))
                .await
                .context("failed to fetch a block header")
        })?
        .with_context(|| format!("midnight node has no header for height {number}"))?;
        Ok(BlockRef {
            number: u64::from(header.number),
            hash: hex_0x(hash),
            parent_hash: hex_0x(header.parent_hash),
        })
    }
}

/// [`MidnightRpc::contract_state`] over explicit transports, so its offline tests can
/// run it without an `OnlineClient`, whose construction fetches metadata and therefore
/// needs a whole node.
async fn contract_state_with(
    rpc: &RpcClient,
    request_timeout: Duration,
    retry: RetryConfig,
    address_64hex: &str,
    at_block_hash_0x: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    /// A definitive outcome no retry changes; routed through `Ok` so the budget is
    /// spent only on transport faults and pruned-or-unknown responses.
    enum Fetched {
        State(Option<Vec<u8>>),
        TooLarge(String),
        ClientClosed(String),
    }

    let fetched = retry_rpc!(request_timeout, retry, "midnight_contractState", {
        let response: Result<String, _> = rpc
            .request(
                "midnight_contractState",
                rpc_params![address_64hex, at_block_hash_0x],
            )
            .await;

        match response {
            Ok(state_hex) => {
                let state = hex::decode(state_hex.trim_start_matches("0x"))
                    .context("midnight_contractState returned non-hex state")?;
                Ok(Fetched::State(Some(state)))
            }
            // The node builds every rpc error as invalid-params with the reason only
            // in the text, so its two answers stay text matches under the code gate.
            Err(RawRpcError::User(reply))
                if reply.code == INVALID_PARAMS_CODE
                    && reply.message.contains("Contract not present") =>
            {
                Ok(Fetched::State(None))
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
            // subxt boxes the concrete jsonrpsee failure, which makes the downcast sound.
            Err(RawRpcError::Client(client_err))
                if matches!(
                    client_err.downcast_ref::<JsonrpseeClientError>(),
                    Some(JsonrpseeClientError::RestartNeeded(_))
                ) =>
            {
                Ok(Fetched::ClientClosed(client_err.to_string()))
            }
            Err(err) => Err(anyhow::Error::new(err).context("midnight_contractState failed")),
        }
    })?;
    match fetched {
        Fetched::State(state) => Ok(state),
        Fetched::TooLarge(detail) => Err(ReadFailure::TooLarge.err(detail)),
        Fetched::ClientClosed(detail) => Err(ReadFailure::ClientClosed.err(detail)),
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
            rpc: Default::default(),
            indexer: Default::default(),
        };
        let rpc = MidnightRpc::connect(&config).await.expect("connect");

        let head = rpc.finalized_head().await.expect("finalized head");
        assert_ne!(head, subxt::utils::H256::zero());

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
        let rpc = RpcClient::new(node.clone());
        let err = contract_state_with(&rpc, READ_TIMEOUT, attempts(2), ADDRESS, AT_HASH)
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
        let rpc = RpcClient::new(node.clone());
        let err = contract_state_with(&rpc, READ_TIMEOUT, attempts(2), ADDRESS, AT_HASH)
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
            let rpc = RpcClient::new(node.clone());
            let err = contract_state_with(&rpc, READ_TIMEOUT, attempts(2), ADDRESS, AT_HASH)
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
        let rpc = RpcClient::new(node.clone());
        let err = contract_state_with(&rpc, READ_TIMEOUT, attempts(2), ADDRESS, AT_HASH)
            .await
            .expect_err("a transport fault is a failure");
        assert_eq!(ReadFailure::of(&err), None, "{err:#}");
        assert_eq!(node.calls_to("midnight_contractState").len(), 3);
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
        let rpc = RpcClient::new(node.clone());
        let absent = contract_state_with(&rpc, READ_TIMEOUT, attempts(2), ADDRESS, AT_HASH)
            .await
            .expect("contract-not-present is an answer, not a failure");
        assert_eq!(absent, None);
        assert_eq!(node.calls_to("midnight_contractState").len(), 1);

        let node = StubNode::new(vec![(
            "midnight_contractState",
            vec![Canned::User(INVALID_PARAMS_CODE, UNSERVABLE_MSG)],
        )]);
        let rpc = RpcClient::new(node.clone());
        let err = contract_state_with(&rpc, READ_TIMEOUT, attempts(2), ADDRESS, AT_HASH)
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
