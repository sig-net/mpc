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
use subxt::ext::codec::{Compact, Decode};
use subxt::ext::subxt_rpcs::rpc_params;
use subxt::utils::H256;
use subxt::SubstrateConfig;

use crate::config::MidnightConfig;

const MIDNIGHT_PALLET: &str = "midnight";
const SEND_MN_TRANSACTION: &str = "send_mn_transaction";

const WATCHDOG_TICK: Duration = Duration::from_secs(5);

/// The pruned-or-unknown-hash failure message for `midnight_contractState`.
pub(crate) const STATE_UNSERVABLE_MSG: &str =
    "midnight node cannot serve contract state at that block (pruned or unknown hash)";

/// All-zero placeholder address for the archive probe: the probe asks whether the node
/// can ANSWER a state query at an old block, not about any real contract, so "contract
/// not present" is as much positive evidence as served state bytes.
const PROBE_ADDRESS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What the startup probe concluded about the node's state retention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveState {
    /// Contract state at `head - archive_probe_window` was reachable.
    Archive,
    /// The node could not serve state at `probed_height`, a finalized ancestor whose
    /// hash the node itself supplied: the pruning signature.
    Pruned { probed_height: u64 },
}

/// A finalized block, wrapping the subxt handle so extrinsics can be fetched lazily.
pub struct FinalizedBlock {
    block: subxt::blocks::Block<SubstrateConfig, OnlineClient<SubstrateConfig>>,
}

impl FinalizedBlock {
    pub fn block_ref(&self) -> BlockRef {
        BlockRef {
            number: u64::from(self.block.number()),
            hash: hex_0x(self.block.hash()),
            parent_hash: hex_0x(self.block.header().parent_hash),
        }
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

fn hex_0x(hash: H256) -> String {
    format!("0x{}", hex::encode(hash.as_bytes()))
}

/// True when `err` carries `contract_state`'s pruned-or-unknown-hash mapping (the
/// outermost context survives `retry_rpc!`'s flattening, per the note on
/// [`STATE_UNSERVABLE_MSG`]).
pub(crate) fn is_state_unservable(err: &anyhow::Error) -> bool {
    err.to_string().contains(STATE_UNSERVABLE_MSG)
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

        let rpc = tokio::time::timeout(connect_timeout, RpcClient::from_url(url))
            .await
            .context("timed out connecting to the midnight node rpc")?
            .context("failed to connect to the midnight node rpc")?;
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
    ) -> anyhow::Result<impl Stream<Item = FinalizedBlock> + Send + Unpin + 'static> {
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
                                return Some((FinalizedBlock { block }, (sub, Instant::now())));
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
        contract_state_over(
            &self.rpc,
            self.request_timeout,
            self.retry,
            address_64hex,
            at_block_hash_0x,
        )
        .await
    }

    /// Probes whether the node retains contract state `window` blocks behind the
    /// finalized head, classifying it [`ArchiveState::Archive`] or
    /// [`ArchiveState::Pruned`].
    pub async fn probe_archive_state(&self, window: u64) -> anyhow::Result<ArchiveState> {
        probe_archive_state_over(
            &self.legacy,
            &self.rpc,
            self.request_timeout,
            self.retry,
            window,
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

    /// Every `send_mn_transaction` blob in the block named by `hash_0x`, for blocks
    /// reached by hash rather than through the live stream.
    pub async fn send_mn_transaction_bytes_at(
        &self,
        hash_0x: &str,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let bytes: [u8; 32] = hex::decode(hash_0x.trim_start_matches("0x"))
            .context("block hash is not hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("block hash is not 32 bytes"))?;
        let block = retry_rpc!(
            self.request_timeout,
            self.retry,
            "midnight_block_at_hash",
            {
                self.client
                    .blocks()
                    .at(H256::from(bytes))
                    .await
                    .context("failed to fetch a finalized block by hash")
            }
        )?;
        self.send_mn_transaction_bytes(&FinalizedBlock { block })
            .await
    }

    /// Every `midnight::send_mn_transaction` blob in `block`, in extrinsic order:
    /// `args[0]` with its SCALE compact length prefix stripped.
    pub async fn send_mn_transaction_bytes(
        &self,
        block: &FinalizedBlock,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let extrinsics = retry_rpc!(
            self.request_timeout,
            self.retry,
            "midnight_block_extrinsics",
            {
                block
                    .block
                    .extrinsics()
                    .await
                    .context("failed to fetch extrinsics for a finalized midnight block")
            }
        )?;
        let mut blobs = Vec::new();
        for extrinsic in extrinsics.iter() {
            if let Some(blob) = extract_send_mn_transaction(
                extrinsic.pallet_name().context("extrinsic pallet name")?,
                extrinsic.variant_name().context("extrinsic variant name")?,
                extrinsic.field_bytes(),
            )? {
                blobs.push(blob);
            }
        }
        Ok(blobs)
    }
}

/// [`MidnightRpc::contract_state`] over explicit transports, so the archive probe, and
/// its offline tests, can run it without an `OnlineClient`, whose construction fetches
/// metadata and therefore needs a whole node.
async fn contract_state_over(
    rpc: &RpcClient,
    request_timeout: Duration,
    retry: RetryConfig,
    address_64hex: &str,
    at_block_hash_0x: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    // The error mapping lives INSIDE the retried operation so that the definitive
    // answers (state bytes, contract not present) return Ok and are never retried,
    // while transport faults and pruned-or-unknown responses surface as Err and consume
    // the retry budget.
    retry_rpc!(request_timeout, retry, "midnight_contractState", {
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
                Ok(Some(state))
            }
            Err(err) => {
                // Both error shapes arrive as -32602 invalid-params and are
                // distinguishable only by message, so match the node's own strings.
                let message = err.to_string();
                if message.contains("Contract not present") {
                    Ok(None)
                } else if message.contains("Unable to get requested contract state") {
                    Err(anyhow::Error::new(err).context(STATE_UNSERVABLE_MSG))
                } else {
                    Err(anyhow::Error::new(err).context("midnight_contractState failed"))
                }
            }
        }
    })
}

/// [`MidnightRpc::probe_archive_state`] over explicit transports: the probe needs only
/// legacy chain calls and the raw client, so tests drive it through an in-process
/// [`subxt::backend::rpc::RpcClientT`] stub.
async fn probe_archive_state_over(
    legacy: &LegacyRpcMethods<SubstrateConfig>,
    rpc: &RpcClient,
    request_timeout: Duration,
    retry: RetryConfig,
    window: u64,
) -> anyhow::Result<ArchiveState> {
    // Every read here rides the ordinary retry_rpc budget ONCE; the probe adds no loop
    // of its own.
    let head_hash = retry_rpc!(request_timeout, retry, "midnight_probe_finalized_head", {
        legacy
            .chain_get_finalized_head()
            .await
            .context("archive probe: failed to fetch the finalized head")
    })?;
    let header = retry_rpc!(request_timeout, retry, "midnight_probe_head_header", {
        legacy
            .chain_get_header(Some(head_hash))
            .await
            .context("archive probe: failed to fetch the finalized head header")
    })?
    .context("midnight node returned no header for its own finalized head")?;
    let head_height = u64::from(header.number);

    let probed_height = head_height.saturating_sub(window).max(1);
    let probed_hash = retry_rpc!(request_timeout, retry, "midnight_probe_block_hash", {
        legacy
            .chain_get_block_hash(Some(NumberOrHex::Number(probed_height)))
            .await
            .context("archive probe: failed to fetch the probed block hash")
    })?
    .with_context(|| {
        format!("midnight node has no block hash for finalized ancestor {probed_height}")
    })?;

    let at_hash = format!("0x{}", hex::encode(probed_hash.as_bytes()));
    match contract_state_over(rpc, request_timeout, retry, PROBE_ADDRESS, &at_hash).await {
        // Served state and contract-not-present both mean the node reached the state at
        // the probed block and searched it: positive evidence.
        Ok(_) => Ok(ArchiveState::Archive),
        Err(err) if err.to_string().contains(STATE_UNSERVABLE_MSG) => {
            Ok(ArchiveState::Pruned { probed_height })
        }
        Err(err) => Err(err.context(format!(
            "archive probe could not classify the node at height {probed_height}"
        ))),
    }
}

/// The pure filter-and-decode step for one extrinsic: `Some(blob)` iff `(pallet,
/// variant)` is exactly `midnight::send_mn_transaction`, where the blob is `args[0]`
/// with the SCALE compact length prefix stripped and checked against the remainder.
fn extract_send_mn_transaction(
    pallet: &str,
    variant: &str,
    field_bytes: &[u8],
) -> anyhow::Result<Option<Vec<u8>>> {
    if pallet != MIDNIGHT_PALLET || variant != SEND_MN_TRANSACTION {
        return Ok(None);
    }
    let mut rest = field_bytes;
    let Compact(declared_len) = Compact::<u32>::decode(&mut rest)
        .context("send_mn_transaction args[0] has a malformed compact length prefix")?;
    anyhow::ensure!(
        rest.len() as u64 == u64::from(declared_len),
        "send_mn_transaction args[0] declares {declared_len} bytes but {} follow",
        rest.len()
    );
    Ok(Some(rest.to_vec()))
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
    use subxt::ext::codec::{Compact, Encode};
    use subxt::ext::subxt_rpcs::{Error as RawRpcError, UserError};

    const TAG: &[u8] = b"midnight:transaction[v12]";

    /// SCALE-encode a `Vec<u8>` call argument: compact length, then bytes.
    fn scale_vec(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Compact(payload.len() as u32).encode();
        bytes.extend_from_slice(payload);
        bytes
    }

    fn tagged_blob(extra: &[u8]) -> Vec<u8> {
        let mut blob = TAG.to_vec();
        blob.extend_from_slice(extra);
        blob
    }

    #[test]
    fn extract_send_mn_transaction_filters_by_pallet_and_call() {
        let blob = tagged_blob(&[0xaa; 7]);
        let field_bytes = scale_vec(&blob);

        let extracted =
            extract_send_mn_transaction("midnight", "send_mn_transaction", &field_bytes)
                .expect("well-formed args decode")
                .expect("matching extrinsic extracts");
        assert_eq!(extracted, blob);
        assert!(
            extracted.starts_with(TAG),
            "args[0] must lead with the ASCII transaction tag"
        );

        // The same call name under another pallet must not match, the same pallet with
        // another call must not match, and matching is exact, never case-insensitive.
        for (pallet, variant) in [
            ("system", "send_mn_transaction"),
            ("midnight", "remark"),
            ("Midnight", "send_mn_transaction"),
            ("midnight", "Send_mn_transaction"),
        ] {
            assert!(
                extract_send_mn_transaction(pallet, variant, &field_bytes)
                    .expect("well-formed args decode")
                    .is_none(),
                "{pallet}::{variant} must not match"
            );
        }
    }

    #[test]
    fn extract_send_mn_transaction_strips_compact_length_prefix() {
        // Single-byte mode, hand-built rather than codec-built so at least one raw
        // prefix byte is pinned non-circularly: compact(5) is one byte, 5 << 2 = 0x14.
        let mut short = vec![0x14];
        short.extend_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(
            extract_send_mn_transaction("midnight", "send_mn_transaction", &short)
                .unwrap()
                .unwrap(),
            [1, 2, 3, 4, 5],
        );

        // Two-byte mode via the codec: a 300-byte payload needs the 0b01 prefix form,
        // so this pins that the strip is mode-aware rather than always dropping one
        // byte.
        let long_blob = tagged_blob(&[0xbb; 300 - TAG.len()]);
        let field_bytes = scale_vec(&long_blob);
        assert_eq!(
            field_bytes.len(),
            2 + long_blob.len(),
            "a 300-byte payload takes the two-byte compact form"
        );
        assert_eq!(
            extract_send_mn_transaction("midnight", "send_mn_transaction", &field_bytes)
                .unwrap()
                .unwrap(),
            long_blob,
        );
    }

    #[test]
    fn extract_send_mn_transaction_errors_on_malformed_args() {
        // A matching extrinsic whose args do not decode must error, never be silently
        // skipped: skipping would drop a real transaction blob.
        assert!(
            extract_send_mn_transaction("midnight", "send_mn_transaction", &[]).is_err(),
            "empty args have no compact prefix to read"
        );

        let mut lying = Compact(10u32).encode();
        lying.extend_from_slice(&[1, 2, 3]);
        assert!(
            extract_send_mn_transaction("midnight", "send_mn_transaction", &lying).is_err(),
            "declared length exceeding the remainder must error"
        );

        let mut trailing = scale_vec(&[1, 2, 3]);
        trailing.push(9);
        assert!(
            extract_send_mn_transaction("midnight", "send_mn_transaction", &trailing).is_err(),
            "trailing bytes beyond the declared length must error"
        );
    }

    #[tokio::test]
    #[ignore = "requires a local midnight node"]
    async fn live_finalized_subscription_extracts_transactions() {
        use futures_util::StreamExt as _;

        let config = crate::config::MidnightConfig {
            sidecar_url: "http://127.0.0.1:8790".to_string(),
            node_ws_url: "ws://127.0.0.1:9944".to_string(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".to_string(),
            rpc: Default::default(),
            sidecar: Default::default(),
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

        // Probe classification against a real node: both -32602 message strings and the
        // success shape are transcribed offline, and this is the one place that checks
        // them live.
        let archive_state = rpc
            .probe_archive_state(config.indexer.archive_probe_window)
            .await
            .expect("the probe must classify a live node, whichever way");
        tracing::debug!(?archive_state, "live archive probe");

        let blobs = rpc
            .send_mn_transaction_bytes(&block)
            .await
            .expect("extrinsics fetch");
        // An idle block is legal; when a ledger transaction is present it must lead
        // with the version tag.
        if let Some(first) = blobs.first() {
            assert!(first.starts_with(TAG));
        }
    }

    // Archive-state probe over an in-process JSON-RPC stub.

    /// One canned reply for a stubbed JSON-RPC method.
    #[derive(Clone)]
    enum Canned {
        /// Raw JSON of a successful `result` field (already quoted if a string).
        Json(String),
        /// A JSON-RPC error response: code and message, as the node sends them.
        NodeError(i32, &'static str),
        /// A transport-level fault (connection trouble), retryable by default.
        Transport(&'static str),
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
                    Canned::Json(raw) => {
                        Ok(RawValue::from_string(raw).expect("canned json is valid"))
                    }
                    Canned::NodeError(code, message) => Err(RawRpcError::User(UserError {
                        code,
                        message: message.to_string(),
                        data: None,
                    })),
                    Canned::Transport(message) => {
                        Err(RawRpcError::Client(message.to_string().into()))
                    }
                }
            })
        }

        fn subscribe_raw<'a>(
            &'a self,
            _sub: &'a str,
            _params: Option<Box<RawValue>>,
            _unsub: &'a str,
        ) -> RawRpcFuture<'a, RawRpcSubscription> {
            Box::pin(async { panic!("the archive probe never subscribes") })
        }
    }

    const HEAD_HASH_HEX: &str =
        "0x1111111111111111111111111111111111111111111111111111111111111111";
    const PROBED_HASH_HEX: &str =
        "0x5555555555555555555555555555555555555555555555555555555555555555";
    const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
    const NOT_PRESENT_MSG: &str = "Contract not present at the requested address";
    const UNSERVABLE_MSG: &str = "Unable to get requested contract state";

    fn json_str(value: &str) -> Canned {
        Canned::Json(format!("\"{value}\""))
    }

    /// A finalized header whose only load-bearing field is `number`.
    fn head_header(number_hex: &str) -> Canned {
        Canned::Json(format!(
            r#"{{"parentHash":"0x{filler}","number":"{number_hex}","stateRoot":"0x{filler}","extrinsicsRoot":"0x{filler}","digest":{{"logs":[]}}}}"#,
            filler = "22".repeat(32),
        ))
    }

    /// The standard healthy-chain reply set: finalized head, its header at
    /// `head_number_hex`, one hash for whatever height gets asked, and the given
    /// `midnight_contractState` reply.
    fn probe_replies(
        head_number_hex: &str,
        contract_state: Canned,
    ) -> Vec<(&'static str, Vec<Canned>)> {
        vec![
            ("chain_getFinalizedHead", vec![json_str(HEAD_HASH_HEX)]),
            ("chain_getHeader", vec![head_header(head_number_hex)]),
            ("chain_getBlockHash", vec![json_str(PROBED_HASH_HEX)]),
            ("midnight_contractState", vec![contract_state]),
        ]
    }

    fn probe_harness(node: &StubNode) -> (LegacyRpcMethods<SubstrateConfig>, RpcClient) {
        let rpc = RpcClient::new(node.clone());
        (LegacyRpcMethods::<SubstrateConfig>::new(rpc.clone()), rpc)
    }

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
    async fn probe_archive_state_detects_archive_node() {
        // "Contract not present at the requested address" is POSITIVE evidence: the
        // node reached the state at head - window and looked for the throwaway probe
        // address.
        let node = StubNode::new(probe_replies(
            "0x400", // head at 1024
            Canned::NodeError(-32602, NOT_PRESENT_MSG),
        ));
        let (legacy, rpc) = probe_harness(&node);

        let state = probe_archive_state_over(&legacy, &rpc, PROBE_TIMEOUT, attempts(0), 100)
            .await
            .expect("a contract-not-present reply classifies cleanly");
        assert_eq!(state, ArchiveState::Archive);

        // The walk-back is pinned at the wire: head 1024, window 100, so the hash
        // request must name height 924 and the state read must use the returned hash,
        // never the head's own.
        assert_eq!(
            node.calls_to("chain_getBlockHash"),
            vec!["[924]".to_string()]
        );
        assert_eq!(
            node.calls_to("midnight_contractState"),
            vec![format!("[\"{PROBE_ADDRESS}\",\"{PROBED_HASH_HEX}\"]")],
        );
    }

    #[tokio::test]
    async fn probe_archive_state_detects_archive_node_serving_state() {
        // Some contract DOES live at the probed address: served state bytes are the
        // other face of positive evidence.
        let node = StubNode::new(probe_replies("0x400", json_str("0x0104")));
        let (legacy, rpc) = probe_harness(&node);

        let state = probe_archive_state_over(&legacy, &rpc, PROBE_TIMEOUT, attempts(0), 100)
            .await
            .expect("served state classifies cleanly");
        assert_eq!(state, ArchiveState::Archive);
    }

    #[tokio::test]
    async fn probe_archive_state_errors_on_unknown_error() {
        // Anything that is neither shape must PROPAGATE: calling an unknown fault
        // "pruned" would silently degrade catchup on a misconfigured endpoint, and
        // calling it "archive" would be worse.
        let node = StubNode::new(probe_replies(
            "0x400",
            Canned::NodeError(-32000, "Internal error: storage backend fault"),
        ));
        let (legacy, rpc) = probe_harness(&node);

        let err = probe_archive_state_over(&legacy, &rpc, PROBE_TIMEOUT, attempts(0), 100)
            .await
            .expect_err("an unknown node error must not classify");
        let text = format!("{err:#}");
        assert!(
            text.contains("could not classify"),
            "the probe must say it could not classify, got: {text}"
        );
        assert!(
            text.contains("midnight_contractState failed"),
            "the underlying read failure must stay in the chain, got: {text}"
        );
    }

    #[tokio::test]
    async fn probe_archive_state_clamps_window_at_block_one() {
        // Head 0x32 = 50 with a window of 100: the subtraction saturates and block 0 is
        // not probeable, so the probe asks at exactly T = max(1, H - window) = 1.
        let node = StubNode::new(probe_replies(
            "0x32",
            Canned::NodeError(-32602, NOT_PRESENT_MSG),
        ));
        let (legacy, rpc) = probe_harness(&node);

        let state = probe_archive_state_over(&legacy, &rpc, PROBE_TIMEOUT, attempts(0), 100)
            .await
            .expect("a short chain still probes");
        assert_eq!(state, ArchiveState::Archive);
        assert_eq!(node.calls_to("chain_getBlockHash"), vec!["[1]".to_string()]);
    }

    #[tokio::test]
    async fn probe_archive_state_uses_existing_retry_budget() {
        // The probe adds no backoff of its own, but every read still goes through
        // retry_rpc once, so a transient transport fault retries within the EXISTING
        // budget and the probe still classifies.
        let mut replies = probe_replies("0x400", Canned::NodeError(-32602, NOT_PRESENT_MSG));
        replies[0]
            .1
            .insert(0, Canned::Transport("connection reset by peer"));
        let node = StubNode::new(replies);
        let (legacy, rpc) = probe_harness(&node);

        let state = probe_archive_state_over(&legacy, &rpc, PROBE_TIMEOUT, attempts(2), 100)
            .await
            .expect("a transient fault within budget still classifies");
        assert_eq!(state, ArchiveState::Archive);
        assert_eq!(
            node.calls_to("chain_getFinalizedHead").len(),
            2,
            "one fault, one retry, no more"
        );
    }

    #[tokio::test]
    async fn contract_state_pruned_answer_spends_one_budget() {
        // Also the pruning-signature classification pin: "Unable to get requested
        // contract state" at a hash the node itself just served for a finalized
        // ancestor is what identifies a pruned node, and the variant carries the height
        // so the policy layer can name it.
        let node = StubNode::new(probe_replies(
            "0x400",
            Canned::NodeError(-32602, UNSERVABLE_MSG),
        ));
        let (legacy, rpc) = probe_harness(&node);

        let state = probe_archive_state_over(&legacy, &rpc, PROBE_TIMEOUT, attempts(2), 100)
            .await
            .expect("pruned is a classification, not an error");
        assert_eq!(state, ArchiveState::Pruned { probed_height: 924 });
        assert_eq!(node.calls_to("midnight_contractState").len(), 3);
        assert_eq!(node.calls_to("chain_getFinalizedHead").len(), 1);
        assert_eq!(node.calls_to("chain_getHeader").len(), 1);
        assert_eq!(node.calls_to("chain_getBlockHash").len(), 1);
    }
}
