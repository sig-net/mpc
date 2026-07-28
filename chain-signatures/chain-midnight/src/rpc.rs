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
use subxt::ext::codec::{Compact, Decode, Encode};
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

/// `MidnightRuntimeApi::get_ledger_parameters`, spelled the way `sp_api` names a
/// dispatch entry point: `{Trait}_{method}`. Read from node 2.0.0-rc.4's own v15
/// metadata on 2026-07-28, which lists this entry point under `MidnightRuntimeApi`;
/// the polkadot.js camelCase spelling is a client-side alias and does not resolve
/// here, and `state_call` answers an unknown entry point with a bare "function
/// doesn't exist" that carries no diagnosis.
const LEDGER_PARAMETERS_ENTRY: &str = "MidnightRuntimeApi_get_ledger_parameters";

/// `MidnightRuntimeApi::get_zswap_chain_state`, from the same metadata read as
/// [`LEDGER_PARAMETERS_ENTRY`].
const ZSWAP_CHAIN_STATE_ENTRY: &str = "MidnightRuntimeApi_get_zswap_chain_state";

/// Substrate's own signature for "this node cannot reach state at that hash",
/// pruned or never known: `sp_blockchain::Error::UnknownBlock` reaches the caller
/// as `Client error: UnknownBlock: ...`. `state_call` carries no per-pallet
/// message to match on, unlike `midnight_contractState`.
const UNKNOWN_BLOCK_MSG: &str = "UnknownBlock";

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

    /// The ledger parameters at `at_block_hash_0x` (`0x`-prefixed). Fees drift per
    /// block, so a caller proving against a state must read these at that state's
    /// own hash.
    // Only the respond path reads this pair, and it does not call into this crate,
    // which exports no part of `mod rpc`: unreachable to the dead-code pass, which
    // CI promotes to an error.
    #[allow(dead_code)]
    pub async fn ledger_parameters(&self, at_block_hash_0x: &str) -> anyhow::Result<Vec<u8>> {
        ledger_parameters_over(
            &self.legacy,
            self.request_timeout,
            self.retry,
            at_block_hash_0x,
        )
        .await
    }

    /// The zswap ledger state at `at_block_hash_0x`, which is the whole chain's, not
    /// one contract's. `address_64hex` (64 hex chars, no `0x`) selects nothing: the
    /// entry point declares an address argument and ignores it, so unlike
    /// [`Self::contract_state`] there is no absent case for this to report.
    #[allow(dead_code)]
    pub async fn zswap_chain_state(
        &self,
        address_64hex: &str,
        at_block_hash_0x: &str,
    ) -> anyhow::Result<Vec<u8>> {
        zswap_chain_state_over(
            &self.legacy,
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
        let hash = block_hash(hash_0x)?;
        let block = retry_rpc!(
            self.request_timeout,
            self.retry,
            "midnight_block_at_hash",
            {
                self.client
                    .blocks()
                    .at(hash)
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

fn block_hash(hash_0x: &str) -> anyhow::Result<H256> {
    let bytes: [u8; 32] = hex::decode(hash_0x.trim_start_matches("0x"))
        .context("block hash is not hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("block hash is not 32 bytes"))?;
    Ok(H256::from(bytes))
}

/// The bare payload of a `Result<Vec<u8>, _>` runtime-API answer: discriminant byte
/// and compact length both dropped, leaving the tagged blob the ledger
/// deserializers take. Both entry points read here answer in that shape at
/// `MidnightRuntimeApi` version 2, which is what `midnight_apiVersions` reports on
/// node 2.0.0-rc.4; anything older answers with a bare `Vec<u8>` whose first byte
/// would be read here as the discriminant.
///
/// `None` is the `Err` variant. The error is never decoded, only its discriminant,
/// so a ledger error this build has never seen still reads as an `Err` rather than
/// as a decode failure. Neither read here has an absent case, so both callers turn
/// it into a fault, but they do it outside the retry budget: the runtime has
/// settled the question and re-asking spends attempts on a fixed answer.
fn unwrap_runtime_api_result(answer: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
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

/// One `MidnightRuntimeApi` read: a `state_call` at `at_block_hash_0x`, unwrapped
/// to the bare payload. Takes the transport explicitly for the same reason
/// [`contract_state_over`] does, and goes through [`LegacyRpcMethods`] rather than
/// the crate's `OnlineClient`: `runtime_api().at(hash).call_raw(..)` puts the same
/// three parameters on the same `state_call` through the legacy backend, but an
/// `OnlineClient` cannot be built offline, and its backend adds a reconnect loop
/// outside the retry budget below.
async fn runtime_api_bytes_over(
    legacy: &LegacyRpcMethods<SubstrateConfig>,
    request_timeout: Duration,
    retry: RetryConfig,
    entry_point: &str,
    call_parameters: &[u8],
    at_block_hash_0x: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let at = block_hash(at_block_hash_0x)?;
    // Same split as contract_state_over: whatever the runtime itself answers is
    // definitive and returns Ok, Err envelope included, while transport faults and a
    // node that cannot reach the state surface as Err and spend the retry budget.
    retry_rpc!(request_timeout, retry, "midnight_state_call", {
        match legacy
            .state_call(entry_point, Some(call_parameters), Some(at))
            .await
        {
            Ok(answer) => unwrap_runtime_api_result(&answer),
            Err(err) if err.to_string().contains(UNKNOWN_BLOCK_MSG) => {
                Err(anyhow::Error::new(err).context(STATE_UNSERVABLE_MSG))
            }
            Err(err) => Err(anyhow::Error::new(err).context(format!("{entry_point} failed"))),
        }
    })
}

/// [`MidnightRpc::ledger_parameters`] over an explicit transport.
async fn ledger_parameters_over(
    legacy: &LegacyRpcMethods<SubstrateConfig>,
    request_timeout: Duration,
    retry: RetryConfig,
    at_block_hash_0x: &str,
) -> anyhow::Result<Vec<u8>> {
    runtime_api_bytes_over(
        legacy,
        request_timeout,
        retry,
        LEDGER_PARAMETERS_ENTRY,
        &[],
        at_block_hash_0x,
    )
    .await?
    // An Err is the node declining to produce the chain's own fee schedule, which
    // leaves nothing to prove against.
    .with_context(|| format!("midnight node has no ledger parameters at {at_block_hash_0x}"))
}

/// [`MidnightRpc::zswap_chain_state`] over an explicit transport.
async fn zswap_chain_state_over(
    legacy: &LegacyRpcMethods<SubstrateConfig>,
    request_timeout: Duration,
    retry: RetryConfig,
    address_64hex: &str,
    at_block_hash_0x: &str,
) -> anyhow::Result<Vec<u8>> {
    // The entry point declares a `Vec<u8>`, so the address goes on the wire SCALE
    // encoded, length prefix and all. The bare 32 bytes do not fail legibly: they
    // trap the runtime wasm on an `unreachable` instruction.
    let call_parameters = hex::decode(address_64hex.trim_start_matches("0x"))
        .context("contract address is not hex")?
        .encode();
    runtime_api_bytes_over(
        legacy,
        request_timeout,
        retry,
        ZSWAP_CHAIN_STATE_ENTRY,
        &call_parameters,
        at_block_hash_0x,
    )
    .await?
    // Global state, so an Err is the chain having no zswap state at all, never a
    // contract this address failed to name.
    .with_context(|| format!("midnight node has no zswap chain state at {at_block_hash_0x}"))
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
            node_ws_url: "ws://127.0.0.1:9944".to_string(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".to_string(),
            publisher: Default::default(),
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

    // MidnightRuntimeApi reads over `state_call`.

    /// A contract deployed on the chain the live answers below were measured against.
    const DEPLOYED_ADDRESS: &str =
        "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
    /// No contract at this one.
    const BARE_ADDRESS: &str = "abababababababababababababababababababababababababababababababab";
    /// What a node that cannot reach state at the requested hash answers a
    /// `state_call` with, pruned or never known.
    const PRUNED_STATE_CALL_MSG: &str =
        "Client error: UnknownBlock: State already discarded for 0x5555";
    /// `Err(LedgerApiError::ContractNotPresent)`, the whole two-byte answer node
    /// 2.0.0-rc.4 gives `get_contract_state` for [`BARE_ADDRESS`].
    const SCALE_ERR: &[u8] = &[0x01, 0x0b];

    fn legacy_over(node: &StubNode) -> LegacyRpcMethods<SubstrateConfig> {
        LegacyRpcMethods::<SubstrateConfig>::new(RpcClient::new(node.clone()))
    }

    /// A `state_call` reply: the runtime API's SCALE answer as the `0x` hex string
    /// the node serializes `Bytes` to.
    fn state_call_reply(scale: &[u8]) -> Canned {
        json_str(&format!("0x{}", hex::encode(scale)))
    }

    /// SCALE `Ok(payload)` of a `Result<Vec<u8>, _>`: the zero variant byte, then
    /// the payload length-prefixed.
    fn scale_ok(payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x00];
        bytes.extend_from_slice(&scale_vec(payload));
        bytes
    }

    #[tokio::test]
    async fn ledger_parameters_calls_the_runtime_api_and_unwraps_the_payload() {
        // The bare payload is what the ledger deserializer takes; handing back the
        // SCALE envelope would put a variant byte and a length prefix in front of the
        // tag and fail far from here. Sized to the answer node 2.0.0-rc.4 gives: a
        // 791-byte tagged blob in a 794-byte envelope, so the compact length lands in
        // its two-byte form and a strip that always dropped one byte is caught.
        let mut params = b"midnight:ledger-parameters[v8]:".to_vec();
        params.resize(791, 0x5a);
        let envelope = scale_ok(&params);
        assert_eq!(
            envelope.len(),
            794,
            "one discriminant byte, a two-byte compact length, then the blob"
        );
        let node = StubNode::new([("state_call", vec![state_call_reply(&envelope)])]);

        let read = ledger_parameters_over(
            &legacy_over(&node),
            PROBE_TIMEOUT,
            attempts(0),
            HEAD_HASH_HEX,
        )
        .await
        .expect("an Ok answer unwraps");
        assert_eq!(read, params);

        // Spelled out rather than built from the constant, so a renamed entry point
        // fails here instead of agreeing with itself. A nullary runtime API takes
        // empty call parameters, and the hash is the caller's, never the best block.
        assert_eq!(
            node.calls_to("state_call"),
            vec![format!(
                "[\"MidnightRuntimeApi_get_ledger_parameters\",\"0x\",\"{HEAD_HASH_HEX}\"]"
            )],
        );
    }

    #[tokio::test]
    async fn zswap_chain_state_ignores_the_address_and_returns_global_state() {
        // Deliberate, and measured against node 2.0.0-rc.4: a deployed contract's
        // address and 32 bytes of 0xab drew byte-identical 1588-byte payloads. The
        // entry point declares an address and selects nothing with it, so this read is
        // the whole chain's zswap state and has no absent case. Nobody should "fix"
        // the caller to key zswap state by contract.
        //
        // Offline, the stub cannot re-prove what the node does; what it pins is this
        // crate's half of it. Both addresses reach the wire, distinctly, so the
        // argument is passed as the runtime API declares it, and the same answer comes
        // back as the same bytes either way: no address-keyed handling, and no Option
        // for a caller to read absence out of.
        let global = b"midnight:zswap-ledger-state[v5]:global".to_vec();
        let node = StubNode::new([("state_call", vec![state_call_reply(&scale_ok(&global))])]);
        let legacy = legacy_over(&node);

        let at_deployed = zswap_chain_state_over(
            &legacy,
            PROBE_TIMEOUT,
            attempts(0),
            DEPLOYED_ADDRESS,
            HEAD_HASH_HEX,
        )
        .await
        .expect("a served answer unwraps");
        let at_bare = zswap_chain_state_over(
            &legacy,
            PROBE_TIMEOUT,
            attempts(0),
            BARE_ADDRESS,
            HEAD_HASH_HEX,
        )
        .await
        .expect("an address with no contract is answered just the same");

        assert_eq!(at_deployed, global);
        assert_eq!(at_deployed, at_bare);

        let calls = node.calls_to("state_call");
        assert!(calls[0].contains(DEPLOYED_ADDRESS));
        assert!(calls[1].contains(BARE_ADDRESS));
    }

    #[tokio::test]
    async fn a_runtime_api_err_answer_is_a_settled_fault() {
        // Neither read here has an absent case, so an Err envelope is a fault for
        // both. It is still the runtime's own answer rather than a transport fault:
        // one call each, never a retry, because no number of re-asks changes it.
        let node = StubNode::new([("state_call", vec![state_call_reply(SCALE_ERR)])]);
        let legacy = legacy_over(&node);

        ledger_parameters_over(&legacy, PROBE_TIMEOUT, attempts(2), HEAD_HASH_HEX)
            .await
            .expect_err("a node with no ledger parameters cannot be proved against");
        assert_eq!(node.calls_to("state_call").len(), 1);

        zswap_chain_state_over(
            &legacy,
            PROBE_TIMEOUT,
            attempts(2),
            DEPLOYED_ADDRESS,
            HEAD_HASH_HEX,
        )
        .await
        .expect_err("a chain with no zswap state cannot be proved against");
        assert_eq!(node.calls_to("state_call").len(), 2);
    }

    #[tokio::test]
    async fn zswap_chain_state_scale_encodes_the_address() {
        // The entry point takes a `Vec<u8>`, so the address arrives length-prefixed.
        // compact(32) is one byte, 32 << 2 = 0x80, hand-built so the prefix is pinned
        // non-circularly. The bare 32 bytes do not come back as a decode error: node
        // 2.0.0-rc.4 traps the runtime wasm on an `unreachable` instruction, which is
        // why this is pinned at the wire rather than left to a live failure.
        let node = StubNode::new([("state_call", vec![state_call_reply(&scale_ok(b"zswap"))])]);

        let state = zswap_chain_state_over(
            &legacy_over(&node),
            PROBE_TIMEOUT,
            attempts(0),
            DEPLOYED_ADDRESS,
            HEAD_HASH_HEX,
        )
        .await
        .expect("a served answer unwraps");

        assert_eq!(state, b"zswap");
        assert_eq!(
            node.calls_to("state_call"),
            vec![format!(
                "[\"MidnightRuntimeApi_get_zswap_chain_state\",\"0x80{DEPLOYED_ADDRESS}\",\"{HEAD_HASH_HEX}\"]"
            )],
        );
    }

    #[tokio::test]
    async fn runtime_api_reads_spend_the_contract_state_retry_budget() {
        // `state_call` carries no per-pallet "not present" message to tell apart, so
        // the only classification left is the pruning signature, and like
        // contract_state it is an Err that spends the whole budget before surfacing.
        let node = StubNode::new([(
            "state_call",
            vec![Canned::NodeError(-32000, PRUNED_STATE_CALL_MSG)],
        )]);
        let legacy = legacy_over(&node);

        let err = ledger_parameters_over(&legacy, PROBE_TIMEOUT, attempts(2), HEAD_HASH_HEX)
            .await
            .expect_err("a node that cannot reach the state must not answer");
        assert!(is_state_unservable(&err), "got: {err:#}");
        assert_eq!(node.calls_to("state_call").len(), 3);

        let err = zswap_chain_state_over(
            &legacy,
            PROBE_TIMEOUT,
            attempts(2),
            DEPLOYED_ADDRESS,
            HEAD_HASH_HEX,
        )
        .await
        .expect_err("a node that cannot reach the state must not answer");
        assert!(is_state_unservable(&err), "got: {err:#}");
        assert_eq!(node.calls_to("state_call").len(), 6);
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
