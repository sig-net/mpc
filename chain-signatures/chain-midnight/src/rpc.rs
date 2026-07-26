//! Midnight node RPC: the read transport everything in the read path goes
//! through. Finalized-block subscription, `send_mn_transaction` extrinsic
//! extraction, raw `midnight_contractState` reads, and the finalized head.
//!
//! This file owns transport only. Interpreting the extracted transaction
//! blobs and the contract state bytes belongs to the sidecar codec layer and
//! the reader; nothing here decodes past the SCALE framing of an extrinsic
//! argument. The filter-and-decode step is a pure function so it can be unit
//! tested offline with hand-built inputs, mirroring how `chain-ethereum`
//! separates parsing from transport.

use std::time::{Duration, Instant};

use anyhow::Context as _;
use futures_util::{Stream, StreamExt};
use mpc_chain_integration_core::utils::retry::{retry_rpc, RetryConfig};
use mpc_chain_integration_core::utils::task::AbortOnDrop;
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::client::OnlineClient;
use subxt::ext::codec::{Compact, Decode};
use subxt::ext::subxt_rpcs::rpc_params;
use subxt::utils::H256;
use subxt::SubstrateConfig;

use crate::config::MidnightConfig;

/// The pallet/call pair whose single argument carries a Midnight ledger
/// transaction blob.
const MIDNIGHT_PALLET: &str = "midnight";
const SEND_MN_TRANSACTION: &str = "send_mn_transaction";

/// How often the stall watchdog wakes to check block-stream liveness.
const WATCHDOG_TICK: Duration = Duration::from_secs(5);

/// A finalized block, wrapping the subxt handle so extrinsics can be
/// fetched lazily.
pub struct FinalizedBlock {
    block: subxt::blocks::Block<SubstrateConfig, OnlineClient<SubstrateConfig>>,
}

impl FinalizedBlock {
    pub fn number(&self) -> u64 {
        u64::from(self.block.number())
    }

    pub fn hash(&self) -> H256 {
        self.block.hash()
    }
}

/// Read-side client for the Midnight node.
pub struct MidnightRpc {
    client: OnlineClient<SubstrateConfig>,
    legacy: LegacyRpcMethods<SubstrateConfig>,
    rpc: RpcClient,
    connect_timeout: Duration,
    request_timeout: Duration,
    stall_timeout: Duration,
    /// Retry budget for the one-shot reads. Connect and subscribe are
    /// deliberately exempt: retrying those would duplicate the supervised
    /// restart, which already re-anchors and catches up.
    retry: RetryConfig,
    /// Keeps subxt metadata current across runtime upgrades; aborted when
    /// this client drops.
    _runtime_updater: AbortOnDrop,
}

impl MidnightRpc {
    /// Dials the node named by `config.node_ws_url`. Validates the config
    /// first: an unusable endpoint should fail here, once, rather than
    /// forever at runtime.
    ///
    /// Deliberately NOT retried, unlike the one-shot reads: a failed dial is
    /// the supervisor's to handle, and an in-place retry loop here would
    /// duplicate the supervised restart that already re-anchors and reruns
    /// catchup, per the disconnect-window design.
    pub async fn connect(config: &MidnightConfig) -> anyhow::Result<Self> {
        config.validate()?;
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

    /// Stream of finalized blocks. Ends on stream error, stream end, or a
    /// stall longer than the configured stall timeout; the supervised
    /// indexer restart is what turns an ended stream into a reconnect and a
    /// catchup, per the disconnect-window design. Like `connect` and unlike
    /// the one-shot reads, this is deliberately not retried in place.
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
    /// `at_block_hash_0x` (`0x`-prefixed), via the `midnight_contractState`
    /// JSON-RPC. The encoding asymmetry between the two parameters is the
    /// node's own wire shape, not a choice made here.
    ///
    /// `Ok(None)` means the contract is not present at that block. A node
    /// that cannot serve state at that block (pruned or unknown hash) is an
    /// error instead, so callers walk back within the archive probe window
    /// rather than concluding absence.
    pub async fn contract_state(
        &self,
        address_64hex: &str,
        at_block_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        // The error mapping lives INSIDE the retried operation so that the
        // definitive answers (state bytes, contract not present) return Ok
        // and are never retried, while transport faults and
        // pruned-or-unknown responses surface as Err and consume the retry
        // budget.
        retry_rpc!(
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
                        Ok(Some(state))
                    }
                    Err(err) => {
                        // Both error shapes arrive as -32602 invalid-params
                        // and are distinguishable only by message, so match
                        // the node's own strings.
                        let message = err.to_string();
                        if message.contains("Contract not present") {
                            Ok(None)
                        } else if message.contains("Unable to get requested contract state") {
                            Err(anyhow::Error::new(err).context(
                                "midnight node cannot serve contract state at that block (pruned or unknown hash)",
                            ))
                        } else {
                            Err(anyhow::Error::new(err).context("midnight_contractState failed"))
                        }
                    }
                }
            }
        )
    }

    /// Every `midnight::send_mn_transaction` blob in `block`, in extrinsic
    /// order: `args[0]` with its SCALE compact length prefix stripped.
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
        let mut triples = Vec::new();
        for extrinsic in extrinsics.iter() {
            triples.push((
                extrinsic
                    .pallet_name()
                    .context("extrinsic pallet name")?
                    .to_string(),
                extrinsic
                    .variant_name()
                    .context("extrinsic variant name")?
                    .to_string(),
                extrinsic.field_bytes().to_vec(),
            ));
        }
        collect_send_mn_blobs(
            triples.iter().map(|(pallet, variant, bytes)| {
                (pallet.as_str(), variant.as_str(), bytes.as_slice())
            }),
        )
    }
}

/// The pure filter-and-decode step for one extrinsic: `Some(blob)` iff
/// `(pallet, variant)` is exactly `midnight::send_mn_transaction`, where
/// the blob is `args[0]` with the SCALE compact length prefix stripped and
/// checked against the remainder. A matching extrinsic with malformed args
/// is an error, never a silent skip: skipping would drop a real transaction
/// blob.
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

/// An EMPTY result is normal and must stay that way: a block with no
/// matching extrinsic is an ordinary idle block, and erroring on it would
/// turn quiet chain periods into supervisor restart storms once the indexer
/// wires this in. The silent-zero-match trap (a misspelled pallet or call
/// name matching nothing forever) is pinned by the offline tests, which
/// require a PRESENT matching extrinsic to come through, not by a runtime
/// invariant. A matching extrinsic with malformed args is still a loud
/// error.
fn collect_send_mn_blobs<'a>(
    extrinsics: impl IntoIterator<Item = (&'a str, &'a str, &'a [u8])>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut blobs = Vec::new();
    for (pallet, variant, field_bytes) in extrinsics {
        if let Some(blob) = extract_send_mn_transaction(pallet, variant, field_bytes)? {
            blobs.push(blob);
        }
    }
    Ok(blobs)
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
    use subxt::ext::codec::{Compact, Encode};

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
    fn filters_send_mn_transaction() {
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

        // The same call name under another pallet must not match, the same
        // pallet with another call must not match, and matching is exact,
        // never case-insensitive.
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
    fn strips_the_compact_length_prefix_in_both_common_modes() {
        // Single-byte mode, hand-built rather than codec-built so at least
        // one raw prefix byte is pinned non-circularly: compact(5) is one
        // byte, 5 << 2 = 0x14.
        let mut short = vec![0x14];
        short.extend_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(
            extract_send_mn_transaction("midnight", "send_mn_transaction", &short)
                .unwrap()
                .unwrap(),
            [1, 2, 3, 4, 5],
        );

        // Two-byte mode via the codec: a 300-byte payload needs the 0b01
        // prefix form, so this pins that the strip is mode-aware rather than
        // always dropping one byte.
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
    fn malformed_args_on_a_matching_extrinsic_are_loud() {
        // A matching extrinsic whose args do not decode must error, never be
        // silently skipped: skipping would drop a real transaction blob.
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

    #[test]
    fn an_idle_block_yields_ok_and_empty() {
        // A block with no matching extrinsic is an ordinary idle block, not
        // an error: erroring here would turn quiet chain periods into
        // supervisor restart storms once the indexer wires this in.
        let field_bytes = scale_vec(&tagged_blob(b""));
        let blobs = collect_send_mn_blobs([
            ("system", "remark", field_bytes.as_slice()),
            ("timestamp", "set", field_bytes.as_slice()),
        ])
        .expect("an idle block is not an error");
        assert!(blobs.is_empty());
    }

    #[test]
    fn a_present_matching_extrinsic_is_never_silently_dropped() {
        // The silent-zero-match trap, pinned where it belongs: a broken
        // filter that returns empty for a block that DOES carry a matching
        // extrinsic must fail here.
        let blob = tagged_blob(&[0xcc; 3]);
        let field_bytes = scale_vec(&blob);
        let noise = scale_vec(&tagged_blob(b""));
        let blobs = collect_send_mn_blobs([
            ("system", "remark", noise.as_slice()),
            ("midnight", "send_mn_transaction", field_bytes.as_slice()),
        ])
        .expect("a well-formed matching extrinsic extracts");
        assert_eq!(blobs, vec![blob], "the present blob must come through");
    }

    /// Requires a local Midnight node at ws://127.0.0.1:9944. Run with
    /// `cargo test -p mpc-chain-midnight -- --ignored`.
    #[tokio::test]
    #[ignore = "requires a local midnight node"]
    async fn live_finalized_subscription_and_extraction() {
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
        let blobs = rpc
            .send_mn_transaction_bytes(&block)
            .await
            .expect("extrinsics fetch");
        // An idle block is legal; when a ledger transaction is present it
        // must lead with the version tag.
        if let Some(first) = blobs.first() {
            assert!(first.starts_with(TAG));
        }
    }
}
