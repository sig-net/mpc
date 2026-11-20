//! The watch over one submitted transaction: the finalized blocks after its
//! submit, scanned for it until one holds it, its TTL passes, the budget ends,
//! or a read verdict ends the watch at once. `native::post` translates the end
//! into the wallet's reservation actions and a `SubmitError`.

use std::time::Duration;

use anyhow::Context as _;
use mpc_chain_integration_core::utils::retry::{is_throttle_status, RpcFailure};

use midnight_base_crypto::time::Timestamp;
use tokio::time::Instant;

use crate::native::SubmitChain;
use crate::rpc::{read_verdict, Landing};
use crate::types::{BlockHash, LedgerTxHash};

pub(crate) const LANDING_POLL: Duration = Duration::from_secs(2);
/// Consecutive throttled scans before the watch escapes to the gate: a transient
/// 429 keeps polling the sent transaction; a standing one parks the chain.
const THROTTLED_SCANS_TO_EXIT: u32 = 3;

/// How the watch over one submitted transaction ended.
#[derive(Debug)]
pub(crate) enum WatchEnd {
    /// A finalized block holds the transaction, applied or partially.
    Landed(Landing),
    /// No finalized block held it by one past the intent's TTL.
    Expired,
    /// The submit budget ended first; the transaction may still land.
    Budget,
    /// A scan read the transport refused with a classic client error.
    TerminalRead(anyhow::Error),
    /// Consecutive throttled scans reached `THROTTLED_SCANS_TO_EXIT`.
    ThrottleEscape(anyhow::Error),
}

/// Whether a failed scan read is the provider throttling, by core's typed
/// 402/429 set (`retry::is_throttle_status`).
// Not `is_provider_throttled`: its text fallback would read the watch's
// renders, which carry block numbers.
pub(crate) fn throttled_scan(failure: &RpcFailure) -> bool {
    failure.status().is_some_and(is_throttle_status)
}

/// Scans each finalized block after `after` for `tx_hash` until one holds it,
/// until a finalized block past `ttl` holds none of it (`WatchEnd::Expired`),
/// or until `deadline`, when the outcome is unknown. A terminal read verdict
/// exits at once; `THROTTLED_SCANS_TO_EXIT` consecutive throttled ones escape
/// to the publisher's gate.
pub(crate) async fn watch_landing<C: SubmitChain>(
    chain: &C,
    tx_hash: LedgerTxHash,
    after: u64,
    ttl: Timestamp,
    deadline: Instant,
) -> WatchEnd {
    let mut scanned = after;
    // The head a scan last finished at: while it stands, no block is new and its
    // time was already compared with the TTL.
    let mut scanned_head: Option<BlockHash> = None;
    // Consecutive scans the provider throttled; any other outcome resets it.
    let mut throttled_scans = 0u32;
    loop {
        let scan = async {
            let head = chain.finalized_head().await?;
            if scanned_head.as_ref() == Some(&head) {
                return anyhow::Ok(None);
            }
            let head_number = chain.block_number(&head).await?;
            while scanned < head_number {
                let number = scanned + 1;
                let hash = if number == head_number {
                    head
                } else {
                    chain
                        .block_hash_at(number)
                        .await?
                        .with_context(|| format!("the node has no finalized block {number}"))?
                };
                if let Some(landing) = chain.landing(&hash, tx_hash).await? {
                    return Ok(Some(landing));
                }
                scanned = number;
            }
            if chain.block_time(&head).await? > ttl {
                return Ok(Some(Landing::Expired));
            }
            scanned_head = Some(head);
            Ok(None)
        };
        match tokio::time::timeout_at(deadline, scan).await {
            Ok(Ok(Some(Landing::Expired))) => return WatchEnd::Expired,
            Ok(Ok(Some(landed))) => return WatchEnd::Landed(landed),
            Ok(Ok(None)) => throttled_scans = 0,
            Ok(Err(error)) => {
                let failure = read_verdict(&error);
                if failure.is_terminal() {
                    return WatchEnd::TerminalRead(error);
                }
                if throttled_scan(&failure) {
                    throttled_scans += 1;
                } else {
                    throttled_scans = 0;
                }
                if throttled_scans >= THROTTLED_SCANS_TO_EXIT {
                    return WatchEnd::ThrottleEscape(error);
                }
                tracing::warn!(
                    throttled = %format_args!("{throttled_scans}/{THROTTLED_SCANS_TO_EXIT}"),
                    ?error,
                    "midnight: watching for the respond transaction failed; retrying"
                );
            }
            Err(_) => break,
        }
        if tokio::time::timeout_at(deadline, tokio::time::sleep(LANDING_POLL))
            .await
            .is_err()
        {
            break;
        }
    }
    WatchEnd::Budget
}
