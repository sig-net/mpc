//! The watch over one submitted transaction. It scans the finalized blocks
//! after its submit until one holds it, its TTL passes, or the budget ends;
//! a terminal read verdict exits at once and `THROTTLED_SCANS_TO_EXIT`
//! consecutive throttled ones escape to the publisher's gate. The caller,
//! `NativeIntentClient::post`, turns the end into reservation and error.

use std::time::Duration;

use anyhow::Context as _;
use mpc_chain_integration_core::utils::retry::{is_throttle_status, RpcFailure};

use midnight_base_crypto::time::Timestamp;
use tokio::time::Instant;

use crate::rpc::{read_verdict, Landing, SubmitChain};
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

    // A block scan either finds the transaction in a finalized block or finds
    // the chain has passed the intent's TTL. Kept separate from `WatchEnd` so
    // `Landing` cannot carry the contradictory `Expired` state.
    enum ScanOutcome {
        Landed(Landing),
        Expired,
    }

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
                    return Ok(Some(ScanOutcome::Landed(landing)));
                }
                scanned = number;
            }
            if chain.block_time(&head).await? > ttl {
                return Ok(Some(ScanOutcome::Expired));
            }
            scanned_head = Some(head);
            Ok(None)
        };
        match tokio::time::timeout_at(deadline, scan).await {
            Ok(Ok(Some(ScanOutcome::Expired))) => return WatchEnd::Expired,
            Ok(Ok(Some(ScanOutcome::Landed(landing)))) => return WatchEnd::Landed(landing),
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use midnight_base_crypto::time::Timestamp;
    use tokio::time::Instant;

    use crate::chain_mock::{scan_read_rejected, LandingRead, ScriptedChain, TX_HASH};
    use crate::rpc::Landing;
    use crate::types::LedgerTxHash;

    use super::{watch_landing, WatchEnd, LANDING_POLL};

    fn tx_hash() -> LedgerTxHash {
        LedgerTxHash::from_bytes(TX_HASH)
    }

    fn far_deadline() -> Instant {
        Instant::now() + Duration::from_secs(300)
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_landing_read_is_retried_on_the_same_block() {
        let chain = ScriptedChain::new(10, 20)
            .failing_read_at(13)
            .landing_at(13, Landing::Applied);
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(5000),
            far_deadline(),
        )
        .await;
        assert!(matches!(end, WatchEnd::Landed(Landing::Applied)), "{end:?}");
        assert_eq!(
            chain
                .landing_reads
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [11, 12, 13, 13]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_read_at_a_standing_head_is_retried() {
        let chain = ScriptedChain::new(10, 13)
            .failing_read_at(13)
            .landing_at(13, Landing::Applied);
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(5000),
            far_deadline(),
        )
        .await;
        assert!(matches!(end, WatchEnd::Landed(Landing::Applied)), "{end:?}");
        assert_eq!(
            chain
                .landing_reads
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [11, 12, 13, 13]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_time_read_at_a_standing_head_is_retried() {
        // The head stands at 12, at 1072: past a 1070 TTL. Its first time read fails,
        // so the next scan of that same head compares its time again and it expires.
        let chain = ScriptedChain::new(11, 12).failing_time_once_at(12);
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(1070),
            far_deadline(),
        )
        .await;
        assert!(matches!(end, WatchEnd::Expired), "{end:?}");
        assert_eq!(*chain.time_reads.lock().unwrap(), [12, 12]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transaction_past_its_ttl_unlanded_ends_expired() {
        let chain = ScriptedChain::new(10, 20);
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(1080),
            far_deadline(),
        )
        .await;
        assert!(matches!(end, WatchEnd::Expired), "{end:?}");
        assert_eq!(
            chain
                .landing_reads
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [11, 12, 13, 14]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_transaction_unseen_by_the_deadline_ends_at_budget() {
        // The head stalls at 12, inside the TTL, so the outcome stays unknown.
        let chain = ScriptedChain::new(10, 12);
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(5000),
            Instant::now() + Duration::from_secs(30),
        )
        .await;
        assert!(matches!(end, WatchEnd::Budget), "{end:?}");
        assert_eq!(
            *chain.number_reads.lock().unwrap(),
            [11, 12],
            "a standing head is read once"
        );
        assert_eq!(*chain.time_reads.lock().unwrap(), [11, 12]);
        assert_eq!(
            chain
                .landing_reads
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [11, 12],
            "every block after the pin, once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_scan_read_outlasting_the_deadline_ends_at_budget() {
        // The 30 s deadline drops the 40 s read mid-flight: the outcome stays
        // Budget whichever verdict the dropped read was carrying.
        for verdict in [
            LandingRead::Fail(scan_read_rejected(403)),
            LandingRead::Found(Landing::Applied),
        ] {
            let chain =
                ScriptedChain::new(10, 20).delaying_read_at(11, Duration::from_secs(40), verdict);
            let end = watch_landing(
                &chain,
                tx_hash(),
                10,
                Timestamp::from_secs(5000),
                Instant::now() + Duration::from_secs(30),
            )
            .await;
            assert!(
                matches!(end, WatchEnd::Budget),
                "the deadline dropped the read still in flight: {end:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_retryable_status_scan_read_keeps_the_watch_scanning() {
        // Retryable-with-status — 409 included, a shared provider's transient:
        // the watch must re-read, not exit.
        for status in [500u16, 409] {
            let chain = ScriptedChain::new(10, 13)
                .failing_read_with(13, scan_read_rejected(status))
                .landing_at(13, Landing::Applied);
            let end = watch_landing(
                &chain,
                tx_hash(),
                10,
                Timestamp::from_secs(5000),
                far_deadline(),
            )
            .await;
            assert!(
                matches!(end, WatchEnd::Landed(Landing::Applied)),
                "status {status}: {end:?}"
            );
            assert_eq!(
                chain
                    .landing_reads
                    .lock()
                    .unwrap()
                    .iter()
                    .copied()
                    .collect::<Vec<_>>(),
                [11, 12, 13, 13],
                "status {status}: the failed block is re-read, not exited on"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_scan_throttle_keeps_polling_the_posted_submit() {
        // One throttled scan is under the escape count: the posted submit is
        // re-read, not re-posted.
        let chain = ScriptedChain::new(10, 13)
            .failing_read_with(13, scan_read_rejected(429))
            .landing_at(13, Landing::Applied);
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(5000),
            far_deadline(),
        )
        .await;
        assert!(matches!(end, WatchEnd::Landed(Landing::Applied)), "{end:?}");
        assert_eq!(
            chain
                .landing_reads
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [11, 12, 13, 13],
            "the throttled block is re-read"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_non_throttled_scan_resets_the_escape_count() {
        // 429, 429, a statusless failure, then 429: only consecutive throttles
        // count — without the reset the last 429 is the third standing one, and
        // the watch escapes before the landing.
        let chain = ScriptedChain::new(10, 11)
            .failing_read_with(11, scan_read_rejected(429))
            .failing_read_with(11, scan_read_rejected(429))
            .failing_read_with(11, anyhow::anyhow!("the node dropped the read"))
            .failing_read_with(11, scan_read_rejected(429))
            .landing_at(11, Landing::Applied);
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(5000),
            far_deadline(),
        )
        .await;
        assert!(matches!(end, WatchEnd::Landed(Landing::Applied)), "{end:?}");
        assert_eq!(
            chain
                .landing_reads
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [11, 11, 11, 11, 11],
            "the reset leaves the count at one, so the fifth scan lands"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_healthy_scan_resets_the_throttle_count() {
        // The healthy scan resets the standing count, so all three 429s at 13
        // must run before the escape.
        let chain = ScriptedChain::new(10, 20)
            .failing_read_with(11, scan_read_rejected(429))
            .failing_read_with(13, scan_read_rejected(429))
            .failing_read_with(13, scan_read_rejected(429))
            .failing_read_with(13, scan_read_rejected(429));
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(5000),
            far_deadline(),
        )
        .await;
        assert!(matches!(end, WatchEnd::ThrottleEscape(_)), "{end:?}");
        assert_eq!(
            chain
                .landing_reads
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [11, 11, 12, 13, 13, 13],
            "a standing count would have exited one scan early, at [11, 11, 12, 13, 13]"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_absent_block_number_never_ends_the_watch() {
        // The watch's own None-wrap renders "…block 403": carrier-less, must not exit.
        for number in [403u64, 429] {
            let chain = ScriptedChain::new(number - 1, number + 2)
                .stepping(2)
                .missing_hash_at(number);
            let end = watch_landing(
                &chain,
                tx_hash(),
                number - 1,
                Timestamp::from_secs(5000),
                Instant::now() + Duration::from_secs(30),
            )
            .await;
            assert!(matches!(end, WatchEnd::Budget), "number {number}: {end:?}");
            let lookups = chain.hash_lookups.lock().unwrap().clone();
            assert!(
                lookups.len() > 1 && lookups.iter().all(|looked| *looked == number),
                "number {number}: the watch kept polling {lookups:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_head_that_jumps_is_scanned_through_every_block_before_it() {
        // Heads 13 and 16: blocks 11, 12, 14 and 15 are looked up by number, each
        // head is its own hash, and the transaction lands in block 15.
        let chain = ScriptedChain::new(10, 20)
            .landing_at(15, Landing::Applied)
            .stepping(3);
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(5000),
            far_deadline(),
        )
        .await;
        assert!(matches!(end, WatchEnd::Landed(Landing::Applied)), "{end:?}");
        assert_eq!(*chain.hash_lookups.lock().unwrap(), [11, 12, 14, 15]);
        assert_eq!(
            chain
                .landing_reads
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [11, 12, 13, 14, 15]
        );
        assert_eq!(*chain.number_reads.lock().unwrap(), [13, 16]);
        assert_eq!(
            *chain.time_reads.lock().unwrap(),
            [13],
            "the scan that lands reads no time"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_terminal_scan_read_ends_the_watch_at_once() {
        // Block 13's landing read answers 403: the watch exits on the read,
        // not on the budget, and does not retry it.
        let chain = ScriptedChain::new(10, 20)
            .failing_read_with(13, scan_read_rejected(403))
            .landing_at(13, Landing::Applied);
        let started = Instant::now();
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(5000),
            far_deadline(),
        )
        .await;
        assert!(
            matches!(end, WatchEnd::TerminalRead(_)),
            "the watch ends on the failing scan, not the budget: {end:?}"
        );
        assert!(
            started.elapsed() < LANDING_POLL * 3,
            "the terminal read exits at once: {:?}",
            started.elapsed()
        );
        assert_eq!(
            chain
                .landing_reads
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [11, 12, 13],
            "no scan follows the terminal read"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_throttled_scan_read_escapes_to_the_gate() {
        // A standing 429 — three consecutive scans — escapes the watch.
        let chain = ScriptedChain::new(10, 20)
            .failing_read_with(11, scan_read_rejected(429))
            .failing_read_with(11, scan_read_rejected(429))
            .failing_read_with(11, scan_read_rejected(429));
        let end = watch_landing(
            &chain,
            tx_hash(),
            10,
            Timestamp::from_secs(5000),
            far_deadline(),
        )
        .await;
        assert!(matches!(end, WatchEnd::ThrottleEscape(_)), "{end:?}");
        assert_eq!(
            chain
                .landing_reads
                .lock()
                .unwrap()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [11, 11, 11],
            "the third consecutive throttled scan exits, re-reading the same block"
        );
    }
}
