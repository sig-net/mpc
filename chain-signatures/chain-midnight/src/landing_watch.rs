//! The watch over one submitted transaction. It scans the finalized blocks
//! after its submit until one holds it, its TTL passes, or the budget ends;
//! a terminal read verdict exits at once. The caller, `NativeIntentClient::post`,
//! turns the end into reservation and error.

use std::time::Duration;

use anyhow::Context as _;
use midnight_base_crypto::time::Timestamp;
use tokio::time::Instant;

use crate::rpc::reads::read_verdict;
use crate::rpc::submit::{Landing, SubmitChain};
use crate::types::{BlockHash, LedgerTxHash};

pub(crate) const LANDING_POLL: Duration = Duration::from_secs(2);

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
}

/// Scans each finalized block after `after` for `tx_hash` until one holds it,
/// until a finalized block past `ttl` holds none of it (`WatchEnd::Expired`),
/// or until `deadline`, when the outcome is unknown. A terminal read verdict
/// ends the watch at once.
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
            Ok(Ok(None)) => {}
            Ok(Err(error)) => {
                let failure = read_verdict(&error);
                if failure.is_terminal() {
                    return WatchEnd::TerminalRead(error);
                }
                // TODO: three consecutive throttled scans, reset by any other
                // outcome, escape to the publisher's gate as a retryable end
                // instead of polling the watch to the budget.
                tracing::warn!(
                    error = %format_args!("{error:#}"),
                    tx_hash = %tx_hash,
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
    use crate::rpc::submit::Landing;
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
        // A block at exactly the TTL still holds the intent, so the watch scans
        // one block further than a non-strict compare would.
        for (ttl, reads) in [
            (1080u64, vec![11, 12, 13, 14]),
            (1084, vec![11, 12, 13, 14, 15]),
        ] {
            let chain = ScriptedChain::new(10, 20);
            let end = watch_landing(
                &chain,
                tx_hash(),
                10,
                Timestamp::from_secs(ttl),
                far_deadline(),
            )
            .await;
            assert!(matches!(end, WatchEnd::Expired), "ttl {ttl}: {end:?}");
            assert_eq!(
                chain
                    .landing_reads
                    .lock()
                    .unwrap()
                    .iter()
                    .copied()
                    .collect::<Vec<_>>(),
                reads,
                "ttl {ttl}: the block at exactly the TTL is scanned through, not past"
            );
        }
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
        // Retryable-with-status — 409 included, a shared provider's transient
        // (`read_verdict`'s status partition): the watch must re-read, not exit.
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
        // A head jump must not skip blocks: every block before the head is
        // looked up by number, each head once.
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
        // A terminal read verdict must end the watch on the read itself, not
        // the budget: no retry follows it.
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
}
