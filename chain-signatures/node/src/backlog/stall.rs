//! Pure settlement-stall logic (doc/checkpoints.md §4, "Settlement stall").
//!
//! The predicate decides whether a chain is stalled at a boundary from the
//! vote tallies the contract exposes and the caller-supplied first boundary
//! above the base. `StallBackoff` governs how often a detected stall may
//! trigger a re-index; it is deliberately free of supervisor state so its
//! semantics can be reviewed and tested in isolation.

use std::time::Duration;

use mpc_contract::primitives::CheckpointVoteTally;
use tokio::time::Instant;

/// Base delay before two consecutive stall-triggered re-indexes.
pub(crate) const STALL_BACKOFF_INITIAL: Duration = Duration::from_secs(30);
/// Upper bound of the stall re-index backoff.
pub(crate) const STALL_BACKOFF_MAX: Duration = Duration::from_secs(600);

/// Backoff for stall-triggered re-indexes (doc/checkpoints.md §4).
///
/// A detection re-indexes immediately; the backoff only *suppresses* another
/// stall-triggered re-index until the deadline. The delay doubles on every
/// consecutive stall-triggered re-index and is capped at [`STALL_BACKOFF_MAX`].
/// It resets only on a rebase onto a settled checkpoint (S3 consensus rebase,
/// including startup recovery), which calls [`StallBackoff::on_settled_rebase`].
#[derive(Debug, Clone)]
pub struct StallBackoff {
    delay: Duration,
    suppressed_until: Option<Instant>,
}

impl StallBackoff {
    pub(crate) fn new() -> Self {
        Self {
            delay: STALL_BACKOFF_INITIAL,
            suppressed_until: None,
        }
    }

    /// Whether a stall-triggered re-index is currently allowed.
    pub(crate) fn allows(&self, now: Instant) -> bool {
        self.suppressed_until.is_none_or(|deadline| now >= deadline)
    }

    /// Records a stall-triggered re-index: suppress until `now + delay`, then
    /// double the delay for the next consecutive trigger. Never resets it.
    pub(crate) fn on_stall_reindex(&mut self, now: Instant) {
        self.suppressed_until = Some(now + self.delay);
        self.delay = self.delay.saturating_mul(2).min(STALL_BACKOFF_MAX);
    }

    /// Resets on a rebase onto a settled checkpoint, clearing suppression.
    pub(crate) fn on_settled_rebase(&mut self) {
        self.delay = STALL_BACKOFF_INITIAL;
        self.suppressed_until = None;
    }

    pub(crate) fn delay(&self) -> Duration {
        self.delay
    }

    pub(crate) fn suppressed_until(&self) -> Option<Instant> {
        self.suppressed_until
    }
}

/// A detected settlement stall: `height` is the first boundary above the base,
/// `votes` the number of votes cast at that height without any digest reaching t.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stall {
    pub height: u64,
    pub votes: usize,
}

/// Detect a settlement stall from the contract's checkpoint vote tallies.
///
/// `first_boundary` is the height of the first checkpoint in `pending` — the
/// first boundary above the node's base. The caller supplies it; this function
/// never derives a boundary from the tallies.
pub fn detect_stall(
    tallies: &[CheckpointVoteTally],
    first_boundary: u64,
    threshold: usize,
    committee_size: usize,
) -> Option<Stall> {
    // Doc §4: f = n - t with f < t <= n, so t == 0 or n < t are invalid inputs.
    if threshold == 0 || committee_size < threshold {
        return None;
    }
    let f = committee_size - threshold;

    let mut total: usize = 0;
    let mut any_at_threshold = false;
    for tally in tallies {
        // Doc §4: judge only the first boundary above the base, never other heights.
        if tally.height != first_boundary {
            continue;
        }
        for &(_digest, count) in &tally.votes {
            // Doc §4: "no digest there has reached t" — one that has means the
            // height is settling or settled, so there is no stall.
            if count >= threshold {
                any_at_threshold = true;
            }
            total = total.saturating_add(count);
        }
    }

    if any_at_threshold {
        return None;
    }
    // Doc §4: "more than 2f votes are cast at that height" — total <= 2f is no stall.
    if total <= f.saturating_mul(2) {
        return None;
    }

    Some(Stall {
        height: first_boundary,
        votes: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_backoff_allows_a_reindex() {
        let backoff = StallBackoff::new();
        let now = Instant::now();
        assert_eq!(backoff.delay(), STALL_BACKOFF_INITIAL);
        assert_eq!(backoff.suppressed_until(), None);
        assert!(backoff.allows(now));
    }

    #[test]
    fn a_trigger_suppresses_for_exactly_the_current_delay() {
        let mut backoff = StallBackoff::new();
        let now = Instant::now();
        backoff.on_stall_reindex(now);

        // Suppression runs until (but not beyond) `now + current_delay`.
        assert_eq!(
            backoff.suppressed_until(),
            Some(now + STALL_BACKOFF_INITIAL)
        );
        assert!(!backoff.allows(now + STALL_BACKOFF_INITIAL - Duration::from_nanos(1)));
        assert!(backoff.allows(now + STALL_BACKOFF_INITIAL));
        // The delay for the *next* trigger has already doubled.
        assert_eq!(backoff.delay(), 2 * STALL_BACKOFF_INITIAL);
    }

    #[test]
    fn consecutive_stall_reindexes_double_and_cap() {
        let mut backoff = StallBackoff::new();
        let now = Instant::now();
        let mut deadline = now;
        for active_delay in [
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(120),
            Duration::from_secs(240),
            Duration::from_secs(480),
            STALL_BACKOFF_MAX,
            STALL_BACKOFF_MAX,
            STALL_BACKOFF_MAX,
        ] {
            backoff.on_stall_reindex(deadline);
            deadline += active_delay;
            assert_eq!(backoff.suppressed_until(), Some(deadline));
            assert!(!backoff.allows(deadline - Duration::from_nanos(1)));
            assert!(backoff.allows(deadline));
            let expected_next = (active_delay * 2).min(STALL_BACKOFF_MAX);
            assert_eq!(backoff.delay(), expected_next);
        }
    }

    #[test]
    fn settled_rebase_resets_delay_and_clears_suppression() {
        let mut backoff = StallBackoff::new();
        let now = Instant::now();
        for _ in 0..5 {
            backoff.on_stall_reindex(now);
        }
        assert_eq!(backoff.delay(), STALL_BACKOFF_MAX);

        backoff.on_settled_rebase();
        assert_eq!(backoff.delay(), STALL_BACKOFF_INITIAL);
        assert_eq!(backoff.suppressed_until(), None);
        assert!(backoff.allows(now));
        // The next stall uses the reset base again.
        backoff.on_stall_reindex(now);
        assert_eq!(
            backoff.suppressed_until(),
            Some(now + STALL_BACKOFF_INITIAL)
        );
    }

    #[test]
    fn stall_reindex_never_resets_even_after_the_suppression_expires() {
        let mut backoff = StallBackoff::new();
        let now = Instant::now();
        backoff.on_stall_reindex(now);
        let after_window = now + STALL_BACKOFF_INITIAL + Duration::from_secs(1);
        assert!(backoff.allows(after_window));

        // A legitimate second trigger keeps escalating from 60s; it does not
        // treat the gap as a fresh start.
        backoff.on_stall_reindex(after_window);
        assert_eq!(backoff.delay(), Duration::from_secs(120));
        assert_eq!(
            backoff.suppressed_until(),
            Some(after_window + Duration::from_secs(60))
        );
    }

    /// A digest identified by its first byte; all 32 bytes are that byte.
    fn tally(height: u64, votes: &[(u8, usize)]) -> CheckpointVoteTally {
        CheckpointVoteTally {
            height,
            votes: votes
                .iter()
                .map(|&(byte, count)| ([byte; 32], count))
                .collect(),
        }
    }

    struct Case {
        name: &'static str,
        tallies: Vec<CheckpointVoteTally>,
        first_boundary: u64,
        threshold: usize,
        committee_size: usize,
        expected: Option<Stall>,
    }

    #[test]
    fn detect_stall_table() {
        const BOUNDARY: u64 = 100;
        let cases = vec![
            // n=7, t=5 -> f=2, 2f=4: 5 votes split 3+2, no digest at t -> stall.
            Case {
                name: "5 votes split 3+2 over 2f=4 stalls with 5 votes",
                tallies: vec![tally(BOUNDARY, &[(1, 3), (2, 2)])],
                first_boundary: BOUNDARY,
                threshold: 5,
                committee_size: 7,
                expected: Some(Stall {
                    height: BOUNDARY,
                    votes: 5,
                }),
            },
            // Exactly 2f votes (4) is not "more than 2f".
            Case {
                name: "4 votes split 2+2 equals 2f and is no stall",
                tallies: vec![tally(BOUNDARY, &[(1, 2), (2, 2)])],
                first_boundary: BOUNDARY,
                threshold: 5,
                committee_size: 7,
                expected: None,
            },
            // A digest at t means the height is settling/settled.
            Case {
                name: "5 votes all on one digest reaching t is no stall",
                tallies: vec![tally(BOUNDARY, &[(1, 5)])],
                first_boundary: BOUNDARY,
                threshold: 5,
                committee_size: 7,
                expected: None,
            },
            // Only tallies at another height exist.
            Case {
                name: "tallies only at a different height is no stall",
                tallies: vec![tally(BOUNDARY + 1, &[(1, 3), (2, 2)])],
                first_boundary: BOUNDARY,
                threshold: 5,
                committee_size: 7,
                expected: None,
            },
            // No tallies at all.
            Case {
                name: "empty tallies is no stall",
                tallies: vec![],
                first_boundary: BOUNDARY,
                threshold: 5,
                committee_size: 7,
                expected: None,
            },
            // Invalid committee: n < t.
            Case {
                name: "committee_size below threshold is no stall",
                tallies: vec![tally(BOUNDARY, &[(1, 3), (2, 2)])],
                first_boundary: BOUNDARY,
                threshold: 5,
                committee_size: 4,
                expected: None,
            },
            // Invalid threshold: t == 0.
            Case {
                name: "zero threshold is no stall",
                tallies: vec![tally(BOUNDARY, &[(1, 3), (2, 2)])],
                first_boundary: BOUNDARY,
                threshold: 0,
                committee_size: 7,
                expected: None,
            },
            // Other heights — even ones with a digest at t — must be ignored.
            Case {
                name: "only first_boundary counted; votes at other heights ignored",
                tallies: vec![
                    tally(BOUNDARY - 1, &[(9, 100)]),
                    tally(BOUNDARY, &[(1, 3), (2, 2)]),
                    tally(BOUNDARY + 1, &[(10, 100)]),
                ],
                first_boundary: BOUNDARY,
                threshold: 5,
                committee_size: 7,
                expected: Some(Stall {
                    height: BOUNDARY,
                    votes: 5,
                }),
            },
            // A boundary tally with an empty votes vector adds nothing.
            Case {
                name: "empty boundary votes vector contributes zero",
                tallies: vec![tally(BOUNDARY, &[])],
                first_boundary: BOUNDARY,
                threshold: 5,
                committee_size: 7,
                expected: None,
            },
        ];

        for case in cases {
            let got = detect_stall(
                &case.tallies,
                case.first_boundary,
                case.threshold,
                case.committee_size,
            );
            assert_eq!(got, case.expected, "case: {}", case.name);
        }
    }
}
