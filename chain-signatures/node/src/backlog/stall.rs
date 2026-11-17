//! Pure settlement-stall predicate (doc/checkpoints.md §4, "Settlement stall").
//!
//! No consumer yet: this module only decides whether a chain is stalled at a
//! boundary from the vote tallies the contract exposes and the caller-supplied
//! first boundary above the base.

use mpc_contract::primitives::CheckpointVoteTally;

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
