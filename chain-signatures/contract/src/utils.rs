/// Computes the signing threshold for a given number of participants.
///
/// The threshold is recomputed on every resharing so that it always tracks the
/// current participant set:
/// - small cohorts (`n < 5`) use a simple majority (`n / 2 + 1`), since a 2/3
///   supermajority would leave no room for downtime (e.g. `n = 3` would require
///   all three participants online),
/// - larger cohorts use a 2/3 supermajority (`floor(2n / 3) + 1`), which keeps
///   an honest supermajority while scaling fault tolerance with the cohort size
///   (up to `n - threshold ≈ n / 3` participants may be offline).
pub fn compute_threshold(n: usize) -> usize {
    if n < 5 {
        n / 2 + 1
    } else {
        2 * n / 3 + 1
    }
}

#[cfg(test)]
mod tests {
    use super::compute_threshold;

    #[test]
    fn test_compute_threshold() {
        // (n, expected): simple majority for n < 5, 2/3 supermajority otherwise.
        let cases = [
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 3),
            (5, 4),
            (6, 5),
            (7, 5),
            (8, 6),
            (9, 7),
            (10, 7),
            (11, 8),
            (12, 9),
            (13, 9),
            (14, 10),
            (15, 11),
            (100, 67),
        ];
        for (n, expected) in cases {
            assert_eq!(compute_threshold(n), expected, "n = {n}");
        }
    }
}
