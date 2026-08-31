//! Deliberator publish: fail over the response publish when the proposer stays silent.
//!
//! Every participant stores the [`PublishState`] when it marks the entry
//! publishing, so failover needs no protocol change, only someone acting on that
//! stored state. The schedule is a pure function of the entry: the stamp it
//! carries plus a per-node jitter, so nothing has to be tracked between sweeps
//! and a restart does not restart the clock.
//!
//! The sweep itself lives in the chain stream, on block events. Having observed
//! the chain through block N is the precondition for concluding the proposer's
//! response did not land, so the catch-up gate is structural rather than a flag
//! that can drift: no blocks observed, no failover.

use crate::sign_bidirectional::PublishState;

use mpc_primitives::{Chain, ChainConfig as _, SignId};
use near_account_id::AccountId;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::Duration;

/// Duplicate responses per silent proposer that we are willing to pay for failover.
const DELIBERATOR_DUPLICATE_RATE: f64 = 2.0;

/// Extra time beyond chain finality for a published response to be observed
/// (submission, a few publish retries, indexer lag) before deliberators take over.
pub const DEFAULT_OBSERVE_MARGIN: Duration = Duration::from_secs(15);

/// The lag from one node publishing a response until another node has observed it.
///
/// `override_lag` is `None` in production, giving chain finality plus the margin.
/// A fixture pins it so its timing does not move when a finality constant does.
fn observe_lag(chain: Chain, override_lag: Option<Duration>) -> Duration {
    override_lag.unwrap_or_else(|| {
        Duration::from_secs(chain.expected_finality_time_secs()) + DEFAULT_OBSERVE_MARGIN
    })
}

/// The longest a deliberator can wait before publishing, for fixtures that outlast
/// the schedule without restating it.
#[cfg(any(test, feature = "test-feature"))]
pub fn max_deliberator_publish_delay(
    chain: Chain,
    deliberators: usize,
    override_lag: Option<Duration>,
) -> Duration {
    deliberator_publish_delay(deliberators, 1.0, observe_lag(chain, override_lag))
}

/// This node's position in the failover schedule for one request: uniform in
/// [0, 1) as a pure function of sign id and account id.
///
/// Identical draws would put every deliberator on chain at once (`E[responses]`
/// of `m`, not `1 + d`); determinism is what lets the schedule survive restarts.
fn deliberator_jitter(sign_id: &SignId, me: &AccountId) -> f64 {
    let mut hasher = DefaultHasher::new();
    (sign_id.request_id, me.as_str()).hash(&mut hasher);
    // Top 53 bits: exact in an f64, so the result stays strictly below 1.
    (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64
}

/// How long a non-proposer waits before publishing: `L + jitter * m*L/d`, for `L`
/// the observe lag, `m` the number of deliberators and `d` [`DELIBERATOR_DUPLICATE_RATE`].
///
/// The `L` offset keeps the happy path at one response: a proposer that publishes
/// is observed before the earliest deliberator can fire. The window prices failover:
/// the lowest draw publishes, and so does every draw within `L` of it, which over
/// a window of `m*L/d` is `d` deliberators in expectation. Slow-finality chains fail
/// over in tens of minutes; accepted, since the alternative is no response at all.
fn deliberator_publish_delay(deliberators: usize, jitter: f64, lag: Duration) -> Duration {
    let window = lag.mul_f64(deliberators as f64 / DELIBERATOR_DUPLICATE_RATE);
    lag + window.mul_f64(jitter)
}

/// Unix second from which `me` may publish `request` itself, if the proposer's
/// response has still not been observed by then. `None` for an entry that
/// carries no stamp, which never fails over; see [`PublishState::publishing_since`].
pub(crate) fn publish_deadline(
    sign_id: &SignId,
    publish: &PublishState,
    me: &AccountId,
    chain: Chain,
    override_lag: Option<Duration>,
) -> Option<u64> {
    let deliberators = publish.participants.len().saturating_sub(1);
    let delay = deliberator_publish_delay(
        deliberators,
        deliberator_jitter(sign_id, me),
        observe_lag(chain, override_lag),
    );
    Some(publish.publishing_since? + delay.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cait_sith::protocol::Participant;
    use k256::{ProjectivePoint, Scalar};
    use mpc_primitives::Signature;

    fn account(name: &str) -> AccountId {
        name.parse().unwrap()
    }

    fn publish_state(participants: usize, publishing_since: Option<u64>) -> PublishState {
        PublishState {
            signature: Signature::new(ProjectivePoint::GENERATOR.to_affine(), Scalar::ONE, 0),
            participants: (0..participants as u32).map(Participant::from).collect(),
            is_proposer: false,
            publishing_since,
        }
    }

    const LAG: Option<Duration> = None;

    /// A proposer whose first attempt failed must still land inside the margin.
    #[test]
    fn observe_margin_outlasts_the_first_publish_retry() {
        assert!(DEFAULT_OBSERVE_MARGIN > crate::rpc::PUBLISH_MIN_DELAY);
    }

    #[test]
    fn deliberator_jitter_is_deterministic_and_spread() {
        let me = account("node0.near");
        let id = SignId::new([7u8; 32]);
        assert_eq!(deliberator_jitter(&id, &me), deliberator_jitter(&id, &me));

        let mut draws: Vec<f64> = (0u8..20)
            .map(|byte| deliberator_jitter(&SignId::new([byte; 32]), &me))
            .collect();
        draws.extend(
            (0u8..20).map(|byte| deliberator_jitter(&id, &account(&format!("node{byte}.near")))),
        );
        assert!(draws.iter().all(|draw| (0.0..1.0).contains(draw)));
        let first = draws[0];
        assert!(draws.iter().any(|draw| *draw != first));
    }

    /// The deadline is anchored on the entry's own stamp, so an entry recovered
    /// after a restart resumes its schedule instead of starting a new one, and
    /// two nodes reach different deadlines for the same entry.
    #[test]
    fn publish_deadline_follows_the_stamp_and_the_node() {
        let sign_id = SignId::new([1u8; 32]);
        let lag = observe_lag(Chain::Solana, LAG).as_secs();
        let me = account("node0.near");

        let deadline = |since, who: &AccountId| {
            publish_deadline(&sign_id, &publish_state(3, since), who, Chain::Solana, LAG)
        };

        let at_zero = deadline(Some(0), &me).expect("a stamped entry has a deadline");
        assert!(at_zero >= lag, "never fires before one observe lag");

        let later = deadline(Some(1_000), &me).expect("a stamped entry has a deadline");
        assert_eq!(
            later,
            at_zero + 1_000,
            "the stamp shifts the whole schedule"
        );

        let peer =
            deadline(Some(0), &account("node1.near")).expect("a stamped entry has a deadline");
        assert_ne!(peer, at_zero, "nodes draw different positions");

        assert!(
            deadline(None, &me).is_none(),
            "an entry written before the stamp existed never fails over"
        );
    }
}
