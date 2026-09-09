//! Publish failover: republish a response the proposer never got on chain.
//!
//! Every participant stores the [`PublishState`] when it marks the entry
//! publishing. The schedule is a pure function of that entry, its stamp plus a
//! per-node jitter, so a restart does not restart the clock.
//!
//! The sweep lives in the chain stream on block events, gated on a completed
//! catchup.
//!
//! The `1 + d` cost assumes the failover response lands, so the nodes still
//! waiting observe it and drop their entries. If none can land, all `m` fire, once
//! each, spread over the window.
//!
//! The proposer is scheduled too. Its own deadline is one observe lag away, by
//! which point its response is either observed, so the entry is gone, or it is
//! not, and a second attempt is wanted. Skipping it would make the schedule
//! depend on `is_proposer`, a local role that checkpoint recovery overwrites.

use crate::sign_bidirectional::PublishState;

use mpc_primitives::{Chain, ChainConfig as _, SignId};
use near_account_id::AccountId;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::Duration;

/// Duplicate responses per silent proposer that we are willing to pay for failover.
const FAILOVER_DUPLICATE_RATE: f64 = 2.0;

/// Extra time beyond chain finality for a published response to be observed
/// (submission, a few publish retries, indexer lag) before the failover takes over.
pub const DEFAULT_OBSERVE_MARGIN: Duration = Duration::from_secs(15);

/// The lag from one node publishing a response until another has observed it.
/// `None` in production, giving chain finality plus the margin; a fixture pins it
/// so its timing does not move when a finality constant does.
pub(crate) fn observe_lag(chain: Chain, override_lag: Option<Duration>) -> Duration {
    override_lag.unwrap_or_else(|| {
        Duration::from_secs(chain.expected_finality_time_secs()) + DEFAULT_OBSERVE_MARGIN
    })
}

/// The longest any participant can wait, for fixtures that outlast the schedule
/// without restating it.
#[cfg(any(test, feature = "test-feature"))]
pub fn max_publish_failover_delay(
    chain: Chain,
    participants: usize,
    override_lag: Option<Duration>,
) -> Duration {
    failover_delay(participants, 1.0, observe_lag(chain, override_lag))
}

/// This node's position in the schedule for one request: uniform in [0, 1) as a
/// pure function of sign id and account id. Identical draws would put every
/// participant on chain at once (`E[responses]` of `m`, not `1 + d`).
fn failover_jitter(sign_id: &SignId, me: &AccountId) -> f64 {
    let mut hasher = DefaultHasher::new();
    (sign_id.request_id, me.as_str()).hash(&mut hasher);
    // Top 53 bits: exact in an f64, so the result stays strictly below 1.
    (hasher.finish() >> 11) as f64 / (1u64 << 53) as f64
}

/// How long a node waits before publishing: `L + jitter * m*L/d`, for `L` the
/// observe lag, `m` the participants and `d` [`FAILOVER_DUPLICATE_RATE`].
///
/// The `L` offset keeps the happy path at one response, since a proposer that
/// publishes is observed before the earliest failover fires. The window prices
/// failover: the lowest draw publishes, and so does every draw within `L` of it,
/// which over `m*L/d` is `d` nodes in expectation.
fn failover_delay(participants: usize, jitter: f64, lag: Duration) -> Duration {
    let window = lag.mul_f64(participants as f64 / FAILOVER_DUPLICATE_RATE);
    lag + window.mul_f64(jitter)
}

/// Unix second from which `me` may publish this entry itself. `None` for an entry
/// carrying no stamp, which never fails over; see
/// [`PublishState::publishing_since`].
pub(crate) fn publish_deadline(
    sign_id: &SignId,
    publish: &PublishState,
    me: &AccountId,
    lag: Duration,
) -> Option<u64> {
    let delay = failover_delay(
        publish.participants.len(),
        failover_jitter(sign_id, me),
        lag,
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
    fn failover_jitter_is_deterministic_and_spread() {
        let me = account("node0.near");
        let id = SignId::new([7u8; 32]);
        assert_eq!(failover_jitter(&id, &me), failover_jitter(&id, &me));

        let mut draws: Vec<f64> = (0u8..20)
            .map(|byte| failover_jitter(&SignId::new([byte; 32]), &me))
            .collect();
        draws.extend(
            (0u8..20).map(|byte| failover_jitter(&id, &account(&format!("node{byte}.near")))),
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
            publish_deadline(
                &sign_id,
                &publish_state(3, since),
                who,
                observe_lag(Chain::Solana, LAG),
            )
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
