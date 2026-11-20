//! In-fixture stand-in for the on-chain checkpoint vote tally.
//!
//! Production nodes emit `RpcAction::VoteCheckpoint` and the contract counts one
//! vote per participant per digest, settling the first digest that reaches the
//! threshold at a height. The fixture intercepts those actions instead of
//! sending them on-chain. Without a stand-in, no checkpoint ever settles, the
//! backlog base never advances, and long tests eventually exhaust the pending
//! checkpoint budget.

use cait_sith::protocol::Participant;
use mpc_primitives::{Chain, CheckpointDigest};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

/// Shared handle passed to every node's mock network task.
pub type CheckpointSettlementHandle = Arc<Mutex<CheckpointSettlement>>;

/// Mirrors the subset of `contract::vote_checkpoint` the fixture needs: one
/// vote per participant per digest, a height settles once (first digest to
/// reach the threshold), and votes at or below a settled height are ignored.
pub struct CheckpointSettlement {
    threshold: usize,
    /// When false, votes stay in the fixture's action log but never settle a
    /// checkpoint. This preserves the fixture's historical behavior for tests
    /// that explicitly opt out via `without_checkpoint_settlement`.
    enabled: bool,
    /// Distinct voters per candidate digest. `CheckpointDigest` already carries
    /// chain and height, so this is the contract's `checkpoint_votes` key.
    votes: HashMap<CheckpointDigest, HashSet<Participant>>,
    /// Highest settled height per chain. Heights settle once and never regress.
    settled: HashMap<Chain, u64>,
    /// One sender per (node, chain). Retaining them keeps every watch channel
    /// alive for the fixture's lifetime and makes the watch chain-specific:
    /// `align_backlog_with_consensus` does not check the digest's chain itself.
    senders: HashMap<(Participant, Chain), watch::Sender<Option<CheckpointDigest>>>,
}

impl CheckpointSettlement {
    pub fn new(threshold: usize, enabled: bool) -> Self {
        Self {
            threshold,
            enabled,
            votes: HashMap::new(),
            settled: HashMap::new(),
            senders: HashMap::new(),
        }
    }

    /// Create the watch a node's stream context reads for `chain`. The matching
    /// sender is retained by this component; do not drop the receiver's peers.
    pub fn new_watch(
        &mut self,
        node: Participant,
        chain: Chain,
    ) -> watch::Receiver<Option<CheckpointDigest>> {
        let (tx, rx) = watch::channel(None);
        let previous = self.senders.insert((node, chain), tx);
        assert!(
            previous.is_none(),
            "duplicate checkpoint watch for node {node:?} on {chain:?}"
        );
        rx
    }

    /// Record a vote from `voter` for `digest`.
    ///
    /// Votes at or below the chain's settled height are ignored. A digest that
    /// gathers `threshold` distinct voters settles its height and is published
    /// to every node watching that chain; competing digests at the same height
    /// can never settle afterwards.
    pub fn record_vote(&mut self, voter: Participant, digest: CheckpointDigest) {
        if !self.enabled {
            return;
        }
        if self
            .settled
            .get(&digest.chain)
            .is_some_and(|&height| digest.height <= height)
        {
            return;
        }

        let voters = self.votes.entry(digest).or_default();
        voters.insert(voter);
        if voters.len() < self.threshold {
            return;
        }

        if self
            .settled
            .get(&digest.chain)
            .is_some_and(|&height| digest.height <= height)
        {
            return;
        }

        self.settled.insert(digest.chain, digest.height);
        // The contract prunes stale candidates once a height settles.
        self.votes.retain(|candidate, _| {
            candidate.chain != digest.chain || candidate.height > digest.height
        });

        for ((_, chain), tx) in &self.senders {
            if *chain == digest.chain {
                tx.send_if_modified(|old| {
                    if *old == Some(digest) {
                        return false;
                    }
                    *old = Some(digest);
                    true
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn voter(id: u32) -> Participant {
        Participant::from(id)
    }

    fn digest(chain: Chain, height: u64, byte: u8) -> CheckpointDigest {
        CheckpointDigest::new(chain, height, [byte; 32])
    }

    #[test]
    fn settles_on_first_digest_to_reach_threshold() {
        let mut settlement = CheckpointSettlement::new(2, true);
        let rx0 = settlement.new_watch(voter(0), Chain::Solana);
        let rx1 = settlement.new_watch(voter(1), Chain::Solana);
        let rx2 = settlement.new_watch(voter(2), Chain::Solana);

        let winning = digest(Chain::Solana, 5, 1);
        settlement.record_vote(voter(0), winning);
        assert_eq!(*rx0.borrow(), None, "one vote must not settle");

        settlement.record_vote(voter(1), winning);
        for rx in [&rx0, &rx1, &rx2] {
            assert_eq!(*rx.borrow(), Some(winning), "every node gets the digest");
        }

        // Competing digest at the same height cannot change the settled value.
        let competing = digest(Chain::Solana, 5, 2);
        settlement.record_vote(voter(0), competing);
        settlement.record_vote(voter(1), competing);
        assert_eq!(*rx0.borrow(), Some(winning));
    }

    #[test]
    fn duplicate_voters_do_not_count() {
        let mut settlement = CheckpointSettlement::new(2, true);
        let rx = settlement.new_watch(voter(0), Chain::Solana);
        let d = digest(Chain::Solana, 5, 1);

        settlement.record_vote(voter(0), d);
        settlement.record_vote(voter(0), d);
        assert_eq!(*rx.borrow(), None);

        settlement.record_vote(voter(1), d);
        assert_eq!(*rx.borrow(), Some(d));
    }

    #[test]
    fn settled_height_never_regresses() {
        let mut settlement = CheckpointSettlement::new(2, true);
        let rx = settlement.new_watch(voter(0), Chain::Solana);
        let first = digest(Chain::Solana, 10, 1);
        let older = digest(Chain::Solana, 9, 2);

        settlement.record_vote(voter(0), first);
        settlement.record_vote(voter(1), first);
        assert_eq!(*rx.borrow(), Some(first));

        for v in [voter(0), voter(1), voter(2)] {
            settlement.record_vote(v, older);
        }
        assert_eq!(*rx.borrow(), Some(first));

        // A higher height still settles and replaces the watch value.
        let later = digest(Chain::Solana, 15, 3);
        settlement.record_vote(voter(0), later);
        settlement.record_vote(voter(1), later);
        assert_eq!(*rx.borrow(), Some(later));
    }

    #[test]
    fn watches_are_isolated_per_chain() {
        let mut settlement = CheckpointSettlement::new(2, true);
        let solana_rx = settlement.new_watch(voter(0), Chain::Solana);
        let ethereum_rx = settlement.new_watch(voter(0), Chain::Ethereum);

        let solana = digest(Chain::Solana, 5, 1);
        settlement.record_vote(voter(0), solana);
        settlement.record_vote(voter(1), solana);
        assert_eq!(*solana_rx.borrow(), Some(solana));
        assert_eq!(*ethereum_rx.borrow(), None);

        let ethereum = digest(Chain::Ethereum, 5, 2);
        settlement.record_vote(voter(0), ethereum);
        settlement.record_vote(voter(1), ethereum);
        assert_eq!(*solana_rx.borrow(), Some(solana));
        assert_eq!(*ethereum_rx.borrow(), Some(ethereum));
    }

    #[test]
    fn disabled_settlement_never_publishes() {
        let mut settlement = CheckpointSettlement::new(2, false);
        let rx = settlement.new_watch(voter(0), Chain::Solana);
        let d = digest(Chain::Solana, 5, 1);

        for v in [voter(0), voter(1), voter(2)] {
            settlement.record_vote(v, d);
        }
        assert_eq!(*rx.borrow(), None);
    }
}
