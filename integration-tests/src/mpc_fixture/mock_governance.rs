use mpc_node::protocol::contract::primitives::ThresholdVotes;
use mpc_node::protocol::contract::ResharingContractState;
use mpc_node::protocol::{Governance, ProtocolState};
use near_sdk::AccountId;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

/// Shared tally of threshold-change votes across every node's [`MockGovernance`].
///
/// The real contract keeps this in its stored `RunningContractState`, but the
/// node-side `RunningContractState` mirror is lean (it carries only the fields a
/// node consumes) and no longer holds vote maps. The mock therefore accumulates
/// threshold votes here instead, shared across all nodes so the count crosses
/// the running threshold exactly as it would on-chain.
pub(super) type SharedThresholdVotes = Arc<Mutex<ThresholdVotes>>;

/// Replaces the governance smart contract for our tests.
///
/// Note: This has not been fully implemented, only enough for what is needed in
/// tests so far. It would be nice to use the real contract code (it is written
/// in Rust after all) but that would require some refactoring of the contract,
/// as it uses env:: functions that rely on the near wasm runtime.
pub(super) struct MockGovernance {
    pub me: AccountId,
    pub protocol_state_tx: watch::Sender<Option<ProtocolState>>,
    pub threshold_votes: SharedThresholdVotes,
}

impl Governance for MockGovernance {
    async fn propose_join(&self) -> anyhow::Result<()> {
        tracing::debug!(me = ?self.me, "propose_join");
        Ok(())
    }

    async fn candidate_info(
        &self,
        _account_id: &AccountId,
    ) -> anyhow::Result<Option<mpc_contract::primitives::CandidateEntry>> {
        // The mock does not simulate the candidate registry, so no account is
        // ever a candidate. Returning `None` matches the real contract's answer
        // for a non-candidate account.
        Ok(None)
    }

    async fn vote_reshared(&self, epoch: u64) -> anyhow::Result<bool> {
        tracing::debug!(me = ?self.me, ?epoch, "vote_reshared");
        Ok(true)
    }

    async fn vote_public_key(&self, public_key: &near_crypto::PublicKey) -> anyhow::Result<bool> {
        use mpc_node::protocol::contract::RunningContractState;
        use mpc_node::util::NearPublicKeyExt;

        tracing::debug!(me = ?self.me, ?public_key, "vote_public_key");
        let mut result = false;
        self.protocol_state_tx.send_if_modified(|protocol_state| {
            let modified = match protocol_state {
                Some(ProtocolState::Initializing(ref mut state)) => {
                    let entry = state
                        .pk_votes
                        .pk_votes
                        .entry(public_key.clone())
                        .or_default();

                    let entry_modified = entry.insert(self.me.clone());

                    if entry.len() >= state.threshold {
                        *protocol_state = Some(ProtocolState::Running(RunningContractState {
                            epoch: 0,
                            participants: state.candidates.clone().into(),
                            threshold: state.threshold,
                            public_key: public_key.clone().into_affine_point(),
                        }));
                        result = true;
                        true
                    } else {
                        entry_modified
                    }
                }
                Some(other) => {
                    tracing::debug!(
                        me = ?self.me,
                        ?other,
                        "vote_public_key: contract not in Initializing state, no-op"
                    );
                    false
                }
                None => {
                    tracing::debug!(
                        me = ?self.me,
                        "vote_public_key: no contract state, no-op"
                    );
                    false
                }
            };
            modified
        });
        Ok(result)
    }

    async fn vote_threshold(&self, new_threshold: usize) -> anyhow::Result<bool> {
        tracing::debug!(me = ?self.me, new_threshold, "vote_threshold");

        // Read the running threshold; a no-op unless the contract is running.
        let running_threshold = match self.protocol_state_tx.borrow().as_ref() {
            Some(ProtocolState::Running(state)) => state.threshold,
            other => {
                tracing::debug!(me = ?self.me, ?other, "vote_threshold: not running, no-op");
                return Ok(false);
            }
        };

        // Voting for the current threshold withdraws any prior vote.
        if new_threshold == running_threshold {
            self.threshold_votes.lock().unwrap().remove(&self.me);
            return Ok(false);
        }

        // Record this node's vote in the shared tally.
        let votes_for_threshold = self
            .threshold_votes
            .lock()
            .unwrap()
            .vote(new_threshold, self.me.clone());
        if votes_for_threshold < running_threshold {
            return Ok(false);
        }

        // Threshold crossed: the first node to observe it transitions the shared
        // state from `Running` into `Resharing`; later voters find it already
        // transitioned and no-op.
        let mut result = false;
        self.protocol_state_tx.send_if_modified(|protocol_state| {
            let Some(ProtocolState::Running(state)) = protocol_state.as_ref() else {
                return false;
            };
            let participants = state.participants.clone();
            // Threshold-change resharing keeps the participant set unchanged;
            // only `new_threshold` differs.
            let resharing = ResharingContractState {
                old_epoch: state.epoch,
                old_participants: participants.clone(),
                new_participants: participants,
                threshold: state.threshold,
                new_threshold,
                public_key: state.public_key,
                finished_votes: Default::default(),
                cancel_votes: Default::default(),
            };
            *protocol_state = Some(ProtocolState::Resharing(resharing));
            result = true;
            true
        });
        Ok(result)
    }
}
