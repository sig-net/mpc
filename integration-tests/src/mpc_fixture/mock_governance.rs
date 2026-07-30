use mpc_node::protocol::contract::RunningContractState;
use mpc_node::protocol::{Governance, ProtocolState};
use mpc_node::util::NearPublicKeyExt;
use near_sdk::AccountId;
use tokio::sync::watch;

/// Replaces the governance smart contract for our tests.
///
/// Note: This has not been fully implemented, only enough for what is needed in
/// tests so far. It would be nice to use the real contract code (it is written
/// in Rust after all) but that would require some refactoring of the contract,
/// as it uses env:: functions that rely on the near wasm runtime.
pub(super) struct MockGovernance {
    pub me: AccountId,
    pub protocol_state_tx: watch::Sender<Option<ProtocolState>>,
}

impl Governance for MockGovernance {
    async fn propose_join(&self) -> anyhow::Result<()> {
        tracing::debug!(me = ?self.me, "propose_join");
        Ok(())
    }

    async fn vote_reshared(&self, epoch: u64) -> anyhow::Result<bool> {
        tracing::debug!(me = ?self.me, ?epoch, "vote_reshared");
        Ok(true)
    }

    async fn vote_public_key(&self, public_key: &near_crypto::PublicKey) -> anyhow::Result<bool> {
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
                            candidates: Default::default(),
                            join_votes: Default::default(),
                            leave_votes: Default::default(),
                            threshold_votes: Default::default(),
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
        let mut result = false;
        self.protocol_state_tx.send_if_modified(|protocol_state| {
            let modified = match protocol_state {
                Some(ProtocolState::Running(ref mut state)) => {
                    let entry = state
                        .threshold_votes
                        .votes
                        .entry(new_threshold)
                        .or_default();
                    let entry_modified = entry.insert(self.me.clone());

                    if entry.len() >= state.threshold {
                        let participants = state.participants.clone();
                        let public_key = state.public_key;
                        let epoch = state.epoch;
                        let old_threshold = state.threshold;
                        // Threshold-change resharing keeps the participant
                        // set unchanged; only `new_threshold` differs.
                        let resharing = mpc_node::protocol::contract::ResharingContractState {
                            old_epoch: epoch,
                            old_participants: participants.clone(),
                            new_participants: participants,
                            threshold: old_threshold,
                            new_threshold,
                            public_key,
                            finished_votes: Default::default(),
                            cancel_votes: Default::default(),
                        };
                        *protocol_state = Some(ProtocolState::Resharing(resharing));
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
                        "vote_threshold: contract not in Running state, no-op"
                    );
                    false
                }
                None => {
                    tracing::debug!(
                        me = ?self.me,
                        "vote_threshold: no contract state, no-op"
                    );
                    false
                }
            };
            modified
        });
        Ok(result)
    }
}
