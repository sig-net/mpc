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
            let mut modified;
            match protocol_state {
                Some(ProtocolState::Initializing(ref mut state)) => {
                    let entry = state
                        .pk_votes
                        .pk_votes
                        .entry(public_key.clone())
                        .or_default();

                    modified = entry.insert(self.me.clone());

                    if entry.len() >= state.threshold {
                        *protocol_state = Some(ProtocolState::Running(RunningContractState {
                            epoch: 0,
                            participants: state.candidates.clone().into(),
                            threshold: state.threshold,
                            public_key: public_key.clone().into_affine_point(),
                            candidates: Default::default(),
                            join_votes: Default::default(),
                            leave_votes: Default::default(),
                        }));
                        result = true;
                        modified = true;
                    }
                }

                Some(_) => todo!(),
                None => todo!(),
            }
            modified
        });
        Ok(result)
    }
}
