use super::contract::{ProtocolState, ResharingContractState};
use super::state::{
    JoiningState, NodeState, PersistentNodeData, RunningState, StartedState,
    WaitingForConsensusState,
};
use super::MpcSignProtocol;
use crate::protocol::contract::primitives::Participants;
use crate::protocol::presignature::PresignatureSpawnerTask;
use crate::protocol::signature::SignatureManager;
use crate::protocol::state::{GeneratingState, ResharingState};
use crate::protocol::triple::TripleSpawnerTask;
use crate::types::{KeygenProtocol, ReshareProtocol, SecretKeyShare};
use crate::util::AffinePointExt;

use std::cmp::Ordering;
use std::sync::Arc;

use tokio::sync::RwLock;

pub(crate) trait ConsensusProtocol {
    async fn advance(self, ctx: &mut MpcSignProtocol, contract_state: ProtocolState) -> NodeState;
}

impl ConsensusProtocol for StartedState {
    async fn advance(self, ctx: &mut MpcSignProtocol, contract_state: ProtocolState) -> NodeState {
        match self.persistent_node_data {
            Some(PersistentNodeData {
                epoch,
                private_share,
                public_key,
            }) => match contract_state {
                ProtocolState::Initializing(contract_state) => {
                    tracing::warn!(
                        ?contract_state,
                        "started(initializing): contract state has not been finalized yet"
                    );
                    NodeState::Started(self)
                }
                ProtocolState::Running(contract_state) => {
                    if contract_state.public_key != public_key {
                        tracing::warn!(
                            node_pk = ?public_key,
                            contract_pk = ?contract_state.public_key,
                            "started(running): our public key is different from the contract, rejoining...",
                        );
                        return NodeState::Joining(JoiningState {
                            participants: contract_state.participants,
                            public_key,
                        });
                    }
                    match contract_state.epoch.cmp(&epoch) {
                        Ordering::Greater => {
                            tracing::warn!(
                                node_epoch = epoch,
                                contract_epoch = contract_state.epoch,
                                "started(running): our current epoch is less than contract, rejoining...",
                            );
                            NodeState::Joining(JoiningState {
                                participants: contract_state.participants,
                                public_key,
                            })
                        }
                        Ordering::Less => {
                            tracing::error!(
                                node_epoch = epoch,
                                contract_epoch = contract_state.epoch,
                                "started(running): unexpected, our current epoch is greater than contract, rejoining...",
                            );
                            NodeState::Joining(JoiningState {
                                participants: contract_state.participants,
                                public_key,
                            })
                        }
                        Ordering::Equal => {
                            let Some(&me) = contract_state
                                .participants
                                .find_participant(&ctx.my_account_id)
                            else {
                                return NodeState::Joining(JoiningState {
                                    participants: contract_state.participants,
                                    public_key,
                                });
                            };

                            tracing::info!(
                                "started: contract state is running and we are already a participant"
                            );

                            let threshold = contract_state.threshold;
                            let triple_task = TripleSpawnerTask::run(me, threshold, epoch, ctx);
                            let presign_task = PresignatureSpawnerTask::run(
                                me,
                                threshold,
                                epoch,
                                ctx,
                                &private_share,
                                &public_key,
                            );

                            let signature_manager = Arc::new(RwLock::new(SignatureManager::new(
                                me,
                                &ctx.my_account_id,
                                contract_state.threshold,
                                public_key,
                                epoch,
                                ctx.sign_rx.clone(),
                                &ctx.presignature_storage,
                                ctx.msg_channel.clone(),
                            )));

                            NodeState::Running(RunningState {
                                epoch,
                                me,
                                participants: contract_state.participants,
                                threshold: contract_state.threshold,
                                private_share,
                                public_key,
                                triple_task,
                                presign_task,
                                signature_manager,
                            })
                        }
                    }
                }
                ProtocolState::Resharing(contract_state) => {
                    if contract_state.public_key != public_key {
                        tracing::warn!(
                            node_pk = ?public_key,
                            contract_pk = ?contract_state.public_key,
                            "started(resharing): our public key is different from the contract, rejoining...",
                        );
                        return NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key,
                        });
                    }
                    match contract_state.old_epoch.cmp(&epoch) {
                        Ordering::Greater => {
                            tracing::warn!(
                                node_epoch = epoch,
                                contract_epoch = contract_state.old_epoch,
                                "started(resharing): contract epoch is greater than node epoch, rejoining...",
                            );
                            NodeState::Joining(JoiningState {
                                participants: contract_state.old_participants,
                                public_key,
                            })
                        }
                        Ordering::Less => {
                            tracing::error!(
                                node_epoch = epoch,
                                contract_epoch = contract_state.old_epoch,
                                "started(resharing): unexpected, contract epoch is less than node epoch, rejoining...",
                            );
                            NodeState::Joining(JoiningState {
                                participants: contract_state.old_participants,
                                public_key,
                            })
                        }
                        Ordering::Equal => {
                            tracing::info!(
                                "started(resharing): contract state is resharing with us, joining as a participant"
                            );
                            start_resharing(Some(private_share), ctx, contract_state).await
                        }
                    }
                }
            },
            None => match contract_state {
                ProtocolState::Initializing(contract_state) => {
                    let participants: Participants = contract_state.candidates.clone().into();
                    let Some(&me) = participants.find_participant(&ctx.my_account_id) else {
                        tracing::info!("started(initializing): we are not a part of the initial participant set, waiting for key generation to complete");
                        return NodeState::Started(self);
                    };

                    tracing::info!(
                        "started(initializing): starting key generation as a part of the participant set"
                    );
                    let protocol = match KeygenProtocol::new(
                        &participants.keys_vec(),
                        me,
                        contract_state.threshold,
                    ) {
                        Ok(protocol) => protocol,
                        Err(err) => {
                            tracing::error!(
                                ?err,
                                "started(initializing): failed to initialize key generation"
                            );
                            return NodeState::Started(self);
                        }
                    };
                    NodeState::Generating(GeneratingState {
                        me,
                        participants,
                        threshold: contract_state.threshold,
                        protocol,
                        failed_store: Default::default(),
                    })
                }
                ProtocolState::Running(contract_state) => NodeState::Joining(JoiningState {
                    participants: contract_state.participants,
                    public_key: contract_state.public_key,
                }),
                ProtocolState::Resharing(contract_state) => NodeState::Joining(JoiningState {
                    participants: contract_state.old_participants,
                    public_key: contract_state.public_key,
                }),
            },
        }
    }
}

impl ConsensusProtocol for GeneratingState {
    async fn advance(self, _ctx: &mut MpcSignProtocol, contract_state: ProtocolState) -> NodeState {
        match contract_state {
            ProtocolState::Initializing(_) => {
                tracing::info!("generating(initializing): continuing generation, contract state has not been finalized yet");
                NodeState::Generating(self)
            }
            ProtocolState::Running(contract_state) => {
                tracing::info!("generating(running): contract state has finished key generation, trying to catch up");
                if contract_state.epoch > 0 {
                    tracing::warn!(
                        "generating(running): contract has already changed epochs, rejoining..."
                    );
                    return NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    });
                }
                if self.participants != contract_state.participants {
                    tracing::warn!(
                        node_participants = ?self.participants,
                        contract_participants = ?contract_state.participants,
                        "generating(running): our participants do not match contract",
                    );
                    return NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    });
                }
                if self.threshold != contract_state.threshold {
                    tracing::warn!(
                        node_threshold = self.threshold,
                        contract_threshold = contract_state.threshold,
                        "generating(running): our threshold does not match contract",
                    );
                    return NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    });
                }
                NodeState::Generating(self)
            }
            ProtocolState::Resharing(contract_state) => {
                tracing::warn!("generating(resharing): contract state is resharing without us, trying to catch up");
                if contract_state.old_epoch > 0 {
                    tracing::warn!(
                        "generating(resharing): contract has already changed epochs, rejoining..."
                    );
                    return NodeState::Joining(JoiningState {
                        participants: contract_state.old_participants,
                        public_key: contract_state.public_key,
                    });
                }
                if self.participants != contract_state.old_participants {
                    tracing::warn!(
                        node_participants = ?self.participants,
                        contract_participants = ?contract_state.old_participants,
                        "generating(resharing): our participants do not match contract",
                    );
                    return NodeState::Joining(JoiningState {
                        participants: contract_state.old_participants,
                        public_key: contract_state.public_key,
                    });
                }
                if self.threshold != contract_state.threshold {
                    tracing::warn!(
                        node_threshold = self.threshold,
                        contract_threshold = contract_state.threshold,
                        "generating(resharing): our threshold does not match contract",
                    );
                    return NodeState::Joining(JoiningState {
                        participants: contract_state.old_participants,
                        public_key: contract_state.public_key,
                    });
                }
                NodeState::Generating(self)
            }
        }
    }
}

impl ConsensusProtocol for WaitingForConsensusState {
    async fn advance(self, ctx: &mut MpcSignProtocol, contract_state: ProtocolState) -> NodeState {
        match contract_state {
            ProtocolState::Initializing(contract_state) => {
                tracing::info!("waiting(initializing): waiting for consensus, contract state has not been finalized yet");
                let public_key = self.public_key.into_near_public_key();
                let has_voted = contract_state
                    .pk_votes
                    .get(&public_key)
                    .map(|ps| ps.contains(&ctx.my_account_id))
                    .unwrap_or_default();
                if !has_voted {
                    tracing::info!("waiting(initializing): we haven't voted yet, voting for the generated public key");
                    if let Err(err) = ctx.near.vote_public_key(&public_key).await {
                        tracing::error!(
                            ?err,
                            "waiting(initializing): failed to vote for the generated public key, retrying..."
                        );
                    }
                }
                NodeState::WaitingForConsensus(self)
            }
            ProtocolState::Running(contract_state) => match contract_state.epoch.cmp(&self.epoch) {
                Ordering::Greater => {
                    tracing::warn!(
                        node_epoch = self.epoch,
                        contract_epoch = contract_state.epoch,
                        "waiting(running): our current epoch is behind contract epoch, rejoining...",
                    );
                    NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    })
                }
                Ordering::Less => {
                    tracing::error!(
                        node_epoch = self.epoch,
                        contract_epoch = contract_state.epoch,
                        "waiting(running, unexpected): our current epoch is ahead of contract, rejoining...",
                    );
                    NodeState::Joining(JoiningState {
                        participants: contract_state.participants,
                        public_key: contract_state.public_key,
                    })
                }
                Ordering::Equal => {
                    tracing::info!("waiting(running): contract state has reached consensus");
                    if contract_state.participants != self.participants {
                        tracing::warn!(
                            node_participants = ?self.participants,
                            contract_participants = ?contract_state.participants,
                            "waiting(running): our participants do not match contract",
                        );
                        return NodeState::Joining(JoiningState {
                            participants: contract_state.participants,
                            public_key: contract_state.public_key,
                        });
                    }
                    if contract_state.threshold != self.threshold {
                        tracing::warn!(
                            node_threshold = self.threshold,
                            contract_threshold = contract_state.threshold,
                            "waiting(running): our threshold does not match contract",
                        );
                        return NodeState::Joining(JoiningState {
                            participants: contract_state.participants,
                            public_key: contract_state.public_key,
                        });
                    }
                    if contract_state.public_key != self.public_key {
                        tracing::warn!(
                            node_pk = ?self.public_key,
                            contract_pk = ?contract_state.public_key,
                            "waiting(running): our public key does not match contract",
                        );
                        return NodeState::Joining(JoiningState {
                            participants: contract_state.participants,
                            public_key: contract_state.public_key,
                        });
                    }

                    let Some(&me) = contract_state
                        .participants
                        .find_participant(&ctx.my_account_id)
                    else {
                        tracing::error!("waiting(running, unexpected): we do not belong to the participant set -- cannot progress!");
                        return NodeState::WaitingForConsensus(self);
                    };

                    let triple_task = TripleSpawnerTask::run(me, self.threshold, self.epoch, ctx);
                    let presign_task = PresignatureSpawnerTask::run(
                        me,
                        self.threshold,
                        self.epoch,
                        ctx,
                        &self.private_share,
                        &self.public_key,
                    );

                    let signature_manager = Arc::new(RwLock::new(SignatureManager::new(
                        me,
                        &ctx.my_account_id,
                        self.threshold,
                        self.public_key,
                        self.epoch,
                        ctx.sign_rx.clone(),
                        &ctx.presignature_storage,
                        ctx.msg_channel.clone(),
                    )));

                    NodeState::Running(RunningState {
                        epoch: self.epoch,
                        me,
                        participants: self.participants,
                        threshold: self.threshold,
                        private_share: self.private_share,
                        public_key: self.public_key,
                        triple_task,
                        presign_task,
                        signature_manager,
                    })
                }
            },
            ProtocolState::Resharing(contract_state) => {
                match (contract_state.old_epoch + 1).cmp(&self.epoch) {
                    Ordering::Greater => {
                        tracing::warn!(
                            node_epoch = self.epoch,
                            contract_old_epoch = contract_state.old_epoch,
                            "waiting(resharing, unexpected): our current epoch is behind contract, rejoining...",
                        );

                        NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        })
                    }
                    Ordering::Less => {
                        tracing::error!(
                            node_epoch = self.epoch,
                            contract_old_epoch = contract_state.old_epoch,
                            "waiting(resharing, unexpected): our current epoch is ahead of contract, trying to rejoin as a new participant",
                        );
                        NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        })
                    }
                    Ordering::Equal => {
                        tracing::info!(
                            "waiting(resharing): waiting for resharing consensus, contract state has not been finalized yet"
                        );
                        let has_voted = contract_state.finished_votes.contains(&ctx.my_account_id);
                        let Some(_me) = contract_state
                            .old_participants
                            .find_participant(&ctx.my_account_id)
                        else {
                            tracing::info!(
                                "waiting(resharing): we are not a part of the old participant set"
                            );
                            return NodeState::WaitingForConsensus(self);
                        };
                        if !has_voted {
                            tracing::info!(
                                epoch = self.epoch,
                                "waiting(resharing): we haven't voted yet, voting for resharing to complete"
                            );
                            if let Err(err) = ctx.near.vote_reshared(self.epoch).await {
                                tracing::error!(
                                    ?err,
                                    "waiting(resharing): failed to vote for resharing to complete, retrying..."
                                );
                            }
                        } else {
                            tracing::debug!(
                                epoch = self.epoch,
                                "waiting(resharing): we have voted for resharing to complete"
                            );
                        }
                        NodeState::WaitingForConsensus(self)
                    }
                }
            }
        }
    }
}

impl ConsensusProtocol for RunningState {
    async fn advance(
        mut self,
        ctx: &mut MpcSignProtocol,
        contract_state: ProtocolState,
    ) -> NodeState {
        match contract_state {
            ProtocolState::Initializing(_) => {
                tracing::warn!(
                    "running(initializing): contract is initializing, staying in running"
                );
                NodeState::Running(self)
            }
            ProtocolState::Running(contract_state) => {
                match contract_state.epoch.cmp(&self.epoch) {
                    Ordering::Greater => {
                        tracing::warn!(
                            node_epoch = self.epoch,
                            contract_epoch = contract_state.epoch,
                            "running: running contract has epoch ahead, rejoining...",
                        );

                        NodeState::Joining(JoiningState {
                            participants: contract_state.participants,
                            public_key: contract_state.public_key,
                        })
                    }
                    Ordering::Less => {
                        tracing::error!(
                            node_epoch = self.epoch,
                            contract_epoch = contract_state.epoch,
                            "running(unexpected): our current epoch is ahead of contract, rejoining...",
                        );
                        NodeState::Joining(JoiningState {
                            participants: contract_state.participants,
                            public_key: contract_state.public_key,
                        })
                    }
                    Ordering::Equal => {
                        tracing::debug!("running(running): continuing to run as normal");
                        if contract_state.public_key != self.public_key {
                            tracing::warn!(
                                node_pk = ?self.public_key,
                                contract_pk = ?contract_state.public_key,
                                "running(running): our public key does not match contract, rejoining...",
                            );
                            return NodeState::Joining(JoiningState {
                                participants: contract_state.participants,
                                public_key: contract_state.public_key,
                            });
                        }
                        if contract_state.participants != self.participants {
                            tracing::warn!(
                                node_participants = ?self.participants,
                                contract_participants = ?contract_state.participants,
                                "running(running): our participants do not match contract...",
                            );
                            if contract_state.participants.contains_key(&self.me) {
                                tracing::warn!("running(running): ... but we are still a participant, overriding");
                                self.participants = contract_state.participants;
                            } else {
                                tracing::warn!(
                                "running(running): ... but we are not a participant anymore, rejoining...",
                            );
                                return NodeState::Joining(JoiningState {
                                    participants: contract_state.participants,
                                    public_key: contract_state.public_key,
                                });
                            }
                        }
                        if contract_state.threshold != self.threshold {
                            tracing::warn!(
                            node_threshold = self.threshold,
                            contract_threshold = contract_state.threshold,
                            "running(running): our threshold does not match contract, overriding",
                        );
                            self.threshold = contract_state.threshold;
                        }
                        NodeState::Running(self)
                    }
                }
            }
            ProtocolState::Resharing(contract_state) => {
                match contract_state.old_epoch.cmp(&self.epoch) {
                    Ordering::Greater => {
                        tracing::warn!(
                            node_epoch = self.epoch,
                            contract_epoch = contract_state.old_epoch,
                            "running(resharing): our current epoch is behind contract, rejoining...",
                        );
                        NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        })
                    }
                    Ordering::Less => {
                        tracing::error!(
                            node_epoch = self.epoch,
                            contract_epoch = contract_state.old_epoch,
                            "running(resharing, unexpected): our current epoch is ahead of contract, rejoining...",
                        );
                        NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        })
                    }
                    Ordering::Equal => {
                        tracing::info!("running(resharing): contract is resharing");
                        let is_in_old_participant_set = contract_state
                            .old_participants
                            .contains_account_id(&ctx.my_account_id);
                        let is_in_new_participant_set = contract_state
                            .new_participants
                            .contains_account_id(&ctx.my_account_id);
                        if !is_in_old_participant_set || !is_in_new_participant_set {
                            tracing::error!(
                                "running(resharing): we have been kicked, rejoining..."
                            );
                            return NodeState::Joining(JoiningState {
                                participants: contract_state.old_participants,
                                public_key: contract_state.public_key,
                            });
                        }
                        if contract_state.public_key != self.public_key {
                            tracing::warn!(
                                node_pk = ?self.public_key,
                                contract_pk = ?contract_state.public_key,
                                "running(resharing): our public key does not match contract, rejoining...",
                            );
                            return NodeState::Joining(JoiningState {
                                participants: contract_state.new_participants,
                                public_key: contract_state.public_key,
                            });
                        }
                        start_resharing(Some(self.private_share), ctx, contract_state).await
                    }
                }
            }
        }
    }
}

impl ConsensusProtocol for ResharingState {
    async fn advance(self, _ctx: &mut MpcSignProtocol, contract_state: ProtocolState) -> NodeState {
        match contract_state {
            ProtocolState::Initializing(_) => {
                tracing::info!(
                    "resharing(initializing): continue reshare, wait for contract finalization"
                );
                NodeState::Resharing(self)
            }
            ProtocolState::Running(contract_state) => {
                match contract_state.epoch.cmp(&(self.old_epoch + 1)) {
                    Ordering::Greater => {
                        tracing::warn!(
                            next_epoch = self.old_epoch + 1,
                            contract_epoch = contract_state.epoch,
                            "resharing(running): our next epoch is behind contract, rejoining...",
                        );
                        NodeState::Joining(JoiningState {
                            participants: contract_state.participants,
                            public_key: contract_state.public_key,
                        })
                    }
                    Ordering::Less => {
                        tracing::error!(
                            next_epoch = self.old_epoch + 1,
                            contract_epoch = contract_state.epoch,
                            "resharing(running, unexpected): our next epoch is ahead of contract, rejoining...",
                        );
                        NodeState::Joining(JoiningState {
                            participants: contract_state.participants,
                            public_key: contract_state.public_key,
                        })
                    }
                    Ordering::Equal => {
                        tracing::info!("resharing(running): contract state has finished resharing, trying to catch up");
                        if contract_state.public_key != self.public_key {
                            tracing::warn!(
                                node_pk = ?self.public_key,
                                contract_pk = ?contract_state.public_key,
                                "resharing(running): our public key does not match contract, rejoining...",
                            );
                            return NodeState::Joining(JoiningState {
                                participants: contract_state.participants,
                                public_key: contract_state.public_key,
                            });
                        }
                        if contract_state.participants != self.new_participants {
                            tracing::warn!(
                                node_participants = ?self.new_participants,
                                contract_participants = ?contract_state.participants,
                                "resharing(running): our participants do not match contract, rejoining...",
                            );
                            return NodeState::Joining(JoiningState {
                                participants: contract_state.participants,
                                public_key: contract_state.public_key,
                            });
                        }
                        if contract_state.threshold != self.threshold {
                            tracing::warn!(
                                node_threshold = self.threshold,
                                contract_threshold = contract_state.threshold,
                                "resharing(running): our threshold does not match contract, rejoining...",
                            );
                            return NodeState::Joining(JoiningState {
                                participants: contract_state.participants,
                                public_key: contract_state.public_key,
                            });
                        }
                        NodeState::Resharing(self)
                    }
                }
            }
            ProtocolState::Resharing(contract_state) => {
                match contract_state.old_epoch.cmp(&self.old_epoch) {
                    Ordering::Greater => {
                        tracing::warn!(
                            old_epoch = self.old_epoch,
                            contract_old_epoch = contract_state.old_epoch,
                            "resharing(resharing): our epoch is different from contract, rejoining...",
                        );
                        NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        })
                    }
                    Ordering::Less => {
                        tracing::error!(
                            old_epoch = self.old_epoch,
                            contract_old_epoch = contract_state.old_epoch,
                            "resharing(resharing, unexpected): our epoch is ahead of contract, rejoining...",
                        );
                        NodeState::Joining(JoiningState {
                            participants: contract_state.old_participants,
                            public_key: contract_state.public_key,
                        })
                    }
                    Ordering::Equal => {
                        tracing::info!("resharing(resharing): continue to reshare as normal");
                        if contract_state.public_key != self.public_key {
                            tracing::warn!(
                                node_pk = ?self.public_key,
                                contract_pk = ?contract_state.public_key,
                                "resharing(resharing): our public key does not match contract, rejoining...",
                            );
                            return NodeState::Joining(JoiningState {
                                participants: contract_state.old_participants,
                                public_key: contract_state.public_key,
                            });
                        }
                        if contract_state.old_participants != self.old_participants {
                            tracing::warn!(
                                node_participants = ?self.old_participants,
                                contract_participants = ?contract_state.old_participants,
                                "resharing(resharing): our old participants do not match contract, rejoining...",
                            );
                            return NodeState::Joining(JoiningState {
                                participants: contract_state.old_participants,
                                public_key: contract_state.public_key,
                            });
                        }
                        if contract_state.new_participants != self.new_participants {
                            tracing::warn!(
                                node_participants = ?self.new_participants,
                                contract_participants = ?contract_state.new_participants,
                                "resharing(resharing): our new participants do not match contract, rejoining...",
                            );
                            return NodeState::Joining(JoiningState {
                                participants: contract_state.old_participants,
                                public_key: contract_state.public_key,
                            });
                        }
                        if contract_state.threshold != self.threshold {
                            tracing::warn!(
                                node_threshold = self.threshold,
                                contract_threshold = contract_state.threshold,
                                "resharing(resharing): our threshold does not match contract, rejoining...",
                            );
                            return NodeState::Joining(JoiningState {
                                participants: contract_state.old_participants,
                                public_key: contract_state.public_key,
                            });
                        }
                        NodeState::Resharing(self)
                    }
                }
            }
        }
    }
}

impl ConsensusProtocol for JoiningState {
    async fn advance(self, ctx: &mut MpcSignProtocol, contract_state: ProtocolState) -> NodeState {
        match contract_state {
            ProtocolState::Initializing(contract_state) => {
                let participants: Participants = contract_state.candidates.clone().into();
                let Some(&me) = participants.find_participant(&ctx.my_account_id) else {
                    tracing::info!("joining(initializing): contract is generating key without us");
                    return NodeState::Joining(self);
                };

                tracing::info!(
                    "joining(initializing): contract is doing keygen with us, need to join"
                );
                let protocol = match KeygenProtocol::new(
                    &participants.keys_vec(),
                    me,
                    contract_state.threshold,
                ) {
                    Ok(protocol) => protocol,
                    Err(err) => {
                        tracing::error!(?err, "joining(initializing): failed to initialize keygen");
                        return NodeState::Joining(self);
                    }
                };
                NodeState::Generating(GeneratingState {
                    me,
                    participants,
                    threshold: contract_state.threshold,
                    protocol,
                    failed_store: Default::default(),
                })
            }
            ProtocolState::Running(contract_state) => {
                let Some(_) = contract_state.candidates.find_candidate(&ctx.my_account_id) else {
                    tracing::info!(
                        "joining(running): sending a transaction to join the participant set"
                    );
                    if let Err(err) = ctx.near.propose_join().await {
                        tracing::error!(?err, "failed to propose to join the participant set");
                    }
                    return NodeState::Joining(self);
                };
                let votes = contract_state
                    .join_votes
                    .get(&ctx.my_account_id)
                    .cloned()
                    .unwrap_or_default();
                let pending_votes = contract_state
                    .participants
                    .iter()
                    .map(|(_, info)| &info.account_id)
                    .filter(|id| !votes.contains(*id))
                    .collect::<Vec<_>>();
                if !pending_votes.is_empty() {
                    tracing::info!(
                        ?pending_votes,
                        "some participants have not voted for you to join yet",
                    );
                }
                NodeState::Joining(self)
            }
            ProtocolState::Resharing(contract_state) => {
                if contract_state
                    .new_participants
                    .contains_account_id(&ctx.my_account_id)
                {
                    tracing::info!("joining(resharing): joining as a new participant");
                    start_resharing(None, ctx, contract_state).await
                } else {
                    tracing::info!("joining(resharing): network is resharing without us, waiting for them to finish");
                    NodeState::Joining(self)
                }
            }
        }
    }
}

impl ConsensusProtocol for NodeState {
    async fn advance(self, ctx: &mut MpcSignProtocol, contract_state: ProtocolState) -> NodeState {
        match self {
            NodeState::Starting => {
                let persistent_node_data = match ctx.secret_storage.load().await {
                    Ok(data) => data,
                    Err(err) => {
                        tracing::error!(?err, "failed to load persistent node data, retrying...");
                        return NodeState::Starting;
                    }
                };
                NodeState::Started(StartedState {
                    persistent_node_data,
                })
            }
            NodeState::Started(state) => state.advance(ctx, contract_state).await,
            NodeState::Generating(state) => state.advance(ctx, contract_state).await,
            NodeState::WaitingForConsensus(state) => state.advance(ctx, contract_state).await,
            NodeState::Running(state) => state.advance(ctx, contract_state).await,
            NodeState::Resharing(state) => state.advance(ctx, contract_state).await,
            NodeState::Joining(state) => state.advance(ctx, contract_state).await,
        }
    }
}

async fn start_resharing(
    private_share: Option<SecretKeyShare>,
    ctx: &MpcSignProtocol,
    contract_state: ResharingContractState,
) -> NodeState {
    let Some(&me) = contract_state
        .new_participants
        .find_participant(&ctx.my_account_id)
    else {
        return NodeState::Joining(JoiningState {
            participants: contract_state.new_participants,
            public_key: contract_state.public_key,
        });
    };
    let protocol = match ReshareProtocol::new(private_share, me, &contract_state) {
        Ok(protocol) => protocol,
        Err(err) => {
            tracing::error!(?err, "resharing: failed to initialize resharing protocol");
            return NodeState::Joining(JoiningState {
                participants: contract_state.new_participants,
                public_key: contract_state.public_key,
            });
        }
    };
    NodeState::Resharing(ResharingState {
        me,
        old_epoch: contract_state.old_epoch,
        old_participants: contract_state.old_participants,
        new_participants: contract_state.new_participants,
        threshold: contract_state.threshold,
        public_key: contract_state.public_key,
        protocol,
        failed_store: Default::default(),
    })
}
