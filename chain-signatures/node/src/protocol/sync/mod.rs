use std::sync::Arc;
use std::time::{Duration, Instant};

use cait_sith::protocol::Participant;
use mpc_keys::hpke::{self, Ciphered};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::config::NetworkConfig;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::ProtocolState;
use crate::rpc::ContractStateWatcher;
use crate::storage::{Initializing, PresignatureStorage, StorageError, TripleStorage};

use super::contract::primitives::{ParticipantInfo, ParticipantMap, Participants};
use super::message::{MessageError, SignedMessage};
use super::presignature::PresignatureId;
use super::triple::TripleId;

/// Capacity of the sync report channel. This is pretty much just based on the
/// number of participants in the network. If we have 1024 participants then our
/// issue will more than likely not be the channel size.
const MAX_SYNC_REPORTS: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("not a participant yet")]
    NotParticipant,
    #[error("rejected sync update: {0}")]
    Rejected(MessageError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("failed to encrypt sync response: {0}")]
    Encrypt(MessageError),
}

/// Result of a sync RPC to a single peer.
pub enum SyncPeerResponse {
    /// Self-peer: no RPC was performed.
    SelfPeer,
    /// Peer responded successfully with its view of not_found artifacts.
    Success(SyncUpdate),
    /// RPC to peer failed.
    Failed(String),
}

/// Outcome of handling broadcast responses for a sync cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncResponseOutcome {
    Processed,
    Dropped,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncUpdate {
    pub triples: Vec<TripleId>,
    pub presignatures: Vec<PresignatureId>,
}

impl SyncUpdate {
    pub fn empty() -> Self {
        Self {
            triples: Vec::new(),
            presignatures: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.triples.is_empty() && self.presignatures.is_empty()
    }
}

/// Handle a peer's `/sync` request: drop the artifacts the signer no longer
/// owns and reply, signed and encrypted to the signer, with the ids we do not
/// hold.
pub async fn process_sync_update<P1, P2>(
    update: &Ciphered,
    triples: &TripleStorage<P1>,
    presignatures: &PresignatureStorage<P2>,
    me: Participant,
    network: &NetworkConfig,
    participants: &ParticipantMap,
) -> Result<Ciphered, SyncError> {
    let start = Instant::now();

    // The signer is the owner whose shares we drop.
    let (from, update) = SignedMessage::decrypt_with::<SyncUpdate, _>(
        update,
        &network.cipher_sk,
        participants,
        |_| Ok(()),
    )
    .map_err(SyncError::Rejected)?;

    let outdated_triples = triples.remove_outdated(from, &update.triples).await?;
    let outdated_presignatures = presignatures
        .remove_outdated(from, &update.presignatures)
        .await?;

    tracing::info!(
        removed_triples = outdated_triples.removed.len(),
        removed_presignatures = outdated_presignatures.removed.len(),
        not_found_triples = outdated_triples.not_found.len(),
        not_found_presignatures = outdated_presignatures.not_found.len(),
        elapsed = ?start.elapsed(),
        "processed sync update",
    );

    let response = SyncUpdate {
        triples: outdated_triples.not_found,
        presignatures: outdated_presignatures.not_found,
    };
    // The signature check above found the sender in `participants`.
    let info = participants
        .get(&from)
        .ok_or(SyncError::Rejected(MessageError::Verification(
            "sync sender is not a participant",
        )))?;
    SignedMessage::encrypt(&response, me, &network.sign_sk, &info.cipher_pk)
        .map_err(SyncError::Encrypt)
}

pub struct SyncTask {
    client: NodeClient,
    triples: TripleStorage<Initializing>,
    presignatures: PresignatureStorage<Initializing>,
    mesh_state: watch::Receiver<MeshState>,
    contract: ContractStateWatcher,
    sync_report_tx: SyncReportSender,
    network: NetworkConfig,
}

impl SyncTask {
    pub fn new(
        client: &NodeClient,
        triples: TripleStorage<Initializing>,
        presignatures: PresignatureStorage<Initializing>,
        mesh_state: watch::Receiver<MeshState>,
        contract: ContractStateWatcher,
        sync_report_tx: SyncReportSender,
        network: NetworkConfig,
    ) -> Self {
        Self {
            client: client.clone(),
            triples,
            presignatures,
            mesh_state,
            contract,
            sync_report_tx,
            network,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tracing::info!("sync task has been started");
        // Trigger sync broadcasts to peers in need_sync state
        let mut sync_interval = tokio::time::interval(Duration::from_millis(200));

        loop {
            sync_interval.tick().await;
            self.run_step().await;
        }
    }

    /// Runs a single iteration of the sync cycle if any peers need syncing.
    pub(crate) async fn run_step(&self) {
        let need_sync = self.mesh_state.borrow().need_sync().clone();
        if need_sync.is_empty() {
            return;
        }

        // Skip the sync cycle unless the contract is Running and we are an active participant.
        let Some(ProtocolState::Running(running)) = self.contract.state() else {
            return;
        };
        let Some(&me) = running
            .participants
            .find_participant(self.contract.account_id())
        else {
            return;
        };

        let triples = self.triples.to_ready(me);
        let presignatures = self.presignatures.to_ready(me);

        let Some(update) = Self::new_update(&triples, &presignatures).await else {
            return;
        };
        let start = Instant::now();
        let responses = broadcast_sync(
            self.client.clone(),
            update,
            need_sync.into_iter(),
            me,
            self.network.clone(),
        )
        .await;

        if let Err(err) = self
            .handle_sync_responses(&triples, &presignatures, responses)
            .await
        {
            tracing::warn!(?err, "failed to process sync responses");
        }
        tracing::debug!(elapsed = ?start.elapsed(), "processed broadcast");
    }

    /// Process responses from a sync broadcast if the contract is still running.
    /// Responses are dropped if the contract has transitioned out of the running state.
    pub(crate) async fn handle_sync_responses(
        &self,
        triples: &TripleStorage,
        presignatures: &PresignatureStorage,
        responses: Vec<(Participant, SyncPeerResponse)>,
    ) -> Result<SyncResponseOutcome, String> {
        let Some(ProtocolState::Running(running)) = self.contract.state() else {
            tracing::warn!("contract is not running, dropping sync responses");
            return Ok(SyncResponseOutcome::Dropped);
        };

        self.process_sync_responses(triples, presignatures, responses, running.threshold)
            .await?;
        Ok(SyncResponseOutcome::Processed)
    }

    async fn new_update(
        triples: &TripleStorage,
        presignatures: &PresignatureStorage,
    ) -> Option<SyncUpdate> {
        let triples = match triples.fetch_owned_with_reserved().await {
            Ok(ids) => ids,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to fetch owned triples, skipping sync broadcast"
                );
                return None;
            }
        };
        let presignatures = match presignatures.fetch_owned_with_reserved().await {
            Ok(ids) => ids,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to fetch owned presignatures, skipping sync broadcast"
                );
                return None;
            }
        };

        Some(SyncUpdate {
            triples,
            presignatures,
        })
    }

    /// Process sync responses:
    /// 1. Remove peers from artifact participants if they're missing data
    /// 2. Send synced peer notifications to mesh (for status transitions)
    async fn process_sync_responses(
        &self,
        triples: &TripleStorage,
        presignatures: &PresignatureStorage,
        responses: Vec<(Participant, SyncPeerResponse)>,
        threshold: usize,
    ) -> Result<(), String> {
        for (peer, result) in responses {
            match result {
                SyncPeerResponse::SelfPeer => {
                    if self
                        .sync_report_tx
                        .send((peer, SyncKind::Synced))
                        .await
                        .is_err()
                    {
                        tracing::error!("sync reporter is down: state sync will no longer work");
                        return Err("sync reporter is down".to_string());
                    }
                }
                SyncPeerResponse::Success(response) => {
                    tracing::debug!(
                        ?peer,
                        not_found_triples = response.triples.len(),
                        not_found_presignatures = response.presignatures.len(),
                        "received sync response"
                    );

                    // Batch remove peer from all triples and prune
                    let triple_res = triples
                        .remove_holder_and_prune(peer, threshold, &response.triples)
                        .await;

                    // Batch remove peer from all presignatures and prune
                    let presig_res = presignatures
                        .remove_holder_and_prune(peer, threshold, &response.presignatures)
                        .await;

                    match (triple_res, presig_res) {
                        (Ok((t_removed, t_updated)), Ok((p_removed, p_updated))) => {
                            tracing::info!(
                                ?peer,
                                removed_triples = t_removed.len(),
                                updated_triples = t_updated.len(),
                                removed_presignatures = p_removed.len(),
                                updated_presignatures = p_updated.len(),
                                "batch removed peer from artifacts and pruned"
                            );
                            // Only notify mesh if both succeeded
                            if self
                                .sync_report_tx
                                .send((peer, SyncKind::Synced))
                                .await
                                .is_err()
                            {
                                tracing::error!(
                                    ?peer,
                                    "sync reporter is down: state sync will no longer work"
                                );
                                return Err("sync reporter is down".to_string());
                            }
                        }
                        (triple_res, presig_res) => {
                            tracing::warn!(
                                ?peer,
                                ?triple_res,
                                ?presig_res,
                                "sync batch failed, not notifying mesh"
                            );
                        }
                    }
                }
                SyncPeerResponse::Failed(err) => {
                    tracing::warn!(?peer, ?err, "failed to sync peer");
                }
            }
        }

        Ok(())
    }

    /// Channel for reporting to the mesh which nodes changed sync status.
    /// Sized well above the participant count: a full channel drops whatever
    /// report is being sent, and the cost of losing a desync report is one
    /// more failed round for that peer.
    pub fn sync_report_channel() -> (SyncReportSender, SyncReportReceiver) {
        mpsc::channel(MAX_SYNC_REPORTS)
    }
}

/// Which way a peer's sync status changed. `Synced` comes from the sync task
/// once a peer's artifacts have been reconciled; `Desynced` comes from anyone
/// who learns our record of what that peer stores is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncKind {
    Synced,
    Desynced,
}

pub type SyncReportSender = mpsc::Sender<(Participant, SyncKind)>;
pub type SyncReportReceiver = mpsc::Receiver<(Participant, SyncKind)>;

/// Broadcast an update to all participants specified by `receivers`.
/// Returns results for all peers. Every call is bounded by the client's sync
/// timeout, and peers that fail are retried on a later broadcast.
async fn broadcast_sync(
    client: NodeClient,
    update: SyncUpdate,
    receivers: impl Iterator<Item = (Participant, ParticipantInfo)>,
    me: Participant,
    network: NetworkConfig,
) -> Vec<(Participant, SyncPeerResponse)> {
    let mut tasks = JoinSet::new();
    let update = Arc::new(update);

    for (p, info) in receivers {
        let client = client.clone();
        let update = update.clone();
        let network = network.clone();
        tasks.spawn(async move {
            let sync_result = if p != me {
                match sync_peer(&client, &update, me, &network, p, &info).await {
                    Ok(response) => SyncPeerResponse::Success(response),
                    Err(err) => SyncPeerResponse::Failed(err),
                }
            } else {
                SyncPeerResponse::SelfPeer
            };
            (p, sync_result)
        });
    }

    let mut results = Vec::new();
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok((p, sync_result)) => results.push((p, sync_result)),
            Err(err) => tracing::warn!(?err, "sync task failed"),
        }
    }

    results
}

/// Send our signed update to `peer` and open its signed reply.
async fn sync_peer(
    client: &NodeClient,
    update: &SyncUpdate,
    me: Participant,
    network: &NetworkConfig,
    peer: Participant,
    info: &ParticipantInfo,
) -> Result<SyncUpdate, String> {
    let encrypted = SignedMessage::encrypt(update, me, &network.sign_sk, &info.cipher_pk)
        .map_err(|err| err.to_string())?;
    let reply = client
        .sync(&info.url, &encrypted)
        .await
        .map_err(|err| err.to_string())?;
    open_reply(&reply, &network.cipher_sk, peer, info).map_err(|err| err.to_string())
}

/// Decrypt a sync reply and check it was signed by `peer`, the node we asked.
/// `info` must be `peer`'s entry from the contract.
fn open_reply(
    reply: &Ciphered,
    cipher_sk: &hpke::SecretKey,
    peer: Participant,
    info: &ParticipantInfo,
) -> Result<SyncUpdate, MessageError> {
    let mut only_peer = Participants::default();
    only_peer.insert(&peer, info.clone());
    let (from, reply) = SignedMessage::decrypt_with::<SyncUpdate, _>(
        reply,
        cipher_sk,
        &ParticipantMap::One(only_peer),
        |_| Ok(()),
    )?;
    if from != peer {
        return Err(MessageError::Verification(
            "sync reply was not signed by the peer we asked",
        ));
    }
    Ok(reply)
}

#[cfg(any(test, feature = "test-feature"))]
pub fn open_reply_for_test(
    reply: &Ciphered,
    cipher_sk: &hpke::SecretKey,
    peer: Participant,
    info: &ParticipantInfo,
) -> Result<SyncUpdate, MessageError> {
    open_reply(reply, cipher_sk, peer, info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::connection::NodeStatus;
    use crate::mesh::MeshState;
    use crate::protocol::contract::primitives::Participants;
    use crate::protocol::ProtocolState;
    use crate::rpc::ContractStateWatcher;
    use crate::storage::presignature_storage::Presignature;
    use crate::storage::triple_storage::TriplePair;
    use near_account_id::AccountId;

    struct TestContext {
        me: Participant,
        peer: Participant,
        peer_info: ParticipantInfo,
        contract_tx: tokio::sync::watch::Sender<Option<ProtocolState>>,
        mesh_tx: tokio::sync::watch::Sender<MeshState>,
        sync_task: SyncTask,
        sync_report_rx: SyncReportReceiver,
    }

    impl TestContext {
        fn set_need_sync(&self) {
            let mut mesh = MeshState::default();
            mesh.update(self.peer, NodeStatus::Syncing, self.peer_info.clone());
            self.mesh_tx.send(mesh).unwrap();
        }
    }

    fn send_resharing(contract_tx: &tokio::sync::watch::Sender<Option<ProtocolState>>) {
        contract_tx
            .send(Some(ProtocolState::Resharing(
                crate::protocol::contract::ResharingContractState {
                    old_epoch: 0,
                    old_participants: Participants::default(),
                    new_participants: Participants::default(),
                    threshold: 2,
                    new_threshold: 2,
                    public_key: k256::AffinePoint::default(),
                    finished_votes: Default::default(),
                    cancel_votes: Default::default(),
                },
            )))
            .unwrap();
    }

    fn test_setup(initial_threshold: usize) -> TestContext {
        let my_account: AccountId = "node0.test".parse().unwrap();
        let peer_account: AccountId = "node1.test".parse().unwrap();

        let me = Participant::from(0);
        let peer = Participant::from(1);

        let my_network = NetworkConfig {
            sign_sk: near_crypto::SecretKey::from_seed(
                near_crypto::KeyType::ED25519,
                "my-test-seed",
            ),
            cipher_sk: hpke::SecretKey::from_bytes(&[1; 32]),
        };
        let peer_network = NetworkConfig {
            sign_sk: near_crypto::SecretKey::from_seed(
                near_crypto::KeyType::ED25519,
                "peer-test-seed",
            ),
            cipher_sk: hpke::SecretKey::from_bytes(&[2; 32]),
        };

        let peer_info = ParticipantInfo {
            id: 1,
            account_id: peer_account,
            url: "http://127.0.0.1:2".to_string(),
            cipher_pk: peer_network.cipher_sk.public_key(),
            sign_pk: peer_network.sign_sk.public_key(),
        };

        let mut participants = Participants::default();
        participants.insert(
            &me,
            ParticipantInfo {
                id: 0,
                account_id: my_account.clone(),
                url: "http://127.0.0.1:1".to_string(),
                cipher_pk: my_network.cipher_sk.public_key(),
                sign_pk: my_network.sign_sk.public_key(),
            },
        );
        participants.insert(&peer, peer_info.clone());

        let (contract_watcher, contract_tx) = ContractStateWatcher::with_running(
            &my_account,
            k256::AffinePoint::default(),
            initial_threshold,
            participants,
        );

        let redis_cfg = deadpool_redis::Config::from_url("redis://127.0.0.1/");
        let pool = redis_cfg
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let (sync_report_tx, sync_report_rx) = SyncTask::sync_report_channel();
        let (mesh_tx, mesh_rx) = tokio::sync::watch::channel(MeshState::default());

        let sync_task = SyncTask::new(
            &NodeClient::new(),
            TriplePair::storage(&pool, &my_account),
            Presignature::storage(&pool, &my_account),
            mesh_rx,
            contract_watcher,
            sync_report_tx,
            my_network,
        );

        TestContext {
            me,
            peer,
            peer_info,
            contract_tx,
            mesh_tx,
            sync_task,
            sync_report_rx,
        }
    }

    #[tokio::test]
    async fn test_handle_sync_responses_processed_when_running() {
        let TestContext {
            me,
            peer,
            sync_task,
            mut sync_report_rx,
            ..
        } = test_setup(2);

        let responses = vec![(peer, SyncPeerResponse::Success(SyncUpdate::empty()))];
        let triples = sync_task.triples.to_ready(me);
        let presignatures = sync_task.presignatures.to_ready(me);

        let outcome = sync_task
            .handle_sync_responses(&triples, &presignatures, responses)
            .await
            .unwrap();

        assert_eq!(outcome, SyncResponseOutcome::Processed);
        assert_eq!(sync_report_rx.try_recv(), Ok((peer, SyncKind::Synced)));
    }

    #[tokio::test]
    async fn test_handle_sync_responses_dropped_when_not_running() {
        let TestContext {
            me,
            peer,
            contract_tx,
            sync_task,
            mut sync_report_rx,
            ..
        } = test_setup(2);

        let responses = vec![(peer, SyncPeerResponse::Success(SyncUpdate::empty()))];
        send_resharing(&contract_tx);

        let triples = sync_task.triples.to_ready(me);
        let presignatures = sync_task.presignatures.to_ready(me);

        let outcome = sync_task
            .handle_sync_responses(&triples, &presignatures, responses)
            .await
            .unwrap();

        // Responses must be dropped because contract is no longer Running
        assert_eq!(outcome, SyncResponseOutcome::Dropped);
        assert!(sync_report_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_run_step_skips_when_not_running() {
        let mut ctx = test_setup(2);
        ctx.set_need_sync();
        send_resharing(&ctx.contract_tx);

        ctx.sync_task.run_step().await;

        assert!(ctx.sync_report_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_run_step_skips_when_not_participant() {
        let mut ctx = test_setup(2);
        ctx.set_need_sync();

        // Remove our node from contract participants
        let mut participants = Participants::default();
        participants.insert(&ctx.peer, ctx.peer_info.clone());
        ctx.contract_tx
            .send(Some(ProtocolState::Running(
                crate::protocol::contract::RunningContractState {
                    epoch: 0,
                    participants,
                    threshold: 1,
                    public_key: k256::AffinePoint::default(),
                    leave_votes: Default::default(),
                    threshold_votes: Default::default(),
                },
            )))
            .unwrap();

        ctx.sync_task.run_step().await;

        assert!(ctx.sync_report_rx.try_recv().is_err());
    }
}
