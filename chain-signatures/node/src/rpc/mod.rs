mod canton;
mod ethereum;
mod hydration;
mod near;
mod solana;

use crate::config::Config;
use crate::indexer_eth::EthConfig;
use crate::indexer_sol::SolConfig;
use crate::metrics::requests::{record_request_latency_since, SignRequestStep};
use crate::protocol::contract::primitives::{ParticipantMap, Participants};
use crate::protocol::contract::RunningContractState;
use crate::protocol::{Chain, IndexedSignRequest, ProtocolState};
use crate::util::retry::{retry_rpc, RetryConfig};
use std::collections::BTreeSet;

pub use canton::{try_publish_canton, CantonClient};
pub use ethereum::EthClient;
pub use hydration::{try_publish_hydration, HydrationClient};
pub use mpc_contract::primitives::{Read, View};
pub use near::{try_publish_near, NearClient};
pub use solana::try_publish_sol;

use enum_map::EnumMap;

use cait_sith::protocol::Participant;
use cait_sith::FullSignature;
use k256::{AffinePoint, Secp256k1};
use mpc_primitives::{CheckpointDigest, SignId, Signature};

use crate::indexer_canton::CantonConfig;
use crate::indexer_hydration::HydrationConfig;
use crate::indexer_sol::SolanaClient;

use near_account_id::AccountId;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

/// The maximum amount of times to retry publishing a signature.
const MAX_PUBLISH_RETRY: usize = 6;
/// The maximum number of concurrent RPC requests the system can make
const MAX_CONCURRENT_RPC_REQUESTS: usize = 1024;
/// The update interval to fetch and update the contract's state
const UPDATE_INTERVAL: Duration = Duration::from_secs(10);
/// The interval to batch send Ethereum responses
pub const ETH_RESPOND_BATCH_INTERVAL: Duration = Duration::from_millis(2000);
/// The batch size for Ethereum responses
pub const ETH_RESPOND_BATCH_SIZE: usize = 10;

// Publish retry constants
const PUBLISH_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(120);
const PUBLISH_FIXED_DELAY: Duration = Duration::from_secs(5);
const BATCH_PUBLISH_MIN_DELAY: Duration = Duration::from_secs(1);
const BATCH_PUBLISH_MAX_DELAY: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct PublishAction {
    pub public_key: mpc_crypto::PublicKey,
    pub indexed: IndexedSignRequest,
    pub signature: Signature,
    pub participants: Vec<Participant>,
    pub timestamp: Instant,
}

impl PublishAction {
    pub fn new(
        public_key: mpc_crypto::PublicKey,
        indexed: IndexedSignRequest,
        output: FullSignature<Secp256k1>,
        participants: Vec<Participant>,
    ) -> Option<Self> {
        let expected_public_key = mpc_crypto::derive_key(public_key, indexed.args.epsilon);
        let signature = crate::kdf::into_signature(
            &expected_public_key,
            &output.big_r,
            &output.s,
            indexed.args.payload,
        )
        .ok()?;
        Some(Self {
            public_key,
            indexed,
            signature,
            participants,
            timestamp: Instant::now(),
        })
    }
}

pub enum RpcAction {
    Publish(PublishAction),
}

#[derive(Debug, Clone)]
pub struct GovernanceInfo {
    pub me: Participant,
    pub threshold: usize,
    pub epoch: u64,
    pub public_key: mpc_crypto::PublicKey,
    pub participants: BTreeSet<Participant>,
    pub is_running: bool,
}

#[derive(Clone)]
pub struct RpcChannel {
    pub tx: mpsc::Sender<RpcAction>,
}

impl RpcChannel {
    pub fn publish(
        &self,
        public_key: mpc_crypto::PublicKey,
        indexed: IndexedSignRequest,
        output: FullSignature<Secp256k1>,
        participants: Vec<Participant>,
    ) {
        let sign_id = indexed.id;
        let Some(action) = PublishAction::new(public_key, indexed, output, participants) else {
            tracing::error!(
                ?sign_id,
                "failed to validate signature; trashing publish request",
            );
            return;
        };
        let rpc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rpc.tx.send(RpcAction::Publish(action)).await {
                tracing::error!(%err, "failed to send publish action");
            }
        });
    }

    pub fn publish_signature(
        &self,
        public_key: mpc_crypto::PublicKey,
        indexed: IndexedSignRequest,
        signature: Signature,
        participants: Vec<Participant>,
    ) {
        let rpc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rpc
                .tx
                .send(RpcAction::Publish(PublishAction {
                    public_key,
                    indexed,
                    signature,
                    participants,
                    timestamp: Instant::now(),
                }))
                .await
            {
                tracing::error!(%err, "failed to send publish action");
            }
        });
    }
}

#[derive(Clone)]
pub struct ContractStateWatcher {
    account_id: AccountId,
    contract_state: watch::Receiver<Option<ProtocolState>>,
}

impl ContractStateWatcher {
    pub fn new(id: &AccountId) -> (Self, watch::Sender<Option<ProtocolState>>) {
        let (tx, rx) = watch::channel(None);
        (
            Self {
                account_id: id.clone(),
                contract_state: rx,
            },
            tx,
        )
    }

    pub fn with(
        id: &AccountId,
        state: ProtocolState,
    ) -> (Self, watch::Sender<Option<ProtocolState>>) {
        // Set the initial state to be None so that `changed()` will pick up the first state change.
        let (tx, rx) = watch::channel(None);
        let _ = tx.send(Some(state));
        (
            Self {
                account_id: id.clone(),
                contract_state: rx,
            },
            tx,
        )
    }

    pub fn with_running(
        node_id: &AccountId,
        public_key: AffinePoint,
        threshold: usize,
        participants: Participants,
    ) -> (Self, watch::Sender<Option<ProtocolState>>) {
        Self::with(
            node_id,
            ProtocolState::Running(RunningContractState {
                epoch: 0,
                public_key,
                participants,
                candidates: Default::default(),
                join_votes: Default::default(),
                leave_votes: Default::default(),
                threshold,
            }),
        )
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn borrow_state(&self) -> watch::Ref<'_, Option<ProtocolState>> {
        self.contract_state.borrow()
    }

    pub fn state(&self) -> Option<ProtocolState> {
        self.borrow_state().clone()
    }

    pub fn governance(&self) -> Option<GovernanceInfo> {
        self.state()?.governance(&self.account_id)
    }

    pub async fn wait_governance(&mut self) -> GovernanceInfo {
        loop {
            if let Some(governance) = self.governance() {
                return governance;
            }
            let _ = self.contract_state.changed().await;
        }
    }

    pub async fn next_state(&mut self) -> Option<ProtocolState> {
        let _ = self.contract_state.changed().await;
        self.contract_state.borrow_and_update().clone()
    }

    pub fn mark_changed(&mut self) {
        self.contract_state.mark_changed();
    }

    pub fn participants(&self) -> Option<Participants> {
        match self.borrow_state().as_ref()? {
            ProtocolState::Initializing(state) => Some(state.candidates.clone().into()),
            ProtocolState::Running(state) => Some(state.participants.clone()),
            ProtocolState::Resharing(state) => Some(state.new_participants.clone()),
        }
    }

    pub async fn me(&self) -> Option<Participant> {
        match self.borrow_state().as_ref()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => state
                .participants
                .find_participant(&self.account_id)
                .copied(),
            ProtocolState::Resharing(state) => state
                .new_participants
                .find_participant(&self.account_id)
                .copied(),
        }
    }

    pub async fn threshold(&self) -> Option<usize> {
        match self.state()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => Some(state.threshold),
            ProtocolState::Resharing(state) => Some(state.threshold),
        }
    }

    /// Wait until the MPC threshold is available and return it
    pub async fn wait_threshold(&mut self) -> usize {
        loop {
            if let Some(threshold) = self.threshold().await {
                return threshold;
            }
            let _ = self.contract_state.changed().await;
        }
    }

    pub async fn public_key(&self) -> Option<AffinePoint> {
        match self.borrow_state().as_ref()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => Some(state.public_key),
            ProtocolState::Resharing(_) => None,
        }
    }

    /// Wait until the public key is available and return it
    pub async fn wait_public_key(&mut self) -> AffinePoint {
        loop {
            if let Some(pk) = self.public_key().await {
                return pk;
            }
            let _ = self.contract_state.changed().await;
        }
    }

    pub async fn info(&self) -> Option<(usize, Participant)> {
        match self.state()? {
            ProtocolState::Initializing(_) => None,
            ProtocolState::Running(state) => Some((
                state.threshold,
                *state.participants.find_participant(&self.account_id)?,
            )),
            ProtocolState::Resharing(state) => Some((
                state.threshold,
                *state.new_participants.find_participant(&self.account_id)?,
            )),
        }
    }

    pub async fn wait_info(&mut self) -> (usize, Participant) {
        loop {
            if let Some((threshold, participant)) = self.info().await {
                return (threshold, participant);
            }
            let _ = self.contract_state.changed().await;
        }
    }

    pub async fn participant_map(&self) -> ParticipantMap {
        let Some(state) = self.state().clone() else {
            return ParticipantMap::Zero;
        };

        match state {
            ProtocolState::Initializing(state) => {
                ParticipantMap::One(state.candidates.clone().into())
            }
            ProtocolState::Running(state) => ParticipantMap::One(state.participants.clone()),
            ProtocolState::Resharing(state) => ParticipantMap::Two(
                state.new_participants.clone(),
                state.old_participants.clone(),
            ),
        }
    }

    /// Waits till the contract is in the running state.
    pub async fn wait_running(&mut self) -> RunningContractState {
        loop {
            if let Some(ProtocolState::Running(state)) = self.borrow_state().as_ref() {
                return state.clone();
            }
            let _ = self.contract_state.changed().await;
        }
    }

    /// Create a list of contract states that share a single channel but use different account ids.
    #[cfg(feature = "test-feature")]
    pub fn test_batch(
        ids: &[AccountId],
        state: ProtocolState,
    ) -> (Vec<Self>, watch::Sender<Option<ProtocolState>>) {
        let (tx, rx) = watch::channel(Some(state));
        let selfs = ids
            .iter()
            .map(|id| Self {
                account_id: id.clone(),
                contract_state: rx.clone(),
            })
            .collect();
        (selfs, tx)
    }
}

pub struct RpcExecutor {
    near: NearClient,
    eth: Option<EthClient>,
    solana: Option<SolanaClient>,
    hydration: Option<HydrationClient>,
    canton: Option<CantonClient>,
    action_rx: mpsc::Receiver<RpcAction>,
}

impl RpcExecutor {
    pub async fn new(
        near: &NearClient,
        eth: &Option<EthConfig>,
        solana: &Option<SolConfig>,
        hydration: &Option<HydrationConfig>,
        canton: &Option<CantonConfig>,
    ) -> (RpcChannel, Self) {
        let eth = eth.as_ref().map(EthClient::new);
        let solana = solana.as_ref().map(SolanaClient::from_config);
        let hydration = match hydration {
            Some(h) => match HydrationClient::new(h).await {
                Ok(client) => Some(client),
                Err(e) => {
                    tracing::error!(%e, "failed to create hydration client");
                    None
                }
            },
            None => None,
        };
        let canton = match canton {
            Some(c) => match CantonClient::new(c).await {
                Ok(client) => Some(client),
                Err(e) => {
                    tracing::error!(%e, "failed to create canton client");
                    None
                }
            },
            None => None,
        };
        let (tx, rx) = mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        (
            RpcChannel { tx },
            Self {
                near: near.clone(),
                eth,
                solana,
                hydration,
                canton,
                action_rx: rx,
            },
        )
    }

    pub async fn run(
        mut self,
        contract: watch::Sender<Option<ProtocolState>>,
        config: watch::Sender<Config>,
        checkpoints: EnumMap<Chain, watch::Sender<CheckpointDigest>>,
    ) {
        // spin up update task for updating contract state, config and checkpoints
        let near = self.near.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(UPDATE_INTERVAL);
            loop {
                interval.tick().await;
                tokio::spawn(update_contract_data(
                    near.clone(),
                    contract.clone(),
                    config.clone(),
                    checkpoints.clone(),
                ));
            }
        });

        let eth_client = self.client(&Chain::Ethereum);
        let (eth_rpc_tx, eth_rpc_rx) = mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        // spin up update task for batch sending eth responses
        tokio::spawn({
            run_batch_respond(
                eth_client,
                eth_rpc_rx,
                ETH_RESPOND_BATCH_INTERVAL,
                ETH_RESPOND_BATCH_SIZE,
            )
        });

        // process incoming actions related to RPC
        loop {
            let Some(RpcAction::Publish(action)) = self.action_rx.recv().await else {
                tracing::error!("rpc channel closed unexpectedly");
                return;
            };

            let chain = action.indexed.chain;
            let client = self.client(&chain);
            let eth_rpc_tx = eth_rpc_tx.clone(); // clone for task use

            tokio::spawn(async move {
                match chain {
                    Chain::NEAR | Chain::Solana | Chain::Hydration | Chain::Canton => {
                        execute_publish(client, action).await;
                    }
                    Chain::Ethereum => {
                        if let Err(err) = eth_rpc_tx.send(action).await {
                            tracing::error!(%err, "eth: failed to send publish action");
                        }
                    }
                    Chain::Bitcoin => {
                        tracing::warn!(
                            ?chain,
                            "publish not supported for Bitcoin yet, dropping action"
                        );
                    }
                }
            });
        }
    }

    /// Get the client for the given chain
    fn client(&self, chain: &Chain) -> ChainClient {
        match chain {
            Chain::NEAR => ChainClient::Near(self.near.clone()),
            Chain::Ethereum => {
                if let Some(eth) = &self.eth {
                    ChainClient::Ethereum(eth.clone())
                } else {
                    ChainClient::Err("no eth client available for node")
                }
            }
            Chain::Solana => {
                if let Some(sol) = &self.solana {
                    ChainClient::Solana(sol.clone())
                } else {
                    ChainClient::Err("no solana client available for node")
                }
            }
            Chain::Hydration => {
                if let Some(hydration) = &self.hydration {
                    ChainClient::Hydration(hydration.clone())
                } else {
                    ChainClient::Err("no hydration client available for node")
                }
            }
            Chain::Canton => {
                if let Some(canton) = &self.canton {
                    ChainClient::Canton(canton.clone())
                } else {
                    ChainClient::Err("no canton client available for node")
                }
            }
            Chain::Bitcoin => ChainClient::Err("no bitcoin client available for node"),
        }
    }
}

/// Client related to a specific chain
#[allow(clippy::large_enum_variant)]
pub enum ChainClient {
    Err(&'static str),
    Near(NearClient),
    Ethereum(EthClient),
    Solana(SolanaClient),
    Hydration(HydrationClient),
    Canton(CantonClient),
}

async fn update_contract_data(
    near: NearClient,
    contract: watch::Sender<Option<ProtocolState>>,
    config: watch::Sender<Config>,
    checkpoints: EnumMap<Chain, watch::Sender<CheckpointDigest>>,
) {
    let reads = vec![Read::State, Read::Config, Read::Checkpoints];
    let views = match near.read(reads).await {
        Ok(views) => views,
        Err(error) => {
            tracing::error!(?error, "could not fetch contract data via read");
            return;
        }
    };

    let mut state_view = None;
    let mut config_view = None;
    let mut checkpoints_view = None;

    for view in views {
        match view {
            View::State(s) => state_view = Some(s),
            View::Config(c) => config_view = Some(c),
            View::Checkpoints(cp) => checkpoints_view = Some(cp),
        }
    }

    if let Some(state) = state_view {
        if let Ok(protocol_state) = ProtocolState::try_from(state) {
            contract.send_if_modified(|old_state| {
                if let Some(old_state) = old_state {
                    if *old_state == protocol_state {
                        return false;
                    }
                }
                *old_state = Some(protocol_state);
                true
            });
        }
    }

    if let Some(contract_config) = config_view {
        if let Ok(config_val) = serde_json::to_value(contract_config) {
            if let Ok(node_config) =
                serde_json::from_value::<crate::config::ContractConfig>(config_val)
            {
                config.send_if_modified(|c| c.update(node_config));
            }
        }
    }

    if let Some(signed_checkpoints) = checkpoints_view {
        for (chain, sc) in signed_checkpoints {
            let new_digest = CheckpointDigest {
                height: sc.checkpoint.height,
                digest: sc.checkpoint.digest,
            };
            let tx = &checkpoints[chain];
            tx.send_if_modified(|old| {
                if *old == new_digest {
                    return false;
                }
                *old = new_digest;
                true
            });
        }
    }
}

/// Publish the signature and retry if it fails
async fn execute_publish(client: ChainClient, action: PublishAction) {
    let chain = action.indexed.chain;
    let sign_id = action.indexed.id;

    tracing::info!(
        ?sign_id,
        ?chain,
        started_at = ?action.timestamp.elapsed(),
        "trying to publish signature",
    );

    let retry_config = RetryConfig {
        max_times: MAX_PUBLISH_RETRY,
        min_delay: PUBLISH_FIXED_DELAY,
        max_delay: PUBLISH_FIXED_DELAY,
        jitter: true,
    };

    let publish_res = retry_rpc!(
        PUBLISH_ATTEMPT_TIMEOUT,
        retry_config,
        // Log the error and retry attempt
        |attempt, err, sleep| {
            tracing::warn!(
                ?sign_id,
                retry_count = attempt,
                elapsed = ?action.timestamp.elapsed(),
                ?chain,
                "failed to publish ({err}), retrying in {sleep:?}"
            );
        },
        // Try to publish the signature
        {
            match &client {
                ChainClient::Near(near) => {
                    try_publish_near(near, &action, &action.timestamp, &action.signature)
                        .await
                        .map_err(|_| anyhow::anyhow!("Near publish failed"))
                }
                ChainClient::Ethereum(eth) => eth
                    .publish_signature(&action, &action.timestamp, &action.signature)
                    .await
                    .map_err(|_| anyhow::anyhow!("Ethereum publish failed")),
                ChainClient::Solana(sol) => {
                    try_publish_sol(sol, &action, &action.timestamp, &action.signature)
                        .await
                        .map_err(|_| anyhow::anyhow!("Solana publish failed"))
                }
                ChainClient::Hydration(hyd) => {
                    try_publish_hydration(hyd, &action, &action.timestamp, &action.signature)
                        .await
                        .map_err(|_| anyhow::anyhow!("Hydration publish failed"))
                }
                ChainClient::Canton(canton) => {
                    try_publish_canton(canton, &action, &action.timestamp, &action.signature)
                        .await
                        .map_err(|_| anyhow::anyhow!("Canton publish failed"))
                }
                ChainClient::Err(msg) => {
                    tracing::error!(msg, "no client for chain");
                    Ok(())
                }
            }
        }
    );

    if publish_res.is_ok() {
        let elapsed_secs =
            crate::util::unix_elapsed(action.indexed.unix_timestamp_indexed).as_secs();
        if elapsed_secs <= chain.expected_response_time_secs() {
            record_request_latency_since(
                chain,
                SignRequestStep::Total,
                "in_time",
                action.indexed.unix_timestamp_indexed,
            );
        } else {
            record_request_latency_since(
                chain,
                SignRequestStep::Total,
                "expired",
                action.indexed.unix_timestamp_indexed,
            );
        }
        record_request_latency_since(chain, SignRequestStep::Responding, "ok", action.timestamp);
    } else {
        tracing::info!(
            ?sign_id,
            elapsed = ?action.timestamp.elapsed(),
            "exceeded max retries, trashing publish request"
        );
    }
}

async fn run_batch_respond(
    client: ChainClient,
    mut actions_rx: mpsc::Receiver<PublishAction>,
    batch_interval: Duration,
    batch_size: usize,
) {
    let mut start = Instant::now();
    let mut actions_batch: Vec<PublishAction> = vec![];
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    loop {
        interval.tick().await;
        if (start.elapsed() > batch_interval || actions_batch.len() >= batch_size)
            && !actions_batch.is_empty()
        {
            tracing::info!(
                num_requests = actions_batch.len(),
                "publishing batch of signatures",
            );
            execute_batch_publish(&client, &mut actions_batch).await;
            start = Instant::now();
        }
        if let Ok(action) = actions_rx.try_recv() {
            actions_batch.push(action);
        }
    }
}

async fn execute_batch_publish(client: &ChainClient, actions: &mut Vec<PublishAction>) {
    let signatures: HashMap<SignId, Signature> = actions
        .iter()
        .map(|action| (action.indexed.id, action.signature))
        .collect();

    let retry_config = RetryConfig {
        max_times: MAX_PUBLISH_RETRY,
        min_delay: BATCH_PUBLISH_MIN_DELAY,
        max_delay: BATCH_PUBLISH_MAX_DELAY,
        jitter: true,
    };

    let res = retry_rpc!(
        PUBLISH_ATTEMPT_TIMEOUT,
        retry_config,
        // Log the error and retry attempt
        |attempt, err, sleep| {
            tracing::warn!(
                "batch publish failed (attempt {attempt}): {err}, retrying in {sleep:?}"
            );
        },
        // Try to publish the signatures in batch
        {
            match client {
                ChainClient::Ethereum(eth) => eth
                    .batch_publish_signatures(actions, &signatures)
                    .await
                    .map_err(|_| anyhow::anyhow!("Eth batch publish failed")),
                ChainClient::Near(_) => {
                    tracing::error!("Near has no batch publish");
                    Ok(())
                }
                ChainClient::Solana(_) => {
                    tracing::error!("Solana has no batch publish");
                    Ok(())
                }
                ChainClient::Hydration(_) => {
                    tracing::error!("Hydration has no batch publish");
                    Ok(())
                }
                ChainClient::Canton(_) => {
                    tracing::error!("Canton has no batch publish");
                    Ok(())
                }
                ChainClient::Err(msg) => {
                    tracing::error!(msg, "no client for chain");
                    Ok(())
                }
            }
        }
    );

    if res.is_ok() {
        for action in actions.iter() {
            let chain = action.indexed.chain;
            let elapsed = crate::util::unix_elapsed(action.indexed.unix_timestamp_indexed);
            if elapsed.as_secs() <= chain.expected_response_time_secs() {
                record_request_latency_since(
                    chain,
                    SignRequestStep::Total,
                    "in_time",
                    action.indexed.unix_timestamp_indexed,
                );
            } else {
                record_request_latency_since(
                    chain,
                    SignRequestStep::Total,
                    "expired",
                    action.indexed.unix_timestamp_indexed,
                );
            }
            record_request_latency_since(
                chain,
                SignRequestStep::Responding,
                "ok",
                action.timestamp,
            );
        }
    } else {
        tracing::info!("exceeded max retries, trashing publish request");
    }

    actions.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::contract::primitives::{ParticipantInfo, Participants};
    use crate::protocol::contract::{ResharingContractState, RunningContractState};
    use crate::protocol::ProtocolState;
    use cait_sith::protocol::Participant;
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::point::DecompressPoint;
    use mpc_crypto::kdf::derive_secret_key;
    use mpc_primitives::SignKind;

    fn scalar(bytes: &[u8; 32]) -> k256::Scalar {
        <k256::Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
            bytes.into(),
        )
    }

    fn make_signature(
        sk: &k256::SecretKey,
        epsilon: k256::Scalar,
        payload: k256::Scalar,
    ) -> FullSignature<Secp256k1> {
        let signing_key = k256::ecdsa::SigningKey::from(&derive_secret_key(sk, epsilon));
        let (ecdsa_sig, _): (k256::ecdsa::Signature, _) =
            <k256::ecdsa::SigningKey as k256::ecdsa::signature::hazmat::PrehashSigner<_>>::sign_prehash(
                &signing_key,
                &payload.to_bytes(),
            )
            .expect("signing should succeed");
        let (r_bytes, _) = ecdsa_sig.split_bytes();
        let big_r =
            AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0))
                .unwrap();
        FullSignature {
            big_r,
            s: *ecdsa_sig.s().as_ref(),
        }
    }

    fn make_indexed(epsilon: k256::Scalar, payload: k256::Scalar) -> IndexedSignRequest {
        IndexedSignRequest {
            id: SignId::new([0u8; 32]),
            args: mpc_primitives::SignArgs {
                entropy: [0u8; 32],
                epsilon,
                payload,
                path: "test".into(),
                key_version: 0,
            },
            chain: Chain::NEAR,
            unix_timestamp_indexed: 0,
            kind: SignKind::Sign,
        }
    }

    fn test_participants() -> Participants {
        let mut participants = Participants::default();
        participants.insert(&Participant::from(0), ParticipantInfo::new(0));
        participants.insert(&Participant::from(1), ParticipantInfo::new(1));
        participants.insert(&Participant::from(2), ParticipantInfo::new(2));
        participants
    }

    #[tokio::test]
    async fn wait_governance_tracks_resharing_state() {
        let account_id: AccountId = "p-0".parse().unwrap();
        let participants = test_participants();
        let (mut watcher, tx) = ContractStateWatcher::new(&account_id);

        let initial = RunningContractState {
            epoch: 0,
            public_key: AffinePoint::default(),
            participants: participants.clone(),
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold: 2,
        };
        tx.send(Some(ProtocolState::Running(initial))).unwrap();

        let governance = watcher.governance().expect("running governance");
        assert_eq!(governance.epoch, 0);
        assert_eq!(governance.threshold, 2);
        assert_eq!(governance.me, Participant::from(0));

        let resharing = ResharingContractState {
            old_epoch: 0,
            old_participants: participants.clone(),
            new_participants: participants.clone(),
            threshold: 2,
            public_key: AffinePoint::default(),
            finished_votes: Default::default(),
            cancel_votes: Default::default(),
        };
        tx.send(Some(ProtocolState::Resharing(resharing))).unwrap();

        let paused = watcher.governance().expect("resharing governance");
        assert_eq!(paused.epoch, 1);
        assert_eq!(paused.threshold, 2);
        assert_eq!(paused.me, Participant::from(0));

        let running = RunningContractState {
            epoch: 1,
            public_key: AffinePoint::default(),
            participants,
            candidates: Default::default(),
            join_votes: Default::default(),
            leave_votes: Default::default(),
            threshold: 2,
        };
        tx.send(Some(ProtocolState::Running(running))).unwrap();

        let resumed = watcher.wait_governance().await;
        assert_eq!(resumed.epoch, 1);
        assert_eq!(resumed.threshold, 2);
        assert_eq!(resumed.me, Participant::from(0));
    }

    #[test]
    fn publish_action_accepts_valid_signature() {
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk: AffinePoint = sk.public_key().into();
        let epsilon = scalar(&[1u8; 32]);
        let payload = scalar(&[42u8; 32]);

        let output = make_signature(&sk, epsilon, payload);
        let indexed = make_indexed(epsilon, payload);

        assert!(PublishAction::new(pk, indexed, output, vec![]).is_some());
    }

    #[test]
    fn publish_action_rejects_invalid_signature() {
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk: AffinePoint = sk.public_key().into();
        let epsilon = scalar(&[1u8; 32]);
        let payload = scalar(&[42u8; 32]);

        let mut output = make_signature(&sk, epsilon, payload);
        output.s += k256::Scalar::ONE;
        let indexed = make_indexed(epsilon, payload);

        assert!(PublishAction::new(pk, indexed, output, vec![]).is_none());
    }
}
