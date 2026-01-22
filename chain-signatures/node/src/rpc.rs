use crate::backlog::Backlog;
use crate::config::{Config, ContractConfig, NetworkConfig};
use crate::indexer_eth::EthConfig;
use crate::indexer_sol::SolConfig;
use crate::protocol::contract::primitives::{ParticipantMap, Participants};
use crate::protocol::contract::RunningContractState;
use crate::protocol::{Chain, Governance, IndexedSignRequest, ProtocolState, SignRequestType};
use crate::util::AffinePointExt as _;

use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signer::keypair::Keypair;

use alloy::primitives::Address;
use alloy::providers::fillers::{FillProvider, JoinFill, WalletFiller};
use alloy::providers::{Provider, RootProvider, WalletProvider};
use alloy::rpc::types::{Transaction, TransactionReceipt};
use cait_sith::protocol::Participant;
use cait_sith::FullSignature;
use k256::{AffinePoint, Secp256k1};
use mpc_keys::hpke;
use mpc_primitives::SignId;
use mpc_primitives::Signature;

use alloy::contract::{ContractInstance, Interface};
use alloy::dyn_abi::DynSolValue;
use alloy::network::EthereumWallet;
use alloy::primitives::U256;
use alloy::providers::ProviderBuilder;
use alloy_signer_local::PrivateKeySigner;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_fetch::result::ExecutionFinalResult;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use url::Url;

use crate::indexer_hydration::HydrationConfig;
use parity_scale_codec::{Decode, Encode};
use subxt::config::substrate::{
    BlakeTwo256, SubstrateConfig, SubstrateExtrinsicParams, SubstrateHeader,
};
use subxt::tx::Payload;
use subxt::Config as SubxtConfig;
use subxt::OnlineClient;
use subxt_signer::{sr25519, SecretUri};

/// The maximum amount of times to retry publishing a signature.
const MAX_PUBLISH_RETRY: usize = 6;
/// The maximum number of concurrent RPC requests the system can make
const MAX_CONCURRENT_RPC_REQUESTS: usize = 1024;
/// The update interval to fetch and update the contract state and config
const UPDATE_INTERVAL: Duration = Duration::from_secs(10);
/// The interval to batch send Ethereum responses
const ETH_RESPOND_BATCH_INTERVAL: Duration = Duration::from_millis(2000);
/// The batch size for Ethereum responses
const ETH_RESPOND_BATCH_SIZE: usize = 10;
/// The maximum number of attempts to fetch eth tx and its receipt
const ETH_TX_RECEIPT_MAX_ATTEMPTS: usize = 6;

type EthContractFillProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<
                alloy::providers::fillers::GasFiller,
                JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

type EthContractInstance = ContractInstance<EthContractFillProvider>;

#[derive(Clone)]
pub struct PublishAction {
    pub public_key: mpc_crypto::PublicKey,
    pub indexed: IndexedSignRequest,
    output: FullSignature<Secp256k1>,
    pub participants: Vec<Participant>,
    timestamp: Instant,
    retry_count: usize,
}

pub enum RpcAction {
    Publish(PublishAction),
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
        let rpc = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rpc
                .tx
                .send(RpcAction::Publish(PublishAction {
                    public_key,
                    indexed,
                    output,
                    participants,
                    timestamp: Instant::now(),
                    retry_count: 0,
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
    action_rx: mpsc::Receiver<RpcAction>,
    backlog: Backlog,
}

impl RpcExecutor {
    pub async fn new(
        near: &NearClient,
        eth: &Option<EthConfig>,
        solana: &Option<SolConfig>,
        hydration: &Option<HydrationConfig>,
        backlog: Backlog,
    ) -> (RpcChannel, Self) {
        let eth = eth.as_ref().map(EthClient::new);
        let solana = solana.as_ref().map(SolanaClient::new);
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
        let (tx, rx) = mpsc::channel(MAX_CONCURRENT_RPC_REQUESTS);
        (
            RpcChannel { tx },
            Self {
                near: near.clone(),
                eth,
                solana,
                hydration,
                action_rx: rx,
                backlog,
            },
        )
    }

    pub async fn run(
        mut self,
        contract: watch::Sender<Option<ProtocolState>>,
        config: watch::Sender<Config>,
    ) {
        // spin up update task for updating contract state and config
        let near = self.near.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(UPDATE_INTERVAL);
            loop {
                interval.tick().await;
                tokio::spawn(update_contract(near.clone(), contract.clone()));
                tokio::spawn(update_config(near.clone(), config.clone()));
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
            let backlog = self.backlog.clone();

            tokio::spawn(async move {
                match chain {
                    Chain::NEAR | Chain::Solana | Chain::Hydration => {
                        execute_publish(client, action, backlog).await;
                    }
                    Chain::Ethereum => {
                        if let Err(err) = eth_rpc_tx.send(action).await {
                            tracing::error!(%err, "eth: failed to send publish action");
                        }
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
        }
    }
}

#[derive(Clone)]
pub struct NearClient {
    client: near_fetch::Client,
    contract_id: AccountId,
    my_addr: Url,
    signer: InMemorySigner,
    cipher_pk: hpke::PublicKey,
    sign_pk: near_crypto::PublicKey,
}

impl Governance for NearClient {
    async fn propose_join(&self) -> anyhow::Result<()> {
        self.propose_join().await
    }

    async fn vote_reshared(&self, epoch: u64) -> anyhow::Result<bool> {
        self.vote_reshared(epoch).await
    }

    async fn vote_public_key(&self, public_key: &near_crypto::PublicKey) -> anyhow::Result<bool> {
        self.vote_public_key(public_key).await
    }
}

impl NearClient {
    pub fn new(
        near_rpc: &str,
        my_addr: &Url,
        network: &NetworkConfig,
        contract_id: &AccountId,
        signer: InMemorySigner,
    ) -> Self {
        Self {
            client: near_fetch::Client::new(near_rpc),
            contract_id: contract_id.clone(),
            my_addr: my_addr.clone(),
            signer,
            cipher_pk: network.cipher_sk.public_key(),
            sign_pk: network.sign_sk.public_key(),
        }
    }

    pub fn rpc_addr(&self) -> String {
        self.client.rpc_addr()
    }

    pub async fn fetch_state(&self) -> anyhow::Result<ProtocolState> {
        let contract_state: mpc_contract::ProtocolContractState =
            self.client.view(&self.contract_id, "state").await?.json()?;

        let protocol_state: ProtocolState = contract_state.try_into().map_err(|_| {
            anyhow::anyhow!("failed to parse protocol state, has it been initialized?")
        })?;

        tracing::debug!(?protocol_state, "protocol state");
        Ok(protocol_state)
    }

    pub async fn fetch_config(&self) -> Option<ContractConfig> {
        self.client
            .view(&self.contract_id, "config")
            .await
            .inspect_err(|err| {
                tracing::warn!(%err, "failed to fetch contract config");
            })
            .ok()?
            .json()
            .inspect(|configs| {
                tracing::debug!(?configs, "contract config");
            })
            .inspect_err(|err| {
                tracing::warn!(%err, "unable to parse config");
            })
            .ok()
    }

    pub async fn vote_public_key(
        &self,
        public_key: &near_crypto::PublicKey,
    ) -> anyhow::Result<bool> {
        tracing::info!(%public_key, signer_id = %self.signer.account_id, "voting for public key");
        let result = self
            .client
            .call(&self.signer, &self.contract_id, "vote_pk")
            .args_json(json!({
                "public_key": public_key
            }))
            .max_gas()
            .retry_exponential(10, 5)
            .transact()
            .await
            .inspect_err(|err| {
                tracing::warn!(%err, "failed to vote for public key");
            })?
            .json()?;

        Ok(result)
    }

    pub async fn vote_reshared(&self, epoch: u64) -> anyhow::Result<bool> {
        tracing::info!(%epoch, signer_id = %self.signer.account_id, "voting for reshared");
        let result = self
            .client
            .call(&self.signer, &self.contract_id, "vote_reshared")
            .args_json(json!({
                "epoch": epoch
            }))
            .max_gas()
            .retry_exponential(10, 5)
            .transact()
            .await
            .inspect_err(|err| {
                tracing::warn!(%err, "failed to vote for reshared");
            })?
            .json()?;

        Ok(result)
    }

    pub async fn propose_join(&self) -> anyhow::Result<()> {
        tracing::info!(signer_id = %self.signer.account_id, "joining the protocol");
        self.client
            .call(&self.signer, &self.contract_id, "join")
            .args_json(json!({
                "url": self.my_addr,
                "cipher_pk": self.cipher_pk.to_bytes(),
                "sign_pk": self.sign_pk,
            }))
            .max_gas()
            .retry_exponential(10, 3)
            .transact()
            .await?
            .into_result()?;

        Ok(())
    }

    pub async fn call_respond(
        &self,
        id: &SignId,
        response: &Signature,
    ) -> Result<ExecutionFinalResult, near_fetch::Error> {
        self.client
            .call(&self.signer, &self.contract_id, "respond")
            .args_json(json!({
                "sign_id": id,
                "signature": response,
            }))
            .max_gas()
            .transact()
            .await
    }
}

#[derive(Clone)]
pub struct EthClient {
    contract: EthContractInstance,
}

impl EthClient {
    pub fn new(eth: &EthConfig) -> Self {
        let signer: PrivateKeySigner = eth
            .account_sk
            .parse()
            .expect("cannot parse Eth account sk into PrivateKeySigner");
        let wallet = EthereumWallet::from(signer.clone());
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(eth.execution_rpc_http_url.parse().unwrap());
        // Create a contract instance.
        let json: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json"
        ))
        .unwrap();

        // Get `abi` from the artifact.
        let abi_value = json.get("abi").expect("Failed to get ABI from artifact");
        let abi = serde_json::from_str(&abi_value.to_string()).unwrap();

        let contract = ContractInstance::new(
            Address::from_str(&format!("0x{}", eth.contract_address)).unwrap(),
            provider.clone(),
            Interface::new(abi),
        );
        Self { contract }
    }
}

#[derive(Clone)]
pub struct SolanaClient {
    client: Arc<anchor_client::Client<Arc<Keypair>>>,
    program_id: Pubkey,
    payer: Arc<Keypair>,
}

impl SolanaClient {
    pub fn new(sol: &SolConfig) -> Self {
        let keypair = Keypair::from_base58_string(&sol.account_sk);
        let payer = Arc::new(keypair);
        let cluster =
            anchor_client::Cluster::Custom(sol.rpc_http_url.clone(), sol.rpc_ws_url.clone());
        let client = anchor_client::Client::new_with_options(
            cluster,
            payer.clone(),
            CommitmentConfig::confirmed(),
        );
        Self {
            client: Arc::new(client),
            program_id: Pubkey::from_str(&sol.program_address)
                .expect("Invalid Solana program address provided in configuration"),
            payer,
        }
    }
}

enum HydradxConfig {}

impl SubxtConfig for HydradxConfig {
    type AccountId = <SubstrateConfig as SubxtConfig>::AccountId;
    type Address = <SubstrateConfig as SubxtConfig>::AccountId;
    type Signature = <SubstrateConfig as SubxtConfig>::Signature;
    type Hasher = BlakeTwo256;
    type Header = SubstrateHeader<u32, BlakeTwo256>;
    type ExtrinsicParams = SubstrateExtrinsicParams<Self>;
    type AssetId = <SubstrateConfig as SubxtConfig>::AssetId;
}

#[derive(Clone)]
pub struct HydrationClient {
    api: OnlineClient<HydradxConfig>,
    signer: sr25519::Keypair,
}

const PALLET_SIGNET: &str = "Signet";

/// This type mirrors the on-chain representation of an affine point
#[derive(Clone, Debug, Encode, Decode)]
struct HydrationAffinePoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// This type mirrors the on-chain signature format
#[derive(Clone, Debug, Encode, Decode)]
struct HydrationSignature {
    pub big_r: HydrationAffinePoint,
    pub s: [u8; 32],
    pub recovery_id: u8,
}

/// A thin wrapper used to mirror the on-chain `BoundedVec` type for SCALE
/// encoding/decoding. This type does **not** enforce any length bounds; it
/// is effectively just a `Vec<T>` on the client side.
///
/// Callers are responsible for ensuring that the inner `Vec` length respects
/// the maximum length enforced by the on-chain pallet, otherwise the
/// resulting transaction may be rejected on-chain.
#[derive(Clone, Debug, Encode, Decode)]
struct BoundedVec<T>(pub Vec<T>);

/// this type is used to construct tx to call respond() on pallet
struct HydrationRespondTx {
    pub request_ids: BoundedVec<[u8; 32]>,
    pub signatures: BoundedVec<HydrationSignature>,
}

impl Payload for HydrationRespondTx {
    fn encode_call_data_to(
        &self,
        metadata: &subxt::Metadata,
        out: &mut Vec<u8>,
    ) -> std::result::Result<(), subxt::ext::subxt_core::Error> {
        let pallet = metadata.pallet_by_name(PALLET_SIGNET).ok_or_else(|| {
            subxt::ext::subxt_core::Error::Metadata(
                subxt::error::MetadataError::PalletNameNotFound(PALLET_SIGNET.to_string()),
            )
        })?;

        let respond_call_index = pallet
            .call_variant_by_name("respond")
            .ok_or_else(|| {
                subxt::ext::subxt_core::Error::Metadata(
                    subxt::error::MetadataError::CallNameNotFound("respond".to_string()),
                )
            })?
            .index;

        let pallet_index: u8 = pallet.index();

        out.push(pallet_index);
        out.push(respond_call_index);

        (&self.request_ids, &self.signatures).encode_to(out);
        Ok(())
    }
}

/// this type is used to construct tx to call respond_bidirectional() on pallet
struct HydrationRespondBidirectionalTx {
    pub request_id: [u8; 32],
    pub serialized_output: BoundedVec<u8>,
    pub signature: HydrationSignature,
}

impl Payload for HydrationRespondBidirectionalTx {
    fn encode_call_data_to(
        &self,
        metadata: &subxt::Metadata,
        out: &mut Vec<u8>,
    ) -> std::result::Result<(), subxt::ext::subxt_core::Error> {
        let pallet = metadata.pallet_by_name(PALLET_SIGNET).ok_or_else(|| {
            subxt::ext::subxt_core::Error::Metadata(
                subxt::error::MetadataError::PalletNameNotFound(PALLET_SIGNET.to_string()),
            )
        })?;

        let pallet_index: u8 = pallet.index();

        let respond_bidirectional_call_index = pallet
            .call_variant_by_name("respond_bidirectional")
            .ok_or_else(|| {
                subxt::ext::subxt_core::Error::Metadata(
                    subxt::error::MetadataError::CallNameNotFound(
                        "respond_bidirectional".to_string(),
                    ),
                )
            })?
            .index;

        out.push(pallet_index);
        out.push(respond_bidirectional_call_index);

        // respond_bidirectional(origin, request_id, serialized_output, signature)
        (&self.request_id, &self.serialized_output, &self.signature).encode_to(out);
        Ok(())
    }
}

impl HydrationClient {
    pub async fn new(config: &HydrationConfig) -> anyhow::Result<Self> {
        let api = OnlineClient::<HydradxConfig>::from_url(&config.rpc_ws_url).await?;
        let uri = SecretUri::from_str(&config.signer_uri)?;
        let signer = sr25519::Keypair::from_uri(&uri)?;
        Ok(Self { api, signer })
    }

    fn to_hydration_signature(sig: &Signature) -> anyhow::Result<HydrationSignature> {
        let enc = sig.big_r.to_encoded_point(false);

        let x: [u8; 32] = enc
            .x()
            .ok_or_else(|| anyhow::anyhow!("missing x"))?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("x must be 32 bytes"))?;

        let y: [u8; 32] = enc
            .y()
            .ok_or_else(|| anyhow::anyhow!("missing y"))?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("y must be 32 bytes"))?;

        let s: [u8; 32] = sig.s.to_bytes().into();

        Ok(HydrationSignature {
            big_r: HydrationAffinePoint { x, y },
            s,
            recovery_id: sig.recovery_id,
        })
    }

    async fn call_respond(&self, id: &SignId, response: &Signature) -> anyhow::Result<()> {
        let tx = HydrationRespondTx {
            request_ids: BoundedVec(vec![id.request_id]),
            signatures: BoundedVec(vec![Self::to_hydration_signature(response)?]),
        };

        let progress = self
            .api
            .tx()
            .sign_and_submit_then_watch_default(&tx, &self.signer)
            .await?;

        progress.wait_for_finalized_success().await?;
        Ok(())
    }

    async fn call_respond_bidirectional(
        &self,
        id: &SignId,
        serialized_output: Vec<u8>,
        response: &Signature,
    ) -> anyhow::Result<subxt::config::HashFor<HydradxConfig>> {
        let tx = HydrationRespondBidirectionalTx {
            request_id: id.request_id,
            serialized_output: BoundedVec(serialized_output),
            signature: Self::to_hydration_signature(response)?,
        };

        let progress = self
            .api
            .tx()
            .sign_and_submit_then_watch_default(&tx, &self.signer)
            .await?;

        let events = progress.wait_for_finalized_success().await?;
        Ok(events.extrinsic_hash())
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
}

async fn update_contract(near: NearClient, contract: watch::Sender<Option<ProtocolState>>) {
    let new_state = match near.fetch_state().await {
        Ok(state) => state,
        Err(error) => {
            tracing::error!(?error, "could not fetch contract state");
            return;
        }
    };

    contract.send_if_modified(|old_state| {
        if let Some(old_state) = old_state {
            if *old_state == new_state {
                return false;
            }
        }
        *old_state = Some(new_state);
        true
    });
}

async fn update_config(near: NearClient, config: watch::Sender<Config>) {
    let Some(contract_config) = near.fetch_config().await else {
        return;
    };

    config.send_if_modified(|config| config.update(contract_config));
}

/// Publish the signature and retry if it fails
async fn execute_publish(client: ChainClient, mut action: PublishAction, backlog: Backlog) {
    let chain = action.indexed.chain;
    let sign_id = action.indexed.id;
    tracing::info!(
        ?sign_id,
        ?chain,
        started_at = ?action.timestamp.elapsed(),
        "trying to publish signature",
    );
    let expected_public_key =
        mpc_crypto::derive_key(action.public_key, action.indexed.args.epsilon);

    // We do this here, rather than on the client side, so we can use the ecrecover system function on NEAR to validate our signature
    let Ok(signature) = crate::kdf::into_eth_sig(
        &expected_public_key,
        &action.output.big_r,
        &action.output.s,
        action.indexed.args.payload,
    ) else {
        tracing::error!(
            ?sign_id,
            "failed to generate a recovery id; trashing publish request",
        );
        return;
    };

    let publish_result = loop {
        let publish = match &client {
            ChainClient::Near(near) => {
                try_publish_near(near, &action, &action.timestamp, &signature)
                    .await
                    .map_err(|_| ())
            }
            ChainClient::Ethereum(eth) => {
                try_publish_eth(eth, &action, &action.timestamp, &signature).await
            }
            ChainClient::Solana(sol) => {
                try_publish_sol(sol, &action, &action.timestamp, &signature)
                    .await
                    .map_err(|_| ())
            }
            ChainClient::Hydration(hyd) => {
                try_publish_hydration(hyd, &action, &action.timestamp, &signature)
                    .await
                    .map_err(|_| ())
            }
            ChainClient::Err(msg) => {
                tracing::error!(msg, "no client for chain");
                Ok(())
            }
        };
        if publish.is_ok() {
            break publish;
        }

        action.retry_count += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if action.retry_count >= MAX_PUBLISH_RETRY {
            tracing::info!(
                ?sign_id,
                elapsed = ?action.timestamp.elapsed(),
                "exceeded max retries, trashing publish request",
            );
            break publish;
        } else {
            tracing::info!(
                ?sign_id,
                retry_count = action.retry_count,
                elapsed = ?action.timestamp.elapsed(),
                "failed to publish, retrying"
            );
        }
    };

    let chain_str = chain.as_str();
    if publish_result.is_ok() {
        let elapsed = crate::util::duration_between_unix(
            action.indexed.unix_timestamp_indexed,
            crate::util::current_unix_timestamp(),
        );
        if elapsed.as_secs() <= chain.expected_response_time_secs() {
            crate::metrics::requests::NUM_SIGN_REQUESTS_MINE_IN_TIME
                .with_label_values(&[chain_str])
                .inc();
        }
        crate::metrics::requests::SIGN_TOTAL_LATENCY
            .with_label_values(&[chain_str])
            .observe(elapsed.as_secs_f64());
        crate::metrics::requests::SIGN_RESPOND_LATENCY
            .with_label_values(&[chain_str])
            .observe(action.timestamp.elapsed().as_secs_f64());
    }

    // Mark completion in Backlog for SignBidirectional requests
    if matches!(
        action.indexed.sign_request_type,
        SignRequestType::SignBidirectional(_)
    ) {
        let success = publish_result.is_ok();
        if let Err(err) = backlog.mark_published(chain, &sign_id, success).await {
            tracing::warn!(?sign_id, ?err, "failed to mark publish status in backlog");
        }
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
            execute_batch_publish(&client, &mut actions_batch, Instant::now()).await;
            start = Instant::now();
        }
        if let Ok(action) = actions_rx.try_recv() {
            actions_batch.push(action);
        }
    }
}

async fn try_publish_near(
    near: &NearClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> Result<(), near_fetch::Error> {
    let outcome = near
        .call_respond(&action.indexed.id, signature)
        .await
        .inspect_err(|err| {
            tracing::error!(
                sign_id = ?action.indexed.id,
                ?err,
                "failed to publish signature",
            );
        })?;

    let _: () = outcome.json().inspect_err(|err| {
        tracing::error!(
            sign_id = ?action.indexed.id,
            big_r = signature.big_r.to_base58(),
            s = ?signature.s,
            ?err,
            "smart contract threw error",
        );
    })?;
    tracing::info!(
        sign_id = ?action.indexed.id,
        big_r = signature.big_r.to_base58(),
        s = ?signature.s,
        elapsed = ?timestamp.elapsed(),
        "published signature sucessfully",
    );
    Ok(())
}

/// Retry with exponential backoff starting at the specified `initial_delay`
async fn handle_wait_for_polling_retry(
    attempt: &mut usize,
    max_attempts: usize,
    sign_ids: &[SignId],
    error_msg: &str,
    initial_delay: Duration,
) -> Result<(), ()> {
    *attempt += 1;
    tracing::error!(?sign_ids, attempt = *attempt, "{}", error_msg);
    if *attempt >= max_attempts {
        tracing::error!(?sign_ids, "exceeded max attempts");
        return Err(());
    }
    let backoff = initial_delay * 2u64.pow((*attempt - 1) as u32) as u32;
    tokio::time::sleep(backoff).await;
    Ok(())
}

// wait for transaction receipt with max_attempts and exponential delay backoff starting at 5s
async fn wait_for_pending_tx(
    provider: &EthContractFillProvider,
    tx_hash: alloy::primitives::B256,
    sign_ids: Vec<SignId>,
    max_attempts: usize,
) -> Result<Transaction, ()> {
    let mut attempt = 0;
    let initial_delay = Duration::from_secs(5);
    loop {
        match tokio::time::timeout(
            Duration::from_secs(10),
            provider.get_transaction_by_hash(tx_hash),
        )
        .await
        {
            Ok(result) => match result {
                Ok(Some(tx)) => {
                    tracing::info!(?sign_ids, "eth signature respond pending transaction found");
                    return Ok(tx);
                }
                Ok(None) => {
                    handle_wait_for_polling_retry(
                        &mut attempt,
                        max_attempts,
                        &sign_ids,
                        "eth signature respond pending transaction not found, retrying",
                        initial_delay,
                    )
                    .await?;
                }
                Err(err) => {
                    handle_wait_for_polling_retry(
                        &mut attempt,
                        max_attempts,
                        &sign_ids,
                        &format!("failed to get eth signature respond pending transaction, retrying: {err:?}"),
                        initial_delay,
                    ).await?;
                }
            },
            Err(_) => {
                handle_wait_for_polling_retry(
                    &mut attempt,
                    max_attempts,
                    &sign_ids,
                    "timeout while getting eth signature respond pending transaction, retrying",
                    initial_delay,
                )
                .await?;
            }
        }
    }
}

// wait for transaction receipt with max_attempts and exponential delay backoff starting at 5s
async fn wait_for_transaction_receipt(
    provider: &EthContractFillProvider,
    tx_hash: alloy::primitives::B256,
    sign_ids: Vec<SignId>,
    max_attempts: usize,
) -> Result<TransactionReceipt, ()> {
    let mut attempt = 0;
    let initial_delay = Duration::from_secs(5);
    loop {
        match tokio::time::timeout(
            Duration::from_secs(10),
            provider.get_transaction_receipt(tx_hash),
        )
        .await
        {
            Ok(result) => match result {
                Ok(Some(receipt)) => {
                    tracing::info!(?sign_ids, "eth signature respond transaction receipt found");
                    return Ok(receipt);
                }
                Ok(None) => {
                    handle_wait_for_polling_retry(
                        &mut attempt,
                        max_attempts,
                        &sign_ids,
                        "eth signature respond transaction receipt not found, retrying",
                        initial_delay,
                    )
                    .await?;
                }
                Err(err) => {
                    handle_wait_for_polling_retry(
                        &mut attempt,
                        max_attempts,
                        &sign_ids,
                        &format!("failed to get eth signature respond transaction receipt, retrying: {err:?}"),
                        initial_delay,
                    ).await?;
                }
            },
            Err(_) => {
                handle_wait_for_polling_retry(
                    &mut attempt,
                    max_attempts,
                    &sign_ids,
                    "timeout while getting eth signature respond transaction receipt, retrying",
                    initial_delay,
                )
                .await?;
            }
        }
    }
}

async fn send_eth_transaction(
    contract: &EthContractInstance,
    params: &[DynSolValue],
    gas: u64,
    sign_ids: &[SignId],
) -> Result<alloy::primitives::B256, ()> {
    // fetch nonce manually since the automatic nonce management in ContractInstance is lagging
    let nonce = match tokio::time::timeout(
        Duration::from_secs(10),
        contract
            .provider()
            .get_transaction_count(contract.provider().default_signer_address())
            .pending(),
    )
    .await
    {
        Ok(Ok(nonce)) => {
            tracing::info!(nonce, "will send eth tx with nonce");
            nonce
        }
        Ok(Err(err)) => {
            tracing::error!(?err, "failed to get nonce");
            return Err(());
        }
        Err(err) => {
            tracing::error!(?err, "timeout to get nonce");
            return Err(());
        }
    };

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        contract
            .function("respond", params)
            .unwrap()
            .gas(gas)
            // setting nonce manually since the automatic nonce management in ContractInstance is lagging
            .nonce(nonce)
            .send(),
    )
    .await
    .map_err(|_| {
        tracing::error!(
            ?sign_ids,
            "timeout while sending ethereum signature transaction"
        );
    })?
    .map_err(|err| {
        tracing::error!(
            ?sign_ids,
            ?err,
            "failed to send ethereum signature transaction"
        );
    })?;

    Ok(*result.tx_hash())
}

async fn try_publish_eth(
    eth: &EthClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> Result<(), ()> {
    let sign_id = action.indexed.id;
    let params = [DynSolValue::Array(vec![DynSolValue::Tuple(vec![
        DynSolValue::FixedBytes(action.indexed.id.request_id.into(), 32),
        DynSolValue::Tuple(vec![
            DynSolValue::Tuple(vec![
                DynSolValue::from(U256::from_be_slice(&signature.big_r.x())),
                DynSolValue::from(U256::from_be_slice(
                    signature.big_r.to_encoded_point(false).y().unwrap(),
                )),
            ]),
            DynSolValue::from(U256::from_be_slice(&signature.s.to_bytes())),
            DynSolValue::from(signature.recovery_id),
        ]),
    ])])];

    let tx_hash = send_eth_transaction(
        &eth.contract,
        &params,
        40000,
        std::slice::from_ref(&action.indexed.id),
    )
    .await?;

    let receipt = wait_for_transaction_receipt(
        eth.contract.provider(),
        tx_hash,
        vec![action.indexed.id],
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    // Check if transaction was successful
    if !receipt.status() {
        tracing::error!(
            ?sign_id,
            tx_hash = ?receipt.transaction_hash,
            "transaction failed"
        );
        return Err(());
    }

    let tx_hash = receipt.transaction_hash;
    tracing::info!(
        ?sign_id,
        tx_hash = ?tx_hash,
        elapsed = ?timestamp.elapsed(),
        "published ethereum signature successfully"
    );
    Ok(())
}

async fn try_batch_publish_eth(
    eth: &EthClient,
    actions: &Vec<PublishAction>,
    signatures: &HashMap<SignId, Signature>,
) -> Result<(), ()> {
    let chain = Chain::Ethereum;
    let mut params_vec = vec![];
    let num_requests = actions.len();
    let sign_ids = actions
        .iter()
        .map(|action| action.indexed.id)
        .collect::<Vec<_>>();
    tracing::info!(?sign_ids, "will send eth batch tx");
    for action in actions {
        let signature = signatures
            .get(&action.indexed.id)
            .expect("signature not found in map");
        params_vec.push(DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(action.indexed.id.request_id.into(), 32),
            DynSolValue::Tuple(vec![
                DynSolValue::Tuple(vec![
                    DynSolValue::from(U256::from_be_slice(&signature.big_r.x())),
                    DynSolValue::from(U256::from_be_slice(
                        signature.big_r.to_encoded_point(false).y().unwrap(),
                    )),
                ]),
                DynSolValue::from(U256::from_be_slice(&signature.s.to_bytes())),
                DynSolValue::from(signature.recovery_id),
            ]),
        ]));
    }

    let params = [DynSolValue::Array(params_vec.clone())];
    let gas = std::cmp::max(40000, 20000 * num_requests as u64);

    let tx_hash = send_eth_transaction(&eth.contract, &params, gas, &sign_ids).await?;

    tracing::info!(?tx_hash, "sent eth tx");

    let tx = wait_for_pending_tx(
        eth.contract.provider(),
        tx_hash,
        sign_ids.clone(),
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    tracing::info!(?tx, "tx found in mempool");

    let receipt = wait_for_transaction_receipt(
        eth.contract.provider(),
        tx_hash,
        sign_ids.clone(),
        ETH_TX_RECEIPT_MAX_ATTEMPTS,
    )
    .await?;

    // Check if transaction was successful
    if !receipt.status() {
        tracing::error!(
            ?sign_ids,
            tx_hash = ?receipt.transaction_hash,
            "eth batch transaction failed"
        );
        return Err(());
    }

    let tx_hash = receipt.transaction_hash;
    tracing::info!(
        ?chain,
        ?sign_ids,
        ?tx_hash,
        num_requests,
        "eth batch published ethereum signatures successfully"
    );
    Ok(())
}

async fn execute_batch_publish(
    client: &ChainClient,
    actions: &mut Vec<PublishAction>,
    start: Instant,
) {
    let mut signatures: HashMap<SignId, Signature> = HashMap::new();

    for action in actions.iter() {
        let expected_public_key =
            mpc_crypto::derive_key(action.public_key, action.indexed.args.epsilon);

        let sign_id = action.indexed.id;
        let Ok(signature) = crate::kdf::into_eth_sig(
            &expected_public_key,
            &action.output.big_r,
            &action.output.s,
            action.indexed.args.payload,
        ) else {
            tracing::error!(
                ?sign_id,
                "failed to generate a recovery id; trashing publish request",
            );
            return;
        };
        signatures.insert(sign_id, signature);
    }

    let mut retry_count = 0;
    loop {
        let publish = match client {
            ChainClient::Near(_) => {
                tracing::error!("near has no batch publish");
                Ok(())
            }
            ChainClient::Solana(_) => {
                tracing::error!("Solana has no batch publish");
                Ok(())
            }
            ChainClient::Ethereum(eth) => try_batch_publish_eth(eth, actions, &signatures).await,
            ChainClient::Hydration(_) => {
                tracing::error!("Hydration has no batch publish");
                Ok(())
            }
            ChainClient::Err(msg) => {
                tracing::error!(msg, "no client for chain");
                Ok(())
            }
        };
        if publish.is_ok() {
            // Record metrics for successful batch publish
            let current_timestamp = crate::util::current_unix_timestamp();
            for action in actions.iter() {
                let chain = action.indexed.chain;
                let elapsed = crate::util::duration_between_unix(
                    action.indexed.unix_timestamp_indexed,
                    current_timestamp,
                );
                if elapsed.as_secs() <= chain.expected_response_time_secs() {
                    crate::metrics::requests::NUM_SIGN_REQUESTS_MINE_IN_TIME
                        .with_label_values(&[chain.as_str()])
                        .inc();
                }
                crate::metrics::requests::SIGN_TOTAL_LATENCY
                    .with_label_values(&[chain.as_str()])
                    .observe(elapsed.as_secs_f64());
            }
            crate::metrics::requests::SIGN_RESPOND_LATENCY
                .with_label_values(&[Chain::Ethereum.as_str()])
                .observe(start.elapsed().as_secs_f64());
            actions.clear();
            break;
        }

        tracing::warn!("batch publish failed, {publish:?}");
        retry_count += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if retry_count >= MAX_PUBLISH_RETRY {
            tracing::info!("exceeded max retries, trashing publish request",);
            // clearing actions to avoid retrying
            actions.clear();
            break;
        } else {
            tracing::info!("failed to publish, retrying");
        }
    }
}

use signet_program::accounts::Respond as SolanaRespondAccount;
use signet_program::accounts::RespondBidirectional as SolanaRespondBidirectionalAccount;
use signet_program::instruction::Respond as SolanaRespond;
use signet_program::instruction::RespondBidirectional as SolanaRespondBidirectional;
use signet_program::AffinePoint as SolanaContractAffinePoint;
use signet_program::Signature as SolanaContractSignature;
use solana_sdk::signature::Signer as SolanaSigner;
async fn try_publish_sol(
    sol: &SolanaClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> Result<(), ()> {
    let program = sol.client.program(sol.program_id).map_err(|_| ())?;

    let sign_id = action.indexed.id;
    let request_ids = vec![action.indexed.id.request_id];
    let big_r = signature.big_r.to_encoded_point(false);
    let signature = SolanaContractSignature {
        big_r: SolanaContractAffinePoint {
            x: big_r.as_bytes()[1..33].try_into().unwrap(),
            y: big_r.as_bytes()[33..65].try_into().unwrap(),
        },
        s: signature.s.to_bytes().into(),
        recovery_id: signature.recovery_id,
    };

    tracing::debug!(
        ?sign_id,
        request_type = ?action.indexed.sign_request_type,
        "try_publish_sol: dispatching request"
    );

    match &action.indexed.sign_request_type {
        SignRequestType::Sign | SignRequestType::SignBidirectional(_) => {
            let (event_authority, _) =
                Pubkey::find_program_address(&[b"__event_authority"], &sol.program_id);
            let tx = program
                .request()
                .signer(sol.payer.clone())
                .accounts(SolanaRespondAccount {
                    responder: sol.payer.pubkey(),
                    event_authority,
                    program: sol.program_id,
                })
                .args(SolanaRespond {
                    request_ids,
                    signatures: vec![signature.clone()],
                })
                .send()
                .await
                .map_err(|err| {
                    tracing::error!(
                        sign_id = ?action.indexed.id,
                        error = ?err,
                        "failed to publish solana signature"
                    );
                })?;

            tracing::info!(
                ?sign_id,
                tx_hash = ?tx,
                elapsed = ?timestamp.elapsed(),
                "published solana signature successfully"
            );
        }
        SignRequestType::RespondBidirectional(respond_bidirectional_tx) => {
            tracing::debug!(
                ?sign_id,
                request_id = ?request_ids[0],
                serialized_output_len = respond_bidirectional_tx.output.len(),
                "try_publish_sol: entering RespondBidirectional arm"
            );
            let respond_bidirectional_serialized_output = respond_bidirectional_tx.output.clone();
            let tx = program
                .request()
                .signer(sol.payer.clone())
                .accounts(SolanaRespondBidirectionalAccount {
                    responder: sol.payer.clone().try_pubkey().unwrap(),
                })
                .args(SolanaRespondBidirectional {
                    request_id: request_ids[0],
                    serialized_output: respond_bidirectional_serialized_output.clone(),
                    signature: signature.clone(),
                })
                .send()
                .await
                .map_err(|err| {
                    tracing::error!(
                        ?sign_id,
                        error = ?err,
                        "failed to publish respond bidirectional solana signature"
                    );
                })?;

            tracing::info!(
                ?sign_id,
                tx_hash = ?tx,
                elapsed = ?timestamp.elapsed(),
                "published respond bidirectional solana signature successfully"
            );
        }
    }

    Ok(())
}

async fn try_publish_hydration(
    hyd: &HydrationClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> Result<(), ()> {
    let chain = action.indexed.chain;
    let sign_id = action.indexed.id;
    let request_ids = [action.indexed.id.request_id];

    tracing::info!(
        ?sign_id,
        ?chain,
        elapsed = ?timestamp.elapsed(),
        request_id = ?request_ids[0],
        "Hydration: publishing signature"
    );

    match &action.indexed.sign_request_type {
        SignRequestType::Sign | SignRequestType::SignBidirectional(_) => {
            hyd.call_respond(&action.indexed.id, signature)
                .await
                .map_err(|e| {
                    tracing::error!(?sign_id, ?e, "Hydration: failed to publish signature");
                })?;
            tracing::info!(
                ?sign_id,
                elapsed = ?timestamp.elapsed(),
                "published hydration signature successfully"
            );
        }
        SignRequestType::RespondBidirectional(respond_bidirectional_tx) => {
            let serialized_output = respond_bidirectional_tx.output.clone();
            tracing::debug!(
                ?sign_id,
                request_id = ?request_ids[0],
                serialized_output_len = serialized_output.len(),
                "try_publish_hydration: entering RespondBidirectional arm"
            );
            let tx_hash = hyd
                .call_respond_bidirectional(&action.indexed.id, serialized_output, signature)
                .await
                .map_err(|e| {
                    tracing::error!(
                        ?sign_id,
                        ?e,
                        "Hydration: failed to publish respond bidirectional signature"
                    );
                })?;
            tracing::info!(
                ?sign_id,
                tx_hash = ?tx_hash,
                elapsed = ?timestamp.elapsed(),
                "published respond bidirectional hydration signature successfully"
            );
        }
    }

    Ok(())
}
