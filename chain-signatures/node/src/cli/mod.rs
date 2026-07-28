mod args;

use std::{collections::HashMap, sync::Arc};

use crate::backlog::Backlog;
use crate::config::{Config, LocalConfig, NetworkConfig, OverrideConfig};
use crate::gcp::GcpService;
use crate::indexer_hydration::{self, HydrationConfig};
use crate::mesh::{self, Mesh, MeshState};
use crate::metrics::telemetry::NodeTelemetry;
use crate::node_client::{self, NodeClient};
use crate::protocol::contract::ProtocolState;
use crate::protocol::message::MessageChannel;
use crate::protocol::presignature::Presignature;
use crate::protocol::request::SignatureSpawnerTask;
use crate::protocol::state::{Node, NodeStateWatcher};
use crate::protocol::sync::SyncTask;
use crate::protocol::{spawn_system_metrics, MpcSignProtocol};
use crate::rpc::{self, ContractStateWatcher, NearGovernanceClient, RpcChannel, RpcExecutor};
use crate::storage::checkpoint_storage::CheckpointStorage;
use crate::storage::presignature_storage::PresignatureStorage;
use crate::storage::secret_storage::SecretNodeStorageVariant;
use crate::storage::triple_storage::{TriplePair, TripleStorage};
use crate::stream::{supervisor::run_supervised, StreamContext};
use crate::{logs, storage, web};
pub use args::{
    canton::CantonArgs, ethereum::EthArgs, hydration::HydrationArgs, midnight::MidnightArgs,
    solana::SolArgs,
};

use cait_sith::protocol::Participant;
use clap::Parser;
use deadpool_redis::Runtime;
use enum_map::EnumMap;
use k256::sha2::Sha256;
use local_ip_address::local_ip;
use mpc_chain_canton::{CantonClient, CantonConfig, CantonIndexer};
use mpc_chain_ethereum::{publisher, EthConfig, EthereumIndexer};
use mpc_chain_integration_core::ChainPublisher;
use mpc_chain_midnight::{
    IntentGen, MidnightConfig, MidnightIndexer, MidnightPublisher, MidnightRpc,
};
use mpc_chain_near::NearClient;
use mpc_chain_solana::{SolConfig, SolanaClient, SolanaIndexer};
use mpc_keys::hpke;
use mpc_primitives::{Chain, CheckpointDigest, SignCommand};
use near_account_id::AccountId;
use near_crypto::{InMemorySigner, PublicKey, SecretKey};
use sha3::Digest;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use url::Url;

const DEFAULT_WEB_PORT: u16 = 3000;

/// Capacity of the SignCommand channel that feeds chain sign events from the
/// indexers/streams into the SignatureSpawner.
const MAX_SIGN_COMMANDS: usize = 16384;

#[derive(Parser, Debug)]
pub enum Cli {
    Start {
        /// NEAR RPC address
        #[arg(
            long,
            env("MPC_NEAR_RPC"),
            default_value("https://rpc.testnet.near.org")
        )]
        near_rpc: String,
        /// MPC contract id
        #[arg(long, env("MPC_CONTRACT_ID"), default_value("dev.sig-net.testnet"))]
        mpc_contract_id: AccountId,
        /// This node's account id
        #[arg(long, env("MPC_ACCOUNT_ID"))]
        account_id: AccountId,
        /// This node's account ed25519 secret key
        #[arg(long, env("MPC_ACCOUNT_SK"))]
        account_sk: SecretKey,
        /// The web port for this server
        /// this is default to 3000 for all nodes now.
        /// Partners can choose to change the port, but then they also need to make sure they change their load balancer config to match this
        #[arg(long, env("MPC_WEB_PORT"), default_value = "3000")]
        web_port: Option<u16>,
        /// The cipher secret key used to decrypt messages between nodes.
        #[arg(long, env("MPC_CIPHER_SK"))]
        cipher_sk: String,
        /// The secret key used to sign messages to be sent between nodes.
        #[arg(long, env("MPC_SIGN_SK"))]
        sign_sk: Option<SecretKey>,
        /// Ethereum Indexer options
        #[clap(flatten)]
        eth: EthArgs,
        /// Solana Indexer options
        #[clap(flatten)]
        sol: SolArgs,
        /// Hydration Indexer options
        #[clap(flatten)]
        hydration: HydrationArgs,
        /// Canton Indexer options
        #[clap(flatten)]
        canton: CantonArgs,
        /// Midnight Indexer options
        #[clap(flatten)]
        midnight: MidnightArgs,
        /// NEAR requests options
        #[clap(flatten)]
        indexer_options: mpc_chain_near::Options,
        /// Local address that other peers can use to message this node.
        /// mainnet nodes: this should be set to their domain name
        /// testnet nodes: this should be set to their http://ip:web_port
        /// dev nodes: this should be set to their local network domain name
        /// integration test nodes: this should be set to None
        #[arg(long, env("MPC_LOCAL_ADDRESS"))]
        my_address: Option<Url>,
        /// Storage options
        #[clap(flatten)]
        storage_options: storage::Options,
        /// Logging options
        #[clap(flatten)]
        log_options: logs::Options,
        /// The set of configurations that we will use to override contract configurations.
        #[arg(long, env("MPC_OVERRIDE_CONFIG"), value_parser = clap::value_parser!(OverrideConfig))]
        override_config: Option<OverrideConfig>,
        /// referer header for mainnet whitelist
        #[arg(long, env("MPC_CLIENT_HEADER_REFERER"), default_value(None))]
        client_header_referer: Option<String>,
        #[clap(flatten)]
        mesh_options: mesh::Options,
        #[clap(flatten)]
        message_options: node_client::Options,
    },
}

impl Cli {
    pub fn into_str_args(self) -> Vec<String> {
        match self {
            Cli::Start {
                near_rpc,
                account_id,
                mpc_contract_id,
                account_sk,
                web_port,
                cipher_sk,
                sign_sk,
                eth,
                sol,
                hydration,
                canton,
                midnight,
                indexer_options,
                my_address,
                storage_options,
                log_options,
                override_config,
                client_header_referer,
                mesh_options,
                message_options,
            } => {
                let mut args = vec![
                    "start".to_string(),
                    "--near-rpc".to_string(),
                    near_rpc,
                    "--mpc-contract-id".to_string(),
                    mpc_contract_id.to_string(),
                    "--account-id".to_string(),
                    account_id.to_string(),
                    "--account-sk".to_string(),
                    account_sk.to_string(),
                    "--cipher-sk".to_string(),
                    cipher_sk,
                    "--redis-url".to_string(),
                    storage_options.redis_url.to_string(),
                ];
                if let Some(sign_sk) = sign_sk {
                    args.extend(["--sign-sk".to_string(), sign_sk.to_string()]);
                }
                if let Some(my_address) = my_address {
                    args.extend(["--my-address".to_string(), my_address.to_string()]);
                }
                if let Some(override_config) = override_config {
                    args.extend([
                        "--override-config".to_string(),
                        serde_json::to_string(&override_config).unwrap(),
                    ]);
                }

                if let Some(client_header_referer) = client_header_referer {
                    args.extend(["--client-header-referer".to_string(), client_header_referer]);
                }
                if let Some(web_port) = web_port {
                    args.extend(["--web-port".to_string(), web_port.to_string()]);
                }

                args.extend(eth.into_str_args());
                args.extend(sol.into_str_args());
                args.extend(hydration.into_str_args());
                args.extend(canton.into_str_args());
                args.extend(midnight.into_str_args());
                args.extend(indexer_options.into_str_args());
                args.extend(storage_options.into_str_args());
                args.extend(log_options.into_str_args());
                args.extend(mesh_options.into_str_args());
                args.extend(message_options.into_str_args());
                args
            }
        }
    }
}

pub async fn run(cmd: Cli) -> anyhow::Result<()> {
    match cmd {
        Cli::Start {
            near_rpc,
            web_port,
            mpc_contract_id,
            account_id,
            account_sk,
            cipher_sk,
            sign_sk,
            eth,
            sol,
            hydration,
            canton,
            midnight,
            indexer_options,
            my_address,
            storage_options,
            log_options,
            override_config,
            client_header_referer,
            mesh_options,
            message_options,
        } => {
            let _guard = logs::setup(&storage_options.env, account_id.as_str(), &log_options).await;
            let _span = tracing::trace_span!("cli").entered();
            crate::metrics::init_metrics(
                &account_id,
                env!("CARGO_PKG_VERSION"),
                option_env!("GIT_COMMIT_HASH"),
            );

            let cipher_sk = hpke::SecretKey::try_from_bytes(&hex::decode(cipher_sk)?)?;

            let cipher_pk_hex = hex::encode(cipher_sk.public_key().to_bytes());

            let digest = configuration_digest(
                mpc_contract_id.clone(),
                account_id.clone(),
                account_sk.clone(),
                cipher_pk_hex.clone(),
                sign_sk.clone(),
                eth.clone(),
            );
            crate::metrics::nodes::CONFIGURATION_DIGEST.set(digest);

            // SignCommand channel: chain sign events (requests, completions,
            // chain aborts) from the indexers/streams into the SignatureSpawner.
            let (sign_tx, sign_rx) = mpsc::channel(MAX_SIGN_COMMANDS);

            let StorageHandles {
                key_storage,
                triple_storage,
                presignature_storage,
                backlog,
            } = StorageHandles::new(&account_id, &storage_options).await?;

            let web_port = web_port.unwrap_or(DEFAULT_WEB_PORT);
            let sign_sk = sign_sk.unwrap_or_else(|| account_sk.clone());
            let my_address = my_address.unwrap_or_else(|| {
                let my_ip = local_ip().unwrap();
                Url::parse(&format!("http://{my_ip}:{web_port}")).unwrap()
            });
            tracing::info!(%my_address, "address detected");

            // NEAR Indexer is only used for integration tests
            // TODO: Remove this once we have integration tests built on other chains
            if storage_options.env == "integration-tests" {
                let rpc_client = setup_rpc_client(&near_rpc, client_header_referer);
                mpc_chain_near::run(
                    &indexer_options,
                    &mpc_contract_id,
                    &account_id,
                    sign_tx.clone(),
                    rpc_client,
                    backlog.clone(),
                )?;
            }

            let MeshHandles {
                node_client,
                mesh,
                mesh_state,
                contract_watcher,
                contract_state_tx,
                synced_peer_tx,
            } = MeshHandles::new(message_options, mesh_options, &account_id);

            let chains = ChainConfigs::from_args(eth, sol, hydration, canton, midnight)?;
            let network = NetworkConfig { cipher_sk, sign_sk };
            let signer = InMemorySigner::from_secret_key(account_id.clone(), account_sk);

            let RpcHandles {
                near_client,
                near_governance_client,
                rpc_channel,
                rpc_executor,
            } = RpcHandles::new(
                &near_rpc,
                &my_address,
                &network,
                &mpc_contract_id,
                signer,
                &chains,
            )
            .await;

            let (sync_channel, sync_task) = SyncTask::new(
                &node_client,
                triple_storage.clone(),
                presignature_storage.clone(),
                mesh_state.clone(),
                contract_watcher.clone(),
                synced_peer_tx,
            );

            log_startup(
                digest,
                &mpc_contract_id,
                &account_id,
                &my_address,
                &cipher_pk_hex,
                &network,
                &near_client,
                &chains,
            );

            let ProtocolHandles {
                protocol,
                message_channel,
                node,
                node_watcher,
                config_tx,
                checkpoints_tx,
                checkpoints_rx,
            } = ProtocolHandles::new(
                &account_id,
                override_config,
                network,
                sign_rx,
                &node_client,
                &contract_watcher,
                key_storage,
                triple_storage.clone(),
                presignature_storage.clone(),
                mesh_state.clone(),
                rpc_channel.clone(),
                backlog.clone(),
            )
            .await;

            tracing::info!("protocol initialized");
            tokio::spawn(sync_task.run());
            tokio::spawn(rpc_executor.run(contract_state_tx, config_tx.clone(), checkpoints_tx));

            tokio::spawn(mesh.run(contract_watcher.clone()));
            let system_handle = spawn_system_metrics().await;
            let protocol_handle = tokio::spawn(protocol.run(
                node,
                near_governance_client,
                contract_watcher.clone(),
                mesh_state.clone(),
            ));
            tracing::info!("protocol thread spawned");
            let web_handle = tokio::spawn(web::run(
                web_port,
                message_channel,
                node_watcher,
                triple_storage,
                presignature_storage,
                sync_channel,
                account_id,
                backlog.clone(),
            ));

            spawn_indexers(
                chains,
                sign_tx,
                rpc_channel.clone(),
                backlog.clone(),
                contract_watcher.clone(),
                mesh_state.clone(),
                node_client.clone(),
                checkpoints_rx,
            )
            .await;
            tracing::info!("protocol http server spawned");
            protocol_handle.await?;
            web_handle.await?;
            system_handle.abort();
            tracing::info!("spinning down");
        }
    };

    Ok(())
}

fn configuration_digest(
    mpc_contract_id: AccountId,
    account_id: AccountId,
    account_sk: SecretKey,
    cipher_pk: String,
    sign_sk: Option<SecretKey>,
    eth: EthArgs,
) -> i64 {
    let sign_sk = sign_sk.unwrap_or_else(|| account_sk.clone());
    let eth_contract_address = eth.eth_contract_address.unwrap_or_default();
    calculate_digest(
        mpc_contract_id,
        account_id,
        account_sk.public_key(),
        cipher_pk,
        sign_sk.public_key(),
        eth_contract_address,
    )
}

fn calculate_digest(
    mpc_contract_id: AccountId,
    account_id: AccountId,
    account_pk: PublicKey,
    cipher_pk: String,
    sign_pk: PublicKey,
    eth_contract_address: String,
) -> i64 {
    let mpc_contract_id_str = mpc_contract_id.to_string();
    let account_id_str = account_id.to_string();
    let account_pk_str = account_pk.to_string();
    let sign_pk_str = sign_pk.to_string();

    tracing::info!(
        %mpc_contract_id_str,
        %account_id_str,
        %account_pk_str,
        %cipher_pk,
        %sign_pk_str,
        eth_contract_address = %eth_contract_address,
        "digest hash inputs (exact strings)"
    );

    let mut hasher = Sha256::new();
    hasher.update(&mpc_contract_id_str);
    hasher.update(&account_id_str);
    hasher.update(&account_pk_str);
    hasher.update(&cipher_pk);
    hasher.update(&sign_pk_str);
    hasher.update(&eth_contract_address);

    let result = hasher.finalize();
    // Convert the first 8 bytes of the hash to an i64
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&result[..8]);
    i64::from_le_bytes(bytes)
}

#[allow(clippy::type_complexity)]
fn checkpoint_watchers() -> (
    EnumMap<Chain, watch::Sender<Option<CheckpointDigest>>>,
    EnumMap<Chain, watch::Receiver<Option<CheckpointDigest>>>,
) {
    let channels = EnumMap::from_fn(|_| watch::channel(None));
    let checkpoints_tx = EnumMap::from_fn(|chain| channels[chain].0.clone());
    let checkpoints_rx = EnumMap::from_fn(|chain| channels[chain].1.clone());
    (checkpoints_tx, checkpoints_rx)
}

/// Validated per-chain indexer configs. A `None` entry means the chain is not configured.
struct ChainConfigs {
    eth: Option<EthConfig>,
    sol: Option<SolConfig>,
    hydration: Option<HydrationConfig>,
    canton: Option<CantonConfig>,
    midnight: Option<MidnightConfig>,
}

impl ChainConfigs {
    fn from_args(
        eth: EthArgs,
        sol: SolArgs,
        hydration: HydrationArgs,
        canton: CantonArgs,
        midnight: MidnightArgs,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            eth: eth.into_config()?,
            sol: sol.into_config(),
            hydration: hydration.into_config(),
            canton: canton.into_config(),
            midnight: midnight.into_config()?,
        })
    }

    /// Build the registry of chain publishers, keyed by chain. NEAR is always present;
    /// each other chain is added only when configured. A client that fails to build is
    /// logged and skipped rather than aborting startup.
    async fn publishers(&self, near: NearClient) -> HashMap<Chain, Arc<dyn ChainPublisher>> {
        let mut publishers: HashMap<Chain, Arc<dyn ChainPublisher>> = HashMap::new();
        publishers.insert(Chain::NEAR, Arc::new(near));

        if let Some(eth) = &self.eth {
            let telemetry = Arc::new(NodeTelemetry::new(Chain::Ethereum));
            let client = Arc::new(publisher::EthClient::new(eth, telemetry));
            publishers.insert(Chain::Ethereum, client);
        }
        if let Some(sol) = &self.sol {
            let telemetry = Arc::new(NodeTelemetry::new(Chain::Solana));
            let client = Arc::new(SolanaClient::from_config(sol, telemetry));
            publishers.insert(Chain::Solana, client);
        }
        if let Some(hydration) = &self.hydration {
            let telemetry = Arc::new(NodeTelemetry::new(Chain::Hydration));
            match rpc::HydrationClient::new(hydration, telemetry).await {
                Ok(client) => {
                    publishers.insert(Chain::Hydration, Arc::new(client));
                }
                Err(e) => tracing::error!(%e, "failed to create hydration client"),
            }
        }
        if let Some(canton) = &self.canton {
            let telemetry = Arc::new(NodeTelemetry::new(Chain::Canton));
            match CantonClient::new(canton, telemetry).await {
                Ok(client) => {
                    publishers.insert(Chain::Canton, Arc::new(client));
                }
                Err(e) => tracing::error!(%e, "failed to create canton client"),
            }
        }
        if let Some(midnight) = &self.midnight {
            if let Some(client) = midnight_publisher(midnight).await {
                publishers.insert(Chain::Midnight, client);
            }
        }

        publishers
    }
}

/// The Midnight publisher, when this deployment has one.
///
/// Gated on the funding seed rather than on the chain being configured, which is the
/// one place Midnight differs from the arms above it. `MidnightConfig::validate`
/// deliberately accepts an empty seed: Midnight deploys indexer-only today, so every
/// existing deployment supplies the endpoint flags and no seed, and making the seed
/// mandatory would both break those deployments and force a node that never spends to
/// invent a credential, putting a fake secret in a real deployment. The gate's shape is
/// this repo's own, absent config means the component does not spawn rather than the
/// node refuses to start.
async fn midnight_publisher(config: &MidnightConfig) -> Option<Arc<MidnightPublisher>> {
    if config.publisher.funding_seed.is_empty() {
        // Loud, and at boot: an operator who meant to run a publisher and forgot the
        // flag would otherwise learn about it from a signature that is indexed, routed
        // and then never answered.
        tracing::warn!(
            "midnight is configured with no funding seed, so no midnight publisher is \
             registered and this node will index midnight requests without answering \
             them. Supply --midnight-funding-seed to register one."
        );
        return None;
    }
    match build_midnight_publisher(config).await {
        Ok(publisher) => Some(Arc::new(publisher)),
        Err(err) => {
            tracing::error!(?err, "failed to create midnight publisher");
            None
        }
    }
}

/// The publisher's own node connection and intent builder.
///
/// A second connection to the node the indexer also dials: `MidnightIndexer` opens its
/// own inside `run()` and does not expose it. The builder is spawned only here, so this
/// stays the single child process however many times it is asked for.
async fn build_midnight_publisher(config: &MidnightConfig) -> anyhow::Result<MidnightPublisher> {
    // Dialed before the builder is spawned, so a node this deployment cannot reach
    // costs no child process.
    let rpc = Arc::new(MidnightRpc::connect(config).await?);
    let intent_gen = Arc::new(IntentGen::spawn(&config.publisher, &config.network_id).await?);
    // This token is never cancelled. `MidnightPublisher::new` takes one so that a
    // proving run in flight stops with the node instead of holding it open through
    // shutdown, and THAT PROPERTY IS NOT DELIVERED HERE: the node has no process-wide
    // shutdown token to thread in, because `run` coordinates shutdown by awaiting join
    // handles and `run_supervised` mints a fresh token per indexer run. Delivering it
    // means threading a real token from `run` down through `RpcHandles::new` to here.
    // Until then a proving run in flight still runs to completion at shutdown.
    MidnightPublisher::new(&config.publisher, rpc, intent_gen, CancellationToken::new())
}

/// Emit the single structured "starting node" banner describing this node's identity
/// and which chains it is configured to index.
#[allow(clippy::too_many_arguments)]
fn log_startup(
    digest: i64,
    mpc_contract_id: &AccountId,
    account_id: &AccountId,
    my_address: &Url,
    cipher_pk_hex: &str,
    network: &NetworkConfig,
    near_client: &NearClient,
    chains: &ChainConfigs,
) {
    let eth_signer_address = chains.eth.as_ref().map(|c| c.signer_address());
    let sol_signer_address = chains.sol.as_ref().map(|c| c.signer_address());
    let hydration_signer_address = chains.hydration.as_ref().and_then(|c| c.signer_address());

    tracing::info!(
        %digest,
        %mpc_contract_id,
        %account_id,
        %my_address,
        cipher_pk_hex = %cipher_pk_hex,
        version = %crate::metrics::version(),
        git_commit_hash = %crate::metrics::git_commit_hash(),
        sign_pk = %network.sign_sk.public_key(),
        near_rpc_url = %near_client.rpc_addr(),
        eth_contract_address = %chains.eth.as_ref().map(|c| c.contract_address.to_string()).unwrap_or_else(|| "None".to_string()),
        eth_signer_address = %eth_signer_address.as_deref().unwrap_or("None"),
        sol_program_address = %chains.sol.as_ref().map(|c| c.program_address.as_str()).unwrap_or("None"),
        sol_rpc_url = %chains.sol.as_ref().map(|c| c.rpc_http_url.as_str()).unwrap_or("None"),
        sol_signer_address = %sol_signer_address.as_deref().unwrap_or("None"),
        hydration_rpc_url = %chains.hydration.as_ref().map(|c| c.rpc_ws_url.as_str()).unwrap_or("None"),
        hydration_signer_address = %hydration_signer_address.as_deref().unwrap_or("None"),
        canton_json_api_url = %chains.canton.as_ref().map(|c| c.json_api_url.as_str()).unwrap_or("None"),
        midnight_node_ws_url = %chains.midnight.as_ref().map(|c| c.node_ws_url.as_str()).unwrap_or("None"),
        "starting node",
    );
}

fn setup_rpc_client(
    near_rpc_url: &str,
    client_header_referer: Option<String>,
) -> near_fetch::Client {
    let mut rpc_client = near_fetch::Client::new(near_rpc_url);
    if let Some(referer) = client_header_referer {
        rpc_client
            .inner_mut()
            .headers_mut()
            .insert(http::header::REFERER, referer.parse().unwrap());
    }
    tracing::info!(rpc_addr = rpc_client.rpc_addr(), "rpc client initialized");
    rpc_client
}

struct MeshHandles {
    node_client: NodeClient,
    mesh: Mesh,
    mesh_state: watch::Receiver<MeshState>,
    contract_watcher: ContractStateWatcher,
    contract_state_tx: watch::Sender<Option<ProtocolState>>,
    synced_peer_tx: mpsc::Sender<Participant>,
}

impl MeshHandles {
    fn new(
        message_options: node_client::Options,
        mesh_options: mesh::Options,
        account_id: &AccountId,
    ) -> Self {
        let node_client = NodeClient::new(&message_options);
        let (synced_peer_tx, synced_peer_rx) = SyncTask::synced_nodes_channel();
        let mesh = Mesh::new(&node_client, mesh_options, account_id, synced_peer_rx);
        let mesh_state = mesh.watch();
        let (contract_watcher, contract_state_tx) = ContractStateWatcher::new(account_id);
        Self {
            node_client,
            mesh,
            mesh_state,
            contract_watcher,
            contract_state_tx,
            synced_peer_tx,
        }
    }
}

struct RpcHandles {
    near_client: NearClient,
    near_governance_client: NearGovernanceClient,
    rpc_channel: RpcChannel,
    rpc_executor: RpcExecutor,
}

impl RpcHandles {
    async fn new(
        near_rpc_url: &str,
        my_address: &Url,
        network: &NetworkConfig,
        mpc_contract_id: &AccountId,
        signer: InMemorySigner,
        chains: &ChainConfigs,
    ) -> Self {
        let publisher_telemetry = Arc::new(NodeTelemetry::new(Chain::NEAR));
        // `NearClient` (publishing) and `NearGovernanceClient` (governance + contract
        // reads) each open their own `near_fetch::Client` to the same RPC endpoint.
        // TODO: two connection are negligible here, but consider sharing a single client if necessary.
        let near_client = NearClient::new(
            near_rpc_url,
            mpc_contract_id,
            signer.clone(),
            publisher_telemetry,
        );
        let near_governance_client = NearGovernanceClient::new(
            near_rpc_url,
            my_address,
            &network.sign_sk,
            &network.cipher_sk,
            mpc_contract_id,
            signer,
        );
        let publishers = chains.publishers(near_client.clone()).await;
        let (rpc_channel, rpc_executor) =
            RpcExecutor::new(near_governance_client.clone(), publishers).await;
        Self {
            near_client,
            near_governance_client,
            rpc_channel,
            rpc_executor,
        }
    }
}

struct StorageHandles {
    key_storage: SecretNodeStorageVariant,
    triple_storage: TripleStorage,
    presignature_storage: PresignatureStorage,
    backlog: Backlog,
}

impl StorageHandles {
    async fn new(
        account_id: &AccountId,
        storage_options: &storage::Options,
    ) -> anyhow::Result<Self> {
        let gcp_service = GcpService::init(account_id, storage_options).await?;
        let key_storage =
            storage::secret_storage::init(Some(&gcp_service), storage_options, account_id);
        let redis_url: Url = Url::parse(storage_options.redis_url.as_str())?;
        let redis_cfg = deadpool_redis::Config::from_url(redis_url);
        let redis_pool = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
        let triple_storage = TriplePair::storage(&redis_pool, account_id);
        let presignature_storage = Presignature::storage(&redis_pool, account_id);
        let backlog = Backlog::persisted(CheckpointStorage::Redis(
            redis_pool.clone(),
            account_id.clone(),
        ));
        Ok(Self {
            key_storage,
            triple_storage,
            presignature_storage,
            backlog,
        })
    }
}

struct ProtocolHandles {
    protocol: MpcSignProtocol,
    message_channel: MessageChannel,
    node: Node,
    node_watcher: NodeStateWatcher,
    config_tx: watch::Sender<Config>,
    checkpoints_tx: EnumMap<Chain, watch::Sender<Option<CheckpointDigest>>>,
    checkpoints_rx: EnumMap<Chain, watch::Receiver<Option<CheckpointDigest>>>,
}

impl ProtocolHandles {
    #[allow(clippy::too_many_arguments)]
    async fn new(
        account_id: &AccountId,
        override_config: Option<OverrideConfig>,
        network: NetworkConfig,
        sign_rx: mpsc::Receiver<SignCommand>,
        node_client: &NodeClient,
        contract_watcher: &ContractStateWatcher,
        key_storage: SecretNodeStorageVariant,
        triple_storage: TripleStorage,
        presignature_storage: PresignatureStorage,
        mesh_state: watch::Receiver<MeshState>,
        rpc_channel: RpcChannel,
        backlog: Backlog,
    ) -> Self {
        let config = Config::new(LocalConfig {
            over: override_config.unwrap_or_default(),
            network,
        });
        let (config_tx, config_rx) = watch::channel(config);
        let (checkpoints_tx, checkpoints_rx) = checkpoint_watchers();
        let node = Node::new();
        let node_watcher = node.watch();

        let message_channel = MessageChannel::spawn(
            node_client.clone(),
            config_rx.clone(),
            contract_watcher.clone(),
        )
        .await;
        let sign_task = SignatureSpawnerTask::run(
            account_id.clone(),
            sign_rx,
            contract_watcher.clone(),
            config_rx.clone(),
            presignature_storage.clone(),
            mesh_state.clone(),
            message_channel.clone(),
            rpc_channel,
            backlog,
        );
        let protocol = MpcSignProtocol {
            my_account_id: account_id.clone(),
            msg_channel: message_channel.clone(),
            generating: message_channel.subscribe_generation().await,
            resharing: message_channel.subscribe_resharing().await,
            ready: message_channel.subscribe_ready().await,
            sign_task,
            secret_storage: key_storage,
            triple_storage,
            presignature_storage,
            config: config_rx,
            mesh_state,
        };

        Self {
            protocol,
            message_channel,
            node,
            node_watcher,
            config_tx,
            checkpoints_tx,
            checkpoints_rx,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn spawn_indexers(
    chains: ChainConfigs,
    sign_tx: mpsc::Sender<SignCommand>,
    rpc_channel: RpcChannel,
    backlog: Backlog,
    contract_watcher: ContractStateWatcher,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    checkpoints_rx: EnumMap<Chain, watch::Receiver<Option<CheckpointDigest>>>,
) {
    let ChainConfigs {
        eth,
        sol,
        hydration,
        canton,
        midnight,
    } = chains;

    tracing::info!(
        ethereum = eth.is_some(),
        solana = sol.is_some(),
        hydration = hydration.is_some(),
        canton = canton.is_some(),
        midnight = midnight.is_some(),
        "spawning chain indexers"
    );

    if let Some(eth_config) = eth {
        let eth_telemetry = NodeTelemetry::new(Chain::Ethereum);
        match EthereumIndexer::new(eth_config, backlog.clone(), eth_telemetry.clone()).await {
            Ok(eth_indexer) => {
                tracing::info!("ethereum indexer created successfully");
                tokio::spawn(run_supervised(
                    eth_indexer,
                    StreamContext::new(
                        backlog.clone(),
                        sign_tx.clone(),
                        rpc_channel.clone(),
                        contract_watcher.clone(),
                        mesh_state.clone(),
                        node_client.clone(),
                        checkpoints_rx[Chain::Ethereum].clone(),
                    ),
                    eth_telemetry,
                ));
            }
            Err(err) => {
                tracing::error!(?err, "failed to create ethereum indexer");
            }
        }
    }

    if let Some(sol_config) = sol {
        let sol_telemetry = NodeTelemetry::new(Chain::Solana);
        match SolanaIndexer::new(sol_config, backlog.clone(), sol_telemetry.clone()) {
            Ok(sol_indexer) => {
                tracing::info!("solana indexer created successfully");
                tokio::spawn(run_supervised(
                    sol_indexer,
                    StreamContext::new(
                        backlog.clone(),
                        sign_tx.clone(),
                        rpc_channel.clone(),
                        contract_watcher.clone(),
                        mesh_state.clone(),
                        node_client.clone(),
                        checkpoints_rx[Chain::Solana].clone(),
                    ),
                    sol_telemetry,
                ));
            }
            Err(err) => {
                tracing::error!(?err, "failed to create solana indexer");
            }
        }
    }

    if let Some(hydration_config) = hydration {
        let hydration_telemetry = NodeTelemetry::new(Chain::Hydration);
        tokio::spawn(indexer_hydration::run(
            hydration_config,
            sign_tx.clone(),
            backlog.clone(),
            hydration_telemetry,
            contract_watcher.clone(),
            mesh_state.clone(),
            node_client.clone(),
            checkpoints_rx[Chain::Hydration].clone(),
        ));
    }

    if let Some(canton_config) = canton {
        let canton_telemetry = NodeTelemetry::new(Chain::Canton);
        match CantonIndexer::new(canton_config, backlog.clone(), canton_telemetry.clone()).await {
            Ok(canton_indexer) => {
                tracing::info!("canton indexer created successfully");
                tokio::spawn(run_supervised(
                    canton_indexer,
                    StreamContext::new(
                        backlog.clone(),
                        sign_tx.clone(),
                        rpc_channel.clone(),
                        contract_watcher.clone(),
                        mesh_state.clone(),
                        node_client.clone(),
                        checkpoints_rx[Chain::Canton].clone(),
                    ),
                    canton_telemetry,
                ));
            }
            Err(err) => {
                tracing::error!(?err, "failed to create canton indexer");
            }
        }
    }

    if let Some(midnight_config) = midnight {
        let midnight_telemetry = NodeTelemetry::new(Chain::Midnight);
        match MidnightIndexer::new(midnight_config, backlog.clone(), midnight_telemetry.clone())
            .await
        {
            Ok(midnight_indexer) => {
                tracing::info!("midnight indexer created successfully");
                tokio::spawn(run_supervised(
                    midnight_indexer,
                    StreamContext::new(
                        backlog,
                        sign_tx,
                        rpc_channel,
                        contract_watcher,
                        mesh_state,
                        node_client,
                        checkpoints_rx[Chain::Midnight].clone(),
                    ),
                    midnight_telemetry,
                ));
            }
            Err(err) => {
                tracing::error!(?err, "failed to create midnight indexer");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Mutex;

    use mpc_chain_midnight::PublisherConfig;

    use super::*;

    const ETH_CONTRACT_ADDRESS: &str = "f8bdC0612361a1E49a8E01423d4C0cFc5dF4791A";

    #[test]
    fn test_digest_staking() {
        let mpc_contract_id = AccountId::from_str("v1.sig-net.near").unwrap();
        let account_id = AccountId::from_str("sig.stakin.near").unwrap();
        let account_pk =
            PublicKey::from_str("ed25519:B1vW5HddtmV526QjtwHwBDupKH9A7mgsVttYvE6sZP59").unwrap();
        let cipher_pk = "395418b55b73977f16dfa0fe8a1c488fb6935451deaaa20c51cb5f542ec9c118";
        let sign_pk =
            PublicKey::from_str("ed25519:7dqefRWCwt4XsxnMpgj4pBSXWuzoFjEVQadarZ7GydpU").unwrap();
        let _eth_account_pk = "04f92c9a55c73db4f916fa017b747a3b3bc14b100f4b40e1d67bbf913c6795563b101b8554db46f4206a3a8640e5baff935b7a4df30fe2719e59c1bb9cd7c97ba9";

        let digest = calculate_digest(
            mpc_contract_id,
            account_id,
            account_pk,
            cipher_pk.to_string(),
            sign_pk,
            ETH_CONTRACT_ADDRESS.to_string(),
        );

        assert_eq!(digest, -1051225187120159684);
    }

    #[test]
    fn test_digest_taxistake() {
        let mpc_contract_id = AccountId::from_str("v1.sig-net.near").unwrap();
        let account_id = AccountId::from_str("taxistake-sig.near").unwrap();
        let account_pk =
            PublicKey::from_str("ed25519:5gEt9Aqo1hXwK3Ym6Fqw2zxgzHCEyMyZbJMH1C6irBam").unwrap();
        let cipher_pk = "472a3f1d0c34b89f45d589949e5f907cc10b1ffdced34012a9b0a7244ae01124";
        let sign_pk =
            PublicKey::from_str("ed25519:7LY7SA8g2HamrdBNnQwadrjb2wfVRy5cbVaY8wyurxk8").unwrap();
        let _eth_account_pk = "0452ef3e306b9aae7f8a9e5fe15824b367e34315e26be7bcafc676182a9c45d95714d3e7c8a29a2e3a12adcdc430ad56956e6fc0a8a0c1bd25a195dd2973d47714";

        let digest = calculate_digest(
            mpc_contract_id,
            account_id,
            account_pk,
            cipher_pk.to_string(),
            sign_pk,
            ETH_CONTRACT_ADDRESS.to_string(),
        );

        assert_eq!(digest, -4992003418219576839);
    }

    #[test]
    fn test_digest_staking_for_all() {
        let mpc_contract_id = AccountId::from_str("v1.sig-net.near").unwrap();
        let account_id = AccountId::from_str("sig-mpc-staking4all-01.near").unwrap();
        let account_pk =
            PublicKey::from_str("ed25519:9FfqwhurgHnRqbfQoekYZbqWUSiPokS7vF5akysmbSmL").unwrap();
        let cipher_pk = "7983950637824082c17d45fb4d84111b872f537223bb26a54521b5ddf84b7417";
        let sign_pk =
            PublicKey::from_str("ed25519:2NxYvtbMRncbtEoX7963FweMUJ6TaWjyBeKxeCi1EMnd").unwrap();
        let _eth_account_pk = "046cb1cbe5bab2e5b0de7068bbcd976a8370c54f0583ca26e8308994690dedb8933e8729b39a31cf72bab122165cfaafc2daf12a55c9b6b2e6dd61a4667725fd35";

        let digest = calculate_digest(
            mpc_contract_id,
            account_id,
            account_pk,
            cipher_pk.to_string(),
            sign_pk,
            ETH_CONTRACT_ADDRESS.to_string(),
        );

        assert_eq!(digest, -930268115875971858);
    }

    #[test]
    fn test_digest_lifted() {
        let mpc_contract_id = AccountId::from_str("v1.sig-net.near").unwrap();
        let account_id = AccountId::from_str("lifted-sig.near").unwrap();
        let account_pk =
            PublicKey::from_str("ed25519:Ds7DppCJ84399g7oskRRTNbBLsm61CJJn7j5837JikiT").unwrap();
        let cipher_pk = "196e53521c601145b5280c06468393ce41fd307276b574471401fad3d449480b";
        let sign_pk =
            PublicKey::from_str("ed25519:48AtaVmpT7r2Bo6AV6nRU27ioNe7NWwfYnZFgm8mU8T5").unwrap();
        let _eth_account_pk = "042c56cb509a7a1381155b25fc2bc2ce97930e0aad1508485189235e63838fcf01b0b0cc678d52ca6911bf24344e5ab223a07750c4bfd5f3cf8c3c8224eaece3fc";

        let digest = calculate_digest(
            mpc_contract_id,
            account_id,
            account_pk,
            cipher_pk.to_string(),
            sign_pk,
            ETH_CONTRACT_ADDRESS.to_string(),
        );

        // Grafan value: -1056529302944347500
        assert_eq!(digest, -1056529302944347488);
    }

    #[test]
    fn test_digest_piertwo() {
        let mpc_contract_id = AccountId::from_str("v1.sig-net.near").unwrap();
        let account_id = AccountId::from_str("sig-piertwo.near").unwrap();
        let account_pk =
            PublicKey::from_str("ed25519:4w4vtSWsRwCdRhnwDG6YqXM5SfYn4d8AcN5d3qnPnjQD").unwrap();
        let cipher_pk = "65171d682c0ed98eeb0797940c752ae8fafb9c9939533f42f0dbc9f7201ad409";
        let sign_pk =
            PublicKey::from_str("ed25519:nATG1EmJTTeEo9m7BGpcd49Zx3BxpaqazGohYSyQTt4").unwrap();
        let _eth_account_pk = "04f92c9a55c73db4f916fa017b747a3b3bc14b100f4b40e1d67bbf913c6795563b101b8554db46f4206a3a8640e5baff935b7a4df30fe2719e59c1bb9cd7c97ba9";

        let digest = calculate_digest(
            mpc_contract_id,
            account_id,
            account_pk,
            cipher_pk.to_string(),
            sign_pk,
            ETH_CONTRACT_ADDRESS.to_string(),
        );

        assert_eq!(digest, 695826193095166746);
    }

    #[test]
    fn test_digest_natsai() {
        let mpc_contract_id = AccountId::from_str("v1.sig-net.near").unwrap();
        let account_id = AccountId::from_str("natsai-bp.near").unwrap();
        let account_pk =
            PublicKey::from_str("ed25519:5eRSDpU4qyULkCsMVT2ghLhwR6VQb68K7pBAZFZDT9U6").unwrap();
        let cipher_pk = "f11d23a6dff8823853e1777041d1bf60d185b63564536e9a5a7c94110cc1563a";
        let sign_pk =
            PublicKey::from_str("ed25519:9v1215AcbHrWhC3muPvUu5EPY93o7AYcSvcxMUeRYDx6").unwrap();
        let _eth_account_pk = "04ced0dc6ededb6a19aaa42c46544ff81fbb984673ea4285b8b4e147a807292a43d82595588ae9c86382bac2921a8b5006c43bc993ce0f02a268dbda477b9f0b8c";

        let digest = calculate_digest(
            mpc_contract_id,
            account_id,
            account_pk,
            cipher_pk.to_string(),
            sign_pk,
            ETH_CONTRACT_ADDRESS.to_string(),
        );

        assert_eq!(digest, -8209029844787147492);
    }

    #[test]
    fn test_digest_fountain_labs() {
        let mpc_contract_id = AccountId::from_str("v1.sig-net.near").unwrap();
        let account_id = AccountId::from_str("node.sig-net.near").unwrap();
        let account_pk =
            PublicKey::from_str("ed25519:JQJSjyqF35rHsGrNLSEUVYNdeSANiZNDNNjheN2kszq").unwrap();
        let cipher_pk = "756111207e38f2518bfdcbda746eafa0ec3a340baeecc02084a75f2240f48651";
        let sign_pk =
            PublicKey::from_str("ed25519:6jGbVGEGPqz8QZD5qKJYYxGZCV56tgcRKD9pM55Uey7A").unwrap();
        let _eth_account_pk = "04ced0dc6ededb6a19aaa42c46544ff81fbb984673ea4285b8b4e147a807292a43d82595588ae9c86382bac2921a8b5006c43bc993ce0f02a268dbda477b9f0b8c";

        let digest = calculate_digest(
            mpc_contract_id,
            account_id,
            account_pk,
            cipher_pk.to_string(),
            sign_pk,
            ETH_CONTRACT_ADDRESS.to_string(),
        );
        assert_eq!(digest, -4889179067099199685);
    }

    #[test]
    fn test_digest_blacksand() {
        let mpc_contract_id = AccountId::from_str("v1.sig-net.near").unwrap();
        let account_id = AccountId::from_str("blacksandtech-sig.near").unwrap();
        let account_pk =
            PublicKey::from_str("ed25519:67w2feimgcV21ZgEegvGhHTxyd9DR4yRxguqP8MctyJE").unwrap();
        let cipher_pk = "231f6ddc22796c076dcc11a90b92c23e54071b1673abd2743fb84d5a1fc53f61";
        let sign_pk =
            PublicKey::from_str("ed25519:D5Pccv8i88AuDGXuXQoNSVGAZLfuHCZw2TQmoZxi2tEM").unwrap();

        let digest = calculate_digest(
            mpc_contract_id,
            account_id,
            account_pk,
            cipher_pk.to_string(),
            sign_pk,
            ETH_CONTRACT_ADDRESS.to_string(),
        );

        assert_eq!(digest, -6950551088322443092);
    }

    /// The `MPC_MIDNIGHT_*` env vars feed the same clap fields as the
    /// `--midnight-*` flags, so a set variable can silently backfill a flag
    /// `into_str_args` dropped and turn the round-trip test green. Those
    /// fixtures use the values a developer running a local stack exports,
    /// which makes that the likely case rather than a remote one.
    pub(super) fn assert_midnight_env_unset() {
        for var in [
            "MPC_MIDNIGHT_NODE_WS_URL",
            "MPC_MIDNIGHT_CENTRAL_ADDRESS",
            "MPC_MIDNIGHT_NETWORK_ID",
            "MPC_MIDNIGHT_FUNDING_SEED",
            "MPC_MIDNIGHT_MANAGED_DIR",
            "MPC_MIDNIGHT_INTENT_GEN_COMMAND",
            "MPC_MIDNIGHT_PROOF_SERVER_URL",
            "MPC_MIDNIGHT_INDEXER_URL",
            "MPC_MIDNIGHT_INDEXER_WS_URL",
        ] {
            assert!(
                std::env::var_os(var).is_none(),
                "{var} is set: these tests require an unpolluted environment"
            );
        }
    }

    /// Dockerized test nodes receive their whole configuration as CLI strings
    /// rebuilt through `Cli::into_str_args`. If Midnight were flattened into
    /// `Cli::Start` but missing from that extension, its config would be
    /// accepted on the command line and then silently dropped on
    /// reconstruction.
    #[test]
    fn into_str_args_forwards_midnight() {
        assert_midnight_env_unset();

        let account_sk = SecretKey::from_seed(near_crypto::KeyType::ED25519, "test").to_string();
        let central_address = "ab".repeat(32);
        let funding_seed = "0f".repeat(32);
        let intent_gen_command = r#"["node","dist/main.js"]"#;
        let argv = [
            "mpc-node",
            "start",
            "--account-id",
            "test.near",
            "--account-sk",
            &account_sk,
            "--cipher-sk",
            "cipher",
            "--env",
            "unit-tests",
            "--gcp-project-id",
            "project",
            "--redis-url",
            "redis://127.0.0.1:6379",
            "--midnight-node-ws-url",
            "ws://127.0.0.1:9944",
            "--midnight-central-address",
            &central_address,
            "--midnight-network-id",
            "undeployed",
            "--midnight-funding-seed",
            &funding_seed,
            "--midnight-managed-dir",
            "/var/lib/mpc/midnight",
            "--midnight-intent-gen-command",
            intent_gen_command,
            "--midnight-proof-server-url",
            "http://127.0.0.1:6300",
        ];
        let out = Cli::try_parse_from(argv).unwrap().into_str_args();

        for expected in [
            "--midnight-node-ws-url",
            "ws://127.0.0.1:9944",
            "--midnight-central-address",
            central_address.as_str(),
            "--midnight-network-id",
            "undeployed",
            "--midnight-funding-seed",
            funding_seed.as_str(),
            "--midnight-managed-dir",
            "/var/lib/mpc/midnight",
            "--midnight-intent-gen-command",
            intent_gen_command,
            "--midnight-proof-server-url",
            "http://127.0.0.1:6300",
        ] {
            assert!(
                out.contains(&expected.to_string()),
                "into_str_args dropped {expected}"
            );
        }
    }

    /// Never dialed: `publishers()` only stores the client in the registry.
    fn near_client() -> NearClient {
        let account_id = AccountId::from_str("test.near").unwrap();
        let signer = InMemorySigner::from_secret_key(
            account_id.clone(),
            SecretKey::from_seed(near_crypto::KeyType::ED25519, "test"),
        );
        NearClient::new(
            "http://127.0.0.1:1",
            &account_id,
            signer,
            Arc::new(NodeTelemetry::new(Chain::NEAR)),
        )
    }

    /// Collects what a `tracing` subscriber writes, so a test can assert on a startup
    /// line. The publisher gate's whole output when it declines is that line, so
    /// without this the decision is unobservable and only its absence from the
    /// registry could be checked, which an unreachable node also produces.
    #[derive(Clone, Default)]
    struct LogSink(Arc<Mutex<Vec<u8>>>);

    impl LogSink {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// A fully configured Midnight deployment whose publisher the caller decides. Every
    /// other field is held equal across the tests below.
    fn midnight_args(publisher: PublisherConfig) -> MidnightArgs {
        MidnightArgs::from_config(Some(MidnightConfig {
            // Port 1 is privileged and unbound, so the dial is refused rather than
            // left to a timeout.
            node_ws_url: "ws://127.0.0.1:1".to_string(),
            central_address: "ab".repeat(32),
            network_id: "undeployed".to_string(),
            publisher,
            rpc: Default::default(),
            indexer: Default::default(),
        }))
    }

    /// A node that answers as well as indexes.
    ///
    /// The seed does not travel alone: the child validates the seed and the endpoints
    /// the funding wallet reaches the chain through as one all-or-none set, so this and
    /// `PublisherConfig::default()` differ by every one of them rather than by the seed.
    /// `node_ws_url` is absent because it has no flag to survive `from_config` in;
    /// `into_config` copies it off the node url above.
    fn responding_publisher() -> PublisherConfig {
        PublisherConfig {
            funding_seed: "0f".repeat(32),
            proof_server_url: "http://127.0.0.1:6300".to_string(),
            indexer_url: "http://127.0.0.1:8088/api/v3/graphql".to_string(),
            indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".to_string(),
            ..Default::default()
        }
    }

    /// `publishers()` over a Midnight-only config, with everything it logged at WARN
    /// or above.
    async fn publishers_with_logs(
        midnight: MidnightArgs,
    ) -> (HashMap<Chain, Arc<dyn ChainPublisher>>, String) {
        let chains = ChainConfigs::from_args(
            EthArgs::from_config(None),
            SolArgs::from_config(None),
            HydrationArgs::from_config(None),
            CantonArgs::from_config(None),
            midnight,
        )
        .unwrap();

        let sink = LogSink::default();
        let publishers = {
            // `#[tokio::test]` runs on a current-thread runtime, so the awaits below
            // stay on the thread this thread-local guard was installed on.
            let _guard = tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .with_writer(sink.clone())
                    .with_ansi(false)
                    .with_max_level(tracing::Level::WARN)
                    .finish(),
            );
            chains.publishers(near_client()).await
        };
        (publishers, sink.text())
    }

    /// The Midnight config gate: with no Midnight flags supplied, the chain
    /// must be entirely absent from the node's wiring. `spawn_indexers` reads
    /// the same `chains.midnight` field, so `None` here also means no indexer
    /// is spawned.
    #[tokio::test]
    async fn midnight_off_by_default() {
        assert_midnight_env_unset();

        let chains = ChainConfigs::from_args(
            EthArgs::from_config(None),
            SolArgs::from_config(None),
            HydrationArgs::from_config(None),
            CantonArgs::from_config(None),
            MidnightArgs::from_config(None),
        )
        .unwrap();

        assert!(
            chains.midnight.is_none(),
            "empty MidnightArgs must not produce a MidnightConfig"
        );

        let publishers = chains.publishers(near_client()).await;

        assert!(
            !publishers.contains_key(&Chain::Midnight),
            "unconfigured Midnight must not register a publisher"
        );
        assert_eq!(
            publishers.len(),
            1,
            "with no chain configured, only the NEAR publisher must exist"
        );
        assert!(publishers.contains_key(&Chain::NEAR));
    }

    /// The publisher gate. `MidnightConfig::validate` accepts an empty funding seed
    /// because every Midnight deployment today is indexer-only, so a seedless node is
    /// a supported configuration and must start: it simply registers no publisher.
    /// Nothing else in the tree pins that, and a refactor tidying the arm into
    /// `if self.midnight.is_some()` would register a publisher with no wallet behind
    /// it, which fails per signature instead of once at boot.
    #[tokio::test]
    async fn midnight_without_a_funding_seed_registers_no_publisher() {
        assert_midnight_env_unset();

        let (publishers, logs) = publishers_with_logs(midnight_args(Default::default())).await;

        assert!(
            !publishers.contains_key(&Chain::Midnight),
            "a midnight deployment with no funding seed must register no publisher"
        );
        assert!(
            logs.contains("--midnight-funding-seed"),
            "the warning must name the flag that would enable the publisher, or an \
             operator who forgot it learns from an unanswered signature: {logs}"
        );
        assert!(
            !logs.contains("failed to create midnight publisher"),
            "the seed is checked before anything is dialed or spawned: {logs}"
        );
    }

    /// The other side of that gate. A seed opens it, and construction is then attempted
    /// against the node: `MidnightRpc::connect` fetches subxt metadata at construction,
    /// so no publisher can be built here without a running node, and the observable
    /// difference from the seedless case is which of the two lines is logged. Building
    /// against a live node is an integration concern.
    #[tokio::test]
    async fn a_funding_seed_opens_the_midnight_publisher_gate() {
        assert_midnight_env_unset();

        let (_publishers, logs) = publishers_with_logs(midnight_args(responding_publisher())).await;

        assert!(
            !logs.contains("--midnight-funding-seed"),
            "a seeded deployment must not be told its publisher went unregistered: {logs}"
        );
        assert!(
            logs.contains("failed to create midnight publisher"),
            "a seeded deployment must go on to build the publisher, and this one has no \
             node to build it against: {logs}"
        );
    }
}
