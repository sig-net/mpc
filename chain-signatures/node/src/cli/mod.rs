mod args;

use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::backlog::Backlog;
use crate::config::{Config, NetworkConfig};
use crate::mesh::{self, Mesh, MeshState};
use crate::metrics::telemetry::NodeTelemetry;
use crate::node_client::NodeClient;
use crate::protocol::contract::ProtocolState;
use crate::protocol::message::MessageChannel;
use crate::protocol::presignature::Presignature;
use crate::protocol::request::{SignatureSpawner, SignatureSpawnerTask};
use crate::protocol::state::{Node, NodeStateWatcher};
use crate::protocol::sync::{SyncReportSender, SyncTask};
use crate::protocol::{spawn_system_metrics, MpcSignProtocol};
use crate::rpc::{self, ContractStateWatcher, NearGovernanceClient, RpcChannel, RpcExecutor};
use crate::storage::checkpoint_storage::CheckpointStorage;
use crate::storage::keystore::Keystore;
use crate::storage::midnight_dust_storage::MidnightDustStorage;
use crate::storage::presignature_storage::PresignatureStorage;
use crate::storage::triple_storage::{TriplePair, TripleStorage};
use crate::storage::Initializing;
use crate::stream::{supervisor::run_supervised, StreamContext};
use crate::types::SignCommand;
use crate::{logs, storage, web};
#[cfg(feature = "test-feature")]
pub use args::ethereum::mock_indexer_config;
pub use args::{
    canton::CantonArgs, ethereum::EthArgs, hydration::HydrationArgs, midnight::MidnightArgs,
    solana::SolArgs, tron::TronArgs,
};

use anyhow::Context as _;
use clap::Parser;
use deadpool_redis::{Hook, Runtime};
use enum_map::EnumMap;
use mpc_chain_canton::{CantonClient, CantonConfig, CantonIndexer};
use mpc_chain_ethereum::{publisher, EthConfig, EthereumIndexer};
use mpc_chain_hydration::{HydrationConfig, HydrationIndexer};
use mpc_chain_integration_core::{utils::retry::SharedBackoff, ChainPublisher, GatedPublisher};
use mpc_chain_midnight::{
    DustCheckpointStore, MidnightConfig, MidnightIndexer, RecoveringMidnightPublisher,
};
use mpc_chain_near::{NearClient, NearRpcGates};
use mpc_chain_solana::{SolConfig, SolanaClient, SolanaIndexer};
use mpc_chain_tron::{TronConfig, TronWatcher};
use mpc_keys::hpke;
use mpc_primitives::{Chain, CheckpointDigest};
use near_account_id::AccountId;
use near_crypto::{InMemorySigner, SecretKey};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Capacity of the SignCommand channel that feeds chain sign events from the
/// indexers/streams into the SignatureSpawner.
const MAX_SIGN_COMMANDS: usize = 16384;

#[derive(Parser, Debug)]
pub enum Cli {
    Start {
        /// NEAR RPC address
        #[arg(long, env("MPC_NEAR_RPC"), hide_env_values = true)]
        near_rpc: Url,
        /// MPC contract id
        #[arg(long, env("MPC_CONTRACT_ID"))]
        mpc_contract_id: AccountId,
        /// This node's account id
        #[arg(long, env("MPC_ACCOUNT_ID"))]
        account_id: AccountId,
        /// Deployment this node belongs to. Labels logs and telemetry.
        #[arg(long, env("MPC_ENV"), value_enum)]
        env: logs::Env,
        /// This node's account ed25519 secret key
        #[arg(long, env("MPC_ACCOUNT_SK"), hide_env_values = true)]
        account_sk: SecretKey,
        /// The web port for this server
        /// this is default to 3000 for all nodes now.
        /// Partners can choose to change the port, but then they also need to make sure they change their load balancer config to match this
        #[arg(long, env("MPC_WEB_PORT"), default_value = "3000")]
        web_port: u16,
        /// The cipher secret key used to decrypt messages between nodes.
        #[arg(long, env("MPC_CIPHER_SK"), hide_env_values = true)]
        cipher_sk: String,
        /// The secret key used to sign messages to be sent between nodes.
        #[arg(long, env("MPC_SIGN_SK"), hide_env_values = true)]
        sign_sk: SecretKey,
        /// Ethereum Indexer options
        #[command(flatten)]
        eth: EthArgs,
        /// Solana Indexer options
        #[command(flatten)]
        sol: SolArgs,
        /// Hydration Indexer options
        #[command(flatten)]
        hydration: HydrationArgs,
        /// Canton Indexer options
        #[command(flatten)]
        canton: CantonArgs,
        /// Midnight Indexer options
        #[command(flatten)]
        midnight: MidnightArgs,
        /// Tron execution watcher options
        #[command(flatten)]
        tron: TronArgs,
        /// URL at which other nodes reach this node's web port, e.g. `https://node.example.org`.
        #[arg(long, env("MPC_LOCAL_ADDRESS"), value_parser = parse_peer_address)]
        my_address: Url,
        /// Storage options
        #[command(flatten)]
        storage_options: storage::Options,
        /// Logging options
        #[command(flatten)]
        log_options: logs::Options,
    },
}

impl Cli {
    /// `Cli::parse`, except an error never prints what the operator typed:
    /// values can hold API keys and passwords, and clap echoes them even with
    /// `hide_env_values`, which only covers `--help`. A rejected value names
    /// its env var, which is what operators set, and its flag. An unknown
    /// argument or subcommand is not named at all: it can be a secret split
    /// off by a missing quote, or glued to a flag.
    pub fn parse_redacted() -> Self {
        Self::try_parse_redacted(std::env::args_os()).unwrap_or_else(|err| err.exit())
    }

    fn try_parse_redacted<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        use clap::error::{ContextKind, ContextValue, ErrorKind};
        Self::try_parse_from(args).map_err(|err| {
            let message = match err.kind() {
                // An empty value is clap's "a value is required": nothing to hide.
                ErrorKind::InvalidValue
                    if matches!(err.get(ContextKind::InvalidValue), Some(ContextValue::String(v)) if v.is_empty()) =>
                {
                    return err;
                }
                ErrorKind::InvalidValue | ErrorKind::ValueValidation | ErrorKind::TooManyValues => {
                    // Clap names the flag as `--near-rpc <NEAR_RPC>`.
                    let arg = err.get(ContextKind::InvalidArg).map(ToString::to_string);
                    let flag = arg.as_deref().unwrap_or_default().split(' ').next().unwrap_or_default();
                    match env_var_of(flag) {
                        Some(env) => format!("invalid value for {env} ({flag})"),
                        None => format!("invalid value for {flag}"),
                    }
                }
                ErrorKind::UnknownArgument => "unexpected argument".to_string(),
                ErrorKind::InvalidSubcommand => "unrecognized subcommand".to_string(),
                // The other kinds print flag names only.
                _ => return err,
            };
            clap::Error::raw(err.kind(), format!("{message}\n"))
        })
    }
}

/// The env var behind a `start` flag, such as `MPC_NEAR_RPC` for `--near-rpc`.
fn env_var_of(flag: &str) -> Option<String> {
    let command = <Cli as clap::CommandFactory>::command();
    let start = command.find_subcommand("start")?;
    let arg = start.get_arguments().find(|arg| {
        arg.get_long()
            .is_some_and(|long| flag == format!("--{long}"))
    })?;
    Some(arg.get_env()?.to_string_lossy().into_owned())
}

/// `Url` alone accepts `node.example.org:8080`, reading the host as the scheme,
/// and the contract cannot change a participant's URL once it has joined.
fn parse_peer_address(s: &str) -> Result<Url, String> {
    let url = Url::parse(s).map_err(|e| format!("`{s}` is not a valid URL: {e}"))?;
    match (url.scheme(), url.host()) {
        ("http" | "https", Some(_)) => Ok(url),
        (scheme, _) => Err(format!(
            "`--my-address` must be an http/https URL with a host, got scheme `{scheme}`"
        )),
    }
}

pub async fn run(cmd: Cli) -> anyhow::Result<()> {
    match cmd {
        Cli::Start {
            near_rpc,
            web_port,
            mpc_contract_id,
            account_id,
            env,
            account_sk,
            cipher_sk,
            sign_sk,
            eth,
            sol,
            hydration,
            canton,
            midnight,
            tron,
            my_address,
            storage_options,
            log_options,
        } => {
            let _guard = logs::setup(env, account_id.as_str(), &log_options).await;
            let _span = tracing::trace_span!("cli").entered();
            // Installed before the slow startup steps, so a stop during them
            // is an orderly exit rather than the OS default.
            let shutdown = shutdown_signal();
            crate::metrics::init_metrics(
                &account_id,
                env!("CARGO_PKG_VERSION"),
                option_env!("GIT_COMMIT_HASH"),
                option_env!("BUILD_TIMESTAMP"),
            );

            let cipher_sk = hpke::SecretKey::try_from_bytes(&hex::decode(cipher_sk)?)?;

            let cipher_pk_hex = hex::encode(cipher_sk.public_key().to_bytes());

            // SignCommand channel: sign requests and completions from the
            // indexers/streams into the SignatureSpawner.
            let (sign_tx, sign_rx) = mpsc::channel(MAX_SIGN_COMMANDS);

            let StorageHandles {
                keystore,
                triple_storage,
                presignature_storage,
                backlog,
                midnight_dust,
            } = StorageHandles::new(&account_id, &storage_options).await?;

            // NEAR as a source chain exists for the integration tests only, and the
            // test harness builds this binary with `test-feature`.
            if cfg!(feature = "test-feature") {
                let rpc_client = near_fetch::Client::new(near_rpc.as_str());
                let near_sign_tx = SignCommand::forward_near(sign_tx.clone(), backlog.clone());
                mpc_chain_near::run(
                    &mpc_contract_id,
                    &account_id,
                    near_sign_tx,
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
                sync_report_tx,
            } = MeshHandles::new(&account_id);

            let stack = ChainStack::new(ChainConfigs::from_args(
                eth, sol, hydration, canton, midnight, tron,
            )?)
            .with_midnight_dust(midnight_dust);
            let network = NetworkConfig { cipher_sk, sign_sk };
            let signer = match InMemorySigner::from_secret_key(account_id.clone(), account_sk) {
                near_crypto::Signer::InMemory(s) => s,
                _ => unreachable!(),
            };
            let account_pk = signer.public_key();

            let RpcHandles {
                near_governance_client,
                rpc_channel,
                rpc_executor,
            } = RpcHandles::new(
                &near_rpc,
                &my_address,
                &network,
                &mpc_contract_id,
                signer,
                &stack,
                backlog.clone(),
            )
            .await?;

            let sync_task = SyncTask::new(
                &node_client,
                triple_storage.clone(),
                presignature_storage.clone(),
                mesh_state.clone(),
                contract_watcher.clone(),
                sync_report_tx.clone(),
                network.clone(),
            );

            log_startup(
                &mpc_contract_id,
                &account_id,
                &account_pk,
                &my_address,
                &cipher_pk_hex,
                &network,
                &near_rpc,
                &stack.configs,
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
                network.clone(),
                sign_rx,
                &node_client,
                &contract_watcher,
                keystore,
                triple_storage.clone(),
                presignature_storage.clone(),
                mesh_state.clone(),
                rpc_channel.clone(),
                sync_report_tx,
            )
            .await;

            tracing::info!("protocol initialized");
            let mut tasks = JoinSet::new();
            tasks.spawn(sync_task.run());
            tasks.spawn(rpc_executor.run(
                backlog.clone(),
                contract_state_tx,
                config_tx.clone(),
                checkpoints_tx,
            ));
            tasks.spawn(mesh.run(contract_watcher.clone()));
            // A blocking loop; `main` shuts the runtime down in the background
            // so it does not keep the process alive.
            spawn_system_metrics().await;
            tasks.spawn(protocol.run(
                node,
                near_governance_client,
                contract_watcher.clone(),
                mesh_state.clone(),
            ));
            tasks.spawn(web::run(
                web_port,
                message_channel,
                node_watcher,
                triple_storage,
                presignature_storage,
                contract_watcher.clone(),
                network.clone(),
                account_id,
                backlog.clone(),
            ));

            spawn_indexers(
                &mut tasks,
                stack,
                sign_tx,
                rpc_channel.clone(),
                backlog.clone(),
                contract_watcher.clone(),
                mesh_state.clone(),
                node_client.clone(),
                checkpoints_rx,
            )
            .await?;
            tracing::info!("node tasks spawned");

            // A core task never returns in normal operation, so the first to
            // finish ends the node; a stop signal ends it cleanly.
            let outcome = tokio::select! {
                finished = tasks.join_next() => Err(match finished {
                    Some(Ok(Err(err))) => err,
                    Some(Err(join)) => anyhow::Error::from(join),
                    _ => anyhow::anyhow!("core task exited"),
                }),
                _ = shutdown.cancelled() => Ok(()),
            };
            match &outcome {
                Ok(()) => tracing::info!("shutdown requested, stopping"),
                Err(err) => tracing::error!(?err, "core task ended, shutting down"),
            }
            tasks.abort_all();
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok(Err(err)) => tracing::error!(?err, "core task also failed"),
                    Err(join) if !join.is_cancelled() => {
                        tracing::error!(?join, "core task also failed")
                    }
                    _ => {}
                }
            }
            outcome
        }
    }
}

/// Cancelled on SIGTERM or Ctrl-C. If a handler cannot be installed the node
/// runs without one and stops the way the OS stops it.
fn shutdown_signal() -> CancellationToken {
    let token = CancellationToken::new();
    let cancel = token.clone();
    tokio::spawn(async move {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(err) => {
                    tracing::error!(?err, "no SIGTERM handler; stops will not be orderly");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            _ = terminate => tracing::info!(signal = "SIGTERM", "stop signal received"),
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => tracing::info!(signal = "SIGINT", "stop signal received"),
                Err(err) => {
                    tracing::error!(?err, "no SIGINT handler; stops will not be orderly");
                    std::future::pending::<()>().await;
                }
            },
        }
        cancel.cancel();
    });
    token
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
    tron: Option<TronConfig>,
}

impl ChainConfigs {
    fn from_args(
        eth: EthArgs,
        sol: SolArgs,
        hydration: HydrationArgs,
        canton: CantonArgs,
        midnight: MidnightArgs,
        tron: TronArgs,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            eth: eth.into_config()?,
            sol: sol.into_config(),
            hydration: hydration.into_config(),
            canton: canton.into_config(),
            midnight: midnight.into_config()?,
            tron: tron.into_config()?,
        })
    }
}

/// Per-chain configs paired with runtime RPC state, built once at startup.
struct ChainStack {
    configs: ChainConfigs,
    /// One 429 cooldown gate per chain, shared by that chain's indexer and
    /// publisher (they hit the same RPC endpoint).
    gates: EnumMap<Chain, SharedBackoff>,
    /// Where the Midnight funding wallet keeps its DUST replay across restarts.
    midnight_dust: Option<Arc<dyn DustCheckpointStore>>,
}

impl ChainStack {
    fn new(configs: ChainConfigs) -> Self {
        Self {
            configs,
            gates: EnumMap::from_fn(|_| SharedBackoff::new()),
            midnight_dust: None,
        }
    }

    fn with_midnight_dust(mut self, store: Arc<dyn DustCheckpointStore>) -> Self {
        self.midnight_dust = Some(store);
        self
    }

    fn gate(&self, chain: Chain) -> SharedBackoff {
        self.gates[chain].clone()
    }

    /// Wraps an internally-ungated publisher in [`GatedPublisher`] bound to
    /// this stack's gate for `chain` (Solana, Midnight and Hydration are
    /// externally gated — their clients don't gate publishes themselves).
    /// `operation` labels the adapter's throttle warn per chain.
    ///
    /// TODO: deleted once those clients gate publishes internally
    fn gated_publisher<P: ChainPublisher>(
        &self,
        chain: Chain,
        operation: &'static str,
        publisher: P,
    ) -> Arc<dyn ChainPublisher> {
        Arc::new(GatedPublisher::new(publisher, self.gate(chain), operation))
    }

    /// Build the registry of chain publishers, keyed by chain. NEAR is always present;
    /// each other chain is added only when configured. A configured chain whose client
    /// cannot be built fails startup: a node must not sign for a chain it cannot reach.
    /// `backlog` lets publishers that queue (Midnight) re-check a response before spending on it.
    async fn publishers(
        &self,
        near: NearClient,
        backlog: Backlog,
    ) -> anyhow::Result<HashMap<Chain, Arc<dyn ChainPublisher>>> {
        let mut publishers: HashMap<Chain, Arc<dyn ChainPublisher>> = HashMap::new();
        publishers.insert(Chain::NEAR, Arc::new(near));

        if let Some(eth) = &self.configs.eth {
            let telemetry = Arc::new(NodeTelemetry::new(Chain::Ethereum));
            let client = Arc::new(publisher::EthClient::new(
                eth,
                telemetry,
                self.gate(Chain::Ethereum),
            ));
            publishers.insert(Chain::Ethereum, client);
        }
        if let Some(sol) = &self.configs.sol {
            let telemetry = Arc::new(NodeTelemetry::new(Chain::Solana));
            let client = SolanaClient::from_config(sol, telemetry);
            publishers.insert(
                Chain::Solana,
                self.gated_publisher(Chain::Solana, "solana publish", client),
            );
        }
        if let Some(hydration) = &self.configs.hydration {
            let telemetry = Arc::new(NodeTelemetry::new(Chain::Hydration));
            let client = rpc::HydrationClient::new(hydration, telemetry)
                .context("failed to create hydration client")?;
            publishers.insert(
                Chain::Hydration,
                self.gated_publisher(Chain::Hydration, "hydration publish", client),
            );
        }
        if let Some(canton) = &self.configs.canton {
            let telemetry = Arc::new(NodeTelemetry::new(Chain::Canton));
            let client = CantonClient::new(canton, telemetry, self.gate(Chain::Canton))
                .await
                .context("failed to create canton client")?;
            publishers.insert(Chain::Canton, Arc::new(client));
        }
        if let Some(midnight) = &self.configs.midnight {
            let telemetry = Arc::new(NodeTelemetry::new(Chain::Midnight));
            let awaiter = Arc::new(rpc::BacklogAwaiter::new(backlog));
            let client = RecoveringMidnightPublisher::start(
                midnight,
                telemetry,
                awaiter,
                self.midnight_dust.clone(),
            )
            .context("failed to create midnight publisher")?;
            publishers.insert(
                Chain::Midnight,
                self.gated_publisher(Chain::Midnight, "midnight publish", client),
            );
        }

        Ok(publishers)
    }
}

/// Host of `url` for the startup log: RPC URLs may carry API keys.
fn host_of(url: &Url) -> &str {
    url.host_str().unwrap_or("invalid")
}

/// Emit the single structured "starting node" banner describing this node's identity
/// and which chains it is configured to index.
#[allow(clippy::too_many_arguments)]
fn log_startup(
    mpc_contract_id: &AccountId,
    account_id: &AccountId,
    account_pk: &near_crypto::PublicKey,
    my_address: &Url,
    cipher_pk_hex: &str,
    network: &NetworkConfig,
    near_rpc: &Url,
    chains: &ChainConfigs,
) {
    let eth_signer_address = chains.eth.as_ref().map(|c| c.signer_address());
    let sol_signer_address = chains.sol.as_ref().map(|c| c.signer_address());
    let hydration_signer_address = chains.hydration.as_ref().and_then(|c| c.signer_address());

    tracing::info!(
        %mpc_contract_id,
        %account_id,
        %account_pk,
        %my_address,
        cipher_pk_hex = %cipher_pk_hex,
        version = %crate::metrics::version(),
        git_commit_hash = %crate::metrics::git_commit_hash(),
        build_timestamp = %crate::metrics::build_timestamp(),
        sign_pk = %network.sign_sk.public_key(),
        near_rpc_host = %host_of(near_rpc),
        eth_contract_address = %chains.eth.as_ref().map(|c| c.contract_address.to_string()).unwrap_or_else(|| "None".to_string()),
        eth_signer_address = %eth_signer_address.as_deref().unwrap_or("None"),
        sol_program_address = %chains.sol.as_ref().map(|c| c.program_address.to_string()).unwrap_or_else(|| "None".to_string()),
        sol_rpc_host = %chains.sol.as_ref().map_or("None", |c| host_of(&c.rpc_http_url)),
        sol_signer_address = %sol_signer_address.as_deref().unwrap_or("None"),
        hydration_rpc_host = %chains.hydration.as_ref().map_or("None", |c| host_of(&c.rpc_ws_url)),
        hydration_signer_address = %hydration_signer_address.as_deref().unwrap_or("None"),
        canton_json_api_host = %chains.canton.as_ref().map_or("None", |c| host_of(&c.json_api_url)),
        // Midnight still holds its node URL as a string.
        midnight_node_host = %chains.midnight.as_ref().map_or("None".to_string(), |c| c.node_url.parse().map_or("invalid".to_string(), |url| host_of(&url).to_string())),
        tron_host = %chains.tron.as_ref().map_or("None", |c| host_of(&c.endpoint)),
        "starting node",
    );
}

struct MeshHandles {
    node_client: NodeClient,
    mesh: Mesh,
    mesh_state: watch::Receiver<MeshState>,
    contract_watcher: ContractStateWatcher,
    contract_state_tx: watch::Sender<Option<ProtocolState>>,
    sync_report_tx: SyncReportSender,
}

impl MeshHandles {
    fn new(account_id: &AccountId) -> Self {
        let node_client = NodeClient::new();
        let (sync_report_tx, sync_report_rx) = SyncTask::sync_report_channel();
        let mesh = Mesh::new(
            &node_client,
            mesh::PING_INTERVAL,
            account_id,
            sync_report_rx,
        );
        let mesh_state = mesh.watch();
        let (contract_watcher, contract_state_tx) = ContractStateWatcher::new(account_id);
        Self {
            node_client,
            mesh,
            mesh_state,
            contract_watcher,
            contract_state_tx,
            sync_report_tx,
        }
    }
}

struct RpcHandles {
    near_governance_client: NearGovernanceClient,
    rpc_channel: RpcChannel,
    rpc_executor: RpcExecutor,
}

impl RpcHandles {
    async fn new(
        near_rpc_url: &Url,
        my_address: &Url,
        network: &NetworkConfig,
        mpc_contract_id: &AccountId,
        signer: InMemorySigner,
        stack: &ChainStack,
        backlog: Backlog,
    ) -> anyhow::Result<Self> {
        let publisher_telemetry = Arc::new(NodeTelemetry::new(Chain::NEAR));
        let near_rpc = near_fetch::Client::new(near_rpc_url.as_str());
        // One set of gates for every NEAR call: the publisher and the governance
        // client share the endpoint and the signer.
        let near_gates = NearRpcGates::new(stack.gate(Chain::NEAR));
        let near_client = NearClient::new(
            near_rpc.clone(),
            mpc_contract_id,
            signer.clone(),
            near_gates.clone(),
            publisher_telemetry,
        );
        let near_governance_client = NearGovernanceClient::new(
            near_rpc,
            my_address,
            &network.sign_sk,
            &network.cipher_sk,
            mpc_contract_id,
            signer,
            near_gates,
        );
        let publishers = stack.publishers(near_client, backlog).await?;
        let (rpc_channel, rpc_executor) =
            RpcExecutor::new(near_governance_client.clone(), publishers).await;
        Ok(Self {
            near_governance_client,
            rpc_channel,
            rpc_executor,
        })
    }
}

struct StorageHandles {
    keystore: Keystore,
    triple_storage: TripleStorage<Initializing>,
    presignature_storage: PresignatureStorage<Initializing>,
    backlog: Backlog,
    midnight_dust: Arc<dyn DustCheckpointStore>,
}

const REDIS_TIMEOUT: Duration = Duration::from_secs(5);

/// A Redis pool whose waits, connects and commands all fail after [`REDIS_TIMEOUT`].
fn redis_pool(url: Url) -> anyhow::Result<deadpool_redis::Pool> {
    Ok(deadpool_redis::Config::from_url(url)
        .builder()?
        .runtime(Runtime::Tokio1)
        .wait_timeout(Some(REDIS_TIMEOUT))
        .create_timeout(Some(REDIS_TIMEOUT))
        .recycle_timeout(Some(REDIS_TIMEOUT))
        .post_create(Hook::sync_fn(|conn, _| {
            conn.set_response_timeout(REDIS_TIMEOUT);
            Ok(())
        }))
        .build()?)
}

impl StorageHandles {
    async fn new(
        account_id: &AccountId,
        storage_options: &storage::Options,
    ) -> anyhow::Result<Self> {
        let keystore = Keystore::init(storage_options, account_id).await?;
        let redis_pool = redis_pool(storage_options.redis_url.clone())?;
        let triple_storage = TriplePair::storage(&redis_pool, account_id);
        let presignature_storage = Presignature::storage(&redis_pool, account_id);
        let backlog = Backlog::persisted(CheckpointStorage::Redis(
            redis_pool.clone(),
            account_id.clone(),
        ));
        let midnight_dust = Arc::new(MidnightDustStorage::new(redis_pool, account_id));
        Ok(Self {
            keystore,
            triple_storage,
            presignature_storage,
            backlog,
            midnight_dust,
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
        network: NetworkConfig,
        sign_rx: mpsc::Receiver<SignCommand>,
        node_client: &NodeClient,
        contract_watcher: &ContractStateWatcher,
        keystore: Keystore,
        triple_storage: TripleStorage<Initializing>,
        presignature_storage: PresignatureStorage<Initializing>,
        mesh_state: watch::Receiver<MeshState>,
        rpc_channel: RpcChannel,
        sync_report_tx: SyncReportSender,
    ) -> Self {
        let (config_tx, config_rx) = Config::channel();
        let (checkpoints_tx, checkpoints_rx) = checkpoint_watchers();
        let node = Node::new();
        let node_watcher = node.watch();

        let message_channel = MessageChannel::spawn(
            node_client.clone(),
            network,
            config_rx.clone(),
            contract_watcher.clone(),
        )
        .await;
        let spawner = SignatureSpawner::new(
            account_id.clone(),
            contract_watcher.clone(),
            presignature_storage.clone(),
            mesh_state.clone(),
            message_channel.clone(),
            rpc_channel,
            sync_report_tx,
        );
        let sign_task = SignatureSpawnerTask::run(spawner, sign_rx, config_rx.clone());
        let protocol = MpcSignProtocol {
            my_account_id: account_id.clone(),
            msg_channel: message_channel.clone(),
            generating: message_channel.subscribe_generation().await,
            resharing: message_channel.subscribe_resharing().await,
            ready: message_channel.subscribe_ready().await,
            sign_task,
            keystore,
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
    tasks: &mut JoinSet<anyhow::Result<()>>,
    stack: ChainStack,
    sign_tx: mpsc::Sender<SignCommand>,
    rpc_channel: RpcChannel,
    backlog: Backlog,
    contract_watcher: ContractStateWatcher,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    checkpoints_rx: EnumMap<Chain, watch::Receiver<Option<CheckpointDigest>>>,
) -> anyhow::Result<()> {
    let ChainStack { configs, gates, .. } = stack;
    let ChainConfigs {
        eth,
        sol,
        hydration,
        canton,
        midnight,
        tron,
    } = configs;

    tracing::info!(
        ethereum = eth.is_some(),
        solana = sol.is_some(),
        hydration = hydration.is_some(),
        canton = canton.is_some(),
        midnight = midnight.is_some(),
        tron = tron.is_some(),
        "spawning chain indexers"
    );

    // Every source chain's stream admits bidirectional requests targeting Ethereum.
    // Admission must match across nodes, so they all need the same Ethereum network.
    let ethereum_chain_id = eth.as_ref().and_then(EthConfig::chain_id);
    if ethereum_chain_id.is_none() {
        tracing::warn!(
            "ethereum not configured: Ethereum-targeted requests are admitted without the \
             chain id check that nodes with ethereum configured apply"
        );
    }

    if tron.is_none() {
        tracing::warn!(
            "tron endpoint not configured: Tron-targeted requests are admitted and signed, \
             but nothing watches their execution or expiry — they stay Executing until a Tron \
             endpoint is configured"
        );
    }

    if let Some(eth_config) = eth {
        let eth_telemetry = NodeTelemetry::new(Chain::Ethereum);
        let eth_indexer = EthereumIndexer::new(
            eth_config,
            backlog.clone(),
            eth_telemetry.clone(),
            gates[Chain::Ethereum].clone(),
        )
        .await
        .context("failed to create ethereum indexer")?;
        tracing::info!("ethereum indexer created successfully");
        tasks.spawn(run_supervised(
            eth_indexer,
            StreamContext::new(
                backlog.clone(),
                sign_tx.clone(),
                rpc_channel.clone(),
                contract_watcher.clone(),
                mesh_state.clone(),
                node_client.clone(),
                checkpoints_rx[Chain::Ethereum].clone(),
            )
            .with_ethereum_chain_id(ethereum_chain_id),
            eth_telemetry,
        ));
    }

    if let Some(sol_config) = sol {
        let sol_telemetry = NodeTelemetry::new(Chain::Solana);
        let sol_indexer = SolanaIndexer::new(
            sol_config,
            backlog.clone(),
            sol_telemetry.clone(),
            gates[Chain::Solana].clone(),
        )
        .context("failed to create solana indexer")?;
        tracing::info!("solana indexer created successfully");
        tasks.spawn(run_supervised(
            sol_indexer,
            StreamContext::new(
                backlog.clone(),
                sign_tx.clone(),
                rpc_channel.clone(),
                contract_watcher.clone(),
                mesh_state.clone(),
                node_client.clone(),
                checkpoints_rx[Chain::Solana].clone(),
            )
            .with_ethereum_chain_id(ethereum_chain_id),
            sol_telemetry,
        ));
    }

    if let Some(hydration_config) = hydration {
        let hydration_telemetry = NodeTelemetry::new(Chain::Hydration);
        // TODO: read-side gating - this indexer's reads don't share the
        // chain's cooldown gate yet
        let hydration_indexer =
            HydrationIndexer::new(hydration_config, hydration_telemetry.clone());
        tracing::info!("hydration indexer created successfully");
        tasks.spawn(run_supervised(
            hydration_indexer,
            StreamContext::new(
                backlog.clone(),
                sign_tx.clone(),
                rpc_channel.clone(),
                contract_watcher.clone(),
                mesh_state.clone(),
                node_client.clone(),
                checkpoints_rx[Chain::Hydration].clone(),
            )
            .with_ethereum_chain_id(ethereum_chain_id),
            hydration_telemetry,
        ));
    }

    if let Some(canton_config) = canton {
        let canton_telemetry = NodeTelemetry::new(Chain::Canton);
        let canton_indexer = CantonIndexer::new(
            canton_config,
            backlog.clone(),
            canton_telemetry.clone(),
            gates[Chain::Canton].clone(),
        )
        .await
        .context("failed to create canton indexer")?;
        tracing::info!("canton indexer created successfully");
        tasks.spawn(run_supervised(
            canton_indexer,
            StreamContext::new(
                backlog.clone(),
                sign_tx.clone(),
                rpc_channel.clone(),
                contract_watcher.clone(),
                mesh_state.clone(),
                node_client.clone(),
                checkpoints_rx[Chain::Canton].clone(),
            )
            .with_ethereum_chain_id(ethereum_chain_id),
            canton_telemetry,
        ));
    }

    if let Some(midnight_config) = midnight {
        let midnight_telemetry = NodeTelemetry::new(Chain::Midnight);
        // TODO: read-side gating - this indexer's reads don't share the
        // chain's cooldown gate yet
        // Waits for the network public key inside the task, so a stop signal or
        // a failed core task during the wait still ends the node.
        let mut contract_watcher = contract_watcher.clone();
        let ctx = StreamContext::new(
            backlog.clone(),
            sign_tx.clone(),
            rpc_channel.clone(),
            contract_watcher.clone(),
            mesh_state.clone(),
            node_client.clone(),
            checkpoints_rx[Chain::Midnight].clone(),
        )
        .with_ethereum_chain_id(ethereum_chain_id);
        let backlog = backlog.clone();
        tasks.spawn(async move {
            tracing::info!("Midnight indexer waiting for the network public key");
            // Fails only when the contract watcher is gone, and then the process
            // is already ending.
            let root_pk = contract_watcher
                .wait_public_key()
                .await
                .context("midnight indexer: no network public key")?;
            let midnight_indexer = MidnightIndexer::new(
                midnight_config,
                backlog,
                midnight_telemetry.clone(),
                root_pk,
            )
            .await
            .context("failed to create midnight indexer")?;
            tracing::info!("midnight indexer created successfully");
            run_supervised(midnight_indexer, ctx, midnight_telemetry).await
        });
    }

    // Target-only: no source indexer — the watcher serves every source
    // chain's Tron-targeted requests.
    if let Some(tron_config) = tron {
        let tron_telemetry = NodeTelemetry::new(Chain::Tron);
        let watcher = TronWatcher::new(tron_config, backlog.clone(), tron_telemetry.clone())
            .context("failed to create tron watcher")?;
        tracing::info!("tron execution watcher created successfully");
        tasks.spawn(run_supervised(
            watcher,
            StreamContext::new(
                backlog.clone(),
                sign_tx.clone(),
                rpc_channel.clone(),
                contract_watcher.clone(),
                mesh_state.clone(),
                node_client.clone(),
                checkpoints_rx[Chain::Tron].clone(),
            )
            .with_ethereum_chain_id(ethereum_chain_id),
            tron_telemetry,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use mpc_chain_integration_core::utils::test::make_publish_action;
    use mpc_primitives::{SignId, SignKind};
    use std::str::FromStr;
    use std::time::Duration;

    use super::*;

    /// No error echoes what the operator typed: every flag meets every way a
    /// secret can land in the input.
    #[test]
    fn no_error_echoes_the_input() {
        use clap::CommandFactory as _;
        let parse = |input: &[String]| {
            let args = ["mpc-node", "start"].map(String::from).into_iter();
            Cli::try_parse_redacted(args.chain(input.iter().cloned()))
                .unwrap_err()
                .to_string()
        };
        let command = Cli::command();
        let flags = command.find_subcommand("start").unwrap().get_arguments();
        for flag in flags.map(|arg| format!("--{}", arg.get_long().unwrap())) {
            for input in [
                vec![format!("{flag}=s3cr3t")],      // bad value, inline
                vec![flag.clone(), "s3cr3t".into()], // bad value, separate
                vec![format!("{flag}s3cr3t")],       // glued to the flag
                vec![flag.clone(), "s3cr3t".into(), "s3cr3t".into()], // stray after the value
            ] {
                let error = parse(&input);
                assert!(!error.contains("s3cr3t"), "{input:?} echoed: {error}");
            }
        }

        // Outside the loop: a secret in the subcommand's place, before `start`.
        let subcommand = Cli::try_parse_redacted(["mpc-node", "s3cr3t"])
            .unwrap_err()
            .to_string();
        assert!(!subcommand.contains("s3cr3t"), "{subcommand}");

        // Operators set env vars, so a rejected value names the one to fix.
        let named = parse(&["--near-rpc=s3cr3t".into()]);
        assert!(named.contains("MPC_NEAR_RPC (--near-rpc)"), "{named}");
    }

    #[test]
    fn peer_address_must_be_http_or_https_with_a_host() {
        for ok in ["http://10.0.0.1:3000", "https://node.example.org"] {
            assert!(parse_peer_address(ok).is_ok(), "{ok} must be accepted");
        }
        for bad in [
            "node.example.org:8080",
            "localhost:3000",
            "ws://node.example.org",
            "file:///tmp/node",
            "node.example.org",
        ] {
            assert!(parse_peer_address(bad).is_err(), "{bad} must be rejected");
        }
    }

    /// A listener that never replies stands in for a stalled Redis.
    #[tokio::test]
    async fn redis_pool_fails_instead_of_hanging_on_a_stalled_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("redis://{}", listener.local_addr().unwrap())).unwrap();
        let pool = redis_pool(url).unwrap();
        let result = tokio::time::timeout(3 * REDIS_TIMEOUT, async {
            let mut conn = pool.get().await?;
            let value: Option<String> = redis::AsyncCommands::get(&mut *conn, "key").await?;
            anyhow::Ok(value)
        })
        .await;
        assert!(
            matches!(result, Ok(Err(_))),
            "expected a timeout error, got {result:?}"
        );
    }

    /// The `MPC_MIDNIGHT_*` env vars feed the same clap fields as the
    /// `--midnight-*` flags, so a set variable can silently backfill a flag a
    /// test left out. Those fixtures use the values a developer running a
    /// local stack exports, which makes that the likely case rather than a
    /// remote one.
    pub(super) fn assert_midnight_env_unset() {
        for var in [
            "MPC_MIDNIGHT_NODE_URL",
            "MPC_MIDNIGHT_CENTRAL_ADDRESS",
            "MPC_MIDNIGHT_RESPONDER_ADDRESS",
            "MPC_MIDNIGHT_FUNDING_SEED",
            "MPC_MIDNIGHT_INDEXER_WS_URL",
            "MPC_MIDNIGHT_OUTPUT_STORAGE_BUCKET",
            "MPC_MIDNIGHT_OUTPUT_STORAGE_PREFIX",
            "MPC_MIDNIGHT_OUTPUT_STORAGE_TIMEOUT_SECS",
        ] {
            assert!(
                std::env::var_os(var).is_none(),
                "{var} is set: these tests require an unpolluted environment"
            );
        }
    }

    /// The Midnight config gate: with no Midnight flags supplied, the chain
    /// must be entirely absent from the node's wiring. `spawn_indexers` reads
    /// the same `chains.midnight` field, so `None` here also means no indexer
    /// is spawned.
    #[tokio::test]
    async fn midnight_off_by_default() {
        assert_midnight_env_unset();

        let chains = ChainConfigs::from_args(
            EthArgs::parse_from(["test"]),
            SolArgs::parse_from(["test"]),
            HydrationArgs::parse_from(["test"]),
            CantonArgs::parse_from(["test"]),
            MidnightArgs::parse_from(["test"]),
            TronArgs::parse_from(["test"]),
        )
        .unwrap();

        assert!(
            chains.midnight.is_none(),
            "empty MidnightArgs must not produce a MidnightConfig"
        );
        assert!(
            chains.tron.is_none(),
            "empty TronArgs must not produce a TronConfig"
        );

        let publishers = ChainStack::new(chains)
            .publishers(undialed_near_client(), Backlog::new())
            .await
            .unwrap();

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

    /// A configured Tron must survive `from_args` into `ChainConfigs``
    #[test]
    fn from_args_routes_a_configured_tron() {
        let chains = ChainConfigs::from_args(
            EthArgs::parse_from(["test"]),
            SolArgs::parse_from(["test"]),
            HydrationArgs::parse_from(["test"]),
            CantonArgs::parse_from(["test"]),
            MidnightArgs::parse_from(["test"]),
            TronArgs::parse_from(["test", "--tron-endpoint", "https://api.trongrid.io"]),
        )
        .unwrap();

        let tron = chains
            .tron
            .expect("configured TronArgs must produce a TronConfig");
        assert_eq!(tron.endpoint.as_str(), "https://api.trongrid.io/");
    }

    /// Hydration's RPC is dialed on first publish: a node whose Hydration
    /// endpoint is down still starts, and a bad signer still fails startup.
    #[tokio::test]
    async fn hydration_publisher_registers_while_its_rpc_is_unreachable() {
        let chains = |signer_uri: &str| ChainConfigs {
            eth: None,
            sol: None,
            hydration: Some(HydrationConfig {
                // Nothing listens on port 1.
                rpc_ws_url: "ws://127.0.0.1:1".parse().unwrap(),
                signer_uri: signer_uri.to_string(),
            }),
            canton: None,
            midnight: None,
            tron: None,
        };

        let publishers = ChainStack::new(chains("//Alice"))
            .publishers(undialed_near_client(), Backlog::new())
            .await
            .unwrap();
        assert!(publishers.contains_key(&Chain::Hydration));

        assert!(ChainStack::new(chains("not a signer uri"))
            .publishers(undialed_near_client(), Backlog::new())
            .await
            .is_err());
    }

    /// A Midnight node that is unreachable at startup must not leave the node without a
    /// Midnight publisher for its lifetime: the publisher registers and connects later.
    #[tokio::test]
    async fn midnight_publisher_registers_while_its_node_is_unreachable() {
        let chains = ChainConfigs {
            eth: None,
            sol: None,
            hydration: None,
            canton: None,
            midnight: Some(MidnightConfig {
                // Nothing listens on port 1, so the startup dial is refused.
                node_url: "http://127.0.0.1:1".to_string(),
                central_address: mpc_chain_midnight::MidnightAddress::from_bytes([0xab; 32]),
                responder_address: mpc_chain_midnight::MidnightAddress::from_bytes([0xcd; 32]),
                publisher: mpc_chain_midnight::PublisherConfig {
                    funding_seed: "ab".repeat(32),
                    indexer_ws_url: "ws://127.0.0.1:1/api/v3/graphql/ws".to_string(),
                    ..Default::default()
                },
                rpc: Default::default(),
                indexer: Default::default(),
            }),
            tron: None,
        };

        let publishers = ChainStack::new(chains)
            .publishers(undialed_near_client(), Backlog::new())
            .await
            .unwrap();

        assert!(publishers.contains_key(&Chain::Midnight));
    }

    /// A NEAR client that is never dialed: publishers() only stores it in the registry.
    fn undialed_near_client() -> NearClient {
        let account_id = AccountId::from_str("test.near").unwrap();
        let signer = match InMemorySigner::from_secret_key(
            account_id.clone(),
            SecretKey::from_seed(near_crypto::KeyType::ED25519, "test"),
        ) {
            near_crypto::Signer::InMemory(signer) => signer,
            _ => unreachable!(),
        };
        let near = near_fetch::Client::new("http://127.0.0.1:1");
        NearClient::new(
            near,
            &account_id,
            signer,
            NearRpcGates::new(SharedBackoff::new()),
            Arc::new(NodeTelemetry::new(Chain::NEAR)),
        )
    }

    fn sol_config_with_bogus_rpc() -> SolConfig {
        SolConfig {
            account_sk: mpc_chain_solana::Keypair::new().to_base58_string(),
            rpc_http_url: "http://127.0.0.1:1".parse().unwrap(),
            program_address: mpc_chain_solana::Pubkey::new_unique(),
            indexer: Default::default(),
        }
    }
    #[tokio::test]
    async fn solana_publisher_shares_the_stacks_cooldown_gate() {
        let stack = ChainStack::new(ChainConfigs {
            eth: None,
            sol: Some(sol_config_with_bogus_rpc()),
            hydration: None,
            canton: None,
            midnight: None,
            tron: None,
        });

        let publishers = stack
            .publishers(undialed_near_client(), Backlog::new())
            .await
            .unwrap();
        let publisher = publishers
            .get(&Chain::Solana)
            .expect("solana publisher must be wired when configured");

        // engage the stack's own gate and check the publisher parks on it
        stack.gate(Chain::Solana).extend_cooldown();

        let start = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            publisher.publish_signature(&make_publish_action(
                Chain::Solana,
                SignKind::Sign,
                SignId::new([0u8; 32]),
            )),
        )
        .await
        .expect("publish must not hang on an engaged gate");

        // the bogus endpoint rejects the send itself; only the park matters
        assert!(outcome.is_err());
        assert!(
            start.elapsed() >= Duration::from_millis(700),
            "publish must wait out the stack gate's engaged window (base cooldown), took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn hide_env_values_configured_on_secret_arguments() {
        use clap::CommandFactory;

        let cmd = Cli::command();
        let start = cmd
            .find_subcommand("start")
            .expect("start subcommand must exist");

        let sensitive_arg_ids = [
            // Secret keys & credentials
            "account_sk",
            "cipher_sk",
            "sign_sk",
            "redis_url",
            "sol_account_sk",
            "eth_account_sk",
            "signer_uri",
            "canton_oidc_client_secret",
            "midnight_funding_seed",
            "near_rpc",
            "otlp_endpoint",
            "eth_execution_rpc_http_url",
            "sol_rpc_http_url",
            "rpc_ws_url",
            "canton_json_api_url",
            "canton_json_api_ws_url",
            "canton_oidc_token_url",
            "midnight_node_url",
            "midnight_indexer_ws_url",
            "tron_endpoint",
            "tron_api_key",
        ];

        for arg_id in sensitive_arg_ids {
            let arg = start
                .get_arguments()
                .find(|a| a.get_id() == arg_id)
                .unwrap_or_else(|| panic!("arg {arg_id} not found"));
            assert!(
                arg.is_hide_env_values_set(),
                "arg {arg_id} must have hide_env_values set"
            );
        }
    }
}
