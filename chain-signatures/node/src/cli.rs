use crate::config::{Config, LocalConfig, NetworkConfig, OverrideConfig};
use crate::gcp::GcpService;
use crate::mesh::Mesh;
use crate::node_client::{self, NodeClient};
use crate::protocol::message::MessageChannel;
use crate::protocol::{MpcSignProtocol, SignQueue};
use crate::storage::app_data_storage;
use crate::{indexer, indexer_eth, logs, mesh, storage, web};
use clap::Parser;
use deadpool_redis::Runtime;
use local_ip_address::local_ip;
use near_account_id::AccountId;
use near_crypto::{InMemorySigner, SecretKey};
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

use mpc_keys::hpke;

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
        #[arg(long, env("MPC_CONTRACT_ID"), default_value("v1.signer-dev.testnet"))]
        mpc_contract_id: AccountId,
        /// This node's account id
        #[arg(long, env("MPC_ACCOUNT_ID"))]
        account_id: AccountId,
        /// This node's account ed25519 secret key
        #[arg(long, env("MPC_ACCOUNT_SK"))]
        account_sk: SecretKey,
        /// The ethereum account secret key used to sign eth respond txn.
        #[arg(long, env("MPC_ETH_ACCOUNT_SK"))]
        eth_account_sk: String,
        /// The web port for this server
        #[arg(long, env("MPC_WEB_PORT"))]
        web_port: u16,
        // TODO: need to add in CipherPK type for parsing.
        /// The cipher public key used to encrypt messages between nodes.
        #[arg(long, env("MPC_CIPHER_PK"))]
        cipher_pk: String,
        /// The cipher secret key used to decrypt messages between nodes.
        #[arg(long, env("MPC_CIPHER_SK"))]
        cipher_sk: String,
        /// The secret key used to sign messages to be sent between nodes.
        #[arg(long, env("MPC_SIGN_SK"))]
        sign_sk: Option<SecretKey>,
        /// NEAR Lake Indexer options
        #[clap(flatten)]
        indexer_options: indexer::Options,
        /// Ethereum Indexer options
        #[clap(flatten)]
        indexer_eth_options: indexer_eth::Options,
        /// Local address that other peers can use to message this node.
        #[arg(long, env("MPC_LOCAL_ADDRESS"))]
        my_address: Option<Url>,
        /// Debuggable id for each MPC node for logging purposes
        #[arg(long, env("MPC_DEBUG_NODE_ID"))]
        debug_id: Option<usize>,
        /// Storage options
        #[clap(flatten)]
        storage_options: storage::Options,
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
                eth_account_sk,
                web_port,
                cipher_pk,
                cipher_sk,
                sign_sk,
                indexer_options,
                indexer_eth_options,
                my_address,
                debug_id,
                storage_options,
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
                    "--eth-account-sk".to_string(),
                    eth_account_sk.to_string(),
                    "--web-port".to_string(),
                    web_port.to_string(),
                    "--cipher-pk".to_string(),
                    cipher_pk,
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
                if let Some(debug_id) = debug_id {
                    args.extend(["--debug-id".to_string(), debug_id.to_string()]);
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

                args.extend(indexer_options.into_str_args());
                args.extend(indexer_eth_options.into_str_args());
                args.extend(storage_options.into_str_args());
                args.extend(mesh_options.into_str_args());
                args.extend(message_options.into_str_args());
                args
            }
        }
    }
}

pub fn run(cmd: Cli) -> anyhow::Result<()> {
    match cmd {
        Cli::Start {
            near_rpc,
            web_port,
            mpc_contract_id,
            account_id,
            account_sk,
            eth_account_sk,
            cipher_pk,
            cipher_sk,
            sign_sk,
            indexer_options,
            indexer_eth_options,
            my_address,
            debug_id,
            storage_options,
            override_config,
            client_header_referer,
            mesh_options,
            message_options,
        } => {
            logs::install_global(debug_id);
            let _span = tracing::trace_span!("cli").entered();

            let (sign_tx, sign_rx) = SignQueue::channel();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let gcp_service =
                rt.block_on(async { GcpService::init(&account_id, &storage_options).await })?;

            let key_storage =
                storage::secret_storage::init(Some(&gcp_service), &storage_options, &account_id);

            let redis_url: Url = Url::parse(storage_options.redis_url.as_str())?;

            let redis_cfg = deadpool_redis::Config::from_url(redis_url);
            let redis_pool = redis_cfg.create_pool(Some(Runtime::Tokio1)).unwrap();
            let triple_storage = storage::triple_storage::init(&redis_pool, &account_id);
            let presignature_storage =
                storage::presignature_storage::init(&redis_pool, &account_id);
            let app_data_storage = app_data_storage::init(&redis_pool, &account_id);

            let mut rpc_client = near_fetch::Client::new(&near_rpc);
            if let Some(referer_param) = client_header_referer {
                let client_headers = rpc_client.inner_mut().headers_mut();
                client_headers.insert(http::header::REFERER, referer_param.parse().unwrap());
            }
            tracing::info!(rpc_addr = rpc_client.rpc_addr(), "rpc client initialized");

            let (indexer_handle, indexer) = indexer::run(
                &indexer_options,
                &mpc_contract_id,
                &account_id,
                sign_tx.clone(),
                app_data_storage.clone(),
                rpc_client.clone(),
            )?;

            let sign_sk = sign_sk.unwrap_or_else(|| account_sk.clone());
            let my_address = my_address
                .map(|mut addr| {
                    addr.set_port(Some(web_port)).unwrap();
                    addr
                })
                .unwrap_or_else(|| {
                    let my_ip = local_ip().unwrap();
                    Url::parse(&format!("http://{my_ip}:{web_port}")).unwrap()
                });

            tracing::info!(%my_address, "address detected");
            let client = NodeClient::new(&message_options);
            let signer = InMemorySigner::from_secret_key(account_id.clone(), account_sk);
            let (mesh, mesh_state) = Mesh::init(&client, mesh_options);
            let config = Arc::new(RwLock::new(Config::new(LocalConfig {
                over: override_config.unwrap_or_else(Default::default),
                network: NetworkConfig {
                    cipher_sk: hpke::SecretKey::try_from_bytes(&hex::decode(cipher_sk)?)?,
                    cipher_pk: hpke::PublicKey::try_from_bytes(&hex::decode(cipher_pk)?)?,
                    sign_sk,
                },
            })));
            let contract_state = Arc::new(RwLock::new(None));

            let contract_updater =
                crate::contract_updater::ContractUpdater::init(&rpc_client, &mpc_contract_id);

            rt.block_on(async {
                let state = Arc::new(RwLock::new(crate::protocol::NodeState::Starting));
                let (sender, channel) =
                    MessageChannel::spawn(client, &account_id, &config, &state, &mesh_state).await;
                let protocol = MpcSignProtocol::init(
                    my_address,
                    mpc_contract_id,
                    account_id.clone(),
                    state.clone(),
                    rpc_client,
                    signer,
                    channel,
                    sign_rx,
                    key_storage,
                    triple_storage,
                    presignature_storage,
                    indexer_eth_options.eth_rpc_http_url.clone(),
                    indexer_eth_options.eth_contract_address.clone(),
                    eth_account_sk,
                );

                tracing::info!("protocol initialized");
                let contract_handle =
                    tokio::spawn(contract_updater.run(contract_state.clone(), config.clone()));
                let mesh_handle = tokio::spawn(mesh.run(contract_state.clone()));
                let protocol_handle =
                    tokio::spawn(protocol.run(contract_state, config, mesh_state));
                tracing::info!("protocol thread spawned");
                let cipher_sk = hpke::SecretKey::try_from_bytes(&hex::decode(cipher_sk)?)?;
                let web_handle = tokio::spawn(async move {
                    web::run(web_port, sender, cipher_sk, protocol_state, indexer).await
                });
                let eth_indexer_handle = tokio::spawn(async move {
                    indexer_eth::run(&indexer_eth_options, sign_tx, &account_id).await
                });
                tracing::info!("protocol http server spawned");

                contract_handle.await??;
                mesh_handle.await??;
                protocol_handle.await??;
                web_handle.await??;
                eth_indexer_handle.await??;
                tracing::info!("spinning down");

                indexer_handle.join().unwrap()?;

                anyhow::Ok(())
            })?;
        }
    }

    Ok(())
}
