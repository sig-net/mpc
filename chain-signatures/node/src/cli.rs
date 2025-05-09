use crate::config::{Config, LocalConfig, NetworkConfig, OverrideConfig};
use crate::gcp::GcpService;
use crate::mesh::Mesh;
use crate::node_client::{self, NodeClient};
use crate::protocol::message::MessageChannel;
use crate::protocol::sync::SyncTask;
use crate::protocol::{spawn_system_metrics, MpcSignProtocol, SignQueue};
use crate::rpc::{NearClient, NodeStateWatcher, RpcExecutor};
use crate::storage::app_data_storage;
use crate::{indexer, indexer_eth, indexer_sol, logs, mesh, storage, web};
use clap::Parser;
use deadpool_redis::Runtime;
use k256::sha2::Sha256;
use local_ip_address::local_ip;
use near_account_id::AccountId;
use near_crypto::{InMemorySigner, PublicKey, SecretKey};
use sha3::Digest;
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
        #[arg(long, env("MPC_CONTRACT_ID"), default_value("dev.sig-net.testnet"))]
        mpc_contract_id: AccountId,
        /// This node's account id
        #[arg(long, env("MPC_ACCOUNT_ID"))]
        account_id: AccountId,
        /// This node's account ed25519 secret key
        #[arg(long, env("MPC_ACCOUNT_SK"))]
        account_sk: SecretKey,
        /// The web port for this server
        #[arg(long, env("MPC_WEB_PORT"))]
        web_port: u16,
        /// The cipher secret key used to decrypt messages between nodes.
        #[arg(long, env("MPC_CIPHER_SK"))]
        cipher_sk: String,
        /// The secret key used to sign messages to be sent between nodes.
        #[arg(long, env("MPC_SIGN_SK"))]
        sign_sk: Option<SecretKey>,
        /// Ethereum Indexer options
        #[clap(flatten)]
        eth: indexer_eth::EthArgs,
        /// Solana Indexer options
        #[clap(flatten)]
        sol: indexer_sol::SolArgs,
        /// NEAR Lake Indexer options
        #[clap(flatten)]
        indexer_options: indexer::Options,
        /// Local address that other peers can use to message this node.
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
                    "--web-port".to_string(),
                    web_port.to_string(),
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

                args.extend(eth.into_str_args());
                args.extend(sol.into_str_args());
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

            let cipher_sk = hpke::SecretKey::try_from_bytes(&hex::decode(cipher_sk)?)?;

            let digest = configuration_digest(
                mpc_contract_id.clone(),
                account_id.clone(),
                account_sk.clone(),
                format!("{:?}", cipher_sk.public_key()),
                sign_sk.clone(),
                eth.clone(),
            );

            crate::metrics::CONFIGURATION_DIGEST
                .with_label_values(&[account_id.as_str()])
                .set(digest);

            let (sign_tx, sign_rx) = SignQueue::channel();

            let gcp_service = GcpService::init(&account_id, &storage_options).await?;

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

            // NEAR Indexer is only used for integration tests
            // TODO: Remove this once we have integration tests built on other chains
            let indexer = if storage_options.env == "integration-tests" {
                let (_handle, indexer) = indexer::run(
                    &indexer_options,
                    &mpc_contract_id,
                    &account_id,
                    sign_tx.clone(),
                    app_data_storage.clone(),
                    rpc_client.clone(),
                )?;
                Some(indexer)
            } else {
                None
            };

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
            let mesh = Mesh::new(&client, mesh_options);
            let mesh_state = mesh.state().clone();
            let watcher = NodeStateWatcher::new(&account_id);
            let contract_state = watcher.state().clone();

            let eth = eth.into_config();
            let sol = sol.into_config();
            let network = NetworkConfig { cipher_sk, sign_sk };
            let near_client =
                NearClient::new(&near_rpc, &my_address, &network, &mpc_contract_id, signer);
            let (rpc_channel, rpc) = RpcExecutor::new(&near_client, &eth, &sol);
            let (sync_channel, sync) = SyncTask::new(
                &client,
                triple_storage.clone(),
                presignature_storage.clone(),
                mesh_state.clone(),
                watcher,
            );

            tracing::info!(
                %digest,
                ?mpc_contract_id,
                ?account_id,
                ?my_address,
                cipher_pk = ?network.cipher_sk.public_key(),
                sign_pk = ?network.sign_sk.public_key(),
                near_rpc_url = ?near_client.rpc_addr(),
                eth_contract_address = ?eth.as_ref().map(|eth| eth.contract_address.as_str()),
                "starting node",
            );

            let config = Arc::new(RwLock::new(Config::new(LocalConfig {
                over: override_config.unwrap_or_else(Default::default),
                network,
            })));

            let state = Arc::new(RwLock::new(crate::protocol::NodeState::Starting));
            let (sender, msg_channel) =
                MessageChannel::spawn(client, &account_id, &config, &state, &mesh_state).await;
            let protocol = MpcSignProtocol {
                my_account_id: account_id.clone(),
                state: state.clone(),
                near: near_client,
                rpc_channel,
                msg_channel,
                sign_rx: Arc::new(RwLock::new(sign_rx)),
                secret_storage: key_storage,
                triple_storage: triple_storage.clone(),
                presignature_storage: presignature_storage.clone(),
            };

            tracing::info!("protocol initialized");
            tokio::spawn(sync.run());
            tokio::spawn(rpc.run(contract_state.clone(), config.clone()));
            tokio::spawn(mesh.run(contract_state.clone()));
            let system_handle = spawn_system_metrics(account_id.as_str()).await;
            let protocol_handle = tokio::spawn(protocol.run(contract_state, config, mesh_state));
            tracing::info!("protocol thread spawned");
            let web_handle = tokio::spawn(web::run(
                web_port,
                sender,
                state,
                indexer,
                triple_storage,
                presignature_storage,
                sync_channel,
            ));
            tokio::spawn(indexer_eth::run(eth, sign_tx.clone(), account_id.clone()));
            tokio::spawn(indexer_sol::run(sol, sign_tx, account_id));
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
    mpc_contrac_id: AccountId,
    account_id: AccountId,
    account_sk: SecretKey,
    cipher_pk: String,
    sign_sk: Option<SecretKey>,
    eth: indexer_eth::EthArgs,
) -> i64 {
    let sign_sk = sign_sk.unwrap_or_else(|| account_sk.clone());
    let eth_contract_address = eth.eth_contract_address.unwrap_or_default();
    calculate_digest(
        mpc_contrac_id,
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
    let mut hasher = Sha256::new();
    hasher.update(mpc_contract_id.to_string());
    hasher.update(account_id.to_string());
    hasher.update(account_pk.to_string());
    hasher.update(cipher_pk);
    hasher.update(sign_pk.to_string());
    hasher.update(eth_contract_address);

    let result = hasher.finalize();
    // Convert the first 8 bytes of the hash to an i64
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&result[..8]);
    i64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

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

        // Grafana value: -1051225187120159700
        assert_eq!(digest, -1051225187120159684);
    }

    #[test]
    fn test_digest_luganodes() {
        let mpc_contract_id = AccountId::from_str("v1.sig-net.near").unwrap();
        let account_id = AccountId::from_str("luganodes-sig.near").unwrap();
        let account_pk =
            PublicKey::from_str("ed25519:HKwJr6kRcARfjHawX6pVcQPxPdTQMvAN7r8Z2kUcPfLc").unwrap();
        let cipher_pk = "fe24961ff9fe0fb11cca7f31dd7173b9f15177e5809eb1054f99faf196f1c25d";
        let sign_pk =
            PublicKey::from_str("ed25519:5GNBtNcnpmJh2iijxWiSepeHvWeet3UuhBTwWCncCdTh").unwrap();
        let _eth_account_pk = "04f0e7b9b93febc13280307414ff7b61be68b73233d0f590987b4ac8bf5818a859b1810d5a692a416fd47a8cd16a784553d7465c071e0e41e09cf4b9a098cb841a";

        let digest = calculate_digest(
            mpc_contract_id,
            account_id,
            account_pk,
            cipher_pk.to_string(),
            sign_pk,
            ETH_CONTRACT_ADDRESS.to_string(),
        );

        // Grafana value: 8063794122839817000 (looks broken)
        assert_eq!(digest, 8458603761268706511);
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

        // Grafana value: --4992003418219577000
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

        // Grafana value --930268115875971800
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

        // Grafana value: 695826193095166700
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

        // Grafana value: -8209029844787148000
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
        // Grafana value: -4889179067099200000
        assert_eq!(digest, -4889179067099199685);
    }
}
