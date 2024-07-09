use crate::gcp::GcpService;
use crate::mesh::NetworkConfig;
use crate::protocol::presignature::PresignatureConfig;
use crate::protocol::triple::TripleConfig;
use crate::protocol::{Config, MpcSignProtocol, SignQueue};
use crate::storage::triple_storage::LockTripleNodeStorageBox;
use crate::{indexer, storage, web};
use clap::Parser;
use local_ip_address::local_ip;
use near_account_id::AccountId;
use near_crypto::{InMemorySigner, SecretKey};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing_subscriber::EnvFilter;
use url::Url;

use mpc_keys::hpke;

#[derive(Parser, Debug)]
pub enum Cli {
    Start {
        /// NEAR RPC address
        #[arg(
            long,
            env("MPC_RECOVERY_NEAR_RPC"),
            default_value("https://rpc.testnet.near.org")
        )]
        near_rpc: String,
        /// MPC contract id
        #[arg(
            long,
            env("MPC_RECOVERY_CONTRACT_ID"),
            default_value("v5.multichain-mpc-dev.testnet")
        )]
        mpc_contract_id: AccountId,
        /// This node's account id
        #[arg(long, env("MPC_RECOVERY_ACCOUNT_ID"))]
        account_id: AccountId,
        /// This node's account ed25519 secret key
        #[arg(long, env("MPC_RECOVERY_ACCOUNT_SK"))]
        account_sk: SecretKey,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
        // TODO: need to add in CipherPK type for parsing.
        /// The cipher public key used to encrypt messages between nodes.
        #[arg(long, env("MPC_RECOVERY_CIPHER_PK"))]
        cipher_pk: String,
        /// The cipher secret key used to decrypt messages between nodes.
        #[arg(long, env("MPC_RECOVERY_CIPHER_SK"))]
        cipher_sk: String,
        /// The secret key used to sign messages to be sent between nodes.
        #[arg(long, env("MPC_RECOVERY_SIGN_SK"))]
        sign_sk: Option<SecretKey>,
        /// NEAR Lake Indexer options
        #[clap(flatten)]
        indexer_options: indexer::Options,
        /// Local address that other peers can use to message this node.
        #[arg(long, env("MPC_RECOVERY_LOCAL_ADDRESS"))]
        my_address: Option<Url>,
        /// Storage options
        #[clap(flatten)]
        storage_options: storage::Options,
        /// At minimum, how many triples to stockpile on this node.
        #[arg(long, env("MPC_RECOVERY_MIN_TRIPLES"), default_value("20"))]
        min_triples: usize,
        /// At maximum, how many triples to stockpile on this node.
        #[arg(long, env("MPC_RECOVERY_MAX_TRIPLES"), default_value("640"))]
        max_triples: usize,

        /// At maximum, how many triple protocols can this current node introduce
        /// at the same time. This should be something like `max_concurrent_gen / num_nodes`
        #[arg(
            long,
            env("MPC_RECOVERY_MAX_CONCURRENT_INTRODUCTION"),
            default_value("2")
        )]
        max_concurrent_introduction: usize,

        /// At maximum, how many ongoing protocols for triples to be running
        /// at the same time. The rest will be queued up.
        #[arg(
            long,
            env("MPC_RECOVERY_MAX_CONCURRENT_GENERATION"),
            default_value("16")
        )]
        max_concurrent_generation: usize,

        /// At minimum, how many presignatures to stockpile on this node.
        #[arg(long, env("MPC_RECOVERY_MIN_PRESIGNATURES"), default_value("10"))]
        min_presignatures: usize,

        /// At maximum, how many presignatures to stockpile on the network.
        #[arg(long, env("MPC_RECOVERY_MAX_PRESIGNATURES"), default_value("320"))]
        max_presignatures: usize,
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
                cipher_pk,
                cipher_sk,
                sign_sk,
                indexer_options,
                my_address,
                storage_options,
                min_triples,
                max_triples,
                max_concurrent_introduction,
                max_concurrent_generation,
                min_presignatures,
                max_presignatures,
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
                    "--cipher-pk".to_string(),
                    cipher_pk,
                    "--cipher-sk".to_string(),
                    cipher_sk,
                    "--min-triples".to_string(),
                    min_triples.to_string(),
                    "--max-triples".to_string(),
                    max_triples.to_string(),
                    "--max-concurrent-introduction".to_string(),
                    max_concurrent_introduction.to_string(),
                    "--max-concurrent-generation".to_string(),
                    max_concurrent_generation.to_string(),
                    "--min-presignatures".to_string(),
                    min_presignatures.to_string(),
                    "--max-presignatures".to_string(),
                    max_presignatures.to_string(),
                ];
                if let Some(sign_sk) = sign_sk {
                    args.extend(["--sign-sk".to_string(), sign_sk.to_string()]);
                }
                if let Some(my_address) = my_address {
                    args.extend(["--my-address".to_string(), my_address.to_string()]);
                }
                args.extend(indexer_options.into_str_args());
                args.extend(storage_options.into_str_args());
                args
            }
        }
    }
}

/// This will whether this code is being ran on top of GCP or not.
fn is_running_on_gcp() -> bool {
    let resp = reqwest::blocking::Client::new()
        .get("http://metadata.google.internal/computeMetadata/v1/instance/id")
        .header("Metadata-Flavor", "Google")
        .send();

    match resp {
        Ok(resp) => resp.status().is_success(),
        _ => false,
    }
}

fn spinup_indexer(
    options: &indexer::Options,
    mpc_contract_id: &AccountId,
    account_id: &AccountId,
    sign_queue: &Arc<RwLock<SignQueue>>,
    gcp: &GcpService,
) -> std::thread::JoinHandle<()> {
    let options = options.clone();
    let mpc_contract_id = mpc_contract_id.clone();
    let account_id = account_id.clone();
    let sign_queue = sign_queue.clone();
    let gcp = gcp.clone();
    std::thread::spawn(move || {
        // If indexer fails for whatever reason, let's spin it back up:
        let mut i = 0;
        loop {
            if i > 0 {
                tracing::info!("restarting indexer after failure: restart count={i}");
            }

            let options = options.clone();
            let mpc_contract_id = mpc_contract_id.clone();
            let account_id = account_id.clone();
            let sign_queue = sign_queue.clone();
            let gcp = gcp.clone();

            // TODO/NOTE: currently indexer does not have any interrupt handlers and will never yield back
            // as successful. We can add interrupt handlers in the future but this is not important right
            // now since we managing nodes through integration tests that can kill it or through docker.
            let Err(err) = indexer::run(options, mpc_contract_id, account_id, sign_queue, gcp)
            else {
                break;
            };
            tracing::error!(%err, "indexer failed");

            let delay = if i <= 7 {
                2u64.pow(i)
            } else {
                // Max out at 2 minutes
                120
            };

            std::thread::sleep(std::time::Duration::from_secs(delay));
            i += 1;
        }
    })
}

pub fn run(cmd: Cli) -> anyhow::Result<()> {
    // Install global collector configured based on RUST_LOG env var.
    let mut subscriber = tracing_subscriber::fmt()
        .with_thread_ids(true)
        .with_env_filter(EnvFilter::from_default_env());
    // Check if running in Google Cloud Run: https://cloud.google.com/run/docs/container-contract#services-env-vars
    if std::env::var("K_SERVICE").is_ok() || is_running_on_gcp() {
        // Disable colored logging as it messes up GCP's log formatting
        subscriber = subscriber.with_ansi(false);
    }
    subscriber.init();
    let _span = tracing::trace_span!("cli").entered();

    match cmd {
        Cli::Start {
            near_rpc,
            web_port,
            mpc_contract_id,
            account_id,
            account_sk,
            cipher_pk,
            cipher_sk,
            sign_sk,
            indexer_options,
            my_address,
            storage_options,
            min_triples,
            max_triples,
            max_concurrent_introduction,
            max_concurrent_generation,
            min_presignatures,
            max_presignatures,
        } => {
            let sign_queue = Arc::new(RwLock::new(SignQueue::new()));
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let (sender, receiver) = mpsc::channel(16384);
                    let gcp_service = GcpService::init(&account_id, &storage_options).await?;
                    let indexer_handle = spinup_indexer(
                        &indexer_options,
                        &mpc_contract_id,
                        &account_id,
                        &sign_queue,
                        &gcp_service,
                    );

                    let key_storage = storage::secret_storage::init(
                        Some(&gcp_service),
                        &storage_options,
                        &account_id,
                    );
                    let triple_storage: LockTripleNodeStorageBox = Arc::new(RwLock::new(
                        storage::triple_storage::init(Some(&gcp_service), &account_id),
                    ));

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
                    let rpc_client = near_fetch::Client::new(&near_rpc);
                    tracing::debug!(rpc_addr = rpc_client.rpc_addr(), "rpc client initialized");
                    let signer = InMemorySigner::from_secret_key(account_id.clone(), account_sk);
                    let (protocol, protocol_state) = MpcSignProtocol::init(
                        my_address,
                        mpc_contract_id,
                        account_id,
                        rpc_client,
                        signer,
                        receiver,
                        sign_queue,
                        key_storage,
                        triple_storage,
                        Config {
                            triple_cfg: TripleConfig {
                                min_triples,
                                max_triples,
                                max_concurrent_introduction,
                                max_concurrent_generation,
                            },
                            presig_cfg: PresignatureConfig {
                                min_presignatures,
                                max_presignatures,
                            },
                            network_cfg: NetworkConfig {
                                cipher_pk: hpke::PublicKey::try_from_bytes(&hex::decode(
                                    cipher_pk,
                                )?)?,
                                sign_sk,
                            },
                        },
                    );
                    tracing::debug!("protocol initialized");
                    let protocol_handle = tokio::spawn(async move { protocol.run().await });
                    tracing::debug!("protocol thread spawned");
                    let cipher_sk = hpke::SecretKey::try_from_bytes(&hex::decode(cipher_sk)?)?;
                    let web_handle = tokio::spawn(async move {
                        web::run(web_port, sender, cipher_sk, protocol_state).await
                    });
                    tracing::debug!("protocol http server spawned");

                    protocol_handle.await??;
                    web_handle.await??;
                    tracing::debug!("spinning down");

                    indexer_handle.join().unwrap();
                    anyhow::Ok(())
                })?;
        }
    }

    Ok(())
}
