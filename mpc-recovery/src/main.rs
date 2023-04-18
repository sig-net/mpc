use clap::Parser;
use mpc_recovery::LeaderConfig;
use near_primitives::types::AccountId;
use threshold_crypto::{serde_impl::SerdeSecret, PublicKeySet, SecretKeyShare};

mod gcp;

#[derive(Parser, Debug)]
enum Cli {
    Generate {
        n: usize,
        t: usize,
    },
    StartLeader {
        /// Node ID
        #[arg(long, env("MPC_RECOVERY_NODE_ID"))]
        node_id: u64,
        /// Root public key
        #[arg(long, env("MPC_RECOVERY_PK_SET"))]
        pk_set: String,
        /// Secret key share, will be pulled from GCP Secret Manager if omitted
        #[arg(long, env("MPC_RECOVERY_SK_SHARE"))]
        sk_share: Option<String>,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
        /// The compute nodes to connect to
        #[arg(long, env("MPC_RECOVERY_SIGN_NODES"))]
        sign_nodes: Vec<String>,
        /// NEAR RPC address
        #[arg(
            long,
            env("MPC_RECOVERY_NEAR_RPC"),
            default_value("https://rpc.testnet.near.org")
        )]
        near_rpc: String,
        /// NEAR meta transaction relayer URL
        #[arg(
            long,
            env("MPC_RECOVERY_RELAYER_URL"),
            default_value("http://34.70.226.83:3030")
        )]
        relayer_url: String,
        /// Account creator ID
        #[arg(long, env("MPC_RECOVERY_ACCOUNT_ID"))]
        account_creator_id: AccountId,
        /// TEMPORARY - Account creator ed25519 secret key
        #[arg(long, env("MPC_RECOVERY_ACCOUNT_CREATOR_SK"))]
        account_creator_sk: String,
    },
    StartSign {
        /// Node ID
        #[arg(long, env("MPC_RECOVERY_NODE_ID"))]
        node_id: u64,
        /// Root public key
        #[arg(long, env("MPC_RECOVERY_PK_SET"))]
        pk_set: String,
        /// Secret key share, will be pulled from GCP Secret Manager if omitted
        #[arg(long, env("MPC_RECOVERY_SK_SHARE"))]
        sk_share: Option<String>,
        /// The web port for this server
        #[arg(long, env("MPC_RECOVERY_WEB_PORT"))]
        web_port: u16,
    },
}

async fn load_sh_skare(node_id: u64, sk_share_arg: Option<String>) -> anyhow::Result<String> {
    match sk_share_arg {
        Some(sk_share) => Ok(sk_share),
        None => Ok(std::str::from_utf8(&gcp::load_secret_share(node_id).await?)?.to_string()),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // install global collector configured based on RUST_LOG env var.
    tracing_subscriber::fmt::init();
    let _span = tracing::trace_span!("cli").entered();

    match Cli::parse() {
        Cli::Generate { n, t } => {
            let (pk_set, sk_shares) = mpc_recovery::generate(n, t)?;
            println!("Public key set: {}", serde_json::to_string(&pk_set)?);
            for (i, sk_share) in sk_shares.iter().enumerate() {
                println!(
                    "Secret key share {}: {}",
                    i,
                    serde_json::to_string(&SerdeSecret(sk_share))?
                );
            }
        }
        Cli::StartLeader {
            node_id,
            pk_set,
            sk_share,
            web_port,
            sign_nodes,
            near_rpc,
            relayer_url,
            account_creator_id,
            account_creator_sk,
        } => {
            let sk_share = load_sh_skare(node_id, sk_share).await?;

            let pk_set: PublicKeySet = serde_json::from_str(&pk_set).unwrap();
            let sk_share: SecretKeyShare = serde_json::from_str(&sk_share).unwrap();

            mpc_recovery::run_leader_node(LeaderConfig {
                id: node_id,
                pk_set,
                sk_share,
                port: web_port,
                sign_nodes,
                near_rpc,
                relayer_url,
                // TODO: Create such an account for testnet and mainnet in a secure way
                account_creator_id,
                // TODO: Load this account secret key from GCP Secret Manager
                account_creator_sk: account_creator_sk.parse()?,
            })
            .await;
        }
        Cli::StartSign {
            node_id,
            pk_set,
            sk_share,
            web_port,
        } => {
            let sk_share = load_sh_skare(node_id, sk_share).await?;

            let pk_set: PublicKeySet = serde_json::from_str(&pk_set).unwrap();
            let sk_share: SecretKeyShare = serde_json::from_str(&sk_share).unwrap();

            mpc_recovery::run_sign_node(node_id, pk_set, sk_share, web_port).await;
        }
    }

    Ok(())
}
