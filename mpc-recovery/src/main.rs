mod oauth;

use clap::Parser;
use threshold_crypto::{serde_impl::SerdeSecret, PublicKeySet, SecretKeyShare};

#[derive(Parser, Debug)]
enum Cli {
    Generate {
        n: usize,
        t: usize,
    },
    StartLeader {
        /// Node ID
        node_id: u64,
        /// Root public key
        #[arg(long)]
        pk_set: String,
        /// Secret key share
        #[arg(long)]
        sk_share: String,
        /// The web port for this server
        #[arg(long)]
        web_port: u16,
        /// The compute nodes to connect to
        #[arg(long)]
        sign_nodes: Vec<String>,
    },
    StartSign {
        /// Node ID
        node_id: u64,
        /// Root public key
        #[arg(long)]
        pk_set: String,
        /// Secret key share
        #[arg(long)]
        sk_share: String,
        /// The web port for this server
        #[arg(long)]
        web_port: u16,
    },
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
        } => {
            let pk_set: PublicKeySet = serde_json::from_str(&pk_set).unwrap();
            let sk_share: SecretKeyShare = serde_json::from_str(&sk_share).unwrap();

            mpc_recovery::run_leader_node(node_id, pk_set, sk_share, web_port, sign_nodes).await;
        }
        Cli::StartSign {
            node_id,
            pk_set,
            sk_share,
            web_port,
        } => {
            let pk_set: PublicKeySet = serde_json::from_str(&pk_set).unwrap();
            let sk_share: SecretKeyShare = serde_json::from_str(&sk_share).unwrap();

            mpc_recovery::run_sign_node(node_id, pk_set, sk_share, web_port).await;
        }
    }

    Ok(())
}
