mod ouath;

use clap::Parser;
use threshold_crypto::{serde_impl::SerdeSecret, PublicKeySet, SecretKeyShare};

#[derive(Parser, Debug)]
enum Cli {
    Generate {
        n: usize,
        t: usize,
    },
    Start {
        /// Node ID
        node_id: u64,
        /// Root public key
        pk_set: String,
        /// Secret key share
        sk_share: String,
        /// The actor port for this server
        actor_port: u16,
        /// The web port for this server
        web_port: u16,
        /// The remote server address to connect to (if Some)
        remote_address: Option<String>,
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
        Cli::Start {
            node_id,
            pk_set,
            sk_share,
            actor_port,
            web_port,
            remote_address,
        } => {
            let pk_set: PublicKeySet = serde_json::from_str(&pk_set).unwrap();
            let sk_share: SecretKeyShare = serde_json::from_str(&sk_share).unwrap();

            mpc_recovery::start(
                node_id,
                pk_set,
                sk_share,
                actor_port,
                web_port,
                remote_address,
            )
            .await?;
        }
    }

    Ok(())
}
