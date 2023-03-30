use clap::Parser;
use ractor::Actor;
use ractor_cluster::node::NodeConnectionMode;
use threshold_crypto::{serde_impl::SerdeSecret, PublicKeySet, SecretKeySet, SecretKeyShare};

mod actor;
mod web;

const COOKIE: &str = "mpc-recovery-cookie";

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
        /// The host port for this NodeServer
        port: u16,
        /// The remote server port to connect to (if Some)
        remote_port: Option<u16>,
    },
}

async fn start(
    node_id: u64,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
    port: u16,
    remote_port: Option<u16>,
) {
    let server = ractor_cluster::NodeServer::new(
        port,
        COOKIE.to_string(),
        format!("mpc-recovery-node-{}", node_id),
        "localhost".to_string(),
        None,
        Some(NodeConnectionMode::Transitive),
    );

    let (actor, handle) = Actor::spawn(None, server, ())
        .await
        .expect("Failed to start NodeServer A");

    let (node_actor, node_handle) =
        Actor::spawn(None, actor::NodeActor, (node_id, pk_set.clone(), sk_share))
            .await
            .expect("Ping pong actor failed to start up!");

    if let Some(rport) = remote_port {
        if let Err(error) =
            ractor_cluster::node::client::connect(&actor, format!("127.0.0.1:{rport}")).await
        {
            eprintln!("Failed to connect with error {error}")
        } else {
            println!("Client connected to NodeServer");
        }
    }

    // start a user-facing web server
    web::start(3000 + port - 9000, node_actor.clone()).await;

    // wait for exit
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for event");

    // cleanup
    node_actor.stop(None);
    node_handle.await.unwrap();
    actor.stop(None);
    handle.await.unwrap();
}

fn generate(n: usize, t: usize) -> anyhow::Result<()> {
    let sk_set = SecretKeySet::random(t - 1, &mut rand::thread_rng());
    let pk_set = sk_set.public_keys();
    println!("Public key set: {}", serde_json::to_string(&pk_set)?);

    for i in 1..=n {
        let sk_share = SerdeSecret(sk_set.secret_key_share(i));
        println!(
            "Secret key share {}: {}",
            i,
            serde_json::to_string(&sk_share)?
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse() {
        Cli::Generate { n, t } => generate(n, t)?,
        Cli::Start {
            node_id,
            pk_set,
            sk_share,
            port,
            remote_port,
        } => {
            let pk_set: PublicKeySet = serde_json::from_str(&pk_set).unwrap();
            let sk_share: SecretKeyShare = serde_json::from_str(&sk_share).unwrap();

            start(node_id, pk_set, sk_share, port, remote_port).await;
        }
    }

    Ok(())
}
