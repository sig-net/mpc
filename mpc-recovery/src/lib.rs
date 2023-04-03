use ractor::Actor;
use ractor_cluster::node::NodeConnectionMode;
use threshold_crypto::{PublicKeySet, SecretKeySet, SecretKeyShare};

const COOKIE: &str = "mpc-recovery-cookie";

mod actor;
mod web;

pub async fn start(
    node_id: u64,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
    actor_port: u16,
    web_port: u16,
    remote_addr: Option<String>,
) {
    let server = ractor_cluster::NodeServer::new(
        actor_port,
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

    if let Some(raddress) = remote_addr {
        if let Err(error) = ractor_cluster::node::client::connect(&actor, raddress).await {
            eprintln!("Failed to connect with error {error}")
        } else {
            println!("Client connected to NodeServer");
        }
    }

    // start a user-facing web server
    web::start(web_port, node_actor.clone()).await;

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

pub fn generate(n: usize, t: usize) -> anyhow::Result<(PublicKeySet, Vec<SecretKeyShare>)> {
    let sk_set = SecretKeySet::random(t - 1, &mut rand::thread_rng());
    let pk_set = sk_set.public_keys();

    let mut sk_shares = Vec::new();
    for i in 1..=n {
        let sk_share = sk_set.secret_key_share(i);
        sk_shares.push(sk_share);
    }

    Ok((pk_set, sk_shares))
}
