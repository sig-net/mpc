use actix_rt::task::JoinHandle;
use actor::NodeActor;
use ractor::{Actor, ActorRef};
use ractor_cluster::{node::NodeConnectionMode, NodeServer};
use threshold_crypto::{PublicKeySet, SecretKeySet, SecretKeyShare};

mod actor;
mod web;

const COOKIE: &str = "mpc-recovery-cookie";
// TODO: not sure if hostname matters in ractor, but localhost seems to be working fine even in Docker networks
const HOSTNAME: &str = "localhost";

type NodeId = u64;

async fn start_node_server(
    node_id: u64,
    node_port: u16,
) -> anyhow::Result<(ActorRef<NodeServer>, JoinHandle<()>)> {
    let node_name = format!("mpc-recovery-node-{}", node_id);
    tracing::debug!(
        node_port,
        cookie = COOKIE,
        node_name,
        hostname = HOSTNAME,
        "starting node server"
    );

    let server = ractor_cluster::NodeServer::new(
        node_port,
        COOKIE.to_string(),
        node_name,
        HOSTNAME.to_string(),
        None,
        Some(NodeConnectionMode::Transitive),
    );
    Ok(Actor::spawn(None, server, ())
        .await
        .map_err(|_e| anyhow::anyhow!("failed to start node server"))?)
}

async fn start_actor(
    node_id: u64,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
) -> anyhow::Result<(ActorRef<NodeActor>, JoinHandle<()>)> {
    // Printing shortened hash should be enough for most use cases, but if you enable TRACE level
    // you can see the entire curve details.
    if tracing::level_enabled!(tracing::Level::TRACE) {
        tracing::trace!(?pk_set, "starting node actor");
    } else {
        tracing::debug!(public_key = ?pk_set.public_key(), "starting node actor");
    }
    Ok(
        Actor::spawn(None, actor::NodeActor, (node_id, pk_set.clone(), sk_share))
            .await
            .map_err(|_e| anyhow::anyhow!("failed to start actor"))?,
    )
}

#[tracing::instrument(level = "debug", skip_all, fields(id = node_id))]
pub async fn start(
    node_id: u64,
    pk_set: PublicKeySet,
    sk_share: SecretKeyShare,
    node_port: u16,
    web_port: u16,
    remote_addr: Option<String>,
) -> anyhow::Result<()> {
    let (node_server, node_server_handle) = start_node_server(node_id, node_port).await?;
    let (node_actor, node_actor_handle) = start_actor(node_id, pk_set, sk_share).await?;

    if let Some(raddress) = remote_addr {
        if let Err(error) = ractor_cluster::node::client::connect(&node_server, &raddress).await {
            anyhow::bail!("failed to connect with error {error}");
        } else {
            tracing::info!(raddress, "connected to remote node server");
        }
    } else {
        tracing::info!("no remote node server address provided, treating this node as the leader");
    }

    // start a user-facing web server
    web::serve(node_id, web_port, node_actor.clone()).await;

    // wait for exit
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for event");

    // cleanup
    node_actor.stop(None);
    node_actor_handle.await.unwrap();
    node_server.stop(None);
    node_server_handle.await.unwrap();

    Ok(())
}

#[tracing::instrument(level = "debug", skip_all, fields(n = n, threshold = t))]
pub fn generate(n: usize, t: usize) -> anyhow::Result<(PublicKeySet, Vec<SecretKeyShare>)> {
    let sk_set = SecretKeySet::random(t - 1, &mut rand::thread_rng());
    let pk_set = sk_set.public_keys();
    tracing::debug!(public_key = ?pk_set.public_key());

    let mut sk_shares = Vec::new();
    for i in 1..=n {
        let sk_share = sk_set.secret_key_share(i);
        sk_shares.push(sk_share);
    }

    Ok((pk_set, sk_shares))
}
