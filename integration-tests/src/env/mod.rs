pub mod containers;
pub mod local;

use curv::elliptic::curves::{Ed25519, Point};
use mpc_recovery::GenerateResult;
use near_primitives::utils::generate_random_string;

use crate::env::containers::{DockerClient, LeaderNodeApi, SignerNodeApi};
use crate::{initialize_relayer, util, RelayerCtx};

pub const NETWORK: &str = "mpc_it_network";
pub const GCP_PROJECT_ID: &str = "mpc-recovery-gcp-project";
// TODO: figure out how to instantiate and use a local firebase deployment
pub const FIREBASE_AUDIENCE_ID: &str = "test_audience";

pub enum Nodes<'a> {
    Local {
        ctx: Context<'a>,
        pk_set: Vec<Point<Ed25519>>,
        leader_node: local::LeaderNode,
        signer_nodes: Vec<local::SignerNode>,
    },
    Docker {
        ctx: Context<'a>,
        pk_set: Vec<Point<Ed25519>>,
        leader_node: containers::LeaderNode<'a>,
        signer_nodes: Vec<containers::SignerNode<'a>>,
    },
}

impl Nodes<'_> {
    pub fn ctx(&self) -> &Context {
        match self {
            Nodes::Local { ctx, .. } => ctx,
            Nodes::Docker { ctx, .. } => ctx,
        }
    }

    pub fn pk_set(&self) -> Vec<Point<Ed25519>> {
        match self {
            Nodes::Local { pk_set, .. } => pk_set.clone(),
            Nodes::Docker { pk_set, .. } => pk_set.clone(),
        }
    }

    pub fn leader_api(&self) -> LeaderNodeApi {
        match self {
            Nodes::Local { leader_node, .. } => leader_node.api(),
            Nodes::Docker { leader_node, .. } => leader_node.api(),
        }
    }

    pub fn signer_apis(&self) -> Vec<SignerNodeApi> {
        match self {
            Nodes::Local { signer_nodes, .. } => signer_nodes.iter().map(|n| n.api()).collect(),
            Nodes::Docker { signer_nodes, .. } => signer_nodes.iter().map(|n| n.api()).collect(),
        }
    }

    pub fn datastore_addr(&self) -> String {
        // this is different per env:
        match self {
            Nodes::Local { ctx, .. } => ctx.datastore.local_address.clone(),
            Nodes::Docker { ctx, .. } => ctx.datastore.address.clone(),
        }
    }
}

pub struct Context<'a> {
    pub relayer_ctx: RelayerCtx<'a>,
    pub datastore: containers::Datastore<'a>,
}

pub async fn setup<'a>(docker_client: &'a DockerClient) -> anyhow::Result<Context<'a>> {
    docker_client.create_network(NETWORK).await?;

    let relayer_id = generate_random_string(7); // used to distinguish relayer tmp files in multiple tests
    let relayer_ctx_future = initialize_relayer(&docker_client, NETWORK, &relayer_id);
    let datastore_future = containers::Datastore::run(&docker_client, NETWORK, GCP_PROJECT_ID);

    let (relayer_ctx, datastore) =
        futures::future::join(relayer_ctx_future, datastore_future).await;
    let relayer_ctx = relayer_ctx?;
    let datastore = datastore?;

    Ok(Context {
        relayer_ctx,
        datastore,
    })
}

pub async fn docker(nodes: usize, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    let ctx = setup(docker_client).await?;

    let GenerateResult { pk_set, secrets } = mpc_recovery::generate(nodes);
    let mut signer_node_futures = Vec::with_capacity(nodes);
    for (i, (share, cipher_key)) in secrets.iter().enumerate().take(nodes) {
        signer_node_futures.push(containers::SignerNode::run_signing_node(
            &docker_client,
            NETWORK,
            i as u64,
            share,
            cipher_key,
            &ctx.datastore.address,
            &ctx.datastore.local_address,
            GCP_PROJECT_ID,
            FIREBASE_AUDIENCE_ID,
        ));
    }
    let signer_nodes = futures::future::join_all(signer_node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let signer_urls: &Vec<_> = &signer_nodes.iter().map(|n| n.address.clone()).collect();

    let near_root_account = ctx.relayer_ctx.worker.root_account()?;
    let leader_node = containers::LeaderNode::run(
        &docker_client,
        NETWORK,
        signer_urls.clone(),
        &ctx.relayer_ctx.sandbox.address,
        &ctx.relayer_ctx.relayer.address,
        &ctx.datastore.address,
        GCP_PROJECT_ID,
        near_root_account.id(),
        ctx.relayer_ctx.creator_account.id(),
        ctx.relayer_ctx.creator_account.secret_key(),
        FIREBASE_AUDIENCE_ID,
    )
    .await?;

    Ok(Nodes::Docker {
        ctx,
        pk_set,
        leader_node,
        signer_nodes,
    })
}

pub async fn host(nodes: usize, docker_client: &DockerClient) -> anyhow::Result<Nodes> {
    let ctx = setup(docker_client).await?;
    let GenerateResult { pk_set, secrets } = mpc_recovery::generate(nodes);
    let mut signer_node_futures = Vec::with_capacity(nodes);
    for (i, (share, cipher_key)) in secrets.iter().enumerate().take(nodes) {
        signer_node_futures.push(local::SignerNode::run(
            util::pick_unused_port().await?,
            i as u64,
            share,
            cipher_key,
            &ctx.datastore.local_address,
            GCP_PROJECT_ID,
            FIREBASE_AUDIENCE_ID,
            true,
        ));
    }
    let signer_nodes = futures::future::join_all(signer_node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let near_root_account = ctx.relayer_ctx.worker.root_account()?;
    let leader_node = local::LeaderNode::run(
        util::pick_unused_port().await?,
        signer_nodes.iter().map(|n| n.address.clone()).collect(),
        &ctx.relayer_ctx.sandbox.local_address,
        &ctx.relayer_ctx.relayer.local_address,
        &ctx.datastore.local_address,
        GCP_PROJECT_ID,
        near_root_account.id(),
        ctx.relayer_ctx.creator_account.id(),
        ctx.relayer_ctx.creator_account.secret_key(),
        FIREBASE_AUDIENCE_ID,
        true,
    )
    .await?;

    Ok(Nodes::Local {
        ctx,
        pk_set,
        leader_node,
        signer_nodes,
    })
}
