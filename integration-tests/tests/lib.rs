use bollard::Docker;
use futures::future::BoxFuture;
use mpc_recovery::msg::{
    AddKeyRequest, AddKeyResponse, LeaderRequest, LeaderResponse, NewAccountRequest,
    NewAccountResponse,
};
use rand::{distributions::Alphanumeric, Rng};
use std::time::Duration;
use threshold_crypto::PublicKeySet;

use crate::docker::{LeaderNode, SignNode};

mod docker;

const NETWORK: &str = "mpc_recovery_integration_test_network";

struct TestContext<'a> {
    leader_node: &'a LeaderNode,
    pk_set: &'a PublicKeySet,
}

async fn with_nodes<F>(shares: usize, threshold: usize, nodes: usize, f: F) -> anyhow::Result<()>
where
    F: for<'a> FnOnce(TestContext<'a>) -> BoxFuture<'a, anyhow::Result<()>>,
{
    let docker = Docker::connect_with_local_defaults()?;

    let (pk_set, sk_shares, root_secret_key) = mpc_recovery::generate(shares, threshold)?;

    let mut sign_nodes = Vec::new();
    for i in 1..nodes {
        let addr = SignNode::start(&docker, NETWORK, i as u64, &pk_set, &sk_shares[i]).await?;
        sign_nodes.push(addr);
    }
    let leader_node = LeaderNode::start(
        &docker,
        NETWORK,
        1,
        &pk_set,
        &sk_shares[0],
        sign_nodes.iter().map(|n| n.address.clone()).collect(),
        &root_secret_key,
    )
    .await?;

    // Wait until all nodes initialize
    tokio::time::sleep(Duration::from_millis(1000)).await;

    f(TestContext {
        leader_node: &leader_node,
        pk_set: &pk_set,
    })
    .await?;

    drop(leader_node);
    drop(sign_nodes);

    // Wait until all docker containers are destroyed.
    // See `Drop` impl for `LeaderNode` and `SignNode` for more info.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    Ok(())
}

#[tokio::test]
async fn test_trio() -> anyhow::Result<()> {
    with_nodes(4, 3, 3, |ctx| {
        Box::pin(async move {
            let payload: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect();
            let (status_code, response) = ctx
                .leader_node
                .submit(LeaderRequest {
                    payload: payload.clone(),
                })
                .await?;

            assert_eq!(status_code, 200);
            if let LeaderResponse::Ok { signature } = response {
                assert!(ctx.pk_set.public_key().verify(&signature, payload));
            } else {
                panic!("response was not successful");
            }

            Ok(())
        })
    })
    .await
}

#[tokio::test]
async fn test_basic_action() -> anyhow::Result<()> {
    with_nodes(4, 3, 3, |ctx| {
        Box::pin(async move {
            // Create new account
            // TODO: write a test with real token
            // "validToken" should triger test token verifyer and return success
            let id_token = "validToken".to_string();
            let account_id = "myaccount.near".to_string();

            let (status_code, new_acc_response) = ctx
                .leader_node
                .new_account(NewAccountRequest {
                    account_id: account_id.clone(),
                    id_token: id_token.clone(),
                })
                .await?;
            assert_eq!(status_code, 200);
            assert!(matches!(new_acc_response, NewAccountResponse::Ok));

            // Add key to the created account
            let public_key =
                "eb936bd8c4f66e66948f8740a91e73f2e93d49370f6493f71b948d7b762a6a88".to_string();

            let (status_code, add_key_response) = ctx
                .leader_node
                .add_key(AddKeyRequest {
                    account_id,
                    id_token,
                    public_key,
                })
                .await?;
            assert_eq!(status_code, 200);
            assert!(matches!(add_key_response, AddKeyResponse::Ok));

            Ok(())
        })
    })
    .await
}
