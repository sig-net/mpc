use bollard::container::{AttachContainerOptions, AttachContainerResults, Config};
use bollard::network::CreateNetworkOptions;
use bollard::service::{HostConfig, Ipam, PortBinding};
use bollard::Docker;
use ed25519_dalek::SecretKey;
use futures::StreamExt;
use hyper::{Body, Client, Method, Request};
use mpc_recovery::msg::LeaderResponse;
use rand::{distributions::Alphanumeric, Rng};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use threshold_crypto::{serde_impl::SerdeSecret, PublicKeySet, SecretKeyShare};
use tokio::io::AsyncWriteExt;
use tokio::spawn;

async fn continuously_print_docker_output(docker: &Docker, id: &str) -> anyhow::Result<()> {
    let AttachContainerResults { mut output, .. } = docker
        .attach_container(
            id,
            Some(AttachContainerOptions::<String> {
                stdout: Some(true),
                stderr: Some(true),
                stream: Some(true),
                ..Default::default()
            }),
        )
        .await?;

    // Asynchronous process that pipes docker attach output into stdout.
    // Will die automatically once Docker container output is closed.
    spawn(async move {
        let mut stdout = tokio::io::stdout();

        while let Some(Ok(output)) = output.next().await {
            stdout
                .write_all(output.into_bytes().as_ref())
                .await
                .unwrap();
            stdout.flush().await.unwrap();
        }
    });

    Ok(())
}

async fn start_mpc_node(
    docker: &Docker,
    cmd: Vec<String>,
    web_port: u16,
    expose_web_port: bool,
) -> anyhow::Result<(String, String)> {
    let mut exposed_ports = HashMap::new();
    let mut port_bindings = HashMap::new();
    if expose_web_port {
        let empty = HashMap::<(), ()>::new();
        exposed_ports.insert(format!("{web_port}/tcp"), empty);
        port_bindings.insert(
            format!("{web_port}/tcp"),
            Some(vec![PortBinding {
                host_ip: None,
                host_port: Some(web_port.to_string()),
            }]),
        );
    }

    let mpc_recovery_config = Config {
        image: Some("near/mpc-recovery:latest".to_string()),
        tty: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        exposed_ports: Some(exposed_ports),
        cmd: Some(cmd),
        host_config: Some(HostConfig {
            network_mode: Some("mpc_recovery_integration_test_network".to_string()),
            port_bindings: Some(port_bindings),
            ..Default::default()
        }),
        env: Some(vec!["RUST_LOG=mpc_recovery=DEBUG".to_string()]),
        ..Default::default()
    };

    let id = docker
        .create_container::<&str, String>(None, mpc_recovery_config)
        .await?
        .id;

    continuously_print_docker_output(docker, &id).await?;
    docker.start_container::<String>(&id, None).await?;

    let network_settings = docker
        .inspect_container(&id, None)
        .await?
        .network_settings
        .unwrap();
    let ip_address = network_settings
        .networks
        .unwrap()
        .get("mpc_recovery_integration_test_network")
        .cloned()
        .unwrap()
        .ip_address
        .unwrap();

    Ok((id, ip_address))
}

async fn start_mpc_leader_node(
    docker: &Docker,
    node_id: u64,
    pk_set: &PublicKeySet,
    sk_share: &SecretKeyShare,
    sign_nodes: Vec<String>,
    root_secret_key: &SecretKey,
) -> anyhow::Result<String> {
    let web_port = portpicker::pick_unused_port().expect("no free ports");

    let mut cmd = vec![
        "start-leader".to_string(),
        "--node-id".to_string(),
        node_id.to_string(),
        "--pk-set".to_string(),
        serde_json::to_string(&pk_set)?,
        "--sk-share".to_string(),
        serde_json::to_string(&SerdeSecret(sk_share))?,
        "--web-port".to_string(),
        web_port.to_string(),
        "--root-secret-key".to_string(),
        hex::encode(root_secret_key),
    ];
    for sign_node in sign_nodes {
        cmd.push("--sign-nodes".to_string());
        cmd.push(sign_node);
    }

    start_mpc_node(docker, cmd, web_port, true).await?;
    // exposed host address
    Ok(format!("http://localhost:{web_port}"))
}

async fn start_mpc_sign_node(
    docker: &Docker,
    node_id: u64,
    pk_set: &PublicKeySet,
    sk_share: &SecretKeyShare,
) -> anyhow::Result<String> {
    let web_port = portpicker::pick_unused_port().expect("no free ports");

    let cmd = vec![
        "start-sign".to_string(),
        "--node-id".to_string(),
        node_id.to_string(),
        "--pk-set".to_string(),
        serde_json::to_string(&pk_set)?,
        "--sk-share".to_string(),
        serde_json::to_string(&SerdeSecret(sk_share))?,
        "--web-port".to_string(),
        web_port.to_string(),
    ];

    let (_, ip_address) = start_mpc_node(docker, cmd, web_port, false).await?;
    // internal network address
    Ok(format!("http://{ip_address}:{web_port}"))
}

async fn create_network(docker: &Docker) -> anyhow::Result<()> {
    let list = docker.list_networks::<&str>(None).await?;
    if list
        .iter()
        .any(|n| n.name == Some("mpc_recovery_integration_test_network".to_string()))
    {
        return Ok(());
    }

    let create_network_options = CreateNetworkOptions {
        name: "mpc_recovery_integration_test_network",
        check_duplicate: true,
        driver: if cfg!(windows) {
            "transparent"
        } else {
            "bridge"
        },
        ipam: Ipam {
            config: None,
            ..Default::default()
        },
        ..Default::default()
    };
    let _response = &docker.create_network(create_network_options).await?;

    Ok(())
}

#[tokio::test]
async fn test_trio() -> anyhow::Result<()> {
    let docker = Docker::connect_with_local_defaults()?;
    create_network(&docker).await?;

    // This test creates 4 sk shares with a threshold of 2 (i.e. minimum 3 required to sign),
    // but only instantiates 3 nodes.
    let (pk_set, sk_shares, root_secret_key) = mpc_recovery::generate(4, 3)?;

    let mut sign_nodes = Vec::new();
    for i in 2..=3 {
        let addr = start_mpc_sign_node(&docker, i as u64, &pk_set, &sk_shares[i - 1]).await?;
        sign_nodes.push(addr);
    }
    let leader_node = start_mpc_leader_node(
        &docker,
        1,
        &pk_set,
        &sk_shares[0],
        sign_nodes,
        &root_secret_key,
    )
    .await?;

    // Wait until all nodes initialize
    tokio::time::sleep(Duration::from_millis(2000)).await;

    let payload: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("{}/submit", leader_node))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "payload": payload }).to_string()))?;

    let client = Client::new();
    let response = client.request(req).await?;

    assert_eq!(response.status(), 200);

    let data = hyper::body::to_bytes(response).await?;
    let response: LeaderResponse = serde_json::from_slice(&data)?;
    if let LeaderResponse::Ok { signature } = response {
        assert!(pk_set.public_key().verify(&signature, payload));
    } else {
        panic!("response was not successful");
    }

    Ok(())
}

#[tokio::test]
async fn test_basic_action() -> anyhow::Result<()> {
    let docker = Docker::connect_with_local_defaults()?;
    create_network(&docker).await?;

    // This test creates 4 sk shares with a threshold of 2 (i.e. minimum 3 required to sign),
    // but only instantiates 3 nodes.
    let (pk_set, sk_shares, root_secret_key) = mpc_recovery::generate(4, 3)?;

    let mut sign_nodes = Vec::new();
    for i in 2..=3 {
        let addr = start_mpc_sign_node(&docker, i as u64, &pk_set, &sk_shares[i - 1]).await?;
        sign_nodes.push(addr);
    }
    let leader_node = start_mpc_leader_node(
        &docker,
        1,
        &pk_set,
        &sk_shares[0],
        sign_nodes,
        &root_secret_key,
    )
    .await?;

    // Wait until all nodes initialize
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Create new account
    // TODO: write a test with real token
    // "validToken" should triger test token verifyer and return success
    let token = "validToken";
    let account_id = "myaccount.near";

    let new_acc_req = Request::builder()
        .method(Method::POST)
        .uri(format!("{}/new_account", leader_node))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"id_token": token, "account_id": account_id}).to_string(),
        ))?;

    let client = Client::new();
    let new_acc_response = client.request(new_acc_req).await?;

    assert_eq!(new_acc_response.status(), 200);

    // Add key to the created account
    let public_key = "eb936bd8c4f66e66948f8740a91e73f2e93d49370f6493f71b948d7b762a6a88";
    let add_key_req = Request::builder()
        .method(Method::POST)
        .uri(format!("{}/add_key", leader_node))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "account_id": account_id,
                "id_token": token,
                "public_key": public_key
            })
            .to_string(),
        ))?;

    let add_key_response = client.request(add_key_req).await?;

    assert_eq!(add_key_response.status(), 200);

    Ok(())
}
