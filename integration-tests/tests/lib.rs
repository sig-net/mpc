use bollard::container::{AttachContainerOptions, AttachContainerResults, Config};
use bollard::network::CreateNetworkOptions;
use bollard::service::{HostConfig, Ipam};
use bollard::Docker;
use futures::StreamExt;
use hyper::{body::HttpBody, Body, Client, Method, Request};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::json;
use std::collections::HashMap;
use std::convert::TryInto;
use std::time::Duration;
use threshold_crypto::{serde_impl::SerdeSecret, PublicKeySet, SecretKeyShare, Signature};
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
    node_id: u64,
    pk_set: &PublicKeySet,
    sk_share: &SecretKeyShare,
    actor_address: Option<String>,
) -> anyhow::Result<(String, String, String)> {
    let actor_port = portpicker::pick_unused_port().expect("no free ports");
    let web_port = portpicker::pick_unused_port().expect("no free ports");

    let empty = HashMap::<(), ()>::new();
    let mut exposed_ports = HashMap::new();
    exposed_ports.insert(format!("{web_port}/tcp"), empty);

    let mut cmd = vec![
        "start".to_string(),
        node_id.to_string(),
        serde_json::to_string(&pk_set)?,
        serde_json::to_string(&SerdeSecret(sk_share))?,
        actor_port.to_string(),
        web_port.to_string(),
    ];
    if let Some(actor_address) = actor_address {
        cmd.push(actor_address);
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
            ..Default::default()
        }),
        ..Default::default()
    };

    let id = docker
        .create_container::<&str, String>(None, mpc_recovery_config)
        .await?
        .id;
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

    continuously_print_docker_output(docker, &id).await?;

    Ok((
        id,
        format!("{ip_address}:{actor_port}"),
        format!("{ip_address}:{web_port}"),
    ))
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
    let (pk_set, sk_shares) = mpc_recovery::generate(4, 3)?;

    let mut actor_addresses = Vec::new();
    let mut web_ports = Vec::new();
    for (i, sk_share) in sk_shares.into_iter().enumerate().take(3) {
        let (_id, actor_address, web_port) = start_mpc_node(
            &docker,
            (i + 1) as u64,
            &pk_set,
            &sk_share,
            actor_addresses.first().cloned(),
        )
        .await?;
        actor_addresses.push(actor_address);
        web_ports.push(web_port);
    }

    tokio::time::sleep(Duration::from_millis(10000)).await;

    // TODO: only leader node works for now, other nodes struggling to connect to each other
    // for some reason.
    let web_port = &web_ports[0];
    let payload: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{}/submit", web_port))
        .header("content-type", "application/json")
        .body(Body::from(json!({ "payload": payload }).to_string()))?;

    let client = Client::new();
    let mut resp = client.request(req).await?;

    assert_eq!(resp.status(), 200);

    let data = resp.body_mut().data().await.expect("no response body")?;
    let response_body: String = serde_json::from_slice(&data)?;
    let signature_bytes = hex::decode(response_body)?;
    let signature_array: [u8; 96] = signature_bytes.as_slice().try_into().map_err(|_e| {
        anyhow::anyhow!(
            "signature has incorrect length: expected 96 bytes, but got {}",
            signature_bytes.len()
        )
    })?;
    let signature = Signature::from_bytes(signature_array)
        .map_err(|e| anyhow::anyhow!("malformed signature: {}", e))?;

    assert!(pk_set.public_key().verify(&signature, payload));

    Ok(())
}
