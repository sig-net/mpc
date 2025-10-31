use anyhow::{bail, Context, Result};
use near_workspaces::network::Sandbox;
use near_workspaces::Worker;
use tokio::task::JoinHandle;

use crate::cluster::DEFAULT_DOCKER_NETWORK;
use crate::containers::{self, DockerClient};

enum ResourceState<T> {
    Pending(JoinHandle<Result<T>>),
    Ready(T),
}

pub struct ClusterEnv {
    docker: DockerClient,
    network: String,
    redis: Option<ResourceState<containers::Redis>>,
    near_sandbox: Option<ResourceState<Worker<Sandbox>>>,
    ethereum_sandbox: Option<ResourceState<containers::EthereumSandbox>>,
    ethereum_enabled: bool,
}

impl ClusterEnv {
    pub fn new() -> Self {
        Self {
            docker: DockerClient::default(),
            network: DEFAULT_DOCKER_NETWORK.to_string(),
            redis: None,
            near_sandbox: None,
            ethereum_sandbox: None,
            ethereum_enabled: false,
        }
    }

    pub fn docker(&self) -> &DockerClient {
        &self.docker
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn with_network(mut self, network: impl Into<String>) -> Self {
        self.network = network.into();
        self
    }

    pub fn set_network(&mut self, network: impl Into<String>) {
        self.network = network.into();
    }

    pub fn with_docker_client(mut self, docker: DockerClient) -> Self {
        self.docker = docker;
        self
    }

    pub fn set_docker_client(&mut self, docker: DockerClient) {
        self.docker = docker;
    }

    pub fn enable_ethereum(&mut self) {
        self.ethereum_enabled = true;
    }

    pub fn with_ethereum(mut self) -> Self {
        self.enable_ethereum();
        self
    }

    pub fn spawn_redis(&mut self) {
        if self.redis.is_some() {
            return;
        }

        let docker = self.docker.clone();
        let network = self.network.clone();
        self.redis = Some(ResourceState::Pending(tokio::spawn(async move {
            docker
                .create_network(&network)
                .await
                .context("failed to ensure docker network for redis")?;
            Ok(containers::Redis::run(&docker, &network).await)
        })));
    }

    pub fn spawn_near_sandbox(&mut self) {
        if self.near_sandbox.is_some() {
            return;
        }

        self.near_sandbox = Some(ResourceState::Pending(tokio::spawn(async {
            near_workspaces::sandbox()
                .await
                .context("failed to spawn near sandbox")
        })));
    }

    pub fn spawn_ethereum_sandbox(&mut self) {
        if !self.ethereum_enabled || self.ethereum_sandbox.is_some() {
            return;
        }

        let docker = self.docker.clone();
        let network = self.network.clone();
        self.ethereum_sandbox = Some(ResourceState::Pending(tokio::spawn(async move {
            docker
                .create_network(&network)
                .await
                .context("failed to ensure docker network for ethereum sandbox")?;
            containers::EthereumSandbox::run(&docker, &network)
                .await
                .context("failed to spawn ethereum sandbox")
        })));
    }

    pub async fn redis(&mut self) -> Result<&containers::Redis> {
        self.spawn_redis();
        Self::await_resource(&mut self.redis, "redis container").await
    }

    pub async fn near_sandbox(&mut self) -> Result<&Worker<Sandbox>> {
        self.spawn_near_sandbox();
        Self::await_resource(&mut self.near_sandbox, "near sandbox").await
    }

    pub async fn ethereum_sandbox(&mut self) -> Result<Option<&containers::EthereumSandbox>> {
        if !self.ethereum_enabled {
            return Ok(None);
        }

        self.spawn_ethereum_sandbox();
        Self::await_resource(&mut self.ethereum_sandbox, "ethereum sandbox")
            .await
            .map(Some)
    }

    async fn await_resource<'a, T>(
        slot: &'a mut Option<ResourceState<T>>,
        name: &str,
    ) -> Result<&'a T> {
        loop {
            match slot {
                Some(ResourceState::Ready(resource)) => return Ok(resource),
                Some(ResourceState::Pending(_)) => {
                    let handle = match slot.take() {
                        Some(ResourceState::Pending(handle)) => handle,
                        _ => continue,
                    };
                    let resource = handle
                        .await
                        .with_context(|| format!("task for {name} panicked"))??;
                    *slot = Some(ResourceState::Ready(resource));
                }
                None => bail!("{name} has not been spawned"),
            }
        }
    }
}

impl Default for ClusterEnv {
    fn default() -> Self {
        Self::new()
    }
}
