use anyhow::{anyhow, bail, Context, Result};
use futures::future::{BoxFuture, FutureExt, Shared};
use near_workspaces::network::Sandbox;
use near_workspaces::Worker;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::cluster::DEFAULT_DOCKER_NETWORK;
use crate::containers::{self, DockerClient};

struct PendingResource<T> {
    wait: Shared<BoxFuture<'static, ()>>,
    result: Arc<Mutex<Option<Result<T>>>>,
}

enum ResourceState<T> {
    Standby,
    Ready(T),
    Pending(PendingResource<T>),
}

impl<T> Default for ResourceState<T> {
    fn default() -> Self {
        ResourceState::Standby
    }
}

impl<T> ResourceState<T> {
    pub fn is_standby(&self) -> bool {
        matches!(self, ResourceState::Standby)
    }
}

pub struct ClusterEnv {
    docker: DockerClient,
    network: String,
    redis: ResourceState<containers::Redis>,
    near_sandbox: ResourceState<Worker<Sandbox>>,
    ethereum_sandbox: ResourceState<containers::EthereumSandbox>,
    ethereum_enabled: bool,
}

impl ClusterEnv {
    pub fn new() -> Self {
        Self {
            docker: DockerClient::default(),
            network: DEFAULT_DOCKER_NETWORK.to_string(),
            redis: ResourceState::Standby,
            near_sandbox: ResourceState::Standby,
            ethereum_sandbox: ResourceState::Standby,
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
        if !self.redis.is_standby() {
            return;
        }

        let docker = self.docker.clone();
        let network = self.network.clone();
        let handle = tokio::spawn(async move {
            docker
                .create_network(&network)
                .await
                .context("failed to ensure docker network for redis")?;
            Ok(containers::Redis::run(&docker, &network).await)
        });
        self.redis = ResourceState::Pending(shared_from_handle("redis container", handle));
    }

    pub fn spawn_near_sandbox(&mut self) {
        if !self.near_sandbox.is_standby() {
            return;
        }

        let handle = tokio::spawn(async {
            near_workspaces::sandbox()
                .await
                .context("failed to spawn near sandbox")
        });
        self.near_sandbox = ResourceState::Pending(shared_from_handle("near sandbox", handle));
    }

    pub fn spawn_ethereum_sandbox(&mut self) {
        if !self.ethereum_enabled || !self.ethereum_sandbox.is_standby() {
            return;
        }

        let docker = self.docker.clone();
        let network = self.network.clone();
        let handle = tokio::spawn(async move {
            docker
                .create_network(&network)
                .await
                .context("failed to ensure docker network for ethereum sandbox")?;
            containers::EthereumSandbox::run(&docker, &network)
                .await
                .context("failed to spawn ethereum sandbox")
        });
        self.ethereum_sandbox =
            ResourceState::Pending(shared_from_handle("ethereum sandbox", handle));
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

    pub async fn take_redis(&mut self) -> Result<containers::Redis> {
        self.spawn_redis();
        Self::await_resource_owned(&mut self.redis, "redis container").await
    }

    pub async fn take_near_sandbox(&mut self) -> Result<Worker<Sandbox>> {
        self.spawn_near_sandbox();
        Self::await_resource_owned(&mut self.near_sandbox, "near sandbox").await
    }

    pub async fn take_ethereum_sandbox(&mut self) -> Result<Option<containers::EthereumSandbox>> {
        if !self.ethereum_enabled {
            return Ok(None);
        }

        self.spawn_ethereum_sandbox();
        Self::await_resource_owned(&mut self.ethereum_sandbox, "ethereum sandbox")
            .await
            .map(Some)
    }

    async fn await_resource<'a, T>(slot: &'a mut ResourceState<T>, name: &str) -> Result<&'a T>
    where
        T: Send + 'static,
    {
        loop {
            if let ResourceState::Ready(resource) = slot {
                return Ok(resource);
            }

            if matches!(slot, ResourceState::Standby) {
                bail!("{name} has not been spawned");
            }

            let (wait, result) = match slot {
                ResourceState::Pending(pending) => {
                    (pending.wait.clone(), Arc::clone(&pending.result))
                }
                _ => continue,
            };

            wait.await;

            let outcome = {
                let mut guard = result.lock().await;
                guard.take()
            };

            match outcome {
                Some(Ok(resource)) => {
                    *slot = ResourceState::Ready(resource);
                }
                Some(Err(err)) => {
                    *slot = ResourceState::Standby;
                    return Err(err);
                }
                None => continue,
            }
        }
    }

    async fn await_resource_owned<T>(slot: &mut ResourceState<T>, name: &str) -> Result<T>
    where
        T: Send + 'static,
    {
        match std::mem::replace(slot, ResourceState::Standby) {
            ResourceState::Ready(resource) => Ok(resource),
            ResourceState::Pending(pending) => {
                let wait = pending.wait.clone();
                let result = Arc::clone(&pending.result);

                wait.await;

                let mut guard = result.lock().await;
                match guard.take() {
                    Some(Ok(resource)) => Ok(resource),
                    Some(Err(err)) => Err(err),
                    None => bail!("{name} has already been taken"),
                }
            }
            ResourceState::Standby => bail!("{name} has not been spawned"),
        }
    }
}

fn shared_from_handle<T>(name: &'static str, handle: JoinHandle<Result<T>>) -> PendingResource<T>
where
    T: Send + 'static,
{
    let result = Arc::new(Mutex::new(None));
    let shared_result = Arc::clone(&result);
    let name = name.to_string();
    let wait = async move {
        let outcome = match handle.await {
            Ok(resource) => resource,
            Err(join_error) => Err(anyhow!("task for {name} panicked: {join_error}")),
        };

        *shared_result.lock().await = Some(outcome);
    }
    .boxed()
    .shared();

    PendingResource { wait, result }
}

impl Default for ClusterEnv {
    fn default() -> Self {
        Self::new()
    }
}
