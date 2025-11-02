use anyhow::{anyhow, bail, Context, Result};
use futures::future::{ready, BoxFuture, FutureExt, Shared};
use near_workspaces::network::Sandbox;
use near_workspaces::Worker;
use std::sync::Arc;
use tokio::task::JoinHandle;

use crate::cluster::DEFAULT_DOCKER_NETWORK;
use crate::containers::{self, DockerClient};

type SharedResourceFuture<T> = Shared<BoxFuture<'static, Result<Arc<T>, Arc<anyhow::Error>>>>;

enum ResourceState<T> {
    Standby,
    Ready(Arc<T>),
    Pending(SharedResourceFuture<T>),
}

impl<T> Default for ResourceState<T> {
    fn default() -> Self {
        Self::Standby
    }
}

impl<T> ResourceState<T> {
    fn is_standby(&self) -> bool {
        matches!(self, ResourceState::Standby)
    }

    fn ensure_with(
        &mut self,
        init: impl FnOnce() -> SharedResourceFuture<T>,
    ) -> SharedResourceFuture<T>
    where
        T: Send + Sync + 'static,
    {
        match self {
            ResourceState::Standby => {
                let future = init();
                let handle = future.clone();
                *self = ResourceState::Pending(future);
                handle
            }
            ResourceState::Pending(shared) => shared.clone(),
            ResourceState::Ready(resource) => {
                ready(Ok::<_, Arc<anyhow::Error>>(Arc::clone(resource)))
                    .boxed()
                    .shared()
            }
        }
    }

    async fn wait_ref(&mut self, name: &str) -> Result<&T>
    where
        T: Send + Sync + 'static,
    {
        loop {
            if let ResourceState::Ready(resource) = self {
                return Ok(Arc::as_ref(resource));
            }

            let shared = match self {
                ResourceState::Pending(shared) => shared.clone(),
                ResourceState::Standby => bail!("{name} has not been spawned"),
                ResourceState::Ready(_) => continue,
            };

            match shared.await {
                Ok(resource) => {
                    *self = ResourceState::Ready(resource);
                }
                Err(err) => {
                    *self = ResourceState::Standby;
                    return Err(arc_error_into_anyhow(err));
                }
            }
        }
    }

    async fn take_owned(&mut self, name: &str) -> Result<T>
    where
        T: Send + Sync + 'static,
    {
        match std::mem::replace(self, ResourceState::Standby) {
            ResourceState::Ready(resource) => match Arc::try_unwrap(resource) {
                Ok(value) => Ok(value),
                Err(resource) => {
                    *self = ResourceState::Ready(resource);
                    bail!("{name} is still in use");
                }
            },
            ResourceState::Pending(shared) => match shared.await {
                Ok(resource) => match Arc::try_unwrap(resource) {
                    Ok(value) => Ok(value),
                    Err(resource) => {
                        *self = ResourceState::Ready(resource);
                        bail!("{name} is still in use");
                    }
                },
                Err(err) => {
                    *self = ResourceState::Standby;
                    Err(arc_error_into_anyhow(err))
                }
            },
            ResourceState::Standby => bail!("{name} has not been spawned"),
        }
    }
}

pub struct ClusterEnv {
    docker: DockerClient,
    network: String,
    network_ready: ResourceState<()>,
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
            network_ready: ResourceState::Standby,
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
        self.network_ready = ResourceState::Standby;
        self
    }

    pub fn set_network(&mut self, network: impl Into<String>) {
        self.network = network.into();
        self.network_ready = ResourceState::Standby;
    }

    pub fn with_docker_client(mut self, docker: DockerClient) -> Self {
        self.docker = docker;
        self.network_ready = ResourceState::Standby;
        self
    }

    pub fn set_docker_client(&mut self, docker: DockerClient) {
        self.docker = docker;
        self.network_ready = ResourceState::Standby;
    }

    pub fn enable_ethereum(&mut self) {
        self.ethereum_enabled = true;
    }

    pub fn with_ethereum(mut self) -> Self {
        self.enable_ethereum();
        self
    }

    fn spawn_network_creation(&mut self) -> SharedResourceFuture<()> {
        let docker = self.docker.clone();
        let network = self.network.clone();

        self.network_ready.ensure_with(move || {
            let handle = tokio::spawn(async move {
                docker
                    .create_network(&network)
                    .await
                    .context("failed to ensure docker network")?;
                Ok(())
            });

            shared_from_handle("docker network", handle)
        })
    }

    pub fn spawn_redis(&mut self) {
        if !self.redis.is_standby() {
            return;
        }

        let network_ready = self.spawn_network_creation();
        let docker = self.docker.clone();
        let network = self.network.clone();

        let _ = self.redis.ensure_with(move || {
            let handle = tokio::spawn(async move {
                network_ready.await.map_err(arc_error_into_anyhow)?;
                Ok(containers::Redis::run(&docker, &network).await)
            });

            shared_from_handle("redis container", handle)
        });
    }

    pub fn spawn_near_sandbox(&mut self) {
        if !self.near_sandbox.is_standby() {
            return;
        }

        let _ = self.near_sandbox.ensure_with(|| {
            let handle = tokio::spawn(async {
                near_workspaces::sandbox()
                    .await
                    .context("failed to spawn near sandbox")
            });

            shared_from_handle("near sandbox", handle)
        });
    }

    pub fn spawn_ethereum_sandbox(&mut self) {
        if !self.ethereum_enabled || !self.ethereum_sandbox.is_standby() {
            return;
        }

        let network_ready = self.spawn_network_creation();
        let docker = self.docker.clone();
        let network = self.network.clone();

        let _ = self.ethereum_sandbox.ensure_with(move || {
            let handle = tokio::spawn(async move {
                network_ready.await.map_err(arc_error_into_anyhow)?;
                containers::EthereumSandbox::run(&docker, &network)
                    .await
                    .context("failed to spawn ethereum sandbox")
            });

            shared_from_handle("ethereum sandbox", handle)
        });
    }

    pub async fn redis(&mut self) -> Result<&containers::Redis> {
        self.spawn_redis();
        self.redis.wait_ref("redis container").await
    }

    pub async fn near_sandbox(&mut self) -> Result<&Worker<Sandbox>> {
        self.spawn_near_sandbox();
        self.near_sandbox.wait_ref("near sandbox").await
    }

    pub async fn ethereum_sandbox(&mut self) -> Result<Option<&containers::EthereumSandbox>> {
        if !self.ethereum_enabled {
            return Ok(None);
        }

        self.spawn_ethereum_sandbox();
        self.ethereum_sandbox
            .wait_ref("ethereum sandbox")
            .await
            .map(Some)
    }

    pub async fn take_redis(&mut self) -> Result<containers::Redis> {
        self.spawn_redis();
        self.redis.take_owned("redis container").await
    }

    pub async fn take_near_sandbox(&mut self) -> Result<Worker<Sandbox>> {
        self.spawn_near_sandbox();
        self.near_sandbox.take_owned("near sandbox").await
    }

    pub async fn take_ethereum_sandbox(&mut self) -> Result<Option<containers::EthereumSandbox>> {
        if !self.ethereum_enabled {
            return Ok(None);
        }

        self.spawn_ethereum_sandbox();
        self.ethereum_sandbox
            .take_owned("ethereum sandbox")
            .await
            .map(Some)
    }
}

fn shared_from_handle<T>(
    name: &'static str,
    handle: JoinHandle<Result<T>>,
) -> SharedResourceFuture<T>
where
    T: Send + Sync + 'static,
{
    let name = name.to_string();
    async move {
        match handle.await {
            Ok(result) => result
                .map(|resource| Arc::new(resource))
                .map_err(|err| Arc::new(err)),
            Err(join_error) => Err(Arc::new(anyhow!("task for {name} panicked: {join_error}"))),
        }
    }
    .boxed()
    .shared()
}

fn arc_error_into_anyhow(error: Arc<anyhow::Error>) -> anyhow::Error {
    match Arc::try_unwrap(error) {
        Ok(err) => err,
        Err(err) => anyhow!(err.to_string()),
    }
}

impl Default for ClusterEnv {
    fn default() -> Self {
        Self::new()
    }
}
