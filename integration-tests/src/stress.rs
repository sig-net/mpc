use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use futures::stream::{FuturesUnordered, StreamExt};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use near_workspaces::network::Sandbox;
use near_workspaces::{AccountId, Worker};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, RwLock};
use url::Url;

use crate::cluster::spawner::{ClusterSpawner, PregeneratedKeys, Prestockpile};
use crate::cluster::Cluster;
use crate::local::{Node, NodeEnvConfig};
use crate::{setup, Context, Nodes};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyFaultProfile {
    pub latency_ms: u64,
    pub blocked: bool,
}

impl ProxyFaultProfile {
    pub fn with_latency(latency: Duration) -> Self {
        Self {
            latency_ms: latency.as_millis() as u64,
            blocked: false,
        }
    }

    fn latency(&self) -> Duration {
        Duration::from_millis(self.latency_ms)
    }
}

pub struct LocalFaultProxy {
    url: Url,
    profile: Arc<RwLock<ProxyFaultProfile>>,
    shutdown_tx: watch::Sender<bool>,
    accept_task: tokio::task::JoinHandle<()>,
}

impl LocalFaultProxy {
    pub async fn spawn(upstream_port: u16) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let listen_addr = listener.local_addr()?;
        let url = Url::parse(&format!("http://{}", listen_addr))?;
        let profile = Arc::new(RwLock::new(ProxyFaultProfile::default()));
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let profile_for_task = Arc::clone(&profile);

        let accept_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((downstream, _)) = result else {
                            break;
                        };
                        let profile = Arc::clone(&profile_for_task);
                        tokio::spawn(async move {
                            if let Err(err) = proxy_connection(downstream, upstream_port, profile).await {
                                tracing::debug!(?err, upstream_port, "fault proxy connection ended");
                            }
                        });
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            url,
            profile,
            shutdown_tx,
            accept_task,
        })
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub async fn set_profile(&self, profile: ProxyFaultProfile) {
        *self.profile.write().await = profile;
    }

    pub async fn clear(&self) {
        self.set_profile(ProxyFaultProfile::default()).await;
    }
}

impl Drop for LocalFaultProxy {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        self.accept_task.abort();
    }
}

async fn proxy_connection(
    downstream: TcpStream,
    upstream_port: u16,
    profile: Arc<RwLock<ProxyFaultProfile>>,
) -> anyhow::Result<()> {
    let upstream = TcpStream::connect(("127.0.0.1", upstream_port)).await?;
    let (downstream_read, downstream_write) = downstream.into_split();
    let (upstream_read, upstream_write) = upstream.into_split();

    let forward_downstream = relay(downstream_read, upstream_write, Arc::clone(&profile));
    let forward_upstream = relay(upstream_read, downstream_write, profile);
    tokio::try_join!(forward_downstream, forward_upstream)?;
    Ok(())
}

async fn relay(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    profile: Arc<RwLock<ProxyFaultProfile>>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            break;
        }

        let snapshot = profile.read().await.clone();
        if snapshot.blocked {
            anyhow::bail!("proxy blocked");
        }
        let latency = snapshot.latency();
        if !latency.is_zero() {
            tokio::time::sleep(latency).await;
        }

        writer.write_all(&buf[..read]).await?;
    }
    writer.shutdown().await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub enum StressAction {
    SetGlobalLatency(Duration),
    SetNodeLatency { node: usize, latency: Duration },
    BlockNode(usize),
    ClearNode(usize),
    ClearAllFaults,
    SubmitSignRequests { total: usize, concurrency: usize },
    Sleep(Duration),
    Snapshot(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StressRequestStatus {
    Success,
    Timeout,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressRequestOutcome {
    pub request_index: usize,
    pub latency_ms: u128,
    pub status: StressRequestStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSnapshot {
    pub node_id: String,
    pub metrics: mpc_node::web::BenchMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressSnapshot {
    pub label: String,
    pub system_load: u32,
    pub nodes: Vec<NodeSnapshot>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StressRunReport {
    pub requests: Vec<StressRequestOutcome>,
    pub snapshots: Vec<StressSnapshot>,
}

pub struct StressHarnessBuilder {
    spawner: ClusterSpawner,
    request_timeout: Duration,
}

impl Default for StressHarnessBuilder {
    fn default() -> Self {
        Self {
            spawner: crate::cluster::spawn(),
            request_timeout: Duration::from_secs(45),
        }
    }
}

impl StressHarnessBuilder {
    pub fn nodes(mut self, nodes: usize) -> Self {
        self.spawner = self.spawner.nodes(nodes);
        self
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.spawner = self.spawner.threshold(threshold);
        self
    }

    pub fn with_config(mut self, call: impl FnOnce(&mut crate::NodeConfig)) -> Self {
        self.spawner = self.spawner.with_config(call);
        self
    }

    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub async fn build(mut self) -> anyhow::Result<StressHarness> {
        #[cfg(feature = "docker-test")]
        anyhow::bail!("stress harness currently supports native-node integration tests only");

        #[cfg(not(feature = "docker-test"))]
        {
            align_pregenerated_keys(&mut self.spawner);
            self.spawner = self.spawner.init_network().await?;

            let ctx = setup(&mut self.spawner).await?;
            let mut node_cfgs = Vec::with_capacity(self.spawner.accounts.len());
            for (account, source) in self
                .spawner
                .accounts
                .iter()
                .zip(self.spawner.node_binary_sources.iter())
            {
                let mut cfg = Node::dry_run(&ctx, account, &self.spawner.cfg).await?;
                cfg.binary_path = source.binary_path()?;
                node_cfgs.push(cfg);
            }

            let proxies = futures::future::try_join_all(
                node_cfgs
                    .iter()
                    .map(|cfg| LocalFaultProxy::spawn(cfg.web_port)),
            )
            .await?;

            for (cfg, proxy) in node_cfgs.iter_mut().zip(proxies.iter()) {
                cfg.advertised_address = Some(proxy.url().clone());
            }

            let cluster = spawn_local_cluster(&mut self.spawner, ctx, node_cfgs).await?;

            if self.spawner.wait_for_running {
                cluster.wait().running().nodes_running().await?;

                if let Some(prestockpile) = self.spawner.prestockpile {
                    cluster.prestockpile(prestockpile).await;
                }
            }

            Ok(StressHarness {
                cluster,
                proxies,
                request_timeout: self.request_timeout,
            })
        }
    }
}

pub struct StressHarness {
    pub cluster: Cluster,
    proxies: Vec<LocalFaultProxy>,
    request_timeout: Duration,
}

impl StressHarness {
    pub async fn set_global_latency(&self, latency: Duration) {
        for proxy in &self.proxies {
            proxy.set_profile(ProxyFaultProfile::with_latency(latency)).await;
        }
    }

    pub async fn set_node_latency(&self, node: usize, latency: Duration) -> anyhow::Result<()> {
        let proxy = self
            .proxies
            .get(node)
            .with_context(|| format!("missing proxy for node {node}"))?;
        proxy
            .set_profile(ProxyFaultProfile::with_latency(latency))
            .await;
        Ok(())
    }

    pub async fn block_node(&self, node: usize) -> anyhow::Result<()> {
        let proxy = self
            .proxies
            .get(node)
            .with_context(|| format!("missing proxy for node {node}"))?;
        proxy
            .set_profile(ProxyFaultProfile {
                blocked: true,
                ..Default::default()
            })
            .await;
        Ok(())
    }

    pub async fn clear_node(&self, node: usize) -> anyhow::Result<()> {
        let proxy = self
            .proxies
            .get(node)
            .with_context(|| format!("missing proxy for node {node}"))?;
        proxy.clear().await;
        Ok(())
    }

    pub async fn clear_all_faults(&self) {
        for proxy in &self.proxies {
            proxy.clear().await;
        }
    }

    pub async fn submit_sign_requests(
        &self,
        total: usize,
        concurrency: usize,
    ) -> Vec<StressRequestOutcome> {
        let mut next_request = 0usize;
        let mut in_flight = FuturesUnordered::new();
        let mut outcomes = Vec::with_capacity(total);
        let concurrency = concurrency.max(1);

        loop {
            while next_request < total && in_flight.len() < concurrency {
                in_flight.push(run_sign_request(
                    &self.cluster,
                    self.request_timeout,
                    next_request,
                ));
                next_request += 1;
            }

            let Some(outcome) = in_flight.next().await else {
                break;
            };
            outcomes.push(outcome);
        }

        outcomes.sort_by_key(|outcome| outcome.request_index);
        outcomes
    }

    pub async fn snapshot(&self, label: impl Into<String>) -> anyhow::Result<StressSnapshot> {
        let label = label.into();
        let system_load = self.fetch_system_load().await?;
        let mut nodes = Vec::with_capacity(self.cluster.len());
        for id in 0..self.cluster.len() {
            nodes.push(NodeSnapshot {
                node_id: self.cluster.account_id(id).to_string(),
                metrics: self.cluster.fetch_bench_metrics(id).await?,
            });
        }

        Ok(StressSnapshot {
            label,
            system_load,
            nodes,
        })
    }

    pub async fn run_actions(&self, actions: &[StressAction]) -> anyhow::Result<StressRunReport> {
        let mut report = StressRunReport::default();

        for action in actions {
            match action {
                StressAction::SetGlobalLatency(latency) => self.set_global_latency(*latency).await,
                StressAction::SetNodeLatency { node, latency } => {
                    self.set_node_latency(*node, *latency).await?;
                }
                StressAction::BlockNode(node) => {
                    self.block_node(*node).await?;
                }
                StressAction::ClearNode(node) => {
                    self.clear_node(*node).await?;
                }
                StressAction::ClearAllFaults => self.clear_all_faults().await,
                StressAction::SubmitSignRequests { total, concurrency } => {
                    report
                        .requests
                        .extend(self.submit_sign_requests(*total, *concurrency).await);
                }
                StressAction::Sleep(duration) => tokio::time::sleep(*duration).await,
                StressAction::Snapshot(label) => {
                    report.snapshots.push(self.snapshot(label.clone()).await?);
                }
            }
        }

        Ok(report)
    }

    async fn fetch_system_load(&self) -> anyhow::Result<u32> {
        self.cluster
            .contract()
            .view("system_load")
            .await
            .context("could not view system_load")?
            .json()
            .context("could not decode system_load")
    }
}

fn align_pregenerated_keys(spawner: &mut ClusterSpawner) {
    if spawner.pregenerated_keys.is_enabled() && spawner.pregenerated_keys.len() != spawner.cfg.nodes
    {
        spawner.pregenerated_keys = PregeneratedKeys::load(spawner.cfg.nodes, spawner.cfg.threshold)
            .unwrap_or(PregeneratedKeys::Disabled);
    }
}

async fn spawn_local_cluster(
    spawner: &mut ClusterSpawner,
    ctx: Context,
    node_cfgs: Vec<NodeEnvConfig>,
) -> anyhow::Result<Cluster> {
    let node_futures = node_cfgs.into_iter().map(|cfg| Node::spawn(&ctx, cfg));
    let nodes = futures::future::join_all(node_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let candidates: HashMap<AccountId, crate::CandidateInfo> = spawner
        .accounts
        .iter()
        .zip(&nodes)
        .map(|(account, node)| {
            (
                account.id().clone(),
                crate::CandidateInfo {
                    account_id: account.id().as_str().parse().unwrap(),
                    url: node.address.clone(),
                    cipher_pk: node.cipher_sk.public_key().to_bytes(),
                    sign_pk: node.sign_sk.public_key().to_string().parse().unwrap(),
                },
            )
        })
        .collect();

    init_contract(&ctx, &spawner.cfg, &spawner.pregenerated_keys, candidates).await?;

    let nodes = Nodes::Local {
        next_id: nodes.len(),
        ctx,
        nodes,
    };
    let connector = near_jsonrpc_client::JsonRpcClient::new_client();
    let jsonrpc_client = connector.connect(nodes.ctx().worker.rpc_addr());
    let rpc_client = near_fetch::Client::from_client(jsonrpc_client);

    Ok(Cluster {
        cfg: spawner.cfg.clone(),
        rpc_client,
        http_client: reqwest::Client::default(),
        docker_client: spawner.docker.clone(),
        account_idx: nodes.len(),
        solana: spawner.solana.take(),
        canton: spawner.canton.take(),
        nodes,
    })
}

async fn init_contract(
    ctx: &Context,
    cfg: &crate::NodeConfig,
    pregenerated_keys: &PregeneratedKeys,
    candidates: HashMap<AccountId, crate::CandidateInfo>,
) -> anyhow::Result<()> {
    if let Some(public_key) = pregenerated_keys.public_key() {
        let participants =
            mpc_contract::primitives::Participants::from(mpc_contract::primitives::Candidates {
                candidates: candidates.clone().into_iter().collect(),
            });
        let near_pk = near_crypto::PublicKey::SECP256K1(
            near_crypto::Secp256K1PublicKey::try_from(
                &public_key.to_encoded_point(false).as_bytes()[1..65],
            )
            .unwrap(),
        );
        ctx.mpc_contract
            .call("init_running")
            .args_json(serde_json::json!({
                "epoch": 0,
                "participants": participants,
                "threshold": cfg.threshold,
                "public_key": near_pk,
            }))
            .transact()
            .await?
            .into_result()?;
    } else {
        ctx.mpc_contract
            .call("init")
            .args_json(serde_json::json!({
                "threshold": cfg.threshold,
                "candidates": candidates,
            }))
            .transact()
            .await?
            .into_result()?;
    }

    Ok(())
}

async fn run_sign_request(
    cluster: &Cluster,
    timeout: Duration,
    request_index: usize,
) -> StressRequestOutcome {
    let started = Instant::now();
    let status = match tokio::time::timeout(timeout, cluster.sign()).await {
        Ok(Ok(_)) => StressRequestStatus::Success,
        Ok(Err(err)) => StressRequestStatus::Error(err.to_string()),
        Err(_) => StressRequestStatus::Timeout,
    };

    StressRequestOutcome {
        request_index,
        latency_ms: started.elapsed().as_millis(),
        status,
    }
}