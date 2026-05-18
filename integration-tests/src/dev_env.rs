use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::Context as _;
use mpc_contract::primitives::SignRequest;
use mpc_contract::ProtocolContractState;
use mpc_keys::hpke;
use mpc_node::config::OverrideConfig;
use mpc_node::indexer_canton::{CantonArgs, CantonConfig};
use mpc_node::indexer_eth::{EthArgs, EthConfig};
use mpc_node::indexer_hydration::{HydrationArgs, HydrationConfig};
use mpc_node::indexer_sol::{SolArgs, SolConfig};
use mpc_node::{logs, mesh, node_client, storage};
use mpc_primitives::Chain;
use near_account_id::AccountId;
use near_crypto::SecretKey as NearSecretKey;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, Contract};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::execute;
use crate::utils;
use crate::{NodeConfig, Nodes};

pub const DEFAULT_STATE_FILE: &str = "target/mpc-dev-env.json";
const DEFAULT_JOIN_BALANCE_NEAR: u128 = 10;
const SIGN_GAS: Gas = Gas::from_tgas(50);
const SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedEthConfig {
    pub account_sk: String,
    pub consensus_rpc_http_url: String,
    pub execution_rpc_http_url: String,
    pub contract_address: String,
    pub network: String,
    pub helios_data_path: String,
    pub refresh_finalized_interval: u64,
    pub optimistic_requests: bool,
    pub light_client: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedSolConfig {
    pub account_sk: String,
    pub rpc_http_url: String,
    pub rpc_ws_url: String,
    pub program_address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedHydrationConfig {
    pub rpc_ws_url: String,
    pub signer_uri: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedCantonConfig {
    pub json_api_url: String,
    pub json_api_ws_url: String,
    pub jwt_private_key_path: String,
    pub jwt_subject: String,
    pub party_id: String,
    pub signer_contract_id: String,
    pub signer_template_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedParticipant {
    pub account_id: String,
    pub secret_key: String,
    pub spawned_by_helper: bool,
    pub pid: Option<u32>,
    pub log_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedEnv {
    pub version: u32,
    pub rpc_url: String,
    pub contract_account_id: String,
    pub contract_secret_key: String,
    pub release: bool,
    pub nodes: usize,
    pub threshold: usize,
    pub protocol: mpc_contract::config::ProtocolConfig,
    pub redis_url: String,
    pub participants: Vec<SavedParticipant>,
    pub eth: Option<SavedEthConfig>,
    pub sol: Option<SavedSolConfig>,
    pub hydration: Option<SavedHydrationConfig>,
    pub canton: Option<SavedCantonConfig>,
}

#[derive(Clone, Debug)]
pub enum SignCommand {
    Default,
    TxHash(String),
    Multi(usize),
    Bidirectional,
}

#[derive(Clone, Debug)]
pub enum ReshareCommand {
    Join,
    Kick(Option<String>),
}

pub fn save_env(path: &Path, nodes: &Nodes, cfg: &NodeConfig) -> anyhow::Result<()> {
    let ctx = nodes.ctx();
    let participants = nodes
        .near_accounts()
        .into_iter()
        .map(|account| SavedParticipant {
            account_id: account.id().to_string(),
            secret_key: account.secret_key().to_string(),
            spawned_by_helper: false,
            pid: None,
            log_path: None,
        })
        .collect();

    let env = SavedEnv {
        version: 1,
        rpc_url: ctx.worker.rpc_addr(),
        contract_account_id: ctx.mpc_contract.id().to_string(),
        contract_secret_key: ctx.mpc_contract.as_account().secret_key().to_string(),
        release: ctx.release,
        nodes: cfg.nodes,
        threshold: cfg.threshold,
        protocol: cfg.protocol.clone(),
        redis_url: ctx.redis.internal_address.clone(),
        participants,
        eth: cfg.eth.clone().map(|eth| SavedEthConfig {
            account_sk: eth.account_sk,
            consensus_rpc_http_url: eth.consensus_rpc_http_url,
            execution_rpc_http_url: eth.execution_rpc_http_url,
            contract_address: eth.contract_address,
            network: eth.network,
            helios_data_path: eth.helios_data_path,
            refresh_finalized_interval: eth.refresh_finalized_interval,
            optimistic_requests: eth.optimistic_requests,
            light_client: eth.light_client,
        }),
        sol: cfg.sol.clone().map(|sol| SavedSolConfig {
            account_sk: sol.account_sk,
            rpc_http_url: sol.rpc_http_url,
            rpc_ws_url: sol.rpc_ws_url,
            program_address: sol.program_address,
        }),
        hydration: cfg.hydration.clone().map(|hydration| SavedHydrationConfig {
            rpc_ws_url: hydration.rpc_ws_url,
            signer_uri: hydration.signer_uri,
        }),
        canton: cfg.canton.clone().map(|canton| SavedCantonConfig {
            json_api_url: canton.json_api_url,
            json_api_ws_url: canton.json_api_ws_url,
            jwt_private_key_path: canton.jwt_private_key_path,
            jwt_subject: canton.jwt_subject,
            party_id: canton.party_id,
            signer_contract_id: canton.signer_contract_id,
            signer_template_id: canton.signer_template_id,
        }),
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(&env)?)?;
    Ok(())
}

pub fn remove_env(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub async fn invoke_sign(path: &Path, command: SignCommand) -> anyhow::Result<()> {
    let env = load_env(path)?;
    if env.participants.is_empty() {
        anyhow::bail!("no participant accounts found in {}", path.display());
    }

    let worker = near_workspaces::custom(&env.rpc_url).await?;
    let contract = saved_contract(&env, &worker)?;
    let caller = saved_account(&env.participants[0], &worker)?;

    match command {
        SignCommand::Default => {
            let request = SignRequest {
                payload: default_payload(0),
                path: "just/default".to_string(),
                key_version: 0,
            };
            send_sign_request(&caller, &contract, &request).await?;
            println!(
                "submitted sign request path={} payload=0x{}",
                request.path,
                hex::encode(request.payload)
            );
        }
        SignCommand::TxHash(tx_hash) => {
            let payload = parse_32_byte_hex(&tx_hash)?;
            let request = SignRequest {
                payload,
                path: "just/tx-hash".to_string(),
                key_version: 0,
            };
            send_sign_request(&caller, &contract, &request).await?;
            println!(
                "submitted sign request for tx hash 0x{}",
                hex::encode(request.payload)
            );
        }
        SignCommand::Multi(count) => {
            for idx in 0..count {
                let request = SignRequest {
                    payload: default_payload(idx as u64),
                    path: format!("just/multi/{idx}"),
                    key_version: 0,
                };
                send_sign_request(&caller, &contract, &request).await?;
                println!("submitted sign request {} path={}", idx + 1, request.path);
            }
        }
        SignCommand::Bidirectional => {
            let request = SignRequest {
                payload: default_payload(777),
                path: "just/bidirectional".to_string(),
                key_version: 0,
            };
            send_sign_request(&caller, &contract, &request).await?;
            println!(
                "submitted sign request path={} payload=0x{}",
                request.path,
                hex::encode(request.payload)
            );
            println!("note: this helper submits bidirectional-tagged request data to the NEAR contract; it does not emulate the full Solana bridge flow");
        }
    }

    Ok(())
}

pub async fn invoke_reshare(path: &Path, command: ReshareCommand) -> anyhow::Result<()> {
    let mut env = load_env(path)?;
    let worker = near_workspaces::custom(&env.rpc_url).await?;
    let contract = saved_contract(&env, &worker)?;

    match command {
        ReshareCommand::Join => {
            let participant = spawn_join_candidate(&env, &worker, &contract).await?;
            env.participants.push(participant.clone());
            persist_env(path, &env)?;

            let candidate = saved_account(&participant, &worker)?;
            wait_for_candidate(&contract, candidate.id()).await?;

            let voters = env
                .participants
                .iter()
                .take(env.threshold)
                .map(|entry| saved_account(entry, &worker))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let voter_refs = voters.iter().collect::<Vec<_>>();

            crate::utils::vote_join(&voter_refs, contract.id(), candidate.id()).await?;
            wait_for_running_epoch_change(&contract).await?;

            println!("submitted reshare join for {}", candidate.id());
        }
        ReshareCommand::Kick(target) => {
            let current_state = view_contract_state(&contract).await?;
            let running = match current_state {
                ProtocolContractState::Running(state) => state,
                other => anyhow::bail!("expected running contract state, got {}", other.name()),
            };

            let kick_account = match target {
                Some(target) => target,
                None => running
                    .participants
                    .iter()
                    .last()
                    .map(|(account_id, _)| account_id.to_string())
                    .context("no participant available to kick")?,
            };
            let kick_id: AccountId = kick_account.parse()?;

            let voters = env
                .participants
                .iter()
                .filter(|entry| entry.account_id != kick_account)
                .take(env.threshold)
                .map(|entry| saved_account(entry, &worker))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let voter_refs = voters.iter().collect::<Vec<_>>();

            crate::utils::vote_leave(&voter_refs, contract.id(), &kick_id).await?;
            wait_for_running_epoch_change(&contract).await?;

            if let Some(index) = env
                .participants
                .iter()
                .position(|entry| entry.account_id == kick_account)
            {
                if let Some(pid) = env.participants[index].pid {
                    let _ = Command::new("kill").arg(pid.to_string()).status();
                }
                env.participants.remove(index);
                persist_env(path, &env)?;
            }

            println!("submitted reshare kick for {}", kick_id);
        }
    }

    Ok(())
}

fn load_env(path: &Path) -> anyhow::Result<SavedEnv> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "failed to read saved environment state from {}",
            path.display()
        )
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn persist_env(path: &Path, env: &SavedEnv) -> anyhow::Result<()> {
    fs::write(path, serde_json::to_vec_pretty(env)?)?;
    Ok(())
}

fn saved_contract(
    env: &SavedEnv,
    worker: &near_workspaces::Worker<near_workspaces::network::Custom>,
) -> anyhow::Result<Contract> {
    let account_id: AccountId = env.contract_account_id.parse()?;
    let secret_key: SecretKey = env.contract_secret_key.parse()?;
    Ok(Contract::from_secret_key(account_id, secret_key, worker))
}

fn saved_account(
    entry: &SavedParticipant,
    worker: &near_workspaces::Worker<near_workspaces::network::Custom>,
) -> anyhow::Result<Account> {
    let account_id: AccountId = entry.account_id.parse()?;
    let secret_key: SecretKey = entry.secret_key.parse()?;
    Ok(Account::from_secret_key(account_id, secret_key, worker))
}

async fn send_sign_request(
    caller: &Account,
    contract: &Contract,
    request: &SignRequest,
) -> anyhow::Result<()> {
    caller
        .call(contract.id(), "sign")
        .args_json(serde_json::json!({ "request": request }))
        .gas(SIGN_GAS)
        .deposit(SIGN_DEPOSIT)
        .transact()
        .await?
        .into_result()?;
    Ok(())
}

async fn spawn_join_candidate(
    env: &SavedEnv,
    worker: &near_workspaces::Worker<near_workspaces::network::Custom>,
    contract: &Contract,
) -> anyhow::Result<SavedParticipant> {
    let parent = saved_account(
        env.participants
            .first()
            .context("at least one participant is required to create a join account")?,
        worker,
    )?;

    let suffix = random_suffix();
    let new_name = format!("join-{suffix}");
    let new_key = SecretKey::from_seed(KeyType::ED25519, &format!("join-{suffix}"));
    let new_account = parent
        .create_subaccount(&new_name)
        .keys(new_key)
        .initial_balance(NearToken::from_near(DEFAULT_JOIN_BALANCE_NEAR))
        .transact()
        .await?
        .into_result()?;

    let web_port = utils::pick_unused_port().await?;
    let (cipher_sk, cipher_pk) = hpke::generate();
    let sign_sk = NearSecretKey::from_seed(near_crypto::KeyType::ED25519, "integration-test");
    let my_address = format!("http://127.0.0.1:{web_port}");

    new_account
        .call(contract.id(), "join")
        .args_json(serde_json::json!({
            "url": my_address,
            "cipher_pk": cipher_pk,
            "sign_pk": sign_sk.public_key().to_string(),
        }))
        .max_gas()
        .transact()
        .await?
        .into_result()?;

    let log_path = joined_node_log_path(&new_account);
    let pid = spawn_detached_node(
        env,
        &new_account,
        web_port,
        &cipher_sk,
        sign_sk.clone(),
        &log_path,
    )?;

    Ok(SavedParticipant {
        account_id: new_account.id().to_string(),
        secret_key: new_account.secret_key().to_string(),
        spawned_by_helper: true,
        pid: Some(pid),
        log_path: Some(log_path.display().to_string()),
    })
}

fn spawn_detached_node(
    env: &SavedEnv,
    account: &Account,
    web_port: u16,
    cipher_sk: &hpke::SecretKey,
    sign_sk: NearSecretKey,
    log_path: &Path,
) -> anyhow::Result<u32> {
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let log_file = File::create(log_path)?;
    let log_file_err = log_file.try_clone()?;

    let eth = EthArgs::from_config(env.eth.clone().map(|eth| EthConfig {
        account_sk: eth.account_sk,
        consensus_rpc_http_url: eth.consensus_rpc_http_url,
        execution_rpc_http_url: eth.execution_rpc_http_url,
        contract_address: eth.contract_address,
        network: eth.network,
        helios_data_path: format!("{}_{}", eth.helios_data_path, account.id()),
        refresh_finalized_interval: eth.refresh_finalized_interval,
        optimistic_requests: eth.optimistic_requests,
        light_client: eth.light_client,
    }));
    let sol = SolArgs::from_config(env.sol.clone().map(|sol| SolConfig {
        account_sk: sol.account_sk,
        rpc_http_url: sol.rpc_http_url,
        rpc_ws_url: sol.rpc_ws_url,
        program_address: sol.program_address,
    }));
    let hydration =
        HydrationArgs::from_config(env.hydration.clone().map(|hydration| HydrationConfig {
            rpc_ws_url: hydration.rpc_ws_url,
            signer_uri: hydration.signer_uri,
        }));
    let canton = CantonArgs::from_config(env.canton.clone().map(|canton| CantonConfig {
        json_api_url: canton.json_api_url,
        json_api_ws_url: canton.json_api_ws_url,
        jwt_private_key_path: canton.jwt_private_key_path,
        jwt_subject: canton.jwt_subject,
        party_id: canton.party_id,
        signer_contract_id: canton.signer_contract_id,
        signer_template_id: canton.signer_template_id,
    }));

    let storage_options = storage::Options {
        env: "integration-tests".to_string(),
        gcp_project_id: "multichain-integration".to_string(),
        sk_share_secret_id: None,
        sk_share_local_path: Some(secret_storage_dir()?.display().to_string()),
        redis_url: env.redis_url.clone(),
    };
    let cli = mpc_node::cli::Cli::Start {
        near_rpc: env.rpc_url.clone(),
        mpc_contract_id: env.contract_account_id.parse()?,
        account_id: account.id().clone(),
        account_sk: account.secret_key().to_string().parse()?,
        web_port: Some(web_port),
        cipher_sk: hex::encode(cipher_sk.to_bytes()),
        sign_sk: Some(sign_sk),
        eth,
        sol,
        hydration,
        canton,
        indexer_options: mpc_node::indexer::Options {
            running_threshold: 120,
        },
        my_address: None,
        storage_options,
        log_options: logs::Options::test(),
        override_config: Some(OverrideConfig::new(serde_json::to_value(
            env.protocol.clone(),
        )?)),
        client_header_referer: None,
        mesh_options: mesh::Options {
            ping_interval: 1000,
        },
        message_options: node_client::Options {
            timeout: 1000,
            state_timeout: 1000,
            sync_timeout: 60000,
        },
    };

    let executable = execute::executable(env.release, execute::PACKAGE_MULTICHAIN)
        .context("could not find mpc-node executable")?;

    let mut command = Command::new(&executable);
    command
        .args(cli.into_str_args())
        .env("RUST_LOG", "info,workspaces=warn")
        .envs(Chain::checkpoint_env_vars())
        .envs(std::env::vars())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err));

    let child = command
        .spawn()
        .with_context(|| format!("failed to spawn detached node: {}", executable.display()))?;

    Ok(child.id())
}

async fn wait_for_candidate(contract: &Contract, account_id: &AccountId) -> anyhow::Result<()> {
    wait_until(Duration::from_secs(60), || async {
        let state = view_contract_state(contract).await?;
        match state {
            ProtocolContractState::Running(state) if state.candidates.contains_key(account_id) => {
                Ok(true)
            }
            _ => Ok(false),
        }
    })
    .await
}

async fn wait_for_running_epoch_change(contract: &Contract) -> anyhow::Result<()> {
    let initial_epoch = match view_contract_state(contract).await? {
        ProtocolContractState::Running(state) => state.epoch,
        ProtocolContractState::Resharing(state) => state.old_epoch,
        other => anyhow::bail!("expected running or resharing state, got {}", other.name()),
    };

    wait_until(Duration::from_secs(180), || async {
        let state = view_contract_state(contract).await?;
        match state {
            ProtocolContractState::Running(state) => Ok(state.epoch > initial_epoch),
            _ => Ok(false),
        }
    })
    .await
}

async fn view_contract_state(contract: &Contract) -> anyhow::Result<ProtocolContractState> {
    Ok(contract.view("state").await?.json()?)
}

async fn wait_until<F, Fut>(timeout: Duration, mut predicate: F) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<bool>>,
{
    let started = std::time::Instant::now();
    loop {
        if predicate().await? {
            return Ok(());
        }
        if started.elapsed() > timeout {
            anyhow::bail!("timed out after {:?}", timeout);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn parse_32_byte_hex(input: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = input.strip_prefix("0x").unwrap_or(input);
    let bytes = hex::decode(trimmed)
        .with_context(|| format!("failed to decode hex payload from '{input}'"))?;
    if bytes.len() != 32 {
        anyhow::bail!("expected 32-byte hex string, got {} bytes", bytes.len());
    }
    let mut payload = [0u8; 32];
    payload.copy_from_slice(&bytes);
    Ok(payload)
}

fn default_payload(seed: u64) -> [u8; 32] {
    let mut payload = [0u8; 32];
    payload[..8].copy_from_slice(&seed.to_be_bytes());
    rand::thread_rng().fill(&mut payload[8..]);
    payload
}

fn random_suffix() -> String {
    (0..6)
        .map(|_| {
            let c = rand::thread_rng().gen_range(b'a'..=b'z');
            c as char
        })
        .collect()
}

fn joined_node_log_path(account: &Account) -> PathBuf {
    secret_storage_dir()
        .unwrap_or_else(|_| PathBuf::from("target/tmp"))
        .join("logs")
        .join(format!("{}.log", account.id()))
}

fn secret_storage_dir() -> anyhow::Result<PathBuf> {
    let mut dir = execute::target_dir().context("could not locate cargo target directory")?;
    dir.push("tmp");
    dir.push("secrets");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}
