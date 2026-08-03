//! The NEAR leg of the localnet: creating node accounts, deploying the MPC contract, and
//! putting it straight into the running state.
//!
//! The contract is the only source of truth for the participant set, so everything the
//! nodes need to find each other is registered here.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use mpc_contract::primitives::{CandidateInfo, Candidates, Participants};
use near_account_id::AccountId;
use near_workspaces::network::ValidatorKey;
use near_workspaces::types::{NearToken, SecretKey};
use near_workspaces::{Account, Contract, Worker};
use serde_json::json;

use crate::nodes::NodeSpec;

/// Balance given to each node account. Nodes pay gas for `respond` and the voting calls.
const NODE_BALANCE: NearToken = NearToken::from_near(100);
/// Balance given to the contract account, which has to cover its own storage.
const CONTRACT_BALANCE: NearToken = NearToken::from_near(200);

/// Protocol config for a laptop.
///
/// The contract's own defaults are `min_triples: 1024` and `min_presignatures: 512`, which
/// would have three nodes generating material for minutes on end before the first
/// signature. These numbers are large enough to serve requests and small enough to reach
/// quickly.
const MIN_TRIPLES: u32 = 8;
const MAX_TRIPLES: u32 = 64;
const MIN_PRESIGNATURES: u32 = 4;
const MAX_PRESIGNATURES: u32 = 32;

pub struct NearConfig {
    pub rpc_url: String,
    pub root_account_id: AccountId,
    pub root_sk: SecretKey,
    pub contract_account_id: AccountId,
    pub threshold: usize,
}

/// Attach to an already-running sandbox rather than spawning one.
///
/// near-workspaces takes this path whenever both an rpc address and a validator key are
/// supplied, so no sandbox binary is downloaded and no process is spawned.
pub async fn connect(config: &NearConfig) -> anyhow::Result<Worker<near_workspaces::network::Sandbox>> {
    near_workspaces::sandbox()
        .rpc_addr(&config.rpc_url)
        .validator_key(ValidatorKey::Known(
            config.root_account_id.clone(),
            config.root_sk.clone(),
        ))
        .await
        .with_context(|| format!("attaching to the near sandbox at {}", config.rpc_url))
}

/// Block until the sandbox serves its status endpoint, or give up after `timeout`.
pub async fn wait_until_healthy(rpc_url: &str, timeout: Duration) -> anyhow::Result<()> {
    let http = reqwest::Client::new();
    let status_url = format!("{}/status", rpc_url.trim_end_matches('/'));
    let deadline = Instant::now() + timeout;
    let mut last_error = None;
    while Instant::now() < deadline {
        match http.get(&status_url).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => last_error = Some(format!("status {}", response.status())),
            Err(err) => last_error = Some(err.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("near sandbox did not become healthy within {timeout:?}: {last_error:?}")
}

/// The single-label prefix `account_id` must be created under `root`.
fn subaccount_prefix(account_id: &AccountId, root: &str) -> anyhow::Result<String> {
    account_id
        .as_str()
        .strip_suffix(&format!(".{root}"))
        .filter(|prefix| !prefix.contains('.'))
        .map(str::to_string)
        .ok_or_else(|| anyhow!("{account_id} is not a direct subaccount of {root}"))
}

async fn account_exists(worker: &Worker<near_workspaces::network::Sandbox>, id: &AccountId) -> bool {
    worker.view_account(&near_workspaces::AccountId::from(id.clone())).await.is_ok()
}

/// Create `account_id` under `root` with the given key, or adopt it if it already exists.
async fn ensure_account(
    worker: &Worker<near_workspaces::network::Sandbox>,
    root: &Account,
    account_id: &AccountId,
    secret_key: &SecretKey,
    balance: NearToken,
) -> anyhow::Result<Account> {
    let workspaces_id = near_workspaces::AccountId::from(account_id.clone());
    if account_exists(worker, account_id).await {
        tracing::info!(%account_id, "account already exists, reusing it");
        return Ok(Account::from_secret_key(workspaces_id, secret_key.clone(), worker));
    }

    let prefix = subaccount_prefix(account_id, root.id().as_str())?;
    let account = root
        .create_subaccount(&prefix)
        .keys(secret_key.clone())
        .initial_balance(balance)
        .transact()
        .await
        .with_context(|| format!("creating {account_id}"))?
        .into_result()
        .with_context(|| format!("creating {account_id}"))?;
    tracing::info!(%account_id, "created account");
    Ok(account)
}

/// Read the contract's `state` view and report whether it is already running.
async fn is_running(contract: &Contract) -> bool {
    match contract.view("state").await {
        Ok(result) => result
            .json::<serde_json::Value>()
            .map(|state| state.get("Running").is_some())
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Create the node accounts, deploy the MPC contract and put it into the running state.
///
/// Every step checks for its own effect first, so the whole thing is safe to re-run against
/// a sandbox that survived a restart.
pub async fn bootstrap(
    config: &NearConfig,
    nodes: &[NodeSpec],
    wasm_path: &Path,
    public_key: mpc_crypto::PublicKey,
) -> anyhow::Result<()> {
    let worker = connect(config).await?;
    let root = worker.root_account().context("reading the sandbox root account")?;
    if root.id().as_str() != config.root_account_id.as_str() {
        anyhow::bail!(
            "sandbox root account is {} but {} was configured",
            root.id(),
            config.root_account_id
        );
    }

    for node in nodes {
        ensure_account(&worker, &root, &node.account_id, &to_workspaces_key(&node.account_sk)?, NODE_BALANCE)
            .await?;
    }

    let contract_sk = SecretKey::from_seed(
        near_workspaces::types::KeyType::ED25519,
        config.contract_account_id.as_str(),
    );
    let contract_account = ensure_account(
        &worker,
        &root,
        &config.contract_account_id,
        &contract_sk,
        CONTRACT_BALANCE,
    )
    .await?;

    let wasm = std::fs::read(wasm_path)
        .with_context(|| format!("reading the contract wasm at {}", wasm_path.display()))?;
    let contract = contract_account
        .deploy(&wasm)
        .await
        .context("deploying the mpc contract")?
        .into_result()
        .context("deploying the mpc contract")?;
    tracing::info!(account = %contract.id(), bytes = wasm.len(), "deployed mpc contract");

    if is_running(&contract).await {
        tracing::info!("mpc contract is already running, leaving its state alone");
        return Ok(());
    }

    let candidates = Candidates {
        candidates: nodes
            .iter()
            .map(|node| {
                Ok((
                    node.account_id.clone(),
                    CandidateInfo {
                        account_id: node.account_id.clone(),
                        url: node.local_address.clone(),
                        cipher_pk: node.cipher_sk.public_key().to_bytes(),
                        sign_pk: node.sign_sk.public_key().to_string().parse()?,
                    },
                ))
            })
            .collect::<anyhow::Result<_>>()?,
    };
    let participants = Participants::from(candidates);

    // The contract wants a NEAR-flavoured secp256k1 key, which is the uncompressed SEC1
    // encoding with its leading 0x04 tag removed.
    let encoded = public_key.to_encoded_point(false);
    let near_public_key = near_crypto::PublicKey::SECP256K1(
        near_crypto::Secp256K1PublicKey::try_from(&encoded.as_bytes()[1..65])
            .map_err(|err| anyhow!("converting the key share public key: {err}"))?,
    );

    // Built from the real struct rather than hand-written JSON. `ProtocolConfig` declares no
    // serde defaults, so a partial object is rejected outright, and spelling every field out
    // by hand would silently rot the moment the contract grows one.
    let mut protocol_config = mpc_contract::config::Config::default();
    protocol_config.protocol.triple.min_triples = MIN_TRIPLES;
    protocol_config.protocol.triple.max_triples = MAX_TRIPLES;
    protocol_config.protocol.presignature.min_presignatures = MIN_PRESIGNATURES;
    protocol_config.protocol.presignature.max_presignatures = MAX_PRESIGNATURES;

    contract
        .call("init_running")
        .args_json(json!({
            "epoch": 0,
            "participants": participants,
            "threshold": config.threshold,
            "public_key": near_public_key,
            "config": protocol_config,
        }))
        .max_gas()
        .transact()
        .await
        .context("calling init_running")?
        .into_result()
        .context("calling init_running")?;

    tracing::info!(
        threshold = config.threshold,
        participants = nodes.len(),
        public_key = %near_public_key,
        "mpc contract initialised in the running state"
    );
    Ok(())
}

/// near-workspaces and near-crypto carry separate but wire-compatible key types.
fn to_workspaces_key(secret_key: &near_crypto::SecretKey) -> anyhow::Result<SecretKey> {
    secret_key
        .to_string()
        .parse()
        .map_err(|err| anyhow!("converting a secret key for near-workspaces: {err:?}"))
}
