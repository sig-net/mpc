use anyhow::Context;
use near_primitives::serialize::from_base64;
use near_workspaces::AccountId;
use serde::Deserialize;
use serde_json::json;
use signet_primitives::Chain;
use std::collections::HashMap;

const TESTNET_RPC_URL: &str = "https://rpc.testnet.near.org";
const MAINNET_RPC_URL: &str = "https://rpc.mainnet.near.org";
const VIEW_STATE_PAGE_SIZE: u64 = 1000;

#[path = "support/sandbox.rs"]
mod sandbox;
use sandbox::{contract_file_path, SANDBOX_VERSION};

#[derive(Deserialize)]
struct ViewStateResponse {
    result: Option<ViewStateResult>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ViewStateResult {
    values: Vec<StateValue>,
    last_key: Option<String>,
}

#[derive(Deserialize)]
struct StateValue {
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct ViewCodeResponse {
    result: Option<ViewCodeResult>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ViewCodeResult {
    code_base64: String,
}

/// The contract code deployed at `contract_id`.
async fn view_code(rpc_url: &str, contract_id: &AccountId) -> anyhow::Result<Vec<u8>> {
    let params = json!({
        "jsonrpc": "2.0",
        "id": "network-migration-test",
        "method": "query",
        "params": {
            "request_type": "view_code",
            "finality": "final",
            "account_id": contract_id,
        }
    });
    let response = reqwest::Client::new()
        .post(rpc_url)
        .json(&params)
        .send()
        .await?
        .error_for_status()?
        .json::<ViewCodeResponse>()
        .await?;
    if let Some(error) = response.error {
        anyhow::bail!("view_code failed for {contract_id}: {error}");
    }
    let result = response
        .result
        .with_context(|| format!("view_code returned no result for {contract_id}"))?;
    Ok(from_base64(&result.code_base64)?)
}

/// Each chain's `latest_checkpoint` view, as JSON.
async fn latest_checkpoints(
    contract: &near_workspaces::Contract,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut checkpoints = Vec::new();
    for chain in Chain::iter() {
        checkpoints.push(
            contract
                .view("latest_checkpoint")
                .args_json(json!({ "chain": chain }))
                .await?
                .json()?,
        );
    }
    Ok(checkpoints)
}

async fn view_state(
    rpc_url: &str,
    contract_id: &AccountId,
) -> anyhow::Result<HashMap<Vec<u8>, Vec<u8>>> {
    let client = reqwest::Client::new();
    let mut state = HashMap::new();
    let mut after_key: Option<String> = None;

    loop {
        let params = json!({
            "jsonrpc": "2.0",
            "id": "network-migration-test",
            "method": "query",
            "params": {
                "request_type": "view_state",
                "finality": "final",
                "account_id": contract_id,
                "prefix_base64": "",
                "limit": VIEW_STATE_PAGE_SIZE,
                "after_key_base64": after_key,
            }
        });

        let response = client
            .post(rpc_url)
            .json(&params)
            .send()
            .await?
            .error_for_status()?
            .json::<ViewStateResponse>()
            .await?;

        if let Some(error) = response.error {
            anyhow::bail!("view_state failed for {contract_id}: {error}");
        }

        let result = response
            .result
            .with_context(|| format!("view_state returned no result for {contract_id}"))?;
        for entry in result.values {
            state.insert(from_base64(&entry.key)?, from_base64(&entry.value)?);
        }

        match result.last_key {
            Some(last_key) => after_key = Some(last_key),
            None => break,
        }
    }

    Ok(state)
}

async fn assert_migration(
    rpc_url: &str,
    source_contract_id: AccountId,
    wasm: &[u8],
) -> anyhow::Result<()> {
    let state = view_state(rpc_url, &source_contract_id).await?;
    assert!(
        state.contains_key(b"STATE".as_slice()),
        "{source_contract_id} has no STATE entry"
    );

    let deployed_wasm = view_code(rpc_url, &source_contract_id).await?;

    let sandbox = near_workspaces::sandbox_with_version(SANDBOX_VERSION).await?;
    let contract = sandbox.dev_deploy(&deployed_wasm).await?;
    sandbox
        .patch(contract.id())
        .states(
            state
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        )
        .transact()
        .await?;
    // What the deployed code serves from this state, read before the upgrade.
    let checkpoints = latest_checkpoints(&contract).await?;

    contract
        .as_account()
        .deploy(wasm)
        .await?
        .into_result()
        .with_context(|| format!("deploy over {source_contract_id}"))?;
    let migration = contract
        .call("migrate")
        .max_gas()
        .transact()
        .await
        .with_context(|| format!("migrate {source_contract_id}"))?;
    assert!(
        migration.is_success(),
        "migration failed for {source_contract_id}: {migration:?}"
    );
    assert_eq!(
        latest_checkpoints(&contract).await?,
        checkpoints,
        "{source_contract_id}: the migration changed a checkpoint"
    );

    Ok(())
}

// Each test migrates a live contract's state. Ignored: CI runs them per target branch.
// Locally: `cargo test -p mpc-contract --test network_migration -- --ignored`.

#[tokio::test]
#[ignore = "run conditionally by CI, see test-unit.yml"]
async fn test_migrate_dev_state() -> anyhow::Result<()> {
    let wasm = std::fs::read(contract_file_path())?;
    assert_migration(TESTNET_RPC_URL, "dev.sig-net.testnet".parse()?, &wasm).await
}

#[tokio::test]
#[ignore = "run conditionally by CI, see test-unit.yml"]
async fn test_migrate_testnet_state() -> anyhow::Result<()> {
    let wasm = std::fs::read(contract_file_path())?;
    assert_migration(TESTNET_RPC_URL, "v1.sig-net.testnet".parse()?, &wasm).await
}

#[tokio::test]
#[ignore = "run conditionally by CI, see test-unit.yml"]
async fn test_migrate_mainnet_state() -> anyhow::Result<()> {
    let wasm = std::fs::read(contract_file_path())?;
    assert_migration(MAINNET_RPC_URL, "v1.sig-net.near".parse()?, &wasm).await
}
