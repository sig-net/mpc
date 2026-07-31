use anyhow::Context;
use near_primitives::serialize::from_base64;
use near_workspaces::AccountId;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

const TESTNET_RPC_URL: &str = "https://rpc.testnet.fastnear.com";
const MAINNET_RPC_URL: &str = "https://rpc.mainnet.fastnear.com";

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
}

#[derive(Deserialize)]
struct StateValue {
    key: String,
    value: String,
}

async fn view_state(
    rpc_url: &str,
    contract_id: &AccountId,
) -> anyhow::Result<HashMap<Vec<u8>, Vec<u8>>> {
    let response = reqwest::Client::new()
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": "network-migration-test",
            "method": "query",
            "params": {
                "request_type": "view_state",
                "finality": "final",
                "account_id": contract_id,
                "prefix_base64": ""
            }
        }))
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
    result
        .values
        .into_iter()
        .map(|entry| Ok((from_base64(&entry.key)?, from_base64(&entry.value)?)))
        .collect()
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

    let sandbox = near_workspaces::sandbox_with_version(SANDBOX_VERSION).await?;
    let contract = sandbox.dev_deploy(wasm).await?;
    sandbox
        .patch(contract.id())
        .states(
            state
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        )
        .transact()
        .await?;

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

    Ok(())
}

#[tokio::test]
async fn test_migrate_deployed_network_states() -> anyhow::Result<()> {
    let wasm = std::fs::read(contract_file_path())?;

    assert_migration(TESTNET_RPC_URL, "dev.sig-net.testnet".parse()?, &wasm).await?;
    assert_migration(TESTNET_RPC_URL, "v1.sig-net.testnet".parse()?, &wasm).await?;
    assert_migration(MAINNET_RPC_URL, "v1.sig-net.near".parse()?, &wasm).await?;

    Ok(())
}
