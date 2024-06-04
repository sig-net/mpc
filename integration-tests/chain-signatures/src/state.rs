use near_account_id::AccountId;
use serde_json::json;

use crate::Context;

async fn import_latest_contract(ctx: &Context<'_>, import: &AccountId) -> anyhow::Result<()> {
    let state: mpc_contract::ProtocolContractState =
        ctx.mpc_contract.view("state").await?.json()?;
    let mpc_contract::ProtocolContractState::Running(state) = state else {
        anyhow::bail!("Cannot import contract state if it is not running");
    };

    // Import latest contract with state from testnet. This will overwrite our current contract:
    let contract = ctx
        .worker
        .import_contract(import, &near_workspaces::testnet().await?)
        .with_data()
        .dest_account_id(ctx.mpc_contract.id())
        .transact()
        .await?;
    tracing::info!(contract_id = %contract.id(), "imported testnet mpc contract");

    // Initialize the contract with the participant info from our local sandbox:
    ctx.mpc_contract
        .call("init_running")
        .args_json(json!({
            "epoch": state.epoch,
            "participants": state.participants,
            "threshold": state.threshold,
            "public_key": state.public_key,
        }))
        .transact()
        .await?
        .into_result()?;

    Ok(())
}
