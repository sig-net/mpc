use goose::prelude::*;
use goose_eggs::{validate_and_load_static_assets, Validate};

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(
            scenario!("LoadtestTransactions").register_transaction(transaction!(mpc_public_key)),
        )
        .execute()
        .await?;

    Ok(())
}

async fn mpc_public_key(user: &mut GooseUser) -> TransactionResult {
    let mpc_pk_result = user.get("mpc_public_key").await?;
    let validate = &Validate::builder().status(200).build();
    validate_and_load_static_assets(user, mpc_pk_result, &validate).await?;
    Ok(())
}
