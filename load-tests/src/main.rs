pub mod common;
pub mod multichain;

use common::{delete_user_account, prepare_user_credentials};
use goose::prelude::*;
use multichain::multichain_sign;
use tracing_subscriber::{filter, prelude::*};

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();

    let sign_calls_per_account = 10;

    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::INFO))
        .init();

    GooseAttack::initialize()?
        .register_scenario(
            scenario!("multichainSign")
                .register_transaction(transaction!(prepare_user_credentials).set_sequence(1))
                .register_transaction(
                    transaction!(multichain_sign)
                        .set_sequence(2)
                        .set_weight(sign_calls_per_account)?,
                )
                .register_transaction(transaction!(delete_user_account).set_sequence(3)),
        )
        .execute()
        .await?;

    Ok(())
}
