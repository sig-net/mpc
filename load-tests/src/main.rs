pub mod common;
pub mod multichain;

use common::{delete_user_account, prepare_user_credentials};
use goose::prelude::*;
use multichain::multichain_sign;
use tracing_subscriber::{filter, prelude::*};

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();

    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::INFO))
        .init();

    GooseAttack::initialize()?
        .register_scenario(
            scenario!("multichainSign")
                .register_transaction(transaction!(prepare_user_credentials).set_sequence(1))
                .register_transaction(transaction!(multichain_sign).set_sequence(2))
                .register_transaction(transaction!(multichain_sign).set_sequence(3))
                .register_transaction(transaction!(multichain_sign).set_sequence(4))
                .register_transaction(transaction!(multichain_sign).set_sequence(5))
                .register_transaction(transaction!(multichain_sign).set_sequence(6))
                .register_transaction(transaction!(multichain_sign).set_sequence(7))
                .register_transaction(transaction!(multichain_sign).set_sequence(8))
                .register_transaction(transaction!(multichain_sign).set_sequence(9))
                .register_transaction(transaction!(multichain_sign).set_sequence(10))
                .register_transaction(transaction!(multichain_sign).set_sequence(11))
                .register_transaction(transaction!(delete_user_account).set_sequence(12)),
        )
        .execute()
        .await?;

    Ok(())
}
