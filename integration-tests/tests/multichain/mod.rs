pub mod actions;

use crate::with_multichain_nodes;
use actions::wait_for;
use test_log::test;

#[test(tokio::test)]
async fn test_multichain_reshare() -> anyhow::Result<()> {
    with_multichain_nodes(3, |mut ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);

            let account = ctx.nodes.ctx().worker.dev_create_account().await?;
            ctx.nodes
                .add_node(account.id(), account.secret_key())
                .await?;

            let state_1 = wait_for::running_mpc(&ctx, 1).await?;
            assert_eq!(state_1.participants.len(), 4);

            assert_eq!(
                state_0.public_key, state_1.public_key,
                "public key must stay the same"
            );

            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_triples_and_presignatures() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            // TODO: add test that checks #triples in datastore
            // for account_id in state_0.participants.keys() {
            //     let triple_storage = ctx.nodes.triple_storage(account_id.to_string()).await?;
            //     // This errs out with
            //     // Err(GcpError(BadRequest(Object {"error": Object {"code": Number(400), "message": String("Payload isn't valid for request."), "status": String("INVALID_ARGUMENT")}})))
            //     let _load_res = triple_storage.load().await;
            //     //print!("result is: {:?}", load_res);
            //     //assert_eq!(load_res.len(), 6);
            // }
            Ok(())
        })
    })
    .await
}

#[test(tokio::test)]
async fn test_signature() -> anyhow::Result<()> {
    with_multichain_nodes(3, |ctx| {
        Box::pin(async move {
            let state_0 = wait_for::running_mpc(&ctx, 0).await?;
            assert_eq!(state_0.participants.len(), 3);
            wait_for::has_at_least_triples(&ctx, 2).await?;
            wait_for::has_at_least_presignatures(&ctx, 2).await?;
            actions::single_signature_production(&ctx, &state_0).await
        })
    })
    .await
}

use std::str::FromStr;

use web3::{
    ethabi::ethereum_types::U256,
    signing::SecretKey,
    types::{Address, TransactionParameters},
};

#[test(tokio::test)]
async fn test_ecsign_experiment() -> Result<(), Box<dyn std::error::Error>> {
    let transport = web3::transports::Http::new("https://rpc2.sepolia.org")?;
    let web3 = web3::Web3::new(transport);

    let to = Address::from_str("0xa3286628134bad128faeef82f44e99aa64085c93").unwrap();

    let prvk =
        SecretKey::from_str("9ea65c28a56227218ae206bacfa424be4da742791d93cb396d0ff5da3cee3736")
            .unwrap();

    let tx_object = TransactionParameters {
        to: Some(to),
        value: U256::one(),
        ..Default::default()
    };

    let signed = web3.accounts().sign_transaction(tx_object, &prvk).await?;

    let result = web3
        .eth()
        .send_raw_transaction(signed.raw_transaction)
        .await?;

    println!("Tx succeeded with hash: {}", result);

    Ok(())
}
