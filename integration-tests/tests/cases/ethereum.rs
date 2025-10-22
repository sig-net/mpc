use anyhow::{Context, Result};
use ethers::types::{BlockNumber, U256};
use integration_tests::{cluster, eth};
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use test_log::test;
use tokio::time::{sleep, Duration};

#[test(tokio::test)]
async fn test_ethereum_signature_roundtrip() -> Result<()> {
    let cluster = cluster::spawn().disable_prestockpile().ethereum().await?;
    cluster.wait().signable().await?;

    let ctx = cluster.nodes.ctx();
    let eth_ctx = ctx
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    let endpoint = eth_ctx.sandbox.external_http_endpoint.clone();
    let private_key = eth_ctx.sandbox.private_key.clone();
    let chain_id = eth_ctx.sandbox.chain_id;
    let contract_address = eth_ctx.contract_address;

    let (client, requester) = eth::client(&endpoint, &private_key, chain_id)?;
    let contract = eth::ChainSignaturesContract::new(contract_address, client.clone());

    let payload = [7u8; 32];
    let path = "m/44'/60'/0'/0/0";
    let algo = "secp256k1";
    let dest = "http://localhost/callback";
    let params = "{}";

    let request = eth::SignRequest {
        payload,
        path: path.to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        algo: algo.to_string(),
        dest: dest.to_string(),
        params: params.to_string(),
    };

    let call = contract.sign(request).value(U256::from(1_u64));
    let pending = call.send().await?;
    let receipt = pending.await?.context("sign transaction failed")?;
    let from_block = BlockNumber::Number(
        receipt
            .block_number
            .context("missing block number in receipt")?,
    );

    let expected_request_id = eth::compute_request_id(
        requester,
        payload,
        path,
        LATEST_MPC_KEY_VERSION,
        U256::from(chain_id),
        algo,
        dest,
        params,
    );

    let mut found = false;
    for _ in 0..30 {
        let events = contract
            .event::<eth::SignatureRespondedFilter>()
            .from_block(from_block)
            .query()
            .await?;
        if events.iter().any(|event| {
            event.request_id == &expected_request_id[..] && event.responder == requester
        }) {
            found = true;
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }

    anyhow::ensure!(found, "did not observe signature response on ethereum");

    Ok(())
}
