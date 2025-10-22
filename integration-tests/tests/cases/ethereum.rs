use anyhow::{anyhow, Context, Result};
use ethers::types::{BlockNumber, U256};
use integration_tests::{actions, cluster, eth};
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, FieldBytes, PublicKey as K256PublicKey};
use mpc_crypto::derive_key;
use mpc_crypto::kdf::derive_epsilon_eth;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use test_log::test;
use tokio::time::{sleep, Duration};

#[test(tokio::test)]
async fn test_signature_ethereum() -> Result<()> {
    let cluster = cluster::spawn().disable_prestockpile().ethereum().await?;
    cluster.wait().signable().await?;

    let ctx = cluster.nodes.ctx();
    let eth_ctx = ctx
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    let endpoint = eth_ctx.sandbox.external_http_endpoint.clone();
    let secret_key = eth_ctx.sandbox.secret_key.clone();
    let chain_id = eth_ctx.sandbox.chain_id;
    let contract_address = eth_ctx.contract_address;

    let (client, requester) = eth::client(&endpoint, &secret_key, chain_id)?;
    let contract = eth::ChainSignaturesContract::new(contract_address, client.clone());

    let payload = [7u8; 32];
    let path = "test";
    let algo = "secp256k1";
    let dest = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
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

    let mut matching_event = None;
    for _ in 0..30 {
        let events = contract
            .event::<eth::SignatureRespondedFilter>()
            .from_block(from_block)
            .query()
            .await?;
        if let Some(event) = events.into_iter().find(|event| {
            event.request_id == expected_request_id[..] && event.responder == requester
        }) {
            matching_event = Some(event);
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }

    let event =
        matching_event.ok_or_else(|| anyhow!("did not observe signature response on ethereum"))?;

    let mut x_bytes = [0u8; 32];
    event.signature.big_r.x.to_big_endian(&mut x_bytes);
    let mut y_bytes = [0u8; 32];
    event.signature.big_r.y.to_big_endian(&mut y_bytes);
    let x_field: &FieldBytes = FieldBytes::from_slice(&x_bytes);
    let y_field: &FieldBytes = FieldBytes::from_slice(&y_bytes);
    let encoded_r = EncodedPoint::from_affine_coordinates(x_field, y_field, false);
    let big_r = AffinePoint::from_encoded_point(&encoded_r)
        .into_option()
        .ok_or_else(|| anyhow!("invalid R component in signature"))?;

    let r_scalar = actions::x_coordinate::<k256::Secp256k1>(&big_r);
    let r_bytes = r_scalar.to_bytes();

    let mut s_bytes = [0u8; 32];
    event.signature.s.to_big_endian(&mut s_bytes);

    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(r_bytes.as_slice());
    signature_bytes[32..].copy_from_slice(&s_bytes);

    let recovered_address =
        actions::recover_eth_address(&payload, &signature_bytes, event.signature.recovery_id);

    let network_public_key = cluster.root_public_key().await?;
    let mut network_pk = vec![0x04];
    network_pk.extend_from_slice(&network_public_key.as_bytes()[1..]);
    let encoded_network_pk =
        EncodedPoint::from_bytes(&network_pk).context("invalid network public key encoding")?;
    let network_affine = AffinePoint::from_encoded_point(&encoded_network_pk)
        .into_option()
        .ok_or_else(|| anyhow!("invalid network public key"))?;

    let sender_hex = format!("0x{}", hex::encode(requester));
    let epsilon = derive_epsilon_eth(LATEST_MPC_KEY_VERSION, &sender_hex, path);
    let user_affine = derive_key(network_affine, epsilon);
    let user_public_key = K256PublicKey::from_affine(user_affine)
        .map_err(|_| anyhow!("invalid derived public key"))?;
    let verifying_key = VerifyingKey::from(&user_public_key);
    let expected_address = ethers::utils::public_key_to_address(&verifying_key);

    anyhow::ensure!(
        recovered_address == expected_address,
        "signature recovered address mismatch: expected {expected_address:?}, got {recovered_address:?}"
    );

    Ok(())
}
