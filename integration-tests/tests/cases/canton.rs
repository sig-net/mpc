use alloy::consensus::{transaction::SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{FixedBytes, Signature, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context as _, Result};
use integration_tests::canton::{
    test_evm_params, test_sign_request_event, test_sign_request_payload,
};
use integration_tests::cluster;
use mpc_node::indexer_canton::contracts::{
    RespondBidirectionalEventPayload, SignatureRespondedEventPayload,
};
use mpc_node::indexer_canton::{compute_request_id, parse_canton_signature};
use mpc_node::respond_bidirectional::CANTON_RESPOND_BIDIRECTIONAL_PATH;
use mpc_node::sign_bidirectional::derive_user_address;
use mpc_node::util::NearPublicKeyExt;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde_json::json;
use serial_test::serial;
use std::time::Duration;
use test_log::test;

#[ignore] // requires dpm + openssl + Docker (for Ethereum)
#[serial]
#[test(tokio::test)]
async fn test_canton_eth_bidirectional_flow() -> Result<()> {
    // 1. Spawn cluster with Canton + Ethereum
    let nodes = cluster::spawn()
        .disable_prestockpile()
        .canton()
        .ethereum()
        .await?;

    nodes.wait().signable().await?;

    // 2. Get Canton and Ethereum contexts
    let canton = nodes
        .canton
        .as_ref()
        .context("canton sandbox not available")?;
    let client = &canton.client;

    let expected_event = test_sign_request_event(canton, None);
    let evm_params = test_evm_params(0);
    let expected_request_id = hex::encode(compute_request_id(&expected_event)?);

    // 3. Submit sign request directly via Signer (bypasses Vault)
    let sign_request = client
        .create_contract(
            &[&canton.operator_party, &canton.requester_party],
            "#daml-signer:Signer:SignRequest",
            serde_json::to_value(test_sign_request_payload(&expected_event))?,
        )
        .await?;
    let (sign_request_cid, _) =
        integration_tests::canton::find_created_contract(&sign_request, "SignRequest")?;

    client
        .exercise_choice(
            &[&canton.requester_party],
            &canton.signer_template_id,
            &canton.signer_cid,
            "SignBidirectional",
            json!({
                "signRequestCid": sign_request_cid,
                "requester": &canton.requester_party,
            }),
            std::slice::from_ref(&canton.signer_disclosure),
        )
        .await?;
    tracing::info!("canton sign request submitted via Signer");

    // 4. Poll for SignatureRespondedEvent matching our expected requestId
    let sig_payload: SignatureRespondedEventPayload = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:SignatureRespondedEvent",
            |p: &SignatureRespondedEventPayload| p.request_id == expected_request_id,
            Duration::from_secs(120),
        )
        .await
        .context("timeout waiting for SignatureRespondedEvent")?;
    tracing::info!(request_id = %sig_payload.request_id, "received SignatureRespondedEvent");

    let root_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();

    // 5. Relay the signed EVM transaction to Anvil
    let eth_ctx = nodes
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum not available")?;
    let anvil_rpc_url = &eth_ctx.sandbox.external_http_endpoint;
    let anvil = ProviderBuilder::new().connect_http(anvil_rpc_url.parse()?);

    let mpc_signature = parse_canton_signature(&sig_payload.signature)?;
    let unsigned_tx = TxEip1559::try_from(&evm_params)?;

    let sign_epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        &expected_event.sender,
        &canton.requester_party,
    );
    let expected_sender_addr = derive_user_address(root_pk, sign_epsilon);

    // recovery_id is now preserved from Canton, no brute-force needed
    let y_parity = mpc_signature.recovery_id == 1;

    let r_bytes: [u8; 32] = mpc_crypto::x_coordinate(&mpc_signature.big_r)
        .to_bytes()
        .into();
    let s_bytes: [u8; 32] = mpc_signature.s.to_bytes().into();

    anvil
        .anvil_set_balance(
            expected_sender_addr,
            U256::from(10_000_000_000_000_000_000u128),
        )
        .await?;

    let sig = Signature::from_scalars_and_parity(
        FixedBytes::from_slice(&r_bytes),
        FixedBytes::from_slice(&s_bytes),
        y_parity,
    );
    let signed_tx = unsigned_tx.into_signed(sig);
    let signed_bytes = signed_tx.encoded_2718();

    let pending_tx = anvil.send_raw_transaction(&signed_bytes).await?;
    let tx_hash = *pending_tx.tx_hash();
    tracing::info!(%tx_hash, y_parity, "relayed signed EIP-1559 transaction to Anvil");

    // Pump blocks on Anvil so the MPC node's Ethereum execution watcher reliably
    // detects the relayed transaction.
    let pump_anvil = anvil.clone();
    let block_pumper = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let _ = pump_anvil.evm_mine(None).await;
        }
    });

    // 6. Poll for RespondBidirectionalEvent (MPC posted the outcome)
    let respond_payload: RespondBidirectionalEventPayload = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:RespondBidirectionalEvent",
            |p: &RespondBidirectionalEventPayload| p.request_id == expected_request_id,
            Duration::from_secs(300),
        )
        .await
        .context("timeout waiting for RespondBidirectionalEvent")?;
    tracing::info!(request_id = %respond_payload.request_id, "received RespondBidirectionalEvent");

    // 7. Verify the Phase 2 response signature
    let respond_signature = parse_canton_signature(&respond_payload.signature)?;
    let response_hash =
        mpc_node::respond_bidirectional::calculate_respond_bidirectional_hash_message(
            &hex::decode(&respond_payload.request_id)?,
            &hex::decode(&respond_payload.serialized_output)?,
        );

    let respond_epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        &expected_event.sender,
        CANTON_RESPOND_BIDIRECTIONAL_PATH,
    );
    let respond_derived_pk = mpc_crypto::derive_key(root_pk, respond_epsilon);

    let respond_ecdsa = k256::ecdsa::Signature::from_scalars(
        mpc_crypto::x_coordinate(&respond_signature.big_r),
        respond_signature.s,
    )
    .context("invalid signature scalars")?;

    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let verifying_key = k256::ecdsa::VerifyingKey::from_affine(respond_derived_pk)
        .map_err(|e| anyhow::anyhow!("invalid derived public key: {e}"))?;
    verifying_key
        .verify_prehash(&response_hash, &respond_ecdsa)
        .map_err(|e| anyhow::anyhow!("RespondBidirectional signature verification failed: {e}"))?;
    tracing::info!("phase 2 signature verified");

    block_pumper.abort();
    Ok(())
}

// These are auth wiring smoke tests for our Canton sandbox setup, not Canton
// auth implementation tests. They verify the sandbox is actually enforcing the
// JWT key/cert configuration that the MPC integration relies on.
#[ignore] // requires dpm
#[serial]
#[test(tokio::test)]
async fn test_canton_rejects_unauthenticated_requests() -> Result<()> {
    let sandbox = integration_tests::canton::CantonSandbox::run().await?;
    let http = reqwest::Client::new();
    let url = format!("{}/v2/state/ledger-end", sandbox.json_api_url);

    // No Authorization header at all.
    let status = http.get(&url).send().await?.status();
    assert_eq!(status, 401, "missing JWT should be rejected, got {status}");

    // Malformed Bearer token.
    let status = http
        .get(&url)
        .bearer_auth("not-a-valid-jwt")
        .send()
        .await?
        .status();
    assert_eq!(status, 401, "invalid JWT should be rejected, got {status}");

    Ok(())
}

#[ignore] // requires dpm + openssl
#[serial]
#[test(tokio::test)]
async fn test_canton_rejects_jwt_signed_by_unconfigured_key() -> Result<()> {
    use mpc_node::indexer_canton::generate_jwt_with_key;

    let sandbox = integration_tests::canton::CantonSandbox::run().await?;

    // Generate a fresh EC P-256 keypair NOT configured in Canton's auth-services.
    // Use genpkey (PKCS#8 output) instead of ecparam (SEC1 output) for jsonwebtoken compatibility.
    let tmp = std::env::temp_dir();
    let rogue_key_path = tmp.join(format!("rogue-jwt-{}.key", uuid::Uuid::new_v4()));
    let output = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-out",
            &rogue_key_path.to_string_lossy(),
        ])
        .output()
        .context("openssl not found")?;
    anyhow::ensure!(output.status.success(), "openssl genpkey failed");

    let rogue_pem = std::fs::read_to_string(&rogue_key_path)?;
    let _ = std::fs::remove_file(&rogue_key_path);

    let rogue_encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(rogue_pem.as_bytes())?;

    // Mint a structurally valid JWT with correct claims, but signed by the wrong key.
    let rogue_jwt = generate_jwt_with_key(&rogue_encoding_key, &sandbox.jwt_subject)?;

    // Canton should reject it — signature doesn't match any configured certificate.
    let http = reqwest::Client::new();
    let url = format!("{}/v2/state/ledger-end", sandbox.json_api_url);
    let status = http
        .get(&url)
        .bearer_auth(&rogue_jwt)
        .send()
        .await?
        .status();
    assert_eq!(
        status, 401,
        "JWT signed by unconfigured key should be rejected, got {status}"
    );

    Ok(())
}
