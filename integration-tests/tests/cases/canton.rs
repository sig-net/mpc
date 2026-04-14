use alloy::consensus::transaction::SignableTransaction;
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{FixedBytes, Signature, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context as _, Result};
use integration_tests::canton::test_evm_params;
use integration_tests::cluster;
use mpc_node::indexer_canton::contracts::{
    RespondBidirectionalEventPayload, SignBidirectionalRequestedEvent,
    SignatureRespondedEventPayload, TxParams,
};
use mpc_node::indexer_canton::{compute_request_id, parse_der_signature, to_tx_eip1559};
use mpc_node::sign_bidirectional::{derive_user_address, resolve_signature_recovery_id};
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

    let evm_params = test_evm_params();

    // Build event struct to compute expected requestId
    let expected_event = SignBidirectionalRequestedEvent {
        operators: vec![canton.operator_party.clone()],
        requester: canton.requester_party.clone(),
        sig_network: canton.party_id.clone(),
        sender: "test-sender".to_string(),
        tx_params: TxParams::EvmTxParams(evm_params.clone()),
        caip2_id: "eip155:31337".to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        path: canton.requester_party.clone(),
        algo: "ECDSA".to_string(),
        dest: "ethereum".to_string(),
        params: String::new(),
        nonce_cid_text: canton.nonce_cid.clone(),
        output_deserialization_schema: r#"[{"name":"","type":"bool"}]"#.to_string(),
        respond_serialization_schema: r#"[{"name":"","type":"bool"}]"#.to_string(),
    };
    let expected_request_id = hex::encode(compute_request_id(&expected_event));

    // 3. Submit sign request directly via Signer (bypasses Vault)
    let sign_request = client
        .create_contract(
            &[&canton.operator_party],
            "#daml-signer:Signer:SignRequest",
            serde_json::to_value(&expected_event)?,
        )
        .await?;
    let (sign_request_cid, sign_request_template_id) =
        integration_tests::canton::find_created_contract(&sign_request, "SignRequest")?;

    let sign_request_disclosure = client
        .get_disclosed_contract(
            &[&canton.operator_party],
            &sign_request_template_id,
            &sign_request_cid,
        )
        .await?;

    client
        .exercise_choice(
            &[&canton.requester_party],
            &canton.signer_template_id,
            &canton.signer_cid,
            "SignBidirectional",
            json!({
                "signRequestCid": sign_request_cid,
                "nonceCid": &canton.nonce_cid,
                "requester": &canton.requester_party,
            }),
            &[canton.signer_disclosure.clone(), sign_request_disclosure],
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

    // Fetch root public key once for both Phase 1 and Phase 2 derivations.
    let root_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();

    // 5. Relay the signed EVM transaction to Anvil
    let eth_ctx = nodes
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum not available")?;
    let anvil_rpc_url = &eth_ctx.sandbox.external_http_endpoint;

    // Create alloy provider for Anvil interactions
    let anvil = ProviderBuilder::new().connect_http(anvil_rpc_url.parse()?);

    // Parse DER signature using existing utility
    let mpc_signature = parse_der_signature(&sig_payload.signature)?;

    // Build unsigned transaction using existing utility
    let unsigned_tx = to_tx_eip1559(&evm_params)?;
    let mut unsigned_rlp = Vec::new();
    unsigned_tx.encode_for_signing(&mut unsigned_rlp);

    // Derive the expected sender address using existing utility
    let epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        "test-sender",
        &canton.requester_party,
    );
    let derived_pk = mpc_crypto::derive_key(root_pk, epsilon);
    let expected_sender_addr = derive_user_address(root_pk, epsilon);

    // Resolve correct recovery ID using existing utility
    let signature_with_recovery =
        resolve_signature_recovery_id(&unsigned_rlp, mpc_signature, &derived_pk)?;
    let y_parity = signature_with_recovery.recovery_id == 1;

    // Extract r and s for alloy Signature
    let r_bytes: [u8; 32] = mpc_crypto::x_coordinate(&signature_with_recovery.big_r)
        .to_bytes()
        .into();
    let s_bytes: [u8; 32] = signature_with_recovery.s.to_bytes().into();

    // Fund sender with 10 ETH via Anvil API
    anvil
        .anvil_set_balance(expected_sender_addr, U256::from(10_000_000_000_000_000_000u128))
        .await?;

    // Build signed EIP-1559 transaction
    let sig = Signature::from_scalars_and_parity(
        FixedBytes::from_slice(&r_bytes),
        FixedBytes::from_slice(&s_bytes),
        y_parity,
    );
    let signed_tx = unsigned_tx.into_signed(sig);
    let signed_bytes = signed_tx.encoded_2718();

    // Send raw transaction via provider
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

    // 7. Verify the Phase 2 response signature against the MPC-derived public key
    let respond_signature = parse_der_signature(&respond_payload.signature)?;

    let request_id_bytes = hex::decode(&respond_payload.request_id)?;
    let serialized_output_bytes = hex::decode(&respond_payload.serialized_output)?;
    let response_hash = mpc_node::respond_bidirectional::calculate_respond_bidirectional_hash_message(
        &request_id_bytes,
        &serialized_output_bytes,
    );

    // Derive the expected Canton public key for Phase 2 response signing.
    let epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        "test-sender",
        "canton response key",
    );
    let phase2_derived_pk = mpc_crypto::derive_key(root_pk, epsilon);

    // Convert MPC signature to k256 ecdsa signature for verification
    let respond_ecdsa = k256::ecdsa::Signature::from_scalars(
        mpc_crypto::x_coordinate(&respond_signature.big_r),
        respond_signature.s,
    )
    .context("invalid signature scalars")?;

    // Verify the signature against the derived public key
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let verifying_key = k256::ecdsa::VerifyingKey::from_affine(phase2_derived_pk)
        .map_err(|e| anyhow::anyhow!("invalid derived public key: {e}"))?;
    verifying_key
        .verify_prehash(&response_hash, &respond_ecdsa)
        .map_err(|e| anyhow::anyhow!("RespondBidirectional signature verification failed: {e}"))?;
    tracing::info!("phase 2 signature verified");

    block_pumper.abort();
    Ok(())
}
