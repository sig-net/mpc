use anyhow::{Context as _, Result};
use integration_tests::cluster;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde_json::json;
use std::time::Duration;
use test_log::test;

#[ignore] // requires dpm + openssl + Docker (for Ethereum)
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
    let _eth_ctx = nodes
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum not available")?;

    // 3. Submit sign request via Vault (nonce-based flow)
    let client = &canton.client;
    let vault_template = "#daml-vault:Erc20Vault:Vault";

    let evm_tx_params = json!({
        "to": "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "functionSignature": "transfer(address,uint256)",
        "args": [
            "0".repeat(64),
            "0000000000000000000000000000000000000000000000000000000005f5e100"
        ],
        "value": "0".repeat(64),
        "nonce": format!("{:0>64}", "1"),
        "gasLimit": format!("{:0>64}", "186a0"),
        "maxFeePerGas": format!("{:0>64}", "3b9aca00"),
        "maxPriorityFee": format!("{:0>64}", "3b9aca00"),
        "chainId": format!("{:0>64}", "aa36a7"),
    });

    let deposit_result = client
        .exercise_choice(
            &[&canton.requester_party],
            vault_template,
            &canton.vault_cid,
            "RequestDeposit",
            json!({
                "requester": &canton.requester_party,
                "signerCid": &canton.signer_cid,
                "path": &canton.requester_party,
                "evmTxParams": evm_tx_params,
                "nonceCid": &canton.nonce_cid,
                "nonceCidText": &canton.nonce_cid,
                "keyVersion": LATEST_MPC_KEY_VERSION,
                "algo": "ECDSA",
                "dest": "ethereum",
                "params": "",
                "outputDeserializationSchema": r#"[{"name":"","type":"bool"}]"#,
                "respondSerializationSchema": r#"[{"name":"","type":"bool"}]"#,
            }),
            Some(&[
                canton.vault_disclosure.clone(),
                canton.signer_disclosure.clone(),
            ]),
        )
        .await?;

    // 4. Extract requestId from PendingDeposit
    let events = deposit_result["transaction"]["events"]
        .as_array()
        .context("no events")?;
    let mut request_id = String::new();
    for event in events {
        if let Some(created) = event.get("CreatedEvent") {
            if created["templateId"]
                .as_str()
                .unwrap_or("")
                .contains("PendingDeposit")
            {
                let payload = created
                    .get("payload")
                    .or_else(|| created.get("createArgument"))
                    .context("no payload")?;
                request_id = payload["requestId"]
                    .as_str()
                    .context("no requestId")?
                    .to_string();
                break;
            }
        }
    }
    anyhow::ensure!(
        !request_id.is_empty(),
        "no requestId found in deposit result"
    );
    tracing::info!(%request_id, "canton deposit request submitted");

    // 5. Poll for SignatureRespondedEvent matching the requestId
    let sig_event = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:SignatureRespondedEvent",
            |payload| payload["requestId"].as_str() == Some(&request_id),
            Duration::from_secs(120),
        )
        .await
        .context("timeout waiting for SignatureRespondedEvent")?;

    tracing::info!("received SignatureRespondedEvent");

    // 6. Verify the signature exists
    let sig_payload = sig_event["createdEvent"]
        .get("payload")
        .or_else(|| sig_event["createdEvent"].get("createArgument"))
        .context("no payload in SignatureRespondedEvent")?;
    let signature_hex = sig_payload["signature"]
        .as_str()
        .context("missing signature field")?;
    assert!(!signature_hex.is_empty(), "signature is empty");

    // 7. Poll for RespondBidirectionalEvent (MPC posted the outcome)
    let respond_event = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:RespondBidirectionalEvent",
            |payload| payload["requestId"].as_str() == Some(&request_id),
            Duration::from_secs(120),
        )
        .await
        .context("timeout waiting for RespondBidirectionalEvent")?;

    tracing::info!("received RespondBidirectionalEvent");

    // 8. Verify the respond event has the same requestId
    let respond_payload = respond_event["createdEvent"]
        .get("payload")
        .or_else(|| respond_event["createdEvent"].get("createArgument"))
        .context("no payload in RespondBidirectionalEvent")?;
    assert_eq!(
        respond_payload["requestId"].as_str(),
        Some(request_id.as_str()),
        "RespondBidirectionalEvent requestId mismatch"
    );

    // Verify the respond event has serializedOutput
    assert!(
        respond_payload.get("serializedOutput").is_some(),
        "RespondBidirectionalEvent missing serializedOutput"
    );

    tracing::info!("Canton bidirectional flow completed successfully");
    Ok(())
}
