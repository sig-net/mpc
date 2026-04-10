use anyhow::{Context as _, Result};
use integration_tests::canton::CantonSandbox;
use mpc_node::backlog::Backlog;
use mpc_node::indexer_canton::CantonStream;
use mpc_node::protocol::Chain;
use mpc_node::stream::{ChainEvent, ChainStream};
use mpc_node::protocol::IndexedSignRequest;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde_json::json;
use std::collections::HashSet;
use std::time::Duration;
use test_log::test;
use tokio::time::timeout;

/// Start a Canton sandbox with deployed contracts (no MPC cluster).
async fn canton_sandbox() -> Result<CantonSandbox> {
    CantonSandbox::run().await
}

/// Create a CantonStream from the sandbox config with an externally-provided Backlog.
/// Accepts Backlog as parameter (needed for checkpoint tests).
async fn stream_canton(sandbox: &CantonSandbox, backlog: Backlog) -> Result<CantonStream> {
    let config = sandbox.get_config();
    let mut stream =
        CantonStream::new(Some(config), backlog).context("failed to create CantonStream")?;
    ChainStream::start(&mut stream).await;
    Ok(stream)
}

/// Submit a sign request through the Vault contract.
/// Uses the nonce-based flow: RequestDeposit with pre-issued SigningNonce.
/// The Vault internally creates a SignRequest, exercises Signer.SignBidirectional
/// (which archives the nonce and creates SignBidirectionalEvent + new nonce).
/// Returns the requestId from the PendingDeposit event.
async fn submit_canton_sign_request(sandbox: &CantonSandbox) -> Result<String> {
    let client = &sandbox.client;
    let vault_template = "#daml-vault:Erc20Vault:Vault";

    // args[0] MUST match evmVaultAddress ("0".repeat(64)) — Daml asserts this
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

    // RequestDeposit — nonceCid is the pre-issued SigningNonce
    let deposit_result = client
        .exercise_choice(
            &[&sandbox.requester_party],
            vault_template,
            &sandbox.vault_cid,
            "RequestDeposit",
            json!({
                "requester": &sandbox.requester_party,
                "signerCid": &sandbox.signer_cid,
                "path": &sandbox.requester_party,
                "evmTxParams": evm_tx_params,
                "nonceCid": &sandbox.nonce_cid,
                "nonceCidText": &sandbox.nonce_cid,
                "keyVersion": LATEST_MPC_KEY_VERSION,
                "algo": "ECDSA",
                "dest": "ethereum",
                "params": "",
                "outputDeserializationSchema": r#"[{"name":"","type":"bool"}]"#,
                "respondSerializationSchema": r#"[{"name":"","type":"bool"}]"#,
            }),
            Some(&[
                sandbox.vault_disclosure.clone(),
                sandbox.signer_disclosure.clone(),
            ]),
        )
        .await?;

    // Extract requestId from PendingDeposit event
    let events = deposit_result["transaction"]["events"]
        .as_array()
        .context("no events")?;
    for event in events {
        if let Some(created) = event.get("CreatedEvent") {
            let tid = created["templateId"].as_str().unwrap_or("");
            if tid.contains("PendingDeposit") {
                let payload = created
                    .get("payload")
                    .or_else(|| created.get("createArgument"))
                    .context("no payload")?;
                return payload["requestId"]
                    .as_str()
                    .map(|s| s.to_string())
                    .context("no requestId");
            }
        }
    }
    anyhow::bail!("no PendingDeposit in RequestDeposit result")
}

/// Poll stream for a SignRequest event with timeout.
async fn wait_for_sign_request(
    stream: &mut CantonStream,
    timeout_secs: u64,
) -> Result<IndexedSignRequest> {
    timeout(Duration::from_secs(timeout_secs), async {
        loop {
            match stream.next_event().await {
                Some(ChainEvent::SignRequest(req)) => return Ok(req),
                Some(ChainEvent::Block(_)) => continue,
                Some(_) => continue,
                None => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .context("timeout waiting for SignRequest")?
}

#[ignore] // requires dpm
#[test(tokio::test)]
async fn test_canton_stream_parse_sign_event() -> Result<()> {
    let sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    let _request_id = submit_canton_sign_request(&sandbox).await?;

    let event = wait_for_sign_request(&mut stream, 30).await?;

    assert_eq!(event.chain, Chain::Canton);
    assert_eq!(event.args.key_version, LATEST_MPC_KEY_VERSION);
    // Canton only supports bidirectional — verify the kind
    assert!(
        matches!(
            event.kind,
            mpc_node::protocol::SignKind::SignBidirectional(_)
        ),
        "expected SignBidirectional, got {:?}",
        event.kind
    );
    Ok(())
}

#[ignore]
#[test(tokio::test)]
async fn test_canton_stream_emits_blocks() -> Result<()> {
    let sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    // Submit a request to generate ledger activity
    let _ = submit_canton_sign_request(&sandbox).await?;

    let mut saw_block = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::Block(_))) => {
                saw_block = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => {
                anyhow::bail!("stream returned None unexpectedly");
            }
            Err(_) => break, // timeout
        }
    }
    assert!(
        saw_block,
        "expected at least one Block event from Canton stream"
    );
    Ok(())
}

#[ignore]
#[test(tokio::test)]
async fn test_canton_stream_concurrent_events() -> Result<()> {
    let sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    // Submit 3 sign requests (each needs its own auth cycle)
    let mut expected_request_ids = HashSet::new();
    for _ in 0..3 {
        let rid = submit_canton_sign_request(&sandbox).await?;
        expected_request_ids.insert(rid);
    }

    // Collect SignRequest events until we have all 3
    let mut received = Vec::new();
    for _ in 0..20 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::SignRequest(req))) => {
                received.push(req);
                if received.len() >= 3 {
                    break;
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("stream closed"),
            Err(_) => break,
        }
    }

    assert_eq!(
        received.len(),
        3,
        "expected 3 SignRequest events, got {}",
        received.len()
    );

    // Verify received IDs are distinct (no duplicate replays)
    let received_ids: HashSet<_> = received
        .iter()
        .map(|r| hex::encode(r.id.request_id))
        .collect();
    assert_eq!(
        received_ids.len(),
        3,
        "expected 3 distinct request IDs, got {}",
        received_ids.len()
    );
    Ok(())
}

#[ignore]
#[test(tokio::test)]
async fn test_canton_stream_catchup_linear() -> Result<()> {
    let sandbox = canton_sandbox().await?;

    // Phase 1: stream1 sees events
    let backlog1 = Backlog::new();
    let mut stream1 = stream_canton(&sandbox, backlog1).await?;

    let _ = submit_canton_sign_request(&sandbox).await?;

    let mut seen_by_stream1 = 0;
    let mut last_block_stream1: u64 = 0;
    for _ in 0..10 {
        match timeout(Duration::from_millis(500), stream1.next_event()).await {
            Ok(Some(ChainEvent::SignRequest(_))) => seen_by_stream1 += 1,
            Ok(Some(ChainEvent::Block(b))) => {
                if b > last_block_stream1 {
                    last_block_stream1 = b;
                }
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert!(seen_by_stream1 > 0, "stream1 saw no events");
    assert!(last_block_stream1 > 0, "stream1 saw no blocks");

    // Drop stream1
    drop(stream1);

    // Phase 2: stream2 should catch up and see new events
    let backlog2 = Backlog::new();
    let mut stream2 = stream_canton(&sandbox, backlog2).await?;

    let _ = submit_canton_sign_request(&sandbox).await?;

    let mut caught_up = false;
    let mut seen_sign_events = false;
    for _ in 0..20 {
        match timeout(Duration::from_secs(1), stream2.next_event()).await {
            Ok(Some(ChainEvent::Block(b))) if b >= last_block_stream1 => caught_up = true,
            Ok(Some(ChainEvent::SignRequest(_))) => seen_sign_events = true,
            Ok(Some(_)) => {}
            _ => break,
        }
        if caught_up && seen_sign_events {
            break;
        }
    }
    assert!(
        caught_up,
        "stream2 did not catch up to stream1's block height"
    );
    assert!(seen_sign_events, "stream2 saw no SignRequest events");
    Ok(())
}

#[ignore]
#[test(tokio::test)]
async fn test_canton_stream_checkpoint_persistence() -> Result<()> {
    let sandbox = canton_sandbox().await?;

    // Phase 1: create stream, submit event, set a checkpoint on the first Block
    let backlog1 = Backlog::new();
    let mut stream1 = stream_canton(&sandbox, backlog1.clone()).await?;

    let _ = submit_canton_sign_request(&sandbox).await?;

    let mut checkpoint_block = None;
    for _ in 0..10 {
        match timeout(Duration::from_secs(1), stream1.next_event()).await {
            Ok(Some(ChainEvent::Block(block))) => {
                backlog1.set_processed_block(Chain::Canton, block).await;
                checkpoint_block = Some(block);
                break;
            }
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    assert!(checkpoint_block.is_some(), "no Block event to checkpoint");
    drop(stream1);

    // Phase 2: new stream should start from checkpoint and see new events
    let backlog2 = Backlog::new();
    let mut stream2 = stream_canton(&sandbox, backlog2).await?;

    let _ = submit_canton_sign_request(&sandbox).await?;

    let event = timeout(Duration::from_secs(10), async {
        loop {
            if let Some(ev) = stream2.next_event().await {
                return ev;
            }
        }
    })
    .await
    .context("timeout waiting for event on stream2")?;

    assert!(
        matches!(event, ChainEvent::SignRequest(_) | ChainEvent::Block(_)),
        "expected SignRequest or Block, got {:?}",
        event
    );
    Ok(())
}

#[ignore]
#[test(tokio::test)]
async fn test_canton_stream_sign_and_respond_flow() -> Result<()> {
    let sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    // Submit a sign request and capture the request ID
    let _request_id = submit_canton_sign_request(&sandbox).await?;

    // Wait for the SignRequest event from the stream
    let sign_event = wait_for_sign_request(&mut stream, 30).await?;
    assert_eq!(sign_event.chain, Chain::Canton);

    // Exercise Signer.Respond directly (no MPC cluster — we mock the response)
    // Use a dummy DER signature (valid ASN.1 structure but not cryptographically valid)
    let dummy_der_sig = "3045022100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02200000000000000000000000000000000000000000000000000000000000000001";

    sandbox
        .client
        .exercise_choice(
            &[&sandbox.party_id],
            &sandbox.signer_template_id,
            &sandbox.signer_cid,
            "Respond",
            json!({
                "operators": [&sandbox.operator_party],
                "requester": &sandbox.requester_party,
                "requestId": &_request_id,
                "signature": dummy_der_sig,
            }),
            None,
        )
        .await?;

    // Poll for Respond event from the stream
    let mut saw_respond = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::Respond(ev))) => {
                assert_eq!(ev.source_chain(), Chain::Canton);
                saw_respond = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("stream closed"),
            Err(_) => break,
        }
    }
    assert!(saw_respond, "expected Respond event from Canton stream");
    Ok(())
}
