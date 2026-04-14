use anyhow::{Context as _, Result};
use integration_tests::canton::{test_evm_params, CantonSandbox};
use mpc_node::backlog::Backlog;
use mpc_node::indexer_canton::ledger_api::{self, Event};
use mpc_node::indexer_canton::CantonStream;
use mpc_node::protocol::Chain;
use mpc_node::protocol::IndexedSignRequest;
use mpc_node::stream::ops::SignatureRespondedEvent;
use mpc_node::stream::{ChainEvent, ChainStream};
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde_json::json;
use serial_test::serial;
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

/// Submit a sign request by creating a SignRequest contract and exercising
/// Signer.SignBidirectional directly (no Vault). Updates sandbox.nonce_cid
/// with the fresh nonce for the next call.
async fn submit_canton_sign_request(sandbox: &mut CantonSandbox) -> Result<()> {
    let client = &sandbox.client;
    let evm_tx_params = serde_json::to_value(test_evm_params())?;

    let sign_request = client
        .create_contract(
            &[&sandbox.operator_party],
            "#daml-signer:Signer:SignRequest",
            json!({
                "operators": [&sandbox.operator_party],
                "requester": &sandbox.requester_party,
                "sigNetwork": &sandbox.party_id,
                "sender": "test-sender",
                "txParams": { "tag": "EvmTxParams", "value": evm_tx_params },
                "caip2Id": "eip155:11155111",
                "keyVersion": LATEST_MPC_KEY_VERSION,
                "path": &sandbox.requester_party,
                "algo": "ECDSA",
                "dest": "ethereum",
                "params": "",
                "nonceCidText": &sandbox.nonce_cid,
                "outputDeserializationSchema": r#"[{"name":"","type":"bool"}]"#,
                "respondSerializationSchema": r#"[{"name":"","type":"bool"}]"#,
            }),
        )
        .await?;
    let sign_request_cid =
        integration_tests::canton::find_created_contract(&sign_request, "SignRequest")?.0;
    let sign_request_disclosure = client
        .get_disclosed_contract(
            &[&sandbox.operator_party],
            "#daml-signer:Signer:SignRequest",
            &sign_request_cid,
        )
        .await?;

    let result = client
        .exercise_choice(
            &[&sandbox.requester_party],
            &sandbox.signer_template_id,
            &sandbox.signer_cid,
            "SignBidirectional",
            json!({
                "signRequestCid": sign_request_cid,
                "nonceCid": &sandbox.nonce_cid,
                "requester": &sandbox.requester_party,
            }),
            &[sandbox.signer_disclosure.clone(), sign_request_disclosure],
        )
        .await?;

    // Update nonce_cid from the fresh SigningNonce created by SignBidirectional
    for event in &result.transaction.events {
        if let Event::CreatedEvent(created) = event {
            if ledger_api::template_suffix_matches(&created.template_id, "SigningNonce") {
                sandbox.nonce_cid = created.contract_id.clone();
            }
        }
    }
    Ok(())
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
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_parse_sign_event() -> Result<()> {
    let mut sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    submit_canton_sign_request(&mut sandbox).await?;

    let event = wait_for_sign_request(&mut stream, 30).await?;

    assert_eq!(event.chain, Chain::Canton);
    assert_eq!(event.args.key_version, LATEST_MPC_KEY_VERSION);
    assert_eq!(event.args.path, sandbox.requester_party);
    assert!(
        matches!(
            event.kind,
            mpc_node::protocol::SignKind::SignBidirectional(_)
        ),
        "expected SignBidirectional, got {:?}",
        event.kind
    );
    assert_ne!(
        event.id.request_id, [0u8; 32],
        "request_id should not be zero"
    );
    Ok(())
}

#[ignore]
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_emits_blocks() -> Result<()> {
    let mut sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    // Submit a request to generate ledger activity
    submit_canton_sign_request(&mut sandbox).await?;

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
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_concurrent_events() -> Result<()> {
    let mut sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    // Submit 3 sign requests
    for _ in 0..3 {
        submit_canton_sign_request(&mut sandbox).await?;
    }

    // Collect SignRequest events until we have all 3, verifying content on each
    let mut received_ids = HashSet::new();
    for _ in 0..20 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::SignRequest(req))) => {
                assert_eq!(req.chain, Chain::Canton);
                assert_eq!(req.args.path, sandbox.requester_party);
                received_ids.insert(req.id.request_id);
                if received_ids.len() >= 3 {
                    break;
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("stream closed"),
            Err(_) => break,
        }
    }

    assert_eq!(received_ids.len(), 3, "expected 3 distinct sign requests");
    Ok(())
}

#[ignore]
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_catchup_linear() -> Result<()> {
    let mut sandbox = canton_sandbox().await?;

    // Phase 1: stream1 sees events
    let backlog1 = Backlog::new();
    let mut stream1 = stream_canton(&sandbox, backlog1).await?;

    submit_canton_sign_request(&mut sandbox).await?;

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

    submit_canton_sign_request(&mut sandbox).await?;

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
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_checkpoint_persistence() -> Result<()> {
    // Use interval=1 so every block produces a checkpoint. Canton generates
    // few blocks (only on ledger activity), so a larger interval risks timing out.
    const INTERVAL: u64 = 1;

    let mut sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog.clone()).await?;

    submit_canton_sign_request(&mut sandbox).await?;

    // Phase 1: process events, insert sign requests into backlog, wait for a
    // checkpoint that contains a pending request.
    let checkpoint = tokio::time::timeout(Duration::from_secs(30), async {
        let mut saw_sign_request = false;
        loop {
            let Some(event) = stream.next_event().await else {
                break None;
            };
            match event {
                ChainEvent::SignRequest(req) => {
                    saw_sign_request = true;
                    backlog.insert(req).await;
                }
                ChainEvent::Block(height) => {
                    if let Some(cp) = backlog
                        .set_processed_block_interval(Chain::Canton, height, INTERVAL)
                        .await
                    {
                        if saw_sign_request && !cp.pending_requests.is_empty() {
                            break Some(cp);
                        }
                    }
                }
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for checkpoint")
    .expect("stream ended without checkpoint");

    assert_eq!(
        checkpoint.pending_requests.len(),
        1,
        "expected one pending request in checkpoint"
    );
    drop(stream);

    // Phase 2: new stream with same backlog should resume from checkpoint
    let mut stream2 = stream_canton(&sandbox, backlog.clone()).await?;

    submit_canton_sign_request(&mut sandbox).await?;

    let mut saw_new_event = false;
    let mut saw_new_checkpoint = false;
    for _ in 0..20 {
        match timeout(Duration::from_secs(5), stream2.next_event()).await {
            Ok(Some(ChainEvent::SignRequest(req))) => {
                saw_new_event = true;
                backlog.insert(req).await;
                if saw_new_checkpoint {
                    break;
                }
            }
            Ok(Some(ChainEvent::Block(height))) => {
                if backlog
                    .set_processed_block_interval(Chain::Canton, height, INTERVAL)
                    .await
                    .is_some()
                {
                    saw_new_checkpoint = true;
                    if saw_new_event {
                        break;
                    }
                }
            }
            Ok(Some(_)) => continue,
            _ => break,
        }
    }

    assert!(saw_new_event, "new stream did not observe new event");
    assert!(
        saw_new_checkpoint,
        "new stream did not observe new checkpoint"
    );
    Ok(())
}

#[ignore]
#[serial]
#[test(tokio::test)]
async fn test_canton_stream_sign_and_respond_flow() -> Result<()> {
    let mut sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    // Submit a sign request, then use the MPC-computed request ID from the stream event
    submit_canton_sign_request(&mut sandbox).await?;
    let sign_event = wait_for_sign_request(&mut stream, 30).await?;
    assert_eq!(sign_event.chain, Chain::Canton);
    let request_id = hex::encode(sign_event.id.request_id);

    // Exercise Signer.Respond directly (no MPC cluster — we mock the response).
    // DER signature with valid secp256k1 scalars (r=1, s=1) — not cryptographically
    // meaningful but parseable by k256::ecdsa::Signature::from_der.
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
                "requestId": &request_id,
                "signature": "3006020101020101",
            }),
            &[],
        )
        .await?;

    // Poll for Respond event and verify fields match
    let mut saw_respond = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::Respond(SignatureRespondedEvent::Canton(ev)))) => {
                assert_eq!(hex::encode(ev.request_id), request_id);
                assert_eq!(ev.signature.s, k256::Scalar::from(1u64));
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

#[ignore] // requires dpm
#[serial]
#[test(tokio::test)]
async fn test_canton_rejects_unauthenticated_requests() -> Result<()> {
    let sandbox = canton_sandbox().await?;
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

    let sandbox = canton_sandbox().await?;

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
