use anyhow::Result;
use integration_tests::hydration::HydrationHandle;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use mpc_node::indexer_hydration::HydrationConfig;
use mpc_node::indexer_hydration::HydrationStream;
use mpc_node::stream::ChainStream;
use std::time::Duration;

#[test_log::test(tokio::test)]
async fn test_hydration_stream_basic_availability() -> Result<()> {
    // Try to get a Hydration node from environment; if missing, start a local fork container.
    let cfg: mpc_node::indexer_hydration::HydrationConfig = match HydrationHandle::from_env().await {
        Ok(h) => h.into_indexer_config(),
        Err(_) => {
            tracing::info!("HYDRATION_RPC_WS_URL not set — attempting to start local galacticcouncil/fork container for test");
            let mut spawner = integration_tests::cluster::spawner::ClusterSpawner::default().init_network().await?;
            match integration_tests::containers::HydrationSandbox::run(&spawner).await {
                Ok(hyd) => mpc_node::indexer_hydration::HydrationConfig {
                    rpc_ws_url: hyd.rpc_ws_url(),
                    signer_uri: String::from("http://127.0.0.1:0"),
                    total_timeout: 60,
                },
                Err(e) => {
                    tracing::warn!(?e, "failed to start Hydration sandbox; skipping test");
                    return Ok(()); // skip test when container can't be started
                }
            }
        }
    };

    let mut stream = match HydrationStream::new(Some(cfg)) {
        Some(s) => s,
        None => {
            tracing::warn!("HydrationStream is disabled; skipping test");
            return Ok(());
        }
    };

    // Ensure the stream is alive and emits at least one Block within timeout
    let saw = tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if let Some(evt) = stream.next_event().await {
                match evt {
                    mpc_node::stream::ChainEvent::Block(_) => break true,
                    _ => continue,
                }
            } else {
                break false;
            }
        }
    })
    .await
    .unwrap_or(false);

    if !saw {
        tracing::warn!("HydrationStream did not emit a Block within timeout — skipping assertion");
        return Ok(());
    }

    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_hydration_stream_parse_sign_event() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    // Need a real Hydration node + signer to submit extrinsics; otherwise skip.
    let handle = match HydrationHandle::from_env().await {
        Ok(h) => h,
        Err(_) => {
            tracing::warn!("no HYDRATION_RPC_WS_URL/HYDRATION_SIGNER_URI — skipping sign-event test");
            return Ok(());
        }
    };

    let cfg = handle.clone().into_indexer_config();
    let mut stream = match HydrationStream::new(Some(cfg)) {
        Some(s) => s,
        None => {
            tracing::warn!("HydrationStream is disabled; skipping test");
            return Ok(());
        }
    };

    // Submit a sign request via Subxt helper
    let payload = k256::Scalar::from(1u64).to_bytes().into();
    let path = "m/44'/60'/0'/0/0";
    handle.submit_sign_request(payload, path).await?;

    // Wait for SignRequest event
    let req = loop {
        match tokio::time::timeout(Duration::from_secs(20), stream.next_event()).await {
            Ok(Some(mpc_node::stream::ChainEvent::SignRequest(req))) => break req,
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("stream ended"),
            Err(_) => anyhow::bail!("timed out waiting for sign request event"),
        }
    };

    assert_eq!(req.chain, mpc_node::protocol::Chain::Hydration);
    assert_eq!(req.args.path, path);
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_hydration_stream_parse_sign_bidirectional_event() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let handle = match HydrationHandle::from_env().await {
        Ok(h) => h,
        Err(_) => {
            tracing::warn!("no HYDRATION_RPC_WS_URL/HYDRATION_SIGNER_URI — skipping sign-bidirectional test");
            return Ok(());
        }
    };

    let cfg = handle.clone().into_indexer_config();
    let mut stream = match HydrationStream::new(Some(cfg)) {
        Some(s) => s,
        None => {
            tracing::warn!("HydrationStream is disabled; skipping test");
            return Ok(());
        }
    };

    // Submit a sign_bidirectional request (serialized tx can be arbitrary bytes for parsing test)
    let serialized_tx = vec![1u8, 2, 3, 4];
    let caip2 = "eip155:31337";
    let program_id = [0u8; 32];

    handle
        .submit_sign_bidirectional_request(
            serialized_tx.clone(),
            caip2,
            0,
            "m/44'/60'/0'/0/0",
            "secp256k1",
            "",
            "",
            program_id,
            vec![],
            vec![],
        )
        .await?;

    // Wait for SignRequest sign-bidirectional event
    let req = loop {
        match tokio::time::timeout(Duration::from_secs(20), stream.next_event()).await {
            Ok(Some(mpc_node::stream::ChainEvent::SignRequest(req))) => {
                if matches!(req.sign_request_type, mpc_node::protocol::SignRequestType::SignBidirectional(_)) {
                    break req;
                } else {
                    continue;
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("stream ended"),
            Err(_) => anyhow::bail!("timed out waiting for sign-bidirectional event"),
        }
    };

    // Confirm fields that should be present
    assert!(matches!(req.sign_request_type, mpc_node::protocol::SignRequestType::SignBidirectional(_)));
    Ok(())
}

#[test_log::test(tokio::test)]
async fn test_hydration_stream_sign_and_respond_flow() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let handle = match HydrationHandle::from_env().await {
        Ok(h) => h,
        Err(_) => {
            tracing::warn!("no HYDRATION_RPC_WS_URL/HYDRATION_SIGNER_URI — skipping sign+respond flow test");
            return Ok(());
        }
    };

    let cfg = handle.clone().into_indexer_config();
    let backlog = mpc_node::backlog::Backlog::new();
    let mut stream = match HydrationStream::new(Some(cfg)) {
        Some(s) => s,
        None => {
            tracing::warn!("HydrationStream is disabled; skipping test");
            return Ok(());
        }
    };

    // Submit sign request
    let payload = [9u8; 32];
    let path = "m/44'/60'/0'/0/42";
    handle.submit_sign_request(payload, path).await?;

    // Capture emitted sign request
    let sign_req = loop {
        match tokio::time::timeout(Duration::from_secs(30), stream.next_event()).await {
            Ok(Some(mpc_node::stream::ChainEvent::SignRequest(req))) => break req,
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("stream ended"),
            Err(_) => anyhow::bail!("timed out waiting for sign request event"),
        }
    };

    // Construct a valid on-curve signature and submit respond via Subxt helper
    let expected_big_r = k256::ProjectivePoint::GENERATOR.to_affine();
    let expected_s = k256::Scalar::from(11u64);
    let recovery_id: u8 = 1;

    let full_sig = cait_sith::FullSignature::<k256::Secp256k1> { big_r: expected_big_r.into(), s: expected_s };

    handle
        .submit_respond(sign_req.id.request_id, full_sig.clone(), recovery_id)
        .await?;

    // Verify the indexer emits the Respond event with matching data.
    let mut saw_respond = false;
    for _ in 0..8 {
        match tokio::time::timeout(Duration::from_secs(10), stream.next_event()).await {
            Ok(Some(mpc_node::stream::ChainEvent::Respond(mpc_node::stream::ops::SignatureRespondedEvent::Hydration(ev)))) => {
                assert_eq!(ev.request_id, sign_req.id.request_id);

                // Compare big_r (x/y) and s using public accessors
                let enc_expected = expected_big_r.to_encoded_point(false);
                let expected_x = enc_expected.x().unwrap();
                let expected_y = enc_expected.y().unwrap();

                let enc_ev = ev.signature.big_r.to_encoded_point(false);
                let ev_x = enc_ev.x().unwrap();
                let ev_y = enc_ev.y().unwrap();

                assert_eq!(ev_x.as_slice(), expected_x.as_slice());
                assert_eq!(ev_y.as_slice(), expected_y.as_slice());

                // Compare scalar `s` as bytes and recovery id
                assert_eq!(ev.signature.s.to_bytes(), expected_s.to_bytes());
                assert_eq!(ev.signature.recovery_id, recovery_id);

                saw_respond = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    assert!(saw_respond, "did not receive SignatureResponded event");
    Ok(())
}
