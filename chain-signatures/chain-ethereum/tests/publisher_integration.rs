#![cfg(feature = "integration")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{submit_sign_request, wait_for_responded, EthTestEnv};
use mpc_chain_ethereum::publisher::EthClient;
use mpc_chain_integration_core::utils::test::make_publish_action;
use mpc_chain_integration_core::{ChainPublisher, NoopPublisherTelemetry};
use mpc_primitives::{Chain, SignId, SignKind};

#[tokio::test]
async fn publishes_single_response() {
    let env = EthTestEnv::new().await.expect("anvil env");

    let request_id = submit_sign_request(&env.contract(), 7)
        .await
        .expect("submit sign request");

    let action = make_publish_action(
        Chain::Ethereum,
        SignKind::Sign,
        SignId::new(request_id.into()),
    );

    let client = EthClient::new(&env.eth_config, Arc::new(NoopPublisherTelemetry));
    client
        .publish_signature(&action)
        .await
        .expect("publish_signature");

    let (responder, _tx_hash) = wait_for_responded(&env, request_id, Duration::from_secs(5))
        .await
        .expect("SignatureResponded observed");
    assert_eq!(responder, env.signer.address());
}

#[tokio::test]
async fn publishes_batched_responses() {
    let env = EthTestEnv::new().await.expect("anvil env");

    // Submit 3 sign requests.
    let mut request_ids = Vec::new();
    for seed in 1..=3 {
        request_ids.push(
            submit_sign_request(&env.contract(), seed)
                .await
                .expect("submit sign request"),
        );
    }

    // Widen the flush window so all 3 actions accumulate before the batch fires
    let mut cfg = env.eth_config.clone();
    cfg.publisher.batch_flush_interval = Duration::from_millis(1000);
    let client = EthClient::new(&cfg, Arc::new(NoopPublisherTelemetry));

    // Publish all 3 responses.
    for rid in &request_ids {
        let action =
            make_publish_action(Chain::Ethereum, SignKind::Sign, SignId::new((*rid).into()));
        client
            .publish_signature(&action)
            .await
            .expect("publish_signature");
    }

    // All 3 must land in a single batched `respond` transaction.
    let mut tx_hashes = Vec::with_capacity(request_ids.len());
    for rid in &request_ids {
        let (responder, tx_hash) = wait_for_responded(&env, *rid, Duration::from_secs(5))
            .await
            .expect("SignatureResponded observed");
        assert_eq!(responder, env.signer.address());
        tx_hashes.push(tx_hash);
    }
    assert!(
        tx_hashes.iter().all(|h| *h == tx_hashes[0]),
        "all 3 responses should share one transaction hash, got {tx_hashes:?}"
    );
}
