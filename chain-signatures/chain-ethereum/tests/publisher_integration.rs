#![cfg(feature = "integration")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::B256;
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

#[tokio::test]
async fn publishes_across_multiple_batches() {
    let env = EthTestEnv::new().await.expect("anvil env");

    // Submit 6 distinct sign requests.
    let mut request_ids = Vec::new();
    for seed in 1..=6 {
        request_ids.push(
            submit_sign_request(&env.contract(), seed)
                .await
                .expect("submit sign request"),
        );
    }

    // max_batch_size of 3 with a long flush window
    let mut cfg = env.eth_config.clone();
    cfg.publisher.max_batch_size = 3;
    cfg.publisher.batch_flush_interval = Duration::from_millis(2000);
    let client = EthClient::new(&cfg, Arc::new(NoopPublisherTelemetry));

    for rid in &request_ids {
        let action =
            make_publish_action(Chain::Ethereum, SignKind::Sign, SignId::new((*rid).into()));
        client
            .publish_signature(&action)
            .await
            .expect("publish_signature");
    }

    // All 6 must be responded, grouped into exactly 2 batched transactions of 3
    let mut by_tx: HashMap<B256, Vec<B256>> = HashMap::new();
    for rid in &request_ids {
        let (responder, tx_hash) = wait_for_responded(&env, *rid, Duration::from_secs(10))
            .await
            .expect("SignatureResponded observed");
        assert_eq!(responder, env.signer.address());
        by_tx.entry(tx_hash).or_default().push(*rid);
    }
    assert_eq!(
        by_tx.len(),
        2,
        "expected exactly 2 batched respond txs, got {by_tx:?}"
    );
    for (tx, rids) in &by_tx {
        assert_eq!(
            rids.len(),
            3,
            "batch {tx:?} should carry 3 responses, got {}",
            rids.len()
        );
    }
}
