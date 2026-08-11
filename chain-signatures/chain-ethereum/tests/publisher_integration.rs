#![cfg(feature = "integration")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::U256;
use alloy::providers::Provider;
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

    let responder = wait_for_responded(&env, request_id, Duration::from_secs(5))
        .await
        .expect("SignatureResponded observed");
    assert_eq!(responder, env.signer.address());
}
