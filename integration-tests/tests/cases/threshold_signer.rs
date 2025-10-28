//! Tests for the new ThresholdSigner trait integration.
//!
//! These tests use MpcFixture to exercise both ECDSA (via CaitSithAdapter)
//! and EdDSA (via NearThresholdSigner) threshold signing implementations.

// TODO: Update these tests to work with the new protocol factory API
// The current tests use the old ThresholdSigner API that has been redesigned.

use deadpool_redis::redis::AsyncCommands;
use integration_tests::mpc_fixture::MpcFixtureBuilder;
use mpc_node::protocol::SignRequestType;
use mpc_node::protocol::{Chain, IndexedSignRequest, ProtocolState};
use mpc_node::signing::{CurveType, ThresholdSigner};
use mpc_primitives::{LATEST_MPC_KEY_VERSION, SignArgs, SignId};
use std::time::Duration;
use threshold_ts::{CaitSithAdapter, NearThresholdSigner};

// Tests are temporarily disabled until updated for new protocol factory API

/// Test ECDSA threshold signing using CaitSithAdapter
#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_signer_ecdsa() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    // Wait for presignatures to be available
    tokio::time::timeout(
        Duration::from_millis(300),
        network.wait_for_presignatures(2),
    )
    .await
    .expect("should start with enough presignatures");

    // Create CaitSithAdapter for ECDSA signing
    let signer = CaitSithAdapter::new();

    // Generate a test key
    let participants = network.nodes.iter().map(|n| n.me).collect::<Vec<_>>();
    let me = network.nodes[0].me;
    let threshold = 2;

    let key_meta = signer
        .generate_key(&participants, me, threshold, CurveType::Ecdsa)
        .await
        .expect("should generate ECDSA key");

    // Create sign request
    let request = mpc_node::signing::SignRequest {
        key_id: key_meta.key_id.clone(),
        message: b"test message for ECDSA".to_vec(),
        chain: "eth".to_string(),
    };

    // Sign the message
    let result = signer.sign(request).await.expect("should sign with ECDSA");

    // Verify the signature
    let is_valid = signer
        .verify(
            &key_meta,
            b"test message for ECDSA",
            &result.signature,
            &result.metadata,
        )
        .await
        .expect("should verify ECDSA signature");

    assert!(is_valid, "ECDSA signature should be valid");
    assert_eq!(
        result.signature.len(),
        64,
        "ECDSA signature should be 64 bytes"
    );
}

/// Test EdDSA threshold signing using NearThresholdSigner
#[tokio::test(flavor = "multi_thread")]
async fn test_threshold_signer_eddsa() {
    let network = MpcFixtureBuilder::default()
        .only_generate_signatures()
        .build()
        .await;

    // Wait for presignatures to be available
    tokio::time::timeout(
        Duration::from_millis(300),
        network.wait_for_presignatures(2),
    )
    .await
    .expect("should start with enough presignatures");

    // Create NearThresholdSigner for EdDSA signing
    let signer = NearThresholdSigner::new();

    // Generate a test key
    let participants = network.nodes.iter().map(|n| n.me).collect::<Vec<_>>();
    let me = network.nodes[0].me;
    let threshold = 2;

    let key_meta = signer
        .generate_key(&participants, me, threshold, CurveType::Eddsa)
        .await
        .expect("should generate EdDSA key");

    // Create sign request
    let request = mpc_node::signing::SignRequest {
        key_id: key_meta.key_id.clone(),
        message: b"test message for EdDSA".to_vec(),
        chain: "near".to_string(),
    };

    // Sign the message
    let result = signer.sign(request).await.expect("should sign with EdDSA");

    // Verify the signature
    let is_valid = signer
        .verify(
            &key_meta,
            b"test message for EdDSA",
            &result.signature,
            &result.metadata,
        )
        .await
        .expect("should verify EdDSA signature");

    assert!(is_valid, "EdDSA signature should be valid");
    // EdDSA signatures are typically 64 bytes (32 bytes R + 32 bytes s)
    assert_eq!(
        result.signature.len(),
        64,
        "EdDSA signature should be 64 bytes"
    );
}

/// Test that CaitSithAdapter rejects EdDSA requests
#[tokio::test(flavor = "multi_thread")]
async fn test_cait_sith_adapter_rejects_eddsa() {
    let signer = CaitSithAdapter::new();
    let participants = vec![cait_sith::protocol::Participant::from(0u32)];
    let me = cait_sith::protocol::Participant::from(0u32);

    let result = signer
        .generate_key(&participants, me, 1, CurveType::Eddsa)
        .await;

    assert!(result.is_err(), "CaitSithAdapter should reject EdDSA");
    assert!(matches!(
        result.unwrap_err(),
        mpc_node::signing::SigningError::UnsupportedCurve(CurveType::Eddsa)
    ));
}
