use anyhow::Context as _;
use integration_tests::cluster;
use k256::elliptic_curve::ops::Reduce;
use mpc_crypto::derive_key;
use mpc_crypto::kdf::{check_ec_signature, derive_epsilon_eth};
use mpc_crypto::{derive_epsilon_sol, derive_key, near_public_key_to_affine_point, ScalarExt as _};
use mpc_node::indexer_eth::EthConfig;
use mpc_node::util::NearPublicKeyExt;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use test_log::test;

const CONTRACT_ADDRESS: &str = "098Ed32aC23c75C5FB5b4Dc0C2BcF5F64ccd5E27";

#[test_log::test(tokio::test)]
async fn test_solana_signature_basic() -> anyhow::Result<()> {
    let cluster = cluster::spawn().solana().await?;
    let payload = [42u8; 32];
    let path = "test/integration/path";
    let key_version = 1; // LATEST_MPC_KEY_VERSION

    let outcome = cluster
        .sign()
        .solana()
        .payload(payload)
        .path(path)
        .key_version(key_version)
        .await?;

    let root_pk_near = cluster.root_public_key().await.unwrap();
    let root_pk = near_public_key_to_affine_point(root_pk_near);

    let epsilon = derive_epsilon_sol(key_version, &outcome.signer_account, path);
    let derived_user_pk = derive_key(root_pk, epsilon);
    let payload_hash = *alloy::primitives::keccak256(payload);
    let big_r = outcome.signature.big_r;
    let s = outcome.signature.s;
    let payload_hash = <k256::Scalar as Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes((&payload_hash).into());

    if check_ec_signature(&derived_user_pk, &big_r, &s, payload_hash, 0).is_ok()
        || check_ec_signature(&derived_user_pk, &big_r, &s, payload_hash, 1).is_ok()
    {
        return Ok(());
    }

    anyhow::bail!("signature verification failed");
}

#[test(tokio::test)]
async fn test_eth_signature_basic() -> anyhow::Result<()> {
    // TODO: move these over to cluster spawner
    let account_sk = std::env::var("IT_ETH_ACCOUNT_SK")
        .context("IT_ETH_ACCOUNT_SK not set")?
        .trim()
        .to_string();
    let consensus_rpc_http_url = std::env::var("IT_ETH_CONSENSUS_RPC_URL")
        .context("IT_ETH_CONSENSUS_RPC_URL not set")?
        .trim()
        .to_string();
    let execution_rpc_http_url = std::env::var("IT_ETH_EXECUTION_RPC_URL")
        .context("IT_ETH_EXECUTION_RPC_URL not set")?
        .trim()
        .to_string();
    let contract_address =
        std::env::var("IT_ETH_CONTRACT_ADDR").unwrap_or_else(|_e| CONTRACT_ADDRESS.to_string());

    let nodes = cluster::spawn()
        .with_config(|config| {
            config.eth = Some(EthConfig {
                account_sk,
                consensus_rpc_http_url,
                execution_rpc_http_url,
                contract_address,
                network: "sepolia".to_string(),
                helios_data_path: "/tmp/helios/sepolia_test".to_string(),
                refresh_finalized_interval: 30000,
                total_timeout: 600,
                optimistic_requests: true,
            });
        })
        .await?;

    tracing::info!("Executing ETH sign request");
    let test_algorithm = "ECDSA";
    let test_payload = [1u8; 32]; // Simple test payload
    let test_path = "ethereum,1"; // ETH derivation path
    let test_payload_hash =
        k256::Scalar::from_bytes(*alloy::primitives::keccak256(test_payload)).unwrap();
    let outcome = nodes
        .sign()
        .eth()
        .payload(test_payload)
        .path(test_path)
        .algorithm(test_algorithm)
        .parameters("{}")
        .deposit(1u64) // 1 ETH in wei
        .await;
    let Ok(outcome) = outcome else {
        anyhow::bail!("ETH sign request failed: {:?}", outcome.err());
    };

    tracing::info!(
        contract = format!("0x{CONTRACT_ADDRESS}"),
        eth_tx_hash = outcome.eth_tx_hash,
        payload = ?outcome.payload,
        payload_hash = ?outcome.payload_hash,
        "ETH sign request completed",
    );

    let mpc_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();
    let signer_addr = format!("0x{:x}", outcome.signer_address);
    let epsilon = derive_epsilon_eth(LATEST_MPC_KEY_VERSION, &signer_addr, test_path);
    let user_pk = derive_key(mpc_pk, epsilon);
    tracing::info!("derived user public key: {user_pk:?}");

    // Validate the signature by trying both recovery IDs
    let big_r = outcome.signature.big_r;
    let s = outcome.signature.s;

    let mut validation_passed = false;
    for recovery_id in 0..=1 {
        if check_ec_signature(&user_pk, &big_r, &s, test_payload_hash, recovery_id).is_ok() {
            tracing::info!("signature validation successful with recovery_id={recovery_id}",);
            validation_passed = true;
            break;
        }
    }

    if !validation_passed {
        anyhow::bail!("signature validation failed");
    } else {
        tracing::info!("signature validation completed");
        Ok(())
    }
}
