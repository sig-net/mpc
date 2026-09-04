use elliptic_curve::ops::Reduce;
use integration_tests::cluster;
use mpc_crypto::kdf::check_ec_signature;
use mpc_crypto::{derive_epsilon_sol, derive_key, near_public_key_to_affine_point};
use test_log::test;

#[test(tokio::test)]
async fn test_solana_signature_basic() -> anyhow::Result<()> {
    let cluster = cluster::spawn().solana().await?;
    let payload = [42u8; 32];
    let path = "test/integration/path";
    let key_version = 0;

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
    let payload_hash = <k256::Scalar as Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes((&payload_hash).into());
    let big_r = outcome.signature.big_r;
    let s = outcome.signature.s;
    let signature_valid = [0u8, 1u8].into_iter().any(|recovery_id| {
        check_ec_signature(&derived_user_pk, &big_r, &s, payload_hash, recovery_id).is_ok()
    });

    if signature_valid {
        Ok(())
    } else {
        anyhow::bail!("signature verification failed");
    }
}
