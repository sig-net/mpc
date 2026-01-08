use elliptic_curve::ops::Reduce;
use integration_tests::cluster;
use mpc_crypto::kdf::check_ec_signature;
use mpc_crypto::{derive_epsilon_hydration, derive_key, near_public_key_to_affine_point};
use test_log::test;

#[test(tokio::test)]
async fn test_hydration_signature_basic() -> anyhow::Result<()> {
    let cluster = cluster::spawn().hydration().await?;
    let payload = [42u8; 32];
    let path = "test/integration/path";
    let key_version = 0;

    let outcome = cluster
        .sign()
        .hydration()
        .payload(payload)
        .path(path)
        .key_version(key_version)
        .await?;

    let root_pk_near = cluster.root_public_key().await.unwrap();
    let root_pk = near_public_key_to_affine_point(root_pk_near);

    let sender_ss58 = outcome.sender_ss58.as_ref().ok_or_else(|| anyhow::anyhow!("missing sender_ss58"))?;
    let epsilon = derive_epsilon_hydration(key_version, sender_ss58, path);
    let derived_user_pk = derive_key(root_pk, epsilon);

    let payload_hash_bytes = outcome.payload_hash;
    let payload_hash = <k256::Scalar as Reduce<
        <k256::Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes((&payload_hash_bytes).into());
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
