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

// Concurrent variant: spawn many sign requests at once against a very small
// presignature stockpile and assert we make forward progress (no livelock).
#[test(tokio::test)]
async fn test_solana_stockpile_depletion_concurrent() -> anyhow::Result<()> {
    let cluster = cluster::spawn()
        .solana()
        .with_config(|conf| {
            // tiny presignature stock so contention is probable
            conf.protocol.presignature.min_presignatures = 2;
            conf.protocol.presignature.max_presignatures = 4;
        })
        .await?;

    // spawn many concurrent requests and assert each completes within a
    // reasonable timeout. This catches stuck/livelock cases deterministically
    // and fast because the concurrent pressure increases contention.
    let concurrent = 30;
    let mut futs = Vec::with_capacity(concurrent);
    for _ in 0..concurrent {
        // don't spawn new tasks at thread boundary; keep futures local so borrows are simple
        futs.push(tokio::time::timeout(
            std::time::Duration::from_secs(10),
            async {
                cluster
                    .sign()
                    .solana()
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            },
        ));
    }

    // wait for all futures to complete and ensure none timed out or errored
    let all = futures::future::join_all(futs).await;
    for r in all {
        match r {
            Ok(inner) => inner.map(|_| ())?,
            Err(_) => anyhow::bail!("timed out waiting for sign request"),
        }
    }

    Ok(())
}
