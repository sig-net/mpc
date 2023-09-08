use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

use mpc_recovery_integration_tests::util::add_pk_and_check_validity;
use mpc_recovery_integration_tests::util::fetch_recovery_pk;
use mpc_recovery_integration_tests::util::new_random_account;
use mpc_recovery_integration_tests::with_nodes;

fn benching(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("basic_action");
    group.sample_size(10);
    group.bench_function("_1", |b| b.to_async(&rt).iter(basic_action));
    // c.bench_function(
    //     "basic_action",
    //     BenchmarkId::new("_1", |b| b.iter(basic_action).sample_size(10)),
    // );
    // c.sample_size(10).bench_function("basic_action", |b| {
    //     // Insert a call to `to_async` to convert the bencher to async mode.
    //     // The timing loops are the same as with the normal bencher.
    //     b.to_async(&rt).iter(basic_action);
    // });
}

async fn basic_action() {
    with_nodes(3, |ctx| {
        Box::pin(async move {
            let (account_id, user_secret_key, oidc_token) = new_random_account(&ctx, None).await?;

            // Add key
            let recovery_pk = fetch_recovery_pk(&ctx, &user_secret_key, &oidc_token).await?;
            let new_user_public_key = add_pk_and_check_validity(
                &ctx,
                &account_id,
                &user_secret_key,
                &oidc_token,
                &recovery_pk,
                None,
            )
            .await?;

            // Adding the same key should now fail
            add_pk_and_check_validity(
                &ctx,
                &account_id,
                &user_secret_key,
                &oidc_token,
                &recovery_pk,
                Some(new_user_public_key),
            )
            .await?;

            Ok(())
        })
    })
    .await
    .unwrap();
}

criterion_group!(benches, benching);
criterion_main!(benches);
