use integration_tests::cluster;

#[test_log::test(tokio::test)]
async fn test_solana_signature_basic() {
    let cluster = cluster::spawn().sol().await.unwrap();
    let _outcome = cluster
        .sign()
        .sol()
        .payload([42u8; 32])
        .path("test/integration/path")
        .await
        .unwrap();
}
