use integration_tests::cluster;

#[test_log::test(tokio::test)]
async fn test_solana_signature_basic() {
    let cluster = cluster::spawn().solana().await.unwrap();
    let _outcome = cluster
        .sign()
        .solana()
        .payload([42u8; 32])
        .path("test/integration/path")
        .await
        .unwrap();
}
