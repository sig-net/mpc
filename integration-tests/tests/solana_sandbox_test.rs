use integration_tests::cluster;

#[test_log::test(tokio::test)]
async fn test_solana_sandbox() {
    let solana = cluster::spawn().spawn_solana().await;
    solana.deploy_contract().await.unwrap();
    solana.sign().await;
}
