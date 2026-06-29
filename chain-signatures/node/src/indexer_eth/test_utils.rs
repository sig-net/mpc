use super::{EthConfig, EthereumClient};
use mpc_indexer_core::utils::retry::RetryConfig;
use std::time::Duration;

/// Creates a test Ethereum client with a small retry strategy for testing purposes.
pub async fn create_test_ethereum_client(url: &str) -> EthereumClient {
    // Use a small retry strategy for testing to avoid long delays
    let retry_strategy = RetryConfig {
        min_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(10),
        max_times: 2,
        jitter: false,
    };

    let eth = EthConfig {
        execution_rpc_http_url: url.to_string(),
        light_client: false,
        account_sk: "".to_string(),
        consensus_rpc_http_url: "".to_string(),
        contract_address: "".to_string(),
        network: "".to_string(),
        helios_data_path: "".to_string(),
        refresh_finalized_interval: 0,
        optimistic_requests: false,
    };

    EthereumClient::new_with_strategy(eth, retry_strategy)
        .await
        .unwrap()
}

pub fn block_response(request_id: u64, number: u64) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "number": format!("0x{number:x}"),
            "hash": format!("0x{:064x}", number),
            "parentHash": format!("0x{:064x}", number.saturating_sub(1)),
            "sha3Uncles": format!("0x{:064x}", 1),
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "transactionsRoot": format!("0x{:064x}", 2),
            "stateRoot": format!("0x{:064x}", 3),
            "receiptsRoot": format!("0x{:064x}", 4),
            "miner": format!("0x{:040x}", 5),
            "difficulty": "0x0",
            "totalDifficulty": "0x0",
            "extraData": "0x",
            "size": "0x1",
            "gasLimit": "0x1c9c380",
            "gasUsed": "0x0",
            "timestamp": "0x1",
            "uncles": [],
            "nonce": "0x0000000000000000",
            "mixHash": format!("0x{:064x}", 9),
            "baseFeePerGas": "0x1",
            "transactions": []
        }
    })
}
