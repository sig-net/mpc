use crate::client::{CatchupItem, EthereumClient};
use crate::indexer::EthereumIndexer;
use crate::EthConfig;
use alloy::primitives::{Address, Bloom};
use alloy::rpc::types::{Block, Log};
use mpc_chain_integration_core::utils::retry::RetryConfig;
use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Default refresh interval (ms) used by `IndexerBuilder` unless overridden.
const DEFAULT_REFRESH_FINALIZED_INTERVAL: u64 = 100;

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

/// Builder for constructing an `EthereumIndexer<MockStateManager, NoopChainTelemetry>`
/// in tests against a mockito server.
///
/// Use [`TestIndexerBuilder::build()`] when you don't need the event receiver, or [`TestIndexerBuilder::build_with_rx()`] when
/// you do.
pub struct TestIndexerBuilder {
    server_url: String,
    pub eth: EthConfig,
    pub state_manager: MockStateManager,
    optimistic_requests: bool,
}

impl TestIndexerBuilder {
    /// Create a builder wired to a mockito server, with field defaults
    pub fn new(server_url: impl Into<String>) -> Self {
        let server_url = server_url.into();
        Self {
            server_url: server_url.clone(),
            eth: EthConfig {
                account_sk: String::new(),
                consensus_rpc_http_url: server_url.clone(),
                execution_rpc_http_url: server_url.clone(),
                contract_address: format!("{:x}", Address::ZERO),
                network: "sepolia".to_string(),
                helios_data_path: "/tmp/helios-test".to_string(),
                refresh_finalized_interval: DEFAULT_REFRESH_FINALIZED_INTERVAL,
                optimistic_requests: true,
                light_client: false,
            },
            state_manager: MockStateManager::new(),
            optimistic_requests: true,
        }
    }

    /// Override `eth.execution_rpc_http_url` (and the URL used to build the
    /// `EthereumClient`)
    pub fn client_url(mut self, url: impl Into<String>) -> Self {
        let url = url.into();
        self.eth.execution_rpc_http_url = url.clone();
        self.server_url = url;
        self
    }

    /// Override both RPC URLs (e.g. empty strings) — only changes config, not
    /// the client build URL.
    pub fn rpc_urls(mut self, consensus: impl Into<String>, execution: impl Into<String>) -> Self {
        self.eth.consensus_rpc_http_url = consensus.into();
        self.eth.execution_rpc_http_url = execution.into();
        self
    }

    /// Override `eth.optimistic_requests`
    pub fn optimistic_requests(mut self, v: bool) -> Self {
        self.optimistic_requests = v;
        self.eth.optimistic_requests = v;
        self
    }

    /// Override `eth.refresh_finalized_interval`
    pub fn refresh_finalized_interval(mut self, ms: u64) -> Self {
        self.eth.refresh_finalized_interval = ms;
        self
    }

    async fn build_inner(self) -> EthereumIndexer<MockStateManager, NoopChainTelemetry> {
        let client = Arc::new(create_test_ethereum_client(&self.server_url).await);
        let (events_tx, events_rx) = mpsc::channel::<mpc_primitives::ChainEvent>(1);
        // events_rx is dropped by `.build()`; returned by `.build_with_rx()`.
        let _ = events_rx;
        EthereumIndexer::new_for_test(
            self.eth,
            self.state_manager,
            NoopChainTelemetry,
            client,
            events_tx,
            Address::ZERO,
        )
    }

    /// Build the indexer without exposing its event receiver. The receiver
    /// is dropped.
    pub async fn build(self) -> EthereumIndexer<MockStateManager, NoopChainTelemetry> {
        self.build_inner().await
    }

    /// Build the indexer and return it together with a receiver for the events
    /// channel wired into it.
    pub async fn build_with_rx(
        self,
    ) -> (
        EthereumIndexer<MockStateManager, NoopChainTelemetry>,
        mpsc::Receiver<mpc_primitives::ChainEvent>,
    ) {
        let client = Arc::new(create_test_ethereum_client(&self.server_url).await);
        let (events_tx, events_rx) = mpsc::channel::<mpc_primitives::ChainEvent>(1);
        let indexer = EthereumIndexer::new_for_test(
            self.eth,
            self.state_manager,
            NoopChainTelemetry,
            client,
            events_tx,
            Address::ZERO,
        );
        (indexer, events_rx)
    }
}

pub fn missing_block_response(request_id: u64) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "result": null
    })
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

/// Build a deserialized `Block` for a given block `number`, suitable for
/// feeding directly into `process_catchup` / `process` as `CatchupItem::LiveBlock`.
/// The hash is `0x{number:064x}` and the timestamp is `0x1`.
pub fn live_block(number: u64) -> CatchupItem {
    let value = block_response(1, number)
        .get("result")
        .expect("block_response has a result envelope")
        .clone();
    let block: Block = serde_json::from_value(value).expect("block fixture should deserialize");
    CatchupItem::LiveBlock(block)
}

pub fn batch_block(number: u64, logs: Vec<Log>) -> CatchupItem {
    let value = block_response(1, number)
        .get("result")
        .expect("block_response has a result envelope")
        .clone();
    let block: Block = serde_json::from_value(value).expect("block fixture should deserialize");
    CatchupItem::BatchBlock { block, logs }
}

/// Build a `Bloom` marked as potentially containing logs from `address`.
pub fn bloom_containing_address(address: Address) -> Bloom {
    let mut bloom = Bloom::default();
    bloom.accrue_raw_log(address, &[]);
    bloom
}

fn bloom_hex(bloom: &Bloom) -> String {
    use alloy::primitives::hex::encode;
    format!("0x{}", encode(bloom.as_slice()))
}

/// Like [`block_response`] but with the `logsBloom` set to a bloom that
/// marks `address` as potentially present.
pub fn block_response_with_bloom(request_id: u64, number: u64, bloom: &Bloom) -> serde_json::Value {
    let mut value = block_response(request_id, number);
    value
        .get_mut("result")
        .expect("block_response has a result envelope")
        .as_object_mut()
        .expect("result is an object")
        .insert(
            "logsBloom".to_string(),
            serde_json::Value::String(bloom_hex(bloom)),
        );
    value
}

/// A minimal `eth_getLogs` result entry for `address` in `block_number`,
/// suitable for `eth_getLogs` batch responses consumed by `get_logs_batch`.
pub fn log_value(address: Address, block_number: u64, log_index: u64) -> serde_json::Value {
    let block_hash = format!("0x{:064x}", block_number);
    let tx_hash = format!("0x{:064x}", block_number);
    serde_json::json!({
        "logIndex": format!("0x{log_index:x}"),
        "blockNumber": format!("0x{block_number:x}"),
        "blockHash": block_hash,
        "transactionHash": tx_hash,
        "transactionIndex": "0x0",
        "address": format!("{:#x}", address),
        "topics": [],
        "data": "0x",
    })
}

/// Build a JSON array of `eth_getLogs` batch responses (one per input
/// `(request_id, logs)` pair)
pub fn logs_batch_response(ids_and_logs: &[(u64, Vec<serde_json::Value>)]) -> serde_json::Value {
    let items: Vec<serde_json::Value> = ids_and_logs
        .iter()
        .map(|(id, logs)| {
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": logs,
            })
        })
        .collect();
    serde_json::Value::Array(items)
}

pub fn receipt_value(tx_hash: &str, block_number: u64) -> serde_json::Value {
    serde_json::json!({
        "transactionHash": tx_hash,
        "blockHash": format!("0x{:064x}", block_number),
        "blockNumber": format!("0x{:x}", block_number),
        "transactionIndex": "0x0",
        "from": format!("0x{:040x}", 0),
        "to":   format!("0x{:040x}", 1),
        "cumulativeGasUsed": "0x0",
        "gasUsed": "0x0",
        "contractAddress": null,
        "logs": [],
        "status": "0x1",
        "logsBloom": format!("0x{}", "0".repeat(512)),
        "type": "0x2",
        "effectiveGasPrice": "0x1"
    })
}
