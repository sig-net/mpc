use super::BlockToProcess;
use crate::backlog::Backlog;
use crate::indexer_eth::parse_filtered_logs;
use crate::indexer_eth::process_respond_events;
use crate::indexer_eth::recover_backlog;
use crate::indexer_eth::BlockAndRequests;
use crate::indexer_eth::BlockNumber;
use crate::indexer_eth::BlockNumberAndHash;
use crate::indexer_eth::EthConfig;
use crate::indexer_eth::EthereumClientTrait;
use crate::indexer_eth::SignatureRequested;
use crate::indexer_eth::SignatureResponded;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::{Chain, IndexedSignRequest};
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::BidirectionalTxId;
use crate::sign_bidirectional::PendingRequestStatus;
use crate::storage::app_data_storage::AppDataStorage;
use alloy::consensus::BlockHeader;
use alloy::eips::{BlockId, BlockNumberOrTag};
use alloy::primitives::Address;
use alloy::rpc::types::Log;
use alloy::sol_types::SolEvent;
use async_trait::async_trait;
use helios::common::types::{SubscriptionEvent, SubscriptionType};
use helios::ethereum::{config::networks::Network, EthereumClient, EthereumClientBuilder};
use near_account_id::AccountId;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tokio::time::Duration;

const MAX_BLOCKS_TO_PROCESS: usize = 10000;

fn blocks_to_process_channel() -> (mpsc::Sender<BlockToProcess>, mpsc::Receiver<BlockToProcess>) {
    mpsc::channel(MAX_BLOCKS_TO_PROCESS)
}

const MAX_INDEXED_REQUESTS: usize = 1024;

fn indexed_channel() -> (
    mpsc::Sender<BlockAndRequests>,
    mpsc::Receiver<BlockAndRequests>,
) {
    mpsc::channel(MAX_INDEXED_REQUESTS)
}

const MAX_FAILED_BLOCKS: usize = 1024;

fn failed_blocks_channel() -> (
    mpsc::Sender<BlockNumberAndHash>,
    mpsc::Receiver<BlockNumberAndHash>,
) {
    mpsc::channel(MAX_FAILED_BLOCKS)
}

const MAX_FINALIZED_BLOCKS: usize = 1024;

fn finalized_block_channel() -> (mpsc::Sender<BlockNumber>, mpsc::Receiver<BlockNumber>) {
    mpsc::channel(MAX_FINALIZED_BLOCKS)
}

pub struct HeliosEthereumClient {
    client: Arc<EthereumClient>,
    max_retries: u8,
    base_delay: Duration,
}

// All fields are Send: Arc<EthereumClient>, u8, and Duration are all Send
unsafe impl Send for HeliosEthereumClient {}
unsafe impl Sync for HeliosEthereumClient {}

#[async_trait]
impl EthereumClientTrait for HeliosEthereumClient {
    async fn get_block(
        &self,
        block_id: alloy::rpc::types::BlockId,
    ) -> Option<alloy::rpc::types::Block> {
        self.fetch_block(block_id.into()).await
    }

    async fn get_block_receipts(
        &self,
        block_number_or_tag: BlockNumberOrTag,
    ) -> anyhow::Result<Option<Vec<alloy::rpc::types::TransactionReceipt>>> {
        self.client
            .get_block_receipts(BlockId::Number(block_number_or_tag.into()))
            .await
            .map_err(|err| {
                anyhow::anyhow!(
                    "Failed to get block receipts for block number {block_number_or_tag:?}: {:?}",
                    err
                )
            })
    }

    async fn get_nonce(
        &self,
        address: Address,
        block_id: alloy::rpc::types::BlockId,
    ) -> anyhow::Result<u64> {
        self.client
            .get_nonce(address, block_id.into())
            .await
            .map_err(|err| {
                anyhow::anyhow!(
                    "Failed to get nonce for address {address:?} and block id {block_id:?}: {:?}",
                    err
                )
            })
    }

    async fn get_transaction_by_hash(
        &self,
        tx_hash: alloy::primitives::B256,
    ) -> anyhow::Result<Option<alloy::rpc::types::Transaction>> {
        self.client
            .get_transaction(tx_hash.into())
            .await
            .map_err(|err| {
                anyhow::anyhow!("Failed to get transaction by hash {tx_hash:?}: {:?}", err)
            })
    }
}

impl HeliosEthereumClient {
    async fn new(
        client: EthereumClient,
        max_retries: u8,
        base_delay: Duration,
    ) -> anyhow::Result<Self> {
        let block_heads_rx = match client.subscribe(SubscriptionType::NewHeads).await {
            Ok(block_heads_rx) => block_heads_rx,
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Failed to subscribe to new block heads: {err:?}"
                ));
            }
        };
        Ok(Self {
            client: Arc::new(client),
            max_retries,
            base_delay,
            block_heads_rx: Arc::new(block_heads_rx),
        })
    }

    // retry getting block from helios with exponential backoff
    async fn fetch_block(&self, block_id: BlockId) -> Option<alloy::rpc::types::Block> {
        let helios_client = self.client.clone();
        let mut retries = 0;
        loop {
            match helios_client.get_block(block_id, false).await {
                Ok(Some(block)) => return Some(block),
                Ok(None) => {
                    tracing::warn!("Block {block_id} not found from Helios client");
                    return None;
                }
                Err(e) => {
                    if retries < self.max_retries {
                        retries += 1;
                        let delay = self.base_delay * 2u32.pow((retries - 1) as u32);
                        tracing::warn!(
                        "Failed to fetch block number {block_id} from Helios client: {:?}, retrying",
                        e
                    );
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    tracing::warn!(
                    "Failed to fetch block number {block_id} from Helios client: {:?}, exceeded maximum retry",
                    e
                );
                    return None;
                }
            }
        }
    }
}

async fn build_helios_client(eth: EthConfig) -> anyhow::Result<HeliosEthereumClient> {
    let Ok(network) = Network::from_str(eth.network.as_str()) else {
        return Err(anyhow::anyhow!("Network input incorrect: {}", eth.network));
    };
    let client: EthereumClient = {
        let builder = match EthereumClientBuilder::new()
            .network(network)
            .consensus_rpc(&eth.consensus_rpc_http_url)
        {
            Ok(builder) => builder,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to build consensus RPC: {err:?}"));
            }
        };

        let builder = match builder.execution_rpc(&eth.execution_rpc_http_url) {
            Ok(builder) => builder,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to build execution RPC: {err:?}"));
            }
        };

        match builder
            .data_dir(PathBuf::from(&eth.helios_data_path))
            .with_file_db()
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                return Err(anyhow::anyhow!("Failed to build Helios client: {err:?}"));
            }
        }
    };
    tracing::info!("Built Helios client on network {}", network);
    client.wait_synced().await;

    HeliosEthereumClient::new(client, 6, Duration::from_millis(200)).await
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    eth: EthConfig,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    app_data_storage: AppDataStorage,
    node_near_account_id: AccountId,
    backlog: Backlog,
    contract_watcher: ContractStateWatcher,
    mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
) {
    recover_backlog(&backlog, contract_watcher, mesh_state, node_client).await;

    let last_processed_block = app_data_storage
        .last_processed_block_eth()
        .await
        .unwrap_or_else(|err| {
            tracing::warn!("Failed to get last processed block: {err:?}");
            None
        });

    let client: HeliosEthereumClient = match build_helios_client(eth).await {
        Ok(client) => client,
        Err(err) => {
            tracing::error!("Failed to build Helios client: {err:?}");
            return;
        }
    };

    tracing::info!("running ethereum indexer");

    let Ok(contract_address) = Address::from_str(&format!("0x{}", eth.contract_address)) else {
        tracing::error!("Failed to parse contract address: {}", eth.contract_address);
        return;
    };
    let total_timeout = Duration::from_secs(eth.total_timeout);

    let (blocks_failed_send, blocks_failed_recv) = failed_blocks_channel();

    let (requests_indexed_send, requests_indexed_recv) = indexed_channel();

    let (finalized_block_send, finalized_block_recv) = finalized_block_channel();

    let (blocks_to_process_send, mut blocks_to_process_recv) = blocks_to_process_channel();

    tokio::spawn(async move {
        tracing::info!("Spawned task to refresh the latest finalized block");
        refresh_finalized_block(
            &helios_client,
            finalized_block_send.clone(),
            eth.refresh_finalized_interval,
        )
        .await;
    });

    tokio::spawn(send_requests_when_final(
        &helios_client,
        requests_indexed_recv,
        finalized_block_recv,
        sign_tx.clone(),
        app_data_storage.clone(),
        node_near_account_id.clone(),
        eth.optimistic_requests,
        backlog.clone(),
    ));

    tokio::spawn(retry_failed_blocks(
        &helios_client,
        blocks_failed_recv,
        blocks_failed_send.clone(),
        contract_address,
        node_near_account_id.clone(),
        requests_indexed_send.clone(),
        total_timeout,
        backlog.clone(),
    ));

    let blocks_to_process_send_clone = blocks_to_process_send.clone();
    if let Some(last_processed_block) = last_processed_block {
        let Ok(SubscriptionEvent::NewHeads(latest_block)) = client.block_heads_rx.recv().await
        else {
            tracing::warn!("Failed to receive latest block head");
            return;
        };
        let end_block_number = latest_block.header.number;
        add_catchup_blocks_to_process(
            blocks_to_process_send_clone,
            last_processed_block,
            end_block_number,
        )
        .await;
    }

    let blocks_to_process_send_clone = blocks_to_process_send.clone();
    tokio::spawn(async move {
        tracing::info!("Spawned task to add new blocks to process");
        add_new_block_to_process(block_heads_rx, blocks_to_process_send_clone).await;
    });

    let mut interval = tokio::time::interval(Duration::from_millis(200));
    let requests_indexed_send_clone = requests_indexed_send.clone();
    loop {
        let Some(block_to_process) = blocks_to_process_recv.recv().await else {
            interval.tick().await;
            continue;
        };
        let (block_number, block_hash, is_catchup) = match block_to_process {
            BlockToProcess::Catchup(block_number) => {
                let block = helios_client
                    .get_block(BlockId::Number(BlockNumberOrTag::Number(block_number)))
                    .await;
                if let Some(block) = block {
                    (block.header.number, block.header.hash, true)
                } else {
                    tracing::warn!("Block {block_number} not found from Helios client");
                    continue;
                }
            }
            BlockToProcess::NewBlock((block_number, block_hash)) => {
                (block_number, block_hash, false)
            }
        };
        if let Err(err) = process_block(
            &helios_client,
            block_number,
            block_hash,
            contract_address,
            node_near_account_id.clone(),
            requests_indexed_send_clone.clone(),
            total_timeout,
            backlog.clone(),
        )
        .await
        {
            tracing::warn!("Eth indexer failed to process block number {block_number}: {err:?}");
            add_failed_block(blocks_failed_send.clone(), block_number, block_hash).await;
            continue;
        }
        if block_number % 10 == 0 {
            if is_catchup {
                tracing::info!("Processed catchup block number {block_number}");
            } else {
                tracing::info!("Processed new block number {block_number}");
            }
        }
        crate::metrics::LATEST_BLOCK_NUMBER
            .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
            .set(block_number as i64);
    }
}

async fn add_new_block_to_process(
    mut block_heads_rx: tokio::sync::broadcast::Receiver<
        SubscriptionEvent<helios::ethereum::spec::Ethereum>,
    >,
    blocks_to_process: mpsc::Sender<BlockToProcess>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(200));
    let mut receiver_state_update_timestamp = Instant::now();
    loop {
        interval.tick().await;
        if block_heads_rx.is_empty()
            && receiver_state_update_timestamp.elapsed() > Duration::from_secs(60)
        {
            tracing::warn!("No new block heads received for 60 seconds, waiting...");
            receiver_state_update_timestamp = Instant::now();
        }
        let new_block_head = match block_heads_rx.recv().await {
            Ok(new_block_head) => new_block_head,
            Err(RecvError::Lagged(lagged_count)) => {
                tracing::warn!(
                    "Eth indexer failed to receive latest block header: block heads stream lagged too far behind, lagged count: {lagged_count}"
                );
                continue;
            }
            Err(RecvError::Closed) => {
                tracing::error!(
                    "Eth indexer failed to receive latest block header: block heads stream closed"
                );
                // TODO: add a retry mechanism for closed block heads stream
                break;
            }
        };
        receiver_state_update_timestamp = Instant::now();
        let SubscriptionEvent::NewHeads(new_block) = new_block_head;
        let block_number = new_block.header.number;
        let block_hash = new_block.header.hash;
        if block_number % 10 == 0 {
            tracing::info!("Received new block head: {block_number}");
        }
        if let Err(err) = blocks_to_process
            .send(BlockToProcess::NewBlock((block_number, block_hash)))
            .await
        {
            tracing::warn!("Failed to send block to process: {err:?}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_block(
    client: &HeliosEthereumClient,
    block_number: u64,
    block_hash: alloy::primitives::B256,
    contract_address: Address,
    node_near_account_id: AccountId,
    requests_indexed: mpsc::Sender<BlockAndRequests>,
    total_timeout: Duration,
    backlog: Backlog,
) -> anyhow::Result<()> {
    tracing::info!(
        "Processing block number {} with hash {:?}",
        block_number,
        block_hash
    );
    let start = Instant::now();
    let block_receipts_result = client
        .get_block_receipts(BlockNumberOrTag::Number(block_number))
        .await;
    crate::metrics::ETH_BLOCK_RECEIPT_LATENCY
        .with_label_values(&[node_near_account_id.as_str()])
        .observe(start.elapsed().as_millis() as f64);
    let Some(block_receipts) = block_receipts_result.map_err(|err| {
        anyhow::anyhow!(
            "Failed to get block receipts for block number {block_number}: {:?}",
            err
        )
    })?
    else {
        tracing::info!("no receipts for block number {block_number}");
        return Ok(());
    };

    let pending_watchers = backlog.pending_execution(Chain::Ethereum).await;

    tracing::info!(
        pending_watchers_count = pending_watchers.len(),
        block_number,
        "checking pending watchers for bidirectional execution"
    );

    let mut respond_bidirectional_requests: Vec<IndexedSignRequest> = Vec::new();

    for receipt in &block_receipts {
        let tx_id: BidirectionalTxId = receipt.transaction_hash.into();
        tracing::debug!(?tx_id, "checking receipt against pending watchers");
        let Some((sign_id, pending_tx)) = pending_watchers.get(&tx_id).cloned() else {
            continue;
        };
        let status = if receipt.status() {
            PendingRequestStatus::Success
        } else {
            PendingRequestStatus::Failed
        };
        tracing::info!(
            ?tx_id,
            ?sign_id,
            block_number,
            "observed bidirectional execution on destination chain"
        );

        let mut updated_tx = pending_tx.clone();
        updated_tx.status = status;

        let completed_tx =
            crate::respond_bidirectional::CompletedTx::new(updated_tx.clone(), block_number);

        if let Some(respond_request) = completed_tx
            .create_sign_request_from_completed_tx(client, Chain::Ethereum, 6, total_timeout)
            .await
        {
            respond_bidirectional_requests.push(respond_request);
        } else {
            tracing::warn!(
                ?tx_id,
                ?sign_id,
                "failed to create respond_bidirectional request from executed tx"
            );
        }

        backlog
            .set_status(pending_tx.source_chain, &sign_id, status)
            .await;
        backlog.unwatch_execution(Chain::Ethereum, &tx_id).await;
    }

    let remaining_watchers = backlog.pending_execution(Chain::Ethereum).await;

    for (tx_id, (sign_id, tx)) in remaining_watchers {
        let current_nonce = match client
            .get_nonce(
                tx.from_address,
                BlockId::Number(BlockNumberOrTag::Number(block_number)),
            )
            .await
        {
            Ok(nonce) => nonce,
            Err(err) => {
                tracing::warn!(?tx_id, ?sign_id, ?err, "failed to get current nonce");
                continue;
            }
        };

        if tx.nonce < current_nonce {
            tracing::warn!(
                ?tx_id,
                ?sign_id,
                expected_nonce = tx.nonce,
                actual_nonce = current_nonce,
                "nonce too low for tx",
            );

            let mut failed_tx = tx.clone();
            failed_tx.status = PendingRequestStatus::Failed;
            let completed_tx =
                crate::respond_bidirectional::CompletedTx::new(failed_tx.clone(), block_number);

            if let Some(request) = completed_tx
                .create_sign_request_from_completed_tx(client, Chain::Ethereum, 6, total_timeout)
                .await
            {
                respond_bidirectional_requests.push(request);
            } else {
                tracing::warn!(
                    ?tx_id,
                    ?sign_id,
                    "failed to create sign request from completed tx"
                );
            }

            backlog
                .set_status(tx.source_chain, &sign_id, PendingRequestStatus::Failed)
                .await;
            backlog.unwatch_execution(Chain::Ethereum, &tx_id).await;
        }
    }

    let relevant_logs: Vec<Log> = block_receipts
        .into_iter()
        .filter_map(|receipt| receipt.as_ref().as_receipt().cloned())
        .flat_map(|receipt| {
            receipt
                .logs
                .into_iter()
                .filter(|log| log.address() == contract_address)
        })
        .collect();

    let (respond_logs, potential_request_logs): (Vec<Log>, Vec<Log>) =
        relevant_logs.into_iter().partition(|log| {
            log.topic0()
                .is_some_and(|topic| *topic == SignatureResponded::SIGNATURE_HASH)
        });

    if !respond_logs.is_empty() {
        process_respond_events(&respond_logs, &backlog).await;
    }

    let request_logs: Vec<Log> = potential_request_logs
        .into_iter()
        .filter(|log| {
            log.topic0()
                .is_some_and(|topic| *topic == SignatureRequested::SIGNATURE_HASH)
        })
        .collect();

    let mut all_sign_requests = Vec::new();
    if !request_logs.is_empty() {
        all_sign_requests.extend(parse_filtered_logs(request_logs, total_timeout));
    }
    if !respond_bidirectional_requests.is_empty() {
        all_sign_requests.extend(respond_bidirectional_requests);
    }

    if all_sign_requests.is_empty() {
        return Ok(());
    }

    requests_indexed
        .send(BlockAndRequests::new(
            block_number,
            block_hash,
            all_sign_requests.clone(),
        ))
        .await
        .map_err(|err| anyhow::anyhow!("Failed to send indexed requests: {:?}", err))?;

    let block_timestamp = client
        .get_block(BlockId::Number(BlockNumberOrTag::Number(block_number)))
        .await
        .map(|block| block.header.timestamp());

    for request in &all_sign_requests {
        if let Some(block_timestamp) = block_timestamp {
            crate::metrics::INDEXER_DELAY
                .with_label_values(&[Chain::Ethereum.as_str(), node_near_account_id.as_str()])
                .observe(
                    crate::util::duration_between_unix(
                        block_timestamp,
                        request.unix_timestamp_indexed,
                    )
                    .as_secs() as f64,
                );
        }
    }

    Ok(())
}
