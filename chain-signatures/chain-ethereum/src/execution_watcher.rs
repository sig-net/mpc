//! Execution-confirmation watching: resolves whether pending bidirectional
//! transactions (tracked by the state manager as "execution watchers") have
//! been mined, and emits [`ChainEvent::ExecutionConfirmed`] for them.
//!
//! The indexer constructs an [`ExecutionWatcher`] per block and calls
//! [`ExecutionWatcher::collect`]. The nonce-gate scheduling state
//! ([`WatcherGateState`]) lives on the indexer and is borrowed per call so it
//! persists across blocks.

use crate::client::EthereumClient;
use crate::config::IndexerConfig;
use crate::event_parsing::is_contract_call;
use crate::respond_bidirectional::{build_serialized_output, TraceOutput};
use alloy::consensus::Transaction;
use alloy::eips::BlockNumberOrTag;
use alloy::network::TransactionResponse;
use alloy::primitives::{Address, B256};
use alloy::rpc::types::{Block, BlockId, BlockTransactions, TransactionReceipt};
use futures_util::{stream, StreamExt};
use mpc_chain_integration_core::{ChainTelemetry, ExtractionFailureKind, StateManager};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainConfig as _, ChainEvent, ExecutionOutcome,
    SignId,
};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Scheduling state for the watcher nonce gate. Persisted across blocks by the
/// indexer (it borrows this) so first-appearance detection and retry tracking
/// survive from one block to the next.
#[derive(Default)]
pub(crate) struct WatcherGateState {
    /// Watchers present at the previous block, for first-appearance detection.
    prev: HashSet<BidirectionalTxId>,
    /// Watchers whose last RPC resolution attempt failed; retried every block.
    retry: HashSet<BidirectionalTxId>,
}

/// A pending execution watcher entry from the state manager.
type WatcherEntry = (BidirectionalTxId, (SignId, Arc<BidirectionalTx>));

/// Per-watcher receipt resolution result.
type WatcherReceipt = (
    BidirectionalTxId,
    SignId,
    Arc<BidirectionalTx>,
    anyhow::Result<BackfillOutcome>,
);

/// Result of a `backfill_execution_confirmation`. `Observed` carries the
/// confirmation for a mined tx; the staleness check skips observed watchers so
/// a mined tx whose extraction must be retried can stay pending. `NotObserved`
/// covers "no receipt yet" (pending or replaced).
#[allow(clippy::large_enum_variant)] // value is consumed in one match arm; never stored.
enum BackfillOutcome {
    NotObserved,
    Observed { confirmation: ConfirmationOutcome },
}

/// Result of resolving a mined transaction into an execution confirmation.
#[allow(clippy::large_enum_variant)] // value is consumed in one match arm; never stored.
enum ConfirmationOutcome {
    /// The execution resolved to a definite outcome.
    Confirmed(ChainEvent),
    /// Output extraction failed for a node-local reason. No event is emitted;
    /// the watcher is re-attempted on the next block.
    RetryExtraction,
}

/// A failed output extraction, classified by whether resolving the execution
/// from it would be consensus-safe.
///
/// Only failures that are a pure function of on-chain data and the request's
/// own schemas are [`Terminal`](ExtractionFailure::Terminal): every node
/// derives them identically, so failing the request cannot make one node
/// disagree with its peers. Anything that depends on *this* node's RPC
/// endpoint — transport errors, missing `debug_traceTransaction` support, a
/// malformed provider response — is
/// [`Retryable`](ExtractionFailure::Retryable), because a peer with a healthy
/// endpoint would extract an output just fine and unilaterally failing here
/// would stall signing on divergent responses.
enum ExtractionFailure {
    Retryable(anyhow::Error),
    Terminal(anyhow::Error),
}

impl ExtractionFailure {
    fn kind(&self) -> ExtractionFailureKind {
        match self {
            Self::Retryable(_) => ExtractionFailureKind::Retryable,
            Self::Terminal(_) => ExtractionFailureKind::Terminal,
        }
    }
}

/// RPC-acquired inputs to deterministic output interpretation.
struct ExtractionInputs {
    is_contract_call: bool,
    trace_output: TraceOutput,
}

/// Borrow-based view over the indexer's dependencies used to resolve execution
/// confirmations for a single block. Cheap to construct (five shared refs).
pub(crate) struct ExecutionWatcher<'a, S: StateManager, T: ChainTelemetry> {
    client: &'a EthereumClient,
    state_manager: &'a S,
    config: &'a IndexerConfig,
    gate: &'a Mutex<WatcherGateState>,
    telemetry: &'a T,
}

impl<'a, S: StateManager, T: ChainTelemetry> ExecutionWatcher<'a, S, T> {
    pub(crate) fn new(
        client: &'a EthereumClient,
        state_manager: &'a S,
        config: &'a IndexerConfig,
        gate: &'a Mutex<WatcherGateState>,
        telemetry: &'a T,
    ) -> Self {
        Self {
            client,
            state_manager,
            config,
            gate,
            telemetry,
        }
    }

    /// Collects execution confirmations for all watchers at the given block.
    pub(crate) async fn collect(&self, block: &Block) -> anyhow::Result<Vec<ChainEvent>> {
        let watchers = self
            .state_manager
            .get_execution_watchers(Chain::Ethereum)
            .await;

        if watchers.is_empty() {
            return Ok(Vec::new());
        }

        let block_number = block.header.number;
        tracing::info!(
            watchers_count = watchers.len(),
            block_number,
            "collect_execution_confirmations checking watchers"
        );

        let (new_watchers, retry) = self.schedule_watcher_gates(&watchers);

        // Extract hashes from the block
        let block_tx_hashes: HashSet<_> = match &block.transactions {
            BlockTransactions::Hashes(hashes) => hashes.iter().copied().collect(),
            BlockTransactions::Full(txs) => txs.iter().map(|tx| tx.tx_hash()).collect(),
            _ => HashSet::new(),
        };

        // Partition watchers into those that mined in this block and those that did not
        let (mined_in_block, unmined_watchers): (Vec<_>, Vec<_>) = watchers
            .into_iter()
            .partition(|(tx_id, _)| block_tx_hashes.contains(&B256::from(tx_id.0)));

        // Receipts for watched txs mined in this block
        let (mut events, consumed_slots, mut failed) = self
            .resolve_mined_watchers(mined_in_block, block_number)
            .await;

        // Fail pending watchers replaced by a sibling tx mined in this block
        let (sibling_events, unmined_watchers) =
            Self::resolve_replaced_siblings(unmined_watchers, &consumed_slots, block_number);

        events.extend(sibling_events);

        // Nonce gate: one-shot for new watchers, every block for retries,
        // every WATCHER_SLOW_SWEEP_INTERVAL blocks for edge-case consumption by a tx with no local watcher.
        let sweep_all = block_number % self.config.watcher_slow_sweep_interval == 0;
        let gated: Vec<_> = unmined_watchers
            .into_iter()
            .filter(|(tx_id, _)| sweep_all || new_watchers.contains(tx_id) || retry.contains(tx_id))
            .collect();

        let (gated_events, gated_failed) = self.resolve_gated_watchers(gated, block_number).await;
        events.extend(gated_events);
        failed.extend(gated_failed);

        // Failed watchers are retried on the next block.
        self.lock_watcher_gate().retry = failed;

        Ok(events)
    }

    /// Locks the watcher gate Mutex, recovering the guard if poisoned.
    fn lock_watcher_gate(&self) -> MutexGuard<'_, WatcherGateState> {
        self.gate.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Updates gate scheduling state, returning the watchers to nonce-check
    /// this block: newly appeared ones (one-shot) and previously failed ones
    /// (retried every block).
    fn schedule_watcher_gates(
        &self,
        watchers: &HashMap<BidirectionalTxId, (SignId, Arc<BidirectionalTx>)>,
    ) -> (HashSet<BidirectionalTxId>, HashSet<BidirectionalTxId>) {
        let mut gate = self.lock_watcher_gate();
        gate.retry.retain(|id| watchers.contains_key(id));
        let new_watchers = watchers
            .keys()
            .filter(|id| !gate.prev.contains(*id))
            .copied()
            .collect();
        gate.prev = watchers.keys().copied().collect();
        (new_watchers, gate.retry.clone())
    }

    /// Fetch the RPC-derived inputs to output extraction: the transaction
    /// itself and, for contract calls, its `debug_traceTransaction` return
    /// data. Every failure here is node-local, so all are retryable — except a
    /// `CREATE` transaction, which is a property of the transaction itself and
    /// can never be extracted by any node.
    async fn fetch_extraction_inputs(
        &self,
        tx_id: alloy::primitives::B256,
    ) -> Result<ExtractionInputs, ExtractionFailure> {
        let tx_info = match self.client.get_transaction_by_hash(tx_id).await {
            Ok(Some(tx_info)) => tx_info,
            Ok(None) => {
                return Err(ExtractionFailure::Retryable(anyhow::anyhow!(
                    "transaction {tx_id:?} not found by the rpc endpoint"
                )))
            }
            Err(err) => {
                return Err(ExtractionFailure::Retryable(
                    err.context(format!("failed to fetch transaction {tx_id:?}")),
                ))
            }
        };

        if tx_info.inner.to().is_none() {
            return Err(ExtractionFailure::Terminal(anyhow::anyhow!(
                "unsupported contract deployment (CREATE): {tx_id:?}"
            )));
        }

        let data = tx_info.inner.input().clone();
        let is_contract_call = is_contract_call(&data);

        let trace_output = if is_contract_call {
            tracing::info!(
                ?tx_id,
                "Extracting transaction output via debug_traceTransaction"
            );
            match self.client.trace_transaction_output(tx_id).await {
                Ok(Some(output)) => TraceOutput::Output(output),
                Ok(None) => {
                    tracing::warn!(
                        ?tx_id,
                        "debug_traceTransaction returned no return data for a call frame"
                    );
                    TraceOutput::NoReturnData
                }
                // Transport errors, endpoints without trace support, and
                // malformed trace envelopes are all indistinguishable
                // node-local problems here: a peer on a healthy endpoint still
                // extracts an output, so never resolve the request from one.
                Err(err) => {
                    return Err(ExtractionFailure::Retryable(
                        err.context(format!("debug_traceTransaction failed for {tx_id:?}")),
                    ))
                }
            }
        } else {
            TraceOutput::NotTraced
        };

        Ok(ExtractionInputs {
            is_contract_call,
            trace_output,
        })
    }

    /// Extract the output of a successful transaction, either from the trace or from the receipt.
    ///
    /// Splits into an RPC acquisition phase and a deterministic interpretation
    /// phase so failures can be classified for consensus safety; see
    /// [`ExtractionFailure`].
    async fn extract_success_tx_output(
        &self,
        tx_id: alloy::primitives::B256,
        tx: &BidirectionalTx,
    ) -> Result<Vec<u8>, ExtractionFailure> {
        let inputs = self.fetch_extraction_inputs(tx_id).await?;

        // Deterministic from here on: on-chain data decoded against the
        // request's own schemas, identically on every node.
        build_serialized_output(
            inputs.is_contract_call,
            &tx.output_deserialization_schema,
            inputs.trace_output,
            tx.source_chain.respond_serialization_format(),
            &tx.respond_serialization_schema,
        )
        .map_err(ExtractionFailure::Terminal)
    }

    /// Construct a `ChainEvent::ExecutionConfirmed` for a mined transaction.
    ///
    /// A terminal extraction failure resolves the execution as
    /// [`ExecutionOutcome::Failed`] rather than dropping the event, so the
    /// bidirectional request completes with an explicit failure instead of
    /// staying pending forever. A retryable one emits nothing and asks for
    /// another attempt on the next block.
    async fn execution_confirmed_event(
        &self,
        tx_id: BidirectionalTxId,
        sign_id: SignId,
        pending_tx: &BidirectionalTx,
        block_number: u64,
        receipt: &TransactionReceipt,
    ) -> ConfirmationOutcome {
        let receipt_succeeded = receipt.status();

        tracing::info!(
            ?tx_id,
            ?sign_id,
            block_number,
            "bidirectional execution observed via rpc"
        );

        let result = if receipt_succeeded {
            match self
                .extract_success_tx_output(tx_id.0.into(), pending_tx)
                .await
            {
                Ok(serialized_output) => {
                    tracing::info!(
                        ?tx_id,
                        ?sign_id,
                        "extracted transaction output for bidirectional tx"
                    );
                    ExecutionOutcome::Success {
                        output: serialized_output,
                    }
                }
                Err(failure) => {
                    self.telemetry
                        .bidirectional_extraction_failed(failure.kind());
                    match failure {
                        ExtractionFailure::Retryable(err) => {
                            tracing::warn!(
                                ?tx_id,
                                ?sign_id,
                                ?err,
                                "failed to extract transaction output; retrying on the next block"
                            );
                            return ConfirmationOutcome::RetryExtraction;
                        }
                        ExtractionFailure::Terminal(err) => {
                            tracing::error!(
                                ?tx_id,
                                ?sign_id,
                                ?err,
                                "unrecoverable transaction output extraction failure; \
                                 resolving bidirectional execution as failed"
                            );
                            ExecutionOutcome::Failed
                        }
                    }
                }
            }
        } else {
            ExecutionOutcome::Failed
        };

        ConfirmationOutcome::Confirmed(ChainEvent::ExecutionConfirmed {
            tx_id,
            sign_id,
            source_chain: pending_tx.source_chain,
            block_height: block_number,
            result,
        })
    }

    async fn backfill_execution_confirmation(
        &self,
        tx_id: BidirectionalTxId,
        sign_id: SignId,
        pending_tx: &BidirectionalTx,
        current_block_number: u64,
    ) -> anyhow::Result<BackfillOutcome> {
        // Fetch this single watcher tx's receipt
        let Some(receipt) = self.client.get_transaction_receipt(tx_id.0.into()).await? else {
            return Ok(BackfillOutcome::NotObserved);
        };

        let Some(mined_block_number) = receipt.block_number else {
            tracing::debug!(
                ?tx_id,
                ?sign_id,
                "late watcher backfill: transaction receipt has no block number"
            );
            return Ok(BackfillOutcome::NotObserved);
        };

        if mined_block_number > current_block_number {
            tracing::debug!(
                ?tx_id,
                ?sign_id,
                mined_block_number,
                current_block_number,
                "skipping late watcher backfill for future ethereum block"
            );

            return Ok(BackfillOutcome::NotObserved);
        }

        tracing::info!(
            ?tx_id,
            ?sign_id,
            mined_block_number,
            current_block_number,
            "backfilled execution confirmation for late ethereum watcher"
        );

        let confirmation = self
            .execution_confirmed_event(tx_id, sign_id, pending_tx, mined_block_number, &receipt)
            .await;
        Ok(BackfillOutcome::Observed { confirmation })
    }

    /// Fetches receipts for a batch of watchers with bounded concurrency,
    /// keeping per-watcher results so one failure doesn't abort the batch.
    async fn fetch_watcher_receipts(
        &self,
        watchers: Vec<WatcherEntry>,
        block_number: u64,
    ) -> Vec<WatcherReceipt> {
        stream::iter(
            watchers
                .into_iter()
                .map(|(tx_id, (sign_id, pending_tx))| async move {
                    let result = self
                        .backfill_execution_confirmation(tx_id, sign_id, &pending_tx, block_number)
                        .await;
                    (tx_id, sign_id, pending_tx, result)
                }),
        )
        .buffer_unordered(self.config.max_concurrent_watcher_rpcs)
        .collect()
        .await
    }

    /// Fetches nonces for the given senders with bounded concurrency.
    async fn fetch_sender_nonces(
        &self,
        senders: HashSet<Address>,
        block_number: u64,
    ) -> Vec<(Address, anyhow::Result<u64>)> {
        stream::iter(senders.into_iter().map(|sender| async move {
            let result = self
                .client
                .get_nonce(
                    sender,
                    BlockId::Number(BlockNumberOrTag::Number(block_number)),
                )
                .await;
            (sender, result)
        }))
        .buffer_unordered(self.config.max_concurrent_watcher_rpcs)
        .collect()
        .await
    }

    /// Resolves watched txs whose hash appears in this block. Returns emitted
    /// events, the (sender, nonce) slots consumed by observed txs (input to
    /// sibling correlation), and watchers whose RPC attempt failed.
    async fn resolve_mined_watchers(
        &self,
        mined: Vec<WatcherEntry>,
        block_number: u64,
    ) -> (
        Vec<ChainEvent>,
        HashSet<(Address, u64)>,
        HashSet<BidirectionalTxId>,
    ) {
        let mut events = Vec::new();
        let mut consumed_slots = HashSet::new();
        let mut failed = HashSet::new();

        for (tx_id, sign_id, pending_tx, result) in
            self.fetch_watcher_receipts(mined, block_number).await
        {
            match result {
                Ok(BackfillOutcome::Observed { confirmation }) => {
                    // The tx mined regardless of extraction outcome, so its
                    // nonce slot is consumed either way.
                    consumed_slots
                        .insert((Address::from(pending_tx.from_address), pending_tx.nonce));
                    match confirmation {
                        ConfirmationOutcome::Confirmed(event) => events.push(event),
                        ConfirmationOutcome::RetryExtraction => {
                            failed.insert(tx_id);
                        }
                    }
                }
                Ok(BackfillOutcome::NotObserved) => {}
                Err(err) => {
                    tracing::warn!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "failed to fetch receipt for bidirectional tx mined in block"
                    );
                    failed.insert(tx_id);
                }
            }
        }

        (events, consumed_slots, failed)
    }

    /// Fails pending watchers whose (sender, nonce) slot was consumed by a
    /// different tx mined in this block: since only the network can sign for
    /// these sender addresses, the consuming tx is necessarily another
    /// watcher, making replacement a pure function of block content + local
    /// watcher state (no RPC, deterministic `block_height` across nodes).
    /// Returns the events and the remaining unmined watchers.
    fn resolve_replaced_siblings(
        unmined: Vec<WatcherEntry>,
        consumed_slots: &HashSet<(Address, u64)>,
        block_number: u64,
    ) -> (Vec<ChainEvent>, Vec<WatcherEntry>) {
        let (replaced, remaining): (Vec<_>, Vec<_>) =
            unmined.into_iter().partition(|(_, (_, tx))| {
                consumed_slots.contains(&(Address::from(tx.from_address), tx.nonce))
            });

        let events = replaced
            .into_iter()
            .map(|(tx_id, (sign_id, tx))| {
                tracing::warn!(
                    ?tx_id,
                    ?sign_id,
                    nonce = tx.nonce,
                    "transaction replaced by sibling tx mined in this block"
                );
                ChainEvent::ExecutionConfirmed {
                    tx_id,
                    sign_id,
                    source_chain: tx.source_chain,
                    block_height: block_number,
                    result: ExecutionOutcome::Failed,
                }
            })
            .collect();

        (events, remaining)
    }

    /// Nonce-gates unmined watchers: fetches deduped sender nonces, then
    /// resolves watchers whose nonce was consumed. Returns emitted events and
    /// watchers whose RPC attempt failed.
    async fn resolve_gated_watchers(
        &self,
        gated: Vec<WatcherEntry>,
        block_number: u64,
    ) -> (Vec<ChainEvent>, HashSet<BidirectionalTxId>) {
        let unique_senders: HashSet<_> = gated
            .iter()
            .map(|(_, (_, tx))| Address::from(tx.from_address))
            .collect();

        // Failed senders are skipped: their watchers stay pending and are
        // retried on the next block.
        let mut nonces = HashMap::new();
        let mut failed = HashSet::new();
        for (sender, result) in self.fetch_sender_nonces(unique_senders, block_number).await {
            match result {
                Ok(nonce) => {
                    nonces.insert(sender, nonce);
                }
                Err(err) => {
                    tracing::warn!(?sender, ?err, "failed to fetch nonce for bidirectional tx");
                    failed.extend(
                        gated
                            .iter()
                            .filter(|(_, (_, tx))| Address::from(tx.from_address) == sender)
                            .map(|(tx_id, _)| *tx_id),
                    );
                }
            }
        }

        // Keep ONLY watchers whose nonces were consumed
        let consumed_txs: Vec<_> = gated
            .into_iter()
            .filter(|(_, (_, tx))| {
                nonces
                    .get(&Address::from(tx.from_address))
                    .is_some_and(|&current_nonce| tx.nonce < current_nonce)
            })
            .collect();

        let mut events = Vec::new();
        for (tx_id, sign_id, pending_tx, result) in self
            .fetch_watcher_receipts(consumed_txs, block_number)
            .await
        {
            match result {
                Ok(BackfillOutcome::Observed { confirmation }) => match confirmation {
                    ConfirmationOutcome::Confirmed(event) => events.push(event), // Late watcher pickup
                    ConfirmationOutcome::RetryExtraction => {
                        failed.insert(tx_id);
                    }
                },
                Ok(BackfillOutcome::NotObserved) => {
                    tracing::warn!(
                        ?tx_id,
                        ?sign_id,
                        expected_nonce = pending_tx.nonce,
                        "transaction replaced or dropped (nonce consumed by another tx)"
                    );
                    events.push(ChainEvent::ExecutionConfirmed {
                        tx_id,
                        sign_id,
                        source_chain: pending_tx.source_chain,
                        block_height: block_number,
                        result: ExecutionOutcome::Failed,
                    });
                }
                Err(err) => {
                    tracing::warn!(
                        ?tx_id,
                        ?sign_id,
                        ?err,
                        "failed to fetch receipt for nonce-consumed bidirectional tx"
                    );
                    failed.insert(tx_id);
                }
            }
        }

        (events, failed)
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utils;
    use alloy::primitives::{address, b256};
    use alloy::rpc::types::{Block, BlockTransactions};
    use mockito::{Matcher, Server};
    use mpc_chain_integration_core::StateManager;
    use mpc_primitives::{
        BidirectionalTx, BidirectionalTxId, Chain, ChainEvent, ExecutionOutcome, SignId,
        LATEST_MPC_KEY_VERSION,
    };
    use serde_json::json;
    use std::sync::Arc;

    #[tokio::test]
    async fn late_watcher_backfill_uses_tx_hash_and_mined_block() {
        let mut server = Server::new_async().await;

        let tx_hash = b256!("018b2331d461a4aeedf6a1f9cc37463377578244e6a35216057a8370714e798f");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let to_address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");

        let receipt_response = json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x2",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{to_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        // Mock Nonce Call: Block height 10 ("0xa"), returning current nonce 1
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0xa"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1" }).to_string())
            .create_async()
            .await;

        // Mock Receipt Call
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": receipt_response,
                })
                .to_string(),
            )
            .create_async()
            .await;

        let sign_id = SignId::new([0x55; 32]);
        let tx = BidirectionalTx {
            id: BidirectionalTxId(tx_hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: sign_id.request_id,
            from_address: **from_address,
            nonce: 0,
        };

        let harness = test_utils::WatcherHarness::new(&server.url()).await;
        harness
            .state_manager
            .watch_execution(Chain::Ethereum, sign_id, Arc::new(tx))
            .await;

        // Construct mock block at height 10 (triggers modulo 10 check)
        let mut block: Block = Block::default();
        block.header.number = 10;
        block.transactions = BlockTransactions::Hashes(Vec::new());

        let events = harness
            .watcher()
            .collect(&block)
            .await
            .expect("late watcher backfill should succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id: event_tx_id,
                sign_id: event_sign_id,
                source_chain,
                block_height,
                result,
            } => {
                assert_eq!(*event_tx_id, BidirectionalTxId(tx_hash.0));
                assert_eq!(*event_sign_id, sign_id);
                assert_eq!(*source_chain, Chain::Solana);
                assert_eq!(*block_height, 2);
                assert!(matches!(result, ExecutionOutcome::Failed));
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn watcher_resolution_deduplicates_nonces_and_gates_receipts() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash_0 = b256!("0000000000000000000000000000000000000000000000000000000000000000");
        let tx_hash_1 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let tx_hash_2 = b256!("2222222222222222222222222222222222222222222222222222222222222222");

        // Mock Nonce Call: Expect exactly 1 call (deduplicated) for height 10 ("0xa"), returning nonce 2
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0xa"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x2" }).to_string())
            .expect(1)
            .create_async()
            .await;

        // Mock Receipts: Expect calls for tx_0 and tx_1. tx_2 should NOT be called.
        let receipt_mock_0 = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({ "method": "eth_getTransactionReceipt", "params": [format!("{tx_hash_0:#x}")] })))
            .with_status(200)
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": null }).to_string())
            .expect(1)
            .create_async().await;

        let receipt_mock_1 = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({ "method": "eth_getTransactionReceipt", "params": [format!("{tx_hash_1:#x}")] })))
            .with_status(200)
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": null }).to_string())
            .expect(1)
            .create_async().await;

        let receipt_mock_2 = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({ "method": "eth_getTransactionReceipt", "params": [format!("{tx_hash_2:#x}")] })))
            .with_status(200)
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": null }).to_string())
            .expect(0) // Nonce < current_nonce is false
            .create_async().await;

        // Setup Indexer & Watchers
        let harness = test_utils::WatcherHarness::new(&server.url()).await;

        let create_tx = |hash: alloy::primitives::B256, nonce: u64| BidirectionalTx {
            id: BidirectionalTxId(hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: hash.0,
            from_address: **from_address,
            nonce,
        };

        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([0; 32]),
                Arc::new(create_tx(tx_hash_0, 0)),
            )
            .await;
        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([1; 32]),
                Arc::new(create_tx(tx_hash_1, 1)),
            )
            .await;
        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([2; 32]),
                Arc::new(create_tx(tx_hash_2, 2)),
            )
            .await;

        // Mock block at height 10
        let mut block: Block = Block::default();
        block.header.number = 10;
        block.transactions = BlockTransactions::Hashes(Vec::new());

        let events = harness
            .watcher()
            .collect(&block)
            .await
            .expect("should succeed");

        assert_eq!(
            events.len(),
            2,
            "Should emit 2 Failed events for consumed nonces"
        );

        nonce_mock.assert_async().await;
        receipt_mock_0.assert_async().await;
        receipt_mock_1.assert_async().await;
        receipt_mock_2.assert_async().await;
    }

    #[tokio::test]
    async fn watcher_resolution_uses_block_transactions_without_nonce_rpc() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash = b256!("018b2331d461a4aeedf6a1f9cc37463377578244e6a35216057a8370714e798f");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");

        let receipt_response = json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x5",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        // Mock Receipt: EXPECT 1 call
        let receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": receipt_response }).to_string())
            .expect(1)
            .create_async()
            .await;

        // Mock Nonce: EXPECT 0 calls (because the hash was found directly in the block!)
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getTransactionCount".to_string()))
            .expect(0)
            .create_async()
            .await;

        let sign_id = SignId::new([0x55; 32]);
        let tx = BidirectionalTx {
            id: BidirectionalTxId(tx_hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: sign_id.request_id,
            from_address: **from_address,
            nonce: 0,
        };

        let harness = test_utils::WatcherHarness::new(&server.url()).await;
        harness
            .state_manager
            .watch_execution(Chain::Ethereum, sign_id, Arc::new(tx))
            .await;

        // Block height 5 (NOT a modulo 10 block), but contains tx_hash in block.transactions
        let mut block: Block = Block::default();
        block.header.number = 5;
        block.transactions = BlockTransactions::Hashes(vec![tx_hash]);

        let events = harness
            .watcher()
            .collect(&block)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 1);
        receipt_mock.assert_async().await;
        nonce_mock.assert_async().await;
    }

    #[tokio::test]
    async fn watcher_resolution_tolerates_single_receipt_failure() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash_ok = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let tx_hash_err = b256!("2222222222222222222222222222222222222222222222222222222222222222");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");

        let receipt_response = json!({
            "transactionHash": format!("{tx_hash_ok:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x5",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        let receipt_ok_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash_ok:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": receipt_response }).to_string())
            .expect(1)
            .create_async()
            .await;

        // Always fail; the test client retries, so assert it was hit at least once
        let receipt_err_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash_err:#x}")]
            })))
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let harness = test_utils::WatcherHarness::new(&server.url()).await;

        let create_tx = |hash: alloy::primitives::B256| BidirectionalTx {
            id: BidirectionalTxId(hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: hash.0,
            from_address: **from_address,
            nonce: 0,
        };

        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([1; 32]),
                Arc::new(create_tx(tx_hash_ok)),
            )
            .await;
        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([2; 32]),
                Arc::new(create_tx(tx_hash_err)),
            )
            .await;

        let mut block: Block = Block::default();
        block.header.number = 5;
        block.transactions = BlockTransactions::Hashes(vec![tx_hash_ok, tx_hash_err]);

        // One failing receipt must not fail the whole block
        let events = harness
            .watcher()
            .collect(&block)
            .await
            .expect("block processing should tolerate a single receipt failure");

        assert_eq!(
            events.len(),
            1,
            "only the successful receipt emits an event"
        );
        match &events[0] {
            ChainEvent::ExecutionConfirmed { tx_id, .. } => {
                assert_eq!(tx_id.0, tx_hash_ok.0);
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }

        // The failed watcher stays pending for a later retry
        let pending = harness
            .state_manager
            .get_execution_watchers(Chain::Ethereum)
            .await;
        assert!(
            pending.contains_key(&BidirectionalTxId(tx_hash_err.0)),
            "failed watcher should remain pending"
        );

        receipt_ok_mock.assert_async().await;
        receipt_err_mock.assert_async().await;
    }

    #[tokio::test]
    async fn watcher_resolution_tolerates_nonce_fetch_failure() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash = b256!("3333333333333333333333333333333333333333333333333333333333333333");

        // Nonce fetch always fails; watcher must stay pending without events
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
            })))
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        // No receipt fetch should happen for an unmined tx whose nonce is unknown
        let receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::Regex("eth_getTransactionReceipt".to_string()))
            .expect(0)
            .create_async()
            .await;

        let tx = BidirectionalTx {
            id: BidirectionalTxId(tx_hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: tx_hash.0,
            from_address: **from_address,
            nonce: 0,
        };

        let harness = test_utils::WatcherHarness::new(&server.url()).await;
        harness
            .state_manager
            .watch_execution(Chain::Ethereum, SignId::new([3; 32]), Arc::new(tx))
            .await;

        // Block height 10 triggers the throttled nonce check
        let mut block: Block = Block::default();
        block.header.number = 10;
        block.transactions = BlockTransactions::Hashes(Vec::new());

        let events = harness
            .watcher()
            .collect(&block)
            .await
            .expect("nonce fetch failure should not fail block processing");

        assert!(events.is_empty());
        let pending = harness
            .state_manager
            .get_execution_watchers(Chain::Ethereum)
            .await;
        assert!(pending.contains_key(&BidirectionalTxId(tx_hash.0)));

        nonce_mock.assert_async().await;
        receipt_mock.assert_async().await;
    }

    #[tokio::test]
    async fn new_watcher_resolves_at_appearance_block() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash = b256!("4444444444444444444444444444444444444444444444444444444444444444");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        let receipt_response = json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x3",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        // Nonce check pinned at block 5 (NOT a tick): one-shot
        // appearance gate fires immediately for newly seen watchers
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0x5"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1" }).to_string())
            .expect(1)
            .create_async()
            .await;

        // Receipt shows the tx already mined at block 3 (before registration)
        let receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": receipt_response }).to_string())
            .expect(1)
            .create_async()
            .await;

        let harness = test_utils::WatcherHarness::new(&server.url()).await;
        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([4; 32]),
                Arc::new(BidirectionalTx {
                    id: BidirectionalTxId(tx_hash.0),
                    sender: [0u8; 32],
                    serialized_transaction: vec![],
                    source_chain: Chain::Solana,
                    target_chain: Chain::Ethereum,
                    caip2_id: "eip155:31337".to_string(),
                    key_version: LATEST_MPC_KEY_VERSION,
                    deposit: 0,
                    path: "m/44'/60'/0'/0/0".to_string(),
                    algo: "secp256k1".to_string(),
                    dest: Chain::Ethereum.to_string(),
                    params: "{}".to_string(),
                    output_deserialization_schema: vec![],
                    respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
                    request_id: tx_hash.0,
                    from_address: **from_address,
                    nonce: 0,
                }),
            )
            .await;

        let mut block: Block = Block::default();
        block.header.number = 5;
        block.transactions = BlockTransactions::Hashes(Vec::new());

        let events = harness
            .watcher()
            .collect(&block)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id,
                block_height,
                result,
                ..
            } => {
                assert_eq!(tx_id.0, tx_hash.0);
                assert_eq!(*block_height, 3, "event height is the mined block");
                assert!(matches!(result, ExecutionOutcome::Failed));
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }

        nonce_mock.assert_async().await;
        receipt_mock.assert_async().await;
    }

    #[tokio::test]
    async fn failed_mined_receipt_retried_next_block() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash = b256!("5555555555555555555555555555555555555555555555555555555555555555");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        let receipt_response = json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x5",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        // Phase 1 (block 5): receipt RPC fails
        let failing_receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let harness = test_utils::WatcherHarness::new(&server.url()).await;
        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([5; 32]),
                Arc::new(BidirectionalTx {
                    id: BidirectionalTxId(tx_hash.0),
                    sender: [0u8; 32],
                    serialized_transaction: vec![],
                    source_chain: Chain::Solana,
                    target_chain: Chain::Ethereum,
                    caip2_id: "eip155:31337".to_string(),
                    key_version: LATEST_MPC_KEY_VERSION,
                    deposit: 0,
                    path: "m/44'/60'/0'/0/0".to_string(),
                    algo: "secp256k1".to_string(),
                    dest: Chain::Ethereum.to_string(),
                    params: "{}".to_string(),
                    output_deserialization_schema: vec![],
                    respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
                    request_id: tx_hash.0,
                    from_address: **from_address,
                    nonce: 0,
                }),
            )
            .await;

        let mut block5: Block = Block::default();
        block5.header.number = 5;
        block5.transactions = BlockTransactions::Hashes(vec![tx_hash]);

        let events = harness
            .watcher()
            .collect(&block5)
            .await
            .expect("receipt failure should not fail block processing");
        assert!(events.is_empty());
        failing_receipt_mock.assert_async().await;
        failing_receipt_mock.remove_async().await;

        // Phase 2 (block 6, NOT a tick): the failed watcher is retried via the
        // nonce gate without waiting for the next sweep
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0x6"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1" }).to_string())
            .expect(1)
            .create_async()
            .await;

        let receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": receipt_response }).to_string())
            .expect(1)
            .create_async()
            .await;

        let mut block6: Block = Block::default();
        block6.header.number = 6;
        block6.transactions = BlockTransactions::Hashes(Vec::new());

        let events = harness
            .watcher()
            .collect(&block6)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id,
                block_height,
                ..
            } => {
                assert_eq!(tx_id.0, tx_hash.0);
                assert_eq!(*block_height, 5, "event height is the mined block");
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }

        nonce_mock.assert_async().await;
        receipt_mock.assert_async().await;
    }

    #[tokio::test]
    async fn failed_nonce_fetch_retried_next_block() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash = b256!("6666666666666666666666666666666666666666666666666666666666666666");

        // Phase 1 (block 10, tick): nonce fetch fails
        let failing_nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
            })))
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let harness = test_utils::WatcherHarness::new(&server.url()).await;
        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([6; 32]),
                Arc::new(BidirectionalTx {
                    id: BidirectionalTxId(tx_hash.0),
                    sender: [0u8; 32],
                    serialized_transaction: vec![],
                    source_chain: Chain::Solana,
                    target_chain: Chain::Ethereum,
                    caip2_id: "eip155:31337".to_string(),
                    key_version: LATEST_MPC_KEY_VERSION,
                    deposit: 0,
                    path: "m/44'/60'/0'/0/0".to_string(),
                    algo: "secp256k1".to_string(),
                    dest: Chain::Ethereum.to_string(),
                    params: "{}".to_string(),
                    output_deserialization_schema: vec![],
                    respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
                    request_id: tx_hash.0,
                    from_address: **from_address,
                    nonce: 0,
                }),
            )
            .await;

        let mut block10: Block = Block::default();
        block10.header.number = 10;
        block10.transactions = BlockTransactions::Hashes(Vec::new());

        let events = harness
            .watcher()
            .collect(&block10)
            .await
            .expect("nonce failure should not fail block processing");
        assert!(events.is_empty());
        failing_nonce_mock.assert_async().await;
        failing_nonce_mock.remove_async().await;

        // Phase 2 (block 11, NOT a tick): retried via the nonce gate; nonce
        // consumed, no receipt -> Failed at block 11
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0xb"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1" }).to_string())
            .expect(1)
            .create_async()
            .await;

        let receipt_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": null }).to_string())
            .expect(1)
            .create_async()
            .await;

        let mut block11: Block = Block::default();
        block11.header.number = 11;
        block11.transactions = BlockTransactions::Hashes(Vec::new());

        let events = harness
            .watcher()
            .collect(&block11)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 1);
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id,
                block_height,
                result,
                ..
            } => {
                assert_eq!(tx_id.0, tx_hash.0);
                assert_eq!(*block_height, 11);
                assert!(matches!(result, ExecutionOutcome::Failed));
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }

        nonce_mock.assert_async().await;
        receipt_mock.assert_async().await;
    }

    /// A successful receipt for a tx mined in `block_number`.
    fn success_receipt(
        tx_hash: alloy::primitives::B256,
        from_address: alloy::primitives::Address,
        block_number: u64,
    ) -> serde_json::Value {
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        json!({
            "transactionHash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": format!("0x{block_number:x}"),
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x1"
        })
    }

    /// A contract-call transaction body (non-empty calldata) for
    /// `eth_getTransactionByHash`, so extraction takes the trace path.
    fn contract_call_transaction(
        tx_hash: alloy::primitives::B256,
        from_address: alloy::primitives::Address,
        to_address: alloy::primitives::Address,
    ) -> serde_json::Value {
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        json!({
            "hash": format!("{tx_hash:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x5",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{to_address:#x}"),
            "value": "0x0",
            "gas": "0x5208",
            "gasPrice": "0x3a29f0f8",
            "input": "0xa9059cbb00",
            "nonce": "0x0",
            "type": "0x0",
            "v": "0x1b",
            "r": format!("{block_hash:#x}"),
            "s": format!("{block_hash:#x}"),
        })
    }

    /// Watcher tx with an empty output schema: any trace return data then
    /// contradicts the declared schema, which is a deterministic (terminal)
    /// extraction failure.
    fn empty_output_schema_tx(
        tx_hash: alloy::primitives::B256,
        from_address: alloy::primitives::Address,
    ) -> BidirectionalTx {
        BidirectionalTx {
            id: BidirectionalTxId(tx_hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: b"[]".to_vec(),
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: tx_hash.0,
            from_address: **from_address,
            nonce: 0,
        }
    }

    /// A deterministic extraction failure — trace return data that contradicts
    /// the declared output schema — resolves the execution as failed instead of
    /// silently dropping the event and wedging the request.
    #[tokio::test]
    async fn terminal_extraction_failure_emits_failed_event() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let to_address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");
        let tx_hash = b256!("9999999999999999999999999999999999999999999999999999999999999999");

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({ "jsonrpc": "2.0", "id": 1, "result": success_receipt(tx_hash, from_address, 5) })
                    .to_string(),
            )
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionByHash",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": contract_call_transaction(tx_hash, from_address, to_address),
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Trace returns 32 bytes of return data while the tx declares an empty
        // output schema: unrecoverable for every node, not just this one.
        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "debug_traceTransaction",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "type": "CALL",
                        "output": format!("0x{}", "0".repeat(63) + "1"),
                    },
                })
                .to_string(),
            )
            .create_async()
            .await;

        let harness = test_utils::WatcherHarness::new(&server.url()).await;
        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([9; 32]),
                Arc::new(empty_output_schema_tx(tx_hash, from_address)),
            )
            .await;

        let mut block: Block = Block::default();
        block.header.number = 5;
        block.transactions = BlockTransactions::Hashes(vec![tx_hash]);

        let events = harness
            .watcher()
            .collect(&block)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 1, "terminal failure emits exactly one event");
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id,
                block_height,
                result,
                ..
            } => {
                assert_eq!(tx_id.0, tx_hash.0);
                assert_eq!(*block_height, 5, "event height is the mined block");
                assert!(matches!(result, ExecutionOutcome::Failed));
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }

        assert_eq!(harness.telemetry.terminal_failures(), 1);
        assert_eq!(harness.telemetry.retryable_failures(), 0);
    }

    /// A trace RPC failure is node-local: emit nothing (a peer with a healthy
    /// endpoint still resolves the execution) and retry on the very next block
    /// rather than waiting for the slow sweep.
    #[tokio::test]
    async fn retryable_extraction_failure_retries_next_block() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let to_address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");
        let tx_hash = b256!("aaaa000000000000000000000000000000000000000000000000000000000000");

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({ "jsonrpc": "2.0", "id": 1, "result": success_receipt(tx_hash, from_address, 5) })
                    .to_string(),
            )
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionByHash",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": contract_call_transaction(tx_hash, from_address, to_address),
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Phase 1 (block 5): the trace endpoint is down.
        let failing_trace_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "debug_traceTransaction",
            })))
            .with_status(500)
            .expect_at_least(1)
            .create_async()
            .await;

        let harness = test_utils::WatcherHarness::new(&server.url()).await;
        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([0xaa; 32]),
                Arc::new(empty_output_schema_tx(tx_hash, from_address)),
            )
            .await;

        let mut block5: Block = Block::default();
        block5.header.number = 5;
        block5.transactions = BlockTransactions::Hashes(vec![tx_hash]);

        let events = harness
            .watcher()
            .collect(&block5)
            .await
            .expect("trace failure should not fail block processing");

        assert!(events.is_empty(), "a node-local failure emits no event");
        assert_eq!(harness.telemetry.retryable_failures(), 1);
        assert_eq!(harness.telemetry.terminal_failures(), 0);
        assert!(
            harness
                .state_manager
                .get_execution_watchers(Chain::Ethereum)
                .await
                .contains_key(&BidirectionalTxId(tx_hash.0)),
            "watcher stays pending for retry"
        );
        failing_trace_mock.assert_async().await;
        failing_trace_mock.remove_async().await;

        // Phase 2 (block 6, NOT a sweep tick): the retry set drives a fresh
        // attempt; the trace now succeeds with the empty return data the
        // schema declares.
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
                "params": [format!("{from_address:#x}"), "0x6"]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x1" }).to_string())
            .expect(1)
            .create_async()
            .await;

        let trace_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "debug_traceTransaction",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": { "type": "CALL", "output": "0x" },
                })
                .to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let mut block6: Block = Block::default();
        block6.header.number = 6;
        block6.transactions = BlockTransactions::Hashes(Vec::new());

        let events = harness
            .watcher()
            .collect(&block6)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 1, "the retry resolves the execution");
        match &events[0] {
            ChainEvent::ExecutionConfirmed {
                tx_id,
                block_height,
                result,
                ..
            } => {
                assert_eq!(tx_id.0, tx_hash.0);
                assert_eq!(*block_height, 5, "event height is the mined block");
                assert!(matches!(result, ExecutionOutcome::Success { .. }));
            }
            other => panic!("expected ExecutionConfirmed, got {other:?}"),
        }
        assert_eq!(
            harness.telemetry.retryable_failures(),
            1,
            "no further failures once the endpoint recovers"
        );

        nonce_mock.assert_async().await;
        trace_mock.assert_async().await;
    }

    /// A malformed `debug_traceTransaction` payload is provider output, not
    /// on-chain data: two nodes can see different responses, so it must take
    /// the retryable path rather than unilaterally failing the request.
    #[tokio::test]
    async fn malformed_trace_response_is_retryable() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let to_address = address!("5fbdb2315678afecb367f032d93f642f64180aa3");
        let tx_hash = b256!("bbbb000000000000000000000000000000000000000000000000000000000000");

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({ "jsonrpc": "2.0", "id": 1, "result": success_receipt(tx_hash, from_address, 5) })
                    .to_string(),
            )
            .create_async()
            .await;

        server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionByHash",
                "params": [format!("{tx_hash:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": contract_call_transaction(tx_hash, from_address, to_address),
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Not a call frame at all.
        let trace_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "debug_traceTransaction",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({ "jsonrpc": "2.0", "id": 1, "result": "not-a-call-frame" }).to_string(),
            )
            .expect_at_least(1)
            .create_async()
            .await;

        let harness = test_utils::WatcherHarness::new(&server.url()).await;
        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([0xbb; 32]),
                Arc::new(empty_output_schema_tx(tx_hash, from_address)),
            )
            .await;

        let mut block: Block = Block::default();
        block.header.number = 5;
        block.transactions = BlockTransactions::Hashes(vec![tx_hash]);

        let events = harness
            .watcher()
            .collect(&block)
            .await
            .expect("malformed trace should not fail block processing");

        assert!(
            events.is_empty(),
            "malformed provider output emits no event"
        );
        assert_eq!(harness.telemetry.retryable_failures(), 1);
        assert_eq!(harness.telemetry.terminal_failures(), 0);
        assert!(
            harness
                .state_manager
                .get_execution_watchers(Chain::Ethereum)
                .await
                .contains_key(&BidirectionalTxId(tx_hash.0)),
            "watcher stays pending for retry"
        );
        trace_mock.assert_async().await;
    }

    #[tokio::test]
    async fn replaced_sibling_fails_at_replacement_block_without_rpc() {
        let mut server = Server::new_async().await;

        let from_address = address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266");
        let tx_hash_a = b256!("7777777777777777777777777777777777777777777777777777777777777777");
        let tx_hash_b = b256!("8888888888888888888888888888888888888888888888888888888888888888");
        let block_hash = b256!("6e4e53d1de650d5a5ebed19b38321db369ef1dc357904284ecf4d89b8834969c");
        let receipt_response = json!({
            "transactionHash": format!("{tx_hash_a:#x}"),
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x5",
            "transactionIndex": "0x0",
            "from": format!("{from_address:#x}"),
            "to": format!("{from_address:#x}"),
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x3a29f0f8",
            "contractAddress": null,
            "logsBloom": format!("0x{}", "0".repeat(512)),
            "cumulativeGasUsed": "0x5208",
            "type": "0x2",
            "logs": [],
            "status": "0x0"
        });

        // Phase 1 (block 4): both watchers appear; one-shot gate checks the
        // (deduped) sender once, nonce not yet consumed
        let nonce_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionCount",
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": "0x0" }).to_string())
            .expect(1)
            .create_async()
            .await;

        let receipt_a_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash_a:#x}")]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({ "jsonrpc": "2.0", "id": 1, "result": receipt_response }).to_string())
            .expect(1)
            .create_async()
            .await;

        // The replaced sibling must never be queried over RPC
        let receipt_b_mock = server
            .mock("POST", "/")
            .match_body(Matcher::PartialJson(json!({
                "method": "eth_getTransactionReceipt",
                "params": [format!("{tx_hash_b:#x}")]
            })))
            .expect(0)
            .create_async()
            .await;

        let harness = test_utils::WatcherHarness::new(&server.url()).await;
        let create_tx = |hash: alloy::primitives::B256| BidirectionalTx {
            id: BidirectionalTxId(hash.0),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:31337".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/44'/60'/0'/0/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
            request_id: hash.0,
            from_address: **from_address,
            nonce: 0,
        };

        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([7; 32]),
                Arc::new(create_tx(tx_hash_a)),
            )
            .await;
        harness
            .state_manager
            .watch_execution(
                Chain::Ethereum,
                SignId::new([8; 32]),
                Arc::new(create_tx(tx_hash_b)),
            )
            .await;

        let mut block4: Block = Block::default();
        block4.header.number = 4;
        block4.transactions = BlockTransactions::Hashes(Vec::new());

        let events = harness
            .watcher()
            .collect(&block4)
            .await
            .expect("should succeed");
        assert!(events.is_empty());
        nonce_mock.assert_async().await;
        nonce_mock.remove_async().await;

        // Phase 2 (block 5, NOT a tick): tx A mines; sibling B is failed
        // purely from local watcher state, no nonce RPC
        let mut block5: Block = Block::default();
        block5.header.number = 5;
        block5.transactions = BlockTransactions::Hashes(vec![tx_hash_a]);

        let events = harness
            .watcher()
            .collect(&block5)
            .await
            .expect("should succeed");

        assert_eq!(events.len(), 2);
        let mut resolved: Vec<_> = events
            .iter()
            .map(|e| match e {
                ChainEvent::ExecutionConfirmed {
                    tx_id,
                    block_height,
                    result,
                    ..
                } => {
                    assert_eq!(*block_height, 5, "both events at the replacement block");
                    assert!(matches!(result, ExecutionOutcome::Failed));
                    tx_id.0
                }
                other => panic!("expected ExecutionConfirmed, got {other:?}"),
            })
            .collect();
        resolved.sort();
        let mut expected = vec![tx_hash_a.0, tx_hash_b.0];
        expected.sort();
        assert_eq!(resolved, expected);

        receipt_a_mock.assert_async().await;
        receipt_b_mock.assert_async().await;
    }
}
