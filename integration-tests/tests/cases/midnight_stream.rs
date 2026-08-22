use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{keccak256, Address, Bytes, U256};
use alloy::providers::ext::AnvilApi as _;
use alloy::providers::{Provider as _, ProviderBuilder};
use anyhow::Context as _;
use integration_tests::cluster;
use mpc_chain_integration_core::{ChainIndexer as _, MockStateManager, NoopChainTelemetry};
use mpc_chain_midnight::MidnightIndexer;
use mpc_node::sign_bidirectional::{derive_user_address, SignBidirectionalEventExt as _};
use mpc_primitives::{Chain, ChainEvent, IndexedSignRequest, SignKind};
use serial_test::serial;
use test_log::test;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const EVENT_TIMEOUT: Duration = Duration::from_secs(8 * 60);
const RETURN_TRUE_RUNTIME_BYTECODE: &str = "600160005260206000f3";

struct MidnightEvents {
    rx: mpsc::Receiver<ChainEvent>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn wait_for_completed_checkpoint(
    cluster: &cluster::Cluster,
    request_id: [u8; 32],
    minimum_height: u64,
) -> anyhow::Result<()> {
    tokio::time::timeout(EVENT_TIMEOUT, async {
        loop {
            let mut complete = true;
            for node in 0..cluster.len() {
                match cluster.nodes.fetch_checkpoint(node, Chain::Midnight).await {
                    Ok(checkpoint) => {
                        complete &= checkpoint.block_height >= minimum_height
                            && checkpoint
                                .pending_requests
                                .iter()
                                .all(|pending| pending.sign_id.request_id != request_id);
                    }
                    Err(_) => complete = false,
                }
            }
            if complete {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .context("timed out waiting for every MPC node to checkpoint final Midnight completion")??;
    Ok(())
}

impl MidnightEvents {
    async fn start(config: mpc_chain_midnight::MidnightConfig) -> anyhow::Result<Self> {
        let indexer =
            MidnightIndexer::new(config, MockStateManager::new(), NoopChainTelemetry).await?;
        let (tx, rx) = mpsc::channel(16_384);
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move { indexer.run(tx, task_cancel).await });
        let mut events = Self { rx, cancel, task };
        events
            .wait_for("catchup completion", |event| {
                matches!(event, ChainEvent::CatchupCompleted).then_some(())
            })
            .await?;
        Ok(events)
    }

    async fn wait_for<T>(
        &mut self,
        description: &str,
        mut take: impl FnMut(ChainEvent) -> Option<T>,
    ) -> anyhow::Result<T> {
        tokio::time::timeout(EVENT_TIMEOUT, async {
            loop {
                let event =
                    self.rx.recv().await.with_context(|| {
                        format!("Midnight indexer stopped before {description}")
                    })?;
                if let Some(value) = take(event) {
                    return Ok(value);
                }
            }
        })
        .await
        .with_context(|| format!("timed out waiting for {description}"))?
    }

    async fn shutdown(self) -> anyhow::Result<()> {
        self.cancel.cancel();
        self.task
            .await
            .context("joining Midnight event monitor")??;
        Ok(())
    }
}

#[ignore = "starts a real Midnight node, indexer, proof server, Anvil, and MPC cluster"]
#[serial]
#[test(tokio::test)]
async fn midnight_to_ethereum_to_midnight_consumes_caller_response() -> anyhow::Result<()> {
    let cluster = cluster::spawn().ethereum().midnight().await?;
    cluster.wait().signable().await?;
    let midnight = cluster
        .midnight
        .as_ref()
        .context("Midnight context was not started")?;
    let mut events = MidnightEvents::start(midnight.config.clone()).await?;

    let ethereum = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("Ethereum context was not started")?;
    let anvil =
        ProviderBuilder::new().connect_http(ethereum.sandbox.external_http_endpoint.parse()?);
    let target = Address::repeat_byte(0x42);
    anvil
        .anvil_set_code(
            target,
            Bytes::from(hex::decode(RETURN_TRUE_RUNTIME_BYTECODE)?),
        )
        .await?;

    let mut argument = [0; 32];
    argument[31] = 6;
    midnight
        .submit_is_even(0, target.into_array(), argument)
        .await?;
    let request: Arc<IndexedSignRequest> = events
        .wait_for("the caller SignRequest", |event| match event {
            ChainEvent::SignRequest { request, .. }
                if request.chain == Chain::Midnight
                    && matches!(request.kind, SignKind::SignBidirectional(_)) =>
            {
                Some(request)
            }
            _ => None,
        })
        .await?;
    let request_id = request.id.request_id;
    let SignKind::SignBidirectional(sign_event) = &request.kind else {
        unreachable!("filtered above")
    };
    assert_eq!(sign_event.caip2_id, Chain::Ethereum.caip2_chain_id());

    events
        .wait_for("the finalized respond entry", |event| {
            matches!(event, ChainEvent::Respond(response) if response.request_id == request_id)
                .then_some(())
        })
        .await?;
    let root_public_key =
        mpc_crypto::near_public_key_to_affine_point(cluster.root_public_key().await?);
    let expected_sender = derive_user_address(root_public_key, sign_event.epsilon()?);
    let signed = midnight
        .signed_evm_transaction(request_id, &format!("{expected_sender:#x}"))
        .await?;
    assert_eq!(signed.from.parse::<Address>()?, expected_sender);
    assert_eq!(signed.to.parse::<Address>()?, target);
    assert_eq!(signed.chain_id, "31337");
    assert_eq!(
        signed.unsigned_hash,
        format!("{:#x}", keccak256(&sign_event.serialized_transaction))
    );
    let mut expected_input = hex::decode("2a2e1320")?;
    expected_input.extend_from_slice(&argument);
    assert_eq!(
        hex::decode(signed.data.trim_start_matches("0x"))?,
        expected_input
    );
    anvil
        .anvil_set_balance(expected_sender, U256::from(10_000_000_000_000_000_000u128))
        .await?;
    let pending = anvil
        .send_raw_transaction(&hex::decode(signed.serialized.trim_start_matches("0x"))?)
        .await?;
    let receipt = pending.get_receipt().await?;
    anyhow::ensure!(receipt.status(), "the MPC-signed EVM transaction reverted");

    events
        .wait_for("the finalized respondBidirectional entry", |event| {
            matches!(
                event,
                ChainEvent::RespondBidirectional(response) if response.request_id == request_id
            )
            .then_some(())
        })
        .await?;
    midnight.settle_response(request_id).await?;
    let final_block = events
        .wait_for("a block after respondBidirectional", |event| match event {
            ChainEvent::Block(height) => Some(height),
            _ => None,
        })
        .await?;
    wait_for_completed_checkpoint(&cluster, request_id, final_block).await?;
    events.shutdown().await?;
    midnight.shutdown().await?;
    Ok(())
}
