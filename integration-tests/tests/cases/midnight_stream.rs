use std::collections::BTreeSet;
use std::io::Write as _;
use std::time::Duration;

use alloy::providers::ext::AnvilApi as _;
use alloy::providers::{Provider as _, ProviderBuilder};
use anyhow::Context as _;
use integration_tests::cluster;
use mpc_chain_integration_core::utils::test::ChainIndexerStream;
use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
use mpc_chain_midnight::MidnightIndexer;
use mpc_primitives::{Chain, ChainEvent, SignKind};
use serial_test::serial;
use test_log::test;

const EVENT_TIMEOUT: Duration = Duration::from_secs(8 * 60);

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
                                .all(|pending| pending.sign_id().request_id != request_id);
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

#[derive(Default)]
struct VaultIndexedEvents {
    requested: BTreeSet<[u8; 32]>,
    responded: BTreeSet<[u8; 32]>,
    attested: BTreeSet<[u8; 32]>,
}

impl VaultIndexedEvents {
    fn record(&mut self, event: &ChainEvent, log: &mut std::fs::File) -> anyhow::Result<()> {
        let entry = match event {
            ChainEvent::SignRequest { request, .. }
                if request.chain == Chain::Midnight
                    && matches!(request.kind, SignKind::SignBidirectional(_)) =>
            {
                self.requested.insert(request.id.request_id);
                serde_json::json!({
                    "event": "SignRequest",
                    "requestId": hex::encode(request.id.request_id),
                })
            }
            ChainEvent::Respond(response) if response.chain == Chain::Midnight => {
                self.responded.insert(response.request_id);
                serde_json::json!({
                    "event": "Respond",
                    "requestId": hex::encode(response.request_id),
                })
            }
            ChainEvent::RespondBidirectional(response) if response.chain == Chain::Midnight => {
                self.attested.insert(response.request_id);
                serde_json::json!({
                    "event": "RespondBidirectional",
                    "requestId": hex::encode(response.request_id),
                })
            }
            ChainEvent::Block(height) => serde_json::json!({"event": "Block", "height": height}),
            _ => serde_json::json!({"event": format!("{event:?}")}),
        };
        serde_json::to_writer(&mut *log, &entry)?;
        writeln!(log)?;
        log.flush()?;
        Ok(())
    }

    fn contains_round_trip(&self, request_id: &[u8; 32]) -> bool {
        self.requested.contains(request_id)
            && self.responded.contains(request_id)
            && self.attested.contains(request_id)
    }
}

async fn wait_for_vault_ethereum_checkpoint(
    cluster: &cluster::Cluster,
    head: u64,
    log: &mut std::fs::File,
) -> anyhow::Result<()> {
    tokio::time::timeout(EVENT_TIMEOUT, async {
        loop {
            let mut checkpoints = Vec::with_capacity(cluster.len());
            for node in 0..cluster.len() {
                checkpoints.push(
                    cluster.nodes.fetch_checkpoint(node, Chain::Ethereum).await
                        .ok().map(|checkpoint| checkpoint.block_height),
                );
            }
            let ready = checkpoints.iter().all(|height| height.is_some_and(|height| height >= head));
            serde_json::to_writer(&mut *log, &serde_json::json!({
                "event": "checkpointBarrier", "head": head, "checkpoints": checkpoints, "ready": ready,
            }))?;
            writeln!(log)?;
            log.flush()?;
            if ready {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }).await.with_context(|| format!("waiting for every Ethereum checkpoint to reach Anvil head {head}"))??;
    Ok(())
}

async fn mine_vault_blocks(
    cluster: &cluster::Cluster,
    evm_rpc_url: &str,
    log: &mut std::fs::File,
) -> anyhow::Result<()> {
    let anvil = ProviderBuilder::new().connect_http(evm_rpc_url.parse()?);
    loop {
        let head = anvil.get_block_number().await?;
        // Anvil historical nonce reads require a stable head during block indexing.
        // Ethereum checkpoints follow the block's awaited execution-watcher reads.
        wait_for_vault_ethereum_checkpoint(cluster, head, log).await?;
        anvil.anvil_mine(Some(1), None).await?;
        serde_json::to_writer(
            &mut *log,
            &serde_json::json!({
                "event": "mined", "previousHead": head, "head": anvil.get_block_number().await?,
            }),
        )?;
        writeln!(log)?;
        log.flush()?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[ignore = "starts the real Midnight/MPC stack and a pinned Sepolia Anvil fork; requires MIDNIGHT_VAULT_FORK_URL and MIDNIGHT_VAULT_FORK_BLOCK"]
#[serial]
#[test(tokio::test)]
async fn midnight_vault_operations_complete_with_real_mpc() -> anyhow::Result<()> {
    anyhow::ensure!(
        std::env::var("CHECKPOINT_INTERVAL_ETHEREUM").as_deref() == Ok("1"),
        "controlled Anvil mining requires CHECKPOINT_INTERVAL_ETHEREUM=1 so each mined block can reach the checkpoint barrier"
    );
    let fork_url =
        std::env::var("MIDNIGHT_VAULT_FORK_URL").context("MIDNIGHT_VAULT_FORK_URL is required")?;
    let fork_block = std::env::var("MIDNIGHT_VAULT_FORK_BLOCK")
        .context("MIDNIGHT_VAULT_FORK_BLOCK is required")?
        .parse::<u64>()
        .context("MIDNIGHT_VAULT_FORK_BLOCK must be a block number")?;
    let cluster = cluster::spawn()
        .ethereum_fork(fork_url, fork_block)
        .midnight()
        .await?;
    cluster.wait().signable().await?;
    let midnight = cluster
        .midnight
        .as_ref()
        .context("Midnight context was not started")?;
    let ethereum = cluster
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("Ethereum context was not started")?;
    let indexer = MidnightIndexer::new(
        midnight.config.clone(),
        MockStateManager::new(),
        NoopChainTelemetry,
    )
    .await?;
    let mut events = ChainIndexerStream::start(indexer, EVENT_TIMEOUT).await?;
    let mut event_log = std::fs::File::create(midnight.artifact_dir().join("vault-events.jsonl"))?;
    let mut mining_log =
        std::fs::File::create(midnight.artifact_dir().join("ethereum-mining.jsonl"))?;
    let anvil =
        ProviderBuilder::new().connect_http(ethereum.sandbox.external_http_endpoint.parse()?);
    anvil.anvil_set_interval_mining(0).await?;
    anvil.anvil_set_auto_mine(false).await?;
    // Before the driver starts, no vault execution watchers exist. This empty
    // block lets an indexer anchored at the next block establish its checkpoint.
    anvil.anvil_mine(Some(1), None).await?;
    let initial_head = anvil.get_block_number().await?;
    serde_json::to_writer(
        &mut mining_log,
        &serde_json::json!({
            "event": "bootstrapBlock", "head": initial_head,
        }),
    )?;
    writeln!(mining_log)?;
    mining_log.flush()?;
    wait_for_vault_ethereum_checkpoint(&cluster, initial_head, &mut mining_log).await?;
    let mining = mine_vault_blocks(
        &cluster,
        &ethereum.sandbox.external_http_endpoint,
        &mut mining_log,
    );
    tokio::pin!(mining);
    let mut observed = VaultIndexedEvents::default();
    let run = midnight.drive_vault(&ethereum.sandbox.external_http_endpoint);
    tokio::pin!(run);
    let result = tokio::time::timeout(Duration::from_secs(60 * 60), async {
        loop {
            tokio::select! {
                result = &mut run => return result,
                result = &mut mining => {
                    result.context("controlled Anvil mining failed")?;
                    anyhow::bail!("controlled Anvil mining stopped before the vault driver finished");
                }
                event = events.next_event() => {
                    let event = event.context("Midnight indexer stopped during the vault flow")?;
                    observed.record(&event, &mut event_log)?;
                }
            }
        }
    })
    .await
    .context("vault operations exceeded the one-hour run limit")??;

    let expected_operations = BTreeSet::from([
        "deposit",
        "withdraw",
        "depositSwap",
        "approveRouter",
        "swap",
        "depositSupply",
        "approveStata",
        "supply",
        "redeem",
    ]);
    let operations = result
        .operations
        .iter()
        .map(|operation| operation.operation.as_str())
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        operations == expected_operations && result.operations.len() == expected_operations.len(),
        "expected exactly the nine vault operations, received {operations:?}"
    );
    let mut request_ids = BTreeSet::new();
    for operation in &result.operations {
        let Some(encoded_request_id) = &operation.request_id else {
            anyhow::ensure!(
                !operation.succeeded,
                "successful vault operation {} omitted its request ID",
                operation.operation
            );
            continue;
        };
        let mut request_id = [0; 32];
        hex::decode_to_slice(encoded_request_id.trim_start_matches("0x"), &mut request_id)
            .with_context(|| format!("invalid request ID for {}", operation.operation))?;
        anyhow::ensure!(
            request_ids.insert(request_id),
            "vault driver repeated a request ID"
        );
    }

    let unsuccessful = result
        .operations
        .iter()
        .filter(|operation| !operation.succeeded)
        .collect::<Vec<_>>();
    if !unsuccessful.is_empty() {
        midnight.shutdown().await?;
        anyhow::bail!(
            "vault integration test completed with failed or blocked operations: {}",
            serde_json::to_string(&unsuccessful)?
        );
    }

    tokio::time::timeout(EVENT_TIMEOUT, async {
        while !request_ids
            .iter()
            .all(|request_id| observed.contains_round_trip(request_id))
        {
            let event = events
                .next_event()
                .await
                .context("Midnight indexer stopped before all vault responses")?;
            observed.record(&event, &mut event_log)?;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context(
        "waiting for every vault request's SignRequest, Respond, and RespondBidirectional events",
    )??;
    let final_block = tokio::time::timeout(EVENT_TIMEOUT, async {
        loop {
            let event = events
                .next_event()
                .await
                .context("Midnight indexer stopped before the final block")?;
            observed.record(&event, &mut event_log)?;
            if let ChainEvent::Block(height) = event {
                return Ok::<_, anyhow::Error>(height);
            }
        }
    })
    .await
    .context("waiting for a block after all vault responses")??;
    for request_id in request_ids {
        wait_for_completed_checkpoint(&cluster, request_id, final_block).await?;
    }
    midnight.shutdown().await?;
    Ok(())
}
