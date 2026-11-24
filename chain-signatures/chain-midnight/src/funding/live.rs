use super::*;
use crate::dust_feed::IndexerDustEvents;
use mpc_chain_integration_core::NoopPublisherTelemetry;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

/// A checkpoint in a file, as the node keeps one in Redis.
struct FileCheckpoints(std::path::PathBuf);

#[async_trait::async_trait]
impl DustCheckpointStore for FileCheckpoints {
    async fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
        match std::fs::read(&self.0) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn save(&self, checkpoint: &[u8]) -> anyhow::Result<()> {
        Ok(std::fs::write(&self.0, checkpoint)?)
    }

    async fn clear(&self) -> anyhow::Result<()> {
        Ok(std::fs::remove_file(&self.0)?)
    }
}

/// With `MIDNIGHT_LIVE_DUST_CHECKPOINT` naming a file, a first run replays and
/// keeps its checkpoint there, and a second run resumes from it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs MIDNIGHT_LIVE_INDEXER_WS_URL; replays that indexer's whole DUST history"]
async fn a_wallet_replays_a_live_indexer_to_its_newest_event() {
    let url = std::env::var("MIDNIGHT_LIVE_INDEXER_WS_URL")
        .ok()
        .and_then(|url| url.parse().ok())
        .expect("MIDNIGHT_LIVE_INDEXER_WS_URL must be a URL");
    let file = std::env::var("MIDNIGHT_LIVE_DUST_CHECKPOINT")
        .ok()
        .map(std::path::PathBuf::from);
    let resuming = file.as_ref().is_some_and(|file| file.exists());
    let checkpoints = file
        .clone()
        .map(|file| Arc::new(FileCheckpoints(file)) as Arc<dyn DustCheckpointStore>);
    let started = std::time::Instant::now();
    let key = dust_secret_key(&[0x42; 32]).unwrap();
    let wallet = FundingWallet::start(
        key,
        Arc::new(IndexerDustEvents::new(url)),
        checkpoints,
        Arc::new(NoopPublisherTelemetry),
    );
    wallet
        .ready_by(Instant::now() + Duration::from_secs(1800))
        .await
        .unwrap();
    let ready_after = started.elapsed();
    if let (Some(file), false) = (&file, resuming) {
        while !file.exists() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!(
            "kept a {} byte checkpoint",
            std::fs::metadata(file).unwrap().len()
        );
    }
    let indexed = wallet.indexed_time().await.unwrap();
    let state = wallet.shared.state();
    println!("the indexer's newest block is at {indexed:?}");
    println!(
        "replayed to event {:?} of {} in {:?} (resumed from a checkpoint: {resuming}); \
             synced to {:?}",
        state.applied, state.max_id, ready_after, state.local.sync_time
    );
}
