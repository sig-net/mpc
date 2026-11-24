//! The DUST checkpoint: the replayed state serialized for the node's store.
//!
//! The wire format is hand-rolled — magic, fixed little-endian fields, then the
//! `tagged_serialize`d `DustLocalState` — and pinned by the
//! `a_checkpoint_keeps_its_stored_layout` test, so a format change must update that
//! pin and a migration story.

use anyhow::Context as _;
use midnight_ledger_v9::dust::DustLocalState;
use midnight_storage::DefaultDB;

/// The least time between two checkpoints a caught-up replay keeps; the first after a
/// start, a forget or a replay from the first event is kept at once.
pub const CHECKPOINT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);
/// How long loading or keeping a checkpoint may take.
pub const CHECKPOINT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const CHECKPOINT_MAGIC: &[u8; 16] = b"mpc-dust-ckpt-v1";

/// Where the funding wallet keeps a checkpoint of its replay across restarts. The
/// checkpoint holds the replayed DUST state, never the secret key.
#[async_trait::async_trait]
pub trait DustCheckpointStore: Send + Sync {
    async fn load(&self) -> anyhow::Result<Option<Vec<u8>>>;
    async fn save(&self, checkpoint: &[u8]) -> anyhow::Result<()>;
    async fn clear(&self) -> anyhow::Result<()>;
}

/// The replayed state after event `applied`, for the key whose public key hashes to
/// `owner`. A restart resumes from it only when the indexer still serves the same
/// event at `applied`, which `super::sync::event_hash` checks.
#[derive(Clone)]
pub struct Checkpoint {
    pub owner: [u8; 32],
    pub applied: u64,
    pub event_hash: [u8; 32],
    pub local: DustLocalState<DefaultDB>,
}

impl Checkpoint {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&self.applied.to_le_bytes());
        bytes.extend_from_slice(&self.event_hash);
        midnight_serialize::tagged_serialize(&self.local, &mut bytes)
            .expect("serializing into a Vec cannot fail");
        bytes
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let rest = bytes
            .strip_prefix(CHECKPOINT_MAGIC.as_slice())
            .context("not a DUST checkpoint of this format")?;
        anyhow::ensure!(rest.len() >= 72, "the DUST checkpoint is truncated");
        let (owner, rest) = rest.split_at(32);
        let (applied, rest) = rest.split_at(8);
        let (event_hash, mut state) = rest.split_at(32);
        Ok(Self {
            owner: owner.try_into().expect("split at 32"),
            applied: u64::from_le_bytes(applied.try_into().expect("split at 8")),
            event_hash: event_hash.try_into().expect("split at 32"),
            local: midnight_serialize::tagged_deserialize(&mut state)
                .context("the checkpointed DUST state did not decode")?,
        })
    }
}
