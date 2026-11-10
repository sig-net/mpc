//! The funding wallet: the DUST that pays every respond transaction's fee.
//!
//! Spendable DUST is derived by replaying the ledger's DUST events into a
//! `DustLocalState`, the same state the Midnight wallet SDK keeps; no node RPC serves
//! it. The state lives in memory. A checkpoint of it, kept in the node's store, lets a
//! restart resume the replay instead of starting it over from the first event.
//!
//! The wallet never adopts the pending marks `DustLocalState::spend` sets on its
//! scratch copy. It reserves the UTXOs a submitted transaction spends instead, and a
//! reservation ends when the chain spends them, when the transaction is refused, never
//! sent, or seen expired, or a minute after the transaction's TTL, by when it has
//! landed or never will.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use futures_util::StreamExt as _;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::TokenType;
use midnight_ledger_v9::dust::{
    DustActions, DustLocalState, DustNullifier, DustOutput, DustSecretKey, QualifiedDustOutput,
};
use midnight_ledger_v9::events::Event;
use midnight_ledger_v9::structure::{
    Intent, LedgerParameters, ProofPreimageMarker, Signature, Transaction, INITIAL_PARAMETERS,
};
use midnight_storage::arena::Sp;
use midnight_storage::DefaultDB;
use midnight_transient_crypto::commitment::PedersenRandomness;
use mpc_utils::task::AbortOnDrop;
use rand::rngs::StdRng;
use rand::{CryptoRng, Rng};
use sha2::Digest as _;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::dust_feed::{DustEventSource, DustEventUpdate};
use crate::submit_error::SubmitError;

/// A proven respond transaction, sealed: what the fee is paid for.
pub(crate) type SealedTx = minocrab_publisher::intent::SealedTx<DefaultDB>;
/// The fee-paying transaction, before its DUST spend proof.
pub(crate) type UnprovenTx = minocrab_publisher::intent::PreimageTx<DefaultDB>;

/// The fee is priced as the wallet SDK prices it: this many blocks of the largest
/// price rise the ledger allows, so a transaction priced now still pays when it lands.
const FEE_BLOCKS_MARGIN: usize = 5;
/// Each pass adds what the previous spends cost on top; two or three passes settle.
const FEE_PASSES: usize = 8;
/// Events applied per replay; a batch only bounds how long the state lock is held.
const REPLAY_BATCH: usize = 512;
/// Backoff between subscription attempts.
const RESUBSCRIBE_DELAY: std::time::Duration = std::time::Duration::from_secs(2);
/// The longest backoff between subscriptions the indexer keeps refusing to open.
const MAX_REFUSED_DELAY: std::time::Duration = std::time::Duration::from_secs(60);
/// The longest backoff between replays that keep restarting from the first event.
const MAX_RESTART_DELAY: std::time::Duration = std::time::Duration::from_secs(600);
/// The least time between two checkpoints a caught-up replay keeps; the first after a
/// start, a forget or a replay from the first event is kept at once.
const CHECKPOINT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);
/// How long loading or keeping a checkpoint may take.
const CHECKPOINT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const CHECKPOINT_MAGIC: &[u8; 16] = b"mpc-dust-ckpt-v1";
/// How long a resumed subscription may stay silent before the checkpoint is dropped:
/// the indexer serves the checkpoint's own event first, from what it has stored.
const RESUME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Failed submits of a restored wallet, after it was used and with none landing in
/// between, before its checkpoint is dropped: the intent builder's snapshot strikes.
/// Above one, because a healthy wallet is also refused at times.
const RESTORE_STRIKES: u32 = 3;

/// The DUST key of account 0 at index 0, derived the way the Midnight wallet SDK
/// derives it from the same seed: BIP-32 `m/44'/2400'/0'/2/0`, then the ledger's
/// `DustSecretKey::derive_secret_key` over that private key.
pub(crate) fn dust_secret_key(seed: &[u8]) -> anyhow::Result<DustSecretKey> {
    let path: bip32::DerivationPath = "m/44'/2400'/0'/2/0"
        .parse()
        .expect("the DUST role path is a valid derivation path");
    let role = path
        .iter()
        .try_fold(master_key(seed)?, |key, child| key.derive_child(child))
        .map_err(|error| anyhow::anyhow!("deriving the funding wallet's DUST role key: {error}"))?;
    Ok(DustSecretKey::derive_secret_key(&role.to_bytes()))
}

/// The BIP-32 master key. `bip32::XPrv::new` takes only 16, 32 or 64 byte seeds, but
/// BIP-32, the wallet SDK and the seed check allow any length from 16 to 64.
fn master_key(seed: &[u8]) -> anyhow::Result<bip32::XPrv> {
    use hmac::Mac as _;
    let mut mac = hmac::Hmac::<sha2::Sha512>::new_from_slice(b"Bitcoin seed")
        .expect("HMAC takes a key of any length");
    mac.update(seed);
    let digest = mac.finalize().into_bytes();
    let (key, chain_code) = digest.split_at(32);
    let mut key_bytes = [0u8; 33];
    key_bytes[1..].copy_from_slice(key);
    bip32::XPrv::try_from(bip32::ExtendedKey {
        prefix: bip32::Prefix::XPRV,
        attrs: bip32::ExtendedKeyAttrs {
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: bip32::ChildNumber::default(),
            chain_code: chain_code.try_into().expect("HMAC-SHA512 is 64 bytes"),
        },
        key_bytes,
    })
    .map_err(|error| anyhow::anyhow!("deriving the funding wallet's master key: {error}"))
}

/// Hex seed bytes, with or without `0x`: the format the configuration validates.
pub(crate) fn parse_seed(seed: &str) -> anyhow::Result<Vec<u8>> {
    let trimmed = seed.trim();
    let bare = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    hex::decode(bare).context("the funding seed is not hex")
}

/// What the publisher needs from the wallet. A trait so the publish path can be
/// driven without an indexer.
pub(crate) trait FeePayer: Send + Sync {
    /// Waits, until `deadline`, for the replayed state to catch up with the newest
    /// event the indexer has reported.
    fn ready_by(
        &self,
        deadline: Instant,
    ) -> impl std::future::Future<Output = Result<(), SubmitError>> + Send;
    /// The block time of the newest replayed event: the earliest `ctime` whose DUST
    /// roots are the ones the replayed state proves against.
    fn sync_time(&self) -> Timestamp;
    /// The block time of the newest block the event source has indexed: past it,
    /// the chain may hold DUST events the replay has not seen.
    fn indexed_time(
        &self,
    ) -> impl std::future::Future<Output = Result<Timestamp, SubmitError>> + Send;
    /// A fee transaction paying for `base` at `ctime`, expiring at `ttl`, and the
    /// UTXOs it spends.
    fn plan(
        &self,
        base: &SealedTx,
        parameters: &LedgerParameters,
        ctime: Timestamp,
        ttl: Timestamp,
        network_id: &str,
        rng: &mut StdRng,
    ) -> Result<FeePlan, SubmitError>;
    /// Keeps `spent` out of every later plan until the chain spends them or `until`.
    fn reserve(&self, spent: &[DustNullifier], until: Timestamp);
    /// Ends the reservation of `spent`: the transaction spending them cannot land.
    fn release(&self, spent: &[DustNullifier]);
    /// A submit failed for any reason but an unsynced wallet. The replay starts over
    /// from the latest checkpoint, and `wallet_used` says whether the failure came
    /// once the wallet was paying, so it can implicate the restored state.
    fn failed(&self, wallet_used: bool);
    /// A submit landed: the wallet in use can pay whatever it was restored from.
    fn landed(&self);
}

/// One fee payment, not yet proven.
pub(crate) struct FeePlan {
    pub tx: UnprovenTx,
    pub spent: Vec<DustNullifier>,
    pub fee: u128,
    /// The spendable DUST it was planned from, in SPECK.
    pub available: u128,
}

struct Reservation {
    spent: Vec<DustNullifier>,
    until: Timestamp,
}

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
/// event at `applied`, which `event_hash` checks.
#[derive(Clone)]
pub(crate) struct Checkpoint {
    pub(crate) owner: [u8; 32],
    pub(crate) applied: u64,
    pub(crate) event_hash: [u8; 32],
    pub(crate) local: DustLocalState<DefaultDB>,
}

impl Checkpoint {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&self.owner);
        bytes.extend_from_slice(&self.applied.to_le_bytes());
        bytes.extend_from_slice(&self.event_hash);
        midnight_serialize::tagged_serialize(&self.local, &mut bytes)
            .expect("serializing into a Vec cannot fail");
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
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

/// Which funding key a checkpoint belongs to: the hash of its public key.
pub(crate) fn owner_of(key: &DustSecretKey) -> [u8; 32] {
    let public = midnight_ledger_v9::dust::DustPublicKey::from(key.clone());
    let mut bytes = Vec::new();
    midnight_serialize::tagged_serialize(&public, &mut bytes)
        .expect("serializing into a Vec cannot fail");
    sha2::Sha256::digest(&bytes).into()
}

pub(crate) fn event_hash(raw: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(raw).into()
}

/// The version in the header of a serialized ledger event, `midnight:event[v<version>]:`.
fn event_version(raw: &[u8]) -> Option<u32> {
    let rest = raw
        .strip_prefix(midnight_serialize::GLOBAL_TAG.as_bytes())?
        .strip_prefix(b"event[v")?;
    let (version, rest) = rest.split_at(rest.iter().position(|byte| *byte == b']')?);
    rest.starts_with(b"]:")
        .then(|| std::str::from_utf8(version).ok()?.parse().ok())?
}

/// Whether the ledger a chain ran before an upgrade serialized this event. The indexer
/// keeps those events as that ledger wrote them, and from the upgrade on serves the DUST
/// timeline again as this ledger's events, as the wallet SDK's migration across ledger
/// versions relies on. So they are no part of this ledger's replay.
fn is_earlier_ledger_event(raw: &[u8]) -> bool {
    static CURRENT: std::sync::LazyLock<Option<u32>> = std::sync::LazyLock::new(|| {
        let tag = <Event<DefaultDB> as midnight_serialize::Tagged>::tag();
        event_version(format!("{}{tag}:", midnight_serialize::GLOBAL_TAG).as_bytes())
    });
    matches!((event_version(raw), *CURRENT), (Some(version), Some(current)) if version < current)
}

/// The replay restarted from the first event: the stream and the state disagree.
#[derive(Debug, thiserror::Error)]
#[error("restarting the DUST replay from the first event")]
struct Restarted;

struct Synced {
    local: DustLocalState<DefaultDB>,
    /// The id of the newest event replayed, `None` before the first.
    applied: Option<u64>,
    /// The hash of event `applied`, as the indexer served it.
    applied_hash: Option<[u8; 32]>,
    /// The newest event id the indexer has reported.
    max_id: u64,
    /// Whether a subscription is currently delivering.
    connected: bool,
    /// The event a restored checkpoint expects the next subscription to start with.
    resume: Option<(u64, [u8; 32])>,
    /// Whether this state descends from a checkpoint rather than the first event.
    restored: bool,
    /// A failed submit asked for the replay to start over from the latest checkpoint.
    reload: bool,
    reservations: Vec<Reservation>,
}

impl Synced {
    fn fresh() -> Self {
        Self {
            local: DustLocalState::new(INITIAL_PARAMETERS.dust),
            applied: None,
            applied_hash: None,
            max_id: 0,
            connected: false,
            resume: None,
            restored: false,
            reload: false,
            reservations: Vec::new(),
        }
    }

    /// Back to the first event, keeping the reservations of submits in flight.
    fn restart(&mut self) {
        let reservations = std::mem::take(&mut self.reservations);
        *self = Self::fresh();
        self.reservations = reservations;
    }

    /// Live, caught up, and not about to start over after a failed submit.
    fn is_ready(&self) -> bool {
        self.connected && self.is_caught_up() && !self.reload
    }

    /// Replayed up to the newest event the indexer reported, live or not.
    fn is_caught_up(&self) -> bool {
        self.applied.is_some_and(|applied| applied >= self.max_id)
    }
}

struct Shared {
    key: DustSecretKey,
    owner: [u8; 32],
    state: Mutex<Synced>,
    progress: watch::Sender<()>,
    snapshots: Mutex<Snapshots>,
    /// Wakes the subscription to act on `Synced::reload`.
    wake: tokio::sync::Notify,
    store: Option<Arc<dyn DustCheckpointStore>>,
    /// Held while a checkpoint is kept and while a forgotten one is cleared, so a clear
    /// is sent only once any save that started before its forget has ended, as the
    /// intent builder's flow lock ordered its snapshot saves and clears.
    storing: tokio::sync::Mutex<()>,
}

/// The latest checkpoint and the strikes against it, which outlive any one replay, as
/// the intent builder's wallet snapshots did.
#[derive(Default)]
struct Snapshots {
    /// The newest checkpoint kept or restored, in memory even when the store refused it.
    latest: Option<Checkpoint>,
    /// When a checkpoint was last kept, and of which event: the intent builder's
    /// `kept_at`. Only keeping a checkpoint sets it; a forget or a replay started over
    /// from the first event clears it, and a reload leaves it.
    kept: Option<(Instant, u64)>,
    /// Failed submits of a restored wallet, once used, since one landed.
    strikes: u32,
    /// The stored checkpoint is being cleared; nothing is kept until it is.
    forget: bool,
}

impl Shared {
    fn snapshots(&self) -> std::sync::MutexGuard<'_, Snapshots> {
        self.snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Never panics on a poisoned lock: nothing inside it is left half-written.
    fn state(&self) -> std::sync::MutexGuard<'_, Synced> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The funding wallet, kept in sync in the background for as long as it lives.
pub(crate) struct FundingWallet {
    shared: Arc<Shared>,
    source: Arc<dyn DustEventSource>,
    _sync: AbortOnDrop,
}

impl FundingWallet {
    /// Starts replaying at once, from the checkpoint in `checkpoints` when it has one
    /// for this key, so the first publish does not pay for the catch-up.
    pub(crate) fn start(
        key: DustSecretKey,
        source: Arc<dyn DustEventSource>,
        checkpoints: Option<Arc<dyn DustCheckpointStore>>,
    ) -> Self {
        let (progress, _) = watch::channel(());
        let shared = Arc::new(Shared {
            owner: owner_of(&key),
            key,
            state: Mutex::new(Synced::fresh()),
            progress,
            snapshots: Mutex::default(),
            wake: tokio::sync::Notify::new(),
            store: checkpoints,
            storing: tokio::sync::Mutex::new(()),
        });
        let sync = AbortOnDrop(tokio::spawn(follow(shared.clone(), source.clone())));
        Self {
            shared,
            source,
            _sync: sync,
        }
    }
}

/// How one subscription ended.
#[derive(Clone, Copy)]
enum Ended {
    /// The connection or the stream ended; the replay goes on from where it is.
    Dropped,
    /// The subscription could not be opened; the replay goes on from where it is.
    Refused,
    /// The replay restarted from the first event, after catching up or not.
    Restarted { caught_up: bool },
    /// A failed submit started the replay over from the latest checkpoint.
    Reloaded,
}

/// Follows the event stream for the wallet's lifetime: resubscribes after any
/// failure from the newest applied event, and starts over from the first event when
/// the replayed state can no longer absorb what the indexer sends, backing off while
/// that keeps happening before the replay catches up, or while the indexer refuses to
/// open a subscription at all.
async fn follow(shared: Arc<Shared>, source: Arc<dyn DustEventSource>) {
    if let Some(store) = &shared.store {
        restore(&shared, store.as_ref()).await;
    }
    let mut delay = RESUBSCRIBE_DELAY;
    loop {
        // Its own task, so a panic below ends one subscription rather than the
        // wallet; held so that dropping the wallet aborts it too.
        let ended = Arc::new(Mutex::new(Ended::Dropped));
        let mut attempt = AbortOnDrop(tokio::spawn({
            let (shared, source) = (shared.clone(), source.clone());
            let ended = ended.clone();
            async move {
                let outcome = subscribe_once(shared, source).await;
                *ended
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = outcome;
            }
        }));
        if let Err(error) = (&mut attempt.0).await {
            tracing::error!(
                ?error,
                "midnight funding wallet: DUST event subscription panicked"
            );
        }
        let ended = *ended
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        shared.state().connected = false;
        shared.progress.send_replace(());
        delay = match ended {
            Ended::Restarted { caught_up: false } => (delay * 2).min(MAX_RESTART_DELAY),
            Ended::Restarted { caught_up: true } => RESUBSCRIBE_DELAY * 2,
            Ended::Refused => (delay * 2).min(MAX_REFUSED_DELAY),
            Ended::Dropped | Ended::Reloaded => RESUBSCRIBE_DELAY,
        };
        tokio::time::sleep(delay).await;
    }
}

/// Resumes from the stored checkpoint when it belongs to this key. The first
/// subscription then checks it against the indexer.
async fn restore(shared: &Shared, store: &dyn DustCheckpointStore) {
    let bytes = match tokio::time::timeout(CHECKPOINT_TIMEOUT, store.load()).await {
        Ok(Ok(Some(bytes))) => bytes,
        Ok(Ok(None)) => return,
        Ok(Err(error)) => {
            tracing::warn!(
                ?error,
                "midnight funding wallet: loading the DUST checkpoint failed"
            );
            return;
        }
        Err(_) => {
            tracing::warn!("midnight funding wallet: loading the DUST checkpoint timed out");
            return;
        }
    };
    let decoded = tokio::task::spawn_blocking(move || Checkpoint::decode(&bytes)).await;
    let checkpoint = match decoded {
        Ok(Ok(checkpoint)) => checkpoint,
        Ok(Err(error)) => {
            tracing::warn!(
                ?error,
                "midnight funding wallet: ignoring an unreadable DUST checkpoint"
            );
            return;
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                "midnight funding wallet: decoding the DUST checkpoint failed"
            );
            return;
        }
    };
    if checkpoint.owner != shared.owner {
        tracing::info!("midnight funding wallet: the DUST checkpoint belongs to another funding key; replaying from the first event");
        return;
    }
    tracing::info!(
        event = checkpoint.applied,
        "midnight funding wallet: resuming the DUST replay from its checkpoint"
    );
    shared.snapshots().latest = Some(checkpoint.clone());
    resume_from(shared, checkpoint);
}

/// Replaces the replayed state with `checkpoint`'s, keeping the reservations of
/// submits in flight; the next subscription starts at its event and checks it.
fn resume_from(shared: &Shared, checkpoint: Checkpoint) {
    let mut state = shared.state();
    state.restart();
    state.local = checkpoint.local;
    state.applied = Some(checkpoint.applied);
    state.applied_hash = Some(checkpoint.event_hash);
    state.max_id = checkpoint.applied;
    state.resume = Some((checkpoint.applied, checkpoint.event_hash));
    state.restored = true;
}

/// Applies one subscription until it ends.
async fn subscribe_once(shared: Arc<Shared>, source: Arc<dyn DustEventSource>) -> Ended {
    let from = shared.state().applied;
    let mut caught_up = false;
    match source.subscribe(from).await {
        Ok(stream) => {
            let mut batches = stream.ready_chunks(REPLAY_BATCH);
            let resume_deadline = Instant::now() + RESUME_TIMEOUT;
            loop {
                let resuming = shared.state().resume.is_some();
                let batch = tokio::select! {
                    batch = batches.next() => match batch {
                        Some(batch) => batch,
                        None => break,
                    },
                    () = shared.wake.notified() => {
                        if !std::mem::take(&mut shared.state().reload) {
                            continue;
                        }
                        reload(&shared);
                        return Ended::Reloaded;
                    }
                    () = tokio::time::sleep_until(resume_deadline), if resuming => {
                        tracing::warn!(
                            "midnight funding wallet: the indexer does not serve the DUST \
                             checkpoint's event; replaying from the first event"
                        );
                        start_over(&shared);
                        return Ended::Restarted { caught_up };
                    }
                };
                // Replaying is CPU work; it stays off the async workers.
                let applying = shared.clone();
                match tokio::task::spawn_blocking(move || apply(&applying, batch)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(?error, "midnight funding wallet: DUST replay failed");
                        return if error.is::<Restarted>() {
                            Ended::Restarted { caught_up }
                        } else {
                            Ended::Dropped
                        };
                    }
                    Err(error) => {
                        tracing::error!(?error, "midnight funding wallet: DUST replay panicked");
                        return Ended::Dropped;
                    }
                }
                caught_up |= shared.state().is_caught_up();
                keep_checkpoint(&shared).await;
            }
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                "midnight funding wallet: DUST event subscription failed"
            );
            return Ended::Refused;
        }
    }
    Ended::Dropped
}

/// Drops the replayed state and the latest checkpoint it may have come from, so the
/// next subscription replays from the first event.
fn start_over(shared: &Shared) {
    shared.state().restart();
    let mut snapshots = shared.snapshots();
    snapshots.latest = None;
    snapshots.kept = None;
    snapshots.strikes = 0;
    drop(snapshots);
    shared.progress.send_replace(());
}

/// Clears the stored checkpoint a forget dropped from memory.
async fn clear(store: &dyn DustCheckpointStore) {
    match tokio::time::timeout(CHECKPOINT_TIMEOUT, store.clear()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::warn!(
            ?error,
            "midnight funding wallet: clearing the stored DUST checkpoint failed"
        ),
        Err(_) => {
            tracing::warn!("midnight funding wallet: clearing the stored DUST checkpoint timed out")
        }
    }
}

/// Starts the replay over from the latest checkpoint, or from the first event once
/// none is left, the way the intent builder retired its child after a failed submit
/// and started the next from the latest wallet snapshot.
fn reload(shared: &Shared) {
    let latest = shared.snapshots().latest.clone();
    match latest {
        Some(checkpoint) => {
            tracing::info!(
                event = checkpoint.applied,
                "midnight funding wallet: a submit failed; resuming the DUST replay from the \
                 latest checkpoint"
            );
            resume_from(shared, checkpoint);
        }
        None => {
            tracing::info!(
                "midnight funding wallet: a submit failed; replaying DUST from the first event"
            );
            shared.state().restart();
        }
    }
    shared.progress.send_replace(());
}

/// Keeps a checkpoint of a caught-up replay that moved since the last one, at most
/// once per `CHECKPOINT_INTERVAL`, in memory and in the wallet's store. A store failure
/// only costs the next node start its resume. As the intent builder kept no snapshot of
/// a child it was retiring, nothing is kept while a failed submit's reload or forget is
/// pending.
async fn keep_checkpoint(shared: &Shared) {
    // From before the checks below until the save has ended: a forget decided
    // meanwhile clears the store after this save, never before it. Only a forget's
    // clear holds it otherwise, and the replay does not wait for one.
    let Ok(_storing) = shared.storing.try_lock() else {
        return;
    };
    let checkpoint = {
        // Held across the snapshots update, so a failure lands either before this
        // check or after the checkpoint is in place for its forget to drop.
        let state = shared.state();
        let (Some(applied), Some(event_hash)) = (state.applied, state.applied_hash) else {
            return;
        };
        if !state.is_caught_up() || state.reload {
            return;
        }
        let mut snapshots = shared.snapshots();
        let due = snapshots
            .kept
            .is_none_or(|(at, kept)| kept != applied && at.elapsed() >= CHECKPOINT_INTERVAL);
        if !due || snapshots.forget {
            return;
        }
        let checkpoint = Checkpoint {
            owner: shared.owner,
            applied,
            event_hash,
            local: state.local.clone(),
        };
        snapshots.kept = Some((Instant::now(), applied));
        snapshots.latest = Some(checkpoint.clone());
        checkpoint
    };
    let applied = checkpoint.applied;
    let Some(store) = shared.store.as_deref() else {
        return;
    };
    let encoded = match tokio::task::spawn_blocking(move || checkpoint.encode()).await {
        Ok(encoded) => encoded,
        Err(error) => {
            tracing::warn!(
                ?error,
                "midnight funding wallet: encoding the DUST checkpoint failed"
            );
            return;
        }
    };
    match tokio::time::timeout(CHECKPOINT_TIMEOUT, store.save(&encoded)).await {
        Ok(Ok(())) => tracing::info!(
            event = applied,
            bytes = encoded.len(),
            "midnight funding wallet: kept a DUST checkpoint"
        ),
        Ok(Err(error)) => {
            tracing::warn!(
                ?error,
                "midnight funding wallet: keeping the DUST checkpoint failed"
            );
        }
        Err(_) => tracing::warn!("midnight funding wallet: keeping the DUST checkpoint timed out"),
    }
}

/// Replays one batch, passing over the events of an earlier ledger. An event the state
/// cannot absorb means the stream and the state disagree about history, so the state
/// restarts from the first event; so does a restored checkpoint whose event the
/// indexer no longer serves.
fn apply(shared: &Shared, batch: Vec<anyhow::Result<DustEventUpdate>>) -> anyhow::Result<()> {
    let mut updates = Vec::with_capacity(batch.len());
    let mut failure = None;
    for update in batch {
        match update {
            Ok(update) => updates.push(update),
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    let mut state = shared.state();
    if let (Some((id, hash)), Some(first)) = (state.resume, updates.first()) {
        if first.id != id || event_hash(&first.raw) != hash {
            drop(state);
            start_over(shared);
            return Err(anyhow::Error::new(Restarted).context(format!(
                "the DUST checkpoint at event {id} does not match the indexer, which served \
                 event {} first",
                first.id
            )));
        }
        state.resume = None;
    }
    if let Some(last) = updates.last() {
        state.max_id = last.max_id;
    }
    let applied = state.applied;
    let fresh: Vec<&DustEventUpdate> = updates
        .iter()
        .filter(|update| applied.is_none_or(|applied| update.id > applied))
        .collect();
    if let Some(newest) = fresh.last() {
        let events = fresh
            .iter()
            .filter(|update| !is_earlier_ledger_event(&update.raw))
            .map(|update| {
                midnight_serialize::tagged_deserialize::<Event<DefaultDB>>(&mut &update.raw[..])
                    .with_context(|| format!("DUST event {} did not decode", update.id))
            })
            .collect::<anyhow::Result<Vec<_>>>();
        let replayed = events.and_then(|events| {
            state
                .local
                .replay_events(&shared.key, events.iter())
                .map_err(|error| anyhow::anyhow!("DUST event replay failed: {error:?}"))
        });
        match replayed {
            Ok(local) => {
                state.local = local.process_ttls(now());
                state.applied = Some(newest.id);
                state.applied_hash = Some(event_hash(&newest.raw));
            }
            Err(error) => {
                drop(state);
                start_over(shared);
                return Err(anyhow::Error::new(Restarted).context(format!("{error:#}")));
            }
        }
    }
    if !updates.is_empty() {
        state.connected = true;
    }
    drop(state);
    shared.progress.send_replace(());
    failure.map_or(Ok(()), Err)
}

fn now() -> Timestamp {
    Timestamp::from_secs(mpc_utils::time::current_unix_timestamp())
}

impl FeePayer for FundingWallet {
    async fn ready_by(&self, deadline: Instant) -> Result<(), SubmitError> {
        let mut progress = self.shared.progress.subscribe();
        loop {
            if self.shared.state().is_ready() {
                return Ok(());
            }
            match tokio::time::timeout_at(deadline, progress.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) | Err(_) => {
                    let state = self.shared.state();
                    return Err(SubmitError::WalletUnsynced(format!(
                        "DUST replay is at event {:?} of {} (subscription {}{}); nothing was \
                         posted",
                        state.applied,
                        state.max_id,
                        if state.connected { "live" } else { "down" },
                        if state.reload {
                            ", reload after a failed submit pending"
                        } else {
                            ""
                        }
                    )));
                }
            }
        }
    }

    fn sync_time(&self) -> Timestamp {
        self.shared.state().local.sync_time
    }

    async fn indexed_time(&self) -> Result<Timestamp, SubmitError> {
        self.source.indexed_time().await.map_err(|error| {
            SubmitError::WalletUnsynced(format!(
                "the indexer did not report its newest block: {error:#}; nothing was posted"
            ))
        })
    }

    fn plan(
        &self,
        base: &SealedTx,
        parameters: &LedgerParameters,
        ctime: Timestamp,
        ttl: Timestamp,
        network_id: &str,
        rng: &mut StdRng,
    ) -> Result<FeePlan, SubmitError> {
        let (local, reserved) = {
            let mut state = self.shared.state();
            // A replay restarted or reloaded since `ready_by` holds a partial or older
            // state, and the reservations' UTXOs may not be in it, so the retain below
            // would end them.
            if !state.is_caught_up() || state.reload || state.resume.is_some() {
                return Err(SubmitError::WalletUnsynced(format!(
                    "the DUST replay is restarting or resuming from a checkpoint and is at \
                     event {:?} of {}; nothing was posted",
                    state.applied, state.max_id
                )));
            }
            let wall = now();
            let local = state.local.clone();
            state.reservations.retain(|reservation| {
                reservation.until >= wall
                    && reservation
                        .spent
                        .iter()
                        .any(|nullifier| local.find_utxo_by_nullifier(*nullifier).is_some())
            });
            let reserved: Vec<DustNullifier> = state
                .reservations
                .iter()
                .flat_map(|reservation| reservation.spent.iter().copied())
                .collect();
            (local, reserved)
        };
        plan_fee(
            &self.shared.key,
            &local,
            &reserved,
            base,
            parameters,
            ctime,
            ttl,
            network_id,
            rng,
        )
    }

    fn reserve(&self, spent: &[DustNullifier], until: Timestamp) {
        self.shared.state().reservations.push(Reservation {
            spent: spent.to_vec(),
            until,
        });
    }

    fn release(&self, spent: &[DustNullifier]) {
        let mut state = self.shared.state();
        state
            .reservations
            .retain(|reservation| !reservation.spent.iter().any(|n| spent.contains(n)));
        drop(state);
        self.shared.progress.send_replace(());
    }

    fn failed(&self, wallet_used: bool) {
        let restored = self.shared.state().restored;
        // The strikes before the reload, so a wake acting on it sees any forget.
        let mut forget = false;
        if restored && wallet_used {
            let mut snapshots = self.shared.snapshots();
            snapshots.strikes += 1;
            if snapshots.strikes >= RESTORE_STRIKES {
                tracing::warn!(
                    "midnight funding wallet: discarding the DUST checkpoint after its \
                     restored wallets failed to land a submit; replaying from the first event"
                );
                snapshots.latest = None;
                snapshots.kept = None;
                snapshots.strikes = 0;
                snapshots.forget = true;
                forget = true;
            }
        }
        self.shared.state().reload = true;
        if forget {
            // Cleared at once, as the intent builder's forget was, whether or not a
            // subscription is live, and after any save already running. Spawned only
            // once the reload is set: nothing is kept between the forget and the reload.
            let shared = self.shared.clone();
            tokio::spawn(async move {
                let _storing = shared.storing.lock().await;
                if let Some(store) = &shared.store {
                    clear(store.as_ref()).await;
                }
                shared.snapshots().forget = false;
            });
        }
        self.shared.wake.notify_one();
    }

    fn landed(&self) {
        self.shared.snapshots().strikes = 0;
    }
}

/// Picks UTXOs until the merged transaction balances: each pass prices `base` with
/// the previous pass's fee transaction attached, mock-proven, which the ledger
/// documents as accurate for fees once no contract call is left unproven.
#[allow(clippy::too_many_arguments)]
pub(crate) fn plan_fee(
    key: &DustSecretKey,
    local: &DustLocalState<DefaultDB>,
    reserved: &[DustNullifier],
    base: &SealedTx,
    parameters: &LedgerParameters,
    ctime: Timestamp,
    ttl: Timestamp,
    network_id: &str,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<FeePlan, SubmitError> {
    let mut candidates: Vec<(QualifiedDustOutput, u128)> = Vec::new();
    let mut held = 0usize;
    let mut held_value: u128 = 0;
    for utxo in local.utxos() {
        let Some(generation) = local.generation_info(&utxo) else {
            continue;
        };
        let value = DustOutput::from(utxo).updated_value(&generation, ctime, &local.params);
        if reserved.contains(&utxo.nullifier(key)) {
            held += 1;
            held_value = held_value.saturating_add(value);
        } else if value > 0 {
            candidates.push((utxo, value));
        }
    }
    // Largest first: the fewest spends, so the smallest fee transaction.
    candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.1));
    let available: u128 = candidates.iter().map(|(_, value)| value).sum();

    let segment = free_segment(base)?;
    let mut required: u128 = 0;
    for _ in 0..FEE_PASSES {
        if required > available {
            // Held DUST comes back as the in-flight submit's change, or whole if it
            // never lands; a fee it could not cover either way is unfunded.
            let busy = held > 0 && required <= available.saturating_add(held_value);
            return Err(if busy {
                SubmitError::WalletBusy(format!(
                    "{held} DUST UTXO(s) are held by a submit still in flight; the free ones \
                     hold {available} of the {required} SPECKS this fee needs"
                ))
            } else {
                SubmitError::WalletUnfunded(format!(
                    "the funding wallet holds {available} spendable SPECKS of DUST, the fee \
                     needs {required}"
                ))
            });
        }
        let (tx, spent) = fee_transaction(
            key,
            local,
            &candidates,
            required,
            segment,
            ctime,
            ttl,
            network_id,
            rng,
        )?;
        let mocked = tx
            .mock_prove()
            .map_err(|error| SubmitError::Internal(format!("mock-proving the fee: {error:?}")))?;
        let merged = base
            .merge(&mocked)
            .map_err(|error| SubmitError::Internal(format!("merging the fee: {error:?}")))?;
        let fee = merged
            .fees_with_margin(parameters, FEE_BLOCKS_MARGIN)
            .map_err(|error| SubmitError::Internal(format!("pricing the fee: {error:?}")))?;
        let deficit = dust_deficit(&merged, fee)?;
        if deficit == 0 {
            return Ok(FeePlan {
                tx,
                spent,
                fee,
                available,
            });
        }
        required = required.saturating_add(deficit);
    }
    Err(SubmitError::Internal(format!(
        "the DUST fee did not settle in {FEE_PASSES} passes"
    )))
}

/// How much DUST `tx` is short of paying `fee`, at the guaranteed segment.
pub(crate) fn dust_deficit(tx: &SealedTx, fee: u128) -> Result<u128, SubmitError> {
    let balance = tx
        .balance(Some(fee))
        .map_err(|error| SubmitError::Internal(format!("balancing the fee: {error:?}")))?;
    let dust = balance.get(&(TokenType::Dust, 0)).copied().unwrap_or(0);
    Ok(if dust < 0 { dust.unsigned_abs() } else { 0 })
}

/// The lowest segment `base` leaves free; segment 0 is the guaranteed one.
fn free_segment(base: &SealedTx) -> Result<u16, SubmitError> {
    let Transaction::Standard(stx) = base else {
        return Err(SubmitError::Internal(
            "the respond transaction is not a standard transaction".to_string(),
        ));
    };
    let used: HashSet<u16> = stx.intents.iter().map(|entry| *entry.0).collect();
    (1..=u16::MAX)
        .find(|segment| !used.contains(segment))
        .ok_or_else(|| SubmitError::Internal("no free intent segment".to_string()))
}

#[allow(clippy::too_many_arguments)]
fn fee_transaction(
    key: &DustSecretKey,
    local: &DustLocalState<DefaultDB>,
    candidates: &[(QualifiedDustOutput, u128)],
    required: u128,
    segment: u16,
    ctime: Timestamp,
    ttl: Timestamp,
    network_id: &str,
    rng: &mut (impl Rng + CryptoRng),
) -> Result<(UnprovenTx, Vec<DustNullifier>), SubmitError> {
    let mut scratch = local.clone();
    let mut spends = midnight_storage::storage::Array::new();
    let mut spent = Vec::new();
    let mut remaining = required;
    for (utxo, value) in candidates {
        if remaining == 0 {
            break;
        }
        let take = remaining.min(*value);
        let (next, spend) = scratch
            .spend(key, utxo, take, ctime)
            .map_err(|error| SubmitError::Internal(format!("spending DUST: {error:?}")))?;
        scratch = next;
        spends = spends.push(spend);
        spent.push(utxo.nullifier(key));
        remaining -= take;
    }
    let mut intent: Intent<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> =
        Intent::empty(rng, ttl);
    intent.dust_actions = Some(Sp::new(DustActions {
        spends,
        registrations: vec![].into(),
        ctime,
    }));
    let intents = midnight_storage::storage::HashMap::new().insert(segment, intent);
    Ok((Transaction::from_intents(network_id, intents), spent))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use async_trait::async_trait;
    use futures_util::stream::BoxStream;
    use rand::SeedableRng as _;

    /// The publisher seed `midnight-devtools`' real-stack driver funds.
    const FUNDED_SEED: &str = "0404040404040404040404040404040404040404040404040404040404040404";

    /// Every DUST event of a local undeployed chain whose seed-0404… wallet was
    /// funded, registered and then paid three fees; see fixtures/README.md.
    fn fixture_updates() -> Vec<DustEventUpdate> {
        let events: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../fixtures/dust-events-undeployed.json")).unwrap();
        events
            .iter()
            .map(|event| DustEventUpdate {
                id: event["id"].as_u64().unwrap(),
                max_id: event["maxId"].as_u64().unwrap(),
                raw: hex::decode(event["raw"].as_str().unwrap()).unwrap(),
            })
            .collect()
    }

    /// The first two DUST events of Midnight Preview, which the ledger that chain ran
    /// before ledger 9 serialized; see fixtures/README.md.
    fn earlier_ledger_updates() -> Vec<DustEventUpdate> {
        let events: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../fixtures/dust-events-preview-earlier-ledger.json"
        ))
        .unwrap();
        events
            .iter()
            .map(|event| DustEventUpdate {
                id: event["id"].as_u64().unwrap(),
                max_id: event["maxId"].as_u64().unwrap(),
                raw: hex::decode(event["raw"].as_str().unwrap()).unwrap(),
            })
            .collect()
    }

    /// The fixture's timeline as a chain that upgraded its ledger serves it: the
    /// earlier ledger's events first, then this ledger's from the next id on.
    fn upgraded_chain_updates() -> Vec<DustEventUpdate> {
        let earlier = earlier_ledger_updates();
        let offset = earlier.last().unwrap().id;
        let current = fixture_updates();
        let max_id = current.last().unwrap().id + offset;
        earlier
            .into_iter()
            .chain(current.into_iter().map(|mut update| {
                update.id += offset;
                update
            }))
            .map(|mut update| {
                update.max_id = max_id;
                update
            })
            .collect()
    }

    pub(crate) fn funded_key() -> DustSecretKey {
        dust_secret_key(&parse_seed(FUNDED_SEED).unwrap()).unwrap()
    }

    pub(crate) fn replayed() -> DustLocalState<DefaultDB> {
        let events: Vec<Event<DefaultDB>> = fixture_updates()
            .iter()
            .map(|update| midnight_serialize::tagged_deserialize(&mut &update.raw[..]).unwrap())
            .collect();
        DustLocalState::new(INITIAL_PARAMETERS.dust)
            .replay_events(&funded_key(), events.iter())
            .unwrap()
    }

    /// A transaction with one empty intent: the smallest base a fee is paid for.
    pub(crate) fn base(rng: &mut StdRng, ttl: Timestamp) -> SealedTx {
        let intent: Intent<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB> =
            Intent::empty(rng, ttl);
        let intents = midnight_storage::storage::HashMap::new().insert(1u16, intent);
        Transaction::<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>::from_intents(
            "undeployed",
            intents,
        )
        .mock_prove()
        .unwrap()
    }

    #[test]
    fn a_planned_fee_pays_for_the_transaction_it_is_merged_into() {
        let local = replayed();
        assert!(
            local.utxos().next().is_some(),
            "the fixture wallet holds DUST"
        );
        let ctime = local.sync_time;
        let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
        let mut rng = StdRng::seed_from_u64(1);
        let base = base(&mut rng, ttl);

        let plan = plan_fee(
            &funded_key(),
            &local,
            &[],
            &base,
            &INITIAL_PARAMETERS,
            ctime,
            ttl,
            "undeployed",
            &mut rng,
        )
        .unwrap();

        assert!(!plan.spent.is_empty());
        let spendable: u128 = local
            .utxos()
            .filter_map(|utxo| {
                let generation = local.generation_info(&utxo)?;
                Some(DustOutput::from(utxo).updated_value(&generation, ctime, &local.params))
            })
            .sum();
        assert_eq!(plan.available, spendable, "nothing was reserved");
        let merged = base.merge(&plan.tx.mock_prove().unwrap()).unwrap();
        let fee = merged.fees_with_margin(&INITIAL_PARAMETERS, 5).unwrap();
        assert_eq!(fee, plan.fee);
        assert_eq!(dust_deficit(&merged, fee).unwrap(), 0);
        let Transaction::Standard(stx) = &plan.tx else {
            panic!("the fee transaction is a standard transaction");
        };
        let segments: Vec<u16> = stx.intents.iter().map(|entry| *entry.0).collect();
        assert_eq!(
            segments,
            vec![2],
            "the fee intent takes the first segment the base leaves"
        );
    }

    #[test]
    fn reserved_utxos_are_never_spent_twice() {
        let local = replayed();
        let key = funded_key();
        let all: Vec<DustNullifier> = local.utxos().map(|utxo| utxo.nullifier(&key)).collect();
        let ctime = local.sync_time;
        let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
        let mut rng = StdRng::seed_from_u64(2);
        let base = base(&mut rng, ttl);
        let error = plan_fee(
            &key,
            &local,
            &all,
            &base,
            &INITIAL_PARAMETERS,
            ctime,
            ttl,
            "undeployed",
            &mut rng,
        )
        .err()
        .expect("every UTXO is held");
        assert!(matches!(error, SubmitError::WalletBusy(_)), "{error}");
    }

    #[test]
    fn a_fee_the_held_dust_could_not_cover_either_is_unfunded() {
        let local = replayed();
        let key = funded_key();
        let first: Vec<DustNullifier> = local
            .utxos()
            .map(|utxo| utxo.nullifier(&key))
            .take(1)
            .collect();
        let ctime = local.sync_time;
        let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
        let mut rng = StdRng::seed_from_u64(5);
        let base = base(&mut rng, ttl);
        // A price no amount of this wallet's DUST pays.
        let mut parameters = INITIAL_PARAMETERS.clone();
        parameters.fee_prices.overall_price =
            midnight_base_crypto::cost_model::FixedPoint::from_u64_div(1 << 40, 1);
        let plan = |reserved: &[DustNullifier], rng: &mut StdRng| {
            plan_fee(
                &key,
                &local,
                reserved,
                &base,
                &parameters,
                ctime,
                ttl,
                "undeployed",
                rng,
            )
            .err()
            .expect("the fee outprices the wallet")
        };
        for reserved in [&[][..], &first[..]] {
            let error = plan(reserved, &mut rng);
            assert!(matches!(error, SubmitError::WalletUnfunded(_)), "{error}");
        }
    }

    #[test]
    fn a_wallet_without_dust_is_unfunded() {
        let empty = DustLocalState::<DefaultDB>::new(INITIAL_PARAMETERS.dust);
        let ctime = Timestamp::from_secs(1_000);
        let ttl = Timestamp::from_secs(1_180);
        let mut rng = StdRng::seed_from_u64(3);
        let base = base(&mut rng, ttl);
        let error = plan_fee(
            &funded_key(),
            &empty,
            &[],
            &base,
            &INITIAL_PARAMETERS,
            ctime,
            ttl,
            "undeployed",
            &mut rng,
        )
        .err()
        .expect("nothing to spend");
        assert!(matches!(error, SubmitError::WalletUnfunded(_)), "{error}");
    }

    fn shared() -> Shared {
        Shared {
            key: funded_key(),
            owner: owner_of(&funded_key()),
            state: Mutex::new(Synced::fresh()),
            progress: watch::channel(()).0,
            snapshots: Mutex::default(),
            wake: tokio::sync::Notify::new(),
            store: None,
            storing: tokio::sync::Mutex::new(()),
        }
    }

    #[test]
    fn replay_is_ready_once_it_reaches_the_newest_event_and_skips_repeats() {
        let shared = shared();
        let updates = fixture_updates();
        let (first, rest) = updates.split_at(10);
        apply(&shared, first.iter().cloned().map(Ok).collect()).unwrap();
        assert!(
            !shared.state().is_ready(),
            "ten of the events are not all of them"
        );
        // A resubscription re-delivers from the newest applied event, inclusive.
        let mut again = vec![first.last().unwrap().clone()];
        again.extend_from_slice(rest);
        apply(&shared, again.into_iter().map(Ok).collect()).unwrap();
        let state = shared.state();
        assert!(state.is_ready());
        assert_eq!(state.applied, Some(updates.last().unwrap().id));
        assert_eq!(
            state.local.utxos().count(),
            replayed().utxos().count(),
            "the batched replay is the single replay"
        );
    }

    #[test]
    fn the_replay_starts_after_the_events_of_an_earlier_ledger() {
        let shared = shared();
        let updates = upgraded_chain_updates();
        // In two deliveries, so one holds events of both ledgers.
        let (first, rest) = updates.split_at(10);
        apply(&shared, first.iter().cloned().map(Ok).collect()).unwrap();
        apply(&shared, rest.iter().cloned().map(Ok).collect()).unwrap();
        let state = shared.state();
        assert!(state.is_ready());
        assert_eq!(state.applied, Some(updates.last().unwrap().id));
        let expected = replayed();
        assert!(expected.utxos().count() > 0);
        assert_eq!(
            state.local.utxos().collect::<Vec<_>>(),
            expected.utxos().collect::<Vec<_>>(),
            "the replay is this ledger's timeline alone"
        );
    }

    #[test]
    fn a_timeline_that_never_left_an_earlier_ledger_is_caught_up_without_dust() {
        let shared = shared();
        let mut updates = earlier_ledger_updates();
        let newest = updates.last().unwrap().id;
        for update in &mut updates {
            update.max_id = newest;
        }
        apply(&shared, updates.into_iter().map(Ok).collect()).unwrap();
        let state = shared.state();
        assert!(state.is_ready());
        assert_eq!(state.applied, Some(newest));
        assert_eq!(state.local.utxos().count(), 0);
    }

    #[test]
    fn only_a_header_of_an_earlier_event_version_is_an_earlier_ledgers() {
        let earlier = earlier_ledger_updates();
        assert_eq!(event_version(&earlier[0].raw), Some(9));
        assert!(is_earlier_ledger_event(&earlier[0].raw));
        let current = fixture_updates();
        assert!(event_version(&current[0].raw) > Some(9));
        assert!(!is_earlier_ledger_event(&current[0].raw));
        // Not an event header at all, a later version, and a version that is no number
        // all go to the decoder, which refuses them.
        for raw in [
            &b"midnight:event[v9]"[..],
            b"midnight:event[v9999]:",
            b"midnight:event[v]:",
            b"midnight:zswap-event[v1]:",
            b"",
        ] {
            assert!(!is_earlier_ledger_event(raw), "{raw:?}");
        }
    }

    #[test]
    fn an_event_the_state_cannot_absorb_restarts_the_replay() {
        let shared = shared();
        let updates = fixture_updates();
        apply(&shared, updates[..5].iter().cloned().map(Ok).collect()).unwrap();
        let held = vec![DustNullifier(midnight_transient_crypto::curve::Fr::from(
            7u64,
        ))];
        shared.state().reservations.push(Reservation {
            spent: held.clone(),
            until: Timestamp::from_secs(u64::MAX / 2),
        });
        let mut corrupt = updates[5].clone();
        corrupt.raw.truncate(10);
        let error = apply(&shared, vec![Ok(corrupt)]).unwrap_err();
        assert!(format!("{error:#}").contains("restarting"), "{error:#}");
        let state = shared.state();
        assert_eq!(state.applied, None);
        assert_eq!(
            state
                .reservations
                .iter()
                .map(|r| &r.spent)
                .collect::<Vec<_>>(),
            [&held],
            "a submit in flight still holds its UTXOs across the restart"
        );
    }

    #[test]
    fn a_quiet_resubscription_is_ready_again_once_it_delivers() {
        let shared = shared();
        let updates = fixture_updates();
        apply(&shared, updates.iter().cloned().map(Ok).collect()).unwrap();
        // What `follow` records when a subscription ends.
        shared.state().connected = false;
        assert!(
            !shared.state().is_ready(),
            "a dropped subscription is not ready"
        );
        // On a quiet chain the resubscription re-delivers only the newest applied event.
        apply(&shared, vec![Ok(updates.last().unwrap().clone())]).unwrap();
        assert!(shared.state().is_ready());
    }

    #[test]
    fn a_resubscription_that_only_fails_is_not_ready() {
        let shared = shared();
        apply(&shared, fixture_updates().into_iter().map(Ok).collect()).unwrap();
        // What `follow` records when a subscription ends.
        shared.state().connected = false;
        apply(&shared, vec![Err(anyhow::anyhow!("the indexer went away"))]).unwrap_err();
        assert!(
            !shared.state().is_ready(),
            "a subscription that delivered nothing is not live"
        );
    }

    /// Delivers the fixture once, then nothing.
    struct OnceSource(Vec<DustEventUpdate>);

    #[async_trait]
    impl DustEventSource for OnceSource {
        async fn subscribe(
            &self,
            from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            let updates: Vec<_> = self
                .0
                .iter()
                .filter(|update| from.is_none_or(|from| update.id >= from))
                .cloned()
                .map(Ok)
                .collect();
            Ok(futures_util::stream::iter(updates)
                .chain(futures_util::stream::pending())
                .boxed())
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            Ok(replayed().sync_time)
        }
    }

    #[tokio::test]
    async fn a_started_wallet_becomes_ready_on_its_own() {
        let wallet =
            FundingWallet::start(funded_key(), Arc::new(OnceSource(fixture_updates())), None);
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(wallet.sync_time(), replayed().sync_time);
    }

    /// Panics on its first subscription, then delivers the fixture.
    struct PanicsFirst(std::sync::atomic::AtomicBool, Vec<DustEventUpdate>);

    #[async_trait]
    impl DustEventSource for PanicsFirst {
        async fn subscribe(
            &self,
            from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            if !self.0.swap(true, std::sync::atomic::Ordering::SeqCst) {
                panic!("a subscription that panics");
            }
            OnceSource(self.1.clone()).subscribe(from).await
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_panicking_subscription_is_retried_rather_than_ending_the_replay() {
        let source = PanicsFirst(Default::default(), fixture_updates());
        let wallet = FundingWallet::start(funded_key(), Arc::new(source), None);
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(30))
            .await
            .unwrap();
    }

    /// Delivers the fixture and ends; every later subscription stays silent.
    struct EndsOnce {
        subscriptions: std::sync::atomic::AtomicUsize,
        updates: Vec<DustEventUpdate>,
    }

    #[async_trait]
    impl DustEventSource for EndsOnce {
        async fn subscribe(
            &self,
            _from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            let first = self
                .subscriptions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0;
            Ok(if first {
                futures_util::stream::iter(self.updates.clone().into_iter().map(Ok)).boxed()
            } else {
                futures_util::stream::pending().boxed()
            })
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_caught_up_wallet_whose_subscription_ended_is_not_ready() {
        let source = Arc::new(EndsOnce {
            subscriptions: Default::default(),
            updates: fixture_updates(),
        });
        let wallet = FundingWallet::start(funded_key(), source.clone(), None);
        // The second subscription starts only after the first one ended.
        while source
            .subscriptions
            .load(std::sync::atomic::Ordering::SeqCst)
            < 2
        {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(wallet.shared.state().is_caught_up());

        let error = wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(1))
            .await
            .expect_err("an indexer that stopped delivering may be missing events");
        assert!(matches!(error, SubmitError::WalletUnsynced(_)), "{error}");
    }

    /// A subscription that never ends, holding `alive` while it is open.
    struct Held(Arc<()>);

    #[async_trait]
    impl DustEventSource for Held {
        async fn subscribe(
            &self,
            _from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            let alive = self.0.clone();
            Ok(futures_util::stream::pending()
                .map(move |update| {
                    let _ = &alive;
                    update
                })
                .boxed())
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test]
    async fn dropping_the_wallet_ends_its_subscription() {
        let alive = Arc::new(());
        let wallet = FundingWallet::start(funded_key(), Arc::new(Held(alive.clone())), None);
        while Arc::strong_count(&alive) < 3 {
            tokio::task::yield_now().await;
        }
        drop(wallet);
        for _ in 0..100 {
            if Arc::strong_count(&alive) == 1 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("the subscription outlived its wallet");
    }

    #[tokio::test]
    async fn a_reservation_holds_until_its_utxos_are_spent_released_or_expired() {
        let wallet =
            FundingWallet::start(funded_key(), Arc::new(OnceSource(fixture_updates())), None);
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(30))
            .await
            .unwrap();
        let local = replayed();
        let key = funded_key();
        let all: Vec<DustNullifier> = local.utxos().map(|utxo| utxo.nullifier(&key)).collect();
        let ctime = local.sync_time;
        let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
        let mut rng = StdRng::seed_from_u64(4);
        let base = base(&mut rng, ttl);
        let plan = |rng: &mut StdRng| {
            wallet.plan(&base, &INITIAL_PARAMETERS, ctime, ttl, "undeployed", rng)
        };
        let forever = Timestamp::from_secs(u64::MAX / 2);

        wallet.reserve(&all, forever);
        assert!(matches!(plan(&mut rng), Err(SubmitError::WalletBusy(_))));
        wallet.release(&all[..1]);
        assert!(
            plan(&mut rng).is_ok(),
            "a released reservation frees its UTXOs"
        );

        wallet.reserve(&all, Timestamp::from_secs(1));
        assert!(plan(&mut rng).is_ok(), "a reservation past its time ends");

        let spent_elsewhere = vec![DustNullifier(midnight_transient_crypto::curve::Fr::from(
            9u64,
        ))];
        wallet.reserve(&spent_elsewhere, forever);
        plan(&mut rng).unwrap();
        assert!(
            wallet.shared.state().reservations.is_empty(),
            "a reservation whose UTXOs the chain spent ends"
        );
    }

    #[tokio::test]
    async fn a_reservation_the_replay_has_seen_partly_spent_still_holds_the_rest() {
        let wallet =
            FundingWallet::start(funded_key(), Arc::new(OnceSource(fixture_updates())), None);
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(30))
            .await
            .unwrap();
        let local = replayed();
        let key = funded_key();
        let unspent = local.utxos().next().unwrap().nullifier(&key);
        let spent = DustNullifier(midnight_transient_crypto::curve::Fr::from(9u64));
        let ctime = local.sync_time;
        let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
        let mut rng = StdRng::seed_from_u64(6);
        let base = base(&mut rng, ttl);

        // The spend of `unspent` is in a batch the replay has not applied yet.
        wallet.reserve(&[spent, unspent], Timestamp::from_secs(u64::MAX / 2));
        if let Ok(plan) = wallet.plan(
            &base,
            &INITIAL_PARAMETERS,
            ctime,
            ttl,
            "undeployed",
            &mut rng,
        ) {
            assert!(!plan.spent.contains(&unspent), "a held UTXO was planned");
        }
        assert_eq!(
            wallet.shared.state().reservations.len(),
            1,
            "a reservation ends only once the chain spent every UTXO it holds"
        );
    }

    #[tokio::test]
    async fn a_replay_restarted_after_ready_plans_nothing_and_keeps_its_reservations() {
        let wallet =
            FundingWallet::start(funded_key(), Arc::new(OnceSource(fixture_updates())), None);
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(30))
            .await
            .unwrap();
        let local = replayed();
        let key = funded_key();
        let all: Vec<DustNullifier> = local.utxos().map(|utxo| utxo.nullifier(&key)).collect();
        let ctime = local.sync_time;
        let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
        let mut rng = StdRng::seed_from_u64(5);
        let base = base(&mut rng, ttl);
        wallet.reserve(&all, Timestamp::from_secs(u64::MAX / 2));
        {
            // What `apply` leaves after a failed replay.
            wallet.shared.state().restart();
        }

        let Err(error) = wallet.plan(
            &base,
            &INITIAL_PARAMETERS,
            ctime,
            ttl,
            "undeployed",
            &mut rng,
        ) else {
            panic!("a restarted replay must not plan a fee");
        };
        assert!(matches!(error, SubmitError::WalletUnsynced(_)), "{error}");
        assert_eq!(
            wallet.shared.state().reservations.len(),
            1,
            "a restart does not end the in-flight reservation"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_wallet_that_cannot_sync_reports_unsynced_at_its_deadline() {
        let wallet = FundingWallet::start(funded_key(), Arc::new(OnceSource(Vec::new())), None);
        let error = wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(error, SubmitError::WalletUnsynced(_)), "{error}");
    }

    #[derive(Default)]
    struct MemoryCheckpoints(Mutex<Option<Vec<u8>>>);

    #[async_trait]
    impl DustCheckpointStore for MemoryCheckpoints {
        async fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self.0.lock().unwrap().clone())
        }

        async fn save(&self, checkpoint: &[u8]) -> anyhow::Result<()> {
            *self.0.lock().unwrap() = Some(checkpoint.to_vec());
            Ok(())
        }

        async fn clear(&self) -> anyhow::Result<()> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }

    impl MemoryCheckpoints {
        fn holding(checkpoint: Checkpoint) -> Self {
            Self(Mutex::new(Some(checkpoint.encode())))
        }

        fn decoded(&self) -> Option<Checkpoint> {
            let bytes = self.0.lock().unwrap().clone()?;
            Some(Checkpoint::decode(&bytes).unwrap())
        }
    }

    /// Serves the fixture from any id, inclusive, and records where each
    /// subscription started.
    struct RecordingSource {
        updates: Vec<DustEventUpdate>,
        froms: Mutex<Vec<Option<u64>>>,
    }

    impl RecordingSource {
        fn new(updates: Vec<DustEventUpdate>) -> Arc<Self> {
            Arc::new(Self {
                updates,
                froms: Mutex::default(),
            })
        }

        fn froms(&self) -> Vec<Option<u64>> {
            self.froms.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DustEventSource for RecordingSource {
        async fn subscribe(
            &self,
            from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            self.froms.lock().unwrap().push(from);
            OnceSource(self.updates.clone()).subscribe(from).await
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    /// The state a replay of the first `count` fixture events reaches, as a checkpoint
    /// of `key`.
    fn checkpoint_after(count: usize, key: &DustSecretKey) -> Checkpoint {
        let updates = fixture_updates();
        let events: Vec<Event<DefaultDB>> = updates[..count]
            .iter()
            .map(|update| midnight_serialize::tagged_deserialize(&mut &update.raw[..]).unwrap())
            .collect();
        let newest = &updates[count - 1];
        Checkpoint {
            owner: owner_of(key),
            applied: newest.id,
            event_hash: event_hash(&newest.raw),
            local: DustLocalState::new(INITIAL_PARAMETERS.dust)
                .replay_events(key, events.iter())
                .unwrap(),
        }
    }

    async fn ready(wallet: &FundingWallet) {
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(30))
            .await
            .unwrap();
    }

    fn assert_fully_replayed(wallet: &FundingWallet) {
        let full = replayed();
        let state = wallet.shared.state();
        assert_eq!(state.applied, Some(fixture_updates().last().unwrap().id));
        assert_eq!(state.local.sync_time, full.sync_time);
        let key = funded_key();
        let nullifiers = |local: &DustLocalState<DefaultDB>| {
            let mut all: Vec<_> = local.utxos().map(|utxo| utxo.nullifier(&key)).collect();
            all.sort_by_key(|nullifier| format!("{nullifier:?}"));
            all
        };
        assert_eq!(nullifiers(&state.local), nullifiers(&full));
    }

    #[tokio::test]
    async fn a_caught_up_wallet_keeps_a_checkpoint_of_its_replay() {
        let store = Arc::new(MemoryCheckpoints::default());
        let wallet = FundingWallet::start(
            funded_key(),
            Arc::new(OnceSource(fixture_updates())),
            Some(store.clone()),
        );
        ready(&wallet).await;
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let checkpoint = loop {
            if let Some(checkpoint) = store.decoded() {
                break checkpoint;
            }
            assert!(Instant::now() < deadline, "no checkpoint was kept");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        let newest = fixture_updates().pop().unwrap();
        assert_eq!(checkpoint.applied, newest.id);
        assert_eq!(checkpoint.event_hash, event_hash(&newest.raw));
        assert_eq!(checkpoint.owner, owner_of(&funded_key()));
        assert_eq!(checkpoint.local.sync_time, replayed().sync_time);
    }

    #[tokio::test]
    async fn a_restarted_wallet_resumes_from_its_checkpoint() {
        let key = funded_key();
        let checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        let source = RecordingSource::new(fixture_updates());
        let wallet = FundingWallet::start(
            key,
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        );
        ready(&wallet).await;
        assert_eq!(source.froms(), vec![Some(resumed_at)]);
        assert_fully_replayed(&wallet);
    }

    #[tokio::test]
    async fn a_checkpoint_the_indexer_disagrees_with_is_replayed_from_the_first_event() {
        let key = funded_key();
        let mut checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        checkpoint.event_hash = event_hash(b"another chain's event");
        let source = RecordingSource::new(fixture_updates());
        let wallet = FundingWallet::start(
            key,
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        );
        ready(&wallet).await;
        assert_eq!(source.froms(), vec![Some(resumed_at), None]);
        assert_fully_replayed(&wallet);
    }

    #[tokio::test]
    async fn a_checkpoint_of_another_funding_key_is_ignored() {
        let other = dust_secret_key(&[0x42; 32]).unwrap();
        let source = RecordingSource::new(fixture_updates());
        let wallet = FundingWallet::start(
            funded_key(),
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint_after(
                10, &other,
            )))),
        );
        ready(&wallet).await;
        assert_eq!(source.froms(), vec![None]);
        assert_fully_replayed(&wallet);
    }

    #[tokio::test]
    async fn an_unreadable_checkpoint_is_ignored() {
        let source = RecordingSource::new(fixture_updates());
        let wallet = FundingWallet::start(
            funded_key(),
            source.clone(),
            Some(Arc::new(MemoryCheckpoints(Mutex::new(Some(
                b"not a checkpoint".to_vec(),
            ))))),
        );
        ready(&wallet).await;
        assert_eq!(source.froms(), vec![None]);
        assert_fully_replayed(&wallet);
    }

    #[tokio::test(start_paused = true)]
    async fn a_checkpoint_past_the_indexers_newest_event_is_replayed_from_the_first_event() {
        let key = funded_key();
        let checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        // A reset chain that has not reached the checkpoint's event: the indexer
        // serves what it has from the cursor, which is nothing, and then waits.
        let mut shorter: Vec<_> = fixture_updates().into_iter().take(5).collect();
        let newest = shorter.last().unwrap().id;
        for update in &mut shorter {
            update.max_id = newest;
        }
        let source = RecordingSource::new(shorter);
        let wallet = FundingWallet::start(
            key,
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        );
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(600))
            .await
            .unwrap();
        assert_eq!(source.froms(), vec![Some(resumed_at), None]);
        assert_eq!(wallet.shared.state().applied, Some(newest));
    }

    /// A wallet resumed from a checkpoint after the fixture's tenth event, its store,
    /// and the source recording where each subscription started.
    async fn restored_wallet() -> (
        FundingWallet,
        Arc<MemoryCheckpoints>,
        Arc<RecordingSource>,
        u64,
    ) {
        let key = funded_key();
        let checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        let store = Arc::new(MemoryCheckpoints::holding(checkpoint));
        let source = RecordingSource::new(fixture_updates());
        let wallet = FundingWallet::start(key, source.clone(), Some(store.clone()));
        ready(&wallet).await;
        (wallet, store, source, resumed_at)
    }

    /// Lets the subscription act on a failure, then waits for the wallet again.
    async fn settle(wallet: &FundingWallet) {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        ready(wallet).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_submit_resumes_the_replay_from_the_latest_checkpoint() {
        let (wallet, store, source, resumed_at) = restored_wallet().await;
        wallet.failed(false);
        settle(&wallet).await;
        assert_eq!(source.froms(), vec![Some(resumed_at), Some(resumed_at)]);
        assert_fully_replayed(&wallet);
        assert!(
            store.decoded().is_some() && wallet.shared.state().restored,
            "a failure alone keeps the checkpoint"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn restored_wallets_failing_three_times_once_used_forget_the_checkpoint() {
        let (wallet, store, source, resumed_at) = restored_wallet().await;
        // A landing between failures clears the strikes, and a failure before the
        // wallet was used is no strike.
        for (used, landed) in [(true, false), (true, true), (false, false), (true, false)] {
            wallet.failed(used);
            settle(&wallet).await;
            if landed {
                wallet.landed();
            }
        }
        assert_eq!(
            wallet.shared.snapshots().strikes,
            1,
            "a landing and a failure before paying count no strike"
        );
        // The first reload resumes the restored checkpoint; its caught-up replay keeps
        // the newest event's, which the later reloads resume.
        let newest = Some(fixture_updates().last().unwrap().id);
        assert_eq!(
            source.froms(),
            vec![Some(resumed_at), Some(resumed_at), newest, newest, newest]
        );

        // The last of those was the first strike since the landing; this is the second.
        wallet.failed(true);
        settle(&wallet).await;
        assert_eq!(
            wallet.shared.snapshots().strikes,
            2,
            "two strikes in a row keep the checkpoint"
        );

        wallet.failed(true);
        settle(&wallet).await;
        assert_eq!(
            source.froms().last(),
            Some(&None),
            "the third strike replays from the first event"
        );
        assert_fully_replayed(&wallet);
        let kept = store
            .decoded()
            .expect("the fresh replay keeps a new checkpoint once caught up");
        assert_eq!(kept.applied, fixture_updates().last().unwrap().id);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wallet_replayed_from_the_first_event_resumes_from_the_checkpoint_it_kept() {
        let source = RecordingSource::new(fixture_updates());
        let wallet = FundingWallet::start(funded_key(), source.clone(), None);
        // Lets the caught-up replay keep its checkpoint before the first failure.
        settle(&wallet).await;
        let newest = fixture_updates().last().unwrap().id;
        for _ in 0..RESTORE_STRIKES {
            wallet.failed(true);
            settle(&wallet).await;
        }
        // Each failure resumes from the checkpoint the replay kept in memory.
        let mut expected = vec![None];
        expected.extend(vec![Some(newest); RESTORE_STRIKES as usize]);
        assert_eq!(source.froms(), expected);
    }

    #[tokio::test(start_paused = true)]
    async fn a_wallet_whose_submit_just_failed_is_not_ready_until_it_reloads() {
        let (wallet, _store, _source, _resumed_at) = restored_wallet().await;
        wallet.failed(false);
        // No await between the failure and the next publish's wait: the reload has not
        // run yet, and the state it will replace is not ready.
        let error = wallet
            .ready_by(Instant::now() + std::time::Duration::from_millis(1))
            .await
            .expect_err("a wallet about to reload is not ready");
        assert!(matches!(error, SubmitError::WalletUnsynced(_)), "{error}");
        ready(&wallet).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_replay_started_over_keeps_its_first_checkpoint_at_once() {
        let store = Arc::new(CountingCheckpoints::default());
        let _wallet = FundingWallet::start(
            funded_key(),
            Arc::new(CatchesUpThenBreaks::default()),
            Some(store.clone()),
        );
        // Kept once caught up; 60 s later the replay starts over and catches up again,
        // well inside the interval, and keeps again since nothing it kept survives.
        tokio::time::sleep(std::time::Duration::from_secs(70)).await;
        let newest = fixture_updates().last().unwrap().id;
        assert_eq!(*store.0.lock().unwrap(), vec![newest, newest]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_replay_started_over_carries_no_strikes() {
        let (wallet, _store, _source, _resumed_at) = restored_wallet().await;
        for _ in 0..RESTORE_STRIKES - 1 {
            wallet.failed(true);
            settle(&wallet).await;
        }
        assert_eq!(wallet.shared.snapshots().strikes, RESTORE_STRIKES - 1);
        start_over(&wallet.shared);
        assert_eq!(
            wallet.shared.snapshots().strikes,
            0,
            "the strikes were against the checkpoint the replay dropped"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_wake_without_a_failure_changes_nothing() {
        let (wallet, _store, source, resumed_at) = restored_wallet().await;
        wallet.shared.wake.notify_one();
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        assert_eq!(source.froms(), vec![Some(resumed_at)]);
    }

    /// Delivers the fixture, then an event the replay cannot absorb; every
    /// subscription, from wherever it starts. Records when each one started.
    #[derive(Default)]
    struct CatchesUpThenBreaks(Mutex<Vec<tokio::time::Instant>>);

    #[async_trait]
    impl DustEventSource for CatchesUpThenBreaks {
        async fn subscribe(
            &self,
            _from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            self.0.lock().unwrap().push(tokio::time::Instant::now());
            let updates = fixture_updates();
            let mut broken = updates.last().unwrap().clone();
            broken.id += 1;
            broken.max_id += 1;
            broken.raw.truncate(10);
            let caught_up: Vec<_> = updates.into_iter().map(Ok).collect();
            let pause =
                futures_util::stream::once(tokio::time::sleep(std::time::Duration::from_secs(60)))
                    .filter_map(|()| async { None });
            Ok(futures_util::stream::iter(caught_up)
                .chain(pause)
                .chain(futures_util::stream::iter([Ok(broken)]))
                .chain(futures_util::stream::pending())
                .boxed())
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    /// Fails its first `failures` subscriptions with a stream error (a dropped
    /// connection, not a replay the state could not absorb), then serves the fixture.
    struct FailsFirst {
        failures: usize,
        subscriptions: std::sync::atomic::AtomicUsize,
        updates: Vec<DustEventUpdate>,
    }

    #[async_trait]
    impl DustEventSource for FailsFirst {
        async fn subscribe(
            &self,
            from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            let attempt = self
                .subscriptions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt < self.failures {
                return Ok(futures_util::stream::iter([Err(anyhow::anyhow!(
                    "the indexer dropped the connection"
                ))])
                .boxed());
            }
            OnceSource(self.updates.clone()).subscribe(from).await
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_subscription_is_resubscribed_without_backing_off() {
        // Six dropped connections at the resubscribe delay take 12 s; backing off as
        // for a failed replay would take 4 + 8 + ... + 128 = 252 s.
        let source = Arc::new(FailsFirst {
            failures: 6,
            subscriptions: Default::default(),
            updates: fixture_updates(),
        });
        let wallet = FundingWallet::start(funded_key(), source.clone(), None);
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(60))
            .await
            .unwrap();
    }

    /// Cannot be subscribed to: the indexer refuses the connection.
    #[derive(Default)]
    struct Refuses {
        subscriptions: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl DustEventSource for Refuses {
        async fn subscribe(
            &self,
            _from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            self.subscriptions
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            anyhow::bail!("HTTP error: 403 Forbidden")
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_subscription_is_retried_with_a_growing_delay() {
        let source = Arc::new(Refuses::default());
        let _wallet = FundingWallet::start(funded_key(), source.clone(), None);
        let attempts = || {
            source
                .subscriptions
                .load(std::sync::atomic::Ordering::SeqCst)
        };
        // Attempts at 0, 4, 12, 28 and 60 s, then one a minute: 14 in the first ten
        // minutes, where the resubscribe delay alone would make 300.
        tokio::time::sleep(std::time::Duration::from_secs(61)).await;
        assert_eq!(attempts(), 5);
        tokio::time::sleep(std::time::Duration::from_secs(540)).await;
        assert_eq!(attempts(), 14);
    }

    /// Serves `batches` in order as separate deliveries, each after `gap` of
    /// silence, then stays open; records where each subscription started.
    struct Batches {
        batches: Vec<(std::time::Duration, Vec<DustEventUpdate>)>,
        froms: Mutex<Vec<Option<u64>>>,
    }

    #[async_trait]
    impl DustEventSource for Batches {
        async fn subscribe(
            &self,
            from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            self.froms.lock().unwrap().push(from);
            let mut stream: BoxStream<'static, anyhow::Result<DustEventUpdate>> =
                futures_util::stream::empty().boxed();
            for (gap, batch) in self.batches.clone() {
                let batch: Vec<_> = batch
                    .into_iter()
                    .filter(|update| from.is_none_or(|from| update.id >= from))
                    .map(Ok)
                    .collect();
                // A pause, so the replay applies what came before as its own batch.
                let pause = futures_util::stream::once(async move {
                    tokio::time::sleep(gap).await;
                    tokio::task::yield_now().await;
                })
                .filter_map(|()| async { None });
                stream = stream
                    .chain(pause)
                    .chain(futures_util::stream::iter(batch))
                    .boxed();
            }
            Ok(stream.chain(futures_util::stream::pending()).boxed())
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test]
    async fn a_resumed_replay_checks_only_its_first_delivery_against_the_checkpoint() {
        let key = funded_key();
        let checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        let updates = fixture_updates();
        let (first, rest) = updates.split_at(15);
        let source = Arc::new(Batches {
            batches: vec![
                (std::time::Duration::ZERO, first.to_vec()),
                (std::time::Duration::ZERO, rest.to_vec()),
            ],
            froms: Mutex::default(),
        });
        let wallet = FundingWallet::start(
            key,
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        );
        ready(&wallet).await;
        assert_eq!(
            *source.froms.lock().unwrap(),
            vec![Some(resumed_at)],
            "a later delivery starting past the checkpoint is not a disagreement"
        );
        assert_fully_replayed(&wallet);
    }

    /// Records the event of every checkpoint kept.
    #[derive(Default)]
    struct CountingCheckpoints(Mutex<Vec<u64>>);

    #[async_trait]
    impl DustCheckpointStore for CountingCheckpoints {
        async fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(None)
        }

        async fn save(&self, checkpoint: &[u8]) -> anyhow::Result<()> {
            let applied = Checkpoint::decode(checkpoint).unwrap().applied;
            self.0.lock().unwrap().push(applied);
            Ok(())
        }

        async fn clear(&self) -> anyhow::Result<()> {
            unimplemented!("never cleared")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_checkpoint_is_kept_once_caught_up_then_at_most_once_per_interval_of_progress() {
        let updates = fixture_updates();
        // Report `newest` as the indexer's newest event, so the replay is caught up
        // at the end of the slice.
        let caught_up_at = |slice: &[DustEventUpdate]| -> Vec<DustEventUpdate> {
            let newest = slice.last().unwrap().id;
            slice
                .iter()
                .cloned()
                .map(|update| DustEventUpdate {
                    max_id: newest,
                    ..update
                })
                .collect()
        };
        let past_interval = CHECKPOINT_INTERVAL + std::time::Duration::from_secs(1);
        let source = Arc::new(Batches {
            batches: vec![
                // Behind the indexer: nothing is kept.
                (std::time::Duration::ZERO, updates[..5].to_vec()),
                // Caught up: the first checkpoint.
                (std::time::Duration::ZERO, caught_up_at(&updates[5..10])),
                // Progress inside the interval: not yet.
                (std::time::Duration::ZERO, caught_up_at(&updates[10..15])),
                // Progress past the interval: the second checkpoint.
                (past_interval, updates[15..].to_vec()),
                // No progress past another interval: nothing new to keep.
                (past_interval, vec![updates.last().unwrap().clone()]),
            ],
            froms: Mutex::default(),
        });
        let store = Arc::new(CountingCheckpoints::default());
        let _wallet = FundingWallet::start(funded_key(), source.clone(), Some(store.clone()));
        tokio::time::sleep(past_interval * 4).await;
        assert_eq!(
            *store.0.lock().unwrap(),
            vec![updates[9].id, updates.last().unwrap().id]
        );
        assert_eq!(*source.froms.lock().unwrap(), vec![None]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_resumed_replay_that_matched_its_checkpoint_is_never_dropped_for_silence() {
        let key = funded_key();
        let checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        let source = RecordingSource::new(fixture_updates());
        let wallet = FundingWallet::start(
            key,
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        );
        ready(&wallet).await;
        // A quiet chain long past the resume timeout, and past any backoff after it.
        tokio::time::sleep(RESUME_TIMEOUT * 10).await;
        assert_eq!(source.froms(), vec![Some(resumed_at)]);
        assert_fully_replayed(&wallet);
    }

    /// The first `restarts` subscriptions serve the fixture with an event the replay
    /// cannot absorb; the next serves it whole and drops the connection; later ones
    /// serve it and stay open.
    struct Scripted {
        restarts: usize,
        subscriptions: Mutex<Vec<tokio::time::Instant>>,
    }

    #[async_trait]
    impl DustEventSource for Scripted {
        async fn subscribe(
            &self,
            from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            let attempt = {
                let mut subscriptions = self.subscriptions.lock().unwrap();
                subscriptions.push(tokio::time::Instant::now());
                subscriptions.len() - 1
            };
            let mut updates = fixture_updates();
            if attempt < self.restarts {
                updates[5].raw.truncate(10);
            }
            let served: Vec<_> = updates
                .into_iter()
                .filter(|update| from.is_none_or(|from| update.id >= from))
                .map(Ok)
                .collect();
            let stream = futures_util::stream::iter(served);
            Ok(if attempt == self.restarts {
                stream
                    .chain(futures_util::stream::iter([Err(anyhow::anyhow!(
                        "the indexer dropped the connection"
                    ))]))
                    .boxed()
            } else {
                stream.chain(futures_util::stream::pending()).boxed()
            })
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_subscription_after_restarts_is_resubscribed_without_their_backoff() {
        let source = Arc::new(Scripted {
            restarts: 2,
            subscriptions: Mutex::default(),
        });
        let _wallet = FundingWallet::start(funded_key(), source.clone(), None);
        // Restarts at 0 s and 4 s grow the delay to 8 s; the third subscription, at 12 s,
        // replays and drops; the fourth follows it by the 2 s resubscribe delay.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let at = source.subscriptions.lock().unwrap().clone();
        assert!(at.len() >= 4, "{} subscriptions", at.len());
        assert_eq!(at[3] - at[2], RESUBSCRIBE_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn a_replay_that_keeps_failing_backs_off_to_at_most_ten_minutes() {
        let mut updates = fixture_updates();
        updates[5].raw.truncate(10);
        let source = RecordingSource::new(updates);
        let _wallet = FundingWallet::start(funded_key(), source.clone(), None);
        // Delays 4, 8, ..., 512 s sum to 1020 s; then 600 s each when capped, 1024, 2048 s uncapped.
        tokio::time::sleep(std::time::Duration::from_secs(1020 + 3 * 600 + 1)).await;
        assert_eq!(source.froms().len(), 9 + 3, "{:?}", source.froms());
    }

    #[test]
    fn a_checkpoint_keeps_its_stored_layout() {
        let checkpoint = checkpoint_after(10, &funded_key());
        let bytes = checkpoint.encode();
        assert_eq!(&bytes[..16], b"mpc-dust-ckpt-v1");
        assert_eq!(&bytes[16..48], &checkpoint.owner);
        assert_eq!(&bytes[48..56], &checkpoint.applied.to_le_bytes());
        assert_eq!(&bytes[56..88], &checkpoint.event_hash);
    }

    /// Holds a checkpoint and logs every save (by event) and clear, in order.
    struct LoggingCheckpoints {
        held: Mutex<Option<Vec<u8>>>,
        log: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DustCheckpointStore for LoggingCheckpoints {
        async fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
            Ok(self.held.lock().unwrap().clone())
        }

        async fn save(&self, checkpoint: &[u8]) -> anyhow::Result<()> {
            let applied = Checkpoint::decode(checkpoint).unwrap().applied;
            self.log.lock().unwrap().push(format!("save {applied}"));
            *self.held.lock().unwrap() = Some(checkpoint.to_vec());
            Ok(())
        }

        async fn clear(&self) -> anyhow::Result<()> {
            self.log.lock().unwrap().push("clear".into());
            *self.held.lock().unwrap() = None;
            Ok(())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_forgotten_checkpoint_is_cleared_from_the_store_once_and_its_strikes_start_over() {
        let key = funded_key();
        let store = Arc::new(LoggingCheckpoints {
            held: Mutex::new(Some(checkpoint_after(10, &key).encode())),
            log: Mutex::default(),
        });
        let source = RecordingSource::new(fixture_updates());
        let wallet = FundingWallet::start(key, source.clone(), Some(store.clone()));
        ready(&wallet).await;
        for _ in 0..RESTORE_STRIKES {
            wallet.failed(true);
            settle(&wallet).await;
        }
        let newest = fixture_updates().last().unwrap().id;
        assert_eq!(
            *store.log.lock().unwrap(),
            vec![
                format!("save {newest}"),
                "clear".to_string(),
                format!("save {newest}")
            ],
            "the stored checkpoint is cleared before the fresh replay keeps its own"
        );
        // The fresh replay's first failure is no strike; the next is the first strike
        // against the checkpoint it resumed from, so nothing is cleared again.
        for _ in 0..2 {
            wallet.failed(true);
            settle(&wallet).await;
        }
        assert_eq!(
            *store.log.lock().unwrap(),
            vec![
                format!("save {newest}"),
                "clear".to_string(),
                format!("save {newest}")
            ],
            "forgetting starts the strikes over and clears the store once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_failed_submits_resume_without_backing_off() {
        let (wallet, _store, source, resumed_at) = restored_wallet().await;
        assert_eq!(source.froms(), vec![Some(resumed_at)]);
        for round in 1..=4 {
            wallet.failed(false);
            // A reload resubscribes after the resubscribe delay, never a backoff.
            tokio::time::sleep(RESUBSCRIBE_DELAY + std::time::Duration::from_secs(1)).await;
            assert_eq!(source.froms().len(), round + 1, "failure {round}");
            ready(&wallet).await;
        }
    }

    /// Serves the fixture from `from` on the first subscription, then ends it; every
    /// later subscription stays silent. Records where each one started.
    struct EndsAfterFirst {
        updates: Vec<DustEventUpdate>,
        froms: Mutex<Vec<Option<u64>>>,
    }

    #[async_trait]
    impl DustEventSource for EndsAfterFirst {
        async fn subscribe(
            &self,
            from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            let first = {
                let mut froms = self.froms.lock().unwrap();
                froms.push(from);
                froms.len() == 1
            };
            if !first {
                return Ok(futures_util::stream::pending().boxed());
            }
            let updates: Vec<_> = self
                .updates
                .iter()
                .filter(|update| from.is_none_or(|from| update.id >= from))
                .cloned()
                .map(Ok)
                .collect();
            Ok(futures_util::stream::iter(updates).boxed())
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_submit_failing_while_the_subscription_is_down_still_reloads() {
        let key = funded_key();
        let checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        let newest = fixture_updates().last().unwrap().id;
        let source = Arc::new(EndsAfterFirst {
            updates: fixture_updates(),
            froms: Mutex::default(),
        });
        let wallet = FundingWallet::start(
            key,
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        );
        // The first subscription replays to the newest event and ends; the wallet waits
        // out the resubscribe delay.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(*source.froms.lock().unwrap(), vec![Some(resumed_at)]);
        assert_eq!(wallet.shared.state().applied, Some(newest));
        wallet.failed(false);
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(
            *source.froms.lock().unwrap(),
            vec![Some(resumed_at), Some(newest), Some(newest)],
            "the silent subscription acts on the failure and resumes the kept checkpoint"
        );
    }

    /// Resumes from `resumed_at` on the first subscription with an event after it the
    /// replay cannot absorb; later subscriptions stay silent.
    struct BreaksAfterResume {
        froms: Mutex<Vec<Option<u64>>>,
    }

    #[async_trait]
    impl DustEventSource for BreaksAfterResume {
        async fn subscribe(
            &self,
            from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            let first = {
                let mut froms = self.froms.lock().unwrap();
                froms.push(from);
                froms.len() == 1
            };
            if !first {
                return Ok(futures_util::stream::pending().boxed());
            }
            let mut updates = fixture_updates();
            updates[12].raw.truncate(10);
            let served: Vec<_> = updates
                .into_iter()
                .filter(|update| from.is_none_or(|from| update.id >= from))
                .map(Ok)
                .collect();
            Ok(futures_util::stream::iter(served)
                .chain(futures_util::stream::pending())
                .boxed())
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_replay_started_over_no_longer_reloads_the_checkpoint_it_came_from() {
        let key = funded_key();
        let checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        let source = Arc::new(BreaksAfterResume {
            froms: Mutex::default(),
        });
        let wallet = FundingWallet::start(
            key,
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        );
        // The resumed replay fails and starts over from the first event, which the
        // indexer has not served yet.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        assert_eq!(*source.froms.lock().unwrap(), vec![Some(resumed_at), None]);
        // A submit in flight from before fails.
        wallet.failed(true);
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(
            *source.froms.lock().unwrap(),
            vec![Some(resumed_at), None, None],
            "the checkpoint the replay started over from is not resumed again"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_restart_after_catching_up_resubscribes_after_four_seconds() {
        let source = Arc::new(CatchesUpThenBreaks::default());
        let _wallet = FundingWallet::start(funded_key(), source.clone(), None);
        tokio::time::sleep(std::time::Duration::from_secs(200)).await;
        let at = source.0.lock().unwrap().clone();
        assert!(at.len() >= 3, "{} subscriptions", at.len());
        // 60 s caught up before the event that cannot be absorbed, then 4 s.
        for pair in at.windows(2) {
            assert_eq!(
                pair[1] - pair[0],
                std::time::Duration::from_secs(64),
                "{at:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_checkpoint_kept_as_the_third_strike_lands_is_forgotten_too() {
        let (wallet, _store, source, resumed_at) = restored_wallet().await;
        for _ in 0..RESTORE_STRIKES - 1 {
            wallet.failed(true);
            settle(&wallet).await;
        }
        assert_eq!(source.froms().len(), 3);
        assert_eq!(source.froms()[0], Some(resumed_at));
        // A checkpoint is due when the third strike lands.
        tokio::time::sleep(CHECKPOINT_INTERVAL).await;
        wallet.failed(true);
        // What the subscription does when that strike lands while it applies a batch:
        // it keeps the due checkpoint before it reaches the select that sees the wake.
        keep_checkpoint(&wallet.shared).await;
        settle(&wallet).await;
        assert_eq!(
            source.froms().last(),
            Some(&None),
            "the third strike replays from the first event: {:?}",
            source.froms()
        );
    }

    /// Serves the first `visible` fixture events (inclusive from `from`), each with
    /// `max_id` set to the newest visible one, and delivers newly visible events
    /// on the open subscription.
    struct GrowingSource {
        updates: Vec<DustEventUpdate>,
        visible: Arc<std::sync::atomic::AtomicUsize>,
        froms: Arc<Mutex<Vec<Option<u64>>>>,
    }

    #[async_trait]
    impl DustEventSource for GrowingSource {
        async fn subscribe(
            &self,
            from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            self.froms.lock().unwrap().push(from);
            let updates = self.updates.clone();
            let visible = self.visible.clone();
            let start = updates
                .iter()
                .position(|update| from.is_none_or(|from| update.id >= from))
                .unwrap_or(updates.len());
            Ok(futures_util::stream::unfold(start, move |next| {
                let updates = updates.clone();
                let visible = visible.clone();
                async move {
                    loop {
                        let shown = visible.load(std::sync::atomic::Ordering::SeqCst);
                        if next < shown {
                            let mut update = updates[next].clone();
                            update.max_id = updates[shown - 1].id;
                            return Some((Ok(update), next + 1));
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            })
            .boxed())
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    /// The interval runs from the last kept checkpoint, whatever reloads came in
    /// between, as the intent builder's `kept_at` did: a failed submit 4 min after a
    /// checkpoint, then new events 2 min later, keep a new one at once.
    #[tokio::test(start_paused = true)]
    async fn a_reload_does_not_postpone_the_next_checkpoint() {
        let store = Arc::new(MemoryCheckpoints::default());
        let visible = Arc::new(std::sync::atomic::AtomicUsize::new(20));
        let froms = Arc::new(Mutex::new(Vec::new()));
        let updates = fixture_updates();
        let wallet = FundingWallet::start(
            funded_key(),
            Arc::new(GrowingSource {
                updates: updates.clone(),
                visible: visible.clone(),
                froms: froms.clone(),
            }),
            Some(store.clone()),
        );
        ready(&wallet).await;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let first = store
            .decoded()
            .expect("first checkpoint kept at once")
            .applied;
        assert_eq!(first, updates[19].id);

        tokio::time::sleep(std::time::Duration::from_secs(4 * 60)).await;
        wallet.failed(false);
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        ready(&wallet).await;

        tokio::time::sleep(std::time::Duration::from_secs(2 * 60)).await;
        visible.store(updates.len(), std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        ready(&wallet).await;
        // 6.5 min since the last kept checkpoint.
        let kept = store.decoded().unwrap().applied;
        assert_eq!(
            kept,
            updates.last().unwrap().id,
            "a checkpoint is kept 6.5 min after the last one, whatever the reload 2.5 min ago"
        );
    }

    /// A reload since `ready_by` holds an older state, which `plan` must not price from.
    #[tokio::test(start_paused = true)]
    async fn a_wallet_reloaded_after_ready_plans_nothing() {
        let (wallet, _store, _source, _resumed_at) = restored_wallet().await;
        let local = replayed();
        let ctime = local.sync_time;
        let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
        let mut rng = StdRng::seed_from_u64(5);
        let base = base(&mut rng, ttl);
        // What `reload` does once a failed submit's wake is acted on.
        resume_from(&wallet.shared, checkpoint_after(10, &funded_key()));
        let planned = wallet.plan(
            &base,
            &INITIAL_PARAMETERS,
            ctime,
            ttl,
            "undeployed",
            &mut rng,
        );
        assert!(
            matches!(planned, Err(SubmitError::WalletUnsynced(_))),
            "a reloaded replay planned a fee from the checkpoint's older state"
        );
    }

    /// A restart (`start_over`, as `apply` runs it on a mismatch or a bad event) right
    /// after the third strike leaves its clear to finish, and a later failure of the
    /// fresh replay clears nothing.
    #[tokio::test(start_paused = true)]
    async fn a_restart_racing_the_third_strike_still_forgets() {
        let (wallet, store, _source, _resumed_at) = restored_wallet().await;
        for _ in 0..2 {
            wallet.failed(true);
            settle(&wallet).await;
        }
        wallet.failed(true);
        // No await in between: the spawned clear has not run yet.
        start_over(&wallet.shared);
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let forget_pending = wallet.shared.snapshots().forget;
        let stored_after_strikes = store.decoded().map(|checkpoint| checkpoint.applied);
        // The fresh replay keeps a good checkpoint (simulated), then any later failure.
        let good = checkpoint_after(29, &funded_key());
        *store.0.lock().unwrap() = Some(good.encode());
        wallet.shared.snapshots().latest = Some(good);
        wallet.failed(false);
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert!(
            !forget_pending,
            "the third strike's forget was left pending"
        );
        assert_eq!(
            stored_after_strikes, None,
            "the third strike cleared the store"
        );
        assert!(
            store.decoded().is_some(),
            "a later failure leaves the replay's good checkpoint stored"
        );
    }

    /// Serves the fixture from `from`; while `down` is set,
    /// open streams end and new subscriptions fail, as with an unreachable indexer.
    struct Switchable {
        down: Arc<std::sync::atomic::AtomicBool>,
        froms: Mutex<Vec<Option<u64>>>,
    }

    #[async_trait]
    impl DustEventSource for Switchable {
        async fn subscribe(
            &self,
            from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            if self.down.load(std::sync::atomic::Ordering::SeqCst) {
                anyhow::bail!("connection refused");
            }
            self.froms.lock().unwrap().push(from);
            let updates: Vec<_> = fixture_updates()
                .into_iter()
                .filter(|update| from.is_none_or(|from| update.id >= from))
                .map(Ok)
                .collect();
            let down = self.down.clone();
            let tail = futures_util::stream::unfold((), move |()| {
                let down = down.clone();
                async move {
                    loop {
                        if down.load(std::sync::atomic::Ordering::SeqCst) {
                            return None;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            });
            Ok(futures_util::stream::iter(updates).chain(tail).boxed())
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_third_strike_while_the_indexer_is_down_still_clears_the_store() {
        let key = funded_key();
        let store = Arc::new(MemoryCheckpoints::holding(checkpoint_after(10, &key)));
        let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let source = Arc::new(Switchable {
            down: down.clone(),
            froms: Mutex::default(),
        });
        let wallet = FundingWallet::start(key, source, Some(store.clone()));
        ready(&wallet).await;
        for _ in 0..RESTORE_STRIKES - 1 {
            wallet.failed(true);
            settle(&wallet).await;
        }
        down.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        wallet.failed(true);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert!(
            store.decoded().is_none(),
            "the third strike clears the store with no subscription live"
        );
    }

    /// Holds a checkpoint and logs its writes in order; a save takes five seconds.
    struct SlowCheckpoints {
        held: MemoryCheckpoints,
        log: Mutex<Vec<&'static str>>,
    }

    #[async_trait]
    impl DustCheckpointStore for SlowCheckpoints {
        async fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
            self.held.load().await
        }

        async fn save(&self, checkpoint: &[u8]) -> anyhow::Result<()> {
            self.log.lock().unwrap().push("save starts");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            self.log.lock().unwrap().push("save lands");
            self.held.save(checkpoint).await
        }

        async fn clear(&self) -> anyhow::Result<()> {
            self.log.lock().unwrap().push("clear");
            self.held.clear().await
        }
    }

    /// A save already running when the third strike lands finishes before the forget
    /// clears the store, as the intent builder's flow lock ordered the two.
    #[tokio::test(start_paused = true)]
    async fn a_third_strike_during_a_checkpoint_save_still_leaves_the_store_cleared() {
        let key = funded_key();
        let store = Arc::new(SlowCheckpoints {
            held: MemoryCheckpoints::holding(checkpoint_after(10, &key)),
            log: Mutex::default(),
        });
        let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let source = Arc::new(Switchable {
            down: down.clone(),
            froms: Mutex::default(),
        });
        let wallet = FundingWallet::start(key, source, Some(store.clone()));
        ready(&wallet).await;
        // The restored replay caught up and is keeping its first checkpoint.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(*store.log.lock().unwrap(), vec!["save starts"]);
        // No indexer, so no fresh replay keeps a checkpoint of its own afterwards.
        down.store(true, std::sync::atomic::Ordering::SeqCst);
        wallet.shared.snapshots().strikes = RESTORE_STRIKES - 1;
        wallet.failed(true);
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        assert_eq!(
            *store.log.lock().unwrap(),
            vec!["save starts", "save lands", "clear"]
        );
        assert!(
            store.held.decoded().is_none(),
            "the save put the forgotten checkpoint back in the store"
        );
    }

    /// Holds a checkpoint; a clear takes twenty seconds.
    struct SlowClear(MemoryCheckpoints);

    #[async_trait]
    impl DustCheckpointStore for SlowClear {
        async fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
            self.0.load().await
        }

        async fn save(&self, checkpoint: &[u8]) -> anyhow::Result<()> {
            self.0.save(checkpoint).await
        }

        async fn clear(&self) -> anyhow::Result<()> {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            self.0.clear().await
        }
    }

    /// The replay a third strike starts over does not wait for a slow store to clear:
    /// it goes on applying events, keeps nothing until the clear is done, and keeps its
    /// own checkpoint after it.
    #[tokio::test(start_paused = true)]
    async fn a_replay_does_not_wait_for_a_forgotten_checkpoint_to_clear() {
        let key = funded_key();
        let store = Arc::new(SlowClear(MemoryCheckpoints::holding(checkpoint_after(
            10, &key,
        ))));
        let visible = Arc::new(std::sync::atomic::AtomicUsize::new(20));
        let updates = fixture_updates();
        let wallet = FundingWallet::start(
            key,
            Arc::new(GrowingSource {
                updates: updates.clone(),
                visible: visible.clone(),
                froms: Arc::default(),
            }),
            Some(store.clone()),
        );
        ready(&wallet).await;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        wallet.shared.snapshots().strikes = RESTORE_STRIKES - 1;
        wallet.failed(true);
        // The replay from the first event catches up while the store is still clearing.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        visible.store(25, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert!(
            wallet.shared.snapshots().forget,
            "the clear is still running"
        );
        assert_eq!(
            wallet.shared.state().applied,
            Some(updates[24].id),
            "the replay waited for the clear"
        );
        assert!(
            wallet.shared.snapshots().latest.is_none(),
            "a checkpoint was kept while the store was clearing"
        );

        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        assert!(
            store.0.decoded().is_none(),
            "the clear left the store empty"
        );
        visible.store(updates.len(), std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(
            store.0.decoded().map(|checkpoint| checkpoint.applied),
            updates.last().map(|update| update.id),
            "the fresh replay keeps its own checkpoint once the clear is done"
        );
    }

    /// A batch a fresh replay applies before the third strike's clear finishes keeps
    /// nothing, even after a restart took the reload.
    #[tokio::test(start_paused = true)]
    async fn nothing_is_kept_while_a_forget_is_pending() {
        let (wallet, _store, _source, _resumed_at) = restored_wallet().await;
        for _ in 0..RESTORE_STRIKES - 1 {
            wallet.failed(true);
            settle(&wallet).await;
        }
        wallet.failed(true);
        // No await until the keep below: the spawned clear has not run.
        start_over(&wallet.shared);
        apply(
            &wallet.shared,
            fixture_updates().into_iter().map(Ok).collect(),
        )
        .unwrap();
        assert!(wallet.shared.state().is_caught_up());
        assert!(!wallet.shared.state().reload, "the restart took the reload");
        keep_checkpoint(&wallet.shared).await;
        assert!(
            wallet.shared.snapshots().latest.is_none(),
            "a checkpoint was kept while the forget was pending"
        );
    }

    /// The resume timeout leaves an indexer a minute to serve the checkpoint's event.
    #[tokio::test(start_paused = true)]
    async fn a_resumed_replay_waits_out_a_slow_first_delivery() {
        let key = funded_key();
        let checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        let source = Arc::new(Batches {
            batches: vec![(std::time::Duration::from_secs(45), fixture_updates())],
            froms: Mutex::default(),
        });
        let wallet = FundingWallet::start(
            key,
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        );
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(120))
            .await
            .unwrap();
        assert_eq!(*source.froms.lock().unwrap(), vec![Some(resumed_at)]);
        assert_fully_replayed(&wallet);
    }

    /// A failed submit's reload is pending until the subscription acts on it; a plan in
    /// that window prices nothing from the state about to be replaced.
    #[tokio::test(start_paused = true)]
    async fn a_wallet_whose_submit_just_failed_plans_nothing() {
        let (wallet, _store, _source, _resumed_at) = restored_wallet().await;
        let local = replayed();
        let ctime = local.sync_time;
        let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
        let mut rng = StdRng::seed_from_u64(5);
        let base = base(&mut rng, ttl);
        wallet.failed(false);
        let planned = wallet.plan(
            &base,
            &INITIAL_PARAMETERS,
            ctime,
            ttl,
            "undeployed",
            &mut rng,
        );
        assert!(
            matches!(planned, Err(SubmitError::WalletUnsynced(_))),
            "a wallet about to reload planned a fee"
        );
        ready(&wallet).await;
        assert!(wallet
            .plan(
                &base,
                &INITIAL_PARAMETERS,
                ctime,
                ttl,
                "undeployed",
                &mut rng
            )
            .is_ok());
    }

    /// Checkpoints of a caught-up replay that keeps moving are kept five minutes apart.
    #[tokio::test(start_paused = true)]
    async fn a_moving_replay_keeps_a_checkpoint_every_five_minutes() {
        let store = Arc::new(MemoryCheckpoints::default());
        let visible = Arc::new(std::sync::atomic::AtomicUsize::new(5));
        let updates = fixture_updates();
        let wallet = FundingWallet::start(
            funded_key(),
            Arc::new(GrowingSource {
                updates: updates.clone(),
                visible: visible.clone(),
                froms: Arc::default(),
            }),
            Some(store.clone()),
        );
        ready(&wallet).await;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert_eq!(store.decoded().unwrap().applied, updates[4].id);
        // At 4 min: progress inside the interval keeps nothing.
        tokio::time::sleep(std::time::Duration::from_secs(4 * 60)).await;
        visible.store(10, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(store.decoded().unwrap().applied, updates[4].id);
        // Past 5 min: the next progress is kept.
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        visible.store(15, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        assert_eq!(store.decoded().unwrap().applied, updates[14].id);
    }

    /// A checkpoint the indexer disagreed with is not resumed again by a later failure.
    #[tokio::test(start_paused = true)]
    async fn a_failure_after_a_mismatched_checkpoint_does_not_resume_it_again() {
        let key = funded_key();
        let mut checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        checkpoint.event_hash = event_hash(b"another chain's event");
        let source = Arc::new(EndsAfterFirst {
            updates: fixture_updates(),
            froms: Mutex::default(),
        });
        let wallet = FundingWallet::start(
            key,
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        );
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        assert_eq!(*source.froms.lock().unwrap(), vec![Some(resumed_at), None]);
        wallet.failed(true);
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(
            *source.froms.lock().unwrap(),
            vec![Some(resumed_at), None, None],
            "the mismatched checkpoint is not resumed again"
        );
    }

    /// Nor is a checkpoint the indexer never served within the resume timeout.
    #[tokio::test(start_paused = true)]
    async fn a_failure_after_a_resume_timeout_does_not_resume_the_checkpoint_again() {
        let key = funded_key();
        let checkpoint = checkpoint_after(10, &key);
        let resumed_at = checkpoint.applied;
        let source = RecordingSource::new(Vec::new());
        let wallet = FundingWallet::start(
            key,
            source.clone(),
            Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        );
        tokio::time::sleep(RESUME_TIMEOUT + std::time::Duration::from_secs(10)).await;
        assert_eq!(source.froms(), vec![Some(resumed_at), None]);
        wallet.failed(true);
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        assert_eq!(
            source.froms(),
            vec![Some(resumed_at), None, None],
            "the checkpoint that timed out is not resumed again"
        );
    }

    /// Catches up, falls behind on a later batch, then hits an event it cannot absorb.
    struct CatchesUpFallsBehindThenBreaks(Mutex<Vec<tokio::time::Instant>>);

    #[async_trait]
    impl DustEventSource for CatchesUpFallsBehindThenBreaks {
        async fn subscribe(
            &self,
            _from: Option<u64>,
        ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
            self.0.lock().unwrap().push(tokio::time::Instant::now());
            let updates = fixture_updates();
            let newest = updates.last().unwrap().id;
            let caught_up: Vec<_> = updates[..20]
                .iter()
                .cloned()
                .map(|update| {
                    Ok(DustEventUpdate {
                        max_id: updates[19].id,
                        ..update
                    })
                })
                .collect();
            let behind: Vec<_> = updates[20..25]
                .iter()
                .cloned()
                .map(|update| {
                    Ok(DustEventUpdate {
                        max_id: newest,
                        ..update
                    })
                })
                .collect();
            let mut broken = updates[25].clone();
            broken.max_id = newest;
            broken.raw.truncate(10);
            // Each pause starts when the stream reaches it.
            let pause = |secs| {
                futures_util::stream::once(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(secs)).await
                })
                .filter_map(|()| async { None })
            };
            Ok(futures_util::stream::iter(caught_up)
                .chain(pause(60))
                .chain(futures_util::stream::iter(behind))
                .chain(pause(1))
                .chain(futures_util::stream::iter([Ok(broken)]))
                .chain(futures_util::stream::pending())
                .boxed())
        }

        async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
            unimplemented!("never asked")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_replay_that_caught_up_once_restarts_without_backoff_though_behind_at_the_end() {
        let source = Arc::new(CatchesUpFallsBehindThenBreaks(Mutex::default()));
        let _wallet = FundingWallet::start(funded_key(), source.clone(), None);
        tokio::time::sleep(std::time::Duration::from_secs(250)).await;
        let at = source.0.lock().unwrap().clone();
        assert!(at.len() >= 3, "{} subscriptions", at.len());
        for pair in at.windows(2) {
            assert_eq!(
                pair[1] - pair[0],
                std::time::Duration::from_secs(65),
                "{at:?}"
            );
        }
    }

    /// Vectors from `@midnightntwrk/wallet-sdk-hd` 3.1.0-beta.1 and
    /// `@midnightntwrk/ledger-v9` 1.0.0-rc.3: `HDWallet.fromSeed(seed).selectAccount(0)
    /// .selectRoles([Roles.Dust]).deriveKeysAt(0)`, then `DustSecretKey.fromSeed(key)
    /// .publicKey`, printed as a bigint in hex.
    const DUST_KEY_VECTORS: [(&str, &str); 7] = [
        (
            "0404040404040404040404040404040404040404040404040404040404040404",
            "115db88b665025219c371ad48289cc6b274bccc6baa8b52fd6f7ada315e030c0",
        ),
        (
            "000102030405060708090a0b0c0d0e0f",
            "17ceaacc85ce9b89676e05f72fb44821f7ffba1892e95bd212a7fa31ed484a11",
        ),
        (
            "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\
             0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            "a1a70b03f310083be4857d1e601e0680d705c86ffbba8c052102d56e6f98797",
        ),
        // Lengths BIP-32 allows but `bip32::XPrv::new` refuses.
        (
            "ababababababababababababababababab",
            "26d8bb16a33c836cb9323c30ff3e29dfae2030c1962572ec05c865f40e2f8ca",
        ),
        (
            "abababababababababababababababababababababababab",
            "3be7a802021cc22fd708234aa773c1737349b2f4b4eba04f299faae4c4b92f27",
        ),
        (
            "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\
             0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f",
            "636c088396cbda348ebaf9e7c4d41c9d28aa732f8c9a9926871103afcdccb3c5",
        ),
        (
            "111111111111111111111111111111111111111111111111111111111111111111\
             111111111111111111111111111111111111111111111111111111111111",
            "4eddc5827d65b0bd423ef08b9c1eb6ad5ec119186f4be03e0a09549b03727a58",
        ),
    ];

    #[test]
    fn the_dust_key_matches_the_wallet_sdk_for_the_same_seed() {
        for (seed, public) in DUST_KEY_VECTORS {
            let key = dust_secret_key(&parse_seed(seed).unwrap()).unwrap();
            let public_key = midnight_ledger_v9::dust::DustPublicKey::from(key);
            let mut le = public_key.0.as_le_bytes();
            le.reverse();
            let hex = hex::encode(le);
            assert_eq!(hex.trim_start_matches('0'), public, "seed {seed}");
        }
    }

    #[test]
    fn a_seed_parses_with_or_without_its_prefix() {
        assert_eq!(parse_seed("0x0a0B").unwrap(), vec![0x0a, 0x0b]);
        assert_eq!(parse_seed(" 0a0b ").unwrap(), vec![0x0a, 0x0b]);
        assert!(parse_seed("0g").is_err());
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use crate::dust_feed::IndexerDustEvents;

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
            .expect("MIDNIGHT_LIVE_INDEXER_WS_URL must be set");
        let file = std::env::var("MIDNIGHT_LIVE_DUST_CHECKPOINT")
            .ok()
            .map(std::path::PathBuf::from);
        let resuming = file.as_ref().is_some_and(|file| file.exists());
        let checkpoints = file
            .clone()
            .map(|file| Arc::new(FileCheckpoints(file)) as Arc<dyn DustCheckpointStore>);
        let started = std::time::Instant::now();
        let key = dust_secret_key(&[0x42; 32]).unwrap();
        let wallet = FundingWallet::start(key, Arc::new(IndexerDustEvents::new(url)), checkpoints);
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(1800))
            .await
            .unwrap();
        let ready_after = started.elapsed();
        if let (Some(file), false) = (&file, resuming) {
            while !file.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
}
