//! The funding wallet: the DUST that pays every respond transaction's fee.
//!
//! Spendable DUST is derived by replaying the ledger's DUST events into a
//! `DustLocalState`, the same state the Midnight wallet SDK keeps; no node RPC serves
//! it. The state lives in memory. A checkpoint of it, kept in the node's store, lets a
//! restart resume the replay instead of starting it over from the first event.
//!
//! The wallet never adopts the pending marks `DustLocalState::spend` sets on its
//! scratch copy. It reserves the UTXOs a submitted transaction spends instead, and a
//! reservation ends when the chain spends them, when the submit is refused, or a
//! minute after the transaction's TTL, by when it has landed or never will.

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
/// The longest backoff between replays that keep restarting from the first event.
const MAX_RESTART_DELAY: std::time::Duration = std::time::Duration::from_secs(600);
/// The least time between two kept checkpoints of a caught-up replay.
const CHECKPOINT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);
/// How long loading or keeping a checkpoint may take.
const CHECKPOINT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const CHECKPOINT_MAGIC: &[u8; 16] = b"mpc-dust-ckpt-v1";

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
}

/// The replayed state after event `applied`, for the key whose public key hashes to
/// `owner`. A restart resumes from it only when the indexer still serves the same
/// event at `applied`, which `event_hash` checks.
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
    /// When a checkpoint was last kept, and of which event.
    checkpointed: Option<(Instant, u64)>,
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
            checkpointed: None,
            reservations: Vec::new(),
        }
    }

    /// Back to the first event, keeping the reservations of submits in flight.
    fn restart(&mut self) {
        let reservations = std::mem::take(&mut self.reservations);
        *self = Self::fresh();
        self.reservations = reservations;
    }

    fn is_ready(&self) -> bool {
        self.connected && self.is_caught_up()
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
}

impl Shared {
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
        });
        let sync = AbortOnDrop(tokio::spawn(follow(
            shared.clone(),
            source.clone(),
            checkpoints,
        )));
        Self {
            shared,
            source,
            _sync: sync,
        }
    }
}

/// Follows the event stream for the wallet's lifetime: resubscribes after any
/// failure from the newest applied event, and starts over from the first event when
/// the replayed state can no longer absorb what the indexer sends, backing off while
/// that keeps happening.
async fn follow(
    shared: Arc<Shared>,
    source: Arc<dyn DustEventSource>,
    checkpoints: Option<Arc<dyn DustCheckpointStore>>,
) {
    if let Some(store) = &checkpoints {
        restore(&shared, store.as_ref()).await;
    }
    let mut delay = RESUBSCRIBE_DELAY;
    loop {
        // Its own task, so a panic below ends one subscription rather than the
        // wallet; held so that dropping the wallet aborts it too.
        let restarted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut attempt = AbortOnDrop(tokio::spawn({
            let (shared, source, checkpoints) =
                (shared.clone(), source.clone(), checkpoints.clone());
            let restarted = restarted.clone();
            async move {
                let ended = subscribe_once(shared, source, checkpoints).await;
                restarted.store(ended, std::sync::atomic::Ordering::Relaxed);
            }
        }));
        if let Err(error) = (&mut attempt.0).await {
            tracing::error!(
                ?error,
                "midnight funding wallet: DUST event subscription panicked"
            );
        }
        let restarted = restarted.load(std::sync::atomic::Ordering::Relaxed);
        shared.state().connected = false;
        shared.progress.send_replace(());
        delay = if restarted {
            (delay * 2).min(MAX_RESTART_DELAY)
        } else {
            RESUBSCRIBE_DELAY
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
    let mut state = shared.state();
    state.local = checkpoint.local;
    state.applied = Some(checkpoint.applied);
    state.applied_hash = Some(checkpoint.event_hash);
    state.max_id = checkpoint.applied;
    state.resume = Some((checkpoint.applied, checkpoint.event_hash));
    state.checkpointed = Some((Instant::now(), checkpoint.applied));
}

/// Applies one subscription until it ends; whether it ended by restarting the replay.
async fn subscribe_once(
    shared: Arc<Shared>,
    source: Arc<dyn DustEventSource>,
    checkpoints: Option<Arc<dyn DustCheckpointStore>>,
) -> bool {
    let from = shared.state().applied;
    match source.subscribe(from).await {
        Ok(stream) => {
            let mut batches = stream.ready_chunks(REPLAY_BATCH);
            while let Some(batch) = batches.next().await {
                // Replaying is CPU work; it stays off the async workers.
                let applying = shared.clone();
                match tokio::task::spawn_blocking(move || apply(&applying, batch)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(?error, "midnight funding wallet: DUST replay failed");
                        return error.is::<Restarted>();
                    }
                    Err(error) => {
                        tracing::error!(?error, "midnight funding wallet: DUST replay panicked");
                        return false;
                    }
                }
                if let Some(store) = &checkpoints {
                    keep_checkpoint(&shared, store.as_ref()).await;
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                "midnight funding wallet: DUST event subscription failed"
            );
        }
    }
    false
}

/// Keeps a checkpoint of a caught-up replay that moved since the last one, at most
/// once per `CHECKPOINT_INTERVAL`. A failure only costs the next restart its resume.
async fn keep_checkpoint(shared: &Shared, store: &dyn DustCheckpointStore) {
    let checkpoint = {
        let state = shared.state();
        let (Some(applied), Some(event_hash)) = (state.applied, state.applied_hash) else {
            return;
        };
        let due = state
            .checkpointed
            .is_none_or(|(at, kept)| kept != applied && at.elapsed() >= CHECKPOINT_INTERVAL);
        if !state.is_caught_up() || !due {
            return;
        }
        Checkpoint {
            owner: shared.owner,
            applied,
            event_hash,
            local: state.local.clone(),
        }
    };
    let applied = checkpoint.applied;
    shared.state().checkpointed = Some((Instant::now(), applied));
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

/// Replays one batch. An event the state cannot absorb means the stream and the
/// state disagree about history, so the state restarts from the first event; so does
/// a restored checkpoint whose event the indexer no longer serves.
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
            state.restart();
            drop(state);
            shared.progress.send_replace(());
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
                state.restart();
                drop(state);
                shared.progress.send_replace(());
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
                        "DUST replay is at event {:?} of {} (subscription {}); nothing was posted",
                        state.applied,
                        state.max_id,
                        if state.connected { "live" } else { "down" }
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
            // A replay restarted since `ready_by` holds a partial state, and the
            // reservations' UTXOs are not in it yet, so the retain below would end them.
            if !state.is_caught_up() {
                return Err(SubmitError::WalletUnsynced(format!(
                    "the DUST replay restarted and is at event {:?} of {}; nothing was posted",
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
        let fee = merged
            .fees_with_margin(&INITIAL_PARAMETERS, FEE_BLOCKS_MARGIN)
            .unwrap();
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
    async fn a_replay_that_keeps_failing_backs_off() {
        let mut updates = fixture_updates();
        updates[5].raw.truncate(10);
        let source = RecordingSource::new(updates);
        let _wallet = FundingWallet::start(funded_key(), source.clone(), None);
        tokio::time::sleep(std::time::Duration::from_secs(30 * 60)).await;
        let subscriptions = source.froms().len();
        assert!(
            (2..=20).contains(&subscriptions),
            "{subscriptions} full replays in 30 minutes"
        );
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
