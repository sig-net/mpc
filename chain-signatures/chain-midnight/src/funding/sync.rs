//! The DUST replay: the synced state the fee-paying wallet plans from.
//!
//! Stream and state disagree at their peril: a checkpoint event the indexer no longer
//! serves, or an event the replayed state cannot absorb, restarts the replay from the
//! first event — only the reservations of in-flight submits survive a restart.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use futures_util::StreamExt as _;
use midnight_base_crypto::time::Timestamp;
use midnight_ledger_v9::dust::{DustLocalState, DustSecretKey};
use midnight_ledger_v9::events::Event;
use midnight_ledger_v9::structure::INITIAL_PARAMETERS;
use midnight_storage::DefaultDB;
use mpc_chain_integration_core::PublisherTelemetry;
use mpc_utils::task::AbortOnDrop;
use sha2::Digest as _;
use tokio::sync::watch;
use tokio::time::Instant;

use super::checkpoint::{Checkpoint, DustCheckpointStore, CHECKPOINT_INTERVAL, CHECKPOINT_TIMEOUT};
use super::wallet::Reservation;
use crate::dust_feed::{DustEventSource, DustEventUpdate};

/// Events applied per replay; a batch only bounds how long the state lock is held.
const REPLAY_BATCH: usize = 512;
/// Backoff between subscription attempts.
pub const RESUBSCRIBE_DELAY: Duration = Duration::from_secs(2);
/// The header of a ledger event as ledger 8 serialized it.
const LEDGER_8_EVENT_HEADER: &[u8] = b"midnight:event[v9]:";
/// The longest backoff between subscriptions the indexer keeps refusing to open.
const MAX_REFUSED_DELAY: Duration = Duration::from_secs(60);
/// The longest backoff between replays that keep restarting from the first event.
const MAX_RESTART_DELAY: Duration = Duration::from_secs(600);
/// How long a resumed subscription may stay silent before the checkpoint is dropped:
/// the indexer serves the checkpoint's own event first, from what it has stored.
pub const RESUME_TIMEOUT: Duration = Duration::from_secs(60);
/// Strikes — submits a restored wallet's state was implicated in, with none landing
/// in between — before its checkpoint is dropped: the intent builder's snapshot
/// strikes did. Above one, because a healthy wallet is also refused at times, and its
/// spends also expire unlanded.
pub const RESTORE_STRIKES: u32 = 3;
/// The sustained-failure window of `stuck`; the drop happens once, after which
/// nothing is restored to drop again.
pub const RESTORE_STUCK_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// How long a live subscription that holds itself caught up may apply nothing while
/// the indexer names a newer event before it is replaced: a connection can stall
/// without closing.
pub const STALL_GRACE: Duration = Duration::from_secs(5);

pub fn event_hash(raw: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(raw).into()
}

/// Whether ledger 8 serialized this event. A chain that upgraded from ledger 8 to
/// ledger 9 still serves those events, but emptied its DUST state at the upgrade and
/// applied its DUST generation again as this ledger's events. So they are no part of
/// this ledger's replay, and the wallet SDK's `skipLedgerV8DustHistory` starts after
/// them too. That holds for this one upgrade: an event of any other version this
/// ledger cannot read fails the replay.
pub fn is_ledger_8_event(raw: &[u8]) -> bool {
    raw.starts_with(LEDGER_8_EVENT_HEADER)
}

/// The replay restarted from the first event: the stream and the state disagree.
#[derive(Debug, thiserror::Error)]
#[error("restarting the DUST replay from the first event")]
struct Restarted;

pub struct Synced {
    pub local: DustLocalState<DefaultDB>,
    /// The id of the newest event replayed, `None` before the first.
    pub applied: Option<u64>,
    /// The hash of event `applied`, as the indexer served it.
    pub applied_hash: Option<[u8; 32]>,
    /// The newest event id the indexer has reported.
    pub max_id: u64,
    /// The newest event id the indexer named when asked apart from the subscription.
    pub named: u64,
    /// Whether a subscription is currently delivering.
    pub connected: bool,
    /// The event a restored checkpoint expects the next subscription to start with.
    pub resume: Option<(u64, [u8; 32])>,
    /// Whether this state descends from a checkpoint rather than the first event.
    pub restored: bool,
    /// A failed submit asked for the replay to start over from the latest checkpoint.
    pub reload: bool,
    /// A wait for the replay asked for the live subscription to be replaced.
    pub resubscribe: bool,
    pub reservations: Vec<Reservation>,
}

impl Synced {
    pub fn fresh() -> Self {
        Self {
            local: DustLocalState::new(INITIAL_PARAMETERS.dust),
            applied: None,
            applied_hash: None,
            max_id: 0,
            named: 0,
            connected: false,
            resume: None,
            restored: false,
            reload: false,
            resubscribe: false,
            reservations: Vec::new(),
        }
    }

    /// Back to the first event, keeping the reservations of submits in flight.
    pub fn restart(&mut self) {
        let reservations = std::mem::take(&mut self.reservations);
        *self = Self::fresh();
        self.reservations = reservations;
    }

    /// Live, caught up, and not about to start over after a failed submit.
    pub fn is_ready(&self) -> bool {
        self.connected && self.is_caught_up() && !self.reload
    }

    /// Replayed up to the newest event the indexer reported or named, live or not.
    pub fn is_caught_up(&self) -> bool {
        self.applied.is_some_and(|applied| applied >= self.newest())
    }

    /// The newest event id the indexer has reported or named.
    pub fn newest(&self) -> u64 {
        self.max_id.max(self.named)
    }
}

pub struct Shared {
    pub key: DustSecretKey,
    pub owner: [u8; 32],
    pub state: Mutex<Synced>,
    pub progress: watch::Sender<()>,
    pub snapshots: Mutex<Snapshots>,
    /// Wakes the subscription to act on `Synced::reload` or `Synced::resubscribe`.
    pub wake: tokio::sync::Notify,
    pub store: Option<Arc<dyn DustCheckpointStore>>,
    /// Where each replay restart from the first event is reported, by cause.
    pub telemetry: Arc<dyn PublisherTelemetry>,
    /// Held while a checkpoint is kept and while a forgotten one is cleared, so a clear
    /// is sent only once any save that started before its forget has ended, as the
    /// intent builder's flow lock ordered its snapshot saves and clears.
    pub storing: tokio::sync::Mutex<()>,
}

/// The latest checkpoint and the strikes against it, which outlive any one replay, as
/// the intent builder's wallet snapshots did.
#[derive(Default)]
pub struct Snapshots {
    /// The newest checkpoint kept or restored, in memory even when the store refused it.
    pub latest: Option<Checkpoint>,
    /// When a checkpoint was last kept, and of which event: the intent builder's
    /// `kept_at`. Only keeping a checkpoint sets it; a forget or a replay started over
    /// from the first event clears it, and a reload leaves it.
    pub kept: Option<(Instant, u64)>,
    /// `StateConflict` submits of a restored wallet since the last `landed` report;
    /// a failure of another class does not clear them — the forgetting strike and
    /// a replay started over from the first event do.
    pub strikes: u32,
    /// The first stuck failure since the last landing or drop; other classes
    /// neither start nor reset it — they are no recovery.
    pub stuck_since: Option<Instant>,
    /// The stored checkpoint is being cleared; nothing is kept until it is.
    pub forget: bool,
}

impl Snapshots {
    /// Discards the checkpoint and its verdicts; `forget` clears the stored one.
    pub fn discard(&mut self) {
        self.latest = None;
        self.kept = None;
        self.strikes = 0;
        self.stuck_since = None;
        self.forget = true;
    }
}

impl Shared {
    pub fn snapshots(&self) -> std::sync::MutexGuard<'_, Snapshots> {
        self.snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Never panics on a poisoned lock: nothing inside it is left half-written.
    pub fn state(&self) -> std::sync::MutexGuard<'_, Synced> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn replay_restarted(&self, cause: &str) {
        self.telemetry.funding_wallet_replay_restarted(cause);
    }
}

/// How one subscription ended.
#[derive(Clone, Copy)]
enum Ended {
    /// The connection or the stream ended, or a stalled one was replaced; the replay
    /// goes on from where it is.
    Dropped,
    /// The subscription could not be opened; the replay goes on from where it is.
    Refused,
    /// The replay restarted from the first event, after catching up or not.
    Restarted { caught_up: bool },
    /// A failed submit started the replay over from the latest checkpoint.
    Reloaded,
}

/// Follows the event stream for the wallet's lifetime: resubscribes after any
/// failure or stall from the newest applied event, and starts over from the first event when
/// the replayed state can no longer absorb what the indexer sends, backing off while
/// that keeps happening before the replay catches up, or while the indexer refuses to
/// open a subscription at all.
pub async fn follow(shared: Arc<Shared>, source: Arc<dyn DustEventSource>) {
    if let Some(store) = &shared.store {
        restore(&shared, store.as_ref()).await;
    }
    let (mut restart_delay, mut refused_delay) = (RESUBSCRIBE_DELAY, RESUBSCRIBE_DELAY);
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
        // Each backoff grows over a run of its own kind of ending and starts again
        // after any other: a refusal ends a run of restarts as a dropped connection does.
        refused_delay = match ended {
            Ended::Refused => (refused_delay * 2).min(MAX_REFUSED_DELAY),
            _ => RESUBSCRIBE_DELAY,
        };
        restart_delay = match ended {
            Ended::Restarted { caught_up: false } => (restart_delay * 2).min(MAX_RESTART_DELAY),
            Ended::Restarted { caught_up: true } => RESUBSCRIBE_DELAY * 2,
            Ended::Refused | Ended::Dropped | Ended::Reloaded => RESUBSCRIBE_DELAY,
        };
        // At most one of the two has grown.
        tokio::time::sleep(restart_delay.max(refused_delay)).await;
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
pub fn resume_from(shared: &Shared, checkpoint: Checkpoint) {
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
            {
                // What either asked of the subscription before is not for this one,
                // which reports the newest event itself.
                let mut state = shared.state();
                state.resubscribe = false;
                state.named = 0;
            }
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
                        if std::mem::take(&mut shared.state().reload) {
                            reload(&shared);
                            return Ended::Reloaded;
                        }
                        if std::mem::take(&mut shared.state().resubscribe) {
                            return Ended::Dropped;
                        }
                        continue;
                    }
                    () = tokio::time::sleep_until(resume_deadline), if resuming => {
                        tracing::warn!(
                            "midnight funding wallet: the indexer does not serve the DUST \
                             checkpoint's event; replaying from the first event"
                        );
                        start_over(&shared, "resume_timeout");
                        return Ended::Restarted { caught_up };
                    }
                };
                // Replaying is CPU work; it stays off the async workers.
                let applying = shared.clone();
                match tokio::task::spawn_blocking(move || apply(&applying, batch)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(
                            error = %format_args!("{error:#}"),
                            "midnight funding wallet: DUST replay failed"
                        );
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
                error = %format_args!("{error:#}"),
                "midnight funding wallet: DUST event subscription failed"
            );
            return Ended::Refused;
        }
    }
    Ended::Dropped
}

/// Drops the replayed state and the latest checkpoint it may have come from, so the
/// next subscription replays from the first event.
pub fn start_over(shared: &Shared, cause: &str) {
    shared.replay_restarted(cause);
    shared.state().restart();
    let mut snapshots = shared.snapshots();
    snapshots.latest = None;
    snapshots.kept = None;
    snapshots.strikes = 0;
    snapshots.stuck_since = None;
    drop(snapshots);
    shared.progress.send_replace(());
}

/// Clears the stored checkpoint a forget dropped from memory.
pub async fn clear(store: &dyn DustCheckpointStore) {
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
pub async fn keep_checkpoint(shared: &Shared) {
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

/// Replays one batch, passing over the events ledger 8 wrote. An event the state
/// cannot absorb means the stream and the state disagree about history, so the state
/// restarts from the first event; so does a restored checkpoint whose event the
/// indexer no longer serves.
pub fn apply(shared: &Shared, batch: Vec<anyhow::Result<DustEventUpdate>>) -> anyhow::Result<()> {
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
            start_over(shared, "checkpoint_mismatch");
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
            .filter(|update| !is_ledger_8_event(&update.raw))
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
                start_over(shared, "replay_failed");
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

pub fn now() -> Timestamp {
    Timestamp::from_secs(mpc_utils::time::current_unix_timestamp())
}
