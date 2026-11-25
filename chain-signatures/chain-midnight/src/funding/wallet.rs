//! The funding wallet: the DUST-funded fee payer over the synced replay state.
//!
//! A fee is priced over iterative mock-proven passes because the fee transaction adds
//! its own fee; UTXOs in flight are kept out of later plans by reservations, not by
//! the ledger's spend marks, which the replay never adopts.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::coin::TokenType;
use midnight_ledger_v9::dust::{
    DustActions, DustLocalState, DustNullifier, DustOutput, DustSecretKey, QualifiedDustOutput,
};
use midnight_ledger_v9::structure::{
    Intent, LedgerParameters, ProofPreimageMarker, Signature, Transaction,
};
use midnight_storage::DefaultDB;
use midnight_storage::arena::Sp;
use midnight_transient_crypto::commitment::PedersenRandomness;
use mpc_chain_integration_core::PublisherTelemetry;
use mpc_utils::task::AbortOnDrop;
use rand::rngs::StdRng;
use rand::{CryptoRng, Rng};
use tokio::sync::watch;
use tokio::time::Instant;

use super::checkpoint::DustCheckpointStore;
use super::keys::owner_of;
use super::sync::{
    RESTORE_STRIKES, RESTORE_STUCK_TIMEOUT, STALL_GRACE, Shared, Synced, clear, follow, now,
};
use crate::dust_feed::DustEventSource;
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

/// What the publisher needs from the wallet. A trait so the publish path can be
/// driven without an indexer.
pub(crate) trait FeePayer: Send + Sync {
    /// Waits, until `deadline`, for the replayed state to catch up with the newest
    /// event the indexer has reported or named.
    fn ready_by(
        &self,
        deadline: Instant,
    ) -> impl std::future::Future<Output = Result<(), SubmitError>> + Send;
    /// The block time of the newest replayed event: the earliest `ctime` whose DUST
    /// roots are the ones the replayed state proves against.
    fn sync_time(&self) -> Timestamp;
    /// The block time of the newest block the event source has indexed: past it,
    /// the chain may hold DUST events the replay has not seen. When the source also names
    /// its newest event, the replay is not ready again until it has applied it or a
    /// subscription opened since reports the newest event itself.
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
    /// A submit failed without implicating the wallet's restored state: the replay
    /// restarts from the latest checkpoint.
    fn failed(&self);
    /// A submit failed implicating a restored wallet's snapshot: the strike counts
    /// toward dropping its checkpoint, and the replay restarts from the latest
    /// checkpoint — from the first event once that strike drops it.
    fn struck(&self);
    /// A submit failed as `wallet_unfunded` or `internal`: sustained past
    /// `RESTORE_STUCK_TIMEOUT` with none landing, drops a restored checkpoint once.
    /// The replay restarts from the latest checkpoint meanwhile.
    fn stuck(&self);
    /// A submit landed: the wallet in use can pay whatever it was restored from.
    fn landed(&self);
}

/// One fee payment, not yet proven.
pub(crate) struct FeePlan {
    pub(crate) tx: UnprovenTx,
    pub(crate) spent: Vec<DustNullifier>,
    pub(crate) fee: u128,
    /// The spendable DUST it was planned from, in SPECK.
    pub(crate) available: u128,
}

pub(crate) struct Reservation {
    pub(super) spent: Vec<DustNullifier>,
    pub(super) until: Timestamp,
}

/// The funding wallet, kept in sync in the background for as long as it lives.
pub(crate) struct FundingWallet {
    pub(super) shared: Arc<Shared>,
    source: Arc<dyn DustEventSource>,
    _sync: AbortOnDrop,
}

impl FundingWallet {
    /// Starts replaying at once, from the checkpoint in `checkpoints` when it has one
    /// for this key, so the first publish does not pay for the catch-up; `telemetry`
    /// hears of each replay the wallet later restarts from the first event.
    pub(crate) fn start(
        key: DustSecretKey,
        source: Arc<dyn DustEventSource>,
        checkpoints: Option<Arc<dyn DustCheckpointStore>>,
        telemetry: Arc<dyn PublisherTelemetry>,
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
            telemetry,
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

impl FundingWallet {
    /// Holds the replay back from ready until it has applied `newest`, the newest event
    /// the indexer named apart from the live subscription. That subscription can stall
    /// without closing and keep the older newest id it last served, and a fee proven
    /// over the roots it left is refused. A subscription opened later reports the
    /// newest event itself, so the name is dropped then.
    fn name_newest_event(&self, newest: u64) {
        let mut state = self.shared.state();
        if state.applied.is_none_or(|applied| applied < newest) {
            tracing::info!(
                applied = ?state.applied,
                reported = state.max_id,
                newest,
                "midnight funding wallet: the indexer holds DUST events the replay has not \
                 applied"
            );
        }
        state.named = state.named.max(newest);
    }
}

impl FeePayer for FundingWallet {
    /// A live subscription that holds itself caught up and applies nothing for
    /// `STALL_GRACE` while the indexer names a newer event is replaced. One still behind
    /// its own newest event is taken to be delivering and is not.
    async fn ready_by(&self, deadline: Instant) -> Result<(), SubmitError> {
        let mut progress = self.shared.progress.subscribe();
        let mut applied = self.shared.state().applied;
        let mut moved = Instant::now();
        loop {
            let until = {
                let mut state = self.shared.state();
                if state.is_ready() {
                    return Ok(());
                }
                if state.applied != applied {
                    applied = state.applied;
                    moved = Instant::now();
                } else if moved.elapsed() >= STALL_GRACE
                    && state.connected
                    && !state.reload
                    && state
                        .applied
                        .is_some_and(|applied| applied >= state.max_id && applied < state.named)
                {
                    tracing::warn!(
                        applied = ?state.applied,
                        newest = state.newest(),
                        "midnight funding wallet: the DUST subscription applied nothing while \
                         behind the indexer; resubscribing"
                    );
                    state.resubscribe = true;
                    moved = Instant::now();
                    self.shared.wake.notify_one();
                }
                // A subscription that is down or reloading wakes this wait itself.
                if moved.elapsed() < STALL_GRACE {
                    deadline.min(moved + STALL_GRACE)
                } else {
                    deadline
                }
            };
            match tokio::time::timeout_at(until, progress.changed()).await {
                Ok(Ok(())) => {}
                Err(_) if Instant::now() < deadline => {}
                Ok(Err(_)) | Err(_) => {
                    let state = self.shared.state();
                    return Err(SubmitError::WalletUnsynced(format!(
                        "DUST replay is at event {:?} of {} (subscription {}{}); nothing was \
                         posted",
                        state.applied,
                        state.newest(),
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
        let from = self.shared.state().applied;
        let indexed = self.source.indexed(from).await.map_err(|error| {
            SubmitError::WalletUnsynced(format!(
                "the indexer did not report its newest block: {error:#}; nothing was posted"
            ))
        })?;
        if let Some(newest) = indexed.newest_event {
            self.name_newest_event(newest);
        }
        Ok(indexed.time)
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
                    state.applied,
                    state.newest()
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

    fn failed(&self) {
        self.restart_replay(false);
    }

    fn struck(&self) {
        // TODO: re-check `restored` inside the snapshots lock — a start_over in
        // between strikes a checkpoint already dropped (safe to defer: its
        // `restart()` clears `restored`, so no later `struck()` counts; the
        // stray strike can only clear what is already gone).
        let restored = self.shared.state().restored;
        // The strike before the reload, so a wake acting on it sees any forget.
        let mut forget = false;
        if restored {
            let mut snapshots = self.shared.snapshots();
            snapshots.strikes += 1;
            // Strikes 1 and 2 are invisible in the metrics until the drop; the
            // per-strike warn is the only record a checkpoint is half-struck.
            tracing::warn!(
                strikes = snapshots.strikes,
                limit = RESTORE_STRIKES,
                class = "state_conflict",
                "midnight funding wallet: a submit of the restored wallet failed as \
                 state_conflict"
            );
            // TODO: a `funding_wallet_strikes` gauge beside the replay-restart
            // counter, zeroed wherever strikes reset; `Shared` already holds the
            // telemetry (safe to defer: logs cover strikes 1–2 meanwhile).
            if snapshots.strikes >= RESTORE_STRIKES {
                tracing::warn!(
                    cause = "strikes",
                    strikes = RESTORE_STRIKES,
                    class = "state_conflict",
                    "midnight funding wallet: discarding the DUST checkpoint; \
                     replaying from the first event"
                );
                snapshots.discard();
                forget = true;
                self.shared.replay_restarted("strikes");
            }
        }
        self.restart_replay(forget);
    }

    fn stuck(&self) {
        let restored = self.shared.state().restored;
        let mut forget = false;
        if restored {
            let mut snapshots = self.shared.snapshots();
            let since = snapshots.stuck_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= RESTORE_STUCK_TIMEOUT {
                tracing::warn!(
                    cause = "stuck",
                    stuck_for = ?RESTORE_STUCK_TIMEOUT,
                    "midnight funding wallet: a restored wallet kept failing as \
                     unfunded/internal with none landing; discarding the DUST \
                     checkpoint, replaying from the first event"
                );
                snapshots.discard();
                forget = true;
                self.shared.replay_restarted("stuck");
            }
        }
        self.restart_replay(forget);
    }

    fn landed(&self) {
        let mut snapshots = self.shared.snapshots();
        snapshots.strikes = 0;
        snapshots.stuck_since = None;
    }
}

impl FundingWallet {
    /// Restarts the replay from `Snapshots::latest`, or the first event once the
    /// caller dropped it; `forget` also clears the stored checkpoint behind it.
    fn restart_replay(&self, forget: bool) {
        self.shared.state().reload = true;
        if forget {
            // Cleared at once, as the intent builder's forget was, whether or not a
            // subscription is live, and after any save already running. Spawned only
            // once the reload is set: nothing is kept between the forget and the reload.
            // TODO: join this task and log its panic as `follow` does — a panic
            // leaves `forget` set forever (safe to defer: `clear()` handles its
            // own errors, and a stuck `forget` only stops checkpoint saves).
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
