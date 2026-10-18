//! The funding wallet: the DUST that pays every respond transaction's fee.
//!
//! Spendable DUST is derived by replaying the ledger's DUST events into a
//! `DustLocalState`, the same state the Midnight wallet SDK keeps; no node RPC serves
//! it. The state is in memory and rebuilt from the first event on every start.
//!
//! The wallet never adopts the pending marks `DustLocalState::spend` sets on its
//! scratch copy. It reserves the UTXOs a submitted transaction spends instead, and a
//! reservation ends when the chain spends them, when the submit is refused, or when
//! the transaction's TTL has passed and it can no longer land.

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
    Intent, LedgerParameters, ProofMarker, ProofPreimageMarker, Signature, Transaction,
    INITIAL_PARAMETERS,
};
use midnight_storage::arena::Sp;
use midnight_storage::DefaultDB;
use midnight_transient_crypto::commitment::{PedersenRandomness, PureGeneratorPedersen};
use mpc_utils::task::AbortOnDrop;
use rand::rngs::StdRng;
use rand::{CryptoRng, Rng};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::dust_feed::{DustEventSource, DustEventUpdate};
use crate::submit_error::SubmitError;

/// A proven respond transaction, sealed: what the fee is paid for.
pub(crate) type SealedTx = Transaction<Signature, ProofMarker, PureGeneratorPedersen, DefaultDB>;
/// The fee-paying transaction, before its DUST spend proof.
pub(crate) type UnprovenTx =
    Transaction<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>;

/// The fee is priced as the wallet SDK prices it: this many blocks of the largest
/// price rise the ledger allows, so a transaction priced now still pays when it lands.
const FEE_BLOCKS_MARGIN: usize = 5;
/// Each pass adds what the previous spends cost on top; two or three passes settle.
const FEE_PASSES: usize = 8;
/// Events applied per replay; a batch only bounds how long the state lock is held.
const REPLAY_BATCH: usize = 512;
/// Backoff between subscription attempts.
const RESUBSCRIBE_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// The DUST key of account 0 at index 0, derived the way the Midnight wallet SDK
/// derives it from the same seed: BIP-32 `m/44'/2400'/0'/2/0`, then the ledger's
/// `DustSecretKey::derive_secret_key` over that private key.
pub(crate) fn dust_secret_key(seed: &[u8]) -> anyhow::Result<DustSecretKey> {
    let path: bip32::DerivationPath = "m/44'/2400'/0'/2/0"
        .parse()
        .expect("the DUST role path is a valid derivation path");
    let role = bip32::XPrv::derive_from_path(seed, &path)
        .map_err(|error| anyhow::anyhow!("deriving the funding wallet's DUST role key: {error}"))?;
    Ok(DustSecretKey::derive_secret_key(&role.to_bytes()))
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
}

struct Reservation {
    spent: Vec<DustNullifier>,
    until: Timestamp,
}

struct Synced {
    local: DustLocalState<DefaultDB>,
    /// The id of the newest event replayed, `None` before the first.
    applied: Option<u64>,
    /// The newest event id the indexer has reported.
    max_id: u64,
    /// Whether a subscription is currently delivering.
    connected: bool,
    reservations: Vec<Reservation>,
}

impl Synced {
    fn fresh() -> Self {
        Self {
            local: DustLocalState::new(INITIAL_PARAMETERS.dust),
            applied: None,
            max_id: 0,
            connected: false,
            reservations: Vec::new(),
        }
    }

    fn is_ready(&self) -> bool {
        self.connected && self.applied.is_some_and(|applied| applied >= self.max_id)
    }
}

struct Shared {
    key: DustSecretKey,
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
    _sync: AbortOnDrop,
}

impl FundingWallet {
    /// Starts replaying from the first event at once, so the first publish does not
    /// pay for the catch-up.
    pub(crate) fn start(key: DustSecretKey, source: Arc<dyn DustEventSource>) -> Self {
        let (progress, _) = watch::channel(());
        let shared = Arc::new(Shared {
            key,
            state: Mutex::new(Synced::fresh()),
            progress,
        });
        let sync = AbortOnDrop(tokio::spawn(follow(shared.clone(), source)));
        Self {
            shared,
            _sync: sync,
        }
    }
}

/// Follows the event stream for the wallet's lifetime: resubscribes after any
/// failure from the newest applied event, and starts over from the first event when
/// the replayed state can no longer absorb what the indexer sends.
async fn follow(shared: Arc<Shared>, source: Arc<dyn DustEventSource>) {
    loop {
        // Its own task, so a panic below ends one subscription rather than the wallet.
        let attempt = tokio::spawn(subscribe_once(shared.clone(), source.clone())).await;
        if let Err(error) = attempt {
            tracing::error!(
                ?error,
                "midnight funding wallet: DUST event subscription panicked"
            );
        }
        shared.state().connected = false;
        shared.progress.send_replace(());
        tokio::time::sleep(RESUBSCRIBE_DELAY).await;
    }
}

async fn subscribe_once(shared: Arc<Shared>, source: Arc<dyn DustEventSource>) {
    let from = shared.state().applied;
    match source.subscribe(from).await {
        Ok(stream) => {
            let mut batches = stream.ready_chunks(REPLAY_BATCH);
            while let Some(batch) = batches.next().await {
                if let Err(error) = apply(&shared, batch) {
                    tracing::warn!(?error, "midnight funding wallet: DUST replay failed");
                    return;
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
}

/// Replays one batch. An event the state cannot absorb means the stream and the
/// state disagree about history, so the state restarts from the first event.
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
            }
            Err(error) => {
                let reservations = std::mem::take(&mut state.reservations);
                *state = Synced::fresh();
                state.reservations = reservations;
                drop(state);
                shared.progress.send_replace(());
                return Err(error.context("restarting the DUST replay from the first event"));
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
    for utxo in local.utxos() {
        if reserved.contains(&utxo.nullifier(key)) {
            held += 1;
            continue;
        }
        let Some(generation) = local.generation_info(&utxo) else {
            continue;
        };
        let value = DustOutput::from(utxo).updated_value(&generation, ctime, &local.params);
        if value > 0 {
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
            return Err(if held > 0 {
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
            return Ok(FeePlan { tx, spent, fee });
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
mod tests {
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

    fn funded_key() -> DustSecretKey {
        dust_secret_key(&parse_seed(FUNDED_SEED).unwrap()).unwrap()
    }

    fn replayed() -> DustLocalState<DefaultDB> {
        let events: Vec<Event<DefaultDB>> = fixture_updates()
            .iter()
            .map(|update| midnight_serialize::tagged_deserialize(&mut &update.raw[..]).unwrap())
            .collect();
        DustLocalState::new(INITIAL_PARAMETERS.dust)
            .replay_events(&funded_key(), events.iter())
            .unwrap()
    }

    /// A transaction with one empty intent: the smallest base a fee is paid for.
    fn base(rng: &mut StdRng, ttl: Timestamp) -> SealedTx {
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
        let mut corrupt = updates[5].clone();
        corrupt.raw.truncate(10);
        let error = apply(&shared, vec![Ok(corrupt)]).unwrap_err();
        assert!(format!("{error:#}").contains("restarting"), "{error:#}");
        assert_eq!(shared.state().applied, None);
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
    }

    #[tokio::test]
    async fn a_started_wallet_becomes_ready_on_its_own() {
        let wallet = FundingWallet::start(funded_key(), Arc::new(OnceSource(fixture_updates())));
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
    }

    #[tokio::test(start_paused = true)]
    async fn a_panicking_subscription_is_retried_rather_than_ending_the_replay() {
        let source = PanicsFirst(Default::default(), fixture_updates());
        let wallet = FundingWallet::start(funded_key(), Arc::new(source));
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(30))
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_wallet_that_cannot_sync_reports_unsynced_at_its_deadline() {
        let wallet = FundingWallet::start(funded_key(), Arc::new(OnceSource(Vec::new())));
        let error = wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(error, SubmitError::WalletUnsynced(_)), "{error}");
    }

    /// Vectors from `@midnightntwrk/wallet-sdk-hd` 3.1.0-beta.1 and
    /// `@midnightntwrk/ledger-v9` 1.0.0-rc.3: `HDWallet.fromSeed(seed).selectAccount(0)
    /// .selectRoles([Roles.Dust]).deriveKeysAt(0)`, then `DustSecretKey.fromSeed(key)
    /// .publicKey`, printed as a bigint in hex.
    const DUST_KEY_VECTORS: [(&str, &str); 3] = [
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

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs MIDNIGHT_LIVE_INDEXER_WS_URL; replays that indexer's whole DUST history"]
    async fn a_wallet_replays_a_live_indexer_to_its_newest_event() {
        let url = std::env::var("MIDNIGHT_LIVE_INDEXER_WS_URL")
            .expect("MIDNIGHT_LIVE_INDEXER_WS_URL must be set");
        let started = std::time::Instant::now();
        let key = dust_secret_key(&[0x42; 32]).unwrap();
        let wallet = FundingWallet::start(key, Arc::new(IndexerDustEvents::new(url)));
        wallet
            .ready_by(Instant::now() + std::time::Duration::from_secs(1800))
            .await
            .unwrap();
        let state = wallet.shared.state();
        println!(
            "replayed to event {:?} of {} in {:?}; synced to {:?}",
            state.applied,
            state.max_id,
            started.elapsed(),
            state.local.sync_time
        );
    }
}
