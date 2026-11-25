use self::Attempt::{Refused, Restarts};
use super::*;
use crate::dust_feed::{DustEventSource, DustEventUpdate, Indexed};
use crate::submit_error::SubmitError;
use async_trait::async_trait;
use futures_util::StreamExt as _;
use futures_util::stream::BoxStream;
use midnight_base_crypto::time::Timestamp;
use midnight_ledger_v9::dust::{DustLocalState, DustNullifier, DustOutput, DustSecretKey};
use midnight_ledger_v9::events::Event;
use midnight_ledger_v9::structure::{
    INITIAL_PARAMETERS, Intent, ProofPreimageMarker, Signature, Transaction,
};
use midnight_storage::DefaultDB;
use midnight_transient_crypto::commitment::PedersenRandomness;
use mpc_chain_integration_core::{NoopPublisherTelemetry, PublishAction, PublisherTelemetry};
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::Instant;

/// The publisher seed `midnight-devtools`' real-stack driver funds.
const FUNDED_SEED: &str = "0404040404040404040404040404040404040404040404040404040404040404";

/// Every DUST event of a local undeployed chain whose seed-0404… wallet was
/// funded, registered and then paid three fees; see fixtures/README.md.
fn fixture_updates() -> Vec<DustEventUpdate> {
    let events: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("../../fixtures/dust-events-undeployed.json")).unwrap();
    events
        .iter()
        .map(|event| DustEventUpdate {
            id: event["id"].as_u64().unwrap(),
            max_id: event["maxId"].as_u64().unwrap(),
            raw: hex::decode(event["raw"].as_str().unwrap()).unwrap(),
        })
        .collect()
}

/// The first two DUST events of Midnight Preview, which ledger 8 serialized; see
/// fixtures/README.md.
fn ledger_8_updates() -> Vec<DustEventUpdate> {
    let events: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../fixtures/dust-events-preview-ledger-8.json"
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

/// The fixture's timeline as a chain that upgraded from ledger 8 serves it: ledger
/// 8's events first, then this ledger's from the next id on.
fn upgraded_chain_updates() -> Vec<DustEventUpdate> {
    let ledger_8 = ledger_8_updates();
    let offset = ledger_8.last().unwrap().id;
    let current = fixture_updates();
    let max_id = current.last().unwrap().id + offset;
    ledger_8
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
        telemetry: Arc::new(NoopPublisherTelemetry),
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
fn the_replay_starts_after_the_events_ledger_8_wrote() {
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
fn a_timeline_that_never_left_ledger_8_is_caught_up_without_dust() {
    let shared = shared();
    let mut updates = ledger_8_updates();
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

/// `update` with its event header rewritten to `event[v<version>]`.
fn with_event_version(mut update: DustEventUpdate, version: &str) -> DustEventUpdate {
    let colons = update
        .raw
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b':');
    let header_end = colons.map(|(at, _)| at).nth(1).unwrap();
    update.raw.splice(
        ..=header_end,
        format!("midnight:event[v{version}]:").into_bytes(),
    );
    update
}

#[test]
fn only_a_ledger_8_event_header_is_passed_over() {
    let ledger_8 = ledger_8_updates();
    assert!(is_ledger_8_event(&ledger_8[0].raw));
    let current = fixture_updates();
    assert!(!is_ledger_8_event(&current[0].raw));
    assert!(is_ledger_8_event(
        &with_event_version(current[0].clone(), "9").raw
    ));
    // Another version, a version written another way and what is no event header
    // at all go to the decoder, which refuses them.
    for raw in [
        &b"midnight:event[v9]"[..],
        b"midnight:event[v8]:",
        b"midnight:event[v12]:",
        b"midnight:event[v13]:",
        b"midnight:event[v9999]:",
        b"midnight:event[v+9]:",
        b"midnight:event[v09]:",
        b"midnight:event[v]:",
        b"midnight:zswap-event[v9]:",
        b"",
    ] {
        assert!(!is_ledger_8_event(raw), "{raw:?}");
    }
}

#[test]
fn an_event_of_another_version_this_ledger_cannot_read_restarts_the_replay() {
    // Ledger 9's release candidates wrote `event[v13]`, and no upgrade from them
    // applied a chain's DUST again.
    let updates: Vec<_> = fixture_updates()
        .into_iter()
        .map(|update| with_event_version(update, "13"))
        .collect();
    let shared = shared();
    let error = apply(&shared, updates.into_iter().map(Ok).collect()).unwrap_err();
    assert!(format!("{error:#}").contains("did not decode"), "{error:#}");
    let state = shared.state();
    assert!(!state.is_ready());
    assert_eq!(state.applied, None);
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
    let wallet = FundingWallet::start(
        funded_key(),
        Arc::new(OnceSource(fixture_updates())),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    wallet
        .ready_by(Instant::now() + Duration::from_secs(30))
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
    let wallet = FundingWallet::start(
        funded_key(),
        Arc::new(source),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    wallet
        .ready_by(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
}

/// Refuses the first subscription and drops the second, each failure under a context.
struct FailsTwice(std::sync::atomic::AtomicUsize);

#[async_trait]
impl DustEventSource for FailsTwice {
    async fn subscribe(
        &self,
        _from: Option<u64>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
        match self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
            0 => Err(anyhow::anyhow!("HTTP error: 503 Service Unavailable")
                .context("connecting to the indexer subscription")),
            1 => Ok(futures_util::stream::iter([Err(anyhow::anyhow!(
                "Connection reset without closing handshake"
            )
            .context("reading the indexer subscription"))])
            .chain(futures_util::stream::pending())
            .boxed()),
            _ => Ok(futures_util::stream::pending().boxed()),
        }
    }

    async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
        unimplemented!("never asked")
    }
}

#[derive(Clone, Default)]
struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Log collectors keep one entry per line, so why the indexer dropped a subscription
/// has to be on the line that says it did.
#[tokio::test(start_paused = true)]
async fn an_indexer_failure_is_logged_on_one_line_with_its_cause() {
    let logs = LogWriter::default();
    let writer = logs.clone();
    // Keep a second scoped dispatch registered so callsites first reached by a
    // parallel test register against the live dispatches, not that thread's default.
    let _registration_guard = tracing::subscriber::set_default(tracing_subscriber::registry());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _subscriber_guard = tracing::subscriber::set_default(subscriber);
    let source = Arc::new(FailsTwice(Default::default()));
    let _wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    while source.0.load(std::sync::atomic::Ordering::SeqCst) < 3 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let recorded = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    for (message, cause) in [
        ("DUST event subscription failed", "503 Service Unavailable"),
        (
            "DUST replay failed",
            "Connection reset without closing handshake",
        ),
    ] {
        let line = recorded
            .lines()
            .find(|line| line.contains(message))
            .unwrap_or_else(|| panic!("no {message:?} line in {recorded}"));
        assert!(line.contains(cause), "{recorded}");
    }
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
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    // The second subscription starts only after the first one ended.
    while source
        .subscriptions
        .load(std::sync::atomic::Ordering::SeqCst)
        < 2
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(wallet.shared.state().is_caught_up());

    let error = wallet
        .ready_by(Instant::now() + Duration::from_secs(1))
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
    let wallet = FundingWallet::start(
        funded_key(),
        Arc::new(Held(alive.clone())),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
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
    let wallet = FundingWallet::start(
        funded_key(),
        Arc::new(OnceSource(fixture_updates())),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    wallet
        .ready_by(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
    let local = replayed();
    let key = funded_key();
    let all: Vec<DustNullifier> = local.utxos().map(|utxo| utxo.nullifier(&key)).collect();
    let ctime = local.sync_time;
    let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
    let mut rng = StdRng::seed_from_u64(4);
    let base = base(&mut rng, ttl);
    let plan =
        |rng: &mut StdRng| wallet.plan(&base, &INITIAL_PARAMETERS, ctime, ttl, "undeployed", rng);
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
    let wallet = FundingWallet::start(
        funded_key(),
        Arc::new(OnceSource(fixture_updates())),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    wallet
        .ready_by(Instant::now() + Duration::from_secs(30))
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
    let wallet = FundingWallet::start(
        funded_key(),
        Arc::new(OnceSource(fixture_updates())),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    wallet
        .ready_by(Instant::now() + Duration::from_secs(30))
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
    let wallet = FundingWallet::start(
        funded_key(),
        Arc::new(OnceSource(Vec::new())),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    let error = wallet
        .ready_by(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(matches!(error, SubmitError::WalletUnsynced(_)), "{error}");
}

#[derive(Default)]
struct MemoryCheckpoints {
    held: Mutex<Option<Vec<u8>>>,
    clears: AtomicUsize,
}

#[async_trait]
impl DustCheckpointStore for MemoryCheckpoints {
    async fn load(&self) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.held.lock().unwrap().clone())
    }

    async fn save(&self, checkpoint: &[u8]) -> anyhow::Result<()> {
        *self.held.lock().unwrap() = Some(checkpoint.to_vec());
        Ok(())
    }

    async fn clear(&self) -> anyhow::Result<()> {
        self.clears.fetch_add(1, Ordering::SeqCst);
        *self.held.lock().unwrap() = None;
        Ok(())
    }
}

impl MemoryCheckpoints {
    fn holding(checkpoint: Checkpoint) -> Self {
        Self {
            held: Mutex::new(Some(checkpoint.encode())),
            clears: AtomicUsize::new(0),
        }
    }

    fn decoded(&self) -> Option<Checkpoint> {
        let bytes = self.held.lock().unwrap().clone()?;
        Some(Checkpoint::decode(&bytes).unwrap())
    }

    fn clears(&self) -> usize {
        self.clears.load(Ordering::SeqCst)
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
        .ready_by(Instant::now() + Duration::from_secs(30))
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
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    let deadline = Instant::now() + Duration::from_secs(30);
    let checkpoint = loop {
        if let Some(checkpoint) = store.decoded() {
            break checkpoint;
        }
        assert!(Instant::now() < deadline, "no checkpoint was kept");
        tokio::time::sleep(Duration::from_millis(10)).await;
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
        Arc::new(NoopPublisherTelemetry),
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
    let restarts = Arc::new(RestartCauses::default());
    let wallet = FundingWallet::start(
        key,
        source.clone(),
        Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        restarts.clone(),
    );
    ready(&wallet).await;
    assert_eq!(source.froms(), vec![Some(resumed_at), None]);
    assert_fully_replayed(&wallet);
    assert_eq!(
        *restarts.0.lock().unwrap(),
        vec!["checkpoint_mismatch"],
        "a checkpoint the indexer disagrees with is reported as a replay restart"
    );
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
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    assert_eq!(source.froms(), vec![None]);
    assert_fully_replayed(&wallet);
}

#[tokio::test]
async fn an_unreadable_checkpoint_is_ignored() {
    let restarts = Arc::new(RestartCauses::default());
    let source = RecordingSource::new(fixture_updates());
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        Some(Arc::new(MemoryCheckpoints {
            held: Mutex::new(Some(b"not a checkpoint".to_vec())),
            clears: AtomicUsize::new(0),
        })),
        restarts.clone(),
    );
    ready(&wallet).await;
    assert_eq!(source.froms(), vec![None]);
    assert_fully_replayed(&wallet);
    assert!(
        restarts.0.lock().unwrap().is_empty(),
        "a restore that rejected its checkpoint replays from the first event uncounted"
    );
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
        Arc::new(NoopPublisherTelemetry),
    );
    wallet
        .ready_by(Instant::now() + Duration::from_secs(600))
        .await
        .unwrap();
    assert_eq!(source.froms(), vec![Some(resumed_at), None]);
    assert_eq!(wallet.shared.state().applied, Some(newest));
}

/// Replay-restart causes persist until the test reads them; Vec order matches
/// restart order.
#[derive(Default)]
struct RestartCauses(Mutex<Vec<String>>);

impl PublisherTelemetry for RestartCauses {
    fn record_publish_metrics(&self, _action: &PublishAction) {}

    fn funding_wallet_replay_restarted(&self, cause: &str) {
        self.0.lock().unwrap().push(cause.to_owned());
    }
}

/// A wallet resumed from a checkpoint after the fixture's tenth event, its store,
/// and the source recording where each subscription started.
async fn restored_wallet_reporting(
    telemetry: Arc<dyn PublisherTelemetry>,
) -> (
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
    let wallet = FundingWallet::start(key, source.clone(), Some(store.clone()), telemetry);
    ready(&wallet).await;
    (wallet, store, source, resumed_at)
}

async fn restored_wallet() -> (
    FundingWallet,
    Arc<MemoryCheckpoints>,
    Arc<RecordingSource>,
    u64,
) {
    restored_wallet_reporting(Arc::new(NoopPublisherTelemetry)).await
}

/// Lets the subscription act on a failure, then waits for the wallet again.
async fn settle(wallet: &FundingWallet) {
    tokio::time::sleep(Duration::from_secs(10)).await;
    ready(wallet).await;
}

#[tokio::test(start_paused = true)]
async fn a_failed_submit_resumes_the_replay_from_the_latest_checkpoint() {
    let (wallet, store, source, resumed_at) = restored_wallet().await;
    wallet.failed();
    settle(&wallet).await;
    assert_eq!(source.froms(), vec![Some(resumed_at), Some(resumed_at)]);
    assert_fully_replayed(&wallet);
    assert!(
        store.decoded().is_some() && wallet.shared.state().restored,
        "a failure alone keeps the checkpoint"
    );
}

#[tokio::test(start_paused = true)]
async fn restored_wallets_struck_three_times_forget_the_checkpoint() {
    let restarts = Arc::new(RestartCauses::default());
    let (wallet, store, source, resumed_at) = restored_wallet_reporting(restarts.clone()).await;
    // A landing clears the strikes; a non-implicating failure is none.
    for (strike, landed) in [(true, false), (true, true), (false, false), (true, false)] {
        if strike {
            wallet.struck();
        } else {
            wallet.failed();
        }
        settle(&wallet).await;
        if landed {
            wallet.landed();
        }
    }
    assert_eq!(
        wallet.shared.snapshots().strikes,
        1,
        "a landing and a non-implicating failure count no strike"
    );
    // The first reload resumes the restored checkpoint; its caught-up replay keeps
    // the newest event's, which the later reloads resume.
    let newest = Some(fixture_updates().last().unwrap().id);
    assert_eq!(
        source.froms(),
        vec![Some(resumed_at), Some(resumed_at), newest, newest, newest]
    );

    // A failure between strikes does not clear them; only a landing does.
    wallet.failed();
    settle(&wallet).await;

    // The last of those was the first strike since the landing; this is the second.
    wallet.struck();
    settle(&wallet).await;
    assert_eq!(
        wallet.shared.snapshots().strikes,
        2,
        "two strikes, with none landing between them, keep the checkpoint"
    );
    assert!(
        restarts.0.lock().unwrap().is_empty(),
        "no checkpoint is dropped before the third strike"
    );

    wallet.struck();
    // The forgetting strike came first; a late landing must be treated as
    // already-forgotten, not re-processed.
    wallet.landed();
    settle(&wallet).await;
    assert_eq!(
        source.froms().last(),
        Some(&None),
        "a landing reported after the third strike still replays from the first event"
    );
    assert_eq!(
        store.clears(),
        1,
        "a landing reported after the third strike clears the store no second time"
    );
    assert_eq!(
        *restarts.0.lock().unwrap(),
        vec!["strikes"],
        "only the strike that forgets the checkpoint is reported"
    );
    assert_fully_replayed(&wallet);
    let kept = store
        .decoded()
        .expect("the fresh replay keeps a new checkpoint once caught up");
    assert_eq!(kept.applied, fixture_updates().last().unwrap().id);
}

#[tokio::test(start_paused = true)]
async fn a_restored_wallet_stuck_for_fifteen_minutes_forgets_the_checkpoint_once() {
    let restarts = Arc::new(RestartCauses::default());
    let (wallet, store, source, resumed_at) = restored_wallet_reporting(restarts.clone()).await;
    // Below the timeout, stuck reports only restart the replay from the
    // checkpoint; the caught-up replay then keeps the newest event's.
    let newest = Some(fixture_updates().last().unwrap().id);
    wallet.stuck();
    settle(&wallet).await;
    tokio::time::sleep(RESTORE_STUCK_TIMEOUT / 2).await;
    wallet.stuck();
    settle(&wallet).await;
    assert_eq!(
        source.froms(),
        vec![Some(resumed_at), Some(resumed_at), newest],
        "before the timeout the checkpoint is kept"
    );
    assert!(restarts.0.lock().unwrap().is_empty());

    // A landing starts the wait over; other failure classes neither start nor
    // reset it.
    wallet.landed();
    tokio::time::sleep(RESTORE_STUCK_TIMEOUT / 2).await;
    wallet.stuck();
    settle(&wallet).await;
    wallet.failed();
    settle(&wallet).await;
    assert!(
        store.clears() == 0 && wallet.shared.state().restored,
        "a landing reset the wait, so nothing drops yet"
    );

    tokio::time::sleep(RESTORE_STUCK_TIMEOUT).await;
    wallet.stuck();
    settle(&wallet).await;
    assert_eq!(source.froms().last(), Some(&None));
    assert_eq!(store.clears(), 1);
    assert_eq!(*restarts.0.lock().unwrap(), vec!["stuck"]);
    assert_fully_replayed(&wallet);

    // Drop-once: nothing is restored anymore.
    wallet.stuck();
    settle(&wallet).await;
    assert_eq!(store.clears(), 1);
    assert_eq!(*restarts.0.lock().unwrap(), vec!["stuck"]);
}

#[tokio::test(start_paused = true)]
async fn a_wallet_replayed_from_the_first_event_resumes_from_the_checkpoint_it_kept() {
    let source = RecordingSource::new(fixture_updates());
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    // Lets the caught-up replay keep its checkpoint before the first failure.
    settle(&wallet).await;
    let newest = fixture_updates().last().unwrap().id;
    for _ in 0..RESTORE_STRIKES {
        wallet.struck();
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
    wallet.failed();
    // No await between the failure and the next publish's wait: the reload has not
    // run yet, and the state it will replace is not ready.
    let error = wallet
        .ready_by(Instant::now() + Duration::from_millis(1))
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
        Arc::new(NoopPublisherTelemetry),
    );
    // Kept once caught up; 60 s later the replay starts over and catches up again,
    // well inside the interval, and keeps again since nothing it kept survives.
    tokio::time::sleep(Duration::from_secs(70)).await;
    let newest = fixture_updates().last().unwrap().id;
    assert_eq!(*store.0.lock().unwrap(), vec![newest, newest]);
}

#[tokio::test(start_paused = true)]
async fn a_replay_that_cannot_absorb_an_event_is_reported_as_replay_failed() {
    let restarts = Arc::new(RestartCauses::default());
    let _wallet = FundingWallet::start(
        funded_key(),
        Arc::new(CatchesUpThenBreaks::default()),
        None,
        restarts.clone(),
    );
    tokio::time::sleep(Duration::from_secs(70)).await;
    assert_eq!(
        *restarts.0.lock().unwrap(),
        vec!["replay_failed"],
        "an event the replay cannot absorb is reported as a replay restart"
    );
}

#[tokio::test(start_paused = true)]
async fn a_wallet_that_never_held_a_checkpoint_still_reports_its_replay_restarts() {
    let restarts = Arc::new(RestartCauses::default());
    // Pinned deliberately: a fresh wallet under an indexer that serves an
    // undecodable event never holds a checkpoint — asserted below, for a
    // completed keep always saves — and the restart ticks the counter
    // anyway: the unit is the restart, not the drop.
    let mut updates = fixture_updates();
    updates[5].raw.truncate(10);
    let store = Arc::new(MemoryCheckpoints::default());
    let _wallet = FundingWallet::start(
        funded_key(),
        RecordingSource::new(updates),
        Some(store.clone()),
        restarts.clone(),
    );
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(
        store.held.lock().unwrap().is_none(),
        "a completed keep always saves, so the wallet never held a checkpoint"
    );
    let recorded = restarts.0.lock().unwrap().clone();
    assert!(
        !recorded.is_empty() && recorded.iter().all(|cause| cause == "replay_failed"),
        "a never-checkpointed wallet's restarts are reported by their cause: {recorded:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_replay_started_over_carries_no_strikes() {
    let (wallet, _store, _source, _resumed_at) = restored_wallet().await;
    for _ in 0..RESTORE_STRIKES - 1 {
        wallet.struck();
        settle(&wallet).await;
    }
    assert_eq!(wallet.shared.snapshots().strikes, RESTORE_STRIKES - 1);
    start_over(&wallet.shared, "replay_failed");
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
    tokio::time::sleep(Duration::from_secs(60)).await;
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
        let pause = futures_util::stream::once(tokio::time::sleep(Duration::from_secs(60)))
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
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    wallet
        .ready_by(Instant::now() + Duration::from_secs(60))
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
    let _wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    let attempts = || {
        source
            .subscriptions
            .load(std::sync::atomic::Ordering::SeqCst)
    };
    // Attempts at 0, 4, 12, 28 and 60 s, then one a minute: 14 in the first ten
    // minutes, where the resubscribe delay alone would make 300.
    tokio::time::sleep(Duration::from_secs(61)).await;
    assert_eq!(attempts(), 5);
    tokio::time::sleep(Duration::from_secs(540)).await;
    assert_eq!(attempts(), 14);
}

/// Its first subscription serves the fixture up to `stalls_at`, naming the last of
/// those the newest, then nothing, as a connection that stalled without closing;
/// every later one serves the whole fixture. Asked apart, it names each of `names`
/// in turn, then the last of them again.
struct StallsAt {
    stalls_at: usize,
    updates: Vec<DustEventUpdate>,
    names: Mutex<VecDeque<Option<u64>>>,
    /// When each subscription opened.
    opened: Mutex<Vec<Instant>>,
}

impl StallsAt {
    fn new(stalls_at: usize, names: impl IntoIterator<Item = Option<u64>>) -> Arc<Self> {
        Arc::new(Self {
            stalls_at,
            updates: fixture_updates(),
            names: Mutex::new(names.into_iter().collect()),
            opened: Mutex::default(),
        })
    }

    fn subscriptions(&self) -> usize {
        self.opened.lock().unwrap().len()
    }
}

#[async_trait]
impl DustEventSource for StallsAt {
    async fn subscribe(
        &self,
        from: Option<u64>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
        let first = {
            let mut opened = self.opened.lock().unwrap();
            opened.push(Instant::now());
            opened.len() == 1
        };
        if !first {
            return OnceSource(self.updates.clone()).subscribe(from).await;
        }
        let mut served = self.updates[..self.stalls_at].to_vec();
        let newest = served.last().unwrap().id;
        for update in &mut served {
            update.max_id = newest;
        }
        Ok(futures_util::stream::iter(served.into_iter().map(Ok))
            .chain(futures_util::stream::pending())
            .boxed())
    }

    async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
        Ok(replayed().sync_time)
    }

    async fn indexed(&self, _from: Option<u64>) -> anyhow::Result<Indexed> {
        let mut names = self.names.lock().unwrap();
        let newest_event = if names.len() > 1 {
            names.pop_front().unwrap()
        } else {
            names.front().copied().flatten()
        };
        Ok(Indexed {
            time: replayed().sync_time,
            newest_event,
        })
    }
}

#[tokio::test(start_paused = true)]
async fn a_stalled_subscription_behind_the_indexer_is_replaced_before_paying() {
    let updates = fixture_updates();
    let newest = updates.last().unwrap().id;
    let source = StallsAt::new(updates.len() - 2, [Some(newest)]);
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    // The stalled subscription still names the last event it served the newest.
    wallet
        .ready_by(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(
        wallet.shared.state().applied,
        Some(updates[updates.len() - 3].id)
    );

    wallet.indexed_time().await.unwrap();
    assert!(
        !wallet.shared.state().is_ready(),
        "the indexer holds two events the replay has not applied"
    );
    let waited = Instant::now();
    wallet
        .ready_by(Instant::now() + Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(wallet.shared.state().applied, Some(newest));
    assert_eq!(source.subscriptions(), 2);
    let replaced_after = source.opened.lock().unwrap()[1] - waited;
    assert!(
        replaced_after >= STALL_GRACE
            && replaced_after <= STALL_GRACE + RESUBSCRIBE_DELAY + Duration::from_secs(1),
        "replaced {replaced_after:?} into the wait"
    );
}

#[tokio::test(start_paused = true)]
async fn a_newest_event_no_subscription_serves_costs_one_replacement_at_most() {
    let updates = fixture_updates();
    let newest = updates.last().unwrap().id;
    // A broken or mismatched indexer names an event once that it never serves.
    let source = StallsAt::new(updates.len(), [Some(newest + 1_000_000), Some(newest)]);
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    wallet.indexed_time().await.unwrap();
    assert!(!wallet.shared.state().is_ready());

    let waited = Instant::now();
    wallet
        .ready_by(Instant::now() + Duration::from_secs(60))
        .await
        .unwrap();
    assert!(
        waited.elapsed() <= STALL_GRACE + RESUBSCRIBE_DELAY + Duration::from_secs(1),
        "{:?}",
        waited.elapsed()
    );
    assert_eq!(source.subscriptions(), 2);
    // The next publish is not held by it.
    wallet.indexed_time().await.unwrap();
    ready(&wallet).await;
    assert_eq!(source.subscriptions(), 2);
}

/// Serves the fixture one event a second, each naming itself the newest. Asked
/// apart, it names the fixture's newest.
#[derive(Default)]
struct Trickles {
    subscriptions: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl DustEventSource for Trickles {
    async fn subscribe(
        &self,
        _from: Option<u64>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
        self.subscriptions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let updates = fixture_updates().into_iter().map(|mut update| {
            update.max_id = update.id;
            update
        });
        Ok(futures_util::stream::iter(updates)
            .then(|update| async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(update)
            })
            .chain(futures_util::stream::pending())
            .boxed())
    }

    async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
        Ok(replayed().sync_time)
    }

    async fn indexed(&self, _from: Option<u64>) -> anyhow::Result<Indexed> {
        Ok(Indexed {
            time: replayed().sync_time,
            newest_event: Some(fixture_updates().last().unwrap().id),
        })
    }
}

#[tokio::test(start_paused = true)]
async fn a_replay_still_moving_toward_the_indexer_keeps_its_subscription() {
    let source = Arc::new(Trickles::default());
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    wallet
        .ready_by(Instant::now() + Duration::from_secs(30))
        .await
        .unwrap();
    wallet.indexed_time().await.unwrap();
    assert!(!wallet.shared.state().is_ready());
    // 28 events still to come, a second apart: past the grace, never stalled for it.
    wallet
        .ready_by(Instant::now() + Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(
        wallet.shared.state().applied,
        Some(fixture_updates().last().unwrap().id)
    );
    assert_eq!(
        source
            .subscriptions
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a subscription applying an event a second is not stalled"
    );
}

/// Serves the fixture one event every `gap`, each naming the fixture's newest, as a
/// catch-up does; asked apart, it names the same.
struct CatchesUpSlowly {
    gap: Duration,
    subscriptions: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl DustEventSource for CatchesUpSlowly {
    async fn subscribe(
        &self,
        _from: Option<u64>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
        self.subscriptions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let gap = self.gap;
        Ok(futures_util::stream::iter(fixture_updates())
            .then(move |update| async move {
                tokio::time::sleep(gap).await;
                Ok(update)
            })
            .chain(futures_util::stream::pending())
            .boxed())
    }

    async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
        Ok(replayed().sync_time)
    }

    async fn indexed(&self, _from: Option<u64>) -> anyhow::Result<Indexed> {
        Ok(Indexed {
            time: replayed().sync_time,
            newest_event: Some(fixture_updates().last().unwrap().id),
        })
    }
}

#[tokio::test(start_paused = true)]
async fn a_subscription_behind_its_own_newest_event_is_never_replaced() {
    let source = Arc::new(CatchesUpSlowly {
        gap: STALL_GRACE * 2,
        subscriptions: Default::default(),
    });
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    tokio::time::sleep(STALL_GRACE * 3).await;
    wallet.indexed_time().await.unwrap();
    wallet
        .ready_by(Instant::now() + Duration::from_secs(600))
        .await
        .unwrap();
    assert_eq!(
        source
            .subscriptions
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a catch-up slower than the grace is still delivering"
    );
}

#[tokio::test(start_paused = true)]
async fn an_indexer_that_names_no_newest_event_leaves_the_replay_ready() {
    let updates = fixture_updates();
    let source = StallsAt::new(updates.len() - 2, [None]);
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    wallet.indexed_time().await.unwrap();
    assert!(wallet.shared.state().is_ready());
    assert_eq!(source.subscriptions(), 1);
}

/// Subscription 1 serves the fixture up to `upto`, naming the last of those the
/// newest, then ends; the next `refusals` subscriptions are refused; every later one
/// serves event `from` at once, then one more event a second. Asked apart, it names
/// the fixture's newest.
struct DownThenTrickle {
    upto: usize,
    refusals: usize,
    opened: Mutex<Vec<Instant>>,
}

#[async_trait]
impl DustEventSource for DownThenTrickle {
    async fn subscribe(
        &self,
        from: Option<u64>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
        let attempt = {
            let mut opened = self.opened.lock().unwrap();
            opened.push(Instant::now());
            opened.len()
        };
        let updates = fixture_updates();
        if attempt == 1 {
            let mut served = updates[..self.upto].to_vec();
            let newest = served.last().unwrap().id;
            for update in &mut served {
                update.max_id = newest;
            }
            return Ok(futures_util::stream::iter(served.into_iter().map(Ok)).boxed());
        }
        if attempt <= 1 + self.refusals {
            anyhow::bail!("connection refused");
        }
        let mut rest = updates
            .into_iter()
            .filter(move |update| from.is_none_or(|from| update.id >= from));
        let first = rest.next().unwrap();
        Ok(futures_util::stream::iter([Ok(first)])
            .chain(futures_util::stream::iter(rest).then(|update| async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(update)
            }))
            .chain(futures_util::stream::pending())
            .boxed())
    }

    async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
        Ok(replayed().sync_time)
    }

    async fn indexed(&self, _from: Option<u64>) -> anyhow::Result<Indexed> {
        Ok(Indexed {
            time: replayed().sync_time,
            newest_event: Some(fixture_updates().last().unwrap().id),
        })
    }
}

#[tokio::test(start_paused = true)]
async fn a_subscription_reopened_after_a_long_outage_is_not_replaced_at_once() {
    let updates = fixture_updates();
    let source = Arc::new(DownThenTrickle {
        upto: updates.len() - 2,
        refusals: 2,
        opened: Mutex::default(),
    });
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        wallet.shared.state().applied,
        Some(updates[updates.len() - 3].id)
    );
    wallet.indexed_time().await.unwrap();
    wallet
        .ready_by(Instant::now() + Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(
        source.opened.lock().unwrap().len(),
        4,
        "one ended, two refused, one back and kept"
    );
}

#[tokio::test(start_paused = true)]
async fn a_failure_and_a_replacement_asked_at_once_still_reload() {
    let wallet = FundingWallet::start(
        funded_key(),
        Arc::new(OnceSource(fixture_updates())),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    // A stall replacement was asked, then a submit failed, before the subscription woke.
    wallet.shared.state().resubscribe = true;
    wallet.failed();
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(!wallet.shared.state().reload, "the reload was acted on");
    ready(&wallet).await;
}

#[tokio::test(start_paused = true)]
async fn a_replacement_asked_of_an_ended_subscription_spares_the_next() {
    let source = Arc::new(DownThenTrickle {
        upto: fixture_updates().len(),
        refusals: 0,
        opened: Mutex::default(),
    });
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    // The first subscription served everything and ended; follow waits to resubscribe.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(source.opened.lock().unwrap().len(), 1);
    assert!(!wallet.shared.state().connected);
    // A replacement asked of it just before it ended, never acted on.
    wallet.shared.state().resubscribe = true;
    wallet.shared.wake.notify_one();
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(source.opened.lock().unwrap().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn a_lower_name_does_not_lower_the_hold() {
    let updates = fixture_updates();
    let newest = updates.last().unwrap().id;
    let source = StallsAt::new(updates.len() - 3, [Some(newest), Some(newest - 1)]);
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    wallet.indexed_time().await.unwrap();
    wallet.indexed_time().await.unwrap();
    assert_eq!(wallet.shared.state().named, newest);
}

#[tokio::test(start_paused = true)]
async fn ready_after_a_name_the_replacement_serves_means_the_name_is_applied() {
    let updates = fixture_updates();
    let newest = updates.last().unwrap().id;
    for stalls_at in [1, 3, updates.len() - 1] {
        let source = StallsAt::new(stalls_at, [Some(newest)]);
        let wallet = FundingWallet::start(
            funded_key(),
            source.clone(),
            None,
            Arc::new(NoopPublisherTelemetry),
        );
        ready(&wallet).await;
        wallet.indexed_time().await.unwrap();
        wallet
            .ready_by(Instant::now() + Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(
            wallet.shared.state().applied,
            Some(newest),
            "stalled after {stalls_at} events"
        );
    }
}

/// Subscription 1 serves the fixture up to `upto`, naming the last of those the
/// newest, then ends; every later one serves its first events only after `first`.
/// Asked apart, it names the fixture's newest.
struct SlowFirst {
    upto: usize,
    first: Duration,
    opened: Mutex<Vec<Instant>>,
}

#[async_trait]
impl DustEventSource for SlowFirst {
    async fn subscribe(
        &self,
        from: Option<u64>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
        let attempt = {
            let mut opened = self.opened.lock().unwrap();
            opened.push(Instant::now());
            opened.len()
        };
        let updates = fixture_updates();
        if attempt == 1 {
            let mut served = updates[..self.upto].to_vec();
            let newest = served.last().unwrap().id;
            for update in &mut served {
                update.max_id = newest;
            }
            return Ok(futures_util::stream::iter(served.into_iter().map(Ok)).boxed());
        }
        let rest: Vec<_> = updates
            .into_iter()
            .filter(|update| from.is_none_or(|from| update.id >= from))
            .collect();
        let first = self.first;
        Ok(
            futures_util::stream::once(async move { tokio::time::sleep(first).await })
                .flat_map(move |()| futures_util::stream::iter(rest.clone().into_iter().map(Ok)))
                .chain(futures_util::stream::pending())
                .boxed(),
        )
    }

    async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
        Ok(replayed().sync_time)
    }

    async fn indexed(&self, _from: Option<u64>) -> anyhow::Result<Indexed> {
        Ok(Indexed {
            time: replayed().sync_time,
            newest_event: Some(fixture_updates().last().unwrap().id),
        })
    }
}

#[tokio::test(start_paused = true)]
async fn an_open_subscription_slow_to_deliver_is_not_replaced() {
    let updates = fixture_updates();
    let source = Arc::new(SlowFirst {
        upto: updates.len() - 2,
        first: STALL_GRACE + Duration::from_secs(3),
        opened: Mutex::default(),
    });
    let wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    // Subscription 1 has ended; 2 opened `RESUBSCRIBE_DELAY` later.
    tokio::time::sleep(RESUBSCRIBE_DELAY + Duration::from_secs(1)).await;
    assert_eq!(source.opened.lock().unwrap().len(), 2);
    assert!(!wallet.shared.state().connected);
    // Named after it opened, so the name stands while it is slow to deliver.
    wallet.indexed_time().await.unwrap();
    wallet
        .ready_by(Instant::now() + Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(
        source.opened.lock().unwrap().len(),
        2,
        "the slow one was kept"
    );
}

#[test]
fn a_newest_event_named_apart_holds_the_replay_until_it_applies_it() {
    let shared = shared();
    let updates = fixture_updates();
    let newest = updates.last().unwrap().id;
    apply(&shared, updates.iter().cloned().map(Ok).collect()).unwrap();
    assert!(shared.state().is_ready());
    // Asked apart, the indexer named an event the subscription has yet to serve.
    shared.state().named = newest + 1;
    assert!(!shared.state().is_ready());
    // The subscription naming an older newest event does not release it.
    apply(&shared, vec![Ok(updates.last().unwrap().clone())]).unwrap();
    assert!(!shared.state().is_ready());
    // Reaching the named event does.
    shared.state().applied = Some(newest + 1);
    assert!(shared.state().is_ready());
}

/// How one subscription of [`RefusesAndRestarts`] goes.
#[derive(Clone, Copy)]
enum Attempt {
    /// The indexer refuses the connection.
    Refused,
    /// Serves a timeline with an event the state cannot absorb.
    Restarts,
}

/// Goes through `attempts` one subscription each, then serves the fixture's timeline
/// and stays open; records when each subscription was asked for.
struct RefusesAndRestarts {
    attempts: Vec<Attempt>,
    subscriptions: Mutex<Vec<tokio::time::Instant>>,
}

impl RefusesAndRestarts {
    /// The seconds between each subscription and the one before it.
    async fn gaps(attempts: Vec<Attempt>) -> Vec<u64> {
        let source = Arc::new(Self {
            attempts,
            subscriptions: Mutex::default(),
        });
        let _wallet = FundingWallet::start(
            funded_key(),
            source.clone(),
            None,
            Arc::new(NoopPublisherTelemetry),
        );
        tokio::time::sleep(Duration::from_secs(3600)).await;
        let at = source.subscriptions.lock().unwrap();
        at.windows(2)
            .map(|pair| (pair[1] - pair[0]).as_secs())
            .collect()
    }
}

#[async_trait]
impl DustEventSource for RefusesAndRestarts {
    async fn subscribe(
        &self,
        from: Option<u64>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
        let attempt = {
            let mut subscriptions = self.subscriptions.lock().unwrap();
            subscriptions.push(tokio::time::Instant::now());
            self.attempts.get(subscriptions.len() - 1).copied()
        };
        let mut updates = fixture_updates();
        match attempt {
            Some(Attempt::Refused) => anyhow::bail!("HTTP error: 403 Forbidden"),
            Some(Attempt::Restarts) => updates[5].raw.truncate(10),
            None => {}
        }
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
async fn a_restart_after_refused_subscriptions_is_not_delayed_by_their_backoff() {
    let gaps = RefusesAndRestarts::gaps(vec![
        Refused, Refused, Refused, Refused, Refused, Refused, Restarts,
    ])
    .await;
    // The refusals back off to a minute; the restart that follows them waits what a
    // first restart waits.
    assert_eq!(gaps, [4, 8, 16, 32, 60, 60, 4]);
}

#[tokio::test(start_paused = true)]
async fn a_refused_subscription_after_restarts_is_not_delayed_by_their_backoff() {
    let gaps = RefusesAndRestarts::gaps(vec![
        Restarts, Restarts, Restarts, Refused, Refused, Restarts,
    ])
    .await;
    // The restarts back off to 16 s; the refusals that follow wait what first
    // refusals wait, and end the run of restarts as a dropped connection does.
    assert_eq!(gaps, [4, 8, 16, 4, 8, 4]);
}

/// Serves `batches` in order as separate deliveries, each after `gap` of
/// silence, then stays open; records where each subscription started.
struct Batches {
    batches: Vec<(Duration, Vec<DustEventUpdate>)>,
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
            (Duration::ZERO, first.to_vec()),
            (Duration::ZERO, rest.to_vec()),
        ],
        froms: Mutex::default(),
    });
    let wallet = FundingWallet::start(
        key,
        source.clone(),
        Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        Arc::new(NoopPublisherTelemetry),
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
    let past_interval = CHECKPOINT_INTERVAL + Duration::from_secs(1);
    let source = Arc::new(Batches {
        batches: vec![
            // Behind the indexer: nothing is kept.
            (Duration::ZERO, updates[..5].to_vec()),
            // Caught up: the first checkpoint.
            (Duration::ZERO, caught_up_at(&updates[5..10])),
            // Progress inside the interval: not yet.
            (Duration::ZERO, caught_up_at(&updates[10..15])),
            // Progress past the interval: the second checkpoint.
            (past_interval, updates[15..].to_vec()),
            // No progress past another interval: nothing new to keep.
            (past_interval, vec![updates.last().unwrap().clone()]),
        ],
        froms: Mutex::default(),
    });
    let store = Arc::new(CountingCheckpoints::default());
    let _wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        Some(store.clone()),
        Arc::new(NoopPublisherTelemetry),
    );
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
        Arc::new(NoopPublisherTelemetry),
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
    let _wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    // Restarts at 0 s and 4 s grow the delay to 8 s; the third subscription, at 12 s,
    // replays and drops; the fourth follows it by the 2 s resubscribe delay.
    tokio::time::sleep(Duration::from_secs(30)).await;
    let at = source.subscriptions.lock().unwrap().clone();
    assert!(at.len() >= 4, "{} subscriptions", at.len());
    assert_eq!(at[3] - at[2], RESUBSCRIBE_DELAY);
}

#[tokio::test(start_paused = true)]
async fn a_replay_that_keeps_failing_backs_off_to_at_most_ten_minutes() {
    let mut updates = fixture_updates();
    updates[5].raw.truncate(10);
    let source = RecordingSource::new(updates);
    let _wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    // Delays 4, 8, ..., 512 s sum to 1020 s; then 600 s each when capped, 1024, 2048 s uncapped.
    tokio::time::sleep(Duration::from_secs(1020 + 3 * 600 + 1)).await;
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
    let wallet = FundingWallet::start(
        key,
        source.clone(),
        Some(store.clone()),
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    for _ in 0..RESTORE_STRIKES {
        wallet.struck();
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
        wallet.struck();
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
        wallet.failed();
        // A reload resubscribes after the resubscribe delay, never a backoff.
        tokio::time::sleep(RESUBSCRIBE_DELAY + Duration::from_secs(1)).await;
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
        Arc::new(NoopPublisherTelemetry),
    );
    // The first subscription replays to the newest event and ends; the wallet waits
    // out the resubscribe delay.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(*source.froms.lock().unwrap(), vec![Some(resumed_at)]);
    assert_eq!(wallet.shared.state().applied, Some(newest));
    wallet.failed();
    tokio::time::sleep(Duration::from_secs(10)).await;
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
        Arc::new(NoopPublisherTelemetry),
    );
    // The resumed replay fails and starts over from the first event, which the
    // indexer has not served yet.
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(*source.froms.lock().unwrap(), vec![Some(resumed_at), None]);
    // A submit in flight from before fails.
    wallet.struck();
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(
        *source.froms.lock().unwrap(),
        vec![Some(resumed_at), None, None],
        "the checkpoint the replay started over from is not resumed again"
    );
}

#[tokio::test(start_paused = true)]
async fn a_restart_after_catching_up_resubscribes_after_four_seconds() {
    let source = Arc::new(CatchesUpThenBreaks::default());
    let _wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    tokio::time::sleep(Duration::from_secs(200)).await;
    let at = source.0.lock().unwrap().clone();
    assert!(at.len() >= 3, "{} subscriptions", at.len());
    // 60 s caught up before the event that cannot be absorbed, then 4 s.
    for pair in at.windows(2) {
        assert_eq!(pair[1] - pair[0], Duration::from_secs(64), "{at:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_checkpoint_kept_as_the_third_strike_lands_is_forgotten_too() {
    let (wallet, _store, source, resumed_at) = restored_wallet().await;
    for _ in 0..RESTORE_STRIKES - 1 {
        wallet.struck();
        settle(&wallet).await;
    }
    assert_eq!(source.froms().len(), 3);
    assert_eq!(source.froms()[0], Some(resumed_at));
    // A checkpoint is due when the third strike lands.
    tokio::time::sleep(CHECKPOINT_INTERVAL).await;
    wallet.struck();
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
                    tokio::time::sleep(Duration::from_secs(1)).await;
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
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let first = store
        .decoded()
        .expect("first checkpoint kept at once")
        .applied;
    assert_eq!(first, updates[19].id);

    tokio::time::sleep(Duration::from_secs(4 * 60)).await;
    wallet.failed();
    tokio::time::sleep(Duration::from_secs(10)).await;
    ready(&wallet).await;

    tokio::time::sleep(Duration::from_secs(2 * 60)).await;
    visible.store(updates.len(), std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(30)).await;
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
        wallet.struck();
        settle(&wallet).await;
    }
    wallet.struck();
    // No await in between: the spawned clear has not run yet.
    start_over(&wallet.shared, "replay_failed");
    tokio::time::sleep(Duration::from_secs(10)).await;
    let forget_pending = wallet.shared.snapshots().forget;
    let stored_after_strikes = store.decoded().map(|checkpoint| checkpoint.applied);
    // The fresh replay keeps a good checkpoint (simulated), then any later failure.
    let good = checkpoint_after(29, &funded_key());
    *store.held.lock().unwrap() = Some(good.encode());
    wallet.shared.snapshots().latest = Some(good);
    wallet.failed();
    tokio::time::sleep(Duration::from_secs(10)).await;
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
                    tokio::time::sleep(Duration::from_secs(1)).await;
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
    let wallet = FundingWallet::start(
        key,
        source,
        Some(store.clone()),
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    for _ in 0..RESTORE_STRIKES - 1 {
        wallet.struck();
        settle(&wallet).await;
    }
    down.store(true, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(5)).await;
    wallet.struck();
    tokio::time::sleep(Duration::from_secs(1)).await;
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
        tokio::time::sleep(Duration::from_secs(5)).await;
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
    let wallet = FundingWallet::start(
        key,
        source,
        Some(store.clone()),
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    // The restored replay caught up and is keeping its first checkpoint.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(*store.log.lock().unwrap(), vec!["save starts"]);
    // No indexer, so no fresh replay keeps a checkpoint of its own afterwards.
    down.store(true, std::sync::atomic::Ordering::SeqCst);
    wallet.shared.snapshots().strikes = RESTORE_STRIKES - 1;
    wallet.struck();
    tokio::time::sleep(Duration::from_secs(60)).await;
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
        tokio::time::sleep(Duration::from_secs(20)).await;
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
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    wallet.shared.snapshots().strikes = RESTORE_STRIKES - 1;
    wallet.struck();
    // The replay from the first event catches up while the store is still clearing.
    tokio::time::sleep(Duration::from_secs(5)).await;
    visible.store(25, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(5)).await;
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

    tokio::time::sleep(Duration::from_secs(20)).await;
    assert!(
        store.0.decoded().is_none(),
        "the clear left the store empty"
    );
    visible.store(updates.len(), std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(5)).await;
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
        wallet.struck();
        settle(&wallet).await;
    }
    wallet.struck();
    // No await until the keep below: the spawned clear has not run.
    start_over(&wallet.shared, "replay_failed");
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
        batches: vec![(Duration::from_secs(45), fixture_updates())],
        froms: Mutex::default(),
    });
    let wallet = FundingWallet::start(
        key,
        source.clone(),
        Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        Arc::new(NoopPublisherTelemetry),
    );
    wallet
        .ready_by(Instant::now() + Duration::from_secs(120))
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
    wallet.failed();
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
    assert!(
        wallet
            .plan(
                &base,
                &INITIAL_PARAMETERS,
                ctime,
                ttl,
                "undeployed",
                &mut rng
            )
            .is_ok()
    );
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
        Arc::new(NoopPublisherTelemetry),
    );
    ready(&wallet).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(store.decoded().unwrap().applied, updates[4].id);
    // At 4 min: progress inside the interval keeps nothing.
    tokio::time::sleep(Duration::from_secs(4 * 60)).await;
    visible.store(10, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(store.decoded().unwrap().applied, updates[4].id);
    // Past 5 min: the next progress is kept.
    tokio::time::sleep(Duration::from_secs(60)).await;
    visible.store(15, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(5)).await;
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
        Arc::new(NoopPublisherTelemetry),
    );
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(*source.froms.lock().unwrap(), vec![Some(resumed_at), None]);
    wallet.struck();
    tokio::time::sleep(Duration::from_secs(10)).await;
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
    let restarts = Arc::new(RestartCauses::default());
    let wallet = FundingWallet::start(
        key,
        source.clone(),
        Some(Arc::new(MemoryCheckpoints::holding(checkpoint))),
        restarts.clone(),
    );
    tokio::time::sleep(RESUME_TIMEOUT + Duration::from_secs(10)).await;
    assert_eq!(source.froms(), vec![Some(resumed_at), None]);
    assert_eq!(
        *restarts.0.lock().unwrap(),
        vec!["resume_timeout"],
        "a checkpoint the indexer never served in time is reported as a replay restart"
    );
    wallet.struck();
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(
        source.froms(),
        vec![Some(resumed_at), None, None],
        "the checkpoint that timed out is not resumed again"
    );
    assert_eq!(
        wallet.shared.snapshots().strikes,
        0,
        "a strike after its checkpoint was dropped counts nothing"
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
                tokio::time::sleep(Duration::from_secs(secs)).await
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
    let _wallet = FundingWallet::start(
        funded_key(),
        source.clone(),
        None,
        Arc::new(NoopPublisherTelemetry),
    );
    tokio::time::sleep(Duration::from_secs(250)).await;
    let at = source.0.lock().unwrap().clone();
    assert!(at.len() >= 3, "{} subscriptions", at.len());
    for pair in at.windows(2) {
        assert_eq!(pair[1] - pair[0], Duration::from_secs(65), "{at:?}");
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
