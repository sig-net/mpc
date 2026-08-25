use super::*;

use crate::emissions::{emissions_in, DecodedTransaction, Emission, EmissionKind};
use crate::source::{BlockProofSeed, CandidateTransactionEmissions};
use crate::test_utils::{
    array_of, cell_from_record, key_of, map_of, notification_payload, response_payload,
    sample_record,
};
use midnight_onchain_state::state::StateValue;
use mpc_chain_integration_core::utils::stream::chain_event_channel;
use mpc_chain_integration_core::{MockStateManager, NoopChainTelemetry};
use mpc_primitives::SignId;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

type TestIndexer = MidnightIndexer<MockStateManager, NoopChainTelemetry>;

const CALLER: [u8; 32] = [0xab; 32];
const SINGLETON: [u8; 32] = [0x12; 32];
const REQUESTS_FIELD: u8 = 4;
const CAPTURE_HEIGHT: u64 = 156;
const CAPTURE_BLOCK_HASH: &str =
    "0xdc5fcc9c954d8e65937cdb3c6904809cde15bfce3f11a2a2ab4b4bb379a59a3e";
const CAPTURE_SINGLETON: &str = "b116cd0482b84922e761278a25d1ee2305fd6d630f0d48954d2af6537f8e214e";
const CAPTURE_CALLER: &str = "e4ae041a1c3f1538902c6a8f5aedb1e791b66cef7a715114153f3bba44a87eb6";
const CAPTURE_REQUEST_ID: &str = "1cd10eb1f4fa5c665084d24a7982b09aa321886dce77d85b5f6feee0687a414b";
const CAPTURE_NOTIFY_TX: &[u8] = include_bytes!("../fixtures/notify-tx-156.mn");
const CAPTURE_CALLER_STATE: &[u8] = include_bytes!("../fixtures/caller-post-state-156.mn");

fn hex_32(value: &str) -> [u8; 32] {
    let mut decoded = [0u8; 32];
    hex::decode_to_slice(value, &mut decoded).expect("fixture constant is 32-byte hex");
    decoded
}

fn test_config() -> MidnightConfig {
    MidnightConfig {
        node_url: "http://127.0.0.1:1".to_string(),
        central_address: hex::encode(SINGLETON),
        publisher: crate::PublisherConfig {
            funding_seed: "ab".repeat(32),
            proof_server_url: "http://127.0.0.1:1".to_string(),
            indexer_url: "http://127.0.0.1:1/api/v3/graphql".to_string(),
            indexer_ws_url: "ws://127.0.0.1:1/api/v3/graphql/ws".to_string(),
            ..Default::default()
        },
        rpc: Default::default(),
        indexer: Default::default(),
    }
}

fn hash_of(number: u64) -> String {
    format!("0x{number:064x}")
}

fn block_ref(number: u64) -> BlockRef {
    BlockRef {
        number,
        hash: hash_of(number),
        parent_hash: hash_of(number.saturating_sub(1)),
    }
}

fn proof_seed(height: u64) -> BlockProofSeed {
    BlockProofSeed {
        reported_genesis_hash: [0x11; 32],
        reported_block_number: height,
        reported_block_hash: [height as u8; 32],
        singleton_address: SINGLETON,
        scale_header: vec![0x21, height as u8],
        scale_body: vec![vec![0x31], vec![0x32, height as u8]],
        scale_system_events: vec![0x41, height as u8],
    }
}

fn batch(height: u64, calls: Vec<SingletonCallEmissions>) -> BlockEmissions {
    BlockEmissions {
        proof_seed: proof_seed(height),
        candidates: vec![CandidateTransactionEmissions {
            extrinsic_index: 1,
            calls,
        }],
    }
}

fn one_call(kind: EmissionKind, payload: [u8; 256]) -> Vec<SingletonCallEmissions> {
    vec![SingletonCallEmissions {
        call_index: 1,
        emissions: vec![Emission { kind, payload }],
    }]
}

fn notification(rid: [u8; 32]) -> [u8; 256] {
    notification_payload(1, rid, CALLER, &[REQUESTS_FIELD])
}

fn named_record_and_rid(nonce: u64) -> (crate::records::SignBidirectionalRecord, [u8; 32]) {
    let mut record = sample_record();
    record.request_nonce = nonce;
    let rid = crate::request_id::compute_request_id(&record);
    (record, rid)
}

fn caller_state(
    record: &crate::records::SignBidirectionalRecord,
    rid: [u8; 32],
) -> crate::reader::Node {
    array_of(vec![
        StateValue::Null,
        StateValue::Null,
        StateValue::Null,
        StateValue::Null,
        map_of(vec![(key_of(rid), cell_from_record(record))]),
    ])
}

enum HeadSample {
    Block(BlockRef),
    Park,
}

#[derive(Default)]
struct FixtureSource {
    head: u64,
    sampled_heads: Mutex<VecDeque<HeadSample>>,
    successful_head_calls: std::sync::atomic::AtomicUsize,
    emissions: HashMap<u64, Option<BlockEmissions>>,
    emission_errors: Mutex<HashMap<u64, (String, usize)>>,
    emission_holds: HashMap<u64, &'static str>,
    states: HashMap<(String, String), crate::reader::Node>,
    state_errors: HashMap<(String, String), String>,
    oversized_states: HashSet<(String, String)>,
    undecodable_states: HashMap<(String, String), String>,
    transient_head_errors: Mutex<usize>,
    live: tokio::sync::Mutex<Option<mpsc::Receiver<BlockRef>>>,
    park_at: Option<u64>,
    reached: Option<mpsc::Sender<String>>,
}

impl FixtureSource {
    fn set_emissions(&mut self, height: u64, calls: Vec<SingletonCallEmissions>) {
        self.emissions.insert(height, Some(batch(height, calls)));
    }

    fn set_state(&mut self, address: [u8; 32], height: u64, state: crate::reader::Node) {
        self.states
            .insert((hex::encode(address), hash_of(height)), state);
    }

    fn set_state_error(&mut self, address: [u8; 32], height: u64, message: &str) {
        self.state_errors
            .insert((hex::encode(address), hash_of(height)), message.to_string());
    }

    fn set_oversized_state(&mut self, address: [u8; 32], height: u64) {
        self.oversized_states
            .insert((hex::encode(address), hash_of(height)));
    }

    fn set_transient_emission_error(&mut self, height: u64, times: usize, message: &str) {
        self.emission_errors
            .lock()
            .expect("emission errors")
            .insert(height, (message.to_string(), times));
    }

    async fn park(&self, label: String) -> ! {
        if let Some(reached) = &self.reached {
            reached.send(label).await.expect("park signal receiver");
        }
        std::future::pending().await
    }
}

#[async_trait]
impl ChainSource for FixtureSource {
    async fn finalized_head(&self) -> anyhow::Result<BlockRef> {
        {
            let mut owed = self.transient_head_errors.lock().expect("head errors");
            if *owed > 0 {
                *owed -= 1;
                anyhow::bail!("finalized head fetch failed: connection reset by peer");
            }
        }
        let successful_call = self
            .successful_head_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let sample = self
            .sampled_heads
            .lock()
            .expect("sampled heads")
            .pop_front();
        match sample {
            Some(HeadSample::Block(block)) => return Ok(block),
            Some(HeadSample::Park) => self.park("finalized_head".to_string()).await,
            None => {}
        }
        if successful_call > 0 {
            if let Some(rx) = self.live.lock().await.as_mut() {
                if let Ok(block) = rx.try_recv() {
                    return Ok(block);
                }
            }
        }
        Ok(block_ref(self.head))
    }

    async fn block_at(&self, number: u64) -> anyhow::Result<BlockRef> {
        if self.park_at == Some(number) {
            self.park(format!("block_at:{number}")).await;
        }
        Ok(block_ref(number))
    }

    async fn block_emissions(
        &self,
        block: &BlockRef,
        singleton: &[u8; 32],
    ) -> anyhow::Result<Option<BlockEmissions>> {
        assert_eq!(singleton, &SINGLETON, "configured singleton bytes");
        if let Some(reason) = self.emission_holds.get(&block.number) {
            return Err(Hold {
                reason,
                height: block.number,
                cause: anyhow::anyhow!("fixture scanner rejected the block"),
            }
            .into());
        }
        if let Some((message, remaining)) = self
            .emission_errors
            .lock()
            .expect("emission errors")
            .get_mut(&block.number)
        {
            if *remaining > 0 {
                *remaining -= 1;
                anyhow::bail!("{message}");
            }
        }
        Ok(self.emissions.get(&block.number).cloned().flatten())
    }

    async fn contract_state_tree(
        &self,
        address_64hex: &str,
        at_hash: &str,
    ) -> anyhow::Result<ContractState> {
        let key = (address_64hex.to_string(), at_hash.to_string());
        if self.oversized_states.contains(&key) {
            return Err(crate::rpc::oversized_contract_state(
                subxt::ext::subxt_rpcs::Error::Client(Box::new(std::io::Error::other(
                    "fixture oversized contract state",
                ))),
            ));
        }
        if let Some(message) = self.state_errors.get(&key) {
            anyhow::bail!("{message}");
        }
        if let Some(message) = self.undecodable_states.get(&key) {
            return Ok(ContractState::Undecodable(anyhow::anyhow!("{message}")));
        }
        Ok(self
            .states
            .get(&key)
            .cloned()
            .map_or(ContractState::Absent, ContractState::Tree))
    }
}

async fn direct_indexer() -> TestIndexer {
    MidnightIndexer::new(test_config(), MockStateManager::new(), NoopChainTelemetry)
        .await
        .expect("indexer constructs")
}

struct RunFixture {
    events_rx: mpsc::Receiver<ChainEvent>,
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    state: MockStateManager,
}

impl RunFixture {
    async fn spawn(source: FixtureSource, checkpoint: u64) -> Self {
        let state = MockStateManager::new();
        if checkpoint > 0 {
            state.set_processed_block(Chain::Midnight, checkpoint).await;
        }
        Self::spawn_with_state(source, state).await
    }

    async fn spawn_with_state(source: FixtureSource, state: MockStateManager) -> Self {
        Self::spawn_with_config(source, state, test_config()).await
    }

    async fn spawn_with_config(
        source: FixtureSource,
        state: MockStateManager,
        config: MidnightConfig,
    ) -> Self {
        let indexer = MidnightIndexer::new(config, state.clone(), NoopChainTelemetry)
            .await
            .expect("indexer constructs");
        let (events_tx, events_rx) = chain_event_channel();
        let cancel = CancellationToken::new();
        let handle = tokio::spawn({
            let cancel = cancel.clone();
            async move { indexer.run_with_source(&source, events_tx, cancel).await }
        });
        Self {
            events_rx,
            cancel,
            handle,
            state,
        }
    }

    async fn next_event(&mut self) -> ChainEvent {
        tokio::time::timeout(Duration::from_secs(5), self.events_rx.recv())
            .await
            .expect("timed out waiting for event")
            .expect("event channel closed")
    }

    async fn cancel_and_join(self) {
        self.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), self.handle)
            .await
            .expect("run stops after cancel")
            .expect("run task")
            .expect("cancel returns Ok");
    }
}

fn with_live(head: u64) -> (FixtureSource, mpsc::Sender<BlockRef>) {
    let (tx, rx) = mpsc::channel(16);
    (
        FixtureSource {
            head,
            live: tokio::sync::Mutex::new(Some(rx)),
            ..Default::default()
        },
        tx,
    )
}

fn assert_block(event: ChainEvent, expected: u64) {
    assert!(
        matches!(event, ChainEvent::Block(number) if number == expected),
        "expected Block({expected}), got {event:?}"
    );
}

fn assert_request(event: ChainEvent, rid: [u8; 32]) {
    let ChainEvent::SignRequest {
        request,
        block_timestamp,
    } = event
    else {
        panic!("expected SignRequest");
    };
    assert_eq!(request.id, SignId::new(rid));
    assert_eq!(block_timestamp, None);
}

#[tokio::test(start_paused = true)]
async fn polling_ignores_nonadvancing_samples_then_closes_the_gap_in_order() {
    let mut divergent = block_ref(8);
    divergent.hash = hash_of(800);
    let source = FixtureSource {
        head: 11,
        sampled_heads: Mutex::new(VecDeque::from([
            HeadSample::Block(block_ref(8)),
            HeadSample::Block(divergent),
            HeadSample::Block(block_ref(7)),
            HeadSample::Block(block_ref(11)),
        ])),
        ..Default::default()
    };
    let mut config = test_config();
    config.indexer.poll_interval = Duration::from_secs(1);
    let state = MockStateManager::new();
    state.set_processed_block(Chain::Midnight, 8).await;
    let mut harness = RunFixture::spawn_with_config(source, state, config).await;

    assert!(matches!(
        harness.next_event().await,
        ChainEvent::CatchupCompleted
    ));
    assert!(harness.events_rx.try_recv().is_err());

    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!harness.handle.is_finished());
    assert!(harness.events_rx.try_recv().is_err());

    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(!harness.handle.is_finished());
    assert!(harness.events_rx.try_recv().is_err());

    tokio::time::advance(Duration::from_secs(1)).await;
    for number in 9..=11 {
        assert_block(harness.next_event().await, number);
    }
    assert!(harness.events_rx.try_recv().is_err());
    harness.cancel_and_join().await;
}

#[tokio::test(start_paused = true)]
async fn nonadvancing_heads_share_one_stall_budget() {
    let mut config = test_config();
    config.indexer.poll_interval = Duration::from_secs(1);
    config.indexer.stall_timeout = Duration::from_secs(2);
    let source = FixtureSource {
        head: 8,
        sampled_heads: Mutex::new(VecDeque::from([
            HeadSample::Block(block_ref(8)),
            HeadSample::Block(block_ref(7)),
        ])),
        ..Default::default()
    };
    let mut harness = RunFixture::spawn_with_config(source, MockStateManager::new(), config).await;
    assert!(matches!(
        harness.next_event().await,
        ChainEvent::CatchupCompleted
    ));

    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(harness.events_rx.try_recv().is_err());
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    let err = harness
        .handle
        .await
        .expect("run task")
        .expect_err("regressed and equal samples share the stall budget");
    assert!(err.to_string().contains("no progress"), "{err:#}");
}

#[tokio::test(start_paused = true)]
async fn cancellation_is_prompt_during_a_finalized_head_read() {
    let (reached_tx, mut reached_rx) = mpsc::channel(1);
    let source = FixtureSource {
        head: 8,
        sampled_heads: Mutex::new(VecDeque::from([
            HeadSample::Block(block_ref(8)),
            HeadSample::Park,
        ])),
        reached: Some(reached_tx),
        ..Default::default()
    };
    let mut config = test_config();
    config.indexer.poll_interval = Duration::from_secs(1);
    let mut harness = RunFixture::spawn_with_config(source, MockStateManager::new(), config).await;
    assert!(matches!(
        harness.next_event().await,
        ChainEvent::CatchupCompleted
    ));

    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(reached_rx.recv().await.as_deref(), Some("finalized_head"));
    harness.cancel_and_join().await;
}

#[tokio::test]
async fn fixture_source_preserves_the_proof_seed_and_stable_locator() {
    let expected = batch(
        42,
        vec![SingletonCallEmissions {
            call_index: 1,
            emissions: vec![
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: [0x71; 256],
                },
                Emission {
                    kind: EmissionKind::SignatureResponded,
                    payload: [0x72; 256],
                },
            ],
        }],
    );
    let mut source = FixtureSource::default();
    source.emissions.insert(42, Some(expected.clone()));

    let carried = source
        .block_emissions(&block_ref(42), &SINGLETON)
        .await
        .expect("source read")
        .expect("candidate block");

    assert_eq!(carried, expected);
    assert_eq!(carried.candidates[0].extrinsic_index, 1);
    assert_eq!(carried.candidates[0].calls[0].call_index, 1);
    assert_eq!(
        carried.candidates[0].calls[0].emissions[1].kind,
        EmissionKind::SignatureResponded
    );
}

#[tokio::test]
async fn process_block_emits_one_request_per_notify_emission() {
    let (record, rid) = named_record_and_rid(7);
    let mut source = FixtureSource::default();
    source.set_emissions(
        9,
        vec![SingletonCallEmissions {
            call_index: 1,
            emissions: vec![
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: notification(rid),
                },
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: notification(rid),
                },
            ],
        }],
    );
    source.set_state(CALLER, 9, caller_state(&record, rid));

    let events = direct_indexer()
        .await
        .process_block(&source, &block_ref(9))
        .await
        .expect("block processes");

    assert_eq!(events.len(), 2);
    for event in events {
        assert_request(event, rid);
    }
}

#[tokio::test]
async fn captured_entry_decodes_resolves_and_converts() {
    let tx: DecodedTransaction =
        midnight_serialize::tagged_deserialize(&mut &CAPTURE_NOTIFY_TX[..])
            .expect("captured notify transaction decodes");
    let calls = emissions_in(&tx, &hex_32(CAPTURE_SINGLETON), true)
        .expect("captured singleton emission decodes");
    let [call] = calls.as_slice() else {
        panic!("expected one captured singleton call, got {calls:?}");
    };
    let [emission] = call.emissions.as_slice() else {
        panic!(
            "expected one captured singleton emission, got {:?}",
            call.emissions
        );
    };
    assert_eq!(emission.kind, EmissionKind::SignBidirectional);
    let notification = decode_notification(&emission.payload);

    let caller_tree = crate::state::decode_contract_state(CAPTURE_CALLER_STATE)
        .expect("captured caller state decodes");
    let caller = hex_32(CAPTURE_CALLER);
    let mut source = FixtureSource::default();
    source.states.insert(
        (hex::encode(caller), CAPTURE_BLOCK_HASH.to_string()),
        caller_tree,
    );

    let request = direct_indexer()
        .await
        .process_entry(&source, notification, CAPTURE_BLOCK_HASH, CAPTURE_HEIGHT, 0)
        .await
        .expect("captured entry processing does not hold")
        .expect("captured entry produces a request");

    assert_eq!(request.id, SignId::new(hex_32(CAPTURE_REQUEST_ID)));
    assert_eq!(request.args.key_version, 1);
    assert_eq!(
        request.args.path,
        "63616c6c65722d70617468000000000000000000000000000000000000000000"
    );
}

#[tokio::test]
async fn respond_emissions_emit_both_lifecycle_events_in_locator_order() {
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;

    let encoded = k256::AffinePoint::GENERATOR.to_encoded_point(false);
    let mut x = [0u8; 32];
    x.copy_from_slice(encoded.x().expect("x"));
    let mut y = [0u8; 32];
    y.copy_from_slice(encoded.y().expect("y"));
    let respond_rid = [0x31; 32];
    let bidirectional_rid = [0x32; 32];
    let s1: [u8; 32] = k256::Scalar::from(9u64).to_bytes().into();
    let s2: [u8; 32] = k256::Scalar::from(10u64).to_bytes().into();
    let mut source = FixtureSource::default();
    source.set_emissions(
        9,
        vec![SingletonCallEmissions {
            call_index: 4,
            emissions: vec![
                Emission {
                    kind: EmissionKind::SignatureResponded,
                    payload: response_payload(respond_rid, x, y, s1, 0),
                },
                Emission {
                    kind: EmissionKind::RespondBidirectional,
                    payload: response_payload(bidirectional_rid, x, y, s2, 1),
                },
            ],
        }],
    );

    let events = direct_indexer()
        .await
        .process_block(&source, &block_ref(9))
        .await
        .expect("responses process");
    assert_eq!(events.len(), 2);
    let ChainEvent::Respond(respond) = &events[0] else {
        panic!("first locator must be Respond: {events:?}");
    };
    assert_eq!(respond.request_id, respond_rid);
    assert_eq!(respond.signature.s, k256::Scalar::from(9u64));
    let ChainEvent::RespondBidirectional(respond) = &events[1] else {
        panic!("second locator must be RespondBidirectional: {events:?}");
    };
    assert_eq!(respond.request_id, bidirectional_rid);
    assert_eq!(respond.signature.s, k256::Scalar::from(10u64));
}

#[tokio::test]
async fn an_invalid_response_is_dropped_without_hiding_the_next_emission() {
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;

    let encoded = k256::AffinePoint::GENERATOR.to_encoded_point(false);
    let mut x = [0u8; 32];
    x.copy_from_slice(encoded.x().expect("x"));
    let mut y = [0u8; 32];
    y.copy_from_slice(encoded.y().expect("y"));
    let rid = [0x44; 32];
    let s: [u8; 32] = k256::Scalar::from(9u64).to_bytes().into();
    let mut source = FixtureSource::default();
    source.set_emissions(
        9,
        vec![SingletonCallEmissions {
            call_index: 1,
            emissions: vec![
                Emission {
                    kind: EmissionKind::SignatureResponded,
                    payload: response_payload([0x43; 32], [0xff; 32], [0xff; 32], s, 0),
                },
                Emission {
                    kind: EmissionKind::SignatureResponded,
                    payload: response_payload(rid, x, y, s, 0),
                },
            ],
        }],
    );

    let events = direct_indexer()
        .await
        .process_block(&source, &block_ref(9))
        .await
        .expect("invalid signature is a per-emission drop");
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], ChainEvent::Respond(event) if event.request_id == rid));
}

#[tokio::test]
async fn a_hold_from_the_block_reader_halts_without_events() {
    let mut source = FixtureSource::default();
    source.emission_holds.insert(9, "singleton-tx-undecodable");
    let indexer = direct_indexer().await;
    let (events_tx, mut events_rx) = chain_event_channel();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        indexer.index_block(
            &source,
            &events_tx,
            &block_ref(9),
            &CancellationToken::new(),
        ),
    )
    .await
    .expect("a Hold surfaces without retrying");
    let result = match result {
        Ok(_) => panic!("held block must fail"),
        Err(err) => err,
    };
    let hold = result.downcast_ref::<Hold>().expect("typed Hold preserved");
    assert_eq!(hold.reason, "singleton-tx-undecodable");
    assert!(events_rx.try_recv().is_err());
}

#[tokio::test]
async fn a_caller_read_error_holds_the_block() {
    let (_record, rid) = named_record_and_rid(7);
    let mut source = FixtureSource::default();
    source.set_emissions(
        9,
        one_call(EmissionKind::SignBidirectional, notification(rid)),
    );
    source.set_state_error(CALLER, 9, "state is unavailable at the requested block");

    let err = direct_indexer()
        .await
        .process_block(&source, &block_ref(9))
        .await
        .expect_err("an unreadable caller state holds the block");
    assert!(
        format!("{err:#}").contains("state is unavailable at the requested block"),
        "{err:#}"
    );
}

#[tokio::test]
async fn caller_data_failures_drop_only_the_affected_notification() {
    let (good, good_rid) = named_record_and_rid(7);
    let (_absent, absent_rid) = named_record_and_rid(8);
    let mut source = FixtureSource {
        head: 9,
        ..Default::default()
    };
    source.set_emissions(
        9,
        vec![SingletonCallEmissions {
            call_index: 1,
            emissions: vec![
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: notification_payload(2, [0x01; 32], CALLER, &[REQUESTS_FIELD]),
                },
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: notification_payload(1, [0x02; 32], CALLER, &[]),
                },
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: notification(absent_rid),
                },
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: notification(good_rid),
                },
            ],
        }],
    );
    source.set_state(CALLER, 9, caller_state(&good, good_rid));

    let events = direct_indexer()
        .await
        .process_block(&source, &block_ref(9))
        .await
        .expect("caller data failures do not hold");
    assert_eq!(events.len(), 1);
    assert_request(events.into_iter().next().expect("good request"), good_rid);
}

#[tokio::test]
async fn caller_state_too_large_and_undecodable_are_per_entry_drops() {
    let (_record, rid) = named_record_and_rid(7);
    for failure in ["too-large", "undecodable"] {
        let mut source = FixtureSource::default();
        source.set_emissions(
            9,
            one_call(EmissionKind::SignBidirectional, notification(rid)),
        );
        if failure == "too-large" {
            source.set_oversized_state(CALLER, 9);
        } else {
            source.undecodable_states.insert(
                (hex::encode(CALLER), hash_of(9)),
                "unexpected state tag".to_string(),
            );
        }
        assert!(
            direct_indexer()
                .await
                .process_block(&source, &block_ref(9))
                .await
                .expect("entry is dropped")
                .is_empty(),
            "{failure}"
        );
    }
}

#[tokio::test]
async fn a_silent_singleton_call_only_warns_and_the_block_advances() {
    let mut source = FixtureSource::default();
    source.set_emissions(
        9,
        vec![SingletonCallEmissions {
            call_index: 6,
            emissions: Vec::new(),
        }],
    );
    let indexer = direct_indexer().await;
    let (events_tx, mut events_rx) = chain_event_channel();
    indexer
        .index_block(
            &source,
            &events_tx,
            &block_ref(9),
            &CancellationToken::new(),
        )
        .await
        .expect("silent call is not a hold");
    assert_block(events_rx.recv().await.expect("Block event"), 9);
}

#[tokio::test]
async fn run_emits_catchup_before_completed_and_live_blocks() {
    let (record, rid) = named_record_and_rid(7);
    let (mut source, live_tx) = with_live(8);
    source.set_emissions(
        7,
        one_call(EmissionKind::SignBidirectional, notification(rid)),
    );
    source.set_state(CALLER, 7, caller_state(&record, rid));
    live_tx.send(block_ref(9)).await.expect("queue live block");

    let mut harness = RunFixture::spawn(source, 5).await;
    assert_block(harness.next_event().await, 6);
    assert_request(harness.next_event().await, rid);
    assert_block(harness.next_event().await, 7);
    assert_block(harness.next_event().await, 8);
    assert!(matches!(
        harness.next_event().await,
        ChainEvent::CatchupCompleted
    ));
    assert_block(harness.next_event().await, 9);
    harness.cancel_and_join().await;
}

#[tokio::test]
async fn catchup_retries_a_transient_block_emission_read() {
    let (record, rid) = named_record_and_rid(7);
    let (mut source, live_tx) = with_live(8);
    source.set_emissions(
        7,
        one_call(EmissionKind::SignBidirectional, notification(rid)),
    );
    source.set_state(CALLER, 7, caller_state(&record, rid));
    source.set_transient_emission_error(7, 1, "connection reset by peer");

    let mut harness = RunFixture::spawn(source, 6).await;
    assert_request(harness.next_event().await, rid);
    assert_block(harness.next_event().await, 7);
    assert_block(harness.next_event().await, 8);
    assert!(matches!(
        harness.next_event().await,
        ChainEvent::CatchupCompleted
    ));
    harness.cancel_and_join().await;
    drop(live_tx);
}

#[tokio::test]
async fn run_returns_ok_on_cancel_mid_catchup() {
    let (reached_tx, mut reached_rx) = mpsc::channel(1);
    let (live_tx, live_rx) = mpsc::channel(8);
    let source = FixtureSource {
        head: 600,
        park_at: Some(103),
        reached: Some(reached_tx),
        live: tokio::sync::Mutex::new(Some(live_rx)),
        ..Default::default()
    };
    let mut harness = RunFixture::spawn(source, 100).await;
    assert_block(harness.next_event().await, 101);
    assert_block(harness.next_event().await, 102);
    assert_eq!(
        reached_rx.recv().await.expect("park reached"),
        "block_at:103"
    );
    assert!(harness.events_rx.try_recv().is_err());
    harness.cancel_and_join().await;
    drop(live_tx);
}

#[tokio::test]
async fn run_leaves_the_persisted_checkpoint_to_the_block_consumer() {
    let (source, live_tx) = with_live(9);
    let mut harness = RunFixture::spawn(source, 5).await;
    for number in 6..=9 {
        assert_block(harness.next_event().await, number);
    }
    assert!(matches!(
        harness.next_event().await,
        ChainEvent::CatchupCompleted
    ));
    assert_eq!(
        harness.state.get_processed_block(Chain::Midnight).await,
        Some(5)
    );
    harness.cancel_and_join().await;
    drop(live_tx);
}

#[tokio::test]
async fn run_anchors_at_head_without_catchup_and_skips_replayed_live_blocks() {
    let (source, live_tx) = with_live(8);
    let mut harness = RunFixture::spawn(source, 0).await;
    assert!(matches!(
        harness.next_event().await,
        ChainEvent::CatchupCompleted
    ));
    live_tx.send(block_ref(8)).await.expect("replay anchor");
    live_tx.send(block_ref(9)).await.expect("new live block");
    assert_block(harness.next_event().await, 9);
    assert!(harness.events_rx.try_recv().is_err());
    harness.cancel_and_join().await;
}

#[tokio::test]
async fn run_retries_a_transient_anchor_read() {
    let (mut source, live_tx) = with_live(8);
    source.transient_head_errors = Mutex::new(2);
    let mut harness = RunFixture::spawn(source, 8).await;
    assert!(matches!(
        harness.next_event().await,
        ChainEvent::CatchupCompleted
    ));
    harness.cancel_and_join().await;
    drop(live_tx);
}

#[tokio::test]
async fn live_retries_a_transient_block_emission_read() {
    let (record, rid) = named_record_and_rid(7);
    let (mut source, live_tx) = with_live(8);
    source.set_emissions(
        9,
        one_call(EmissionKind::SignBidirectional, notification(rid)),
    );
    source.set_state(CALLER, 9, caller_state(&record, rid));
    source.set_transient_emission_error(9, 1, "connection reset by peer");

    let mut harness = RunFixture::spawn(source, 8).await;
    assert!(matches!(
        harness.next_event().await,
        ChainEvent::CatchupCompleted
    ));
    live_tx.send(block_ref(9)).await.expect("send live block");
    assert_request(harness.next_event().await, rid);
    assert_block(harness.next_event().await, 9);
    harness.cancel_and_join().await;
}

#[tokio::test]
async fn run_recatches_from_the_persisted_checkpoint_after_restart() {
    let (source, live_tx) = with_live(9);
    let mut first = RunFixture::spawn(source, 5).await;
    for number in 6..=9 {
        assert_block(first.next_event().await, number);
    }
    assert!(matches!(
        first.next_event().await,
        ChainEvent::CatchupCompleted
    ));
    let state = first.state.clone();
    first.cancel_and_join().await;
    drop(live_tx);
    state.set_processed_block(Chain::Midnight, 9).await;

    let (source, live_tx) = with_live(12);
    let mut second = RunFixture::spawn_with_state(source, state).await;
    for number in 10..=12 {
        assert_block(second.next_event().await, number);
    }
    assert!(matches!(
        second.next_event().await,
        ChainEvent::CatchupCompleted
    ));
    second.cancel_and_join().await;
    drop(live_tx);
}

#[tokio::test]
async fn caller_contract_absent_is_a_per_entry_drop() {
    let (_record, rid) = named_record_and_rid(7);
    let mut source = FixtureSource {
        head: 9,
        ..Default::default()
    };
    source.set_emissions(
        9,
        one_call(EmissionKind::SignBidirectional, notification(rid)),
    );
    let events = direct_indexer()
        .await
        .process_block(&source, &block_ref(9))
        .await
        .expect("an absent caller contract is not a read failure");
    assert!(events.is_empty());
}

#[tokio::test]
async fn path_walk_and_conversion_failures_drop_only_the_affected_entry() {
    let (good_record, good_rid) = named_record_and_rid(7);
    let mut bad_record = sample_record();
    bad_record.request_nonce = 8;
    bad_record.algo = 1;
    let bad_rid = crate::request_id::compute_request_id(&bad_record);
    let mut source = FixtureSource::default();
    source.set_emissions(
        9,
        vec![SingletonCallEmissions {
            call_index: 1,
            emissions: vec![
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: notification_payload(1, [0x81; 32], CALLER, &[9]),
                },
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: notification(bad_rid),
                },
                Emission {
                    kind: EmissionKind::SignBidirectional,
                    payload: notification(good_rid),
                },
            ],
        }],
    );
    source.set_state(
        CALLER,
        9,
        array_of(vec![
            StateValue::Null,
            StateValue::Null,
            StateValue::Null,
            StateValue::Null,
            map_of(vec![
                (key_of(bad_rid), cell_from_record(&bad_record)),
                (key_of(good_rid), cell_from_record(&good_record)),
            ]),
        ]),
    );

    let events = direct_indexer()
        .await
        .process_block(&source, &block_ref(9))
        .await
        .expect("per-entry failures do not hold the block");
    assert_eq!(events.len(), 1);
    assert_request(events.into_iter().next().expect("good request"), good_rid);
}

#[tokio::test]
async fn emit_block_does_not_double_count_requests() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct CountingTelemetry(Arc<AtomicUsize>);

    impl ChainTelemetry for CountingTelemetry {
        fn block_indexed(&self, _block_number: u64) {}
        fn block_finalized(&self, _block_number: u64) {}
        fn checkpoint_created(&self, _block_number: u64) {}
        fn request_indexed_at(&self, _block_timestamp: u64) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn request_indexed(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        fn bidirectional_extraction_failed(
            &self,
            _kind: mpc_chain_integration_core::ExtractionFailureKind,
        ) {
        }
    }

    let (record, rid) = named_record_and_rid(7);
    let (mut source, live_tx) = with_live(9);
    source.set_emissions(
        9,
        one_call(EmissionKind::SignBidirectional, notification(rid)),
    );
    source.set_state(CALLER, 9, caller_state(&record, rid));
    let state = MockStateManager::new();
    state.set_processed_block(Chain::Midnight, 8).await;
    let counted = CountingTelemetry::default();
    let indexer = MidnightIndexer::new(test_config(), state, counted.clone())
        .await
        .expect("indexer constructs");
    let (events_tx, mut events_rx) = chain_event_channel();
    let cancel = CancellationToken::new();
    let handle = tokio::spawn({
        let cancel = cancel.clone();
        async move { indexer.run_with_source(&source, events_tx, cancel).await }
    });
    loop {
        if matches!(events_rx.recv().await.expect("event"), ChainEvent::Block(9)) {
            break;
        }
    }
    assert_eq!(counted.0.load(Ordering::Relaxed), 0);
    cancel.cancel();
    handle.await.expect("run task").expect("cancel returns Ok");
    drop(live_tx);
}

#[tokio::test]
async fn midnight_indexer_new_rejects_unusable_config() {
    let mut config = test_config();
    config.central_address = "not-hex".to_string();
    let err = match MidnightIndexer::new(config, MockStateManager::new(), NoopChainTelemetry).await
    {
        Ok(_) => panic!("invalid config must fail"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("central"));
}
