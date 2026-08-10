//! End to end, against a running chain: build, prove and post a respond, then read it
//! back through this crate's OWN decoder. The read-back is the assertion that matters:
//! a submit receipt only says the node accepted some bytes; decoding the singleton's
//! respond map afterwards says the write happened, under the id it was posted for,
//! carrying the signature that was posted.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use midnight_base_crypto::fab::AlignedValue;
use midnight_onchain_state::state::StateValue;
use midnight_storage::DefaultDB;
use mpc_chain_integration_core::utils::test::make_publish_action;
use mpc_chain_integration_core::{ChainPublisher, NoopPublisherTelemetry, PublishAction};
use mpc_chain_midnight::{
    decode_contract_state, IntentGen, MidnightConfig, MidnightPublisher, MidnightRpc,
    PublisherConfig,
};
use mpc_primitives::{Chain, SignBidirectionalEvent, SignId, SignKind};
use tokio_util::sync::CancellationToken;

/// The deployed signet singleton this test posts to: a placeholder, paste the one the
/// midnight-integration deploy (`yarn deploy:signet-contract`) prints. A wrong
/// address cannot pass.
const SIGNET: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const NODE_WS_URL: &str = "ws://127.0.0.1:9944";
const PROOF_SERVER_URL: &str = "http://127.0.0.1:6300";
/// The indexer is what the funding wallet syncs its spendable DUST from.
const INDEXER_URL: &str = "http://127.0.0.1:8088/api/v3/graphql";
const INDEXER_WS_URL: &str = "ws://127.0.0.1:8088/api/v3/graphql/ws";
const NETWORK_ID: &str = "undeployed";

/// Never rendered: a spending key. The local stack's copy lives in the
/// midnight-integration checkout's `.env`.
const FUNDING_SEED_VAR: &str = "MPC_RESPONDER_SEED";

/// Arbitrary (blind append), ASCII for legibility in the respond map, and ending in a
/// nonzero byte so the stored key atom is not trailing-zero trimmed away from it.
const REQUEST_ID: &[u8; 32] = b"chain-midnight/respond_live 0001";

/// `respondMap`, ledger field 3 of the singleton per its own `compiler/contract-info.json`.
const RESPOND_MAP_FIELD: usize = 3;

/// The singleton's declared field count, under the compact compiler's chunk arity, so
/// the fields are the state root's own children rather than a chunk tree.
const LEDGER_FIELDS: usize = 6;

/// The production builder plus the wallet that pays.
fn live_publisher_config() -> PublisherConfig {
    PublisherConfig {
        funding_seed: funding_seed(),
        node_ws_url: NODE_WS_URL.to_string(),
        proof_server_url: PROOF_SERVER_URL.to_string(),
        indexer_url: INDEXER_URL.to_string(),
        indexer_ws_url: INDEXER_WS_URL.to_string(),
        ..common::base_live_config()
    }
}

/// Straight out of the environment into the config that carries it, never rendered anywhere.
fn funding_seed() -> String {
    std::env::var(FUNDING_SEED_VAR).unwrap_or_else(|_| {
        panic!(
            "{FUNDING_SEED_VAR} is unset: export the local stack's funding wallet seed \
             (midnight-integration's .env) before running this test"
        )
    })
}

fn node_config() -> MidnightConfig {
    MidnightConfig {
        node_ws_url: NODE_WS_URL.to_string(),
        central_address: SIGNET.to_string(),
        network_id: NETWORK_ID.to_string(),
        publisher: live_publisher_config(),
        rpc: Default::default(),
        indexer: Default::default(),
    }
}

/// The action the node would hand its publisher: a Midnight `SignBidirectional`.
fn respond_action() -> PublishAction {
    make_publish_action(
        Chain::Midnight,
        SignKind::SignBidirectional(SignBidirectionalEvent {
            sender: [0; 32],
            serialized_transaction: vec![],
            caip2_id: "midnight:undeployed".to_string(),
            key_version: 1,
            deposit: 0,
            path: String::new(),
            algo: String::new(),
            dest: String::new(),
            params: String::new(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            chain: Chain::Midnight,
            chain_ctx: None,
        }),
        SignId::new(*REQUEST_ID),
    )
}

/// One stored respond, as the four atoms the circuit pushed; stored atoms are trailing-zero trimmed.
#[derive(Debug, PartialEq, Eq)]
struct StoredSignature {
    big_r_x: [u8; 32],
    big_r_y: [u8; 32],
    s: [u8; 32],
    recovery_id: u8,
}

fn padded<const N: usize>(atom: &[u8], what: &str) -> [u8; N] {
    assert!(
        atom.len() <= N,
        "{what}: {} stored bytes do not fit Bytes<{N}>",
        atom.len()
    );
    let mut out = [0u8; N];
    out[..atom.len()].copy_from_slice(atom);
    out
}

/// The signet field at `index`, off the decoded state root.
fn ledger_field(root: &StateValue<DefaultDB>, index: usize) -> &StateValue<DefaultDB> {
    let StateValue::Array(fields) = root else {
        panic!("the singleton's state root is not an array of ledger fields: {root:?}");
    };
    assert_eq!(
        fields.len(),
        LEDGER_FIELDS,
        "the singleton declares {LEDGER_FIELDS} ledger fields; a different count means the \
         deployed contract is not the build this test reads field {index} of"
    );
    fields
        .iter_deref()
        .nth(index)
        .unwrap_or_else(|| panic!("ledger field {index} is absent"))
}

/// Every signature filed under `request_id`, collected rather than looked up: the map
/// key's count is the contract's own.
fn responses_for(state: &[u8], request_id: &[u8; 32]) -> Vec<StoredSignature> {
    let root = decode_contract_state(state).expect("the singleton's state decodes");
    let field = ledger_field(&root, RESPOND_MAP_FIELD);
    let StateValue::Map(entries) = field else {
        panic!("ledger field {RESPOND_MAP_FIELD} is not the respond map: {field:?}");
    };
    entries
        .iter()
        .filter_map(|entry| {
            let (key, value) = &*entry;
            (filed_under(key) == *request_id).then(|| stored_signature(value))
        })
        .collect()
}

/// The `requestId` half of a `{count, requestId}` map key.
fn filed_under(key: &AlignedValue) -> [u8; 32] {
    let atoms = &key.value.0;
    assert_eq!(
        atoms.len(),
        2,
        "a respond map key is {{count, requestId}}, got {} atoms",
        atoms.len()
    );
    padded::<32>(&atoms[1].0, "respond map key requestId")
}

fn stored_signature(value: &StateValue<DefaultDB>) -> StoredSignature {
    let StateValue::Cell(cell) = value else {
        panic!("a respond map value is a cell, got {value:?}");
    };
    let atoms = &cell.value.0;
    assert_eq!(
        atoms.len(),
        4,
        "a stored signature is bigR.x, bigR.y, s and recoveryId, got {} atoms",
        atoms.len()
    );
    StoredSignature {
        big_r_x: padded(&atoms[0].0, "bigR.x"),
        big_r_y: padded(&atoms[1].0, "bigR.y"),
        s: padded(&atoms[2].0, "s"),
        // A Uint<8> is stored little-endian trimmed, so recovery id 0 is the empty atom.
        recovery_id: padded::<1>(&atoms[3].0, "recoveryId")[0],
    }
}

/// The signature this run posted, in the form the circuit pushed it.
fn posted_signature(action: &PublishAction) -> StoredSignature {
    use k256::elliptic_curve::sec1::ToEncodedPoint as _;

    let encoded = action.signature.big_r.to_encoded_point(false);
    StoredSignature {
        big_r_x: (*encoded.x().expect("big_r has affine coordinates")).into(),
        big_r_y: (*encoded.y().expect("big_r has affine coordinates")).into(),
        s: action.signature.s.to_bytes().into(),
        recovery_id: action.signature.recovery_id,
    }
}

/// The child waits out the transaction's own finality; this covers the head catching up.
const READ_BACK_TIMEOUT: Duration = Duration::from_secs(180);
const READ_BACK_POLL: Duration = Duration::from_secs(2);

/// The singleton's contract state at the current finalized head.
async fn state_at_finalized_head(rpc: &MidnightRpc) -> (Vec<u8>, u64) {
    let head = rpc
        .finalized_block_ref()
        .await
        .expect("the node answers with its finalized head");
    let state = rpc
        .contract_state(SIGNET, &head.hash)
        .await
        .expect("the node answers a contract state read")
        .unwrap_or_else(|| panic!("no contract lives at {SIGNET} at {}", head.hash));
    (state, head.number)
}

#[tokio::test]
#[ignore = "needs a live midnight node, indexer and proof server, a funded wallet, and \
            `npm ci && npm run build` in chain-signatures/midnight-publisher-ts; submits a \
            real transaction"]
async fn a_respond_lands_on_chain_and_reads_back_through_this_crate_s_decoder() {
    let config = node_config();
    let rpc = Arc::new(
        MidnightRpc::connect(&config)
            .await
            .expect("the local midnight node is reachable"),
    );
    let intent_gen = Arc::new(
        IntentGen::spawn(&config.publisher, &config.network_id)
            .await
            .expect("the intent builder starts"),
    );
    let publisher = MidnightPublisher::new(
        &config.publisher,
        SIGNET.to_string(),
        rpc.clone(),
        intent_gen,
        Arc::new(NoopPublisherTelemetry),
        CancellationToken::new(),
    )
    .expect("the funding seed derives a wallet");

    // This run's signature is freshly minted, so an earlier entry under the same id cannot satisfy it.
    let action = respond_action();
    let posted = posted_signature(&action);
    let (before, before_height) = state_at_finalized_head(&rpc).await;
    assert!(
        !responses_for(&before, REQUEST_ID).contains(&posted),
        "the singleton already holds this run's signature at height {before_height}"
    );

    publisher
        .publish_signature(&action)
        .await
        .expect("the respond is built, proved, paid for and accepted by the node");

    // The loop closes here, not at the submit: what the node accepted is only bytes
    // until this crate's own reader finds them in the contract's state.
    let deadline = Instant::now() + READ_BACK_TIMEOUT;
    loop {
        let (state, height) = state_at_finalized_head(&rpc).await;
        let filed = responses_for(&state, REQUEST_ID);
        if filed.contains(&posted) {
            println!(
                "midnight respond read back at finalized height {height}: {} response(s) \
                 filed under {}",
                filed.len(),
                String::from_utf8_lossy(REQUEST_ID)
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the publish reported success but {READ_BACK_TIMEOUT:?} later the singleton's \
             respond map still does not hold this run's signature under {}: {} response(s) \
             are filed under that id at finalized height {height}, none of them this one, \
             so either the transaction never changed the state or the read path and the \
             write path disagree about contract {SIGNET}",
            String::from_utf8_lossy(REQUEST_ID),
            filed.len()
        );
        tokio::time::sleep(READ_BACK_POLL).await;
    }
}
