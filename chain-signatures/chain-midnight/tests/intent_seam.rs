//! The seam: the real Rust client drives the real TypeScript builder, and what comes
//! back parses here as the ledger's own `Intent`, the only test where neither side's
//! expectations were authored by the side under test. Committed fixtures and the ledger
//! crate's constants stand in for node, prover and wallet; only the midnight-publisher-ts workflow runs it.

mod common;

use midnight_ledger_v9::structure::{
    ContractAction, ContractCall, Intent, ProofPreimageMarker, Signature, INITIAL_PARAMETERS,
};
use midnight_onchain_state::state::ContractState;
use midnight_storage::DefaultDB;
use midnight_transient_crypto::commitment::PedersenRandomness;
use mpc_chain_midnight::{IntentGen, IntentRequest, WirePoint, WireSignature};

/// Any well-formed 32-byte hex address serves.
const SINGLETON: &str = "5555555555555555555555555555555555555555555555555555555555555555";

/// Any 32 bytes serve for a blind append: nothing checks this against prior state.
const REQUEST_ID: &str = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

/// All different deliberately: equal-looking components would hide a transposed x and y.
const BIG_R_X: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const BIG_R_Y: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const S: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// The transcript renders a trailing-zero-trimmed value, so a zero recovery id is `-`.
const RECOVERY_ID_ZERO: &str = "-";

/// The publisher package's committed fixture, valid input at any contract version.
const SINGLETON_STATE: &[u8] =
    include_bytes!("../../midnight-publisher-ts/tests/fixtures/initial-singleton-state.mn");

/// The child refuses to boot without one; any value the contract library recognises.
const NETWORK_ID: &str = "undeployed";

/// Ledger 9's own tagged reading of what the builder wrote.
type ChainIntent = Intent<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>;

fn signature() -> WireSignature {
    WireSignature {
        big_r: WirePoint {
            x: BIG_R_X.to_string(),
            y: BIG_R_Y.to_string(),
        },
        s: S.to_string(),
        recovery_id: 0,
    }
}

/// A second pin: the Rust and TypeScript ledger builds still agree on this blob.
fn initial_ledger_parameters() -> String {
    let mut bytes = Vec::new();
    midnight_serialize::tagged_serialize(&INITIAL_PARAMETERS, &mut bytes)
        .expect("the ledger's own initial parameters serialize");
    hex::encode(bytes)
}

fn respond_request() -> IntentRequest {
    IntentRequest {
        circuit: "respond",
        contract_address: SINGLETON.to_string(),
        request_id: REQUEST_ID.to_string(),
        signature: signature(),
        contract_state: hex::encode(SINGLETON_STATE),
        ledger_parameters: initial_ledger_parameters(),
        ttl_seconds: 1_800_000_000,
    }
}

/// The one call the intent carries. Decoded, never byte-compared: the builder samples a
/// fresh commitment per call, so only the decode is stable.
fn sole_call(bytes: &[u8]) -> ContractCall<ProofPreimageMarker, DefaultDB> {
    // Tagged rather than bare, so a ledger version skew fails by name.
    let intent: ChainIntent = midnight_serialize::tagged_deserialize(&mut &bytes[..])
        .expect("the TypeScript intent deserializes as the ledger's own Intent");

    let actions: Vec<_> = intent.actions.iter_deref().cloned().collect();
    assert_eq!(actions.len(), 1, "one contract call");
    let ContractAction::Call(call) = &actions[0] else {
        panic!("the single action must be a Call");
    };
    assert_eq!(
        hex::encode(call.address.0 .0),
        SINGLETON,
        "the call must name the contract the request named"
    );
    // The Rust half treats a built intent as final because respond has no fallible work.
    assert!(
        call.guaranteed_transcript.is_some(),
        "respond runs wholly in the guaranteed phase"
    );
    assert!(
        call.fallible_transcript.is_none(),
        "nothing in respond belongs to the fallible phase"
    );
    (**call).clone()
}

/// The circuit's arguments as the transcript pushed them: one `pushs` op ending in the
/// signature's `b32b32b32b1`. The only thing that can tell a correctly encoded request
/// from a transposed one, since the package pins the same string from its own TypeScript input.
fn pushed_call_args(call: &ContractCall<ProofPreimageMarker, DefaultDB>) -> String {
    let rendered = format!(
        "{:#?}",
        call.guaranteed_transcript
            .as_ref()
            .expect("the guaranteed transcript is present")
    );
    let ops: Vec<&str> = rendered
        .lines()
        .map(|line| line.trim().trim_end_matches(','))
        .filter(|op| op.starts_with("pushs <[") && op.ends_with("b32b32b32b1>"))
        .collect();

    assert_eq!(
        ops.len(),
        1,
        "expected one argument push in the transcript: {rendered}"
    );
    ops[0].to_string()
}

#[tokio::test]
#[ignore = "needs npm ci and npm run build in chain-signatures/midnight-publisher-ts"]
async fn the_rust_client_and_the_ts_builder_agree_on_respond_intents() {
    let builder = IntentGen::spawn(&common::base_live_config(), NETWORK_ID)
        .await
        .expect("spawn the builder");

    for circuit in ["respond", "respondBidirectional"] {
        let bytes = builder
            .build(&IntentRequest {
                circuit,
                ..respond_request()
            })
            .await
            .unwrap_or_else(|error| panic!("the builder refused {circuit}: {error:#}"));

        let call = sole_call(&bytes);
        assert_eq!(
            call.entry_point.0.as_slice(),
            circuit.as_bytes(),
            "{circuit}"
        );
        assert_eq!(
            pushed_call_args(&call),
            format!("pushs <[{BIG_R_X}, {BIG_R_Y}, {S}, {RECOVERY_ID_ZERO}]: b32b32b32b1>"),
            "{circuit}"
        );
    }
}

#[tokio::test]
#[ignore = "needs npm ci and npm run build in chain-signatures/midnight-publisher-ts"]
async fn a_contract_missing_the_entry_point_arrives_as_the_child_s_own_refusal() {
    // Stands in for a managed dir pointed at the wrong build: the child's verdict must survive the pipe.
    let builder = IntentGen::spawn(&common::base_live_config(), NETWORK_ID)
        .await
        .expect("spawn the builder");
    let mut empty = Vec::new();
    midnight_serialize::tagged_serialize(&ContractState::<DefaultDB>::default(), &mut empty)
        .expect("an empty contract state serializes");

    let error = builder
        .build(&IntentRequest {
            contract_state: hex::encode(&empty),
            ..respond_request()
        })
        .await
        .expect_err("a contract with no respond operation cannot be answered");

    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("contract_mismatch"),
        "the child's code has to survive the wire: {rendered}"
    );
    assert!(
        rendered.contains("exposes no operation `respond`"),
        "the child's message has to survive the wire: {rendered}"
    );
}
