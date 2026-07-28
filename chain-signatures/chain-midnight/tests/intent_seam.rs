//! The seam: the real Rust client drives the real TypeScript builder, and what comes
//! back parses here as the ledger's own `Intent`. Both halves are unit-tested against
//! stubs, which proves each one keeps its own end of the wire and nothing about the two
//! agreeing. This is the only test where neither side's expectations were authored by
//! the side under test.
//!
//! `#[ignore]`d: it runs `node dist/main.js` out of the publisher package's own
//! installed dependencies, so `npm ci` and `npm run build` have to have run there. The
//! midnight-publisher-ts workflow is the only place it runs.
//!
//! Everything the child is handed comes from committed fixtures and the ledger crate's
//! own constants, so no node, no proof server and no wallet is involved.

use std::path::{Path, PathBuf};

use midnight_ledger_v9::structure::{
    ContractAction, ContractCall, Intent, ProofPreimageMarker, Signature, INITIAL_PARAMETERS,
};
use midnight_onchain_state::state::ContractState;
use midnight_storage::DefaultDB;
use midnight_transient_crypto::commitment::PedersenRandomness;
use mpc_chain_midnight::{IntentGen, IntentRequest, PublisherConfig, WirePoint, WireSignature};
use tokio_util::sync::CancellationToken;

/// The contract `respond-singleton-state-37571.mn` was captured from, per
/// `tests/fixtures/README.md`. Its embedded verifier keys match the installed
/// `@sig-net/midnight-contract`, which is what lets the entry-point lookup succeed.
const SINGLETON: &str = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";

/// Minted by the real circuit on the capture chain. Any 32 bytes would do for a blind
/// append, but a real one keeps the fixture honest.
const REQUEST_ID: &str = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";

/// Deliberately all different from each other. Equal-looking components would make a
/// transposed x and y invisible, which is the exact bug the argument assertion exists
/// to catch: a transposed signature still produces a well-formed intent that lands
/// under the right request id and recovers a different key.
const BIG_R_X: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const BIG_R_Y: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const S: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// The transcript renders a trailing-zero-trimmed value, so a zero recovery id is `-`.
const RECOVERY_ID_ZERO: &str = "-";

const SINGLETON_STATE: &[u8] =
    include_bytes!("../../midnight-publisher-ts/tests/fixtures/respond-singleton-state-37571.mn");

/// The child refuses to boot without one. Nothing here encodes an address, so it only
/// has to be a value the contract library recognises.
const NETWORK_ID: &str = "undeployed";

/// Ledger 9's own tagged reading of what the builder wrote: `signature`, `pre-proof`
/// and `pre-binding`, the three markers the TypeScript side names when it decodes its
/// own output.
type ChainIntent = Intent<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>;

fn publisher_package() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../midnight-publisher-ts")
}

fn path_arg(path: &Path) -> String {
    path.to_str()
        .unwrap_or_else(|| panic!("{} is not valid UTF-8", path.display()))
        .to_string()
}

/// The builder as the node runs it in production: argv straight to the built entry
/// point, with the compiled contract assets the circuit runs against.
fn live_config() -> PublisherConfig {
    let package = publisher_package();
    let entry = package.join("dist/main.js");
    // The library resolves its own assets relative to its package, so this is the
    // installed copy rather than anything under `tests/`.
    let managed = package.join("node_modules/@sig-net/midnight-contract/dist/managed");
    // Checked here rather than left to the child: a missing entry point makes `node`
    // exit at boot, which reaches the caller as a closed pipe and reads like a protocol
    // fault instead of an unbuilt package.
    assert!(
        entry.is_file(),
        "{} is missing: run `npm ci && npm run build` in {}",
        entry.display(),
        package.display()
    );
    assert!(
        managed.is_dir(),
        "{} is missing: run `npm ci` in {}",
        managed.display(),
        package.display()
    );
    PublisherConfig {
        intent_gen_command: vec!["node".to_string(), path_arg(&entry)],
        managed_dir: path_arg(&managed),
        ..Default::default()
    }
}

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

/// The parameters the chain starts on, straight out of the ledger crate. The child
/// reads them with ledger 9's `LedgerParameters.deserialize`, so producing them here
/// with `tagged_serialize` is a second thing this test pins: the Rust and TypeScript
/// ledger builds still agree on that blob.
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
        serialized_output: None,
        output_len: None,
        contract_state: hex::encode(SINGLETON_STATE),
        ledger_parameters: initial_ledger_parameters(),
        coin_public_key: "44".repeat(32),
        ttl_seconds: 1_800_000_000,
    }
}

/// The one call the intent carries, or a failure naming which assumption broke.
///
/// Decoded, never byte-compared: the builder samples a fresh communication commitment
/// per call, deliberately, because that commitment is what unlinks a call from its
/// caller. Only the decode is stable.
fn sole_call(bytes: &[u8]) -> ContractCall<ProofPreimageMarker, DefaultDB> {
    // Tagged rather than bare, so a ledger version skew fails by name here instead of
    // as a field-shaped parse error on good bytes.
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
    // Both respond circuits are blind appends with no fallible work, and the Rust half
    // treats a built intent as final on that basis. A contract change that moves work
    // into the fallible segment surfaces here.
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

/// The circuit's arguments as the transcript pushed them: one `pushs` op whose tuple IS
/// the event struct, in the order the contract declared it, tagged with each field's
/// width.
///
/// This is what makes the test a seam test rather than a shape check. The values only
/// survive into the intent here, so it is the only thing that can tell a request this
/// crate encoded correctly from one whose fields the wire transposed, dropped or
/// zeroed. The publisher package pins the same string, but from its own TypeScript
/// input, so it cannot see a permutation introduced on this side.
///
/// Both circuits end in the signature's `b32b32b32b1`, which is what distinguishes this
/// op from the transcript's other pushes.
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
async fn the_rust_client_and_the_ts_builder_agree_on_a_respond_intent() {
    let builder = IntentGen::spawn(&live_config(), NETWORK_ID)
        .await
        .expect("spawn the builder");

    let bytes = builder
        .build(&respond_request(), &CancellationToken::new())
        .await
        .expect("the builder answers");

    let call = sole_call(&bytes);
    assert_eq!(call.entry_point.0.as_slice(), b"respond");
    assert_eq!(
        pushed_call_args(&call),
        format!("pushs <[{BIG_R_X}, {BIG_R_Y}, {S}, {RECOVERY_ID_ZERO}]: b32b32b32b1>")
    );
}

#[tokio::test]
#[ignore = "needs npm ci and npm run build in chain-signatures/midnight-publisher-ts"]
async fn the_rust_client_and_the_ts_builder_agree_on_a_bidirectional_intent() {
    // The second circuit is a separate deployed operation with a wider event struct, so
    // the unidirectional case passing says nothing about it. `output_len` is what tells
    // a consumer how much of the fixed Bytes<128> is real return data, and it renders
    // in hex: 0x20.
    let output = "ab".repeat(128);
    let builder = IntentGen::spawn(&live_config(), NETWORK_ID)
        .await
        .expect("spawn the builder");

    let bytes = builder
        .build(
            &IntentRequest {
                circuit: "respondBidirectional",
                serialized_output: Some(output.clone()),
                output_len: Some(32),
                ..respond_request()
            },
            &CancellationToken::new(),
        )
        .await
        .expect("the builder answers");

    let call = sole_call(&bytes);
    assert_eq!(call.entry_point.0.as_slice(), b"respondBidirectional");
    assert_eq!(
        pushed_call_args(&call),
        format!(
            "pushs <[{output}, 20, {BIG_R_X}, {BIG_R_Y}, {S}, {RECOVERY_ID_ZERO}]: \
             b128b1b32b32b32b1>"
        )
    );
}

#[tokio::test]
#[ignore = "needs npm ci and npm run build in chain-signatures/midnight-publisher-ts"]
async fn a_contract_missing_the_entry_point_arrives_as_the_child_s_own_refusal() {
    // A contract with no operations at all stands in for the real case: a managed dir
    // pointed at a different build than what is deployed. What is under test is that
    // the child's own verdict survives the pipe, because a generic transport error
    // would send an operator looking at the wire instead of at the deployment.
    let builder = IntentGen::spawn(&live_config(), NETWORK_ID)
        .await
        .expect("spawn the builder");
    let mut empty = Vec::new();
    midnight_serialize::tagged_serialize(&ContractState::<DefaultDB>::default(), &mut empty)
        .expect("an empty contract state serializes");

    let error = builder
        .build(
            &IntentRequest {
                contract_state: hex::encode(&empty),
                ..respond_request()
            },
            &CancellationToken::new(),
        )
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
