//! Publishes finished MPC signatures to the Midnight central contract through opaque
//! intents built and submitted by the companion process.

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use mpc_chain_integration_core::{ChainPublisher, PublishAction, PublisherTelemetry};
use mpc_primitives::{Chain, SignKind, Signature};
use mpc_utils::time::current_unix_timestamp;

use crate::config::{MidnightConfig, PublisherConfig};
use crate::intent_gen::{is_ambiguous_submit, IntentGen, IntentRequest, WirePoint, WireSignature};
use crate::reader::{
    central_map, decode_response_entry, RESPOND_BIDIRECTIONAL_MAP_FIELD, RESPOND_MAP_FIELD,
};
use crate::rpc::{MidnightPublisherRpc, PinnedReads};
use crate::state::decode_contract_state;

const RESPOND: &str = "respond";
const RESPOND_BIDIRECTIONAL: &str = "respondBidirectional";

/// What one finalized hash yielded. One hash for every read is the whole point: fees
/// drift per block, so parameters priced at one block against a state read at another
/// produce an intent the node answers `OutOfGas`.
pub(crate) struct PinnedState {
    pub at_hash: String,
    pub contract_state: Vec<u8>,
    pub ledger_parameters: Vec<u8>,
}

/// What builds a respond intent and turns it into a transaction the node has accepted:
/// the companion process in production, a stand-in in the in-process tests. `submit`
/// takes the bytes `build` wrote: re-serializing a decoded intent would stake the
/// transaction on a round trip nothing checks. The returned string names the
/// transaction, opaque here.
#[async_trait]
pub(crate) trait IntentClient: Send + Sync {
    async fn build(&self, request: &IntentRequest) -> anyhow::Result<Vec<u8>>;
    async fn submit(&self, intent: &[u8]) -> anyhow::Result<String>;
}

#[async_trait]
impl IntentClient for IntentGen {
    async fn build(&self, request: &IntentRequest) -> anyhow::Result<Vec<u8>> {
        IntentGen::build(self, request).await
    }

    async fn submit(&self, intent: &[u8]) -> anyhow::Result<String> {
        IntentGen::submit(self, intent).await
    }
}

#[derive(Clone, Copy, Debug)]
enum RespondCircuit {
    Respond,
    RespondBidirectional,
}

impl RespondCircuit {
    const fn wire_name(self) -> &'static str {
        match self {
            Self::Respond => RESPOND,
            Self::RespondBidirectional => RESPOND_BIDIRECTIONAL,
        }
    }

    /// The central ledger field holding this circuit's append-only response map.
    const fn map_field(self) -> u8 {
        match self {
            Self::Respond => RESPOND_MAP_FIELD,
            Self::RespondBidirectional => RESPOND_BIDIRECTIONAL_MAP_FIELD,
        }
    }

    /// The map's name in the deployed contract, as the indexer labels it.
    const fn map_name(self) -> &'static str {
        match self {
            Self::Respond => "respondMap",
            Self::RespondBidirectional => "respondBidirectionalMap",
        }
    }
}

/// One respond call, marshalled off the action before anything is read or spawned.
struct RespondCall {
    circuit: RespondCircuit,
    request_id: [u8; 32],
    signature: WireSignature,
    stored_signature: Signature,
}

/// Posts MPC responses back to the Midnight central contract.
pub struct MidnightPublisher {
    config: PublisherConfig,
    reads: Arc<dyn PinnedReads>,
    client: Arc<dyn IntentClient>,
    central_address: String,
    telemetry: Arc<dyn PublisherTelemetry>,
    /// One funding wallet and one DUST UTXO mean build-to-submit is one serial flow.
    flow: tokio::sync::Mutex<()>,
}

impl MidnightPublisher {
    /// Dials the node, spawns the intent builder on the node's network id, and wires
    /// both. The order is the invariant: the builder validates the id the node reports.
    pub async fn connect(
        config: &MidnightConfig,
        telemetry: Arc<dyn PublisherTelemetry>,
    ) -> anyhow::Result<Self> {
        let rpc = Arc::new(MidnightPublisherRpc::connect(config).await?);
        let intent_gen = Arc::new(IntentGen::spawn(config, rpc.network_id()).await?);
        Ok(Self::new(
            &config.publisher,
            config.central_address.clone(),
            rpc,
            intent_gen,
            telemetry,
        ))
    }

    fn new(
        config: &PublisherConfig,
        central_address: String,
        reads: Arc<dyn PinnedReads>,
        client: Arc<dyn IntentClient>,
        telemetry: Arc<dyn PublisherTelemetry>,
    ) -> Self {
        Self {
            config: config.clone(),
            central_address,
            reads,
            client,
            telemetry,
            flow: tokio::sync::Mutex::new(()),
        }
    }

    /// The contract state and ledger parameters at one finalized hash.
    async fn pin(&self, central_address: &str, at_hash: String) -> anyhow::Result<PinnedState> {
        let contract_state = self
            .reads
            .contract_state(central_address, &at_hash)
            .await?
            .with_context(|| {
                format!("midnight central contract {central_address} is not present at {at_hash}")
            })?;
        let ledger_parameters = self.reads.ledger_parameters(&at_hash).await?;
        Ok(PinnedState {
            at_hash,
            contract_state,
            ledger_parameters,
        })
    }
}

#[async_trait]
impl ChainPublisher for MidnightPublisher {
    // TODO: Batch responses if one-response-per-transaction publication becomes a bottleneck.
    // Retries and finalized-state reconciliation currently operate per request.
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let call = respond_call(action)?;
        let _flow = self.flow.lock().await;
        let sign_id = action.request.id;
        tracing::info!(
            ?sign_id,
            circuit = call.circuit.wire_name(),
            central = %self.central_address,
            request_id = %hex::encode(call.request_id),
            elapsed = ?action.timestamp.elapsed(),
            "midnight: publishing signature"
        );

        // One head for every read below it.
        let at_hash = self.reads.finalized_head().await?;
        let chain = self.pin(&self.central_address, at_hash).await?;
        if response_present(&chain.contract_state, &call)? {
            tracing::info!(
                ?sign_id,
                circuit = call.circuit.wire_name(),
                at_hash = %chain.at_hash,
                "midnight: exact response is already finalized"
            );
            self.telemetry.record_publish_metrics(action);
            return Ok(());
        }

        let request = IntentRequest {
            circuit: call.circuit.wire_name(),
            contract_address: self.central_address.clone(),
            request_id: hex::encode(call.request_id),
            signature: call.signature.clone(),
            contract_state: hex::encode(&chain.contract_state),
            ledger_parameters: hex::encode(&chain.ledger_parameters),
            ttl_seconds: ttl_seconds(&self.config, current_unix_timestamp()),
        };
        let bytes = self.client.build(&request).await?;

        let receipt = self
            .client
            .submit(&bytes)
            .await
            .with_context(|| {
                format!(
                    "submitting the midnight respond intent built over the chain at {}",
                    chain.at_hash
                )
            })
            .inspect_err(|error| {
                // The one failure shape worth naming: the transaction may land anyway,
                // and settlement is deferred to a later attempt's pinned read.
                if is_ambiguous_submit(error) {
                    tracing::warn!(
                        ?sign_id,
                        circuit = call.circuit.wire_name(),
                        request_id = %hex::encode(call.request_id),
                        at_hash = %chain.at_hash,
                        elapsed = ?action.timestamp.elapsed(),
                        "midnight: submit answer was lost; deferring settlement to the \
                         retry attempt's pinned read"
                    );
                }
            })?;

        tracing::info!(
            ?sign_id,
            circuit = call.circuit.wire_name(),
            at_hash = %chain.at_hash,
            receipt = %receipt,
            elapsed = ?action.timestamp.elapsed(),
            "midnight: published respond successfully"
        );
        self.telemetry.record_publish_metrics(action);
        Ok(())
    }
}

/// The action as one respond call, or a refusal: every gate is here, ahead of the
/// first read, so a refused action costs nothing.
fn respond_call(action: &PublishAction) -> anyhow::Result<RespondCall> {
    anyhow::ensure!(
        action.request.chain == Chain::Midnight,
        "midnight publisher was handed a {:?} request",
        action.request.chain
    );
    let stored_signature = action.signature;
    let signature = wire_signature(&stored_signature)?;
    let request_id = action.request.id.request_id;

    match &action.request.kind {
        SignKind::SignBidirectional(event) => {
            anyhow::ensure!(
                event.chain == Chain::Midnight,
                "midnight publisher was handed a request routed to it carrying a {:?} event",
                event.chain
            );
            Ok(RespondCall {
                circuit: RespondCircuit::Respond,
                request_id,
                signature,
                stored_signature,
            })
        }
        // The output never travels: the contract stores a bare signature, and the
        // attestation already commits to the output.
        SignKind::RespondBidirectional(_) => Ok(RespondCall {
            circuit: RespondCircuit::RespondBidirectional,
            request_id,
            signature,
            stored_signature,
        }),
        SignKind::Sign => anyhow::bail!(
            "midnight publisher serves SignBidirectional and RespondBidirectional only, not Sign"
        ),
    }
}

/// The signature in the shape the circuit pushes. Nothing re-encodes downstream, so a
/// transposition introduced here lands on chain under the right request id and
/// recovers a different key.
fn wire_signature(signature: &Signature) -> anyhow::Result<WireSignature> {
    let encoded = signature.big_r.to_encoded_point(false);
    let (Some(x), Some(y)) = (encoded.x(), encoded.y()) else {
        anyhow::bail!("midnight respond: big_r has no affine coordinates (identity point)");
    };
    // The circuit takes Uint<8>; only the parities 0 and 1 recover the key.
    anyhow::ensure!(
        signature.recovery_id <= 1,
        "midnight respond: recovery_id {} is not 0 or 1",
        signature.recovery_id
    );
    Ok(WireSignature {
        big_r: WirePoint {
            x: hex::encode(x),
            y: hex::encode(y),
        },
        s: hex::encode(signature.s.to_bytes()),
        recovery_id: signature.recovery_id,
    })
}

fn response_present(state: &[u8], call: &RespondCall) -> anyhow::Result<bool> {
    let root = decode_contract_state(state)?;
    let entries = central_map(&root, call.circuit.map_field(), call.circuit.map_name())?;
    for entry in entries.iter() {
        let (key, value) = &*entry;
        let decoded = decode_response_entry(key, value)
            .context("midnight finalized response schema drift")?;
        let stored_request_id = decoded.request_id;
        match decoded.signature {
            Ok(stored_signature)
                if stored_request_id == call.request_id
                    && stored_signature == call.stored_signature =>
            {
                return Ok(true);
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(
                circuit = call.circuit.wire_name(),
                request_id = %hex::encode(call.request_id),
                "midnight finalized response signature ignored: {err:#}"
            ),
        }
    }
    Ok(false)
}

/// The intent's expiry, as absolute unix seconds: one publish's build and submit
/// budgets summed. It bounds how late a transaction whose answer was lost can still
/// land; whether it did is the next attempt's pinned read to settle.
fn ttl_seconds(config: &PublisherConfig, now: u64) -> u64 {
    now.saturating_add(config.request_timeout.as_secs())
        .saturating_add(config.submit_timeout.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::intent_gen::AmbiguousSubmit;
    use std::sync::Mutex;
    use std::time::Duration;

    use midnight_base_crypto::fab::{
        AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
    };
    use midnight_onchain_state::state::{ChargedState, ContractState, StateValue};
    use midnight_storage::DefaultDB;
    use mpc_chain_integration_core::utils::test::make_publish_action;
    use mpc_chain_integration_core::NoopPublisherTelemetry;
    use mpc_primitives::{
        BidirectionalTxId, Chain, RespondBidirectionalTx, SignBidirectionalEvent, SignId, SignKind,
    };

    use crate::test_utils::{array_of, cell_from_atoms, map_of, trim};

    /// An arbitrary well-formed central address.
    const CENTRAL: &str = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
    const REQUEST_ID: [u8; 32] = [0x5c; 32];
    /// Two different heads, so a per-read re-reader cannot pass the one-hash assertion.
    const HEAD_ONE: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const HEAD_TWO: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";

    /// Distinct per read, so a test can tell which read produced which bytes.
    const CONTRACT_STATE: &[u8] =
        include_bytes!("../../midnight-publisher-ts/tests/fixtures/initial-singleton-state.mn");
    const LEDGER_PARAMETERS: &[u8] = b"ledger-parameters";

    /// One read the publisher made: which surface, and at which hash.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Read {
        method: &'static str,
        at_hash: String,
    }

    /// An in-process node stand-in serving a DIFFERENT finalized head on every ask.
    #[derive(Default)]
    struct StubReads {
        calls: Mutex<Vec<Read>>,
        heads_served: Mutex<usize>,
        contract_state: Mutex<Vec<u8>>,
        /// `false` makes `contract_state` answer "no contract here".
        contract_present: bool,
    }

    impl StubReads {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                contract_present: true,
                contract_state: Mutex::new(CONTRACT_STATE.to_vec()),
                ..Default::default()
            })
        }

        fn with_state(state: Vec<u8>) -> Arc<Self> {
            Arc::new(Self {
                contract_present: true,
                contract_state: Mutex::new(state),
                ..Default::default()
            })
        }

        fn absent() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn reads(&self) -> Vec<Read> {
            self.calls.lock().unwrap().clone()
        }

        fn record(&self, method: &'static str, at_hash: &str) {
            self.calls.lock().unwrap().push(Read {
                method,
                at_hash: at_hash.to_string(),
            });
        }

        fn set_state(&self, state: Vec<u8>) {
            *self.contract_state.lock().unwrap() = state;
        }
    }

    #[async_trait]
    impl PinnedReads for StubReads {
        async fn finalized_head(&self) -> anyhow::Result<String> {
            let mut served = self.heads_served.lock().unwrap();
            *served += 1;
            self.record("finalized_head", "");
            Ok(if *served == 1 { HEAD_ONE } else { HEAD_TWO }.to_string())
        }

        async fn contract_state(
            &self,
            _address: &str,
            at_hash: &str,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            self.record("contract_state", at_hash);
            Ok(self
                .contract_present
                .then(|| self.contract_state.lock().unwrap().clone()))
        }

        async fn ledger_parameters(&self, at_hash: &str) -> anyhow::Result<Vec<u8>> {
            self.record("ledger_parameters", at_hash);
            Ok(LEDGER_PARAMETERS.to_vec())
        }
    }

    /// The builder's grant, and so the bytes `submit` must be handed back: the
    /// pass-through property every stub client asserts.
    const GRANTED_INTENT: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

    /// A refused build, in the child's own words: the way a managed dir pointed at the
    /// wrong build refuses.
    const BUILD_REFUSAL: &str =
        "midnight intent builder refused the request [contract_mismatch]: exposes no operation";

    /// An in-process child. Grants every build with `GRANTED_INTENT` and keeps the
    /// request for assertions on the marshalling; counting submits is the only mark a
    /// proving run leaves.
    #[derive(Default)]
    struct StubClient {
        built: Mutex<Vec<IntentRequest>>,
        refuse_build: bool,
        submitted: std::sync::atomic::AtomicUsize,
        /// What `submit` refuses with, standing in for the child's own verdict.
        submit_failure: Option<&'static str>,
    }

    impl StubClient {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn refusing_build() -> Arc<Self> {
            Arc::new(Self {
                refuse_build: true,
                ..Default::default()
            })
        }

        fn refusing_submit(failure: &'static str) -> Arc<Self> {
            Arc::new(Self {
                submit_failure: Some(failure),
                ..Default::default()
            })
        }

        fn built(&self) -> Vec<IntentRequest> {
            self.built.lock().unwrap().clone()
        }

        fn submissions(&self) -> usize {
            self.submitted.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl IntentClient for StubClient {
        async fn build(&self, request: &IntentRequest) -> anyhow::Result<Vec<u8>> {
            anyhow::ensure!(!self.refuse_build, "{BUILD_REFUSAL}");
            self.built.lock().unwrap().push(request.clone());
            Ok(GRANTED_INTENT.to_vec())
        }

        async fn submit(&self, intent: &[u8]) -> anyhow::Result<String> {
            // The bytes have to be the builder's own: whatever is proved and paid for is this.
            assert_eq!(
                intent, GRANTED_INTENT,
                "the submitter must be handed the bytes the builder wrote"
            );
            if let Some(failure) = self.submit_failure {
                // Before the record: a submit that failed posted nothing.
                anyhow::bail!("{failure}");
            }
            self.submitted
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok("stub-receipt".to_string())
        }
    }

    struct LandingWithoutReply {
        reads: Arc<StubReads>,
        landed_state: Vec<u8>,
        builds: std::sync::atomic::AtomicUsize,
        attempts: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl IntentClient for LandingWithoutReply {
        async fn build(&self, _request: &IntentRequest) -> anyhow::Result<Vec<u8>> {
            self.builds
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(GRANTED_INTENT.to_vec())
        }

        async fn submit(&self, _intent: &[u8]) -> anyhow::Result<String> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.reads.set_state(self.landed_state.clone());
            Err(anyhow::anyhow!("stdout closed after submit").context(AmbiguousSubmit))
        }
    }

    #[derive(Default)]
    struct BlockingClient {
        attempts: std::sync::atomic::AtomicUsize,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl IntentClient for BlockingClient {
        async fn build(&self, _request: &IntentRequest) -> anyhow::Result<Vec<u8>> {
            Ok(GRANTED_INTENT.to_vec())
        }

        async fn submit(&self, _intent: &[u8]) -> anyhow::Result<String> {
            let attempt = self
                .attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.entered.notify_one();
            if attempt == 0 {
                self.release.notified().await;
            }
            Ok(format!("receipt-{attempt}"))
        }
    }

    /// The two budgets the publisher spends, pinned because `ttl_seconds` is their sum
    /// and a test reading a default would test the default. The rest is the child's.
    fn config() -> PublisherConfig {
        PublisherConfig {
            request_timeout: Duration::from_secs(5),
            submit_timeout: Duration::from_secs(30),
            ..Default::default()
        }
    }

    fn publisher(reads: Arc<dyn PinnedReads>, client: Arc<dyn IntentClient>) -> MidnightPublisher {
        MidnightPublisher::new(
            &config(),
            CENTRAL.to_string(),
            reads,
            client,
            Arc::new(NoopPublisherTelemetry),
        )
    }

    fn sign_event(chain: Chain) -> SignBidirectionalEvent {
        SignBidirectionalEvent {
            sender: [0; 32],
            serialized_transaction: vec![],
            caip2_id: "eip155:31337".to_string(),
            key_version: 1,
            deposit: 0,
            path: String::new(),
            algo: String::new(),
            dest: String::new(),
            params: String::new(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            chain,
            chain_ctx: None,
        }
    }

    fn respond_action() -> PublishAction {
        make_publish_action(
            Chain::Midnight,
            SignKind::SignBidirectional(sign_event(Chain::Midnight)),
            SignId::new(REQUEST_ID),
        )
    }

    fn bidirectional_action(output: Vec<u8>) -> PublishAction {
        make_publish_action(
            Chain::Midnight,
            SignKind::RespondBidirectional(RespondBidirectionalTx {
                tx_id: BidirectionalTxId([0x11; 32]),
                output,
                chain_ctx: None,
            }),
            SignId::new(REQUEST_ID),
        )
    }

    fn state_with_response(action: &PublishAction) -> Vec<u8> {
        let call = respond_call(action).expect("the test action maps to a response");
        let field = usize::from(call.circuit.map_field());
        let mut contract: ContractState<DefaultDB> =
            midnight_serialize::tagged_deserialize(&mut &CONTRACT_STATE[..])
                .expect("the initial singleton state decodes");
        let StateValue::Array(fields) = contract.data.get_ref() else {
            panic!("the initial singleton root is an array")
        };
        let mut fields: Vec<_> = fields.iter_deref().cloned().collect();
        let key = AlignedValue {
            value: Value(vec![ValueAtom(vec![1]), ValueAtom(trim(&call.request_id))]),
            alignment: Alignment(vec![
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 8 }),
                AlignmentSegment::Atom(AlignmentAtom::Bytes { length: 32 }),
            ]),
        };
        let encoded = call.stored_signature.big_r.to_encoded_point(false);
        let value = cell_from_atoms(
            &[
                trim(encoded.x().expect("affine x")),
                trim(encoded.y().expect("affine y")),
                trim(call.stored_signature.s.to_bytes().as_slice()),
                trim(&[call.stored_signature.recovery_id]),
            ],
            &[32, 32, 32, 1],
        );
        fields[field] = map_of(vec![(key, value)]);
        contract.data = ChargedState::new(array_of(fields));

        let mut encoded = Vec::new();
        midnight_serialize::tagged_serialize(&contract, &mut encoded)
            .expect("the singleton state serializes");
        encoded
    }

    fn state_with_malformed_response(action: &PublishAction) -> Vec<u8> {
        let call = respond_call(action).expect("the test action maps to a response");
        let field = usize::from(call.circuit.map_field());
        let state = state_with_response(action);
        let mut contract: ContractState<DefaultDB> =
            midnight_serialize::tagged_deserialize(&mut &state[..])
                .expect("the singleton response state decodes");
        let StateValue::Array(fields) = contract.data.get_ref() else {
            panic!("the singleton root is an array")
        };
        let mut fields: Vec<_> = fields.iter_deref().cloned().collect();
        let StateValue::Map(entries) = &fields[field] else {
            panic!("the response field is a map")
        };
        let (key, _) = &*entries.iter().next().expect("one response entry");
        fields[field] = map_of(vec![(
            (**key).clone(),
            cell_from_atoms(&[vec![1], vec![2], vec![3]], &[400, 1, 1]),
        )]);
        contract.data = ChargedState::new(array_of(fields));

        let mut encoded = Vec::new();
        midnight_serialize::tagged_serialize(&contract, &mut encoded)
            .expect("the malformed singleton state serializes");
        encoded
    }

    fn state_with_invalid_signature_response(action: &PublishAction) -> Vec<u8> {
        let call = respond_call(action).expect("the test action maps to a response");
        let field = usize::from(call.circuit.map_field());
        let state = state_with_response(action);
        let mut contract: ContractState<DefaultDB> =
            midnight_serialize::tagged_deserialize(&mut &state[..])
                .expect("the singleton response state decodes");
        let StateValue::Array(fields) = contract.data.get_ref() else {
            panic!("the singleton root is an array")
        };
        let mut fields: Vec<_> = fields.iter_deref().cloned().collect();
        let StateValue::Map(entries) = &fields[field] else {
            panic!("the response field is a map")
        };
        let (key, _) = &*entries.iter().next().expect("one response entry");
        fields[field] = map_of(vec![(
            (**key).clone(),
            cell_from_atoms(
                &[vec![0xff; 32], vec![0xff; 32], vec![1], vec![]],
                &[32, 32, 32, 1],
            ),
        )]);
        contract.data = ChargedState::new(array_of(fields));

        let mut encoded = Vec::new();
        midnight_serialize::tagged_serialize(&contract, &mut encoded)
            .expect("the invalid-signature singleton state serializes");
        encoded
    }

    #[tokio::test]
    async fn publish_signature_rejects_actions_neither_circuit_answers() {
        // Three gates, one property: a refused action must not reach the node, the
        // builder or the submitter.
        let cases = [
            (
                make_publish_action(
                    Chain::Canton,
                    SignKind::SignBidirectional(sign_event(Chain::Canton)),
                    SignId::new(REQUEST_ID),
                ),
                "Canton",
            ),
            (
                make_publish_action(
                    Chain::Midnight,
                    SignKind::SignBidirectional(sign_event(Chain::Canton)),
                    SignId::new(REQUEST_ID),
                ),
                "Canton",
            ),
            (
                make_publish_action(Chain::Midnight, SignKind::Sign, SignId::new(REQUEST_ID)),
                "Sign",
            ),
        ];
        for (action, named) in cases {
            let reads = StubReads::new();
            let client = StubClient::new();
            let publisher = publisher(reads.clone(), client.clone());

            let err = publisher
                .publish_signature(&action)
                .await
                .expect_err("neither circuit answers this action");
            assert!(format!("{err:#}").contains(named), "got: {err:#}");
            assert!(reads.reads().is_empty(), "a refused action read the node");
            assert!(
                client.built().is_empty(),
                "a refused action reached the builder"
            );
            assert_eq!(client.submissions(), 0);
        }
    }

    #[tokio::test]
    async fn publish_signature_pins_and_marshals_both_circuits() {
        for (action, circuit) in [
            (respond_action(), RESPOND),
            (bidirectional_action(vec![0xab; 32]), RESPOND_BIDIRECTIONAL),
        ] {
            // The stub serves a different head on every ask, so a per-read taker
            // would spread the two reads across blocks.
            let reads = StubReads::new();
            let client = StubClient::new();
            let publisher = publisher(reads.clone(), client.clone());
            let before = current_unix_timestamp();

            publisher
                .publish_signature(&action)
                .await
                .expect("the stub client grants and accepts");
            let after = current_unix_timestamp();

            let reads = reads.reads();
            let at_hashes: Vec<_> = reads
                .iter()
                .filter(|read| read.method != "finalized_head")
                .map(|read| read.at_hash.as_str())
                .collect();
            assert_eq!(at_hashes, vec![HEAD_ONE; 2], "{circuit} pinned reads");
            assert_eq!(
                reads
                    .iter()
                    .filter(|read| read.method == "finalized_head")
                    .count(),
                1,
                "{circuit} finalized-head reads"
            );

            let [request] = client.built().try_into().expect("one build per publish");
            assert_eq!(request.circuit, circuit);
            assert_eq!(request.contract_address, CENTRAL);
            assert_eq!(request.request_id, hex::encode(REQUEST_ID));
            assert_eq!(request.contract_state, hex::encode(CONTRACT_STATE));
            assert_eq!(request.ledger_parameters, hex::encode(LEDGER_PARAMETERS));

            let encoded = action.signature.big_r.to_encoded_point(false);
            assert_eq!(
                request.signature,
                WireSignature {
                    big_r: WirePoint {
                        x: hex::encode(encoded.x().unwrap()),
                        y: hex::encode(encoded.y().unwrap()),
                    },
                    s: hex::encode(action.signature.s.to_bytes()),
                    recovery_id: action.signature.recovery_id,
                },
                "{circuit} signature"
            );

            let budget = config().request_timeout.as_secs() + config().submit_timeout.as_secs();
            assert!(
                (before.saturating_add(budget)..=after.saturating_add(budget))
                    .contains(&request.ttl_seconds),
                "{circuit} ttl"
            );
            assert_eq!(client.submissions(), 1, "{circuit} submissions");
        }
    }

    #[tokio::test]
    async fn a_rejected_intent_fails_the_publish_without_spending_a_proof() {
        // Proving is the one expensive step, and a refusal means no intent was built.
        let client = StubClient::refusing_build();
        let publisher = publisher(StubReads::new(), client.clone());

        let err = publisher
            .publish_signature(&respond_action())
            .await
            .expect_err("a refused request cannot be published");
        assert!(
            format!("{err:#}").contains("contract_mismatch"),
            "the builder's verdict has to reach the caller: {err:#}"
        );
        assert_eq!(
            client.submissions(),
            0,
            "a refused intent reached the prover"
        );
    }

    #[test]
    fn response_schema_drift_preserves_its_cause_and_is_retryable() {
        for action in [respond_action(), bidirectional_action(vec![0xab; 32])] {
            let call = respond_call(&action).expect("the action maps to a response");
            let err = response_present(&state_with_malformed_response(&action), &call)
                .expect_err("a malformed response entry is contract-schema drift");
            assert!(
                format!("{err:#}").contains("response bigR.x"),
                "the structural cause must reach the caller: {err:#}"
            );
            assert!(
                mpc_chain_integration_core::utils::retry::is_retryable(&err),
                "schema drift must remain at the shared retry boundary: {err:#}"
            );
        }
    }

    #[tokio::test]
    async fn nonmatching_finalized_responses_do_not_suppress_publish() {
        let respond = respond_action();
        let mut other = respond.clone();
        other.signature.recovery_id ^= 1;
        let bidirectional = bidirectional_action(vec![0xab; 32]);
        let cases = [
            (
                "different signature",
                respond.clone(),
                state_with_response(&other),
            ),
            (
                "invalid respond signature",
                respond.clone(),
                state_with_invalid_signature_response(&respond),
            ),
            (
                "invalid bidirectional signature",
                bidirectional.clone(),
                state_with_invalid_signature_response(&bidirectional),
            ),
        ];

        for (case, action, state) in cases {
            let client = StubClient::new();
            let publisher = publisher(StubReads::with_state(state), client.clone());

            publisher
                .publish_signature(&action)
                .await
                .unwrap_or_else(|error| panic!("{case} blocked publishing: {error:#}"));
            assert_eq!(client.submissions(), 1, "{case}");
        }
    }

    #[tokio::test]
    async fn a_landed_submit_with_a_lost_reply_defers_to_the_retry_and_does_not_repost() {
        for action in [respond_action(), bidirectional_action(vec![0xab; 32])] {
            let reads = StubReads::new();
            let client = Arc::new(LandingWithoutReply {
                reads: reads.clone(),
                landed_state: state_with_response(&action),
                builds: std::sync::atomic::AtomicUsize::new(0),
                attempts: std::sync::atomic::AtomicUsize::new(0),
            });
            let publisher = publisher(reads, client.clone());

            // The first attempt's answer is lost after the post landed: it must fail
            // as a retryable ambiguity, never report success for an unnamed post.
            let error = publisher
                .publish_signature(&action)
                .await
                .expect_err("a lost answer is not a published signature");
            assert!(
                is_ambiguous_submit(&error),
                "the ambiguity must survive to the caller: {error:#}"
            );
            assert!(
                mpc_chain_integration_core::utils::retry::is_retryable(&error),
                "an ambiguous submit hands settlement to the retry: {error:#}"
            );
            assert_eq!(
                client.attempts.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "an ambiguous landed submit must not be posted twice within one attempt"
            );
            assert_eq!(
                client.builds.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the initial attempt must build exactly one intent"
            );

            // The retry attempt's pinned read finds the exact response and settles
            // without building or posting anything.
            publisher
                .publish_signature(&action)
                .await
                .expect("the retry settles on the already-finalized response");
            assert_eq!(
                client.attempts.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the settled retry must not repost"
            );
            assert_eq!(
                client.builds.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "the settled retry must not rebuild"
            );
        }
    }

    #[tokio::test]
    async fn concurrent_publishes_serialize_before_the_first_pinned_read() {
        let reads = StubReads::new();
        let client = Arc::new(BlockingClient::default());
        let publisher = Arc::new(publisher(reads.clone(), client.clone()));
        let first_entered = client.entered.notified();

        let first = tokio::spawn({
            let publisher = publisher.clone();
            async move { publisher.publish_signature(&respond_action()).await }
        });
        first_entered.await;
        let second = tokio::spawn({
            let publisher = publisher.clone();
            async move { publisher.publish_signature(&respond_action()).await }
        });
        tokio::task::yield_now().await;

        assert_eq!(
            reads
                .reads()
                .iter()
                .filter(|read| read.method == "finalized_head")
                .count(),
            1,
            "the second flow read state while the first still held the funding wallet"
        );

        client.release.notify_one();
        first
            .await
            .expect("the first task returns")
            .expect("the first publish succeeds");
        second
            .await
            .expect("the second task returns")
            .expect("the second publish succeeds");
        assert_eq!(client.attempts.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_submit_that_fails_must_not_be_reported_as_a_published_signature() {
        // An `Ok` here settles the signature as answered and nothing retries it.
        let client = StubClient::refusing_submit("no spendable dust");
        let publisher = publisher(StubReads::new(), client.clone());

        let err = publisher
            .publish_signature(&respond_action())
            .await
            .expect_err("a post that never landed is not a published signature");
        assert!(
            format!("{err:#}").contains("no spendable dust"),
            "got: {err:#}"
        );
        assert_eq!(client.submissions(), 0);
    }

    #[tokio::test]
    async fn a_central_contract_absent_at_the_pinned_hash_fails_the_publish() {
        // A wrong central address or a node that cannot reach the block: either way
        // there is nothing to prove against.
        let publisher = publisher(StubReads::absent(), StubClient::new());

        let err = publisher
            .publish_signature(&respond_action())
            .await
            .expect_err("an absent contract has no respond operation");
        assert!(format!("{err:#}").contains("not present"), "got: {err:#}");
    }
}
