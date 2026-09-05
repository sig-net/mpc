//! Publishes finished MPC signatures to the Midnight central contract through opaque
//! intents built and submitted by the companion process.

use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use mpc_chain_integration_core::{ChainPublisher, PublishAction, PublisherTelemetry};
use mpc_primitives::{Chain, SignKind, Signature};
use mpc_utils::time::current_unix_timestamp;

use crate::config::{MidnightAddress, MidnightConfig, PublisherConfig};
use crate::intent_gen::{IntentGen, IntentRequest, WirePoint, WireSignature};
use crate::output_storage::{GcsOutputStore, OutputStore};
use crate::rpc::{MidnightPublisherRpc, PinnedReads};

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
}

/// One respond call, marshalled off the action before anything is read or spawned.
struct RespondCall {
    circuit: RespondCircuit,
    request_id: [u8; 32],
    signature: WireSignature,
}

/// Posts MPC responses back to the Midnight central contract.
pub struct MidnightPublisher {
    config: PublisherConfig,
    reads: Arc<dyn PinnedReads>,
    client: Arc<dyn IntentClient>,
    output_store: Option<Arc<dyn OutputStore>>,
    central_address: MidnightAddress,
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
        config.publisher.validate_output_storage()?;
        let rpc = Arc::new(MidnightPublisherRpc::connect(config).await?);
        let output_store =
            GcsOutputStore::connect(&config.publisher, rpc.network_id(), config.central_address)
                .await?
                .map(|store| Arc::new(store) as Arc<dyn OutputStore>);
        let intent_gen = Arc::new(IntentGen::spawn(config, rpc.network_id()).await?);
        Ok(Self::new(
            &config.publisher,
            config.central_address,
            rpc,
            intent_gen,
            output_store,
            telemetry,
        ))
    }

    fn new(
        config: &PublisherConfig,
        central_address: MidnightAddress,
        reads: Arc<dyn PinnedReads>,
        client: Arc<dyn IntentClient>,
        output_store: Option<Arc<dyn OutputStore>>,
        telemetry: Arc<dyn PublisherTelemetry>,
    ) -> Self {
        Self {
            config: config.clone(),
            central_address,
            reads,
            client,
            output_store,
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
    // Retries currently operate per request.
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let call = respond_call(action)?;
        if let (Some(store), SignKind::RespondBidirectional(response)) =
            (&self.output_store, &action.request.kind)
        {
            store
                .ensure_output(&call.request_id, &response.output)
                .await?;
        }
        let _flow = self.flow.lock().await;
        let central_address = self.central_address.to_hex();
        let sign_id = action.request.id;
        tracing::info!(
            ?sign_id,
            circuit = call.circuit.wire_name(),
            central = %central_address,
            request_id = %hex::encode(call.request_id),
            elapsed = ?action.timestamp.elapsed(),
            "midnight: publishing signature"
        );

        // One head for every read below it.
        let at_hash = self.reads.finalized_head().await?;
        let chain = self.pin(&central_address, at_hash).await?;
        let request = IntentRequest {
            circuit: call.circuit.wire_name(),
            contract_address: central_address,
            request_id: hex::encode(call.request_id),
            signature: call.signature.clone(),
            contract_state: hex::encode(&chain.contract_state),
            ledger_parameters: hex::encode(&chain.ledger_parameters),
            ttl_seconds: ttl_seconds(&self.config, current_unix_timestamp()),
        };
        let bytes = self.client.build(&request).await?;

        let receipt = self.client.submit(&bytes).await.with_context(|| {
            format!(
                "submitting the midnight respond intent built over the chain at {}",
                chain.at_hash
            )
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
    let signature = wire_signature(&action.signature)?;
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
            })
        }
        // The on-chain event carries only the signature; output storage is handled
        // by the publisher, when configured, before it builds this circuit call.
        SignKind::RespondBidirectional(_) => Ok(RespondCall {
            circuit: RespondCircuit::RespondBidirectional,
            request_id,
            signature,
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

/// The intent's expiry, as absolute unix seconds: one publish's build and submit
/// budgets summed. It bounds how late a transaction whose answer was lost can land.
fn ttl_seconds(config: &PublisherConfig, now: u64) -> u64 {
    now.saturating_add(config.request_timeout.as_secs())
        .saturating_add(config.submit_timeout.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::intent_gen::{is_ambiguous_submit, AmbiguousSubmit};
    use std::sync::Mutex;
    use std::time::Duration;

    use mpc_chain_integration_core::utils::test::make_publish_action;
    use mpc_chain_integration_core::NoopPublisherTelemetry;
    use mpc_primitives::{
        BidirectionalTxId, Chain, RespondBidirectionalTx, SignBidirectionalEvent, SignId, SignKind,
    };

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
        contract_addresses: Mutex<Vec<String>>,
        heads_served: Mutex<usize>,
        /// `false` makes `contract_state` answer "no contract here".
        contract_present: bool,
    }

    impl StubReads {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                contract_present: true,
                ..Default::default()
            })
        }

        fn absent() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn reads(&self) -> Vec<Read> {
            self.calls.lock().unwrap().clone()
        }

        fn contract_addresses(&self) -> Vec<String> {
            self.contract_addresses.lock().unwrap().clone()
        }

        fn record(&self, method: &'static str, at_hash: &str) {
            self.calls.lock().unwrap().push(Read {
                method,
                at_hash: at_hash.to_string(),
            });
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
            address: &str,
            at_hash: &str,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            self.contract_addresses
                .lock()
                .unwrap()
                .push(address.to_string());
            self.record("contract_state", at_hash);
            Ok(self.contract_present.then(|| CONTRACT_STATE.to_vec()))
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
        attempts: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl IntentClient for LandingWithoutReply {
        async fn build(&self, _request: &IntentRequest) -> anyhow::Result<Vec<u8>> {
            Ok(GRANTED_INTENT.to_vec())
        }

        async fn submit(&self, _intent: &[u8]) -> anyhow::Result<String> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
            MidnightAddress::from_hex(CENTRAL).expect("CENTRAL is a 32-byte hex address"),
            reads,
            client,
            Some(Arc::new(StubOutputStore::default())),
            Arc::new(NoopPublisherTelemetry),
        )
    }

    #[derive(Default)]
    struct StubOutputStore {
        outputs: Mutex<Vec<([u8; 32], Vec<u8>)>>,
        failure: bool,
    }

    #[async_trait]
    impl OutputStore for StubOutputStore {
        async fn ensure_output(&self, request_id: &[u8; 32], output: &[u8]) -> anyhow::Result<()> {
            anyhow::ensure!(!self.failure, "output storage unavailable");
            self.outputs
                .lock()
                .unwrap()
                .push((*request_id, output.to_vec()));
            Ok(())
        }
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

    #[tokio::test]
    async fn final_response_requires_output_storage_before_reading_the_chain() {
        let reads = StubReads::new();
        let client = StubClient::new();
        let mut publisher = publisher(reads.clone(), client.clone());
        publisher.output_store = Some(Arc::new(StubOutputStore {
            failure: true,
            ..Default::default()
        }));
        let result = publisher
            .publish_signature(&bidirectional_action(vec![0xde, 0xad, 0xbe, 0xef, 1]))
            .await;

        assert!(result.is_err(), "final response needs an output store");
        assert!(reads.reads().is_empty());
        assert!(client.built().is_empty());
        assert_eq!(client.submissions(), 0);
    }

    #[tokio::test]
    async fn final_response_publishes_when_output_storage_is_disabled() {
        let client = StubClient::new();
        let mut publisher = publisher(StubReads::new(), client.clone());
        publisher.output_store = None;
        publisher
            .publish_signature(&bidirectional_action(vec![0, 255, 0]))
            .await
            .unwrap();
        assert_eq!(client.submissions(), 1);
    }

    #[tokio::test]
    async fn only_final_responses_store_the_exact_output() {
        let store = Arc::new(StubOutputStore::default());
        let mut publisher = publisher(StubReads::new(), StubClient::new());
        publisher.output_store = Some(store.clone());
        publisher
            .publish_signature(&respond_action())
            .await
            .unwrap();
        assert!(store.outputs.lock().unwrap().is_empty());
        for output in [vec![], vec![0, 255, 0], vec![0xde, 0xad, 0xbe, 0xef, 1]] {
            publisher
                .publish_signature(&bidirectional_action(output.clone()))
                .await
                .unwrap();
            assert_eq!(
                store.outputs.lock().unwrap().pop(),
                Some((REQUEST_ID, output))
            );
        }
    }

    #[tokio::test]
    async fn storage_finishes_before_chain_reads_without_holding_the_wallet_lock() {
        #[derive(Default)]
        struct BlockingStore {
            entered: tokio::sync::Notify,
            release: tokio::sync::Notify,
        }
        #[async_trait]
        impl OutputStore for BlockingStore {
            async fn ensure_output(&self, _: &[u8; 32], _: &[u8]) -> anyhow::Result<()> {
                self.entered.notify_one();
                self.release.notified().await;
                Ok(())
            }
        }
        let store = Arc::new(BlockingStore::default());
        let reads = StubReads::new();
        let client = StubClient::new();
        let mut publisher = publisher(reads.clone(), client.clone());
        publisher.output_store = Some(store.clone());
        let publisher = Arc::new(publisher);
        let task_publisher = publisher.clone();
        let task = tokio::spawn(async move {
            task_publisher
                .publish_signature(&bidirectional_action(vec![1]))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), store.entered.notified())
            .await
            .unwrap();
        assert!(reads.reads().is_empty());
        assert!(client.built().is_empty());
        tokio::time::timeout(
            Duration::from_secs(1),
            publisher.publish_signature(&respond_action()),
        )
        .await
        .unwrap()
        .unwrap();
        store.release.notify_one();
        task.await.unwrap().unwrap();
        assert_eq!(client.submissions(), 2);
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
    async fn publish_signature_reads_contract_and_ledger_state_at_one_finalized_hash() {
        // The stub serves a different head on every ask, so a per-read taker would
        // spread the two reads across blocks.
        let reads = StubReads::new();
        let client = StubClient::new();
        let publisher = publisher(reads.clone(), client.clone());

        publisher
            .publish_signature(&respond_action())
            .await
            .expect("the stub client grants and accepts");

        let at_hashes: Vec<String> = reads
            .reads()
            .into_iter()
            .filter(|read| read.method != "finalized_head")
            .map(|read| read.at_hash)
            .collect();
        assert_eq!(
            at_hashes,
            vec![HEAD_ONE.to_string(); 2],
            "both reads must pin the first head, and there must be exactly two"
        );
        assert_eq!(
            reads
                .reads()
                .iter()
                .filter(|read| read.method == "finalized_head")
                .count(),
            1,
            "the head is taken once per publish"
        );
        assert_eq!(client.submissions(), 1);
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

    #[tokio::test]
    async fn a_lost_submit_reply_is_a_retryable_error_and_the_retry_posts_again() {
        for action in [respond_action(), bidirectional_action(vec![0xab; 32])] {
            let client = Arc::new(LandingWithoutReply {
                attempts: std::sync::atomic::AtomicUsize::new(0),
            });
            let publisher = publisher(StubReads::new(), client.clone());

            for expected_attempts in 1..=2 {
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
                    "an ambiguous submit remains retryable: {error:#}"
                );
                assert!(
                    format!("{error:#}")
                        .contains("a later publisher retry may post the response again"),
                    "the error must disclose the duplicate-post policy: {error:#}"
                );
                assert_eq!(
                    client.attempts.load(std::sync::atomic::Ordering::SeqCst),
                    expected_attempts,
                    "each publish attempt submits exactly once"
                );
            }
            assert_eq!(
                client.attempts.load(std::sync::atomic::Ordering::SeqCst),
                2,
                "the retry must repost when settlement is handled by the backlog"
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

    #[tokio::test]
    async fn the_build_request_is_marshalled_from_the_pinned_reads_and_the_action() {
        // The publisher package pins the same wire from its own TypeScript input, so
        // only this side can see a field filled from the wrong read or a transposed
        // coordinate. The JSON encoding of the request is pinned in `intent_gen`.
        let client = StubClient::new();
        let reads = StubReads::new();
        let publisher = publisher(reads.clone(), client.clone());

        let action = respond_action();
        let before = current_unix_timestamp();
        publisher.publish_signature(&action).await.expect("granted");
        let after = current_unix_timestamp();

        let [request] = client.built().try_into().expect("one build per publish");
        assert_eq!(request.circuit, RESPOND);
        assert_eq!(request.contract_address, CENTRAL);
        assert_eq!(reads.contract_addresses(), [CENTRAL]);
        assert_eq!(request.request_id, hex::encode(REQUEST_ID));
        assert_eq!(request.contract_state, hex::encode(CONTRACT_STATE));
        assert_eq!(request.ledger_parameters, hex::encode(LEDGER_PARAMETERS));

        // Against the action's own signature, so a swapped x and y is caught.
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
            }
        );

        let ttl = request.ttl_seconds;
        let budget = config().request_timeout.as_secs() + config().submit_timeout.as_secs();
        assert!(
            (before.saturating_add(budget)..=after.saturating_add(budget)).contains(&ttl),
            "the ttl {ttl} is the two-budget sum {budget} from a time in {before}..={after}"
        );
    }

    #[tokio::test]
    async fn a_bidirectional_action_names_the_other_circuit_on_the_same_request() {
        // Output storage does not change the signature-only circuit arguments.
        let client = StubClient::new();
        let publisher = publisher(StubReads::new(), client.clone());

        publisher
            .publish_signature(&bidirectional_action(vec![0xab; 32]))
            .await
            .expect("granted");

        let [request] = client.built().try_into().expect("one build per publish");
        assert_eq!(request.circuit, RESPOND_BIDIRECTIONAL);
        assert_eq!(request.contract_address, CENTRAL);
        assert_eq!(request.request_id, hex::encode(REQUEST_ID));
    }
}
