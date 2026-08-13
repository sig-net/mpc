//! Midnight publisher: a finished MPC signature becomes a respond call on the central
//! singleton. The intent's bytes are opaque here; nothing in this crate names a ledger
//! type, and drift in their shape is caught by the child's own submit-side decode and
//! the wire tests its package pins from the TypeScript side. The two seams are traits
//! because the things behind them cannot exist in a unit test: [`PinnedReads`] hides
//! `MidnightRpc`, which needs a running node, and [`IntentSubmitter`] hides the ledger
//! transaction, which needs a wallet and a proving run.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use midnight_onchain_state::state::StateValue;
use mpc_chain_integration_core::{ChainPublisher, PublishAction, PublisherTelemetry};
use mpc_primitives::{Chain, SignKind, Signature};
use tokio_util::sync::CancellationToken;

use crate::config::PublisherConfig;
use crate::indexer::unix_now;
use crate::intent_gen::{
    is_ambiguous_submit, AmbiguousSubmit, IntentGen, IntentRequest, WirePoint, WireSignature,
};
use crate::reader::{
    decode_response_entry, CENTRAL_LEDGER_FIELDS, RESPOND_BIDIRECTIONAL_MAP_FIELD,
    RESPOND_MAP_FIELD,
};
use crate::rpc::MidnightRpc;
use crate::state::decode_contract_state;

/// The deployed entry point for a phase-1 signature response.
const RESPOND: &str = "respond";
/// The deployed entry point for a phase-2 signature response.
const RESPOND_BIDIRECTIONAL: &str = "respondBidirectional";
const RECONCILE_POLL: Duration = Duration::from_secs(2);

/// The reads the respond path pins. A trait because `MidnightRpc` cannot be built
/// without a node: its `OnlineClient` fetches metadata at construction.
#[async_trait]
pub(crate) trait PinnedReads: Send + Sync {
    /// The node's current finalized head, `0x` prefixed.
    async fn finalized_head(&self) -> anyhow::Result<String>;
    /// `None` when no contract lives at `address_64hex` at that block.
    async fn contract_state(
        &self,
        address_64hex: &str,
        at_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    async fn ledger_parameters(&self, at_hash_0x: &str) -> anyhow::Result<Vec<u8>>;
}

#[async_trait]
impl PinnedReads for MidnightRpc {
    async fn finalized_head(&self) -> anyhow::Result<String> {
        MidnightRpc::finalized_head_0x(self).await
    }

    async fn contract_state(
        &self,
        address_64hex: &str,
        at_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        // The two surfaces disagree about `0x`; both are decoded to bytes inside
        // `rpc.rs`, so nothing above it may reintroduce the distinction.
        MidnightRpc::contract_state(self, address_64hex, at_hash_0x).await
    }

    async fn ledger_parameters(&self, at_hash_0x: &str) -> anyhow::Result<Vec<u8>> {
        MidnightRpc::ledger_parameters(self, at_hash_0x).await
    }
}

/// What one finalized hash yielded. One hash for every read is the whole point: fees
/// drift per block, so parameters priced at one block against a state read at another
/// produce an intent the node answers `OutOfGas`.
pub(crate) struct PinnedState {
    pub at_hash: String,
    pub contract_state: Vec<u8>,
    pub ledger_parameters: Vec<u8>,
}

/// What turns the builder's intent into a transaction the node has accepted. Takes the
/// bytes the builder wrote: re-serializing a decoded intent would stake the transaction
/// on a round trip nothing checks. The returned string names the transaction, opaque here.
#[async_trait]
pub(crate) trait IntentSubmitter: Send + Sync {
    async fn submit(&self, intent: &[u8], cancel: &CancellationToken) -> anyhow::Result<String>;
}

#[async_trait]
impl IntentSubmitter for IntentGen {
    async fn submit(&self, intent: &[u8], cancel: &CancellationToken) -> anyhow::Result<String> {
        IntentGen::submit(self, intent, cancel).await
    }
}

/// One respond call, marshalled off the action before anything is read or spawned.
struct RespondCall {
    circuit: &'static str,
    request_id: String,
    signature: WireSignature,
    stored_signature: Signature,
}

/// Posts MPC responses back to the Midnight central contract.
pub struct MidnightPublisher {
    config: PublisherConfig,
    reads: Arc<dyn PinnedReads>,
    intent_gen: Arc<IntentGen>,
    submitter: Arc<dyn IntentSubmitter>,
    /// Config-sourced: Midnight requests carry no per-request chain context.
    central_address: String,
    telemetry: Arc<dyn PublisherTelemetry>,
    /// The node's shutdown token, so a build in flight stops with the node.
    cancel: CancellationToken,
    /// One funding wallet and one DUST UTXO mean build-to-submit is one serial flow.
    flow: tokio::sync::Mutex<()>,
}

impl MidnightPublisher {
    pub fn new(
        config: &PublisherConfig,
        central_address: String,
        rpc: Arc<MidnightRpc>,
        intent_gen: Arc<IntentGen>,
        telemetry: Arc<dyn PublisherTelemetry>,
        cancel: CancellationToken,
    ) -> Self {
        Self::assemble(
            config,
            central_address,
            rpc,
            intent_gen.clone(),
            intent_gen,
            telemetry,
            cancel,
        )
    }

    fn assemble(
        config: &PublisherConfig,
        central_address: String,
        reads: Arc<dyn PinnedReads>,
        intent_gen: Arc<IntentGen>,
        submitter: Arc<dyn IntentSubmitter>,
        telemetry: Arc<dyn PublisherTelemetry>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            config: config.clone(),
            central_address,
            reads,
            intent_gen,
            submitter,
            telemetry,
            cancel,
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

    async fn publish_inner(&self, action: &PublishAction) -> anyhow::Result<()> {
        let call = respond_call(action)?;
        let _flow = tokio::select! {
            guard = self.flow.lock() => guard,
            _ = self.cancel.cancelled() => anyhow::bail!("midnight publish cancelled while queued"),
        };
        let sign_id = action.request.id;
        tracing::info!(
            ?sign_id,
            circuit = call.circuit,
            central = %self.central_address,
            "midnight: publishing signature"
        );

        // One head for every read below it.
        let at_hash = self.reads.finalized_head().await?;
        let chain = self.pin(&self.central_address, at_hash).await?;
        if response_present(&chain.contract_state, &call)? {
            tracing::info!(
                ?sign_id,
                circuit = call.circuit,
                at_hash = %chain.at_hash,
                "midnight: exact response is already finalized"
            );
            self.telemetry.record_publish_metrics(action);
            return Ok(());
        }

        let expires_at = ttl_seconds(&self.config, unix_now()?);
        let request = IntentRequest {
            circuit: call.circuit,
            contract_address: self.central_address.clone(),
            request_id: call.request_id.clone(),
            signature: call.signature.clone(),
            contract_state: hex::encode(&chain.contract_state),
            ledger_parameters: hex::encode(&chain.ledger_parameters),
            ttl_seconds: expires_at,
        };
        let bytes = self.intent_gen.build(&request, &self.cancel).await?;

        let backstop = submit_backstop(&self.config);
        let submitted = tokio::time::timeout(backstop, async {
            self.submitter
                .submit(&bytes, &self.cancel)
                .await
                .with_context(|| {
                    format!(
                        "submitting the midnight respond intent built over the chain at {}",
                        chain.at_hash
                    )
                })
        })
        .await;
        let receipt = match submitted {
            Ok(Ok(receipt)) => receipt,
            Ok(Err(error)) if is_ambiguous_submit(&error) => {
                self.reconcile_ambiguous(&call, expires_at, error).await?;
                "reconciled-finalized-state".to_string()
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                let error = anyhow::anyhow!(
                "the midnight submit step ran past its {backstop:?} backstop without returning: \
                 it is not enforcing the {:?} submit_timeout it was given",
                self.config.submit_timeout
                )
                .context(AmbiguousSubmit);
                self.reconcile_ambiguous(&call, expires_at, error).await?;
                "reconciled-finalized-state".to_string()
            }
        };

        tracing::info!(
            ?sign_id,
            circuit = call.circuit,
            at_hash = %chain.at_hash,
            receipt = %receipt,
            elapsed = ?action.timestamp.elapsed(),
            "midnight: published respond successfully"
        );
        self.telemetry.record_publish_metrics(action);
        Ok(())
    }

    async fn reconcile_ambiguous(
        &self,
        call: &RespondCall,
        expires_at: u64,
        original: anyhow::Error,
    ) -> anyhow::Result<()> {
        loop {
            match self.finalized_response_present(call).await {
                Ok(Some(at_hash)) => {
                    tracing::warn!(
                        circuit = call.circuit,
                        request_id = %call.request_id,
                        %at_hash,
                        "midnight submit answer was lost, but the exact response is finalized"
                    );
                    return Ok(());
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    circuit = call.circuit,
                    request_id = %call.request_id,
                    "midnight reconciliation read failed: {error:#}"
                ),
            }

            let now = unix_now()?;
            if now >= expires_at {
                return Err(original.context(format!(
                    "the exact response was absent from finalized state through intent expiry \
                     at unix second {expires_at}"
                )));
            }
            let wait = RECONCILE_POLL.min(Duration::from_secs(expires_at - now));
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    return Err(original.context("midnight reconciliation cancelled"));
                }
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }

    async fn finalized_response_present(
        &self,
        call: &RespondCall,
    ) -> anyhow::Result<Option<String>> {
        let at_hash = self.reads.finalized_head().await?;
        let state = self
            .reads
            .contract_state(&self.central_address, &at_hash)
            .await?
            .with_context(|| {
                format!(
                    "midnight central contract {} is not present at {at_hash}",
                    self.central_address
                )
            })?;
        response_present(&state, call).map(|present| present.then_some(at_hash))
    }
}

#[async_trait]
impl ChainPublisher for MidnightPublisher {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        self.publish_inner(action).await
    }

    fn should_retry(&self, _error: &anyhow::Error) -> bool {
        true
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
    let request_id = hex::encode(action.request.id.request_id);

    match &action.request.kind {
        SignKind::SignBidirectional(event) => {
            anyhow::ensure!(
                event.chain == Chain::Midnight,
                "midnight publisher was handed a request routed to it carrying a {:?} event",
                event.chain
            );
            Ok(RespondCall {
                circuit: RESPOND,
                request_id,
                signature,
                stored_signature,
            })
        }
        // The output never travels: the contract stores a bare signature, and the
        // attestation already commits to the output.
        SignKind::RespondBidirectional(_) => Ok(RespondCall {
            circuit: RESPOND_BIDIRECTIONAL,
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
    // The circuit's field is one bit wide.
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
    let StateValue::Array(fields) = &root else {
        anyhow::bail!("midnight singleton state root is not an array")
    };
    anyhow::ensure!(
        fields.len() == CENTRAL_LEDGER_FIELDS,
        "midnight singleton state has {} ledger fields, expected {CENTRAL_LEDGER_FIELDS}",
        fields.len()
    );
    let field = match call.circuit {
        RESPOND => usize::from(RESPOND_MAP_FIELD),
        RESPOND_BIDIRECTIONAL => usize::from(RESPOND_BIDIRECTIONAL_MAP_FIELD),
        circuit => anyhow::bail!("midnight publisher has no response map for {circuit}"),
    };
    let map = fields
        .iter_deref()
        .nth(field)
        .context("midnight singleton response map is absent")?;
    let StateValue::Map(entries) = map else {
        anyhow::bail!("midnight singleton ledger field {field} is not a response map")
    };
    let request_id: [u8; 32] = hex::decode(&call.request_id)
        .context("midnight response request id is not hex")?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!(
                "midnight response request id is {} bytes, expected 32",
                bytes.len()
            )
        })?;
    for entry in entries.iter() {
        let (key, value) = &*entry;
        match decode_response_entry(key, value) {
            Ok((stored_request_id, stored_signature))
                if stored_request_id == request_id && stored_signature == call.stored_signature =>
            {
                return Ok(true);
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(
                circuit = call.circuit,
                request_id = %call.request_id,
                "midnight finalized response entry ignored: {err:#}"
            ),
        }
    }
    Ok(false)
}

/// The intent's expiry, as the absolute unix seconds the child wants: the sum of the
/// two budgets a publish spends, past which this publish has already given up.
fn ttl_seconds(config: &PublisherConfig, now: u64) -> u64 {
    now.saturating_add(config.request_timeout.as_secs())
        .saturating_add(config.submit_timeout.as_secs())
}

/// The outer bound on the submit step, behind the `submit_timeout` the step itself
/// enforces. A fire has two candidate causes: a step that forgot its own deadline, or
/// a submit stuck behind concurrent publishes on the builder's one lock. Deliberately
/// looser than the budget it backs, or which one fired would be a race; the headroom
/// is one build budget, for the respawn of a dead child. A fire abandons the wait,
/// never the transaction, so the result is reconciled against finalized state through
/// the intent's expiry before a caller may retry.
fn submit_backstop(config: &PublisherConfig) -> Duration {
    config.submit_timeout.saturating_add(config.request_timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::Mutex;

    use midnight_base_crypto::fab::{
        AlignedValue, Alignment, AlignmentAtom, AlignmentSegment, Value, ValueAtom,
    };
    use midnight_onchain_state::state::{ChargedState, ContractState};
    use midnight_storage::DefaultDB;
    use mpc_chain_integration_core::utils::retry::RetryConfig;
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

    fn funding_seed() -> String {
        "0f".repeat(32)
    }

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

    /// Records what it was asked to submit: counting is the only mark a proving run
    /// leaves.
    #[derive(Default)]
    struct StubSubmitter {
        submitted: std::sync::atomic::AtomicUsize,
        /// Held before answering, so a test can drive the caller's deadline.
        delay: Duration,
        /// What it refuses with, standing in for the child's own verdict.
        failure: Option<&'static str>,
        /// Whether the handed token was ever cancelled: a fresh token instead of the
        /// node's own keeps proving through a shutdown.
        saw_cancelled_token: std::sync::atomic::AtomicBool,
        /// Signalled on entry, so a test can cancel while the step certainly runs.
        entered: tokio::sync::Notify,
    }

    impl StubSubmitter {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn slow() -> Arc<Self> {
            Arc::new(Self {
                delay: Duration::from_secs(300),
                ..Default::default()
            })
        }

        fn refusing(failure: &'static str) -> Arc<Self> {
            Arc::new(Self {
                failure: Some(failure),
                ..Default::default()
            })
        }

        fn submissions(&self) -> usize {
            self.submitted.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn saw_cancelled_token(&self) -> bool {
            self.saw_cancelled_token
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl IntentSubmitter for StubSubmitter {
        async fn submit(
            &self,
            intent: &[u8],
            cancel: &CancellationToken,
        ) -> anyhow::Result<String> {
            self.entered.notify_one();
            tokio::select! {
                _ = cancel.cancelled() => {
                    self.saw_cancelled_token
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    anyhow::bail!("stub submit cancelled");
                }
                _ = tokio::time::sleep(self.delay) => {}
            }
            // The bytes have to be the builder's own: whatever is proved and paid for is this.
            assert_eq!(
                hex::encode(intent),
                GRANTED_INTENT_HEX,
                "the submitter must be handed the bytes the builder wrote"
            );
            if let Some(failure) = self.failure {
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
        attempts: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl IntentSubmitter for LandingWithoutReply {
        async fn submit(
            &self,
            _intent: &[u8],
            _cancel: &CancellationToken,
        ) -> anyhow::Result<String> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.reads.set_state(self.landed_state.clone());
            Err(anyhow::anyhow!("stdout closed after submit").context(AmbiguousSubmit))
        }
    }

    #[derive(Default)]
    struct BlockingSubmitter {
        attempts: std::sync::atomic::AtomicUsize,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait]
    impl IntentSubmitter for BlockingSubmitter {
        async fn submit(
            &self,
            _intent: &[u8],
            _cancel: &CancellationToken,
        ) -> anyhow::Result<String> {
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

    /// Catches the stub child's request line, for asserting on the marshalling.
    struct Recorder(PathBuf);

    impl Recorder {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mpc-midnight-publisher-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }

        fn request(&self) -> serde_json::Value {
            let line = std::fs::read_to_string(&self.0).expect("the stub recorded its request");
            serde_json::from_str(&line).expect("the recorded request is JSON")
        }
    }

    impl Drop for Recorder {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// The submitter asserting it received exactly these bytes is the pass-through property.
    const GRANTED_INTENT_HEX: &str = "deadbeef";

    /// A stub child granting every request with `GRANTED_INTENT_HEX`, echoing the asked id.
    fn granting_child(recorder: &Recorder) -> Vec<String> {
        script(&format!(
            r#"while read -r line; do printf '%s' "$line" > {}; id=$(printf "%s" "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p'); printf '{{"id":%s,"ok":true,"intent":"{}"}}\n' "$id"; done"#,
            recorder.0.display(),
            GRANTED_INTENT_HEX,
        ))
    }

    /// A stub child that refuses, the way a managed dir pointed at the wrong build refuses.
    fn refusing_child() -> Vec<String> {
        script(
            r#"read -r line; printf '{"id":0,"ok":false,"code":"contract_mismatch","message":"exposes no operation"}\n'"#,
        )
    }

    fn script(body: &str) -> Vec<String> {
        vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                r#"read -r ready; ready_id=$(printf "%s" "$ready" | sed -n 's/.*"id":\([0-9]*\).*/\1/p'); printf '{{"id":%s,"ok":true,"ready":true,"submitTimeoutMs":2,"recipeTtlMs":1}}\n' "$ready_id"; {body}"#
            ),
        ]
    }

    /// Every field pinned, none inherited: a test reading a default would test the default.
    fn config(intent_gen_command: Vec<String>) -> PublisherConfig {
        PublisherConfig {
            intent_gen_command,
            funding_seed: funding_seed(),
            node_ws_url: "ws://127.0.0.1:9944".to_string(),
            proof_server_url: "http://127.0.0.1:6300".to_string(),
            indexer_url: "http://127.0.0.1:8088/api/v3/graphql".to_string(),
            indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".to_string(),
            request_timeout: Duration::from_secs(5),
            submit_timeout: Duration::from_secs(30),
            restart_backoff: RetryConfig {
                min_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(5),
                max_times: 1,
                jitter: false,
            },
        }
    }

    async fn publisher(
        config: &PublisherConfig,
        reads: Arc<dyn PinnedReads>,
        submitter: Arc<dyn IntentSubmitter>,
    ) -> MidnightPublisher {
        publisher_with_cancel(config, reads, submitter, CancellationToken::new()).await
    }

    async fn publisher_with_cancel(
        config: &PublisherConfig,
        reads: Arc<dyn PinnedReads>,
        submitter: Arc<dyn IntentSubmitter>,
        cancel: CancellationToken,
    ) -> MidnightPublisher {
        let intent_gen = IntentGen::spawn(config, "undeployed")
            .await
            .expect("the stub child spawns");
        MidnightPublisher::assemble(
            config,
            CENTRAL.to_string(),
            reads,
            Arc::new(intent_gen),
            submitter,
            Arc::new(NoopPublisherTelemetry),
            cancel,
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
        let field = match call.circuit {
            RESPOND => usize::from(RESPOND_MAP_FIELD),
            RESPOND_BIDIRECTIONAL => usize::from(RESPOND_BIDIRECTIONAL_MAP_FIELD),
            _ => unreachable!(),
        };
        let mut contract: ContractState<DefaultDB> =
            midnight_serialize::tagged_deserialize(&mut &CONTRACT_STATE[..])
                .expect("the initial singleton state decodes");
        let StateValue::Array(fields) = contract.data.get_ref() else {
            panic!("the initial singleton root is an array")
        };
        let mut fields: Vec<_> = fields.iter_deref().cloned().collect();
        let request_id: [u8; 32] = hex::decode(&call.request_id)
            .expect("the call request id is hex")
            .try_into()
            .expect("the call request id is 32 bytes");
        let key = AlignedValue {
            value: Value(vec![ValueAtom(vec![1]), ValueAtom(trim(&request_id))]),
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
        let field = match call.circuit {
            RESPOND => usize::from(RESPOND_MAP_FIELD),
            RESPOND_BIDIRECTIONAL => usize::from(RESPOND_BIDIRECTIONAL_MAP_FIELD),
            _ => unreachable!(),
        };
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
            cell_from_atoms(&[vec![1], vec![2], vec![3]], &[1, 1, 1]),
        )]);
        contract.data = ChargedState::new(array_of(fields));

        let mut encoded = Vec::new();
        midnight_serialize::tagged_serialize(&contract, &mut encoded)
            .expect("the malformed singleton state serializes");
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
            let submitter = StubSubmitter::new();
            let recorder = Recorder::new("rejected-action");
            let config = config(granting_child(&recorder));
            let publisher = publisher(&config, reads.clone(), submitter.clone()).await;

            let err = publisher
                .publish_signature(&action)
                .await
                .expect_err("neither circuit answers this action");
            assert!(format!("{err:#}").contains(named), "got: {err:#}");
            assert!(reads.reads().is_empty(), "a refused action read the node");
            assert_eq!(submitter.submissions(), 0);
        }
    }

    #[tokio::test]
    async fn publish_signature_reads_contract_and_ledger_state_at_one_finalized_hash() {
        // The stub serves a different head on every ask, so a per-read taker would
        // spread the two reads across blocks.
        let reads = StubReads::new();
        let submitter = StubSubmitter::new();
        let recorder = Recorder::new("one-hash");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, reads.clone(), submitter.clone()).await;

        publisher
            .publish_signature(&respond_action())
            .await
            .expect("the stub child grants and the stub submitter accepts");

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
        assert_eq!(submitter.submissions(), 1);
    }

    #[tokio::test]
    async fn a_rejected_intent_fails_the_publish_without_spending_a_proof() {
        // Proving is the one expensive step, and a refusal means no intent was built.
        let reads = StubReads::new();
        let submitter = StubSubmitter::new();
        let config = config(refusing_child());
        let publisher = publisher(&config, reads.clone(), submitter.clone()).await;

        let err = publisher
            .publish_signature(&respond_action())
            .await
            .expect_err("a refused request cannot be published");
        assert!(
            format!("{err:#}").contains("contract_mismatch"),
            "the child's code has to survive to the caller: {err:#}"
        );
        assert!(
            submitter.submissions() == 0,
            "a refused intent reached the prover"
        );
    }

    #[tokio::test]
    async fn an_exact_finalized_response_is_not_posted_again() {
        let action = respond_action();
        let reads = StubReads::with_state(state_with_response(&action));
        let submitter = StubSubmitter::new();
        let recorder = Recorder::new("duplicate");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, reads.clone(), submitter.clone()).await;

        publisher
            .publish_signature(&action)
            .await
            .expect("a finalized exact response makes the retry complete");
        assert_eq!(submitter.submissions(), 0);
    }

    #[test]
    fn a_malformed_response_entry_does_not_poison_reconciliation() {
        for action in [respond_action(), bidirectional_action(vec![0xab; 32])] {
            let call = respond_call(&action).expect("the action maps to a response");
            let state = state_with_malformed_response(&action);
            assert!(
                !response_present(&state, &call).expect("a malformed individual entry is skipped"),
                "the malformed entry is not an exact finalized response"
            );
        }
    }

    #[tokio::test]
    async fn a_different_signature_under_the_same_request_id_is_still_posted() {
        let action = respond_action();
        let mut other = action.clone();
        other.signature.recovery_id ^= 1;
        let reads = StubReads::with_state(state_with_response(&other));
        let submitter = StubSubmitter::new();
        let recorder = Recorder::new("same-id-different-signature");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, reads, submitter.clone()).await;

        publisher
            .publish_signature(&action)
            .await
            .expect("only the exact signature makes a retry complete");
        assert_eq!(submitter.submissions(), 1);
    }

    #[tokio::test]
    async fn a_landed_submit_with_a_lost_reply_is_reconciled_without_reposting() {
        for action in [respond_action(), bidirectional_action(vec![0xab; 32])] {
            let reads = StubReads::new();
            let submitter = Arc::new(LandingWithoutReply {
                reads: reads.clone(),
                landed_state: state_with_response(&action),
                attempts: std::sync::atomic::AtomicUsize::new(0),
            });
            let recorder = Recorder::new("lost-reply");
            let config = config(granting_child(&recorder));
            let publisher = publisher(&config, reads, submitter.clone()).await;

            publisher
                .publish_signature(&action)
                .await
                .expect("the finalized exact response resolves the ambiguous submit");

            assert_eq!(
                submitter.attempts.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "an ambiguous landed submit must not be posted twice"
            );
        }
    }

    #[tokio::test]
    async fn concurrent_publishes_serialize_before_the_first_pinned_read() {
        let reads = StubReads::new();
        let submitter = Arc::new(BlockingSubmitter::default());
        let recorder = Recorder::new("whole-flow-lock");
        let config = config(granting_child(&recorder));
        let publisher = Arc::new(publisher(&config, reads.clone(), submitter.clone()).await);
        let first_entered = submitter.entered.notified();

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

        submitter.release.notify_one();
        first
            .await
            .expect("the first task returns")
            .expect("the first publish succeeds");
        second
            .await
            .expect("the second task returns")
            .expect("the second publish succeeds");
        assert_eq!(
            submitter.attempts.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
    }

    #[tokio::test]
    async fn a_submit_that_fails_must_not_be_reported_as_a_published_signature() {
        // An `Ok` here settles the signature as answered and nothing retries it.
        let submitter = StubSubmitter::refusing("no spendable dust");
        let recorder = Recorder::new("failing-submit");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, StubReads::new(), submitter.clone()).await;

        let err = publisher
            .publish_signature(&respond_action())
            .await
            .expect_err("a post that never landed is not a published signature");
        assert!(
            format!("{err:#}").contains("no spendable dust"),
            "got: {err:#}"
        );
        assert_eq!(submitter.submissions(), 0);
    }

    #[tokio::test]
    async fn the_submit_step_is_handed_the_node_s_own_shutdown_token() {
        // A step handed a fresh token instead of the node's own is indistinguishable in
        // every other observation and keeps proving straight through a shutdown.
        let cancel = CancellationToken::new();
        let submitter = StubSubmitter::slow();
        let recorder = Recorder::new("shutdown-token");
        let config = config(granting_child(&recorder));
        let publisher = Arc::new(
            publisher_with_cancel(&config, StubReads::new(), submitter.clone(), cancel.clone())
                .await,
        );

        let publishing = tokio::spawn({
            let publisher = publisher.clone();
            async move { publisher.publish_signature(&respond_action()).await }
        });
        submitter.entered.notified().await;
        cancel.cancel();

        let err = publishing
            .await
            .expect("the publish task is not lost")
            .expect_err("a cancelled submit cannot report success");
        assert!(format!("{err:#}").contains("cancelled"), "got: {err:#}");
        assert!(
            submitter.saw_cancelled_token(),
            "the step was handed a token that shutdown never reaches"
        );
    }

    #[tokio::test]
    async fn a_submit_step_that_never_returns_does_not_hold_the_publisher_task() {
        // The step is expected to enforce its own budget, and this is what happens when
        // it does not: the publish ends and says which fault it is.
        let mut config = config(granting_child(&Recorder::new("submit-backstop")));
        config.submit_timeout = Duration::from_millis(20);
        config.request_timeout = Duration::from_millis(30);

        // A backstop equal to `submit_timeout` would turn an ordinary slow submit
        // into a race between two different error messages.
        let backstop = submit_backstop(&config);
        assert!(
            backstop > config.submit_timeout,
            "the backstop must never fire before the budget it backs: {backstop:?} vs {:?}",
            config.submit_timeout
        );
        assert_eq!(backstop, config.submit_timeout + config.request_timeout);

        let publisher = publisher(&config, StubReads::new(), StubSubmitter::slow()).await;

        let started = std::time::Instant::now();
        let err = publisher
            .publish_signature(&respond_action())
            .await
            .expect_err("a submit that never returns must not hold the task");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("backstop"), "got: {rendered}");
        assert!(
            rendered.contains("not enforcing"),
            "the message has to name which of the two faults this is: {rendered}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "waited past the 70ms backstop this config sets"
        );
    }

    #[tokio::test]
    async fn a_central_contract_absent_at_the_pinned_hash_fails_the_publish() {
        // A wrong central address or a node that cannot reach the block: either way
        // there is nothing to prove against.
        let recorder = Recorder::new("absent");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, StubReads::absent(), StubSubmitter::new()).await;

        let err = publisher
            .publish_signature(&respond_action())
            .await
            .expect_err("an absent contract has no respond operation");
        assert!(format!("{err:#}").contains("not present"), "got: {err:#}");
    }

    #[tokio::test]
    async fn the_request_is_the_shape_the_child_validates() {
        // The only place the marshalling is observable: the publisher package pins the
        // same wire from its own TypeScript input, so it cannot see a transposed field.
        let recorder = Recorder::new("wire-shape");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, StubReads::new(), StubSubmitter::new()).await;

        let action = respond_action();
        publisher.publish_signature(&action).await.expect("granted");

        let request = recorder.request();
        assert_eq!(request["circuit"], RESPOND);
        assert_eq!(request["contractAddress"], CENTRAL);
        assert_eq!(request["requestId"], hex::encode(REQUEST_ID));
        assert_eq!(request["contractState"], hex::encode(CONTRACT_STATE));
        assert_eq!(request["ledgerParameters"], hex::encode(LEDGER_PARAMETERS));
        assert!(
            request.get("serializedOutput").is_none() && request.get("outputLen").is_none(),
            "the unidirectional circuit carries no output fields: {request}"
        );

        // Against the action's own signature, so a swapped x and y is caught.
        let encoded = action.signature.big_r.to_encoded_point(false);
        assert_eq!(
            request["signature"],
            serde_json::json!({
                "bigR": {
                    "x": hex::encode(encoded.x().unwrap()),
                    "y": hex::encode(encoded.y().unwrap()),
                },
                "s": hex::encode(action.signature.s.to_bytes()),
                "recoveryId": action.signature.recovery_id,
            })
        );

        let ttl = request["ttlSeconds"].as_u64().expect("ttl is an integer");
        let now = unix_now().unwrap();
        assert_eq!(
            ttl.saturating_sub(now),
            config.request_timeout.as_secs() + config.submit_timeout.as_secs(),
            "the ttl is the sum of the two budgets a publish spends, from now"
        );
    }

    #[tokio::test]
    async fn the_bidirectional_circuit_is_signature_only_on_the_wire() {
        // The contract's RespondBidirectionalEvent is a bare Signature; a request
        // carrying an output is rejected by the child's union.
        let recorder = Recorder::new("bidirectional");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, StubReads::new(), StubSubmitter::new()).await;

        publisher
            .publish_signature(&bidirectional_action(vec![0xab; 32]))
            .await
            .expect("granted");

        let request = recorder.request();
        assert_eq!(request["circuit"], RESPOND_BIDIRECTIONAL);
        assert_eq!(request["contractAddress"], CENTRAL);
        assert!(
            request.get("serializedOutput").is_none() && request.get("outputLen").is_none(),
            "wire v2 carries no output fields: {request}"
        );
    }
}
