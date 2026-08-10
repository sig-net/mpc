//! Midnight publisher: a finished MPC signature becomes a respond call on the central
//! singleton. The intent's bytes are opaque here; nothing in this crate names a ledger
//! type, and drift in their shape is caught by the child's own submit-side decode and
//! the wire tests its package pins from the TypeScript side. The two seams are traits
//! because the things behind them cannot exist in a unit test: [`PinnedReads`] hides
//! `MidnightRpc`, which needs a running node, and [`IntentSubmitter`] hides the ledger
//! transaction, which needs a wallet and a proving run; see [`ChildSubmitter`] for why it is not Rust.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use midnight_node_ledger_helpers::ledger_9::{ShieldedWallet, WalletSeed};
use midnight_storage::DefaultDB;
use mpc_chain_integration_core::{ChainPublisher, PublishAction, PublisherTelemetry};
use mpc_primitives::{Chain, SignKind, Signature};
use tokio_util::sync::CancellationToken;

use crate::config::PublisherConfig;
use crate::indexer::unix_now;
use crate::intent_gen::{IntentGen, IntentRequest, WirePoint, WireSignature};
use crate::rpc::MidnightRpc;

/// The deployed entry point for a phase-1 signature response.
const RESPOND: &str = "respond";
/// The deployed entry point for a phase-2 signature response.
const RESPOND_BIDIRECTIONAL: &str = "respondBidirectional";

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
    async fn zswap_chain_state(
        &self,
        address_64hex: &str,
        at_hash_0x: &str,
    ) -> anyhow::Result<Vec<u8>>;
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

    async fn zswap_chain_state(
        &self,
        address_64hex: &str,
        at_hash_0x: &str,
    ) -> anyhow::Result<Vec<u8>> {
        MidnightRpc::zswap_chain_state(self, address_64hex, at_hash_0x).await
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
    async fn submit(
        &self,
        intent: &[u8],
        chain: &PinnedState,
        cancel: &CancellationToken,
    ) -> anyhow::Result<String>;
}

/// The same child that built the intent, asked to spend for it. Not Rust because
/// balancing spends DUST, and `DustLocalState` can only be filled by replaying ledger
/// events from genesis, which the child's indexer-synced wallet already does. The
/// same child rather than a second one because that wallet holds a single dust UTXO:
/// one child makes `IntentGen`'s own lock the thing that serializes spenders.
struct ChildSubmitter {
    intent_gen: Arc<IntentGen>,
}

#[async_trait]
impl IntentSubmitter for ChildSubmitter {
    async fn submit(
        &self,
        intent: &[u8],
        chain: &PinnedState,
        cancel: &CancellationToken,
    ) -> anyhow::Result<String> {
        self.intent_gen
            .submit(intent, cancel)
            .await
            // A submit refused for a state that moved is only actionable next to the
            // read it stopped matching.
            .with_context(|| {
                format!(
                    "submitting the midnight respond intent built over the chain at {}",
                    chain.at_hash
                )
            })
    }
}

/// One respond call, marshalled off the action before anything is read or spawned.
struct RespondCall {
    circuit: &'static str,
    request_id: String,
    signature: WireSignature,
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
    /// The funding wallet's Zswap public key, derived once at construction.
    coin_public_key: String,
    /// The node's shutdown token, so a build in flight stops with the node.
    cancel: CancellationToken,
}

impl MidnightPublisher {
    /// Fallible because the funding seed is decoded here: an unusable seed is a
    /// startup fault, not the first signature's.
    pub fn new(
        config: &PublisherConfig,
        central_address: String,
        rpc: Arc<MidnightRpc>,
        intent_gen: Arc<IntentGen>,
        telemetry: Arc<dyn PublisherTelemetry>,
        cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        Self::assemble(
            config,
            central_address,
            rpc,
            intent_gen.clone(),
            Arc::new(ChildSubmitter { intent_gen }),
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
    ) -> anyhow::Result<Self> {
        Ok(Self {
            coin_public_key: coin_public_key(&config.funding_seed)?,
            config: config.clone(),
            central_address,
            reads,
            intent_gen,
            submitter,
            telemetry,
            cancel,
        })
    }

    /// The three reads, all at `at_hash`.
    async fn pin(&self, central_address: &str, at_hash: String) -> anyhow::Result<PinnedState> {
        let contract_state = self
            .reads
            .contract_state(central_address, &at_hash)
            .await?
            .with_context(|| {
                format!("midnight central contract {central_address} is not present at {at_hash}")
            })?;
        let ledger_parameters = self.reads.ledger_parameters(&at_hash).await?;
        // Read for whether it answers, not what it says: a node that cannot serve
        // zswap state at this hash is refused before a proving run is paid for.
        self.reads
            .zswap_chain_state(central_address, &at_hash)
            .await?;
        Ok(PinnedState {
            at_hash,
            contract_state,
            ledger_parameters,
        })
    }

    async fn publish_inner(&self, action: &PublishAction) -> anyhow::Result<()> {
        let call = respond_call(action)?;
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

        let request = IntentRequest {
            circuit: call.circuit,
            contract_address: self.central_address.clone(),
            request_id: call.request_id,
            signature: call.signature,
            contract_state: hex::encode(&chain.contract_state),
            ledger_parameters: hex::encode(&chain.ledger_parameters),
            coin_public_key: self.coin_public_key.clone(),
            ttl_seconds: ttl_seconds(&self.config, unix_now()?),
        };
        let bytes = self.intent_gen.build(&request, &self.cancel).await?;

        let backstop = submit_backstop(&self.config);
        let receipt = tokio::time::timeout(
            backstop,
            self.submitter.submit(&bytes, &chain, &self.cancel),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "the midnight submit step ran past its {backstop:?} backstop without returning: \
                 either it is not enforcing the {:?} submit_timeout it was given, or the \
                 submit spent the window queued behind concurrent publishes on the one \
                 builder child; the abandoned submit may still land on chain, so the retry \
                 of this publish can append a duplicate respond and pay fees twice",
                self.config.submit_timeout
            )
        })??;

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
}

#[async_trait]
impl ChainPublisher for MidnightPublisher {
    /// Nothing here remembers a request id: both circuits are blind appends, so a
    /// duplicate publish costs a transaction and changes nothing. A dedupe cache would
    /// be worse: a publish that submits and then fails on the way back would be
    /// remembered as done, and the retry that rescues it dropped.
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        self.publish_inner(action)
            .await
            .map_err(defuse_terminal_status_tokens)
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
            })
        }
        // The output never travels: the contract stores a bare signature, and the
        // attestation already commits to the output.
        SignKind::RespondBidirectional(_) => Ok(RespondCall {
            circuit: RESPOND_BIDIRECTIONAL,
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

/// The funding wallet's Zswap public key. Contained: the helpers ship with `can-panic`
/// on, and a panic in a publisher task takes a runtime worker with it.
fn coin_public_key(funding_seed: &str) -> anyhow::Result<String> {
    let seed = WalletSeed::try_from_hex_str(funding_seed)
        .map_err(|err| anyhow::anyhow!("midnight publisher funding_seed is unusable: {err}"))?;
    let key = std::panic::catch_unwind(AssertUnwindSafe(|| {
        ShieldedWallet::<DefaultDB>::default(seed).coin_public_key
    }))
    .map_err(|_| {
        anyhow::anyhow!("deriving the midnight funding wallet's zswap public key panicked")
    })?;
    Ok(hex::encode(key.0 .0))
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
/// never the transaction, so the retry can append a duplicate respond.
fn submit_backstop(config: &PublisherConfig) -> Duration {
    config.submit_timeout.saturating_add(config.request_timeout)
}

/// The status tokens the node's retry heuristic treats as terminal
/// (`chain-integration-core/src/utils/retry.rs`). 408/429 are retryable there and
/// are deliberately not rewritten.
const TERMINAL_STATUS_TOKENS: [&str; 5] = ["400", "401", "403", "404", "405"];

/// Rewrites every standalone terminal status token in `err`'s rendered chain into a
/// digit-broken spelling (`400` becomes `4_0_0`), so no error this publisher returns
/// can end the node's retry-forever loop: everything here is operator-fixable and must
/// keep retrying while it pages.
fn defuse_terminal_status_tokens(err: anyhow::Error) -> anyhow::Error {
    let rendered = format!("{err:#}");
    let mut defused = rendered.clone();
    for token in TERMINAL_STATUS_TOKENS {
        defused = rewrite_standalone(&defused, token);
    }
    if defused == rendered {
        return err;
    }
    anyhow::anyhow!("{defused}")
}

/// `token` replaced by its digit-broken spelling wherever it appears standalone (not
/// embedded in a longer digit run), the same boundary rule the retry heuristic uses.
fn rewrite_standalone(text: &str, token: &str) -> String {
    let bytes = text.as_bytes();
    let spelling = token
        .chars()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("_");
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(pos) = text[cursor..].find(token) {
        let i = cursor + pos;
        let end = i + token.len();
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_digit();
        let after_ok = end >= bytes.len() || !bytes[end].is_ascii_digit();
        out.push_str(&text[cursor..i]);
        if before_ok && after_ok {
            out.push_str(&spelling);
        } else {
            out.push_str(token);
        }
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::Mutex;

    use mpc_chain_integration_core::utils::retry::RetryConfig;
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

    fn funding_seed() -> String {
        "0f".repeat(32)
    }

    /// Distinct per read, so a test can tell which read produced which bytes.
    const CONTRACT_STATE: &[u8] = b"contract-state";
    const LEDGER_PARAMETERS: &[u8] = b"ledger-parameters";
    const ZSWAP_CHAIN_STATE: &[u8] = b"zswap-chain-state";

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
            _address: &str,
            at_hash: &str,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            self.record("contract_state", at_hash);
            Ok(self.contract_present.then(|| CONTRACT_STATE.to_vec()))
        }

        async fn ledger_parameters(&self, at_hash: &str) -> anyhow::Result<Vec<u8>> {
            self.record("ledger_parameters", at_hash);
            Ok(LEDGER_PARAMETERS.to_vec())
        }

        async fn zswap_chain_state(
            &self,
            _address: &str,
            at_hash: &str,
        ) -> anyhow::Result<Vec<u8>> {
            self.record("zswap_chain_state", at_hash);
            Ok(ZSWAP_CHAIN_STATE.to_vec())
        }
    }

    /// Records what it was asked to submit: counting is the only mark a proving run
    /// leaves.
    #[derive(Default)]
    struct StubSubmitter {
        /// One entry per submission, naming the hash the intent was built over.
        submitted: Mutex<Vec<String>>,
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

        fn submissions(&self) -> Vec<String> {
            self.submitted.lock().unwrap().clone()
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
            chain: &PinnedState,
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
            self.submitted.lock().unwrap().push(chain.at_hash.clone());
            Ok("stub-receipt".to_string())
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
        vec!["sh".to_string(), "-c".to_string(), body.to_string()]
    }

    /// Every field pinned, none inherited: a test reading a default would test the default.
    fn config(intent_gen_command: Vec<String>) -> PublisherConfig {
        PublisherConfig {
            intent_gen_command,
            managed_dir: "/managed".to_string(),
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
        .expect("a validated funding seed derives a wallet")
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
            assert!(submitter.submissions().is_empty());
        }
    }

    #[tokio::test]
    async fn publish_signature_reads_all_three_states_at_one_finalized_hash() {
        // The stub serves a different head on every ask, so a per-read taker would
        // spread the three across two blocks.
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
            vec![HEAD_ONE.to_string(); 3],
            "all three reads must pin the FIRST head, and there must be exactly three"
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
        assert_eq!(
            submitter.submissions(),
            vec![HEAD_ONE.to_string()],
            "the submit step is handed the hash its intent was built over, not a later one"
        );
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
            submitter.submissions().is_empty(),
            "a refused intent reached the prover"
        );
    }

    #[tokio::test]
    async fn publish_signature_is_idempotent_for_a_duplicate_request_id() {
        // The count is the load-bearing half: a dedupe cache would also make this Ok
        // twice, while silently dropping the retry that rescues a failed publish.
        let reads = StubReads::new();
        let submitter = StubSubmitter::new();
        let recorder = Recorder::new("duplicate");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, reads.clone(), submitter.clone()).await;

        let action = respond_action();
        publisher
            .publish_signature(&action)
            .await
            .expect("the first publish lands");
        publisher
            .publish_signature(&action)
            .await
            .expect("a duplicate publish is an Ok, not an Err");
        assert_eq!(
            submitter.submissions().len(),
            2,
            "the second publish must be posted, not remembered as already done"
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
        assert!(submitter.submissions().is_empty());
    }

    /// The reads one publish pinned.
    fn pinned_state() -> PinnedState {
        PinnedState {
            at_hash: HEAD_ONE.to_string(),
            contract_state: CONTRACT_STATE.to_vec(),
            ledger_parameters: LEDGER_PARAMETERS.to_vec(),
        }
    }

    /// The real submitter over a stub child, as far as this seam goes without a wallet.
    async fn child_submitter(config: &PublisherConfig) -> ChildSubmitter {
        ChildSubmitter {
            intent_gen: Arc::new(
                IntentGen::spawn(config, "undeployed")
                    .await
                    .expect("the stub child spawns"),
            ),
        }
    }

    #[tokio::test]
    async fn the_submit_step_answers_with_the_transaction_id_the_child_reported() {
        // The identifier has to be the child's own rather than anything this side
        // composed.
        let tx_id = "ab".repeat(32);
        let config = config(script(&format!(
            r#"read -r line; printf '{{"id":0,"ok":true,"txId":"{tx_id}","blockHash":"{}"}}\n'"#,
            "cd".repeat(32)
        )));
        let submitter = child_submitter(&config).await;

        let receipt = submitter
            .submit(&[0xde, 0xad], &pinned_state(), &CancellationToken::new())
            .await
            .expect("the stub child posts");
        assert_eq!(receipt, tx_id);
    }

    #[tokio::test]
    async fn the_child_s_own_verdict_on_a_submit_reaches_the_publisher() {
        // A refusal like `wallet_unfunded` is the operator's to act on, not a fault
        // of the pipe.
        let config = config(script(
            r#"read -r line; printf '{"id":0,"ok":false,"code":"wallet_unfunded","message":"no spendable dust"}\n'"#,
        ));
        let submitter = child_submitter(&config).await;

        let err = submitter
            .submit(&[0xde, 0xad], &pinned_state(), &CancellationToken::new())
            .await
            .expect_err("a child that will not post cannot be answered");
        let rendered = format!("{err:#}");
        assert!(rendered.contains("wallet_unfunded"), "got: {rendered}");
        assert!(rendered.contains("no spendable dust"), "got: {rendered}");
        assert!(
            rendered.contains(HEAD_ONE),
            "a submit refused for a state that moved is only actionable next to the read \
             it stopped matching: {rendered}"
        );
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

    #[test]
    fn the_coin_public_key_is_derived_from_the_configured_seed() {
        // Transcribed from the helpers' own derivation for this seed, so a ledger-line
        // bump that moves the Zswap role's key is caught here rather than on chain.
        let key = coin_public_key(&funding_seed()).expect("a 32 byte seed derives");
        assert_eq!(
            key,
            "687a8db8e44bbd007b6baaf9004c742d1d89ee7bd8f367e6ec6b017a2cf98baf"
        );
        // The half a transcribed value cannot check on its own: that the seed is read
        // at all.
        let other = coin_public_key(&"11".repeat(32)).expect("another 32 byte seed derives");
        assert_ne!(key, other);
        assert_eq!(other.len(), 64);
    }

    #[test]
    fn an_unusable_funding_seed_fails_at_construction_rather_than_at_the_first_signature() {
        // A publisher that deferred the decode would look healthy until the first
        // request it could not answer.
        assert!(coin_public_key("").is_err());
        assert!(coin_public_key("zz".repeat(32).as_str()).is_err());
        // 17 bytes: hex-clean, and neither of the three lengths a wallet seed takes.
        assert!(coin_public_key(&"0f".repeat(17)).is_err());
    }

    fn code_spelling(code: &str) -> String {
        code.chars()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("_")
    }

    #[test]
    fn defused_errors_are_always_retryable() {
        use mpc_chain_integration_core::utils::retry::is_retryable;
        for code in ["400", "401", "403", "404", "405"] {
            let raw = anyhow::anyhow!("proof server answered {code} for this request");
            assert!(
                !is_retryable(&raw),
                "the premise: a bare {code} is terminal to the retry loop"
            );
            let defused = defuse_terminal_status_tokens(raw);
            assert!(
                is_retryable(&defused),
                "defused {code} must retry, got: {defused:#}"
            );
            assert!(
                format!("{defused:#}").contains(&code_spelling(code)),
                "the code must stay legible in the defused text"
            );
        }
    }

    #[test]
    fn defusing_leaves_ordinary_text_and_retryable_codes_alone() {
        use mpc_chain_integration_core::utils::retry::is_retryable;
        // 408/429 are retryable on purpose; ports and ids embed the digits in longer
        // runs. Neither may be rewritten.
        for text in [
            "timed out with 408 after 3 tries",
            "rate limited: 429",
            "dial 127.0.0.1:40001 refused",
            "request id 314159 not found in cache",
        ] {
            let err = anyhow::anyhow!("{text}");
            let defused = defuse_terminal_status_tokens(err);
            assert_eq!(
                format!("{defused}"),
                text,
                "text must pass through untouched"
            );
            assert!(is_retryable(&defused));
        }
    }
}
