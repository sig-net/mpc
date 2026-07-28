//! Midnight publisher: a finished MPC signature becomes a respond call on the central
//! singleton.
//!
//! The path is fixed: marshal the action into the shape the out-of-process builder
//! validates, pin one finalized hash, read the chain at it, have the builder run the
//! circuit, read what comes back as the ledger's own `Intent`, then balance, prove,
//! sign and submit it. Only the last step spends anything expensive, which is why
//! everything that can refuse the action refuses it before reaching there.
//!
//! Two seams are traits rather than direct calls, and both for the same reason: the
//! things behind them cannot exist in a unit test. [`PinnedReads`] hides `MidnightRpc`,
//! whose subxt client fetches metadata at construction and therefore needs a running
//! node. [`IntentSubmitter`] hides the ledger transaction, which needs a funding wallet
//! and a proving run; see [`ChildSubmitter`] for what fills it and why it is not Rust.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use async_trait::async_trait;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use midnight_ledger_v9::structure::{Intent, ProofPreimageMarker, Signature as LedgerSignature};
use midnight_node_ledger_helpers::ledger_9::{ShieldedWallet, WalletSeed};
use midnight_storage::DefaultDB;
use midnight_transient_crypto::commitment::PedersenRandomness;
use mpc_chain_integration_core::{ChainPublisher, PublishAction};
use mpc_primitives::{Chain, SignKind, Signature};
use tokio_util::sync::CancellationToken;

use crate::config::PublisherConfig;
use crate::convert::MidnightChainCtx;
use crate::intent_gen::{IntentGen, IntentRequest, WirePoint, WireSignature};
use crate::rpc::MidnightRpc;

/// Ledger 9's own tagged reading of what the builder wrote: `signature`, `pre-proof`
/// and `pre-binding`, the three markers the TypeScript side names when it serializes.
pub(crate) type ChainIntent =
    Intent<LedgerSignature, ProofPreimageMarker, PedersenRandomness, DefaultDB>;

/// The deployed entry point for a phase-1 signature response.
const RESPOND: &str = "respond";
/// The deployed entry point for a response carrying the call's return data.
const RESPOND_BIDIRECTIONAL: &str = "respondBidirectional";

/// The circuit's `Bytes<128>` return-data slot. The whole slot travels, zero padded,
/// because the contract stores it whole and a consumer reads `output_len` to know how
/// much of it is real.
const OUTPUT_SLOT_BYTES: usize = 128;

/// The reads the respond path pins, as one surface.
///
/// A trait because `MidnightRpc` cannot be built without a node: its `OnlineClient`
/// fetches metadata at construction. `rpc.rs` splits its own reads into `*_over`
/// functions for the same reason, but those are private to it.
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
        Ok(format!("0x{}", hex::encode(self.finalized_head().await?)))
    }

    async fn contract_state(
        &self,
        address_64hex: &str,
        at_hash_0x: &str,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        // The two surfaces disagree about `0x`: `midnight_contractState` answers with
        // bare hex and `state_call` with a prefix. Both are decoded to bytes inside
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

/// What one finalized hash yielded, carried together with the hash itself.
///
/// One hash for every read is the whole point: fees drift per block, so parameters
/// priced at one block against a state read at another produce an intent the node
/// answers `OutOfGas`. Keeping `at_hash` beside the bytes is what makes that
/// checkable rather than merely intended.
///
/// The zswap chain state is read at that hash and is not here, because nothing in this
/// process balances: see [`ChildSubmitter`] and [`MidnightPublisher::pin`].
pub(crate) struct PinnedState {
    pub at_hash: String,
    pub contract_state: Vec<u8>,
    pub ledger_parameters: Vec<u8>,
}

/// What turns the builder's intent into a transaction the node has accepted: balance
/// it against the funding wallet, prove it, sign it, submit it.
///
/// Takes the intent as the bytes the builder wrote rather than as the decoded value.
/// The decode above this is a gate, not a conversion: whoever submits forwards what
/// the builder produced, and re-serializing a decoded intent to recover those bytes
/// would stake the transaction on a round trip nothing checks.
///
/// `chain` is carried because the intent means nothing apart from the reads it was built
/// over: an implementation that balances in this process prices against them, and one
/// that hands the intent to a wallet elsewhere still needs the hash, because losing a
/// race to another writer is the one failure a submit has that nothing before it could
/// have seen. `cancel` because the step outlives a node shutdown otherwise: it is a
/// proving run, and it belongs to whoever owns the token rather than to whoever
/// implements this.
///
/// The returned string is whatever names the transaction on chain, for the log and for
/// an end-to-end test that wants to read it back. Opaque here on purpose: this side
/// neither parses it nor decides its shape.
#[async_trait]
pub(crate) trait IntentSubmitter: Send + Sync {
    async fn submit(
        &self,
        intent: &[u8],
        chain: &PinnedState,
        cancel: &CancellationToken,
    ) -> anyhow::Result<String>;
}

/// The submitter: the same child that built the intent, asked to spend for it.
///
/// **Why it is not Rust.** Balancing a ledger-9 transaction spends DUST, and the funding
/// wallet's `DustLocalState` cannot be built from chain state. `DustWallet` starts it
/// empty and `DustLocalState::replay_events` is the only thing that fills it, in strict
/// merkle index order from genesis, out of plaintext that the global commitment and
/// nullifier state does not carry. None of the three pinned reads supplies it and no
/// constructor derives it, so a Rust submitter would need a chain-replay subsystem this
/// node does not have. The child already has a wallet that syncs from the indexer, which
/// is why the wallet stays on that side, and why the reads pinned here do not travel with
/// the intent: what balances it is that wallet's own synced state.
///
/// **Why the same child rather than a second one.** That wallet holds a single dust UTXO,
/// so two processes spending it could only race onto the same coin. One child makes
/// `IntentGen`'s own lock the thing that serializes them, and a build queued behind a
/// submit is the honest price of that.
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
            // The hash rather than the bytes: the child refuses a submit whose transcript
            // no longer replays, and that refusal is only actionable next to the read it
            // stopped matching.
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
    central_address: String,
    request_id: String,
    signature: WireSignature,
    /// Both `Some` on the bidirectional circuit and both `None` on the other: the
    /// child discriminates its request union on `circuit` and refuses a request whose
    /// fields disagree with it.
    serialized_output: Option<String>,
    output_len: Option<u8>,
}

/// Posts MPC responses back to the Midnight central contract.
pub struct MidnightPublisher {
    config: PublisherConfig,
    reads: Arc<dyn PinnedReads>,
    intent_gen: Arc<IntentGen>,
    submitter: Arc<dyn IntentSubmitter>,
    /// The funding wallet's Zswap public key, derived once at construction. Public,
    /// and the only thing about that wallet the child is ever told.
    coin_public_key: String,
    /// The node's shutdown token, so a build in flight stops with the node rather than
    /// holding it open for the length of a proving run.
    cancel: CancellationToken,
}

impl MidnightPublisher {
    /// Fallible because the funding seed is decoded here: a seed that cannot produce a
    /// wallet is a startup fault, not a fault of the first signature that needs one.
    pub fn new(
        config: &PublisherConfig,
        rpc: Arc<MidnightRpc>,
        intent_gen: Arc<IntentGen>,
        cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        Self::assemble(
            config,
            rpc,
            intent_gen.clone(),
            // The one child, twice: see `ChildSubmitter`. A second builder here would be
            // a second process holding the same funding key.
            Arc::new(ChildSubmitter { intent_gen }),
            cancel,
        )
    }

    fn assemble(
        config: &PublisherConfig,
        reads: Arc<dyn PinnedReads>,
        intent_gen: Arc<IntentGen>,
        submitter: Arc<dyn IntentSubmitter>,
        cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            coin_public_key: coin_public_key(&config.funding_seed)?,
            config: config.clone(),
            reads,
            intent_gen,
            submitter,
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
        // Read for whether it answers, not for what it says. The bytes have no consumer:
        // what balances the transaction is the child's own wallet, which syncs its zswap
        // and dust state from the indexer and cannot be handed a caller's copy. What the
        // call still buys is a node that serves zswap state at this exact hash, refused
        // here rather than after a proving run has been paid for. A balancer moving into
        // this process is what would make the bytes worth carrying again.
        self.reads
            .zswap_chain_state(central_address, &at_hash)
            .await?;
        Ok(PinnedState {
            at_hash,
            contract_state,
            ledger_parameters,
        })
    }
}

#[async_trait]
impl ChainPublisher for MidnightPublisher {
    /// Nothing here remembers a request id. A duplicate publish repeats the whole
    /// path and succeeds, because both circuits are blind appends and the indexer
    /// skips responds for ids it does not know, so a second response for an answered
    /// id costs a transaction and changes nothing. A dedupe cache here would be worse
    /// than useless: a publish that submits and then fails on the way back would be
    /// remembered as done, and the retry that is supposed to rescue it would be
    /// dropped instead.
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let call = respond_call(action)?;
        let sign_id = action.request.id;
        tracing::info!(
            ?sign_id,
            circuit = call.circuit,
            central = %call.central_address,
            "midnight: publishing signature"
        );

        // One head for every read below it. Re-reading it per read is the bug this
        // shape exists to prevent.
        let at_hash = self.reads.finalized_head().await?;
        let chain = self.pin(&call.central_address, at_hash).await?;

        let request = IntentRequest {
            circuit: call.circuit,
            contract_address: call.central_address,
            request_id: call.request_id,
            signature: call.signature,
            serialized_output: call.serialized_output,
            output_len: call.output_len,
            contract_state: hex::encode(&chain.contract_state),
            ledger_parameters: hex::encode(&chain.ledger_parameters),
            coin_public_key: self.coin_public_key.clone(),
            ttl_seconds: ttl_seconds(&self.config, unix_now()?),
        };
        let bytes = self.intent_gen.build(&request, &self.cancel).await?;
        // A gate, not a conversion: what the submitter forwards is `bytes`. Proving
        // that they are a ledger-9 `Intent` before anything is spent proving and paying
        // for them is the whole value. Tagged rather than bare, so a ledger line skew
        // fails by name here instead of as a field-shaped parse error on bytes that
        // were never ours to read.
        let intent: ChainIntent = midnight_serialize::tagged_deserialize(&mut &bytes[..])
            .context("the intent the builder granted did not deserialize as a ledger Intent")?;
        tracing::debug!(?sign_id, ttl = ?intent.ttl, "midnight: intent decoded");

        let backstop = submit_backstop(&self.config);
        let receipt = tokio::time::timeout(
            backstop,
            self.submitter.submit(&bytes, &chain, &self.cancel),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "the midnight submit step ran past its {backstop:?} backstop without returning, \
                 so it is not enforcing the {:?} submit_timeout it was given",
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
        Ok(())
    }
}

/// The action as one respond call, or a refusal.
///
/// Every gate is here, ahead of the first read and the first line to the child, so an
/// action this node cannot serve costs nothing.
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
            // The routing chain and the event's own must agree. They are set by
            // different layers, and a disagreement is a mis-routed request rather
            // than one this node should answer.
            anyhow::ensure!(
                event.chain == Chain::Midnight,
                "midnight publisher was handed a request routed to it carrying a {:?} event",
                event.chain
            );
            Ok(RespondCall {
                circuit: RESPOND,
                central_address: central_address(event.chain_ctx.as_deref())?,
                request_id,
                signature,
                serialized_output: None,
                output_len: None,
            })
        }
        SignKind::RespondBidirectional(tx) => {
            let output_len = u8::try_from(tx.output.len())
                .ok()
                .filter(|len| usize::from(*len) <= OUTPUT_SLOT_BYTES)
                .with_context(|| {
                    format!(
                        "midnight respondBidirectional carries {} bytes of output, more than the \
                     circuit's Bytes<{OUTPUT_SLOT_BYTES}> slot holds",
                        tx.output.len()
                    )
                })?;
            // The whole slot, zero padded: the circuit's argument is fixed width, and
            // `output_len` is what tells a consumer where the real data stops.
            let mut slot = tx.output.clone();
            slot.resize(OUTPUT_SLOT_BYTES, 0);
            Ok(RespondCall {
                circuit: RESPOND_BIDIRECTIONAL,
                central_address: central_address(tx.chain_ctx.as_deref())?,
                request_id,
                signature,
                serialized_output: Some(hex::encode(slot)),
                output_len: Some(output_len),
            })
        }
        other => anyhow::bail!(
            "midnight publisher serves SignBidirectional and RespondBidirectional only, not {}",
            match other {
                SignKind::Sign => "Sign",
                SignKind::Checkpoint(_) => "Checkpoint",
                _ => "an unhandled kind",
            }
        ),
    }
}

/// The central singleton this response belongs on, off the request's own chain
/// context rather than off configuration: the indexer recorded which contract minted
/// the request, and a node whose config has since moved must still answer it where it
/// was asked.
fn central_address(chain_ctx: Option<&[u8]>) -> anyhow::Result<String> {
    let bytes = chain_ctx.context("midnight request carries no chain_ctx")?;
    let ctx: MidnightChainCtx =
        borsh::from_slice(bytes).context("midnight chain_ctx did not deserialize")?;
    // The child validates this as 64 lowercase hex and `MidnightConfig::validate`
    // produced it in that form, so the check is only for a ctx that reached us some
    // other way. Refusing here names the field; refusing at the child names the wire.
    anyhow::ensure!(
        ctx.central_address.len() == 64
            && ctx
                .central_address
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "midnight chain_ctx central_address is not 64 lowercase hex: {}",
        ctx.central_address
    );
    Ok(ctx.central_address)
}

/// The signature in the shape the circuit pushes: SEC1 big-endian affine coordinates
/// and the scalar, each a bare 32-byte hex string. Nothing re-encodes downstream, so a
/// transposition introduced here would land on chain under the right request id and
/// recover a different key.
fn wire_signature(signature: &Signature) -> anyhow::Result<WireSignature> {
    let encoded = signature.big_r.to_encoded_point(false);
    let (Some(x), Some(y)) = (encoded.x(), encoded.y()) else {
        anyhow::bail!("midnight respond: big_r has no affine coordinates (identity point)");
    };
    // The circuit's field is one bit wide and the child's union rejects anything else.
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

/// The funding wallet's Zswap public key.
///
/// Contained rather than only pre-validated. `MidnightConfig::validate` bounds the
/// seed to 16..=64 bytes, which is bip32's own rule, so the panic inside `derive_seed`
/// is unreachable from a validated config; unreachable is not impossible, this crate
/// takes the helpers with `can-panic` on, and a panic in a publisher task takes a
/// runtime worker with it. Doing it once at construction is what keeps the containment
/// off the per-signature path.
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

/// The intent's expiry, as the absolute unix seconds the child wants.
///
/// Sized from the two budgets a publish actually spends rather than picked: the child
/// may take `request_timeout` to answer and the node `submit_timeout` to accept, and
/// past their sum this publish has already given up, so a longer window would only
/// leave an intent alive that nobody is still trying to land. Both circuits are blind
/// appends, so an expired intent costs a repost and nothing else.
fn ttl_seconds(config: &PublisherConfig, now: u64) -> u64 {
    now.saturating_add(config.request_timeout.as_secs())
        .saturating_add(config.submit_timeout.as_secs())
}

/// The outer bound on the submit step.
///
/// `submit_timeout` is the budget the step itself enforces, because only it knows what
/// it is waiting on and only it can kill what it is waiting on. This is the second
/// line, and it exists for one failure: a step that forgot its own deadline would hold
/// a publisher task open for as long as whatever it talks to feels like.
///
/// Deliberately looser than the budget it backs. Were the two equal, which one fired
/// would be a race, and the operator would get a coin flip between "the node did not
/// accept it in time" and "the step is not enforcing its budget", which are different
/// faults with different fixes.
///
/// The headroom is one build budget, because that is the most the step can spend
/// before its own deadline starts: a submit is not repeatable, so it is attempted
/// exactly once, but the attempt may first have to bring a dead child back up, and
/// that respawn runs under the restart backoff bounded by `request_timeout`.
fn submit_backstop(config: &PublisherConfig) -> Duration {
    config.submit_timeout.saturating_add(config.request_timeout)
}

fn unix_now() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the system clock is before the unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::Mutex;

    use midnight_base_crypto::time::Timestamp;
    use midnight_node_ledger_helpers::ledger_9::{SeedableRng as _, StdRng};
    use mpc_chain_integration_core::utils::retry::RetryConfig;
    use mpc_chain_integration_core::utils::test::make_publish_action;
    use mpc_primitives::{
        BidirectionalTxId, Chain, RespondBidirectionalTx, SignBidirectionalEvent, SignId, SignKind,
    };

    /// The contract the fixtures were captured from, and the only address these tests
    /// ever name.
    const CENTRAL: &str = "d7b3c45da613be25050bbdf3fde4cef8f66154d3a52ca8c1edd878bd6391f169";
    const REQUEST_ID: [u8; 32] = [0x5c; 32];
    /// Two different heads, so a publisher that re-reads the head per read cannot pass
    /// the one-hash assertion by accident.
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

    /// An in-process stand-in for the node. Serves a DIFFERENT finalized head on every
    /// ask, which is the whole discrimination in the one-hash test.
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

    /// Records what it was asked to submit. Counting is the only way to observe that a
    /// refused intent cost no proving run, because the run itself leaves no other mark.
    #[derive(Default)]
    struct StubSubmitter {
        /// One entry per submission, naming the hash the intent it was handed was built
        /// over: an intent submitted against a later read is one the node can refuse for
        /// a state that moved, and nothing above this would see which read it was.
        submitted: Mutex<Vec<String>>,
        /// Held before answering, so a test can drive the caller's deadline.
        delay: Duration,
        /// What it refuses with, standing in for the child's own verdict on a submit it
        /// could not make.
        failure: Option<&'static str>,
        /// Whether the token this step was handed was ever cancelled. A step given a
        /// fresh token instead of the node's own would look identical in every other
        /// observation and would keep proving through a shutdown.
        saw_cancelled_token: std::sync::atomic::AtomicBool,
        /// Signalled on entry, so a test can cancel at a point where the step is
        /// certainly running rather than racing the reads and the build ahead of it.
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
            // The bytes have to be the builder's own, not a re-serialization of a
            // decoded value: whatever is proved and paid for downstream is this.
            assert_eq!(
                hex::encode(intent),
                intent_hex(),
                "the submitter must be handed the bytes the builder wrote"
            );
            if let Some(failure) = self.failure {
                // Before the record: a submit that failed posted nothing, and a test that
                // counts submissions has to be able to tell the two apart.
                anyhow::bail!("{failure}");
            }
            self.submitted.lock().unwrap().push(chain.at_hash.clone());
            Ok("stub-receipt".to_string())
        }
    }

    /// A scratch file the stub child writes the request line it was handed into, so a
    /// test can assert on exactly what this crate marshalled.
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

    /// A real serialized ledger `Intent`, so the deserialize step in the publish path
    /// is exercised rather than stepped over. Empty: nothing above the submitter reads
    /// the actions, and the seam test drives the real builder for the case that does.
    fn intent_hex() -> String {
        let mut rng = StdRng::seed_from_u64(7);
        let intent: ChainIntent = Intent::empty(&mut rng, Timestamp::from_secs(1_800_000_000));
        let mut bytes = Vec::new();
        midnight_serialize::tagged_serialize(&intent, &mut bytes)
            .expect("an empty intent serializes");
        hex::encode(bytes)
    }

    /// A stub child that answers every request with `intent_hex`, echoing the id it was
    /// asked so more than one request can be served on one child.
    fn granting_child(recorder: &Recorder) -> Vec<String> {
        script(&format!(
            r#"while read -r line; do printf '%s' "$line" > {}; id=$(printf "%s" "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p'); printf '{{"id":%s,"ok":true,"intent":"{}"}}\n' "$id"; done"#,
            recorder.0.display(),
            intent_hex(),
        ))
    }

    /// A stub child that refuses, the way a managed dir pointed at a different build
    /// than what is deployed refuses.
    fn refusing_child() -> Vec<String> {
        script(
            r#"read -r line; printf '{"id":0,"ok":false,"code":"contract_mismatch","message":"exposes no operation"}\n'"#,
        )
    }

    fn script(body: &str) -> Vec<String> {
        vec!["sh".to_string(), "-c".to_string(), body.to_string()]
    }

    /// Every field pinned, none inherited: the defaults are a trap for a test of a path
    /// that reads one of them, which would then be testing the default rather than a
    /// value it chose.
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
        MidnightPublisher::assemble(config, reads, Arc::new(intent_gen), submitter, cancel)
            .expect("a validated funding seed derives a wallet")
    }

    fn chain_ctx(central: &str) -> Option<Vec<u8>> {
        Some(
            borsh::to_vec(&MidnightChainCtx {
                central_address: central.to_string(),
            })
            .expect("MidnightChainCtx serializes"),
        )
    }

    fn sign_event(chain: Chain, central: &str) -> SignBidirectionalEvent {
        SignBidirectionalEvent {
            sender: [0; 32],
            serialized_transaction: vec![],
            caip2_id: "midnight:testnet".to_string(),
            key_version: 1,
            deposit: 0,
            path: String::new(),
            algo: String::new(),
            dest: String::new(),
            params: String::new(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            chain,
            chain_ctx: chain_ctx(central),
        }
    }

    fn respond_action() -> PublishAction {
        make_publish_action(
            Chain::Midnight,
            SignKind::SignBidirectional(sign_event(Chain::Midnight, CENTRAL)),
            SignId::new(REQUEST_ID),
        )
    }

    fn bidirectional_action(output: Vec<u8>) -> PublishAction {
        make_publish_action(
            Chain::Midnight,
            SignKind::RespondBidirectional(RespondBidirectionalTx {
                tx_id: BidirectionalTxId([0x11; 32]),
                output,
                chain_ctx: chain_ctx(CENTRAL),
            }),
            SignId::new(REQUEST_ID),
        )
    }

    #[tokio::test]
    async fn publish_signature_rejects_a_chain_it_does_not_serve() {
        // A request routed elsewhere must not reach the intent builder, the node or the
        // submitter: the refusal is free and everything past it is not.
        let reads = StubReads::new();
        let submitter = StubSubmitter::new();
        let recorder = Recorder::new("wrong-chain");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, reads.clone(), submitter.clone()).await;

        let action = make_publish_action(
            Chain::Canton,
            SignKind::SignBidirectional(sign_event(Chain::Canton, CENTRAL)),
            SignId::new(REQUEST_ID),
        );
        let err = publisher
            .publish_signature(&action)
            .await
            .expect_err("midnight does not serve canton");
        assert!(format!("{err:#}").contains("Canton"), "got: {err:#}");
        assert!(reads.reads().is_empty(), "a refused chain read the node");
        assert!(submitter.submissions().is_empty());
    }

    #[tokio::test]
    async fn publish_signature_rejects_a_midnight_request_carrying_another_chain_s_event() {
        // The routing chain and the event's own are set by different layers. Trusting
        // the routing field alone would post a Canton response to Midnight's contract.
        let reads = StubReads::new();
        let recorder = Recorder::new("mixed-chain");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, reads.clone(), StubSubmitter::new()).await;

        let action = make_publish_action(
            Chain::Midnight,
            SignKind::SignBidirectional(sign_event(Chain::Canton, CENTRAL)),
            SignId::new(REQUEST_ID),
        );
        assert!(publisher.publish_signature(&action).await.is_err());
        assert!(reads.reads().is_empty());
    }

    #[tokio::test]
    async fn publish_signature_rejects_a_kind_neither_circuit_answers() {
        let reads = StubReads::new();
        let recorder = Recorder::new("wrong-kind");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, reads.clone(), StubSubmitter::new()).await;

        let action = make_publish_action(Chain::Midnight, SignKind::Sign, SignId::new(REQUEST_ID));
        let err = publisher
            .publish_signature(&action)
            .await
            .expect_err("there is no respond circuit for a plain Sign");
        assert!(format!("{err:#}").contains("Sign"), "got: {err:#}");
        assert!(reads.reads().is_empty());
    }

    #[tokio::test]
    async fn publish_signature_reads_all_three_states_at_one_finalized_hash() {
        // The stub serves a different head on every ask, so a publisher that took the
        // head per read would spread the three across two blocks. Fees drift per block,
        // and that spread is what produces an OutOfGas on a correctly built intent.
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
        // The child's own verdict has to end the publish. Proving is the one expensive
        // step, and there is nothing to prove: the refusal means no intent was built.
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
    async fn bytes_that_are_not_a_ledger_intent_never_reach_the_submit_step() {
        // The decode is the only thing standing between the child's output and a
        // proving run paid for out of the funding wallet. Well-formed hex that is not
        // an Intent is exactly what a ledger line skew produces, and it has to fail
        // here, by name, rather than deeper inside something that assumed it parsed.
        let submitter = StubSubmitter::new();
        let config = config(script(
            r#"read -r line; printf '{"id":0,"ok":true,"intent":"deadbeef"}\n'"#,
        ));
        let publisher = publisher(&config, StubReads::new(), submitter.clone()).await;

        let err = publisher
            .publish_signature(&respond_action())
            .await
            .expect_err("four bytes are not a ledger Intent");
        assert!(
            format!("{err:#}").contains("did not deserialize"),
            "got: {err:#}"
        );
        assert!(
            submitter.submissions().is_empty(),
            "unreadable bytes reached the step that pays for them"
        );
    }

    #[tokio::test]
    async fn publish_signature_is_idempotent_for_a_duplicate_request_id() {
        // Both circuits are blind appends and the indexer skips responds for unknown
        // ids, so a second response for an id already answered costs a transaction and
        // changes nothing. The count is the load-bearing half: a dedupe cache would
        // also make this Ok twice, while silently dropping the retry that rescues a
        // publish which submitted and then failed on its way back.
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
        // An `Ok` here settles the signature as answered and nothing retries it, so a
        // submit that posted nothing has to end the publish. The count is the other half:
        // a failure recorded as a submission would mean the publisher believed it had
        // posted something.
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

    /// The reads one publish pinned, as the submit step is handed them.
    fn pinned_state() -> PinnedState {
        PinnedState {
            at_hash: HEAD_ONE.to_string(),
            contract_state: CONTRACT_STATE.to_vec(),
            ledger_parameters: LEDGER_PARAMETERS.to_vec(),
        }
    }

    /// The real submitter over a stub child, which is as far as this seam can be driven
    /// without a funding wallet, an indexer and a proof server.
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
        // The identifier is what the success line carries and what an operator reads the
        // chain back with, so it has to be the child's own rather than anything this side
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
        // `wallet_unfunded` is a deployment out of dust and `state_conflict` is another
        // writer having won the race. Both are the operator's to act on and neither is a
        // fault of the pipe, so a generic transport error here would send them to read
        // the wire instead of the deployment.
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

    #[test]
    fn the_submit_backstop_is_strictly_looser_than_the_budget_it_backs() {
        // The property, not the arithmetic. A backstop equal to `submit_timeout` turns
        // an ordinary slow submit into a race between two different error messages, one
        // saying the node was slow and one saying the step ignored its budget. Both
        // budgets are read, so retuning either moves this with it.
        let config = config(vec!["true".to_string()]);
        let backstop = submit_backstop(&config);
        assert!(
            backstop > config.submit_timeout,
            "the backstop must never fire before the budget it backs: {backstop:?} vs {:?}",
            config.submit_timeout
        );
        assert_eq!(
            backstop,
            config.submit_timeout + config.request_timeout,
            "headroom for the one thing that can run before the step's own deadline \
             starts: bringing a dead child back up, which the restart backoff bounds by \
             request_timeout"
        );
    }

    #[tokio::test]
    async fn the_submit_step_is_handed_the_node_s_own_shutdown_token() {
        // A step handed a fresh token instead of the node's own is indistinguishable in
        // every other observation and keeps proving straight through a shutdown, holding
        // the node open for the length of a proving run. The stub signals on entry, so
        // the cancel lands while the step is certainly running rather than racing the
        // reads and the build ahead of it.
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
        // The reason `submit_timeout` is read at all. The step is expected to enforce
        // its own budget, and this is what happens when it does not: the publish ends
        // and says which fault it is, rather than parking a task on a child that will
        // never answer.
        let mut config = config(granting_child(&Recorder::new("submit-backstop")));
        config.submit_timeout = Duration::from_millis(20);
        config.request_timeout = Duration::from_millis(30);
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
        // Not a possible state for a request this node indexed off that contract, so it
        // is a wrong central address or a node that cannot reach the block. Either way
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
        // The only place the marshalling is observable. The publisher package pins the
        // same wire from its own TypeScript input, so it cannot see a field this side
        // transposed, dropped or misnamed.
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

        // Against the action's own signature, so a swapped x and y is caught. Equal
        // looking components would make that invisible, which is exactly the bug: a
        // transposed signature still lands under the right id and recovers another key.
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
    async fn the_bidirectional_circuit_carries_its_output_padded_to_the_whole_slot() {
        // A separate deployed operation with a wider event struct, so the other case
        // passing says nothing about it. The slot is fixed width and `outputLen` is
        // what tells a consumer how much of it is real.
        let recorder = Recorder::new("bidirectional");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, StubReads::new(), StubSubmitter::new()).await;

        publisher
            .publish_signature(&bidirectional_action(vec![0xab; 32]))
            .await
            .expect("granted");

        let request = recorder.request();
        assert_eq!(request["circuit"], RESPOND_BIDIRECTIONAL);
        assert_eq!(request["outputLen"], 32);
        assert_eq!(
            request["serializedOutput"],
            format!("{}{}", "ab".repeat(32), "00".repeat(96)),
            "the whole Bytes<128> travels, zero padded on the right"
        );
    }

    #[tokio::test]
    async fn an_output_wider_than_the_slot_is_refused_before_anything_is_read() {
        // Truncating would post a response whose payload is not the one that was
        // signed, and the child would accept the request because it only sees the
        // truncated slot.
        let reads = StubReads::new();
        let recorder = Recorder::new("overlong-output");
        let config = config(granting_child(&recorder));
        let publisher = publisher(&config, reads.clone(), StubSubmitter::new()).await;

        let err = publisher
            .publish_signature(&bidirectional_action(vec![0xab; 129]))
            .await
            .expect_err("129 bytes do not fit a Bytes<128> slot");
        assert!(format!("{err:#}").contains("129"), "got: {err:#}");
        assert!(reads.reads().is_empty());
    }

    #[test]
    fn a_missing_or_malformed_chain_ctx_is_refused() {
        // The address is the request's own, not configuration's, so there is no
        // fallback to a configured value: answering the wrong contract is worse than
        // not answering.
        let mut action = respond_action();
        let SignKind::SignBidirectional(event) = &mut action.request.kind else {
            panic!("the fixture is a SignBidirectional");
        };
        event.chain_ctx = None;
        assert!(respond_call(&action).is_err());

        let SignKind::SignBidirectional(event) = &mut action.request.kind else {
            panic!("the fixture is a SignBidirectional");
        };
        event.chain_ctx = Some(vec![0xff, 0xff]);
        assert!(respond_call(&action).is_err());

        let SignKind::SignBidirectional(event) = &mut action.request.kind else {
            panic!("the fixture is a SignBidirectional");
        };
        // Uppercase is a valid Borsh string and an address the child refuses, so it has
        // to be caught by name here rather than as a wire error there.
        event.chain_ctx = chain_ctx(&CENTRAL.to_uppercase());
        assert!(respond_call(&action).is_err());
    }

    #[test]
    fn the_coin_public_key_is_derived_from_the_configured_seed() {
        // Transcribed from the helpers' own derivation for this seed, so a ledger-line
        // bump that moves the Zswap role's key is caught here rather than by a proof
        // that verifies against a key the funding wallet does not hold.
        let key = coin_public_key(&funding_seed()).expect("a 32 byte seed derives");
        assert_eq!(
            key,
            "687a8db8e44bbd007b6baaf9004c742d1d89ee7bd8f367e6ec6b017a2cf98baf"
        );
        // The half a transcribed value cannot check on its own: that the seed is read
        // at all. A key returned from anywhere but this seed passes the line above for
        // as long as nobody changes the seed.
        let other = coin_public_key(&"11".repeat(32)).expect("another 32 byte seed derives");
        assert_ne!(key, other);
        assert_eq!(other.len(), 64);
    }

    #[test]
    fn an_unusable_funding_seed_fails_at_construction_rather_than_at_the_first_signature() {
        // The seed is decoded once. A publisher that deferred it would look healthy
        // until the first request it could not answer, which is the worst moment to
        // discover a deployment typo.
        assert!(coin_public_key("").is_err());
        assert!(coin_public_key("zz".repeat(32).as_str()).is_err());
        // 17 bytes: hex-clean, and neither of the three lengths a wallet seed takes.
        assert!(coin_public_key(&"0f".repeat(17)).is_err());
    }
}
