//! Builds, proves, pays for and posts respond intents in process.
//!
//! The call comes from `minocrab-publisher`, which writes the respond call's transcript
//! and proves it under the responder's packaged keys with zkir v3. The fee is a second
//! intent spending the funding wallet's DUST, proven with the ledger's own zkir v2
//! prover. Both halves are sealed separately and merged, the way the Midnight wallet
//! SDK finalizes a balanced transaction.
//!
//! A submit has one budget, `PublisherConfig::submit_timeout`, from the first wait to
//! the finalized landing.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode, BASE_URL};
use midnight_base_crypto::hash::HashOutput;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger_v9::dust::{DustNullifier, DustResolver, DUST_EXPECTED_FILES};
use midnight_ledger_v9::structure::LedgerParameters;
use midnight_onchain_runtime::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_state::state::ContractState;
use midnight_storage::DefaultDB;
use minocrab_publisher::intent::{build_intent, preimage_tx, PreimageIntent};
use minocrab_publisher::{Deployment, InProcessProver, ManagedDir, SignerResolver};
use mpc_utils::task::AbortOnDrop;
use rand::rngs::StdRng;
use rand::{Rng as _, SeedableRng as _};
use tokio::time::Instant;

use crate::funding::{dust_deficit, FeePayer, SealedTx, UnprovenTx};
use crate::intent::{IntentRequest, RespondCircuit, Submitted};
use crate::landing_watch::{watch_landing, WatchEnd};
use crate::publisher::IntentClient;
#[cfg(test)]
use crate::rpc::PinnedReads;
use crate::rpc::{SubmitChain, SubmitRefusal};
use crate::submit_error::SubmitError;
use crate::types::{BlockHash, LedgerTxHash, NetworkId};

/// The respond intent's segment; the fee intent takes the next free one.
const RESPOND_SEGMENT: u16 = 1;
/// How long the fee intent, and so the whole transaction, stays includable.
const FEE_TTL: Duration = Duration::from_secs(180);
/// A fee intent shorter-lived than this is not worth submitting.
const MIN_FEE_TTL: Duration = Duration::from_secs(30);
/// Kept free of the DUST wait: proving, pricing and the landing need it.
const WORK_RESERVE: Duration = Duration::from_secs(120);
/// How long past its TTL a landed transaction may take to finalize.
const FINALITY_SLACK: Duration = Duration::from_secs(60);
/// How long after a submit went unanswered the transaction is first sent again. Each
/// further unanswered attempt doubles the wait, up to `MAX_RESEND_DELAY`, so a node
/// shedding load is not asked again at a fixed pace.
const RESEND_DELAY: Duration = Duration::from_secs(6);
const MAX_RESEND_DELAY: Duration = Duration::from_secs(60);

/// What a submit spent before it asked the wallet to pay, for its log line.
struct SubmitTimings {
    started: Instant,
    wallet_wait: Duration,
    prove_respond: Duration,
}

/// The packaged contract keys and the parameters every proof needs.
pub(crate) struct Provers {
    managed: ManagedDir,
    contract: SignerResolver,
    params: MidnightDataProvider,
    dust: DustResolver,
}

impl Provers {
    /// `artifacts` holds `keys/<circuit>.{prover,verifier}` and `zkir/<circuit>.bzkir`;
    /// `zk_params` holds the KZG parameters and the DUST spend keys, and missing
    /// files are fetched into it and checked against the ledger's pinned hashes.
    pub(crate) fn new(
        artifacts: impl Into<std::path::PathBuf>,
        zk_params: impl Into<std::path::PathBuf>,
    ) -> anyhow::Result<Self> {
        let zk_params = zk_params.into();
        // Built directly: `MidnightDataProvider::new` resolves a cache directory from
        // HOME, XDG_CACHE_HOME or MIDNIGHT_PP and fails when none is set, and the node
        // replaces that directory with `zk_params` anyway.
        let provider = |expected: Vec<_>| MidnightDataProvider {
            fetch_mode: FetchMode::OnDemand,
            base_url: BASE_URL.clone(),
            output_mode: OutputMode::Log,
            expected_data: expected,
            dir: zk_params.clone(),
        };
        let managed = ManagedDir::new(artifacts);
        for circuit in ["respond", "respondBidirectional"] {
            for path in [
                managed.prover_key_path(circuit),
                managed.verifier_key_path(circuit),
                managed.ir_path(circuit),
            ] {
                anyhow::ensure!(
                    path.is_file(),
                    "midnight publisher: the packaged contract artifact {} is missing",
                    path.display()
                );
            }
        }
        Ok(Self {
            contract: SignerResolver::new(managed.clone()),
            managed,
            params: provider(vec![]),
            dust: DustResolver(provider(DUST_EXPECTED_FILES.to_vec())),
        })
    }
}

pub(crate) struct NativeIntentClient<W, C> {
    chain: Arc<C>,
    wallet: W,
    provers: Arc<Provers>,
    network_id: NetworkId,
    submit_timeout: Duration,
}

impl<W: FeePayer, C: SubmitChain + 'static> NativeIntentClient<W, C> {
    pub(crate) fn new(
        chain: Arc<C>,
        wallet: W,
        provers: Arc<Provers>,
        network_id: NetworkId,
        submit_timeout: Duration,
    ) -> Self {
        Self {
            chain,
            wallet,
            provers,
            network_id,
            submit_timeout,
        }
    }

    fn build_intent(&self, request: &IntentRequest) -> Result<Vec<u8>, SubmitError> {
        let state: ContractState<DefaultDB> =
            midnight_serialize::tagged_deserialize(&mut &request.contract_state[..]).map_err(
                |error| SubmitError::BadRequest(format!("contractState did not decode: {error}")),
            )?;
        let parameters: LedgerParameters = midnight_serialize::tagged_deserialize(
            &mut &request.ledger_parameters[..],
        )
        .map_err(|error| {
            SubmitError::BadRequest(format!("ledgerParameters did not decode: {error}"))
        })?;
        let circuit = request.circuit.name();
        let packaged = self
            .provers
            .managed
            .verifier_key_hash(circuit)
            .map_err(|error| SubmitError::ContractMismatch(error.to_string()))?;
        let deployment = Deployment::new(
            ContractAddress(HashOutput(*request.contract_address.as_bytes())),
            [(circuit.to_string(), packaged)],
        );
        deployment
            .check_deployed(&state)
            .map_err(|error| SubmitError::DeployMismatch(error.to_string()))?;

        let call = match &request.circuit {
            RespondCircuit::Respond => minocrab_publisher::respond::<DefaultDB>(
                &deployment,
                &request.request_id,
                &request.signature,
            ),
            RespondCircuit::RespondBidirectional(attestation) => {
                minocrab_publisher::respond_bidirectional::<DefaultDB>(
                    &deployment,
                    &request.request_id,
                    attestation,
                    &request.signature,
                )
            }
        }
        .map_err(|error| SubmitError::BadRequest(error.to_string()))?;

        let mut rng = StdRng::from_entropy();
        let prototype = call
            .prototype(&state.data, &parameters, rng.gen())
            .map_err(|error| SubmitError::Internal(error.to_string()))?;
        let intent = build_intent(
            &mut rng,
            vec![prototype],
            Timestamp::from_secs(request.ttl_seconds),
        );
        let mut bytes = Vec::new();
        midnight_serialize::tagged_serialize(&intent, &mut bytes)
            .map_err(|error| SubmitError::Internal(format!("serializing the intent: {error}")))?;
        Ok(bytes)
    }

    async fn submit_intent(&self, intent: &[u8]) -> Result<Submitted, SubmitError> {
        let deadline = Instant::now() + self.submit_timeout;
        let intent: PreimageIntent<DefaultDB> =
            midnight_serialize::tagged_deserialize(&mut &intent[..]).map_err(|error| {
                SubmitError::BadRequest(format!("the intent did not decode: {error}"))
            })?;

        let started = Instant::now();
        self.wallet
            .ready_by(deadline.checked_sub(WORK_RESERVE).unwrap_or(deadline))
            .await?;
        let wallet_wait = started.elapsed();

        let stage = Instant::now();
        let base = self.prove_respond(intent, deadline).await?;
        let prove_respond = stage.elapsed();
        let before = SubmitTimings {
            started,
            wallet_wait,
            prove_respond,
        };
        self.pay_for(&base, deadline, before).await
    }

    /// Pays for the proven respond `base` and posts it.
    async fn pay_for(
        &self,
        base: &SealedTx,
        deadline: Instant,
        before: SubmitTimings,
    ) -> Result<Submitted, SubmitError> {
        let head = self.chain.finalized_head().await.map_err(node)?;
        let parameters: LedgerParameters = midnight_serialize::tagged_deserialize(
            &mut &self.chain.ledger_parameters(&head).await.map_err(node)?[..],
        )
        .map_err(|error| {
            SubmitError::Internal(format!("ledger parameters did not decode: {error}"))
        })?;
        let head_number = self.chain.block_number(&head).await.map_err(node)?;
        let ctime = self.fee_ctime_at(&head, deadline).await?;

        let wall = mpc_utils::time::current_unix_timestamp();
        let remaining = deadline.saturating_duration_since(Instant::now());
        let fee_ttl = fee_ttl(remaining).ok_or_else(|| {
            SubmitError::ProvingTimeout(format!(
                "{remaining:?} of the submit budget is left, too little to land a transaction; \
                 nothing was posted"
            ))
        })?;
        let ttl = Timestamp::from_secs(wall + fee_ttl.as_secs());

        let stage = Instant::now();
        let plan = self.wallet.plan(
            base,
            &parameters,
            ctime,
            ttl,
            self.network_id.as_str(),
            &mut StdRng::from_entropy(),
        );
        let plan = plan?;
        let price_fee = stage.elapsed();
        let fee_tx = plan.tx;
        let stage = Instant::now();
        let fee_sealed = self.prove_fee(fee_tx, deadline).await?;
        let prove_fee = stage.elapsed();
        let (bytes, tx_hash) = paid_transaction(base, &fee_sealed, &parameters)?;

        tracing::info!(
            fee = plan.fee,
            tx_hash = %tx_hash,
            wallet_wait = ?before.wallet_wait,
            prove_respond = ?before.prove_respond,
            ?price_fee,
            ?prove_fee,
            before_post = ?before.started.elapsed(),
            "midnight: posting respond"
        );
        let tx_id = self
            .post(&bytes, tx_hash, &plan.spent, head_number, ttl, deadline)
            .await?;
        Ok(Submitted {
            tx_id,
            dust_balance: plan.available,
        })
    }

    /// The fee's `ctime` at `head`, once the replay has caught up with what the
    /// indexer reports; see [`fee_ctime`].
    async fn fee_ctime_at(
        &self,
        head: &BlockHash,
        deadline: Instant,
    ) -> Result<Timestamp, SubmitError> {
        let head_time = self.chain.block_time(head).await.map_err(node)?;
        let indexed_time = self.wallet.indexed_time().await?;
        // Events indexed up to `indexed_time` may still be on their way to the replay.
        self.wallet
            .ready_by(deadline.checked_sub(WORK_RESERVE).unwrap_or(deadline))
            .await?;
        Ok(fee_ctime(head_time, indexed_time, self.wallet.sync_time()))
    }

    /// The respond call proven under the packaged contract keys (zkir v3).
    async fn prove_respond(
        &self,
        intent: PreimageIntent<DefaultDB>,
        deadline: Instant,
    ) -> Result<SealedTx, SubmitError> {
        let respond = preimage_tx(self.network_id.as_str(), RESPOND_SEGMENT, intent);
        let provers = self.provers.clone();
        let proven = prove_blocking(deadline, move || async move {
            let prover = InProcessProver {
                rng: StdRng::from_entropy(),
                resolver: &provers.contract,
                params: &provers.params,
            };
            respond.prove(prover, &INITIAL_COST_MODEL).await
        })
        .await?;
        Ok(proven.seal(StdRng::from_entropy()))
    }

    /// The fee transaction's DUST spends proven under the ledger's spend keys (zkir v2).
    async fn prove_fee(
        &self,
        fee_tx: UnprovenTx,
        deadline: Instant,
    ) -> Result<SealedTx, SubmitError> {
        let provers = self.provers.clone();
        let proven = prove_blocking(deadline, move || async move {
            let prover = midnight_zkir::LocalProvingProvider {
                rng: StdRng::from_entropy(),
                resolver: &provers.dust,
                params: &provers.params,
            };
            fee_tx.prove(prover, &INITIAL_COST_MODEL).await
        })
        .await?;
        Ok(proven.seal(StdRng::from_entropy()))
    }

    /// Posts a paid transaction and waits for it: the UTXOs it spends stay reserved
    /// until it lands, the node refuses the first submit or it could not be sent, a
    /// finalized block past its TTL does not hold it, or a minute past its TTL.
    // The deadline's ambiguous exit finds that reservation expired — `fee_ttl`
    // leaves the budget the slack — so the retry may plan the same UTXOs, and if
    // this transaction landed after all, the node refuses that spend. A read
    // verdict ending the watch earlier holds the reservation: the retry plans
    // other UTXOs, or stops at `wallet_busy` until they expire.
    async fn post(
        &self,
        bytes: &[u8],
        tx_hash: LedgerTxHash,
        spent: &[DustNullifier],
        after: u64,
        ttl: Timestamp,
        deadline: Instant,
    ) -> Result<LedgerTxHash, SubmitError> {
        self.wallet.reserve(
            spent,
            Timestamp::from_secs(ttl.to_secs() + FINALITY_SLACK.as_secs()),
        );
        let started = Instant::now();
        let unanswered = match self.chain.submit(bytes).await {
            Ok(()) => false,
            Err(SubmitRefusal::Refused(reason)) => {
                self.wallet.release(spent);
                return Err(SubmitError::StateConflict(format!(
                    "the node refused the transaction: {reason}; nothing was posted"
                )));
            }
            Err(SubmitRefusal::Unsent(error)) => {
                self.wallet.release(spent);
                return Err(SubmitError::Node {
                    source: error.context("the transaction could not be sent; nothing was posted"),
                });
            }
            Err(SubmitRefusal::Mismatch(error)) => {
                self.wallet.release(spent);
                return Err(SubmitError::ContractMismatch(error.to_string()));
            }
            Err(SubmitRefusal::Unanswered(error)) => {
                tracing::warn!(
                    error = %format_args!("{error:#}"),
                    tx_hash = %tx_hash,
                    "midnight: submit unanswered; sending it again while watching for the \
                     transaction"
                );
                true
            }
        };
        let submitted = started.elapsed();
        // Ends with the wait, so a resend held up by the node never delays the scan.
        let _resending = unanswered.then(|| {
            AbortOnDrop(tokio::spawn(resend(
                self.chain.clone(),
                bytes.to_vec(),
                tx_hash,
            )))
        });
        let end = watch_landing(self.chain.as_ref(), tx_hash, after, ttl, deadline).await;
        let landed = match &end {
            WatchEnd::Landed(landing) => Some(landing),
            _ => None,
        };
        tracing::info!(
            tx_hash = %tx_hash,
            ?submitted,
            settled = ?started.elapsed(),
            ?landed,
            outcome = ?end,
            "midnight: respond settled"
        );
        match end {
            // The respond's only transcript and the DUST spends are guaranteed, which
            // a partial success commits and readers read; the reservation ends when
            // the replay sees the spends.
            WatchEnd::Landed(_) => Ok(tx_hash),
            WatchEnd::Expired => {
                self.wallet.release(spent);
                Err(SubmitError::StateConflict(format!(
                    "transaction {tx_hash} expired without landing"
                )))
            }
            WatchEnd::Budget => Err(SubmitError::Ambiguous(format!(
                "transaction {tx_hash} was not seen finalized within the submit budget; it may \
                 still land, and a later publisher retry may post the response again"
            ))),
            WatchEnd::TerminalRead(error) | WatchEnd::ThrottleEscape(error) => Err(node(error)),
        }
    }
}

#[async_trait]
impl<W, C> IntentClient for NativeIntentClient<W, C>
where
    W: FeePayer + 'static,
    C: SubmitChain + 'static,
{
    async fn build(&self, request: &IntentRequest) -> anyhow::Result<Vec<u8>> {
        self.build_intent(request)
            .map_err(SubmitError::into_publish_error)
    }

    /// Tells the wallet how the submit ended, as the intent builder's parent did: a
    /// landing clears the strikes, and any failure but an unsynced wallet starts the
    /// replay over from the latest checkpoint; only a state conflict implicates the
    /// restored state.
    async fn submit(&self, intent: &[u8]) -> anyhow::Result<Submitted> {
        let submitted = self.submit_intent(intent).await;
        report_submit(&self.wallet, &submitted);
        submitted.map_err(SubmitError::into_publish_error)
    }
}

fn report_submit<W: FeePayer>(wallet: &W, submitted: &Result<Submitted, SubmitError>) {
    match submitted {
        Ok(_) => wallet.landed(),
        Err(SubmitError::WalletUnsynced(_)) => {}
        Err(error) => wallet.failed(error.strikes_restored_state()),
    }
}

/// The fee's `ctime`. The spend proves against the replayed state's DUST roots,
/// which the chain looks up by `ctime`, so it names a time the replay has seen: no
/// later than the finalized head or the newest block the indexer has indexed, and
/// no earlier than the newest replayed event. The replay is checked caught up after
/// the indexer answers, up to the newest event id the indexer names right after it.
/// An event the subscription has not delivered can still leave the roots stale when
/// the indexer names none in time, or when a subscription opened since serves an
/// indexer that has not stored it yet; the node then refuses the spend and the publish
/// retries.
fn fee_ctime(head_time: Timestamp, indexed_time: Timestamp, sync_time: Timestamp) -> Timestamp {
    head_time.min(indexed_time).max(sync_time)
}

/// The respond merged with its proven fee, serialized, and its ledger hash. The plan
/// priced the fee over a mock proof, so the real one is checked to still pay.
fn paid_transaction(
    base: &SealedTx,
    fee: &SealedTx,
    parameters: &LedgerParameters,
) -> Result<(Vec<u8>, LedgerTxHash), SubmitError> {
    let transaction = base
        .merge(fee)
        .map_err(|error| SubmitError::Internal(format!("merging the fee: {error:?}")))?;
    let owed = transaction
        .fees(parameters, false)
        .map_err(|error| SubmitError::Internal(format!("pricing the transaction: {error:?}")))?;
    let short = dust_deficit(&transaction, owed)?;
    if short > 0 {
        return Err(SubmitError::Internal(format!(
            "the proven transaction is {short} SPECKS short of its fee; nothing was posted"
        )));
    }
    let mut bytes = Vec::new();
    midnight_serialize::tagged_serialize(&transaction, &mut bytes)
        .map_err(|error| SubmitError::Internal(format!("serializing the transaction: {error}")))?;
    Ok((
        bytes,
        LedgerTxHash::from_bytes(transaction.transaction_hash().0 .0),
    ))
}

/// How long the fee intent stays includable with `remaining` of the budget left:
/// enough of it must remain to see the transaction finalized past its TTL.
fn fee_ttl(remaining: Duration) -> Option<Duration> {
    Some(FEE_TTL.min(remaining.saturating_sub(FINALITY_SLACK))).filter(|ttl| *ttl >= MIN_FEE_TTL)
}

/// Runs a proof on the blocking pool: proving holds a core for seconds, and the
/// zkir provers do their own file reads.
async fn prove_blocking<T, E, F, Fut>(deadline: Instant, job: F) -> Result<T, SubmitError>
where
    T: Send + 'static,
    E: std::fmt::Debug + Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let handle = tokio::runtime::Handle::current();
    let proving = tokio::task::spawn_blocking(move || handle.block_on(job()));
    match tokio::time::timeout_at(deadline, proving).await {
        Err(_) => Err(SubmitError::ProvingTimeout(
            "proving outlasted the submit budget; nothing was posted".to_string(),
        )),
        Ok(Err(join)) => Err(SubmitError::Internal(format!(
            "the proving task failed: {join}"
        ))),
        Ok(Ok(Err(error))) => Err(SubmitError::Internal(format!("proving failed: {error:?}"))),
        Ok(Ok(Ok(proven))) => Ok(proven),
    }
}

/// Sends a transaction whose submit went unanswered again, `RESEND_DELAY` later and
/// then at doubling intervals, until a node answers one: the node may never have
/// received it. The ledger applies an intent once, so a resend cannot post it twice,
/// and a refusal may be the transaction already in a block, so only the landing scan
/// decides the outcome.
async fn resend<C: SubmitChain>(chain: Arc<C>, transaction: Vec<u8>, tx_hash: LedgerTxHash) {
    let mut delay = RESEND_DELAY;
    loop {
        tokio::time::sleep(delay).await;
        match chain.submit(&transaction).await {
            Ok(()) => {
                tracing::info!(
                    tx_hash = %tx_hash,
                    "midnight: the node took the resent respond transaction"
                );
                return;
            }
            Err(SubmitRefusal::Refused(reason)) => {
                tracing::info!(
                    tx_hash = %tx_hash,
                    %reason,
                    "midnight: the node refused the resent respond transaction; watching for it"
                );
                return;
            }
            Err(SubmitRefusal::Mismatch(error)) => {
                tracing::warn!(
                    error = %format_args!("{error:#}"),
                    tx_hash = %tx_hash,
                    "midnight: the node cannot carry the resent respond transaction; watching \
                     for it"
                );
                return;
            }
            Err(SubmitRefusal::Unanswered(error) | SubmitRefusal::Unsent(error)) => {
                if let Some(count) = mpc_utils::throttle::check("midnight:resend-unanswered") {
                    tracing::warn!(
                        count,
                        error = %format_args!("{error:#}"),
                        tx_hash = %tx_hash,
                        "midnight: resent respond transactions went unanswered"
                    );
                }
                delay = (delay * 2).min(MAX_RESEND_DELAY);
            }
        }
    }
}

fn node(error: anyhow::Error) -> SubmitError {
    SubmitError::Node { source: error }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain_mock::{
        block_hash, block_number_of, ledger_parameters, scan_read_rejected, ScriptedChain, TX_HASH,
    };
    use crate::emissions::{emissions_of_call, Emission, EmissionKind, MISC_PAYLOAD_LEN};
    use crate::funding::tests::{base, funded_key, replayed};
    use crate::funding::{plan_fee, FeePlan};
    use crate::landing_watch::LANDING_POLL;
    use crate::rpc::Landing;
    use crate::test_utils::{EventRecorder, RecordedFields};
    use crate::MidnightAddress;
    use http::StatusCode;
    use midnight_ledger_v9::structure::{
        ContractAction, ContractCall, Intent, ProofPreimageMarker, Signature, INITIAL_PARAMETERS,
    };
    use midnight_transient_crypto::commitment::PedersenRandomness;
    use minocrab_publisher::{Attestation, EcdsaSignature};
    use mpc_chain_integration_core::utils::retry::{
        is_retryable, run_gated, RpcFailure, SharedBackoff,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;
    use tracing_subscriber::layer::SubscriberExt;

    /// The responder's initial state with the package's verifier keys
    /// (`midnight-devtools`' `gen:initial-state`).
    const RESPONDER_STATE: &[u8] = include_bytes!("../fixtures/initial-responder-state.mn");
    const RESPONDER: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const REQUEST_ID: &str = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";
    const TTL: u64 = 1_800_000_000;

    type ChainIntent = Intent<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>;

    /// A wallet that records reservations; the build and post paths never plan.
    #[derive(Default)]
    pub(super) struct RecordingWallet {
        reserved: Mutex<Vec<Vec<DustNullifier>>>,
        reserved_until: Mutex<Vec<Timestamp>>,
        released: Mutex<Vec<Vec<DustNullifier>>>,
        waited_until: Mutex<Vec<Instant>>,
        sync_secs: AtomicU64,
        indexed_secs: u64,
        /// Where the replay stands once `ready_by` has waited for it, if it moves.
        caught_up_secs: Option<u64>,
        failures: Mutex<Vec<bool>>,
        landings: AtomicU64,
    }

    impl FeePayer for RecordingWallet {
        async fn ready_by(&self, deadline: Instant) -> Result<(), SubmitError> {
            self.waited_until.lock().unwrap().push(deadline);
            if let Some(secs) = self.caught_up_secs {
                self.sync_secs.store(secs, Ordering::SeqCst);
            }
            Ok(())
        }

        fn sync_time(&self) -> Timestamp {
            Timestamp::from_secs(self.sync_secs.load(Ordering::SeqCst))
        }

        async fn indexed_time(&self) -> Result<Timestamp, SubmitError> {
            Ok(Timestamp::from_secs(self.indexed_secs))
        }

        fn plan(
            &self,
            _base: &SealedTx,
            _parameters: &LedgerParameters,
            _ctime: Timestamp,
            _ttl: Timestamp,
            _network_id: &str,
            _rng: &mut StdRng,
        ) -> Result<FeePlan, SubmitError> {
            unimplemented!("no test prices a fee")
        }

        fn reserve(&self, spent: &[DustNullifier], until: Timestamp) {
            self.reserved.lock().unwrap().push(spent.to_vec());
            self.reserved_until.lock().unwrap().push(until);
        }

        fn release(&self, spent: &[DustNullifier]) {
            self.released.lock().unwrap().push(spent.to_vec());
        }

        fn failed(&self, strike: bool) {
            self.failures.lock().unwrap().push(strike);
        }

        fn landed(&self) {
            self.landings.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A managed directory holding the verifier keys the fixture state carries, as
    /// `keys/<circuit>.verifier`.
    fn managed_dir(verifier: impl Fn(&str, Vec<u8>) -> Vec<u8>) -> tempfile::TempDir {
        let state: ContractState<DefaultDB> =
            midnight_serialize::tagged_deserialize(&mut &RESPONDER_STATE[..]).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        std::fs::create_dir_all(dir.join("zkir")).unwrap();
        for circuit in ["respond", "respondBidirectional"] {
            // Empty: a test that proves with them fails at the first one.
            std::fs::write(dir.join("keys").join(format!("{circuit}.prover")), b"").unwrap();
            std::fs::write(dir.join("zkir").join(format!("{circuit}.bzkir")), b"").unwrap();
        }
        for circuit in ["respond", "respondBidirectional"] {
            let op = state
                .operations
                .get(&circuit.as_bytes().into())
                .expect("the fixture carries every responder circuit");
            let mut bytes = Vec::new();
            midnight_serialize::tagged_serialize(op.v3.as_ref().unwrap(), &mut bytes).unwrap();
            std::fs::write(
                dir.join("keys").join(format!("{circuit}.verifier")),
                verifier(circuit, bytes),
            )
            .unwrap();
        }
        temp
    }

    /// A client over a managed directory that lives as long as the client: the
    /// build reads the verifier keys from it.
    struct TestClient {
        client: NativeIntentClient<RecordingWallet, ScriptedChain>,
        _dir: tempfile::TempDir,
    }

    impl std::ops::Deref for TestClient {
        type Target = NativeIntentClient<RecordingWallet, ScriptedChain>;

        fn deref(&self) -> &Self::Target {
            &self.client
        }
    }

    impl std::ops::DerefMut for TestClient {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.client
        }
    }

    fn client_over(dir: tempfile::TempDir, chain: ScriptedChain) -> TestClient {
        TestClient {
            client: NativeIntentClient::new(
                Arc::new(chain),
                RecordingWallet::default(),
                Arc::new(Provers::new(dir.path(), dir.path()).unwrap()),
                NetworkId::Undeployed,
                Duration::from_secs(420),
            ),
            _dir: dir,
        }
    }

    fn client() -> TestClient {
        client_over(managed_dir(|_, bytes| bytes), ScriptedChain::new(0, 0))
    }

    impl TestClient {
        /// Posts the fixture transaction on the test deadline.
        async fn post(&self, ttl: u64) -> Result<LedgerTxHash, SubmitError> {
            self.post_within(ttl, deadline()).await
        }

        /// Posts the fixture transaction within the caller-supplied deadline.
        async fn post_within(&self, ttl: u64, by: Instant) -> Result<LedgerTxHash, SubmitError> {
            self.client
                .post(
                    b"tx",
                    LedgerTxHash::from_bytes(TX_HASH),
                    &spent(),
                    10,
                    Timestamp::from_secs(ttl),
                    by,
                )
                .await
        }
    }

    fn hex32(value: &str) -> [u8; 32] {
        hex::decode(format!("{value:0>64}"))
            .unwrap()
            .try_into()
            .unwrap()
    }

    pub(super) fn respond_request() -> IntentRequest {
        IntentRequest {
            circuit: RespondCircuit::Respond,
            contract_address: MidnightAddress::from_bytes(hex32(RESPONDER)),
            request_id: hex32(REQUEST_ID),
            signature: EcdsaSignature {
                big_r_x: [0x11; 32],
                big_r_y: [0x22; 32],
                s: [0x33; 32],
                recovery_id: 1,
            },
            contract_state: RESPONDER_STATE.to_vec(),
            ledger_parameters: ledger_parameters(),
            ttl_seconds: TTL,
        }
    }

    /// The compiled responder's own `respondBidirectional` event, captured by
    /// `midnight-devtools`' `gen:api-parity-vectors`, as a request.
    pub(super) fn bidirectional_request() -> IntentRequest {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/api-parity-vectors.json")).unwrap();
        let event = &fixtures["responseEvent"];
        let text = |value: &serde_json::Value| value.as_str().unwrap().to_string();
        let uint64 = |value: &serde_json::Value| text(value).parse::<u64>().unwrap();
        IntentRequest {
            circuit: RespondCircuit::RespondBidirectional(Attestation {
                block_height: uint64(&event["blockHeight"]),
                output_kind: event["outputKind"].as_u64().unwrap() as u8,
                serialized_output_length: uint64(&event["serializedOutputLength"]),
                output_hash: hex32(&text(&event["outputHash"])),
                digest: hex32(&text(&event["digest"])),
            }),
            request_id: hex32(&text(&event["requestId"])),
            signature: EcdsaSignature {
                big_r_x: hex32(&text(&event["signature"]["bigR"]["x"])),
                big_r_y: hex32(&text(&event["signature"]["bigR"]["y"])),
                s: hex32(&text(&event["signature"]["s"])),
                recovery_id: event["signature"]["recoveryId"].as_u64().unwrap() as u8,
            },
            ..respond_request()
        }
    }

    /// The one call the built intent carries, decoded as the ledger's own `Intent`.
    fn sole_call(bytes: &[u8]) -> ContractCall<ProofPreimageMarker, DefaultDB> {
        let intent: ChainIntent = midnight_serialize::tagged_deserialize(&mut &bytes[..]).unwrap();
        assert_eq!(intent.ttl, Timestamp::from_secs(TTL));
        let actions: Vec<_> = intent.actions.iter_deref().cloned().collect();
        assert_eq!(actions.len(), 1, "one contract call");
        let ContractAction::Call(call) = &actions[0] else {
            panic!("the single action must be a call");
        };
        assert_eq!(hex::encode(call.address.0 .0), RESPONDER);
        assert!(call.guaranteed_transcript.is_some());
        assert!(call.fallible_transcript.is_none());
        (**call).clone()
    }

    #[test]
    fn a_respond_intent_emits_the_signature_the_request_carries() {
        let call = sole_call(&client().build_intent(&respond_request()).unwrap());
        assert_eq!(call.entry_point.0.as_slice(), b"respond");
        let mut payload = [0u8; MISC_PAYLOAD_LEN];
        hex::decode_to_slice(REQUEST_ID, &mut payload[0..32]).unwrap();
        payload[32..64].fill(0x11);
        payload[64..96].fill(0x22);
        payload[96..128].fill(0x33);
        payload[128] = 1;
        assert_eq!(
            emissions_of_call(&call).unwrap(),
            vec![Emission {
                kind: EmissionKind::SignatureResponded,
                payload,
            }]
        );
    }

    #[test]
    fn a_bidirectional_intent_emits_the_payload_the_compiled_contract_emits() {
        // The compiled responder's own emission for this event, captured by
        // `midnight-devtools`' `gen:api-parity-vectors`.
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/api-parity-vectors.json")).unwrap();
        let event = &fixtures["responseEvent"];
        let text = |value: &serde_json::Value| value.as_str().unwrap().to_string();
        let request = bidirectional_request();
        let call = sole_call(&client().build_intent(&request).unwrap());
        assert_eq!(call.entry_point.0.as_slice(), b"respondBidirectional");
        let payload: [u8; MISC_PAYLOAD_LEN] = hex::decode(text(&event["payload"]))
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            emissions_of_call(&call).unwrap(),
            vec![Emission {
                kind: EmissionKind::RespondBidirectional,
                payload,
            }]
        );
    }

    #[tokio::test]
    async fn a_contract_the_artifacts_do_not_prove_for_is_awaited_not_refused() {
        // The packaged respond key is another circuit's, so the deployed one differs:
        // an on-chain upgrade may still be landing, so the publish retries rather
        // than paying a failover that hits the same mismatch everywhere.
        let dir = managed_dir(|circuit, bytes| {
            if circuit == "respond" {
                let mut tampered = bytes;
                let last = tampered.len() - 1;
                tampered[last] ^= 1;
                tampered
            } else {
                bytes
            }
        });
        let client = client_over(dir, ScriptedChain::new(0, 0));
        let error = client.build(&respond_request()).await.unwrap_err();
        assert_eq!(
            crate::submit_error::refusal_code(&error),
            Some("deploy_mismatch"),
            "{error:#}"
        );
        assert!(is_retryable(&error), "{error:#}");

        let mut empty = Vec::new();
        midnight_serialize::tagged_serialize(&ContractState::<DefaultDB>::default(), &mut empty)
            .unwrap();
        let error = client
            .build(&IntentRequest {
                contract_state: empty,
                ..respond_request()
            })
            .await
            .unwrap_err();
        assert_eq!(
            crate::submit_error::refusal_code(&error),
            Some("deploy_mismatch"),
            "{error:#}"
        );
        assert!(is_retryable(&error), "{error:#}");
    }

    #[test]
    fn provers_refuse_a_directory_without_the_packaged_artifacts() {
        let dir = managed_dir(|_, bytes| bytes);
        std::fs::remove_file(dir.path().join("zkir/respondBidirectional.bzkir")).unwrap();
        let error = Provers::new(dir.path(), dir.path())
            .err()
            .expect("an artifact is missing");
        assert!(
            format!("{error:#}").contains("respondBidirectional.bzkir"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn the_publisher_sees_build_and_submit_failures_with_their_verdict() {
        let client = client();
        let built = client
            .build(&IntentRequest {
                contract_state: vec![0xff],
                ..respond_request()
            })
            .await
            .unwrap_err();
        let submitted = client.submit(&[0xff]).await.unwrap_err();
        for error in [built, submitted] {
            assert_eq!(
                crate::submit_error::refusal_code(&error),
                Some("bad_request")
            );
            assert!(
                error
                    .downcast_ref::<mpc_chain_integration_core::utils::retry::RpcFailure>()
                    .is_some(),
                "a classified failure carries its verdict: {error:#}"
            );
        }
        assert_eq!(
            *client.wallet.failures.lock().unwrap(),
            vec![false],
            "the wallet hears of the failed submit, from before it paid anything"
        );
    }

    #[test]
    fn the_wallet_hears_how_each_submit_ended() {
        let wallet = RecordingWallet::default();
        let landed = Ok(Submitted {
            tx_id: LedgerTxHash::from_bytes([0x00; 32]),
            dust_balance: 1,
        });
        report_submit(&wallet, &landed);
        report_submit(&wallet, &Err(SubmitError::WalletUnsynced("syncing".into())));
        report_submit(&wallet, &Err(SubmitError::StateConflict("refused".into())));
        report_submit(&wallet, &Err(SubmitError::WalletBusy("held".into())));
        // An empty wallet fails like any other, but implicates nothing.
        report_submit(&wallet, &Err(SubmitError::WalletUnfunded("empty".into())));
        // The throttled watch-exit shape (a_throttled_scan_read_exits_and_engages_the_gate):
        // reported for the reload, never a strike.
        report_submit(
            &wallet,
            &Err(SubmitError::Node {
                source: scan_read_rejected(429),
            }),
        );
        assert_eq!(wallet.landings.load(Ordering::SeqCst), 1, "one landing");
        assert_eq!(
            *wallet.failures.lock().unwrap(),
            vec![true, false, false, false],
            "every failure but an unsynced wallet, with whether it can strike"
        );
    }

    /// Each arm's error from its construction site in `post` reaches the wallet
    /// through the report `submit` runs for every outcome.
    #[tokio::test(start_paused = true)]
    async fn post_failures_strike_the_restored_wallet_by_their_class() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20)
                .refusing(SubmitRefusal::Refused("1010: Invalid Transaction".into())),
        );
        let error = client.post(5000).await.unwrap_err();
        assert!(matches!(error, SubmitError::StateConflict(_)), "{error}");
        report_submit(&client.wallet, &Err(error));
        assert_eq!(
            *client.wallet.failures.lock().unwrap(),
            [true],
            "the refusal strikes"
        );

        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20)
                .failing_read_with(11, scan_read_rejected(429))
                .failing_read_with(11, scan_read_rejected(429))
                .failing_read_with(11, scan_read_rejected(429)),
        );
        let error = client.post(5000).await.unwrap_err();
        assert!(matches!(error, SubmitError::Node { .. }), "{error:#}");
        report_submit(&client.wallet, &Err(error));
        assert_eq!(
            *client.wallet.failures.lock().unwrap(),
            [false],
            "the throttle escape never strikes"
        );

        let client = client_over(
            managed_dir(|_, bytes| bytes),
            // Block 14, at 1084, is the first past a 1080 TTL.
            ScriptedChain::new(10, 20),
        );
        let error = client.post(1080).await.unwrap_err();
        assert!(matches!(error, SubmitError::StateConflict(_)), "{error}");
        report_submit(&client.wallet, &Err(error));
        assert_eq!(
            *client.wallet.failures.lock().unwrap(),
            [true],
            "the expiry unlanded strikes"
        );
    }

    #[tokio::test]
    async fn a_submit_failing_before_the_wallet_pays_strikes_nothing() {
        let client = client();
        let intent = client.build(&respond_request()).await.unwrap();
        // The packaged keys are empty here, so proving the respond fails.
        client
            .submit(&intent)
            .await
            .expect_err("nothing can be proven");
        assert_eq!(*client.wallet.failures.lock().unwrap(), vec![false]);
    }

    #[tokio::test]
    async fn malformed_requests_are_refused_before_anything_is_built() {
        let cases: Vec<(&str, IntentRequest)> = vec![
            (
                "undecodable contract state",
                IntentRequest {
                    contract_state: vec![0xff],
                    ..respond_request()
                },
            ),
            (
                "undecodable ledger parameters",
                IntentRequest {
                    ledger_parameters: vec![0xff],
                    ..respond_request()
                },
            ),
        ];
        let client = client();
        for (case, request) in cases {
            let error = client.build(&request).await.unwrap_err();
            assert_eq!(
                crate::submit_error::refusal_code(&error),
                Some("bad_request"),
                "{case}: {error:#}"
            );
            assert!(
                !is_retryable(&error),
                "{case}: a malformed request must be terminal: {error:#}"
            );
        }
    }

    fn spent() -> Vec<DustNullifier> {
        vec![DustNullifier(midnight_transient_crypto::curve::Fr::from(
            7u64,
        ))]
    }

    /// Far past every scripted TTL in these tests' paused clock.
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(300)
    }

    #[tokio::test(start_paused = true)]
    async fn a_transaction_that_lands_is_answered_with_its_hash() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20).landing_at(13, Landing::Applied),
        );
        let landed = client.post(5000).await.unwrap();
        assert_eq!(landed, LedgerTxHash::from_bytes(TX_HASH));
        assert_eq!(*client.wallet.reserved.lock().unwrap(), vec![spent()]);
        assert_eq!(
            *client.wallet.reserved_until.lock().unwrap(),
            vec![Timestamp::from_secs(5000 + FINALITY_SLACK.as_secs())],
            "the reservation outlives the TTL by the finality slack"
        );
        assert!(client.wallet.released.lock().unwrap().is_empty());
        let reads: Vec<u64> = client
            .chain
            .landing_reads
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect();
        assert_eq!(
            reads,
            vec![11, 12, 13],
            "every block after the pin, in order, once"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_submit_releases_its_utxos() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20)
                .refusing(SubmitRefusal::Refused("1010: Invalid Transaction".into())),
        );
        let error = client.post(5000).await.unwrap_err();
        assert!(matches!(error, SubmitError::StateConflict(_)), "{error}");
        assert_eq!(*client.wallet.released.lock().unwrap(), vec![spent()]);
        assert!(client.chain.landing_reads.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unsent_transaction_releases_its_utxos_without_blaming_the_chain() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20)
                .refusing(SubmitRefusal::Unsent(anyhow::anyhow!("connection refused"))),
        );
        let error = client.post(5000).await.unwrap_err();
        assert!(matches!(error, SubmitError::Node { .. }), "{error}");
        assert_eq!(*client.wallet.released.lock().unwrap(), vec![spent()]);
        assert!(client.chain.landing_reads.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_runtime_without_the_call_is_a_contract_mismatch() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20).refusing(SubmitRefusal::Mismatch(anyhow::anyhow!(
                "send_mn_transaction did not match the node's metadata"
            ))),
        );
        let error = client.post(5000).await.unwrap_err();
        assert_eq!(*client.wallet.released.lock().unwrap(), vec![spent()]);

        let error = error.into_publish_error();
        assert_eq!(
            crate::submit_error::refusal_code(&error),
            Some("contract_mismatch"),
            "{error:#}"
        );
        assert!(
            !is_retryable(&error),
            "a node without the call must be terminal: {error:#}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswered_submit_is_still_watched_for() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20)
                .landing_at(12, Landing::Applied)
                .refusing(SubmitRefusal::Unanswered(anyhow::anyhow!(
                    "connection reset"
                ))),
        );
        let landed = client.post(5000).await.unwrap();
        assert_eq!(landed, LedgerTxHash::from_bytes(TX_HASH));
    }

    fn unanswered() -> SubmitRefusal {
        SubmitRefusal::Unanswered(anyhow::anyhow!("request timed out"))
    }

    /// The gaps between consecutive submits.
    fn gaps(submits: &[Instant]) -> Vec<Duration> {
        submits.windows(2).map(|pair| pair[1] - pair[0]).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswered_submit_is_sent_again_ever_later_until_the_node_answers() {
        // Block 25 is the scan's 15th ask, 28 s in.
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 30)
                .landing_at(25, Landing::Applied)
                .refusing(unanswered())
                .refusing(unanswered()),
        );
        let landed = client.post(5000).await.unwrap();
        assert_eq!(landed, LedgerTxHash::from_bytes(TX_HASH));
        let submits = client.chain.submits();
        assert_eq!(submits.len(), 3, "sent until the third was answered");
        assert_eq!(gaps(&submits), [RESEND_DELAY, RESEND_DELAY * 2]);
        assert!(client.wallet.released.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_resend_the_node_takes_is_not_sent_again() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 30)
                .landing_at(25, Landing::Applied)
                .refusing(unanswered()),
        );
        client.post(5000).await.unwrap();
        assert_eq!(client.chain.submits().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_resend_that_could_not_be_sent_is_sent_again() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 30)
                .landing_at(25, Landing::Applied)
                .refusing(unanswered())
                .refusing(SubmitRefusal::Unsent(anyhow::anyhow!(
                    "reading the node's runtime"
                ))),
        );
        client.post(5000).await.unwrap();
        assert_eq!(client.chain.submits().len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn resends_to_a_node_that_never_answers_back_off_to_their_cap() {
        // The head stalls inside the TTL, so the wait runs to its deadline.
        let mut chain = ScriptedChain::new(10, 12);
        for _ in 0..20 {
            chain = chain.refusing(unanswered());
        }
        let client = client_over(managed_dir(|_, bytes| bytes), chain);
        let error = client
            .post_within(5000, Instant::now() + Duration::from_secs(300))
            .await
            .unwrap_err();
        assert!(matches!(error, SubmitError::Ambiguous(_)), "{error}");
        let secs = |s| Duration::from_secs(s);
        assert_eq!(
            gaps(&client.chain.submits()),
            [
                secs(6),
                secs(12),
                secs(24),
                secs(48),
                secs(60),
                secs(60),
                secs(60)
            ]
        );
        tokio::time::sleep(MAX_RESEND_DELAY * 2).await;
        assert_eq!(
            client.chain.submits().len(),
            8,
            "nothing is sent past the deadline"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_resend_is_not_sent_again_and_the_scan_decides() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20)
                .landing_at(19, Landing::Applied)
                .refusing(unanswered())
                .refusing(SubmitRefusal::Refused(
                    "1012: Transaction is temporarily banned".into(),
                )),
        );
        let landed = client.post(5000).await.unwrap();
        assert_eq!(landed, LedgerTxHash::from_bytes(TX_HASH));
        assert_eq!(client.chain.submits().len(), 2);
        assert!(client.wallet.released.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_resend_the_node_cannot_carry_is_not_sent_again_and_the_scan_decides() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            // Block 25 is the scan's 15th ask, 28 s in: room for further resends.
            ScriptedChain::new(10, 30)
                .landing_at(25, Landing::Applied)
                .refusing(unanswered())
                .refusing(SubmitRefusal::Mismatch(anyhow::anyhow!(
                    "send_mn_transaction did not match the node's metadata"
                ))),
        );
        let landed = client.post(5000).await.unwrap();
        assert_eq!(landed, LedgerTxHash::from_bytes(TX_HASH));
        assert_eq!(client.chain.submits().len(), 2);
        assert!(client.wallet.released.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_answered_submit_is_not_sent_again() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20).landing_at(19, Landing::Applied),
        );
        client.post(5000).await.unwrap();
        assert_eq!(client.chain.submits().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transaction_the_node_never_answers_for_still_expires() {
        // Block 26, at 1156, is the first past a 1150 TTL, 30 s in.
        let mut chain = ScriptedChain::new(10, 30);
        for _ in 0..10 {
            chain = chain.refusing(unanswered());
        }
        let client = client_over(managed_dir(|_, bytes| bytes), chain);
        let error = client.post(1150).await.unwrap_err();
        assert!(matches!(error, SubmitError::StateConflict(_)), "{error}");
        assert_eq!(*client.wallet.released.lock().unwrap(), vec![spent()]);
        let submits = client.chain.submits();
        assert_eq!(
            submits.len(),
            3,
            "the first and two resends until it expired"
        );
        assert_eq!(gaps(&submits), [RESEND_DELAY, RESEND_DELAY * 2]);
        tokio::time::sleep(MAX_RESEND_DELAY * 2).await;
        assert_eq!(
            client.chain.submits().len(),
            3,
            "nothing is sent once the wait has ended"
        );
    }

    /// A chain on the clock: block `10 + s / 6` is final `s` seconds in, and the
    /// transaction lands in block `lands`. Reads answer at once; every submit is held
    /// for the 10 s request timeout and goes unanswered.
    struct ClockChain {
        start: Instant,
        lands: u64,
        submits: Mutex<Vec<Instant>>,
    }

    #[async_trait]
    impl PinnedReads for ClockChain {
        async fn finalized_head(&self) -> anyhow::Result<BlockHash> {
            Ok(block_hash(10 + self.start.elapsed().as_secs() / 6))
        }

        async fn contract_state(
            &self,
            _: &MidnightAddress,
            _: &BlockHash,
        ) -> anyhow::Result<Option<Vec<u8>>> {
            unimplemented!("the post path reads no contract state")
        }

        async fn ledger_parameters(&self, _: &BlockHash) -> anyhow::Result<Vec<u8>> {
            Ok(ledger_parameters())
        }
    }

    #[async_trait]
    impl SubmitChain for ClockChain {
        async fn block_number(&self, at: &BlockHash) -> anyhow::Result<u64> {
            Ok(block_number_of(at))
        }

        async fn block_hash_at(&self, number: u64) -> anyhow::Result<Option<BlockHash>> {
            Ok(Some(block_hash(number)))
        }

        async fn block_time(&self, at: &BlockHash) -> anyhow::Result<Timestamp> {
            Ok(Timestamp::from_secs(1000 + 6 * block_number_of(at)))
        }

        async fn submit(&self, _transaction: &[u8]) -> Result<(), SubmitRefusal> {
            self.submits.lock().unwrap().push(Instant::now());
            tokio::time::sleep(Duration::from_secs(10)).await;
            Err(unanswered())
        }

        async fn landing(
            &self,
            at: &BlockHash,
            _tx_hash: LedgerTxHash,
        ) -> anyhow::Result<Option<Landing>> {
            Ok((block_number_of(at) == self.lands).then_some(Landing::Applied))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_resend_held_up_by_the_node_neither_delays_the_scan_nor_outlives_the_deadline() {
        // Block 13 is final 18 s in; the second budget ends 21 s in.
        for budget in [300, 21] {
            let start = Instant::now();
            let dir = managed_dir(|_, bytes| bytes);
            let client = NativeIntentClient::new(
                Arc::new(ClockChain {
                    start,
                    lands: 13,
                    submits: Mutex::default(),
                }),
                RecordingWallet::default(),
                Arc::new(Provers::new(dir.path(), dir.path()).unwrap()),
                NetworkId::Undeployed,
                Duration::from_secs(420),
            );
            let landed = client
                .post(
                    b"tx",
                    LedgerTxHash::from_bytes(TX_HASH),
                    &spent(),
                    10,
                    Timestamp::from_secs(5000),
                    start + Duration::from_secs(budget),
                )
                .await
                .unwrap_or_else(|error| panic!("budget {budget} s: {error}"));
            assert_eq!(landed, LedgerTxHash::from_bytes(TX_HASH));
            assert!(
                start.elapsed() <= Duration::from_secs(18) + LANDING_POLL,
                "budget {budget} s: seen {:?} in",
                start.elapsed()
            );
            let sent = client.chain.submits.lock().unwrap().len();
            tokio::time::sleep(MAX_RESEND_DELAY * 2).await;
            assert_eq!(
                client.chain.submits.lock().unwrap().len(),
                sent,
                "budget {budget} s: nothing is sent once the wait has ended"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_partial_success_answers_the_publish() {
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20).landing_at(12, Landing::PartialSuccess),
        );
        let landed = client.post(5000).await.unwrap();
        assert_eq!(landed, LedgerTxHash::from_bytes(TX_HASH));
        assert!(
            client.wallet.released.lock().unwrap().is_empty(),
            "the guaranteed segment spent the DUST; the replay ends the reservation"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_settle_log_names_which_landing_the_watch_ended_in() {
        let recorder = EventRecorder::default();
        let _registration_guard = tracing::subscriber::set_default(tracing_subscriber::registry());
        let subscriber = tracing_subscriber::registry().with(recorder.clone());
        let _subscriber_guard = tracing::subscriber::set_default(subscriber);
        for landing in [Landing::Applied, Landing::PartialSuccess] {
            let client = client_over(
                managed_dir(|_, bytes| bytes),
                ScriptedChain::new(10, 20).landing_at(12, landing),
            );
            assert_eq!(
                client.post(5000).await.unwrap(),
                LedgerTxHash::from_bytes(TX_HASH)
            );
        }
        let settles: Vec<RecordedFields> = recorder
            .snapshot()
            .into_iter()
            .filter(|fields| fields.contains_key("settled"))
            .collect();
        assert_eq!(settles.len(), 2, "{settles:?}");
        for (fields, landed, outcome) in [
            (&settles[0], "Some(Applied)", "Landed(Applied)"),
            (
                &settles[1],
                "Some(PartialSuccess)",
                "Landed(PartialSuccess)",
            ),
        ] {
            assert_eq!(
                fields.get("landed").map(String::as_str),
                Some(landed),
                "{fields:?}"
            );
            assert_eq!(
                fields.get("outcome").map(String::as_str),
                Some(outcome),
                "{fields:?}"
            );
        }
    }

    #[test]
    fn the_fee_ctime_is_a_time_the_replay_has_fully_seen() {
        let at = Timestamp::from_secs;
        // The indexer behind the finalized head: its newest block bounds ctime.
        assert_eq!(fee_ctime(at(100), at(90), at(80)), at(90));
        // The indexer ahead of finality: the finalized head bounds it.
        assert_eq!(fee_ctime(at(100), at(110), at(80)), at(100));
        // The replay holds an event past both: ctime may not precede it.
        assert_eq!(fee_ctime(at(100), at(110), at(105)), at(105));
    }

    #[tokio::test]
    async fn the_fee_ctime_reads_the_head_the_indexer_and_the_caught_up_replay() {
        // Block 10 is at 1060.
        let mut client = client();
        client.wallet.indexed_secs = 1050;
        let deadline = deadline();
        let ctime = client
            .fee_ctime_at(&block_hash(10), deadline)
            .await
            .unwrap();
        assert_eq!(ctime, Timestamp::from_secs(1050), "the indexer bounds it");

        // The replay was behind the indexer, and delivered an event past it once waited for.
        client.wallet.sync_secs = AtomicU64::new(1040);
        client.wallet.caught_up_secs = Some(1055);
        let ctime = client
            .fee_ctime_at(&block_hash(10), deadline)
            .await
            .unwrap();
        assert_eq!(
            ctime,
            Timestamp::from_secs(1055),
            "the replay, once waited for"
        );
        assert_eq!(
            *client.wallet.waited_until.lock().unwrap(),
            vec![deadline - WORK_RESERVE; 2],
            "the wait leaves the work its reserve"
        );
    }

    #[test]
    fn the_proven_fee_is_merged_and_checked_to_pay_before_posting() {
        let local = replayed();
        let ctime = local.sync_time;
        let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
        let mut rng = StdRng::seed_from_u64(7);
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
        let fee = plan.tx.mock_prove().unwrap();

        let (bytes, tx_hash) = paid_transaction(&base, &fee, &INITIAL_PARAMETERS).unwrap();
        let posted: SealedTx = midnight_serialize::tagged_deserialize(&mut &bytes[..]).unwrap();
        assert_eq!(posted.transaction_hash().0 .0, *tx_hash.as_bytes());
        assert_eq!(
            base.merge(&fee).unwrap().transaction_hash().0 .0,
            *tx_hash.as_bytes(),
            "the posted transaction is the respond and its fee"
        );

        // Priced higher than the plan was: the fee no longer pays.
        let mut dearer = INITIAL_PARAMETERS.clone();
        dearer.fee_prices.overall_price =
            midnight_base_crypto::cost_model::FixedPoint::from_u64_div(1 << 40, 1);
        let error = paid_transaction(&base, &fee, &dearer).unwrap_err();
        assert!(matches!(error, SubmitError::Internal(_)), "{error}");
        assert!(format!("{error}").contains("short of its fee"), "{error}");
    }

    #[test]
    fn the_fee_ttl_leaves_the_landing_its_finality_slack() {
        let secs = Duration::from_secs;
        assert_eq!(fee_ttl(secs(420)), Some(FEE_TTL));
        assert_eq!(fee_ttl(secs(100)), Some(secs(40)));
        assert_eq!(fee_ttl(secs(90)), Some(MIN_FEE_TTL));
        assert_eq!(fee_ttl(secs(89)), None);
        assert_eq!(fee_ttl(secs(0)), None);
    }

    #[tokio::test]
    async fn proving_past_the_deadline_is_a_proving_timeout() {
        // Already due: the proof is still running when the deadline is checked.
        let error = prove_blocking(Instant::now(), || async {
            std::thread::sleep(Duration::from_millis(200));
            Ok::<_, std::convert::Infallible>(())
        })
        .await
        .unwrap_err();
        assert!(matches!(error, SubmitError::ProvingTimeout(_)), "{error}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_transaction_past_its_ttl_unlanded_releases_its_utxos() {
        // Block 14 is at 1084: past a 1080 TTL. At exactly 1084 the ledger still
        // takes the intent (it expires only when the TTL is below the block time),
        // so block 15, at 1090, is the first past it.
        for ttl in [1080, 1084] {
            let client = client_over(managed_dir(|_, bytes| bytes), ScriptedChain::new(10, 20));
            let error = client.post(ttl).await.unwrap_err();
            assert!(matches!(error, SubmitError::StateConflict(_)), "{error}");
            assert_eq!(*client.wallet.released.lock().unwrap(), vec![spent()]);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_transaction_unseen_by_the_deadline_stays_reserved_and_is_ambiguous() {
        // The head stalls at 12, inside the TTL, so the outcome stays unknown.
        let client = client_over(managed_dir(|_, bytes| bytes), ScriptedChain::new(10, 12));
        let error = client
            .post_within(5000, Instant::now() + Duration::from_secs(30))
            .await
            .unwrap_err();
        assert!(matches!(error, SubmitError::Ambiguous(_)), "{error}");
        assert!(
            error
                .to_string()
                .contains("a later publisher retry may post the response again"),
            "{error}"
        );
        assert!(client.wallet.released.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_terminal_scan_read_holds_reservations_and_is_not_retryable() {
        // Block 13's landing read answers 403: `post` reports it as a node error
        // and keeps the reservation for the caller's retry policy.
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20)
                .failing_read_with(13, scan_read_rejected(403))
                .landing_at(13, Landing::Applied),
        );
        let error = client.post(5000).await.unwrap_err();
        assert!(matches!(error, SubmitError::Node { .. }), "{error:#}");
        assert!(client.wallet.released.lock().unwrap().is_empty());
        let published = SubmitError::into_publish_error(error);
        assert!(!is_retryable(&published), "{published:#}");
        let carrier = published
            .chain()
            .find_map(|cause| cause.downcast_ref::<RpcFailure>())
            .unwrap_or_else(|| panic!("the exit carries its carrier: {published:#}"));
        assert_eq!(
            carrier.status(),
            StatusCode::from_u16(403).ok(),
            "{published:#}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_early_exit_stops_the_resends_of_an_unanswered_submit() {
        // The exit drops the resend task: past its 6 s delay, no second submit.
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20)
                .refusing(SubmitRefusal::Unanswered(anyhow::anyhow!("no answer")))
                .failing_read_with(13, scan_read_rejected(403)),
        );
        let error = client.post(5000).await.unwrap_err();
        assert!(matches!(error, SubmitError::Node { .. }), "{error:#}");
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert_eq!(
            client.chain.submits().len(),
            1,
            "the resend task died with the watch, not with the budget"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_throttled_scan_read_exits_and_engages_the_gate() {
        // A standing 429 — three consecutive scans — escapes the watch: only a
        // returned error reaches the gate wrapper.
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20)
                .failing_read_with(11, scan_read_rejected(429))
                .failing_read_with(11, scan_read_rejected(429))
                .failing_read_with(11, scan_read_rejected(429)),
        );
        let error = client.post(5000).await.unwrap_err();
        assert!(matches!(error, SubmitError::Node { .. }), "{error:#}");
        assert!(
            client.wallet.released.lock().unwrap().is_empty(),
            "the escape holds the reservation like the deadline exit"
        );
        let published = SubmitError::into_publish_error(error);
        assert!(is_retryable(&published), "{published:#}");
        let carrier = published
            .chain()
            .find_map(|cause| cause.downcast_ref::<RpcFailure>())
            .unwrap_or_else(|| panic!("the exit carries its carrier: {published:#}"));
        assert_eq!(
            carrier.status(),
            StatusCode::from_u16(429).ok(),
            "{published:#}"
        );

        let gate =
            SharedBackoff::with_cooldowns(Duration::from_millis(300), Duration::from_millis(600));
        let failed = run_gated(&gate, "midnight publish", async { Err::<(), _>(published) })
            .await
            .unwrap_err();
        assert_eq!(
            failed
                .chain()
                .find_map(|cause| cause.downcast_ref::<RpcFailure>())
                .unwrap()
                .status(),
            StatusCode::from_u16(429).ok(),
            "the error returns unchanged: {failed:#}"
        );
        assert!(
            gate.remaining() > Duration::ZERO,
            "the typed 429 engaged the shared cooldown"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_standing_read_throttle_reposts_per_attempt() {
        // The accepted cost of the throttle escape: one fresh fee transaction per
        // gate-paced attempt, reservations held, where the old watch kept polling.
        let client = client_over(
            managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20)
                .failing_read_with(11, scan_read_rejected(429))
                .failing_read_with(11, scan_read_rejected(429))
                .failing_read_with(11, scan_read_rejected(429))
                .failing_read_with(11, scan_read_rejected(429))
                .failing_read_with(11, scan_read_rejected(429))
                .failing_read_with(11, scan_read_rejected(429)),
        );
        for _ in 0..2 {
            let error = client.post(5000).await.unwrap_err();
            assert!(matches!(error, SubmitError::Node { .. }), "{error:#}");
        }
        assert_eq!(
            client.chain.submits().len(),
            2,
            "each attempt posts a fresh fee transaction"
        );
        assert_eq!(
            *client.wallet.reserved.lock().unwrap(),
            vec![spent(), spent()],
            "every attempt reserves UTXOs none release"
        );
        assert!(client.wallet.released.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
mod bench {
    //! What each proof costs in process. `MIDNIGHT_BENCH_ARTIFACTS` is the package's
    //! `dist/managed`, `MIDNIGHT_BENCH_ZK_PARAMS` the parameter store, and
    //! `MIDNIGHT_BENCH_RUNS` the samples per step (10). Prints one JSON line per
    //! sample; proving wants `--release`.

    use super::tests::{bidirectional_request, respond_request, RecordingWallet};
    use super::*;
    use crate::chain_mock::ScriptedChain;
    use crate::funding::plan_fee;
    use crate::funding::tests::{funded_key, replayed};
    use midnight_ledger_v9::structure::INITIAL_PARAMETERS;

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs MIDNIGHT_BENCH_ARTIFACTS and MIDNIGHT_BENCH_ZK_PARAMS"]
    async fn proving_cost() {
        let runs: usize = std::env::var("MIDNIGHT_BENCH_RUNS")
            .map(|runs| runs.parse().unwrap())
            .unwrap_or(10);
        let client = NativeIntentClient::new(
            Arc::new(ScriptedChain::new(0, 0)),
            RecordingWallet::default(),
            Arc::new(
                Provers::new(
                    env("MIDNIGHT_BENCH_ARTIFACTS"),
                    env("MIDNIGHT_BENCH_ZK_PARAMS"),
                )
                .unwrap(),
            ),
            NetworkId::Undeployed,
            Duration::from_secs(3600),
        );
        let deadline = Instant::now() + Duration::from_secs(3600);
        let sample = |step: &str, run: usize, took: Duration, extra: serde_json::Value| {
            println!(
                "{}",
                serde_json::json!({ "step": step, "run": run, "ms": took.as_secs_f64() * 1e3, "extra": extra })
            );
        };

        let mut base = None;
        for request in [respond_request(), bidirectional_request()] {
            let intent = client.build_intent(&request).unwrap();
            for run in 0..runs {
                let preimage = midnight_serialize::tagged_deserialize(&mut &intent[..]).unwrap();
                let started = Instant::now();
                let sealed = client.prove_respond(preimage, deadline).await.unwrap();
                sample(
                    request.circuit.name(),
                    run,
                    started.elapsed(),
                    serde_json::Value::Null,
                );
                base.get_or_insert(sealed);
            }
        }

        let base = base.unwrap();
        let (key, local) = (funded_key(), replayed());
        let ctime = local.sync_time;
        let ttl = Timestamp::from_secs(ctime.to_secs() + 180);
        let mut rng = StdRng::seed_from_u64(7);
        for run in 0..runs {
            let started = Instant::now();
            let plan = plan_fee(
                &key,
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
            sample(
                "price_fee",
                run,
                started.elapsed(),
                serde_json::json!({ "spends": plan.spent.len() }),
            );
            let started = Instant::now();
            let fee = client.prove_fee(plan.tx, deadline).await.unwrap();
            sample("prove_fee", run, started.elapsed(), serde_json::Value::Null);
            let merged = base.merge(&fee).unwrap();
            let owed = merged.fees(&INITIAL_PARAMETERS, false).unwrap();
            assert_eq!(
                dust_deficit(&merged, owed).unwrap(),
                0,
                "the proven fee pays"
            );
        }
    }
}

#[cfg(test)]
mod live {
    //! Against a running stack: `MIDNIGHT_LIVE_*` name a node, its indexer, a deployed
    //! responder, a funded seed and the artifact directories. Proving wants `--release`.

    use super::*;
    use crate::config::{MidnightConfig, PublisherConfig};
    use crate::dust_feed::IndexerDustEvents;
    use crate::funding::{dust_secret_key, parse_seed, FundingWallet};
    use crate::rpc::MidnightPublisherRpc;
    use crate::types::MidnightAddress;
    use minocrab_publisher::{Attestation, EcdsaSignature};

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a running Midnight stack named by MIDNIGHT_LIVE_*"]
    async fn a_respond_and_a_bidirectional_respond_land_and_apply() {
        let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
        let config = MidnightConfig {
            node_url: env("MIDNIGHT_LIVE_NODE_URL").parse().unwrap(),
            // Unread: this test only posts.
            central_address: MidnightAddress::from_bytes([0; 32]),
            responder_address: MidnightAddress::from_hex(&env("MIDNIGHT_LIVE_RESPONDER")).unwrap(),
            publisher: PublisherConfig {
                funding_seed: env("MIDNIGHT_LIVE_SEED"),
                indexer_ws_url: env("MIDNIGHT_LIVE_INDEXER_WS_URL").parse().unwrap(),
                contract_artifacts_dir: env("MIDNIGHT_LIVE_ARTIFACTS").into(),
                zk_params_dir: env("MIDNIGHT_LIVE_ZK_PARAMS").into(),
                ..Default::default()
            },
            rpc: Default::default(),
            indexer: Default::default(),
        };
        config.validate().unwrap();
        let rpc = Arc::new(MidnightPublisherRpc::connect(&config).await.unwrap());
        let key = dust_secret_key(&parse_seed(&config.publisher.funding_seed).unwrap()).unwrap();
        let wallet = FundingWallet::start(
            key,
            Arc::new(IndexerDustEvents::new(
                config.publisher.indexer_ws_url.clone(),
            )),
            None,
        );
        let provers = Arc::new(
            Provers::new(
                &config.publisher.contract_artifacts_dir,
                &config.publisher.zk_params_dir,
            )
            .unwrap(),
        );
        let client = NativeIntentClient::new(
            rpc.clone(),
            wallet,
            provers,
            rpc.network_id(),
            config.publisher.submit_timeout,
        );
        let responder = config.responder_address;
        let bidirectional = RespondCircuit::RespondBidirectional(Attestation {
            block_height: 123_456,
            output_kind: 0,
            serialized_output_length: 32,
            output_hash: [0x44; 32],
            digest: [0x55; 32],
        });
        for circuit in [
            RespondCircuit::Respond,
            bidirectional,
            RespondCircuit::Respond,
        ] {
            let head = rpc.finalized_head().await.unwrap();
            let state = rpc
                .contract_state(&responder, &head)
                .await
                .unwrap()
                .unwrap();
            let parameters = rpc.ledger_parameters(&head).await.unwrap();
            let request = IntentRequest {
                circuit,
                contract_address: config.responder_address,
                request_id: rand::random(),
                signature: EcdsaSignature {
                    big_r_x: [0x11; 32],
                    big_r_y: [0x22; 32],
                    s: [0x33; 32],
                    recovery_id: 1,
                },
                contract_state: state,
                ledger_parameters: parameters,
                ttl_seconds: mpc_utils::time::current_unix_timestamp() + 600,
            };
            let started = std::time::Instant::now();
            let intent = client.build(&request).await.unwrap();
            let landed = client
                .submit(&intent)
                .await
                .unwrap_or_else(|error| panic!("{}: {error:#}", circuit.name()));
            println!(
                "{}: landed {} in {:?}",
                circuit.name(),
                landed.tx_id,
                started.elapsed()
            );
        }
    }
}
