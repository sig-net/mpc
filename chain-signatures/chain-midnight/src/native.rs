//! Builds, proves, pays for and posts respond intents in process.
//!
//! The call comes from `minocrab-publisher`, which writes the singleton's transcript
//! and proves it under the contract's packaged keys with zkir v3. The fee is a second
//! intent spending the funding wallet's DUST, proven with the ledger's own zkir v2
//! prover. Both halves are sealed separately and merged, the way the Midnight wallet
//! SDK finalizes a balanced transaction.
//!
//! A submit has one budget, `PublisherConfig::submit_timeout`, from the first wait to
//! the finalized landing.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use midnight_base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use midnight_base_crypto::hash::HashOutput;
use midnight_base_crypto::time::Timestamp;
use midnight_coin_structure::contract::ContractAddress;
use midnight_ledger_v9::dust::{DustNullifier, DustResolver, DUST_EXPECTED_FILES};
use midnight_ledger_v9::structure::LedgerParameters;
use midnight_onchain_runtime::cost_model::INITIAL_COST_MODEL;
use midnight_onchain_state::state::ContractState;
use midnight_storage::DefaultDB;
use minocrab_publisher::intent::{build_intent, preimage_tx, PreimageIntent};
use minocrab_publisher::{
    Attestation, Deployment, EcdsaSignature, InProcessProver, ManagedDir, SignerResolver,
};
use rand::rngs::StdRng;
use rand::{Rng as _, SeedableRng as _};
use tokio::time::Instant;

use crate::funding::{dust_deficit, FeePayer, SealedTx, UnprovenTx};
use crate::intent::{IntentRequest, Submitted, WireAttestation, WireSignature};
use crate::publisher::IntentClient;
use crate::rpc::{Landing, PinnedReads, SubmitRefusal};
use crate::submit_error::SubmitError;

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
const LANDING_POLL: Duration = Duration::from_secs(2);

/// What the submit path needs from the node, beyond the pinned reads.
#[async_trait]
pub(crate) trait SubmitChain: PinnedReads {
    async fn block_number(&self, at_hash_0x: &str) -> anyhow::Result<u64>;
    async fn block_hash_at(&self, number: u64) -> anyhow::Result<Option<String>>;
    /// The block's `Timestamp::Now`, in whole seconds.
    async fn block_time(&self, at_hash_0x: &str) -> anyhow::Result<Timestamp>;
    async fn submit(&self, transaction: &[u8]) -> Result<(), SubmitRefusal>;
    /// The status the block reports for the ledger transaction `tx_hash`, if it holds it.
    async fn landing(&self, at_hash_0x: &str, tx_hash: [u8; 32])
        -> anyhow::Result<Option<Landing>>;
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
        let provider = |expected: Vec<_>| -> anyhow::Result<MidnightDataProvider> {
            let mut provider =
                MidnightDataProvider::new(FetchMode::OnDemand, OutputMode::Log, expected)
                    .context("opening the zero-knowledge parameter store")?;
            provider.dir = zk_params.clone();
            Ok(provider)
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
            params: provider(vec![])?,
            dust: DustResolver(provider(DUST_EXPECTED_FILES.to_vec())?),
        })
    }
}

pub(crate) struct NativeIntentClient<W, C> {
    chain: Arc<C>,
    wallet: W,
    provers: Arc<Provers>,
    network_id: String,
    submit_timeout: Duration,
}

impl<W: FeePayer, C: SubmitChain> NativeIntentClient<W, C> {
    pub(crate) fn new(
        chain: Arc<C>,
        wallet: W,
        provers: Arc<Provers>,
        network_id: impl Into<String>,
        submit_timeout: Duration,
    ) -> Self {
        Self {
            chain,
            wallet,
            provers,
            network_id: network_id.into(),
            submit_timeout,
        }
    }

    fn build_intent(&self, request: &IntentRequest) -> Result<Vec<u8>, SubmitError> {
        let address = ContractAddress(HashOutput(hex32(
            "contractAddress",
            &request.contract_address,
        )?));
        let request_id = hex32("requestId", &request.request_id)?;
        let signature = parse_signature(&request.signature)?;
        let state: ContractState<DefaultDB> = midnight_serialize::tagged_deserialize(
            &mut &hex_bytes("contractState", &request.contract_state)?[..],
        )
        .map_err(|error| {
            SubmitError::BadRequest(format!("contractState did not decode: {error}"))
        })?;
        let parameters: LedgerParameters = midnight_serialize::tagged_deserialize(
            &mut &hex_bytes("ledgerParameters", &request.ledger_parameters)?[..],
        )
        .map_err(|error| {
            SubmitError::BadRequest(format!("ledgerParameters did not decode: {error}"))
        })?;

        let circuit = request.circuit;
        let packaged = self
            .provers
            .managed
            .verifier_key_hash(circuit)
            .map_err(|error| SubmitError::ContractMismatch(error.to_string()))?;
        let deployment = Deployment::new(address, [(circuit.to_string(), packaged)]);
        deployment
            .check_deployed(&state)
            .map_err(|error| SubmitError::ContractMismatch(error.to_string()))?;

        let call = match (circuit, &request.attestation) {
            ("respond", None) => {
                minocrab_publisher::respond::<DefaultDB>(&deployment, &request_id, &signature)
            }
            ("respondBidirectional", Some(attestation)) => {
                minocrab_publisher::respond_bidirectional::<DefaultDB>(
                    &deployment,
                    &request_id,
                    &parse_attestation(attestation)?,
                    &signature,
                )
            }
            ("respond" | "respondBidirectional", _) => {
                return Err(SubmitError::BadRequest(
                    "attestation is required only for respondBidirectional".to_string(),
                ))
            }
            (other, _) => {
                return Err(SubmitError::BadRequest(format!(
                    "unknown circuit `{other}`"
                )))
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

        let head = self.chain.finalized_head().await.map_err(internal)?;
        let parameters: LedgerParameters = midnight_serialize::tagged_deserialize(
            &mut &self
                .chain
                .ledger_parameters(&head)
                .await
                .map_err(internal)?[..],
        )
        .map_err(|error| {
            SubmitError::Internal(format!("ledger parameters did not decode: {error}"))
        })?;
        let head_number = self.chain.block_number(&head).await.map_err(internal)?;
        let head_time = self.chain.block_time(&head).await.map_err(internal)?;
        let indexed_time = self.wallet.indexed_time().await?;
        // Events indexed up to `indexed_time` may still be on their way to the replay.
        self.wallet
            .ready_by(deadline.checked_sub(WORK_RESERVE).unwrap_or(deadline))
            .await?;
        let ctime = fee_ctime(head_time, indexed_time, self.wallet.sync_time());

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
            &base,
            &parameters,
            ctime,
            ttl,
            &self.network_id,
            &mut StdRng::from_entropy(),
        )?;
        let price_fee = stage.elapsed();
        let fee_tx = plan.tx;
        let stage = Instant::now();
        let fee_sealed = self.prove_fee(fee_tx, deadline).await?;
        let prove_fee = stage.elapsed();
        let transaction = base
            .merge(&fee_sealed)
            .map_err(|error| SubmitError::Internal(format!("merging the fee: {error:?}")))?;
        let fee = transaction.fees(&parameters, false).map_err(|error| {
            SubmitError::Internal(format!("pricing the transaction: {error:?}"))
        })?;
        let short = dust_deficit(&transaction, fee)?;
        if short > 0 {
            return Err(SubmitError::Internal(format!(
                "the proven transaction is {short} SPECKS short of its fee; nothing was posted"
            )));
        }
        let tx_hash = transaction.transaction_hash().0 .0;
        let mut bytes = Vec::new();
        midnight_serialize::tagged_serialize(&transaction, &mut bytes).map_err(|error| {
            SubmitError::Internal(format!("serializing the transaction: {error}"))
        })?;

        tracing::info!(
            fee = plan.fee,
            tx_hash = %hex::encode(tx_hash),
            ?wallet_wait,
            ?prove_respond,
            ?price_fee,
            ?prove_fee,
            before_post = ?started.elapsed(),
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

    /// The respond call proven under the packaged contract keys (zkir v3).
    async fn prove_respond(
        &self,
        intent: PreimageIntent<DefaultDB>,
        deadline: Instant,
    ) -> Result<SealedTx, SubmitError> {
        let respond = preimage_tx(&self.network_id, RESPOND_SEGMENT, intent);
        let provers = self.provers.clone();
        let proven = prove_blocking(deadline, move || {
            let provers = provers;
            async move {
                let prover = InProcessProver {
                    rng: StdRng::from_entropy(),
                    resolver: &provers.contract,
                    params: &provers.params,
                };
                respond.prove(prover, &INITIAL_COST_MODEL).await
            }
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
        let proven = prove_blocking(deadline, move || {
            let provers = provers;
            async move {
                let prover = midnight_zkir::LocalProvingProvider {
                    rng: StdRng::from_entropy(),
                    resolver: &provers.dust,
                    params: &provers.params,
                };
                fee_tx.prove(prover, &INITIAL_COST_MODEL).await
            }
        })
        .await?;
        Ok(proven.seal(StdRng::from_entropy()))
    }

    /// Posts a paid transaction and waits for it: the UTXOs it spends stay reserved
    /// until it lands, the node refuses or never receives it, or a minute past its
    /// TTL. An ambiguous outcome comes no earlier than that minute, so the retry may
    /// plan the same UTXOs; if this transaction landed after all, the node refuses
    /// that spend.
    async fn post(
        &self,
        bytes: &[u8],
        tx_hash: [u8; 32],
        spent: &[DustNullifier],
        after: u64,
        ttl: Timestamp,
        deadline: Instant,
    ) -> Result<String, SubmitError> {
        self.wallet.reserve(
            spent,
            Timestamp::from_secs(ttl.to_secs() + FINALITY_SLACK.as_secs()),
        );
        let started = Instant::now();
        match self.chain.submit(bytes).await {
            Ok(()) => {}
            Err(SubmitRefusal::Refused(reason)) => {
                self.wallet.release(spent);
                return Err(SubmitError::StateConflict(format!(
                    "the node refused the transaction: {reason}; nothing was posted"
                )));
            }
            Err(SubmitRefusal::Unsent(error)) => {
                self.wallet.release(spent);
                return Err(SubmitError::Internal(format!(
                    "the transaction could not be sent: {error:#}; nothing was posted"
                )));
            }
            Err(SubmitRefusal::Unanswered(error)) => {
                tracing::warn!(
                    ?error,
                    tx_hash = %hex::encode(tx_hash),
                    "midnight: submit unanswered; watching for the transaction"
                );
            }
        }
        let submitted = started.elapsed();
        let landing = self.await_landing(tx_hash, after, ttl, deadline).await;
        tracing::info!(
            tx_hash = %hex::encode(tx_hash),
            ?submitted,
            settled = ?started.elapsed(),
            outcome = ?landing,
            "midnight: respond settled"
        );
        match landing {
            Ok(Landing::Applied) => Ok(hex::encode(tx_hash)),
            // The DUST spends sit in the guaranteed segment, so they were applied:
            // the reservation ends when the replay sees them spent.
            Ok(Landing::PartialSuccess) => Err(SubmitError::StateConflict(format!(
                "transaction {} landed with a failed segment, which readers skip",
                hex::encode(tx_hash)
            ))),
            Ok(Landing::Expired) => {
                self.wallet.release(spent);
                Err(SubmitError::StateConflict(format!(
                    "transaction {} expired without landing; nothing was posted",
                    hex::encode(tx_hash)
                )))
            }
            Err(error) => Err(error),
        }
    }

    /// Scans each finalized block after `after` for `tx_hash` until it lands, until a
    /// finalized block is past `ttl` without it (`Landing::Expired`), or until
    /// `deadline`, when the outcome is unknown.
    async fn await_landing(
        &self,
        tx_hash: [u8; 32],
        after: u64,
        ttl: Timestamp,
        deadline: Instant,
    ) -> Result<Landing, SubmitError> {
        let mut scanned = after;
        loop {
            let scan = async {
                let head = self.chain.finalized_head().await?;
                let head_number = self.chain.block_number(&head).await?;
                while scanned < head_number {
                    let number = scanned + 1;
                    let hash = self
                        .chain
                        .block_hash_at(number)
                        .await?
                        .with_context(|| format!("the node has no finalized block {number}"))?;
                    if let Some(landing) = self.chain.landing(&hash, tx_hash).await? {
                        return anyhow::Ok(Some(landing));
                    }
                    scanned = number;
                }
                if self.chain.block_time(&head).await? > ttl {
                    return Ok(Some(Landing::Expired));
                }
                Ok(None)
            };
            match tokio::time::timeout_at(deadline, scan).await {
                Ok(Ok(Some(landing))) => return Ok(landing),
                Ok(Ok(None)) => {}
                Ok(Err(error)) => {
                    tracing::warn!(
                        ?error,
                        "midnight: watching for the respond transaction failed; retrying"
                    );
                }
                Err(_) => break,
            }
            if tokio::time::timeout_at(deadline, tokio::time::sleep(LANDING_POLL))
                .await
                .is_err()
            {
                break;
            }
        }
        Err(SubmitError::Ambiguous(format!(
            "transaction {} was not seen finalized within the submit budget",
            hex::encode(tx_hash)
        )))
    }
}

#[async_trait]
impl<W, C> IntentClient for NativeIntentClient<W, C>
where
    W: FeePayer + 'static,
    C: SubmitChain + 'static,
{
    async fn build(&self, request: &IntentRequest) -> anyhow::Result<Vec<u8>> {
        self.build_intent(request).map_err(SubmitError::into_anyhow)
    }

    async fn submit(&self, intent: &[u8]) -> anyhow::Result<Submitted> {
        self.submit_intent(intent)
            .await
            .map_err(SubmitError::into_anyhow)
    }
}

/// The fee's `ctime`. The spend proves against the replayed state's DUST roots,
/// which the chain looks up by `ctime`, so it names a time the replay has seen: no
/// later than the finalized head or the newest block the indexer has indexed, and
/// no earlier than the newest replayed event. The replay is checked caught up after
/// the indexer answers, but an event the subscription has not delivered yet still
/// leaves the roots stale; the node then refuses the spend and the publish retries.
fn fee_ctime(head_time: Timestamp, indexed_time: Timestamp, sync_time: Timestamp) -> Timestamp {
    head_time.min(indexed_time).max(sync_time)
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

fn internal(error: anyhow::Error) -> SubmitError {
    SubmitError::Internal(format!("{error:#}"))
}

fn hex_bytes(field: &str, value: &str) -> Result<Vec<u8>, SubmitError> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) || value.starts_with("0x") {
        return Err(SubmitError::BadRequest(format!(
            "{field} must be bare lowercase hex"
        )));
    }
    hex::decode(value)
        .map_err(|_| SubmitError::BadRequest(format!("{field} must be bare lowercase hex")))
}

fn hex32(field: &str, value: &str) -> Result<[u8; 32], SubmitError> {
    hex_bytes(field, value)?
        .try_into()
        .map_err(|_| SubmitError::BadRequest(format!("{field} must be 32 bytes")))
}

fn parse_signature(wire: &WireSignature) -> Result<EcdsaSignature, SubmitError> {
    if wire.recovery_id > 1 {
        return Err(SubmitError::BadRequest(
            "recoveryId must be 0 or 1".to_string(),
        ));
    }
    Ok(EcdsaSignature {
        big_r_x: hex32("signature.bigR.x", &wire.big_r.x)?,
        big_r_y: hex32("signature.bigR.y", &wire.big_r.y)?,
        s: hex32("signature.s", &wire.s)?,
        recovery_id: wire.recovery_id,
    })
}

fn parse_attestation(wire: &WireAttestation) -> Result<Attestation, SubmitError> {
    let uint64 = |field: &str, value: &str| {
        value
            .parse::<u64>()
            .ok()
            .filter(|parsed| parsed.to_string() == value)
            .ok_or_else(|| SubmitError::BadRequest(format!("{field} must be a decimal uint64")))
    };
    if wire.output_kind > 2 {
        return Err(SubmitError::BadRequest(
            "outputKind must be 0, 1 or 2".to_string(),
        ));
    }
    Ok(Attestation {
        block_height: uint64("attestation.blockHeight", &wire.block_height)?,
        output_kind: wire.output_kind,
        serialized_output_length: uint64(
            "attestation.serializedOutputLength",
            &wire.serialized_output_length,
        )?,
        output_hash: hex32("attestation.outputHash", &wire.output_hash)?,
        digest: hex32("attestation.digest", &wire.digest)?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use midnight_ledger_v9::structure::{
        ContractAction, ContractCall, Intent, ProofPreimageMarker, Signature, INITIAL_PARAMETERS,
    };
    use midnight_transient_crypto::commitment::PedersenRandomness;

    use super::*;
    use crate::emissions::{emissions_of_call, Emission, EmissionKind, MISC_PAYLOAD_LEN};
    use crate::funding::FeePlan;
    use crate::intent::WirePoint;

    /// The singleton's initial state with the package's verifier keys
    /// (`midnight-devtools`' `gen:initial-state`).
    const SINGLETON_STATE: &[u8] = include_bytes!("../fixtures/initial-singleton-state.mn");
    const SINGLETON: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const REQUEST_ID: &str = "abf32e141d471192a834779b0a8960aa05a7f94534564f477420eef80f588c48";
    const TTL: u64 = 1_800_000_000;
    const TX_HASH: [u8; 32] = [0x7a; 32];

    type ChainIntent = Intent<Signature, ProofPreimageMarker, PedersenRandomness, DefaultDB>;

    /// A wallet that records reservations; the build and post paths never plan.
    #[derive(Default)]
    pub(super) struct RecordingWallet {
        reserved: Mutex<Vec<Vec<DustNullifier>>>,
        released: Mutex<Vec<Vec<DustNullifier>>>,
    }

    impl FeePayer for RecordingWallet {
        async fn ready_by(&self, _deadline: Instant) -> Result<(), SubmitError> {
            Ok(())
        }

        fn sync_time(&self) -> Timestamp {
            Timestamp::from_secs(0)
        }

        async fn indexed_time(&self) -> Result<Timestamp, SubmitError> {
            Ok(Timestamp::from_secs(0))
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
            unimplemented!("these tests never price a fee")
        }

        fn reserve(&self, spent: &[DustNullifier], _until: Timestamp) {
            self.reserved.lock().unwrap().push(spent.to_vec());
        }

        fn release(&self, spent: &[DustNullifier]) {
            self.released.lock().unwrap().push(spent.to_vec());
        }
    }

    /// A chain whose finalized head moves one block per ask, from `head` up to `last`,
    /// with blocks six seconds apart from time 1000.
    pub(super) struct ScriptedChain {
        head: Mutex<u64>,
        last: u64,
        submit: Mutex<Option<SubmitRefusal>>,
        landing: Option<(u64, Landing)>,
        landing_reads: Mutex<VecDeque<u64>>,
    }

    impl ScriptedChain {
        pub(super) fn new(head: u64, last: u64, landing: Option<(u64, Landing)>) -> Self {
            Self {
                head: Mutex::new(head),
                last,
                submit: Mutex::new(None),
                landing,
                landing_reads: Mutex::new(VecDeque::new()),
            }
        }

        fn refusing(self, refusal: SubmitRefusal) -> Self {
            *self.submit.lock().unwrap() = Some(refusal);
            self
        }
    }

    fn block_hash(number: u64) -> String {
        format!("0x{number:064x}")
    }

    fn block_number_of(hash: &str) -> u64 {
        u64::from_str_radix(&hash[2..], 16).unwrap()
    }

    #[async_trait]
    impl PinnedReads for ScriptedChain {
        async fn finalized_head(&self) -> anyhow::Result<String> {
            let mut head = self.head.lock().unwrap();
            *head = (*head + 1).min(self.last);
            Ok(block_hash(*head))
        }

        async fn contract_state(&self, _: &str, _: &str) -> anyhow::Result<Option<Vec<u8>>> {
            unimplemented!("the post path reads no contract state")
        }

        async fn ledger_parameters(&self, _: &str) -> anyhow::Result<Vec<u8>> {
            unimplemented!("the post path reads no ledger parameters")
        }
    }

    #[async_trait]
    impl SubmitChain for ScriptedChain {
        async fn block_number(&self, at_hash_0x: &str) -> anyhow::Result<u64> {
            Ok(block_number_of(at_hash_0x))
        }

        async fn block_hash_at(&self, number: u64) -> anyhow::Result<Option<String>> {
            Ok(Some(block_hash(number)))
        }

        async fn block_time(&self, at_hash_0x: &str) -> anyhow::Result<Timestamp> {
            Ok(Timestamp::from_secs(1000 + 6 * block_number_of(at_hash_0x)))
        }

        async fn submit(&self, _transaction: &[u8]) -> Result<(), SubmitRefusal> {
            self.submit.lock().unwrap().take().map_or(Ok(()), Err)
        }

        async fn landing(
            &self,
            at_hash_0x: &str,
            tx_hash: [u8; 32],
        ) -> anyhow::Result<Option<Landing>> {
            assert_eq!(tx_hash, TX_HASH);
            let number = block_number_of(at_hash_0x);
            self.landing_reads.lock().unwrap().push_back(number);
            Ok(self
                .landing
                .filter(|(at, _)| *at == number)
                .map(|(_, landing)| landing))
        }
    }

    /// A managed directory holding the verifier keys the fixture state carries, as
    /// `keys/<circuit>.verifier`.
    fn managed_dir(verifier: impl Fn(&str, Vec<u8>) -> Vec<u8>) -> std::path::PathBuf {
        let state: ContractState<DefaultDB> =
            midnight_serialize::tagged_deserialize(&mut &SINGLETON_STATE[..]).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "mpc-midnight-native-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        std::fs::create_dir_all(dir.join("zkir")).unwrap();
        for circuit in ["respond", "respondBidirectional"] {
            // Present, never read: these tests prove nothing.
            std::fs::write(dir.join("keys").join(format!("{circuit}.prover")), b"").unwrap();
            std::fs::write(dir.join("zkir").join(format!("{circuit}.bzkir")), b"").unwrap();
        }
        for circuit in ["respond", "respondBidirectional", "signBidirectional"] {
            let op = state
                .operations
                .get(&circuit.as_bytes().into())
                .expect("the fixture carries every signer circuit");
            let mut bytes = Vec::new();
            midnight_serialize::tagged_serialize(op.v3.as_ref().unwrap(), &mut bytes).unwrap();
            std::fs::write(
                dir.join("keys").join(format!("{circuit}.verifier")),
                verifier(circuit, bytes),
            )
            .unwrap();
        }
        dir
    }

    fn client_over(
        dir: &std::path::Path,
        chain: ScriptedChain,
    ) -> NativeIntentClient<RecordingWallet, ScriptedChain> {
        NativeIntentClient::new(
            Arc::new(chain),
            RecordingWallet::default(),
            Arc::new(Provers::new(dir, dir).unwrap()),
            "undeployed",
            Duration::from_secs(420),
        )
    }

    fn client() -> NativeIntentClient<RecordingWallet, ScriptedChain> {
        client_over(
            &managed_dir(|_, bytes| bytes),
            ScriptedChain::new(0, 0, None),
        )
    }

    fn ledger_parameters() -> String {
        let mut bytes = Vec::new();
        midnight_serialize::tagged_serialize(&INITIAL_PARAMETERS, &mut bytes).unwrap();
        hex::encode(bytes)
    }

    pub(super) fn respond_request() -> IntentRequest {
        IntentRequest {
            circuit: "respond",
            contract_address: SINGLETON.to_string(),
            request_id: REQUEST_ID.to_string(),
            signature: WireSignature {
                big_r: WirePoint {
                    x: "11".repeat(32),
                    y: "22".repeat(32),
                },
                s: "33".repeat(32),
                recovery_id: 1,
            },
            attestation: None,
            contract_state: hex::encode(SINGLETON_STATE),
            ledger_parameters: ledger_parameters(),
            ttl_seconds: TTL,
        }
    }

    /// The compiled singleton's own `respondBidirectional` event, captured by
    /// `midnight-devtools`' `gen:api-parity-vectors`, as a request.
    pub(super) fn bidirectional_request() -> IntentRequest {
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../fixtures/api-parity-vectors.json")).unwrap();
        let event = &fixtures["responseEvent"];
        let text = |value: &serde_json::Value| value.as_str().unwrap().to_string();
        IntentRequest {
            circuit: "respondBidirectional",
            request_id: text(&event["requestId"]),
            signature: WireSignature {
                big_r: WirePoint {
                    x: format!("{:0>64}", text(&event["signature"]["bigR"]["x"])),
                    y: format!("{:0>64}", text(&event["signature"]["bigR"]["y"])),
                },
                s: format!("{:0>64}", text(&event["signature"]["s"])),
                recovery_id: event["signature"]["recoveryId"].as_u64().unwrap() as u8,
            },
            attestation: Some(WireAttestation {
                block_height: text(&event["blockHeight"]),
                output_kind: event["outputKind"].as_u64().unwrap() as u8,
                serialized_output_length: text(&event["serializedOutputLength"]),
                output_hash: text(&event["outputHash"]),
                digest: text(&event["digest"]),
            }),
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
        assert_eq!(hex::encode(call.address.0 .0), SINGLETON);
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
        // The compiled singleton's own emission for this event, captured by
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

    #[test]
    fn a_contract_whose_key_is_not_the_packaged_one_is_refused() {
        // The packaged respond key is another circuit's, so the deployed one differs.
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
        let client = client_over(&dir, ScriptedChain::new(0, 0, None));
        let error = client.build_intent(&respond_request()).unwrap_err();
        assert!(matches!(error, SubmitError::ContractMismatch(_)), "{error}");

        let mut empty = Vec::new();
        midnight_serialize::tagged_serialize(&ContractState::<DefaultDB>::default(), &mut empty)
            .unwrap();
        let error = client
            .build_intent(&IntentRequest {
                contract_state: hex::encode(empty),
                ..respond_request()
            })
            .unwrap_err();
        assert!(matches!(error, SubmitError::ContractMismatch(_)), "{error}");
    }

    #[test]
    fn provers_refuse_a_directory_without_the_packaged_artifacts() {
        let dir = managed_dir(|_, bytes| bytes);
        std::fs::remove_file(dir.join("zkir/respondBidirectional.bzkir")).unwrap();
        let error = Provers::new(&dir, &dir)
            .err()
            .expect("an artifact is missing");
        assert!(
            format!("{error:#}").contains("respondBidirectional.bzkir"),
            "{error:#}"
        );
    }

    #[test]
    fn malformed_requests_are_refused_before_anything_is_built() {
        let attestation = WireAttestation {
            block_height: "42".into(),
            output_kind: 0,
            serialized_output_length: "32".into(),
            output_hash: "44".repeat(32),
            digest: "55".repeat(32),
        };
        let bidirectional = IntentRequest {
            circuit: "respondBidirectional",
            attestation: Some(attestation.clone()),
            ..respond_request()
        };
        let cases: Vec<(&str, IntentRequest)> = vec![
            (
                "attestation on respond",
                IntentRequest {
                    attestation: Some(attestation.clone()),
                    ..respond_request()
                },
            ),
            (
                "no attestation on respondBidirectional",
                IntentRequest {
                    attestation: None,
                    ..bidirectional.clone()
                },
            ),
            (
                "unknown circuit",
                IntentRequest {
                    circuit: "signBidirectional",
                    ..respond_request()
                },
            ),
            (
                "uppercase hex",
                IntentRequest {
                    request_id: REQUEST_ID.to_ascii_uppercase(),
                    ..respond_request()
                },
            ),
            (
                "0x prefix",
                IntentRequest {
                    contract_address: format!("0x{}", &SINGLETON[2..]),
                    ..respond_request()
                },
            ),
            ("recovery id 2", {
                let mut request = respond_request();
                request.signature.recovery_id = 2;
                request
            }),
            ("output kind 3", {
                let mut request = bidirectional.clone();
                request.attestation.as_mut().unwrap().output_kind = 3;
                request
            }),
            ("non-canonical decimal", {
                let mut request = bidirectional.clone();
                request.attestation.as_mut().unwrap().block_height = "042".into();
                request
            }),
            ("short output hash", {
                let mut request = bidirectional.clone();
                request.attestation.as_mut().unwrap().output_hash = "44".repeat(31);
                request
            }),
        ];
        let client = client();
        for (case, request) in cases {
            let error = client.build_intent(&request).unwrap_err();
            assert!(
                matches!(error, SubmitError::BadRequest(_)),
                "{case}: {error}"
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
            &managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20, Some((13, Landing::Applied))),
        );
        let landed = client
            .post(
                b"tx",
                TX_HASH,
                &spent(),
                10,
                Timestamp::from_secs(5000),
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(landed, hex::encode(TX_HASH));
        assert_eq!(*client.wallet.reserved.lock().unwrap(), vec![spent()]);
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
            &managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20, None)
                .refusing(SubmitRefusal::Refused("1010: Invalid Transaction".into())),
        );
        let error = client
            .post(
                b"tx",
                TX_HASH,
                &spent(),
                10,
                Timestamp::from_secs(5000),
                deadline(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SubmitError::StateConflict(_)), "{error}");
        assert_eq!(*client.wallet.released.lock().unwrap(), vec![spent()]);
        assert!(client.chain.landing_reads.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unsent_transaction_releases_its_utxos_without_blaming_the_chain() {
        let client = client_over(
            &managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20, None)
                .refusing(SubmitRefusal::Unsent(anyhow::anyhow!("connection refused"))),
        );
        let error = client
            .post(
                b"tx",
                TX_HASH,
                &spent(),
                10,
                Timestamp::from_secs(5000),
                deadline(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SubmitError::Internal(_)), "{error}");
        assert_eq!(*client.wallet.released.lock().unwrap(), vec![spent()]);
        assert!(client.chain.landing_reads.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswered_submit_is_still_watched_for() {
        let client = client_over(
            &managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20, Some((12, Landing::Applied))).refusing(
                SubmitRefusal::Unanswered(anyhow::anyhow!("connection reset")),
            ),
        );
        let landed = client
            .post(
                b"tx",
                TX_HASH,
                &spent(),
                10,
                Timestamp::from_secs(5000),
                deadline(),
            )
            .await
            .unwrap();
        assert_eq!(landed, hex::encode(TX_HASH));
    }

    #[tokio::test(start_paused = true)]
    async fn a_partial_success_is_a_conflict_the_retry_rebuilds() {
        let client = client_over(
            &managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20, Some((12, Landing::PartialSuccess))),
        );
        let error = client
            .post(
                b"tx",
                TX_HASH,
                &spent(),
                10,
                Timestamp::from_secs(5000),
                deadline(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SubmitError::StateConflict(_)), "{error}");
        assert!(
            client.wallet.released.lock().unwrap().is_empty(),
            "the guaranteed segment spent the DUST; the replay ends the reservation"
        );
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

    #[test]
    fn the_fee_ttl_leaves_the_landing_its_finality_slack() {
        let secs = Duration::from_secs;
        assert_eq!(fee_ttl(secs(420)), Some(FEE_TTL));
        assert_eq!(fee_ttl(secs(100)), Some(secs(40)));
        assert_eq!(fee_ttl(secs(90)), Some(MIN_FEE_TTL));
        assert_eq!(fee_ttl(secs(89)), None);
        assert_eq!(fee_ttl(secs(0)), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transaction_past_its_ttl_unlanded_releases_its_utxos() {
        // Block 14 is at 1084, past the 1080 TTL, and nothing landed up to it.
        let client = client_over(
            &managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 20, None),
        );
        let error = client
            .post(
                b"tx",
                TX_HASH,
                &spent(),
                10,
                Timestamp::from_secs(1080),
                deadline(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SubmitError::StateConflict(_)), "{error}");
        assert_eq!(*client.wallet.released.lock().unwrap(), vec![spent()]);
        let reads: Vec<u64> = client
            .chain
            .landing_reads
            .lock()
            .unwrap()
            .iter()
            .copied()
            .collect();
        assert_eq!(reads, vec![11, 12, 13, 14]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transaction_unseen_by_the_deadline_stays_reserved_and_is_ambiguous() {
        // The head stalls at 12, inside the TTL, so the outcome stays unknown.
        let client = client_over(
            &managed_dir(|_, bytes| bytes),
            ScriptedChain::new(10, 12, None),
        );
        let error = client
            .post(
                b"tx",
                TX_HASH,
                &spent(),
                10,
                Timestamp::from_secs(5000),
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SubmitError::Ambiguous(_)), "{error}");
        assert!(client.wallet.released.lock().unwrap().is_empty());
        assert!(crate::intent::is_ambiguous_submit(&error.into_anyhow()));
    }
}

#[cfg(test)]
mod bench {
    //! What each proof costs in process. `MIDNIGHT_BENCH_ARTIFACTS` is the package's
    //! `dist/managed`, `MIDNIGHT_BENCH_ZK_PARAMS` the parameter store, and
    //! `MIDNIGHT_BENCH_RUNS` the samples per step (10). Prints one JSON line per
    //! sample; proving wants `--release`.

    use midnight_ledger_v9::structure::INITIAL_PARAMETERS;

    use super::tests::{bidirectional_request, respond_request, RecordingWallet, ScriptedChain};
    use super::*;
    use crate::funding::plan_fee;
    use crate::funding::tests::{funded_key, replayed};

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
            Arc::new(ScriptedChain::new(0, 0, None)),
            RecordingWallet::default(),
            Arc::new(
                Provers::new(
                    env("MIDNIGHT_BENCH_ARTIFACTS"),
                    env("MIDNIGHT_BENCH_ZK_PARAMS"),
                )
                .unwrap(),
            ),
            "undeployed",
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
                    request.circuit,
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
    //! singleton, a funded seed and the artifact directories. Proving wants `--release`.

    use super::*;
    use crate::config::{MidnightAddress, MidnightConfig, PublisherConfig};
    use crate::dust_feed::IndexerDustEvents;
    use crate::funding::{dust_secret_key, parse_seed, FundingWallet};
    use crate::intent::WirePoint;
    use crate::rpc::MidnightPublisherRpc;

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a running Midnight stack named by MIDNIGHT_LIVE_*"]
    async fn a_respond_and_a_bidirectional_respond_land_and_apply() {
        let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
        let config = MidnightConfig {
            node_url: env("MIDNIGHT_LIVE_NODE_URL"),
            central_address: MidnightAddress::from_hex(&env("MIDNIGHT_LIVE_CENTRAL")).unwrap(),
            publisher: PublisherConfig {
                funding_seed: env("MIDNIGHT_LIVE_SEED"),
                indexer_ws_url: env("MIDNIGHT_LIVE_INDEXER_WS_URL"),
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
        let central = config.central_address.to_hex();
        for circuit in ["respond", "respondBidirectional", "respond"] {
            let head = rpc.finalized_head().await.unwrap();
            let state = rpc.contract_state(&central, &head).await.unwrap().unwrap();
            let parameters = rpc.ledger_parameters(&head).await.unwrap();
            let request = IntentRequest {
                circuit,
                contract_address: central.clone(),
                request_id: hex::encode(rand::random::<[u8; 32]>()),
                signature: WireSignature {
                    big_r: WirePoint {
                        x: "11".repeat(32),
                        y: "22".repeat(32),
                    },
                    s: "33".repeat(32),
                    recovery_id: 1,
                },
                attestation: (circuit == "respondBidirectional").then(|| WireAttestation {
                    block_height: "123456".into(),
                    output_kind: 0,
                    serialized_output_length: "32".into(),
                    output_hash: "44".repeat(32),
                    digest: "55".repeat(32),
                }),
                contract_state: hex::encode(state),
                ledger_parameters: hex::encode(parameters),
                ttl_seconds: mpc_utils::time::current_unix_timestamp() + 600,
            };
            let started = std::time::Instant::now();
            let intent = client.build(&request).await.unwrap();
            let landed = client
                .submit(&intent)
                .await
                .unwrap_or_else(|error| panic!("{circuit}: {error:#}"));
            println!(
                "{circuit}: landed {} in {:?}",
                landed.tx_id,
                started.elapsed()
            );
        }
    }
}
