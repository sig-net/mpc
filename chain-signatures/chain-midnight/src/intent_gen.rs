//! Client for the out-of-process intent builder: one JSON object per line down the
//! child's stdin, one back up its stdout, mirroring `protocol.ts` field for field. The
//! hazard is a reply landing on the wrong request, which would put one post's signature
//! into another post's intent; the pipe has no framing beyond the newline, so once the
//! stream is in any doubt the child is replaced rather than resynchronized.

use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use mpc_chain_integration_core::utils::retry::retry_op;
use mpc_utils::task::AbortOnDrop;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

use crate::config::{validate_publisher_network_id, MidnightConfig, PublisherConfig};
use crate::wallet_snapshot::{Snapshots, WalletSnapshotStore};

#[derive(Debug)]
pub(crate) struct AmbiguousSubmit;

impl std::fmt::Display for AmbiguousSubmit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "the answer was lost; the transaction may still land, and a later publisher retry \
             may post the response again",
        )
    }
}

impl std::error::Error for AmbiguousSubmit {}

#[cfg(test)]
pub(crate) fn is_ambiguous_submit(error: &anyhow::Error) -> bool {
    error.downcast_ref::<AmbiguousSubmit>().is_some()
}

/// A request the child answered without carrying out, under its `protocol.ts` code.
#[derive(Debug)]
struct Refusal {
    code: String,
    message: String,
    /// The child's account of its funding wallet, logged but kept out of the error text:
    /// retry and throttle detection scan that text for status codes, which counts can mimic.
    wallet_state: Option<String>,
    /// Whether the submit had started balancing with the funding wallet: only such a
    /// refusal can implicate the wallet a snapshot restored.
    wallet_used: bool,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "midnight intent builder refused the request [{}]: {}",
            self.code, self.message
        )
    }
}

impl std::error::Error for Refusal {}

/// A refused submit costs its child whatever the reason: one restored from the latest
/// wallet snapshot is cheap, so no refusal is diagnosed in place. The exception is a
/// wallet still syncing, which a fresh child would only start syncing over.
fn retires_child(operation: Operation, error: &anyhow::Error) -> bool {
    operation == Operation::Submit
        && error
            .downcast_ref::<Refusal>()
            .is_none_or(|refusal| refusal.code != "wallet_unsynced")
}

/// One respond call, in the shape the child validates. Every byte field is bare
/// lowercase hex with no `0x`; the child converts nothing and rejects anything else.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentRequest {
    /// `respond` or `respondBidirectional`.
    pub circuit: &'static str,
    pub contract_address: String,
    pub request_id: String,
    pub signature: WireSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<WireAttestation>,
    /// The reads this caller pinned, so the child stays a pure function of them.
    pub contract_state: String,
    pub ledger_parameters: String,
    /// Absolute unix seconds, not a duration from now.
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireSignature {
    pub big_r: WirePoint,
    pub s: String,
    /// 0 or 1.
    pub recovery_id: u8,
}

/// Decimal strings preserve the SDK's Uint<64> fields across the JSON boundary.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireAttestation {
    pub block_height: String,
    pub output_kind: u8,
    pub serialized_output_length: String,
    pub output_hash: String,
    pub digest: String,
}

/// SEC1 big-endian affine coordinates, reaching the ledger untouched.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct WirePoint {
    pub x: String,
    pub y: String,
}

/// One submit call: only the intent travels, the child balances against a wallet it
/// syncs itself.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct SubmitRequest {
    intent: String,
}

/// Asks the child for its funding wallet's snapshot; it carries no fields.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct SnapshotRequest {}

/// What the child is being asked to do. A build's lost answer can simply be asked for
/// again; a submit's may be on chain, and asking again races the single dust UTXO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    BuildIntent,
    Submit,
    Snapshot,
}

/// The wire `op` of the readiness handshake, which runs its own exchange in
/// `verify_ready` rather than under [`Operation`]'s budget and reissue policy.
const READY_OP: &str = "ready";

impl Operation {
    /// Build and readiness share the request budget. Submit uses Rust's process
    /// backstop, whose strict ordering against the child's own deadlines is checked
    /// during the readiness exchange.
    fn deadline(self, config: &PublisherConfig) -> Duration {
        match self {
            Self::BuildIntent | Self::Snapshot => config.request_timeout,
            Self::Submit => config.submit_timeout,
        }
    }

    /// Whether an answer lost in transit may simply be asked for again. A snapshot could
    /// be, but a fresh child has nothing synced to snapshot.
    fn is_repeatable(self) -> bool {
        matches!(self, Self::BuildIntent)
    }

    /// The `op` the child discriminates on.
    fn wire_op(self) -> &'static str {
        match self {
            Self::BuildIntent => "build",
            Self::Submit => "submit",
            Self::Snapshot => "snapshot",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::BuildIntent => "intent build",
            Self::Submit => "submit",
            Self::Snapshot => "wallet snapshot",
        }
    }
}

/// Builds intents and posts them, by driving one persistent child process.
pub struct IntentGen {
    config: MidnightConfig,
    network_id: String,
    /// Two interleaved requests on one pipe have no correct reading, so the lock is the
    /// concurrency story: callers queue.
    session: Mutex<Option<Session>>,
    /// Every child starts from the latest of these.
    snapshots: Snapshots,
}

impl IntentGen {
    /// Starts the builder eagerly: a command that cannot run fails here, not on the first signature.
    pub async fn spawn(config: &MidnightConfig, network_id: &str) -> anyhow::Result<Self> {
        Self::spawn_with_snapshots(config, network_id, None).await
    }

    /// [`Self::spawn`], with the funding wallet resuming from and saving to `store`.
    pub async fn spawn_with_snapshots(
        config: &MidnightConfig,
        network_id: &str,
        store: Option<Arc<dyn WalletSnapshotStore>>,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        validate_publisher_network_id(network_id)?;
        let snapshots = Snapshots::load(store).await;
        let session = spawn_session(config, network_id, snapshots.latest().as_deref()).await?;
        Ok(Self {
            config: config.clone(),
            network_id: network_id.to_string(),
            session: Mutex::new(Some(session)),
            snapshots,
        })
    }

    /// The serialized ledger `Intent` for `request`.
    pub async fn build(&self, request: &IntentRequest) -> anyhow::Result<Vec<u8>> {
        let reply = self.dispatch(request, Operation::BuildIntent).await?;
        let intent = reply
            .intent
            .context("midnight intent builder granted a request without an intent")?;
        hex::decode(&intent).context("decoding the intent the builder granted")
    }

    /// Balances, proves and posts `intent`, answering with what names it on chain.
    /// Attempted exactly once.
    pub async fn submit(&self, intent: &[u8]) -> anyhow::Result<String> {
        let request = SubmitRequest {
            intent: hex::encode(intent),
        };
        self.dispatch(&request, Operation::Submit)
            .await?
            .tx_id
            .context("midnight intent builder posted a transaction without naming it")
    }

    /// Keeps the child's wallet snapshot when one is due. Called between publishes, where no
    /// intent's TTL is running, and never spawns a child only to ask.
    pub async fn refresh_snapshot(&self) {
        if !self.snapshots.due() {
            return;
        }
        let outcome = {
            let mut session = self.session.lock().await;
            if session.is_none() {
                return;
            }
            self.attempt(&mut session, &SnapshotRequest {}, Operation::Snapshot)
                .await
        };
        self.keep_snapshot(outcome).await;
    }

    /// Keeps what a snapshot request returned. The child hands one over only while its
    /// wallet is synced with nothing in flight.
    async fn keep_snapshot(&self, outcome: Exchange) {
        match outcome {
            Exchange::Answered(Ok(reply)) => {
                if let Some(snapshot) = reply.wallet_snapshot {
                    tracing::info!(bytes = snapshot.len(), "kept a midnight wallet snapshot");
                    self.snapshots.keep(snapshot).await;
                }
            }
            // Still syncing, or a submit or an in-flight coin still owns the wallet.
            Exchange::Answered(Err(error)) => {
                tracing::info!("midnight wallet snapshot not taken: {error:#}");
            }
            Exchange::Broken { error, .. } => {
                tracing::warn!(?error, "midnight wallet snapshot failed");
            }
        }
    }

    /// One operation, start to finish; budget and reissue policy come from
    /// `operation`, never from the caller.
    async fn dispatch<T: Serialize>(
        &self,
        request: &T,
        operation: Operation,
    ) -> anyhow::Result<WireReply> {
        let mut session = self.session.lock().await;
        let (error, retry) = match self.attempt(&mut session, request, operation).await {
            Exchange::Answered(result) => return result.map(|reply| *reply),
            Exchange::Broken { error, retry } => (error, retry),
        };
        if !retry {
            return Err(self.blame_the_command(error));
        }
        // One respawn, never the caller's post; past one retry the failure is the builder's.
        tracing::warn!(
            reason = "respawning",
            "midnight intent builder failed: {error:#}; retrying once on a fresh child"
        );
        match self.attempt(&mut session, request, operation).await {
            Exchange::Answered(result) => result.map(|reply| *reply),
            Exchange::Broken { error, .. } => Err(self.blame_the_command(error)),
        }
    }

    /// Named only on failures of the child itself: a refusal is an answer, not the command's fault.
    fn blame_the_command(&self, error: anyhow::Error) -> anyhow::Error {
        error.context(format!(
            "midnight intent builder command [{}]",
            self.config.publisher.intent_gen_command.join(" ")
        ))
    }

    /// One pass. A broken exchange or a refused submit, unless refused for a wallet still
    /// syncing, empties the slot, killing the child: nothing later reads its pipe.
    async fn attempt<T: Serialize>(
        &self,
        session: &mut Option<Session>,
        request: &T,
        operation: Operation,
    ) -> Exchange {
        if session.is_none() {
            let snapshot = self.snapshots.latest();
            match spawn_session(&self.config, &self.network_id, snapshot.as_deref()).await {
                Ok(fresh) => *session = Some(fresh),
                // The restart budget was already spent inside the spawn; a second pass
                // would only spend it again.
                Err(error) => return Exchange::give_up(error),
            }
        }
        let live = session
            .as_mut()
            .expect("the slot was just filled or was already full");
        let outcome = exchange(live, request, operation, &self.config.publisher).await;
        if operation == Operation::Submit && matches!(outcome, Exchange::Answered(Ok(_))) {
            self.snapshots.proved();
        }
        if let Exchange::Answered(Err(error)) = &outcome {
            let refusal = error.downcast_ref::<Refusal>();
            let wallet = refusal.and_then(|refusal| refusal.wallet_state.as_deref());
            if retires_child(operation, error) {
                tracing::warn!(
                    wallet,
                    "retiring the midnight intent builder after a refused submit; the next \
                     request starts one from the latest wallet snapshot: {error:#}"
                );
                // Restored wallets that keep being refused without one submit landing may
                // have brought a fault back with the snapshot, and every later restore would
                // too, so the next child syncs from the start. Snapshots this child kept
                // descend from the same restore. A refusal from before the wallet was used,
                // such as a proof server that is down, says nothing about the snapshot.
                let wallet_used = refusal.is_some_and(|refusal| refusal.wallet_used);
                if live.restored && wallet_used && self.snapshots.strike() {
                    tracing::warn!(
                        "discarding the midnight wallet snapshot after its restored wallets \
                         failed to land a submit; the next builder syncs from the start"
                    );
                    self.snapshots.forget().await;
                }
                // An ambiguous submit's wallet work may also still be running, so no later
                // request may reuse this child either way.
                *session = None;
                return outcome;
            }
            if wallet.is_some() {
                tracing::info!(wallet, "midnight submit refused: {error:#}");
            }
        }
        let Exchange::Broken { error, retry } = outcome else {
            return outcome;
        };
        // Attached before the slot empties: emptying kills the child and takes its
        // stderr with it.
        let error = match live.last_words().await {
            Some(said) => error.context(format!("the midnight intent builder said: {said}")),
            None => error,
        };
        // A restored child that dies or wedges, rather than refusing, may equally have
        // brought its fault back with the snapshot.
        if live.restored && self.snapshots.strike() {
            tracing::warn!(
                "discarding the midnight wallet snapshot after its restored builders kept \
                 failing; the next builder syncs from the start"
            );
            self.snapshots.forget().await;
        }
        *session = None;
        Exchange::Broken { error, retry }
    }
}

/// One live child. Dropping it kills the child, which is how every failure path recovers.
struct Session {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// Per session: a fresh pipe cannot deliver a previous child's reply.
    next_id: u64,
    /// Whether its wallet resumed from a snapshot rather than syncing from the start.
    restored: bool,
    /// What the drain below has heard, for the error that reports this child's death.
    stderr: StderrTail,
    /// Held for `kill_on_drop`; dropped after `stdin`, so a child that exits on
    /// end-of-input gets to do that before the kill lands.
    _child: Child,
    /// Awaited briefly by `last_words`; its end says the child finished saying why it died.
    stderr_drain: AbortOnDrop,
}

impl Session {
    /// What the child said on its stderr, or `None`. Waits for the drain briefly: a dead
    /// child's explanation may still be in flight, and a wedged one never closes stderr.
    async fn last_words(&mut self) -> Option<String> {
        let _ = tokio::time::timeout(STDERR_TAIL_GRACE, &mut self.stderr_drain.0).await;
        self.stderr.take()
    }
}

const STDERR_TAIL_LINES: usize = 10;

/// How long a broken pass waits for the drain to finish before reporting what it has.
const STDERR_TAIL_GRACE: Duration = Duration::from_millis(200);

/// The child's last words, bound for an error rather than a log: `tracing` reaches
/// nobody in a process without a subscriber. `drain_stderr` is the only filler.
#[derive(Clone, Default)]
struct StderrTail(Arc<std::sync::Mutex<VecDeque<String>>>);

impl StderrTail {
    /// Never panics on a poisoned lock: a panic here takes a runtime worker with it
    /// over a diagnostic, and nothing inside the lock can panic anyway.
    fn lines(&self) -> std::sync::MutexGuard<'_, VecDeque<String>> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn push(&self, line: String) {
        let mut lines = self.lines();
        if lines.len() == STDERR_TAIL_LINES {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    /// Oldest first, on one line: this becomes an `anyhow` context.
    fn take(&self) -> Option<String> {
        let lines = self.lines();
        (!lines.is_empty()).then(|| lines.iter().cloned().collect::<Vec<_>>().join("; "))
    }
}

/// What a pass at the child produced.
enum Exchange {
    /// A reply that answers this request, whether it granted it or refused it. Boxed:
    /// a reply is ten times the size of a fault.
    Answered(anyhow::Result<Box<WireReply>>),
    /// The child is replaced either way; only a transport fault is worth a second try.
    Broken { error: anyhow::Error, retry: bool },
}

impl Exchange {
    /// The pipe failed under us; only an operation that left nothing on chain may be asked again.
    fn lost(error: anyhow::Error, operation: Operation) -> Self {
        Self::Broken {
            error,
            retry: operation.is_repeatable(),
        }
    }

    /// The child is finished either way, and asking a new one would only reproduce this.
    fn give_up(error: anyhow::Error) -> Self {
        Self::Broken {
            error,
            retry: false,
        }
    }
}

/// `error`, plus what an operation that cannot be asked again leaves behind. Applied
/// to every locally broken exchange after encoding: from there the transport may have
/// been attempted, so a lost answer and a landed transaction are indistinguishable.
fn unanswered(error: anyhow::Error, operation: Operation) -> anyhow::Error {
    match operation {
        Operation::Submit => error.context(AmbiguousSubmit),
        Operation::BuildIntent | Operation::Snapshot => error,
    }
}

/// Resolves the packaged publisher and its `#!/usr/bin/env node` interpreter without
/// making the parent's executable search path part of the child configuration.
const CHILD_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The child parses numbers as JavaScript `number`, whose integer precision ends here.
const MAX_SAFE_WIRE_ID: u64 = (1_u64 << 53) - 1;

/// Returns one lossless JSON id and advances the private session counter.
fn take_wire_id(next_id: &mut u64) -> u64 {
    let id = *next_id;
    debug_assert!(id <= MAX_SAFE_WIRE_ID);
    *next_id = if id == MAX_SAFE_WIRE_ID { 0 } else { id + 1 };
    id
}

/// Starts the builder under the restart budget, its wallet resuming from `snapshot`.
async fn spawn_session(
    config: &MidnightConfig,
    network_id: &str,
    snapshot: Option<&str>,
) -> anyhow::Result<Session> {
    retry_op!(
        config.publisher.request_timeout,
        config.publisher.restart_backoff,
        "midnight_intent_gen_spawn",
        {
            let session = spawn_child(config, network_id)?;
            verify_ready(session, &config.publisher, snapshot).await
        }
    )
}

const PUBLISHER_PROTOCOL_VERSION: u64 = 3;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadyRequest<'a> {
    protocol_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_snapshot: Option<&'a str>,
}

async fn verify_ready(
    mut session: Session,
    config: &PublisherConfig,
    snapshot: Option<&str>,
) -> anyhow::Result<Session> {
    let id = take_wire_id(&mut session.next_id);
    let line = encode_request(
        &ReadyRequest {
            protocol_version: PUBLISHER_PROTOCOL_VERSION,
            wallet_snapshot: snapshot,
        },
        id,
        READY_OP,
    )?;
    let reply = tokio::time::timeout(config.request_timeout, round_trip(&mut session, &line))
        .await
        .context("midnight intent builder did not become ready before its startup deadline")??;
    let decoded = match decode_reply(&reply, id) {
        Exchange::Answered(result) => result?,
        Exchange::Broken { error, .. } => return Err(error),
    };
    anyhow::ensure!(
        decoded.ready == Some(true),
        "midnight intent builder readiness reply did not identify itself"
    );
    anyhow::ensure!(
        decoded.protocol_version == Some(PUBLISHER_PROTOCOL_VERSION),
        "midnight intent builder readiness reply has protocolVersion {:?}, expected {}",
        decoded.protocol_version,
        PUBLISHER_PROTOCOL_VERSION
    );
    let submit_timeout = Duration::from_millis(
        decoded
            .submit_timeout_ms
            .context("midnight intent builder readiness reply has no submitTimeoutMs")?,
    );
    let recipe_ttl = Duration::from_millis(
        decoded
            .recipe_ttl_ms
            .context("midnight intent builder readiness reply has no recipeTtlMs")?,
    );
    anyhow::ensure!(
        recipe_ttl < submit_timeout && submit_timeout < config.submit_timeout,
        "midnight publisher deadlines must satisfy recipe TTL ({recipe_ttl:?}) < child submit \
         timeout ({submit_timeout:?}) < Rust backstop ({:?})",
        config.submit_timeout
    );
    // Readiness is a session bootstrap, not an application request. Reusing id zero
    // keeps the application protocol independent of whether the bootstrap grows.
    session.next_id = 0;
    session.restored = snapshot.is_some();
    Ok(session)
}

fn spawn_child(config: &MidnightConfig, network_id: &str) -> anyhow::Result<Session> {
    let mut command = intent_gen_command(config, network_id)?;
    let mut child = command.spawn().with_context(|| {
        format!(
            "spawning the midnight intent builder ({})",
            config.publisher.intent_gen_command.join(" ")
        )
    })?;

    let stdin = child
        .stdin
        .take()
        .context("intent builder stdin was not piped")?;
    let stdout = child
        .stdout
        .take()
        .context("intent builder stdout was not piped")?;
    let stderr = child
        .stderr
        .take()
        .context("intent builder stderr was not piped")?;
    let tail = StderrTail::default();
    Ok(Session {
        stdin,
        stdout: BufReader::new(stdout),
        next_id: 0,
        restored: false,
        stderr: tail.clone(),
        _child: child,
        stderr_drain: AbortOnDrop(tokio::spawn(drain_stderr(stderr, tail))),
    })
}

/// Configured but not spawned, so a test can read back the environment the child would get.
fn intent_gen_command(config: &MidnightConfig, network_id: &str) -> anyhow::Result<Command> {
    let (program, args) = config
        .publisher
        .intent_gen_command
        .split_first()
        .context("midnight publisher config: intent_gen_command is empty")?;
    let mut command = Command::new(program);
    command.args(args);

    command
        .env_clear()
        .env("PATH", CHILD_PATH)
        .env("MIDNIGHT_PUB_FUNDING_SEED", &config.publisher.funding_seed)
        .env("MIDNIGHT_PUB_NETWORK_ID", network_id)
        .env("MIDNIGHT_PUB_NODE_URL", &config.node_url)
        .env(
            "MIDNIGHT_PUB_PROOF_SERVER_URL",
            &config.publisher.proof_server_url,
        )
        .env("MIDNIGHT_PUB_INDEXER_URL", &config.publisher.indexer_url)
        .env(
            "MIDNIGHT_PUB_INDEXER_WS_URL",
            &config.publisher.indexer_ws_url,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Piped: an unread stderr pipe eventually blocks the child mid-proof.
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok(command)
}

/// Forwards the child's stderr to the log and keeps the tail for errors.
async fn drain_stderr(stderr: ChildStderr, tail: StderrTail) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        tracing::warn!(source = "midnight-intent-builder", "{line}");
        tail.push(line);
    }
}

/// Encodes one request and applies the post-encoding uncertainty policy once.
async fn exchange<T: Serialize>(
    session: &mut Session,
    request: &T,
    operation: Operation,
    config: &PublisherConfig,
) -> Exchange {
    let id = take_wire_id(&mut session.next_id);
    let line = match encode_request(request, id, operation.wire_op()) {
        Ok(line) => line,
        // Nothing reached the pipe, so the child is still in step.
        Err(error) => return Exchange::Answered(Err(error)),
    };

    match exchange_inner(session, &line, id, operation, config).await {
        Exchange::Broken { error, retry } => Exchange::Broken {
            error: unanswered(error, operation),
            retry,
        },
        answered => answered,
    }
}

/// One line out, one line in; anything leaving the pipe in an unknown state reports `Broken`.
async fn exchange_inner(
    session: &mut Session,
    line: &str,
    id: u64,
    operation: Operation,
    config: &PublisherConfig,
) -> Exchange {
    let deadline = operation.deadline(config);
    // A timed-out child is a dead publisher if kept: a wedged circuit run wedges the
    // process while it still looks healthy. `Broken` kills it; a submit is still not reissued.
    let reply = match tokio::time::timeout(deadline, round_trip(session, line)).await {
        Ok(Ok(reply)) => reply,
        Ok(Err(error)) => return Exchange::lost(error, operation),
        Err(_) => {
            return Exchange::lost(
                anyhow::anyhow!("midnight {} timed out after {deadline:?}", operation.name()),
                operation,
            )
        }
    };
    decode_reply(&reply, id)
}

async fn round_trip(session: &mut Session, line: &str) -> anyhow::Result<String> {
    session
        .stdin
        .write_all(format!("{line}\n").as_bytes())
        .await
        .context("writing the intent request to the builder")?;
    session
        .stdin
        .flush()
        .await
        .context("flushing the intent request to the builder")?;
    let mut reply = String::new();
    let read = session
        .stdout
        .read_line(&mut reply)
        .await
        .context("reading the intent builder's reply")?;
    anyhow::ensure!(read > 0, "midnight intent builder closed its stdout");
    Ok(reply)
}

/// Reads one reply line as the answer to request `id`.
fn decode_reply(line: &str, id: u64) -> Exchange {
    let reply: WireReply = match serde_json::from_str(line.trim()) {
        Ok(reply) => reply,
        // Not this wire at all: the reader's idea of where a line starts is now wrong.
        Err(error) => {
            return Exchange::give_up(
                anyhow::Error::new(error)
                    .context("midnight intent builder sent an unreadable reply"),
            )
        }
    };
    // A rejection carrying no id is this request's own; a reply naming a different request
    // means the stream has slipped, the one outcome worth killing a healthy child over.
    match reply.id {
        Some(answered) if answered != id => {
            return Exchange::give_up(anyhow::anyhow!(
                "midnight intent builder answered id {answered}, not the id {id} it was asked"
            ))
        }
        None if reply.ok => {
            // A grant with no id is not an answer to anything nameable.
            return Exchange::give_up(anyhow::anyhow!(
                "midnight intent builder granted a request with no id"
            ));
        }
        _ => {}
    }
    Exchange::Answered(granted(reply).map(Box::new))
}

fn granted(reply: WireReply) -> anyhow::Result<WireReply> {
    if !reply.ok {
        let refusal = Refusal {
            code: reply.code.unwrap_or_else(|| "no code".to_string()),
            message: reply.message.unwrap_or_else(|| "no message".to_string()),
            wallet_state: reply.wallet_state,
            wallet_used: reply.wallet_used.unwrap_or(false),
        };
        let ambiguous = refusal.code == "ambiguous_submit";
        let error = anyhow::Error::new(refusal);
        return Err(if ambiguous {
            error.context(AmbiguousSubmit)
        } else {
            error
        });
    }
    Ok(reply)
}

fn encode_request<T: Serialize>(request: &T, id: u64, op: &'static str) -> anyhow::Result<String> {
    serde_json::to_string(&WireRequest { id, op, request })
        .context("encoding the request for the builder")
}

/// The wire shape: the caller's fields, the id that pairs the reply, the discriminating op.
#[derive(Serialize)]
struct WireRequest<'a, T> {
    id: u64,
    op: &'static str,
    #[serde(flatten)]
    request: &'a T,
}

/// Both arms of a reply in one shape. Unknown fields are ignored on purpose: growing
/// the wire is meant to be additive on one side at a time.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireReply {
    /// Null when the child could not read an id off the line it was rejecting.
    id: Option<u64>,
    ok: bool,
    ready: Option<bool>,
    protocol_version: Option<u64>,
    submit_timeout_ms: Option<u64>,
    recipe_ttl_ms: Option<u64>,
    intent: Option<String>,
    /// What names a posted transaction on chain. The submit arm's own payload.
    tx_id: Option<String>,
    /// The snapshot arm's own payload, opaque here.
    wallet_snapshot: Option<String>,
    code: Option<String>,
    message: Option<String>,
    /// A refused submit's account of the funding wallet.
    wallet_state: Option<String>,
    /// Set on a refused submit that had started using the funding wallet.
    wallet_used: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::{MidnightAddress, MidnightConfig, PublisherConfig};
    use crate::wallet_snapshot::RESTORE_STRIKES;
    use mpc_chain_integration_core::utils::retry::RetryConfig;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    const NETWORK_ID: &str = "undeployed";
    const NODE_URL: &str = "https://node.example.com/rpc?network=preprod";

    /// A shell stub in place of the real Node child; a test reading an unpinned field
    /// must pin its own, or it silently tests the default.
    fn stub_config(script: &str) -> MidnightConfig {
        let script = format!(
            r#"read -r ready; ready_id=$(printf "%s" "$ready" | sed -n 's/.*"id":\([0-9]*\).*/\1/p'); printf '{{"id":%s,"ok":true,"ready":true,"protocolVersion":3,"submitTimeoutMs":2,"recipeTtlMs":1}}\n' "$ready_id"; {script}"#
        );
        MidnightConfig {
            node_url: NODE_URL.to_string(),
            central_address: MidnightAddress::from_bytes([0xab; 32]),
            publisher: PublisherConfig {
                intent_gen_command: vec!["sh".to_string(), "-c".to_string(), script],
                funding_seed: "ab".repeat(32),
                proof_server_url: "http://127.0.0.1:6300".to_string(),
                indexer_url: "http://127.0.0.1:8088/api/v3/graphql".to_string(),
                indexer_ws_url: "ws://127.0.0.1:8088/api/v3/graphql/ws".to_string(),
                request_timeout: Duration::from_secs(5),
                restart_backoff: RetryConfig {
                    min_delay: Duration::from_millis(1),
                    max_delay: Duration::from_millis(5),
                    max_times: 2,
                    jitter: false,
                },
                ..Default::default()
            },
            rpc: Default::default(),
            indexer: Default::default(),
        }
    }

    async fn spawn_stub(config: &MidnightConfig) -> IntentGen {
        IntentGen::spawn(config, NETWORK_ID)
            .await
            .expect("the stub spawns")
    }

    #[tokio::test]
    async fn spawn_rejects_a_network_the_child_sdk_does_not_support() {
        let error = IntentGen::spawn(&stub_config("exit 0"), "unknown-network")
            .await
            .err()
            .expect("the parent must reject an unsupported network");
        assert!(error.to_string().contains("network_id"), "{error:#}");
    }

    fn ready_reply_config(reply: &str) -> MidnightConfig {
        let mut config = stub_config("unreachable");
        config.publisher.intent_gen_command = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("read -r ready; printf '%s\\n' '{reply}'; sleep 30"),
        ];
        config
    }

    /// A scratch file a stub counts its spawns in: only state outside the script survives a respawn.
    struct SpawnCounter(PathBuf);

    impl SpawnCounter {
        /// Removed up front, so a previous run of this test cannot decide this one.
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mpc-midnight-intent-gen-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }

        /// A stub prologue that leaves the count of this spawn in `$n`.
        fn prologue(&self) -> String {
            let path = self.0.display();
            format!("n=$(cat {path} 2>/dev/null || echo 0); n=$((n+1)); echo $n > {path};")
        }

        fn spawns(&self) -> u32 {
            std::fs::read_to_string(&self.0)
                .ok()
                .and_then(|text| text.trim().parse().ok())
                .unwrap_or(0)
        }

        /// Waits until `count` children have counted themselves; a killed-early child never counts.
        async fn wait_for(&self, count: u32) {
            for _ in 0..1_000 {
                if self.spawns() >= count {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("the stub never reported {count} spawns");
        }
    }

    impl Drop for SpawnCounter {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// The stub's reply to whatever id it was asked.
    const ECHO_ID_REPLY: &str = r#"id=$(printf "%s" "$line" | sed -n "s/.*\"id\":\([0-9]*\).*/\1/p"); printf "{\"id\":%s,\"ok\":true,\"intent\":\"0a\"}\n" "$id";"#;

    fn sample_request() -> IntentRequest {
        IntentRequest {
            circuit: "respond",
            attestation: None,
            contract_address: "ab".repeat(32),
            request_id: "cd".repeat(32),
            signature: WireSignature {
                big_r: WirePoint {
                    x: "11".repeat(32),
                    y: "22".repeat(32),
                },
                s: "33".repeat(32),
                recovery_id: 1,
            },
            contract_state: "beef".to_string(),
            ledger_parameters: "f00d".to_string(),
            ttl_seconds: 1_800_000_000,
        }
    }

    #[tokio::test]
    async fn build_returns_the_child_s_intent_bytes() {
        let builder = spawn_stub(&stub_config(
            r#"read line; printf '{"id":0,"ok":true,"intent":"deadbeef"}\n'"#,
        ))
        .await;
        let bytes = builder.build(&sample_request()).await.unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[tokio::test]
    async fn build_surfaces_the_child_s_error_code_and_message() {
        let builder = spawn_stub(&stub_config(
        r#"read line; printf '{"id":0,"ok":false,"code":"contract_mismatch","message":"no operation"}\n'"#,
    ))
    .await;
        let err = builder.build(&sample_request()).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("contract_mismatch"),
            "got: {err:#}"
        );
        assert!(format!("{err:#}").contains("no operation"), "got: {err:#}");
        // A refusal is an answer: the command is demonstrably fine, so not named.
        assert!(
            !format!("{err:#}").contains("midnight intent builder command"),
            "a refusal must not be blamed on the command: {err:#}"
        );

        // A null id on the failure arm is this request's own rejection, not a mismatch to bury it under.
        let builder = spawn_stub(&stub_config(
        r#"read line; printf '{"id":null,"ok":false,"code":"bad_request","message":"invalid JSON"}\n'"#,
    ))
    .await;
        let err = builder.build(&sample_request()).await.unwrap_err();
        assert!(format!("{err:#}").contains("bad_request"), "got: {err:#}");
        assert!(format!("{err:#}").contains("invalid JSON"), "got: {err:#}");
    }

    #[tokio::test]
    async fn a_reply_for_another_request_is_refused_rather_than_returned() {
        // The one guard against a desynchronized stream: without it a late reply
        // from an abandoned request becomes this request's signature.
        let builder = spawn_stub(&stub_config(
            r#"read line; printf '{"id":7,"ok":true,"intent":"deadbeef"}\n'"#,
        ))
        .await;
        let err = builder.build(&sample_request()).await.unwrap_err();
        assert!(format!("{err:#}").contains("id 7"), "got: {err:#}");
    }

    #[tokio::test]
    async fn a_dead_child_is_respawned_rather_than_poisoning_every_later_call() {
        let builder = spawn_stub(&stub_config(
            r#"read line; printf '{"id":0,"ok":true,"intent":"01"}\n'"#,
        ))
        .await;
        assert!(builder.build(&sample_request()).await.is_ok());
        assert!(builder.build(&sample_request()).await.is_ok());
    }

    #[tokio::test]
    async fn a_child_that_closes_its_stdout_is_noticed_without_waiting_out_the_timeout() {
        // End-of-input read as a zero-length line would look like an unreadable reply minutes later.
        let mut config = stub_config(r#"read line; exec 1>&-; sleep 30"#);
        // Long enough that the timeout cannot be what saves this test.
        config.publisher.request_timeout = Duration::from_secs(30);
        let builder = spawn_stub(&config).await;
        let started = Instant::now();
        let err = builder.build(&sample_request()).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("closed its stdout"),
            "got: {err:#}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "waited on a pipe that was already closed"
        );
    }

    /// Whatever a build answered with. Opaque to this side, so any bytes do.
    const SAMPLE_INTENT: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

    #[tokio::test]
    async fn a_submit_carries_the_intent_and_answers_with_the_transaction_id() {
        // The stub names the transaction after the intent it was handed, so one
        // assertion covers the whole exchange.
        let builder = spawn_stub(&stub_config(
        r#"read -r line; case "$line" in *'"op":"submit"'*) intent=$(printf "%s" "$line" | sed -n 's/.*"intent":"\([0-9a-f]*\)".*/\1/p'); printf '{"id":0,"ok":true,"txId":"%s","blockHash":"cd"}\n' "$intent" ;; *) printf '{"id":0,"ok":false,"code":"bad_request","message":"this line carries no submit op"}\n' ;; esac"#,
    ))
    .await;
        let tx_id = builder.submit(SAMPLE_INTENT).await.unwrap();
        assert_eq!(tx_id, hex::encode(SAMPLE_INTENT));
    }

    #[tokio::test]
    async fn a_submit_reply_for_another_request_is_ambiguous() {
        let builder = spawn_stub(&stub_config(
            r#"read -r line; printf '{"id":7,"ok":true,"txId":"ab","blockHash":"cd"}\n'"#,
        ))
        .await;
        let err = builder.submit(SAMPLE_INTENT).await.unwrap_err();
        let rendered = format!("{err:#}");

        assert!(rendered.contains("id 7"), "got: {rendered}");
        assert!(
            is_ambiguous_submit(&err),
            "an unpairable submit reply must preserve the on-chain uncertainty: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_submit_the_child_granted_without_naming_the_transaction_is_not_a_receipt() {
        // An empty receipt would log "published successfully" for a post nothing can be looked up by.
        let builder = spawn_stub(&stub_config(
            r#"read -r line; printf '{"id":0,"ok":true,"blockHash":"cd"}\n'"#,
        ))
        .await;
        let err = builder.submit(SAMPLE_INTENT).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("without naming it"),
            "got: {err:#}"
        );
    }

    #[tokio::test]
    async fn a_submit_that_loses_its_answer_is_not_asked_again() {
        // Reissuing a submit whose answer was lost races a second post onto the one
        // dust UTXO; both loss shapes are driven, the dead pipe and the deadline.
        let counter = SpawnCounter::new("submit-dead-pipe");
        let mut config = stub_config(&format!(
            "{} read -r line; exec 1>&-; sleep 30",
            counter.prologue()
        ));
        // Long enough that the closed pipe, not the deadline, is what ends this.
        config.publisher.submit_timeout = Duration::from_secs(30);
        let builder = spawn_stub(&config).await;
        counter.wait_for(1).await;

        let started = Instant::now();
        let err = builder.submit(SAMPLE_INTENT).await.unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("closed its stdout"), "got: {rendered}");
        assert!(
            is_ambiguous_submit(&err),
            "a lost answer must not be reported as a bare transport fault: {rendered}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "waited on a pipe that was already closed"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            counter.spawns(),
            1,
            "a submit must not be reissued on a fresh child"
        );

        // The deadline-blown loss: the wedged child is killed, just not asked again.
        let counter = SpawnCounter::new("submit-timeout");
        let mut config = stub_config(&format!("{} sleep 30", counter.prologue()));
        config.publisher.submit_timeout = Duration::from_millis(50);
        let builder = spawn_stub(&config).await;
        counter.wait_for(1).await;

        let err = builder.submit(SAMPLE_INTENT).await.unwrap_err();
        assert!(
            is_ambiguous_submit(&err),
            "a blown submit deadline must keep the on-chain uncertainty: {err:#}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            counter.spawns(),
            1,
            "a submit must not be reissued on a fresh child"
        );
    }

    #[tokio::test]
    async fn a_submit_surfaces_the_child_s_error_code_and_message() {
        // A refusal like `wallet_unfunded` is the operator's to act on: an answer, not a pipe fault.
        let builder = spawn_stub(&stub_config(
        r#"read -r line; printf '{"id":0,"ok":false,"code":"wallet_unfunded","message":"no spendable dust"}\n'"#,
    ))
    .await;
        let err = builder.submit(SAMPLE_INTENT).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("wallet_unfunded"),
            "got: {err:#}"
        );
        assert!(
            format!("{err:#}").contains("no spendable dust"),
            "got: {err:#}"
        );
        // A refusal is an answer: nothing was posted, so nothing is ambiguous.
        assert!(
            !is_ambiguous_submit(&err),
            "a refusal spent nothing: {err:#}"
        );
    }

    #[tokio::test]
    async fn a_child_submit_timeout_is_typed_as_ambiguous() {
        let builder = spawn_stub(&stub_config(
        r#"read -r line; printf '{"id":0,"ok":false,"code":"ambiguous_submit","message":"may still land"}\n'"#,
    ))
    .await;

        let error = builder
            .submit(&[0xde, 0xad])
            .await
            .expect_err("an ambiguous child answer is not a receipt");

        assert!(is_ambiguous_submit(&error), "unexpected error: {error:#}");
        assert!(format!("{error:#}").contains("may still land"));
        assert!(
            builder.session.lock().await.is_none(),
            "an ambiguous submit answer must retire its child"
        );
    }

    #[tokio::test]
    async fn a_submit_is_bounded_by_the_submit_budget_and_not_the_build_one() {
        // Bounding a submit by the build's budget would kill the child mid-prove on every real post.
        let mut config = stub_config("sleep 30");
        config.publisher.request_timeout = Duration::from_millis(50);
        config.publisher.submit_timeout = Duration::from_millis(400);
        let builder = spawn_stub(&config).await;

        let started = Instant::now();
        let err = builder.submit(SAMPLE_INTENT).await.unwrap_err();
        assert!(format!("{err:#}").contains("timed out"), "got: {err:#}");
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "a submit bounded by the build's 50ms budget would have given up at once, \
         killing the child mid-prove on every real post"
        );
    }

    #[tokio::test]
    async fn a_timed_out_child_is_killed_so_a_later_request_is_served_by_a_fresh_one() {
        // The stub hangs on its first two spawns, exactly the budget one build spends.
        let counter = SpawnCounter::new("timeout-recovery");
        let mut config = stub_config(&format!(
            r#"{} if [ $n -le 2 ]; then sleep 30; else read -r line; {} fi"#,
            counter.prologue(),
            ECHO_ID_REPLY
        ));
        // Wide enough that a fresh `sh -c` spawn beats it even on a loaded machine.
        config.publisher.request_timeout = Duration::from_millis(500);
        let builder = spawn_stub(&config).await;
        counter.wait_for(1).await;

        let err = builder.build(&sample_request()).await.unwrap_err();
        assert!(format!("{err:#}").contains("timed out"), "got: {err:#}");
        // A build leaves nothing behind, so its timeout is never ambiguous.
        assert!(
            !is_ambiguous_submit(&err),
            "a build that timed out spent nothing: {err:#}"
        );

        let bytes = builder
            .build(&sample_request())
            .await
            .expect("the hung child was killed, so this request gets a fresh one");
        assert_eq!(bytes, vec![0x0a]);
    }

    #[tokio::test]
    async fn queued_callers_all_get_their_turn_after_the_child_in_front_of_them_is_replaced() {
        // The lock is held across the kill and the respawn, which is right but is the
        // shape a deadlock would hide in.
        let counter = SpawnCounter::new("queued-callers");
        let mut config = stub_config(&format!(
            r#"{} if [ $n -le 1 ]; then sleep 30; else while read -r line; do {} done fi"#,
            counter.prologue(),
            ECHO_ID_REPLY
        ));
        config.publisher.request_timeout = Duration::from_millis(500);
        let builder = std::sync::Arc::new(spawn_stub(&config).await);
        counter.wait_for(1).await;

        let callers: Vec<_> = (0..3)
            .map(|_| {
                let builder = builder.clone();
                tokio::spawn(async move { builder.build(&sample_request()).await })
            })
            .collect();
        for caller in callers {
            let bytes = caller
                .await
                .expect("no caller is lost")
                .expect("every caller is served, in its turn, by a live child");
            assert_eq!(bytes, vec![0x0a]);
        }
    }

    #[tokio::test]
    async fn a_command_that_exits_at_once_costs_one_respawn_and_then_gives_up() {
        // Uncatchable at `spawn`; what has to hold is bounded failure, not a spin.
        let counter = SpawnCounter::new("exits-at-once");
        let script = format!("{} exit 1", counter.prologue());
        let builder = spawn_stub(&stub_config(&script)).await;

        let started = Instant::now();
        let err = builder.build(&sample_request()).await.unwrap_err();
        // The raw failure is a broken pipe that names no command.
        assert!(
            format!("{err:#}").contains(&script),
            "the error has to name the command that died: {err:#}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a child that dies at once should cost one retry, not a wait"
        );

        // The settle is for the count: a spin would have written hundreds more.
        counter.wait_for(2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            counter.spawns(),
            2,
            "one child at startup and exactly one respawn, no more"
        );
    }

    #[tokio::test]
    async fn a_child_that_exits_before_readiness_fails_startup() {
        let mut config = stub_config("unreachable");
        config.publisher.intent_gen_command =
            vec!["sh".to_string(), "-c".to_string(), "exit 1".to_string()];

        let Err(error) = IntentGen::spawn(&config, NETWORK_ID).await else {
            panic!("an exited process is not a ready publisher")
        };

        assert!(
            format!("{error:#}").contains("closed its stdout"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn a_child_deadline_that_reaches_the_rust_backstop_fails_startup() {
        let mut config = stub_config("unreachable");
        config.publisher.submit_timeout = Duration::from_millis(2);

        let Err(error) = IntentGen::spawn(&config, NETWORK_ID).await else {
            panic!("the Rust supervisor must outlive the child submit deadline")
        };

        assert!(
            format!("{error:#}").contains("child submit timeout (2ms) < Rust backstop (2ms)"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn a_command_that_does_not_exist_fails_at_startup_and_names_itself() {
        // The case the eager spawn does catch: a missing binary is learned at startup.
        let mut config = stub_config("unreachable");
        config.publisher.intent_gen_command = vec!["mpc-midnight-no-such-binary".to_string()];

        let started = Instant::now();
        let Err(err) = IntentGen::spawn(&config, NETWORK_ID).await else {
            panic!("a command that cannot be run must not produce a usable builder")
        };
        assert!(
            format!("{err:#}").contains("mpc-midnight-no-such-binary"),
            "the error has to name the command, since that is the thing to fix: {err:#}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the restart budget is capped, so this cannot hold startup open"
        );
    }

    #[tokio::test]
    async fn the_child_s_environment_is_only_fixed_path_and_parent_config() {
        // The stub reports every name it can see. Whatever the shell did not add must
        // be the fixed launcher path or one of the six parent-set config entries.
        let builder = spawn_stub(&stub_config(
        r#"read -r line; printf '{"id":0,"ok":false,"code":"bad_request","message":"%s"}\n' "$(env | awk -F= '/^[A-Za-z_][A-Za-z0-9_]*=/{print $1}' | sort | tr "\n" ",")""#,
    ))
    .await;
        let err = builder.build(&sample_request()).await.unwrap_err();
        let rendered = format!("{err:#}");
        let (_, names) = rendered
            .split_once("[bad_request]: ")
            .expect("the stub answered with its environment");
        let names: Vec<&str> = names.split(',').filter(|name| !name.is_empty()).collect();

        let ours: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| name.starts_with("MIDNIGHT_PUB_"))
            .collect();
        assert_eq!(
            ours,
            [
                "MIDNIGHT_PUB_FUNDING_SEED",
                "MIDNIGHT_PUB_INDEXER_URL",
                "MIDNIGHT_PUB_INDEXER_WS_URL",
                "MIDNIGHT_PUB_NETWORK_ID",
                "MIDNIGHT_PUB_NODE_URL",
                "MIDNIGHT_PUB_PROOF_SERVER_URL",
            ],
            "the child must receive exactly the parent-owned publisher config"
        );
        let shell_added = ["PWD", "OLDPWD", "SHLVL", "_"];
        let strays: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| {
                !name.starts_with("MIDNIGHT_PUB_") && *name != "PATH" && !shell_added.contains(name)
            })
            .collect();
        assert!(strays.is_empty(), "the child inherited {strays:?}");
    }

    #[tokio::test]
    async fn a_child_that_dies_after_readiness_reports_what_it_said_on_its_way_out() {
        let builder = spawn_stub(&stub_config(
            r#"printf 'publisher stopped after readiness\n' >&2; exit 1"#,
        ))
        .await;

        let err = builder.build(&sample_request()).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("publisher stopped after readiness"),
            "the child's own explanation has to reach whoever asked: {err:#}"
        );
    }

    #[test]
    fn only_fixed_path_and_parent_config_reach_the_child() {
        let config = stub_config("true");
        let command =
            intent_gen_command(&config, NETWORK_ID).expect("the stub command is well formed");
        let mut values: Vec<(String, String)> = command
            .as_std()
            .get_envs()
            .map(|(name, value)| {
                let value = value.unwrap_or_else(|| panic!("{name:?} is unset rather than absent"));
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect();
        values.sort();
        assert_eq!(
            values,
            [
                (
                    "MIDNIGHT_PUB_FUNDING_SEED".to_string(),
                    config.publisher.funding_seed.clone(),
                ),
                (
                    "MIDNIGHT_PUB_INDEXER_URL".to_string(),
                    config.publisher.indexer_url.clone(),
                ),
                (
                    "MIDNIGHT_PUB_INDEXER_WS_URL".to_string(),
                    config.publisher.indexer_ws_url.clone(),
                ),
                (
                    "MIDNIGHT_PUB_NETWORK_ID".to_string(),
                    NETWORK_ID.to_string(),
                ),
                ("MIDNIGHT_PUB_NODE_URL".to_string(), config.node_url.clone()),
                (
                    "MIDNIGHT_PUB_PROOF_SERVER_URL".to_string(),
                    config.publisher.proof_server_url.clone(),
                ),
                (
                    "PATH".to_string(),
                    "/usr/local/bin:/usr/bin:/bin".to_string(),
                ),
            ],
            "the child environment is exactly fixed PATH plus parent-owned config"
        );
    }

    #[test]
    fn the_encoded_line_is_the_shape_the_child_validates() {
        let encoded: serde_json::Value = serde_json::from_str(
            &encode_request(&sample_request(), 3, Operation::BuildIntent.wire_op()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({
                "id": 3,
                "op": "build",
                "circuit": "respond",
                "contractAddress": "ab".repeat(32),
                "requestId": "cd".repeat(32),
                "signature": {
                    "bigR": { "x": "11".repeat(32), "y": "22".repeat(32) },
                    "s": "33".repeat(32),
                    "recoveryId": 1,
                },
                "contractState": "beef",
                "ledgerParameters": "f00d",
                "ttlSeconds": 1_800_000_000u64,
            }),
            "the unidirectional circuit carries no output fields, and the child's \
         discriminated union rejects the request outright if it does. Every protocol \
         application request names its operation explicitly"
        );
    }

    #[tokio::test]
    async fn readiness_sends_and_requires_protocol_generation_three() {
        let script = r#"read -r ready; if [ "$ready" = '{"id":0,"op":"ready","protocolVersion":3}' ]; then printf '{"id":0,"ok":true,"ready":true,"protocolVersion":3,"submitTimeoutMs":2,"recipeTtlMs":1}\n'; else printf '{"id":0,"ok":false,"code":"bad_request","message":"wrong ready request"}\n'; fi; sleep 30"#;
        let mut config = stub_config("unreachable");
        config.publisher.intent_gen_command =
            vec!["sh".to_string(), "-c".to_string(), script.to_string()];

        IntentGen::spawn(&config, NETWORK_ID)
            .await
            .expect("generation 3 readiness without a snapshot succeeds");
    }

    #[tokio::test]
    async fn readiness_rejects_every_invalid_handshake() {
        let invalid_replies = [
            (
                "missing ready field",
                r#"{"id":0,"ok":true,"protocolVersion":3,"submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
            (
                "false ready field",
                r#"{"id":0,"ok":true,"ready":false,"protocolVersion":3,"submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
            (
                "missing protocol version",
                r#"{"id":0,"ok":true,"ready":true,"submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
            (
                "older protocol version",
                r#"{"id":0,"ok":true,"ready":true,"protocolVersion":2,"submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
            (
                "newer protocol version",
                r#"{"id":0,"ok":true,"ready":true,"protocolVersion":4,"submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
            (
                "wrongly typed protocol version",
                r#"{"id":0,"ok":true,"ready":true,"protocolVersion":"3","submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
            (
                "null protocol version",
                r#"{"id":0,"ok":true,"ready":true,"protocolVersion":null,"submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
        ];

        for (case, reply) in invalid_replies {
            let result = IntentGen::spawn(&ready_reply_config(reply), NETWORK_ID).await;
            assert!(result.is_err(), "{case} must not start a session");
        }
    }

    #[tokio::test]
    async fn request_ids_wrap_before_json_would_round_them() {
        let builder = spawn_stub(&stub_config(
            r#"for round in 1 2; do read -r line; id=$(printf "%s" "$line" | sed -n "s/.*\"id\":\([0-9]*\).*/\1/p"); case "$round:$id" in 1:9007199254740991|2:0) printf '{"id":%s,"ok":true,"intent":"0a"}\n' "$id" ;; *) printf '{"id":%s,"ok":false,"code":"bad_request","message":"expected max then zero"}\n' "$id" ;; esac; done"#,
        ))
        .await;
        builder.session.lock().await.as_mut().unwrap().next_id = 9_007_199_254_740_991;

        builder
            .build(&sample_request())
            .await
            .expect("the maximum safe id is valid");
        builder
            .build(&sample_request())
            .await
            .expect("the next id wraps to zero instead of crossing the JSON integer boundary");
    }

    #[test]
    fn a_submit_line_names_the_operation_and_carries_nothing_but_the_intent() {
        let encoded: serde_json::Value = serde_json::from_str(
            &encode_request(
                &SubmitRequest {
                    intent: "deadbeef".to_string(),
                },
                4,
                Operation::Submit.wire_op(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            encoded,
            serde_json::json!({ "id": 4, "op": "submit", "intent": "deadbeef" }),
            "the pinned reads that built the intent have no reader on the other side, \
         and the child balances against a wallet it syncs itself"
        );
    }

    /// A store whose contents a test sets and reads back.
    #[derive(Default)]
    struct MemoryStore {
        stored: std::sync::Mutex<Option<String>>,
        saves: std::sync::atomic::AtomicUsize,
        clears: std::sync::atomic::AtomicUsize,
        fail_load: bool,
    }

    impl MemoryStore {
        fn holding(snapshot: &str) -> Arc<Self> {
            let store = Self::default();
            *store.stored.lock().unwrap() = Some(snapshot.to_string());
            Arc::new(store)
        }

        fn stored(&self) -> Option<String> {
            self.stored.lock().unwrap().clone()
        }

        fn saves(&self) -> usize {
            self.saves.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn clears(&self) -> usize {
            self.clears.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl WalletSnapshotStore for MemoryStore {
        async fn load(&self) -> anyhow::Result<Option<String>> {
            anyhow::ensure!(!self.fail_load, "redis is down");
            Ok(self.stored())
        }

        async fn save(&self, snapshot: &str) -> anyhow::Result<()> {
            *self.stored.lock().unwrap() = Some(snapshot.to_string());
            self.saves.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        async fn clear(&self) -> anyhow::Result<()> {
            *self.stored.lock().unwrap() = None;
            self.clears
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    /// A scratch file a stub appends lines to, removed up front and on drop.
    struct StubLog(PathBuf);

    impl StubLog {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mpc-midnight-intent-gen-{name}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&path);
            Self(path)
        }

        fn lines(&self) -> Vec<String> {
            std::fs::read_to_string(&self.0)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    impl Drop for StubLog {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// A child that logs its ready line to `readies` and every snapshot request to
    /// `asked`, answering each snapshot request with `snapshot_replies` in turn (the last
    /// repeating) and each submit with `submit_reply`. Replies are the fields after `id`.
    fn snapshot_stub(
        readies: &StubLog,
        asked: &StubLog,
        snapshot_replies: &[&str],
        submit_reply: &str,
    ) -> MidnightConfig {
        let mut config = stub_config("unreachable");
        let (readies, asked) = (readies.0.display(), asked.0.display());
        let replies = snapshot_replies
            .iter()
            .enumerate()
            .map(|(index, reply)| format!("{}) body='{reply}' ;;", index + 1))
            .collect::<Vec<_>>()
            .join(" ");
        let last = snapshot_replies
            .last()
            .expect("at least one snapshot reply");
        config.publisher.intent_gen_command = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                r#"read -r ready; printf '%s\n' "$ready" >> {readies}; printf '{{"id":0,"ok":true,"ready":true,"protocolVersion":3,"submitTimeoutMs":2,"recipeTtlMs":1}}\n'; n=0; while read -r line; do id=$(printf "%s" "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p'); case "$line" in *'"op":"snapshot"'*) printf '%s\n' "$line" >> {asked}; n=$((n+1)); case "$n" in {replies} *) body='{last}' ;; esac ;; *) body='{submit_reply}' ;; esac; printf '{{"id":%s,%s}}\n' "$id" "$body"; done"#
            ),
        ];
        config
    }

    const LANDED: &str = r#""ok":true,"txId":"ab""#;
    const FRESH: &str = r#""ok":true,"walletSnapshot":"fresh""#;

    async fn spawn_with(config: &MidnightConfig, store: Arc<MemoryStore>) -> IntentGen {
        IntentGen::spawn_with_snapshots(config, NETWORK_ID, Some(store))
            .await
            .expect("the stub spawns")
    }

    #[tokio::test]
    async fn a_child_resumes_from_the_stored_snapshot_and_a_refresh_stores_a_fresh_one() {
        let (readies, asked) = (StubLog::new("snap-ready"), StubLog::new("snap-asked"));
        let store = MemoryStore::holding("stored");
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[FRESH], LANDED),
            store.clone(),
        )
        .await;

        builder.refresh_snapshot().await;

        assert_eq!(
            readies.lines(),
            [r#"{"id":0,"op":"ready","protocolVersion":3,"walletSnapshot":"stored"}"#]
        );
        assert_eq!(asked.lines(), [r#"{"id":0,"op":"snapshot"}"#]);
        assert_eq!(store.stored().as_deref(), Some("fresh"));
        assert_eq!(builder.snapshots.latest().as_deref(), Some("fresh"));
    }

    #[tokio::test]
    async fn a_kept_snapshot_is_not_asked_for_again_within_the_interval() {
        let (readies, asked) = (
            StubLog::new("snap-interval-ready"),
            StubLog::new("snap-interval-asked"),
        );
        let store = Arc::new(MemoryStore::default());
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[FRESH], LANDED),
            store.clone(),
        )
        .await;

        builder.refresh_snapshot().await;
        builder.refresh_snapshot().await;

        assert_eq!(asked.lines().len(), 1);
        assert_eq!(store.saves(), 1);
    }

    #[tokio::test]
    async fn a_refused_snapshot_is_asked_for_again_on_the_next_refresh() {
        let (readies, asked) = (
            StubLog::new("snap-refused-ready"),
            StubLog::new("snap-refused-asked"),
        );
        let unsynced = r#""ok":false,"code":"wallet_unsynced","message":"still syncing""#;
        let store = Arc::new(MemoryStore::default());
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[unsynced, FRESH], LANDED),
            store.clone(),
        )
        .await;

        builder.refresh_snapshot().await;
        assert_eq!(store.saves(), 0, "a refusal keeps nothing");
        builder.refresh_snapshot().await;

        assert_eq!(asked.lines().len(), 2);
        assert_eq!(store.stored().as_deref(), Some("fresh"));
    }

    #[tokio::test]
    async fn a_respawned_child_resumes_from_the_snapshot_kept_in_memory() {
        let (readies, asked) = (
            StubLog::new("snap-respawn-ready"),
            StubLog::new("snap-respawn-asked"),
        );
        let ambiguous = r#""ok":false,"code":"ambiguous_submit","message":"may still land""#;
        let store = Arc::new(MemoryStore::default());
        let builder =
            spawn_with(&snapshot_stub(&readies, &asked, &[FRESH], ambiguous), store).await;
        builder.snapshots.keep("kept".to_string()).await;

        let error = builder.submit(&[0x0a]).await.unwrap_err();
        assert!(is_ambiguous_submit(&error), "{error:#}");
        builder.refresh_snapshot().await;
        assert_eq!(
            readies.lines().len(),
            1,
            "no child is spawned only to snapshot it"
        );
        assert!(asked.lines().is_empty());
        let _ = builder.build(&sample_request()).await;

        assert_eq!(readies.lines().len(), 2);
        assert_eq!(
            readies.lines()[1],
            r#"{"id":0,"op":"ready","protocolVersion":3,"walletSnapshot":"kept"}"#
        );
    }

    const UNFUNDED: &str = r#""ok":false,"code":"wallet_unfunded","message":"could not balance dust","walletUsed":true"#;
    const CONFLICT: &str = r#""ok":false,"code":"state_conflict","message":"1010: Invalid Transaction","walletUsed":true"#;

    #[tokio::test]
    async fn a_retired_child_is_not_asked_for_a_snapshot() {
        let (readies, asked) = (
            StubLog::new("snap-last-ready"),
            StubLog::new("snap-last-asked"),
        );
        let store = Arc::new(MemoryStore::default());
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[FRESH], CONFLICT),
            store.clone(),
        )
        .await;

        builder.submit(&[0x0a]).await.unwrap_err();

        assert!(builder.session.lock().await.is_none());
        assert!(
            asked.lines().is_empty(),
            "a refused wallet's state is not kept"
        );
        assert_eq!(store.saves(), 0);
        let _ = builder.build(&sample_request()).await;
        assert_eq!(
            readies.lines()[1],
            r#"{"id":0,"op":"ready","protocolVersion":3}"#
        );
    }

    #[tokio::test]
    async fn a_restored_child_refused_unfunded_once_keeps_the_snapshot() {
        let (readies, asked) = (
            StubLog::new("snap-unfunded-ready"),
            StubLog::new("snap-unfunded-asked"),
        );
        let store = MemoryStore::holding("stored");
        let busy = r#""ok":false,"code":"wallet_busy","message":"coins in flight""#;
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[busy], UNFUNDED),
            store.clone(),
        )
        .await;

        builder.submit(&[0x0a]).await.unwrap_err();

        assert!(builder.session.lock().await.is_none());
        assert_eq!(builder.snapshots.latest().as_deref(), Some("stored"));
        assert_eq!(store.clears(), 0);
    }

    #[tokio::test]
    async fn a_discard_lets_the_next_settled_wallet_be_kept_at_once() {
        let (readies, asked) = (
            StubLog::new("snap-discard-ready"),
            StubLog::new("snap-discard-asked"),
        );
        let store = Arc::new(MemoryStore::default());
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[FRESH], LANDED),
            store.clone(),
        )
        .await;
        builder.snapshots.keep("kept".to_string()).await;

        builder.snapshots.forget().await;
        assert_eq!(store.clears(), 1);
        builder.refresh_snapshot().await;

        assert_eq!(store.stored().as_deref(), Some("fresh"));
    }

    #[tokio::test]
    async fn a_restored_child_refused_once_otherwise_keeps_the_snapshot() {
        let (readies, asked) = (
            StubLog::new("snap-keep-ready"),
            StubLog::new("snap-keep-asked"),
        );
        let store = MemoryStore::holding("stored");
        let busy = r#""ok":false,"code":"wallet_busy","message":"coins in flight""#;
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[busy], CONFLICT),
            store.clone(),
        )
        .await;

        builder.submit(&[0x0a]).await.unwrap_err();

        assert_eq!(builder.snapshots.latest().as_deref(), Some("stored"));
        assert_eq!(store.clears(), 0);
    }

    #[tokio::test]
    async fn restored_children_refused_in_a_row_discard_the_snapshot_for_a_full_sync() {
        let (readies, asked) = (
            StubLog::new("snap-strikes-ready"),
            StubLog::new("snap-strikes-asked"),
        );
        let store = MemoryStore::holding("stored");
        let busy = r#""ok":false,"code":"wallet_busy","message":"coins in flight""#;
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[busy], CONFLICT),
            store.clone(),
        )
        .await;

        for _ in 1..RESTORE_STRIKES {
            builder.submit(&[0x0a]).await.unwrap_err();
        }
        assert_eq!(builder.snapshots.latest().as_deref(), Some("stored"));
        builder.submit(&[0x0a]).await.unwrap_err();
        assert_eq!(builder.snapshots.latest(), None);
        assert_eq!(store.clears(), 1);
        let _ = builder.build(&sample_request()).await;

        let readies = readies.lines();
        let restored = r#"{"id":0,"op":"ready","protocolVersion":3,"walletSnapshot":"stored"}"#;
        assert_eq!(readies.len(), RESTORE_STRIKES as usize + 1);
        assert!(readies[..RESTORE_STRIKES as usize]
            .iter()
            .all(|ready| ready == restored));
        assert_eq!(
            readies[RESTORE_STRIKES as usize],
            r#"{"id":0,"op":"ready","protocolVersion":3}"#
        );
        assert!(
            asked.lines().is_empty(),
            "no retiring child is asked for a snapshot"
        );
    }

    #[tokio::test]
    async fn restored_children_refused_before_using_the_wallet_keep_the_snapshot() {
        let (readies, asked) = (
            StubLog::new("snap-prewallet-ready"),
            StubLog::new("snap-prewallet-asked"),
        );
        let store = MemoryStore::holding("stored");
        let proving =
            r#""ok":false,"code":"internal","message":"proof server /prove request failed""#;
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[FRESH], proving),
            store.clone(),
        )
        .await;

        for _ in 0..=RESTORE_STRIKES {
            builder.submit(&[0x0a]).await.unwrap_err();
            assert!(builder.session.lock().await.is_none());
        }

        assert_eq!(builder.snapshots.latest().as_deref(), Some("stored"));
        assert_eq!(store.clears(), 0);
    }

    /// A child that logs its ready line to `readies`, then dies on its first request.
    fn dying_stub(readies: &StubLog) -> MidnightConfig {
        let mut config = stub_config("unreachable");
        config.publisher.intent_gen_command = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!(
                r#"read -r ready; printf '%s\n' "$ready" >> {}; printf '{{"id":0,"ok":true,"ready":true,"protocolVersion":3,"submitTimeoutMs":2,"recipeTtlMs":1}}\n'; read -r line; exit 1"#,
                readies.0.display()
            ),
        ];
        config
    }

    #[tokio::test]
    async fn restored_children_that_keep_dying_discard_the_snapshot_for_a_full_sync() {
        let readies = StubLog::new("snap-dying-ready");
        let store = MemoryStore::holding("stored");
        let builder = spawn_with(&dying_stub(&readies), store.clone()).await;

        for _ in 1..RESTORE_STRIKES {
            builder.submit(&[0x0a]).await.unwrap_err();
        }
        assert_eq!(builder.snapshots.latest().as_deref(), Some("stored"));
        builder.submit(&[0x0a]).await.unwrap_err();
        assert_eq!(builder.snapshots.latest(), None);
        assert_eq!(store.clears(), 1);
        let _ = builder.build(&sample_request()).await;

        let readies = readies.lines();
        let restored = r#"{"id":0,"op":"ready","protocolVersion":3,"walletSnapshot":"stored"}"#;
        assert!(readies[..RESTORE_STRIKES as usize]
            .iter()
            .all(|ready| ready == restored));
        assert_eq!(
            readies[RESTORE_STRIKES as usize],
            r#"{"id":0,"op":"ready","protocolVersion":3}"#
        );
    }

    #[tokio::test]
    async fn a_dying_child_that_synced_from_the_start_strikes_nothing() {
        let readies = StubLog::new("snap-dying-fresh-ready");
        let builder = spawn_with(&dying_stub(&readies), Arc::new(MemoryStore::default())).await;

        for _ in 1..RESTORE_STRIKES {
            builder.submit(&[0x0a]).await.unwrap_err();
        }

        assert!(
            !builder.snapshots.strike(),
            "no child was restored from a snapshot, so this is the first strike"
        );
    }

    #[tokio::test]
    async fn a_landed_submit_starts_the_restored_refusals_over() {
        let (readies, asked) = (
            StubLog::new("snap-proved-ready"),
            StubLog::new("snap-proved-asked"),
        );
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[FRESH], LANDED),
            MemoryStore::holding("stored"),
        )
        .await;
        for _ in 1..RESTORE_STRIKES {
            builder.snapshots.strike();
        }

        builder.submit(&[0x0a]).await.unwrap();

        assert!(
            !builder.snapshots.strike(),
            "a landed submit starts the count over"
        );
    }

    #[tokio::test]
    async fn only_a_landed_submit_or_a_discard_starts_the_restored_refusals_over() {
        let (readies, asked) = (
            StubLog::new("snap-count-ready"),
            StubLog::new("snap-count-asked"),
        );
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[FRESH], LANDED),
            Arc::new(MemoryStore::default()),
        )
        .await;
        for _ in 1..RESTORE_STRIKES {
            builder.snapshots.strike();
        }

        builder.refresh_snapshot().await;
        assert_eq!(builder.snapshots.latest().as_deref(), Some("fresh"));
        assert!(builder.snapshots.strike(), "a kept snapshot proves nothing");

        builder.snapshots.forget().await;
        assert!(
            !builder.snapshots.strike(),
            "a discard starts the count over"
        );
    }

    #[tokio::test]
    async fn a_child_that_synced_from_the_start_strikes_nothing_against_the_snapshot() {
        let (readies, asked) = (
            StubLog::new("snap-unrestored-ready"),
            StubLog::new("snap-unrestored-asked"),
        );
        let store = Arc::new(MemoryStore::default());
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[FRESH], CONFLICT),
            store.clone(),
        )
        .await;

        // The first child syncs from the start and keeps its snapshot; the restored ones
        // after it stop one short of a discard.
        builder.refresh_snapshot().await;
        for _ in 0..RESTORE_STRIKES {
            builder.submit(&[0x0a]).await.unwrap_err();
        }

        assert_eq!(builder.snapshots.latest().as_deref(), Some("fresh"));
        assert_eq!(store.clears(), 0);
    }

    #[tokio::test]
    async fn a_refused_submit_retires_its_child_for_one_restored_from_the_kept_snapshot() {
        let (readies, asked) = (
            StubLog::new("snap-retire-ready"),
            StubLog::new("snap-retire-asked"),
        );
        let conflict =
            r#""ok":false,"code":"state_conflict","message":"1010: Invalid Transaction""#;
        let store = Arc::new(MemoryStore::default());
        let builder = spawn_with(&snapshot_stub(&readies, &asked, &[FRESH], conflict), store).await;
        builder.snapshots.keep("kept".to_string()).await;

        let error = builder.submit(&[0x0a]).await.unwrap_err();
        assert!(format!("{error:#}").contains("state_conflict"), "{error:#}");
        assert!(!is_ambiguous_submit(&error), "{error:#}");
        assert!(
            builder.session.lock().await.is_none(),
            "a refused submit must retire its child"
        );
        let _ = builder.build(&sample_request()).await;

        assert_eq!(
            readies.lines(),
            [
                r#"{"id":0,"op":"ready","protocolVersion":3}"#,
                r#"{"id":0,"op":"ready","protocolVersion":3,"walletSnapshot":"kept"}"#,
            ]
        );
    }

    #[tokio::test]
    async fn a_submit_refused_while_the_wallet_syncs_keeps_its_child_syncing() {
        let (readies, asked) = (
            StubLog::new("snap-syncing-ready"),
            StubLog::new("snap-syncing-asked"),
        );
        let unsynced = r#""ok":false,"code":"wallet_unsynced","message":"still syncing""#;
        let store = Arc::new(MemoryStore::default());
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[unsynced], unsynced),
            store,
        )
        .await;

        builder.submit(&[0x0a]).await.unwrap_err();
        builder.submit(&[0x0a]).await.unwrap_err();

        assert!(builder.session.lock().await.is_some());
        assert_eq!(
            readies.lines().len(),
            1,
            "a restart would only start the sync over"
        );
    }

    #[tokio::test]
    async fn a_refusal_s_wallet_state_stays_out_of_the_error_text() {
        // Status-code detection scans the error text, and a count like 429 would trip it.
        let (readies, asked) = (
            StubLog::new("snap-state-ready"),
            StubLog::new("snap-state-asked"),
        );
        let unsynced = r#""ok":false,"code":"wallet_unsynced","message":"still syncing","walletState":"applied=429/1000""#;
        let store = Arc::new(MemoryStore::default());
        let builder = spawn_with(
            &snapshot_stub(&readies, &asked, &[unsynced], unsynced),
            store,
        )
        .await;

        let error = builder.submit(&[0x0a]).await.unwrap_err();

        assert!(format!("{error:#}").contains("still syncing"), "{error:#}");
        assert!(!format!("{error:#}").contains("429"), "{error:#}");
        let refusal = error.downcast_ref::<Refusal>().expect("a typed refusal");
        assert_eq!(refusal.wallet_state.as_deref(), Some("applied=429/1000"));
    }

    #[tokio::test]
    async fn a_store_that_fails_to_load_starts_the_child_without_a_snapshot() {
        let (readies, asked) = (
            StubLog::new("snap-noload-ready"),
            StubLog::new("snap-noload-asked"),
        );
        let store = Arc::new(MemoryStore {
            fail_load: true,
            ..Default::default()
        });
        spawn_with(&snapshot_stub(&readies, &asked, &[FRESH], LANDED), store).await;

        assert_eq!(
            readies.lines(),
            [r#"{"id":0,"op":"ready","protocolVersion":3}"#]
        );
    }
}
