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
use mpc_chain_integration_core::utils::retry::retry_rpc;
use mpc_utils::task::AbortOnDrop;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::config::{validate_publisher_network_id, MidnightConfig, PublisherConfig};

#[derive(Debug)]
pub(crate) struct AmbiguousSubmit;

impl std::fmt::Display for AmbiguousSubmit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "the answer was lost; the transaction may still reach the chain, so check it for \
             this request before posting again by reconciling finalized state",
        )
    }
}

impl std::error::Error for AmbiguousSubmit {}

pub(crate) fn is_ambiguous_submit(error: &anyhow::Error) -> bool {
    error.downcast_ref::<AmbiguousSubmit>().is_some()
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

/// What the child is being asked to do. A build's lost answer can simply be asked for
/// again; a submit's may be on chain, and asking again races the single dust UTXO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Ready,
    BuildIntent,
    Submit,
}

impl Operation {
    /// Build and readiness share the request budget. Submit uses Rust's process
    /// backstop, whose strict ordering against the child's own deadlines is checked
    /// during the readiness exchange.
    fn deadline(self, config: &PublisherConfig) -> Duration {
        match self {
            Self::Ready | Self::BuildIntent => config.request_timeout,
            Self::Submit => config.submit_timeout,
        }
    }

    /// Whether an answer lost in transit may simply be asked for again.
    fn is_repeatable(self) -> bool {
        matches!(self, Self::Ready | Self::BuildIntent)
    }

    /// The `op` the child discriminates on.
    fn wire_op(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::BuildIntent => "build",
            Self::Submit => "submit",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Ready => "readiness check",
            Self::BuildIntent => "intent build",
            Self::Submit => "submit",
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
}

impl IntentGen {
    /// Starts the builder eagerly: a command that cannot run fails here, not on the first signature.
    pub async fn spawn(config: &MidnightConfig, network_id: &str) -> anyhow::Result<Self> {
        config.validate()?;
        validate_publisher_network_id(network_id)?;
        Ok(Self {
            config: config.clone(),
            network_id: network_id.to_string(),
            session: Mutex::new(Some(spawn_session(config, network_id).await?)),
        })
    }

    /// The serialized ledger `Intent` for `request`.
    pub async fn build(
        &self,
        request: &IntentRequest,
        cancel: &CancellationToken,
    ) -> anyhow::Result<Vec<u8>> {
        let reply = self
            .dispatch(request, cancel, Operation::BuildIntent)
            .await?;
        let intent = reply
            .intent
            .context("midnight intent builder granted a request without an intent")?;
        hex::decode(&intent).context("decoding the intent the builder granted")
    }

    /// Balances, proves and posts `intent`, answering with what names it on chain.
    /// Attempted exactly once.
    pub async fn submit(
        &self,
        intent: &[u8],
        cancel: &CancellationToken,
    ) -> anyhow::Result<String> {
        let request = SubmitRequest {
            intent: hex::encode(intent),
        };
        let reply = self.dispatch(&request, cancel, Operation::Submit).await?;
        reply
            .tx_id
            .context("midnight intent builder posted a transaction without naming it")
    }

    /// One operation, start to finish; budget and reissue policy come from
    /// `operation`, never from the caller.
    async fn dispatch<T: Serialize>(
        &self,
        request: &T,
        cancel: &CancellationToken,
        operation: Operation,
    ) -> anyhow::Result<WireReply> {
        let mut session = self.session.lock().await;
        let (error, retry) = match self.attempt(&mut session, request, cancel, operation).await {
            Exchange::Answered(result) => return result,
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
        match self.attempt(&mut session, request, cancel, operation).await {
            Exchange::Answered(result) => result,
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

    /// One pass. A broken exchange or ambiguous submit empties the slot, killing the
    /// child: nothing later reads its pipe.
    async fn attempt<T: Serialize>(
        &self,
        session: &mut Option<Session>,
        request: &T,
        cancel: &CancellationToken,
        operation: Operation,
    ) -> Exchange {
        if session.is_none() {
            match spawn_session(&self.config, &self.network_id).await {
                Ok(fresh) => *session = Some(fresh),
                // The restart budget was already spent inside the spawn; a second pass
                // would only spend it again.
                Err(error) => return Exchange::give_up(error),
            }
        }
        let live = session
            .as_mut()
            .expect("the slot was just filled or was already full");
        let outcome = exchange(live, request, operation, &self.config.publisher, cancel).await;
        if matches!(
            &outcome,
            Exchange::Answered(Err(error))
                if error.downcast_ref::<AmbiguousSubmit>().is_some()
        ) {
            // The wallet work may still be running after its answer times out, so no
            // later request may reuse this child.
            *session = None;
            return outcome;
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
    /// A reply that answers this request, whether it granted it or refused it.
    Answered(anyhow::Result<WireReply>),
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
        Operation::Ready | Operation::BuildIntent => error,
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

/// Starts the builder under the restart budget.
async fn spawn_session(config: &MidnightConfig, network_id: &str) -> anyhow::Result<Session> {
    retry_rpc!(
        config.publisher.request_timeout,
        config.publisher.restart_backoff,
        "midnight_intent_gen_spawn",
        {
            let session = spawn_child(config, network_id)?;
            verify_ready(session, &config.publisher).await
        }
    )
}

const PUBLISHER_PROTOCOL_VERSION: u64 = 1;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadyRequest {
    protocol_version: u64,
}

async fn verify_ready(mut session: Session, config: &PublisherConfig) -> anyhow::Result<Session> {
    let id = take_wire_id(&mut session.next_id);
    let line = encode_request(
        &ReadyRequest {
            protocol_version: PUBLISHER_PROTOCOL_VERSION,
        },
        id,
        Operation::Ready,
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
        .env("MIDNIGHT_PUB_NODE_URL", &config.node_ws_url)
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
    cancel: &CancellationToken,
) -> Exchange {
    let id = take_wire_id(&mut session.next_id);
    let line = match encode_request(request, id, operation) {
        Ok(line) => line,
        // Nothing reached the pipe, so the child is still in step.
        Err(error) => return Exchange::Answered(Err(error)),
    };

    match exchange_inner(session, &line, id, operation, config, cancel).await {
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
    cancel: &CancellationToken,
) -> Exchange {
    let deadline = operation.deadline(config);
    let reply = tokio::select! {
        // Nothing here can tell a cancel that raced the write from one that beat it,
        // so a cancelled submit reports what it may have left behind.
        _ = cancel.cancelled() => {
            return Exchange::give_up(anyhow::anyhow!(
                "midnight {} cancelled",
                operation.name(),
            ))
        }
        // A timed-out child is a dead publisher if kept: a wedged circuit run wedges the
        // process while it still looks healthy. `Broken` kills it; a submit is still not reissued.
        result = tokio::time::timeout(deadline, round_trip(session, line)) => match result {
            Ok(Ok(reply)) => reply,
            Ok(Err(error)) => return Exchange::lost(error, operation),
            Err(_) => return Exchange::lost(
                anyhow::anyhow!("midnight {} timed out after {deadline:?}", operation.name()),
                operation,
            ),
        },
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
        // A grant with no id is not an answer to anything nameable.
        None if reply.ok => {
            return Exchange::give_up(anyhow::anyhow!(
                "midnight intent builder granted a request with no id"
            ))
        }
        _ => {}
    }
    Exchange::Answered(granted(reply))
}

fn granted(reply: WireReply) -> anyhow::Result<WireReply> {
    if !reply.ok {
        let code = reply.code.as_deref().unwrap_or("no code");
        let error = anyhow::anyhow!(
            "midnight intent builder refused the request [{}]: {}",
            code,
            reply.message.as_deref().unwrap_or("no message")
        );
        return Err(if code == "ambiguous_submit" {
            error.context(AmbiguousSubmit)
        } else {
            error
        });
    }
    Ok(reply)
}

fn encode_request<T: Serialize>(
    request: &T,
    id: u64,
    operation: Operation,
) -> anyhow::Result<String> {
    serde_json::to_string(&WireRequest {
        id,
        op: operation.wire_op(),
        request,
    })
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
    code: Option<String>,
    message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::{MidnightConfig, PublisherConfig};
    use mpc_chain_integration_core::utils::retry::RetryConfig;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;

    const NETWORK_ID: &str = "undeployed";
    const NODE_WS_URL: &str = "ws://127.0.0.1:9944";

    /// A shell stub in place of the real Node child; a test reading an unpinned field
    /// must pin its own, or it silently tests the default.
    fn stub_config(script: &str) -> MidnightConfig {
        let script = format!(
            r#"read -r ready; ready_id=$(printf "%s" "$ready" | sed -n 's/.*"id":\([0-9]*\).*/\1/p'); printf '{{"id":%s,"ok":true,"ready":true,"protocolVersion":1,"submitTimeoutMs":2,"recipeTtlMs":1}}\n' "$ready_id"; {script}"#
        );
        MidnightConfig {
            node_ws_url: NODE_WS_URL.to_string(),
            central_address: "ab".repeat(32),
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
        let bytes = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[tokio::test]
    async fn build_surfaces_the_child_s_error_code_and_message() {
        let builder = spawn_stub(&stub_config(
        r#"read line; printf '{"id":0,"ok":false,"code":"contract_mismatch","message":"no operation"}\n'"#,
    ))
    .await;
        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
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
        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
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
        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("id 7"), "got: {err:#}");
    }

    #[tokio::test]
    async fn a_dead_child_is_respawned_rather_than_poisoning_every_later_call() {
        let builder = spawn_stub(&stub_config(
            r#"read line; printf '{"id":0,"ok":true,"intent":"01"}\n'"#,
        ))
        .await;
        assert!(builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .is_ok());
        assert!(builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn a_child_that_closes_its_stdout_is_noticed_without_waiting_out_the_timeout() {
        // End-of-input read as a zero-length line would look like an unreadable reply minutes later.
        let mut config = stub_config(r#"read line; exec 1>&-; sleep 30"#);
        // Long enough that the timeout cannot be what saves this test.
        config.publisher.request_timeout = Duration::from_secs(30);
        let builder = spawn_stub(&config).await;
        let started = Instant::now();
        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
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
        let tx_id = builder
            .submit(SAMPLE_INTENT, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(tx_id, hex::encode(SAMPLE_INTENT));
    }

    #[tokio::test]
    async fn a_submit_reply_for_another_request_is_ambiguous() {
        let builder = spawn_stub(&stub_config(
            r#"read -r line; printf '{"id":7,"ok":true,"txId":"ab","blockHash":"cd"}\n'"#,
        ))
        .await;
        let err = builder
            .submit(SAMPLE_INTENT, &CancellationToken::new())
            .await
            .unwrap_err();
        let rendered = format!("{err:#}");

        assert!(rendered.contains("id 7"), "got: {rendered}");
        assert!(
            rendered.contains("check it for this request before posting again"),
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
        let err = builder
            .submit(SAMPLE_INTENT, &CancellationToken::new())
            .await
            .unwrap_err();
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
        let err = builder
            .submit(SAMPLE_INTENT, &CancellationToken::new())
            .await
            .unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("closed its stdout"), "got: {rendered}");
        assert!(
            rendered.contains("check it for this request before posting again"),
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

        let err = builder
            .submit(SAMPLE_INTENT, &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("check it for this request before posting again"),
            "the error has to say what an operator must do before retrying by hand: {err:#}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            counter.spawns(),
            1,
            "a submit must not be reissued on a fresh child"
        );
    }

    #[tokio::test]
    async fn a_cancelled_submit_says_what_may_be_on_chain_too() {
        // Shutdown cannot tell a cancel that beat the write from one that raced it.
        let cancel = CancellationToken::new();
        let builder = spawn_stub(&stub_config("sleep 30")).await;
        cancel.cancel();

        let err = builder.submit(SAMPLE_INTENT, &cancel).await.unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("cancelled"), "got: {rendered}");
        assert!(
            rendered.contains("check it for this request before posting again"),
            "got: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_submit_surfaces_the_child_s_error_code_and_message() {
        // A refusal like `wallet_unfunded` is the operator's to act on: an answer, not a pipe fault.
        let builder = spawn_stub(&stub_config(
        r#"read -r line; printf '{"id":0,"ok":false,"code":"wallet_unfunded","message":"no spendable dust"}\n'"#,
    ))
    .await;
        let err = builder
            .submit(SAMPLE_INTENT, &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("wallet_unfunded"),
            "got: {err:#}"
        );
        assert!(
            format!("{err:#}").contains("no spendable dust"),
            "got: {err:#}"
        );
        // A refusal is an answer: nothing here should send an operator to the chain.
        assert!(
            !format!("{err:#}").contains("may still reach the chain"),
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
            .submit(&[0xde, 0xad], &CancellationToken::new())
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
        let err = builder
            .submit(SAMPLE_INTENT, &CancellationToken::new())
            .await
            .unwrap_err();
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

        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("timed out"), "got: {err:#}");
        // A build leaves nothing behind: sending its operator to the chain would be a false alarm.
        assert!(
            !format!("{err:#}").contains("may still reach the chain"),
            "a build that timed out spent nothing: {err:#}"
        );

        let bytes = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .expect("the hung child was killed, so this request gets a fresh one");
        assert_eq!(bytes, vec![0x0a]);
    }

    #[tokio::test]
    async fn a_cancelled_child_is_killed_so_a_later_request_does_not_wait_on_it() {
        // Killing the cancelled child keeps its stale reply from becoming the NEXT caller's failure.
        let counter = SpawnCounter::new("cancel-recovery");
        let config = stub_config(&format!(
            r#"{} if [ $n -eq 1 ]; then sleep 30; else read -r line; {} fi"#,
            counter.prologue(),
            ECHO_ID_REPLY
        ));
        let builder = spawn_stub(&config).await;
        counter.wait_for(1).await;

        let cancel = CancellationToken::new();
        cancel.cancel();
        let cancelled_at = Instant::now();
        let err = builder.build(&sample_request(), &cancel).await.unwrap_err();
        assert!(format!("{err:#}").contains("cancelled"), "got: {err:#}");
        assert!(
            cancelled_at.elapsed() < Duration::from_secs(1),
            "a cancelled build must return promptly, not wait on the child"
        );

        let started = Instant::now();
        let bytes = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .expect("the cancelled child was killed, so this request gets a fresh one");
        assert_eq!(bytes, vec![0x0a]);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "answered only after waiting out the 5s timeout, so it was handed the cancelled child"
        );
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
                tokio::spawn(async move {
                    builder
                        .build(&sample_request(), &CancellationToken::new())
                        .await
                })
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
        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
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
        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
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

        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
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
                (
                    "MIDNIGHT_PUB_NODE_URL".to_string(),
                    config.node_ws_url.clone(),
                ),
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
            &encode_request(&sample_request(), 3, Operation::BuildIntent).unwrap(),
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
    async fn readiness_sends_and_requires_protocol_generation_one() {
        let script = r#"read -r ready; if [ "$ready" = '{"id":0,"op":"ready","protocolVersion":1}' ]; then printf '{"id":0,"ok":true,"ready":true,"protocolVersion":1,"submitTimeoutMs":2,"recipeTtlMs":1}\n'; else printf '{"id":0,"ok":false,"code":"bad_request","message":"wrong ready request"}\n'; fi; sleep 30"#;
        let mut config = stub_config("unreachable");
        config.publisher.intent_gen_command =
            vec!["sh".to_string(), "-c".to_string(), script.to_string()];

        IntentGen::spawn(&config, NETWORK_ID)
            .await
            .expect("generation 1 readiness succeeds");
    }

    #[tokio::test]
    async fn readiness_rejects_every_non_exact_protocol_version() {
        let invalid_replies = [
            (
                "missing",
                r#"{"id":0,"ok":true,"ready":true,"submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
            (
                "older",
                r#"{"id":0,"ok":true,"ready":true,"protocolVersion":0,"submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
            (
                "newer",
                r#"{"id":0,"ok":true,"ready":true,"protocolVersion":2,"submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
            (
                "wrongly typed",
                r#"{"id":0,"ok":true,"ready":true,"protocolVersion":"1","submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
            (
                "null",
                r#"{"id":0,"ok":true,"ready":true,"protocolVersion":null,"submitTimeoutMs":2,"recipeTtlMs":1}"#,
            ),
        ];

        for (case, reply) in invalid_replies {
            let result = IntentGen::spawn(&ready_reply_config(reply), NETWORK_ID).await;
            assert!(
                result.is_err(),
                "a {case} protocol version must not start a session"
            );
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
            .build(&sample_request(), &CancellationToken::new())
            .await
            .expect("the maximum safe id is valid");
        builder
            .build(&sample_request(), &CancellationToken::new())
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
                Operation::Submit,
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
}
