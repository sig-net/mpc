//! Client for the out-of-process intent builder.
//!
//! The respond circuit, its proving stack and the wallet that pays for a post only exist
//! in TypeScript, so both halves of a post run in a child process and this is the only
//! thing that talks to it: one JSON object per line down its stdin, one back up its
//! stdout, mirroring `protocol.ts` field for field. Building an intent is a pure
//! function of what the caller pinned and put on the wire; submitting one spends, which
//! is the whole reason [`Operation`] exists.
//!
//! A reply landing on the wrong request is what this guards hardest against, because it
//! would put one post's signature into another post's intent. The pipe has no framing
//! beyond the newline, so once the stream is in any doubt the child is replaced rather
//! than resynchronized.

use std::collections::VecDeque;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use mpc_chain_integration_core::utils::retry::retry_rpc;
use mpc_chain_integration_core::utils::task::AbortOnDrop;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::config::PublisherConfig;

/// One respond call, in the shape the child validates. Every byte field is bare
/// lowercase hex with no `0x`; the child converts nothing and rejects anything else.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentRequest {
    /// `respond` or `respondBidirectional`. The child discriminates its request union
    /// on this before anything else, so a wrong value costs the whole request.
    pub circuit: &'static str,
    pub contract_address: String,
    pub request_id: String,
    pub signature: WireSignature,
    /// The whole zero-padded ABI return data, not a digest of it. `respondBidirectional`
    /// only, and the child rejects the request outright if the other circuit carries it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serialized_output: Option<String>,
    /// How much of `serialized_output` is meaningful, 0..=128.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_len: Option<u8>,
    /// The contract state and ledger parameters this caller read, pinned here so the
    /// child stays a pure function of what it is handed.
    pub contract_state: String,
    pub ledger_parameters: String,
    /// The funding wallet's Zswap public key, public and the only thing about that
    /// wallet the child is ever told.
    pub coin_public_key: String,
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

/// One submit call: the intent a previous build answered with, in the same bare
/// lowercase hex every byte field on this wire takes.
///
/// Nothing else travels, and none of the reads that built the intent do. The child
/// balances against a wallet it syncs itself, and the call inside the intent is already
/// partitioned and priced, so there is nothing left over there for a pinned read to be
/// weighed against.
#[derive(Debug, Clone, PartialEq, Serialize)]
struct SubmitRequest {
    intent: String,
}

/// A hex seed is at least 16 bytes. Kept in step with the child's own floor.
const SHORTEST_SEED_HEX: usize = 32;

/// Scrubs the funding seed out of anything the child says before this node repeats it.
///
/// The child is handed a spending key, and two of its outputs come back through here on
/// their way to the log: its stderr, which `drain_stderr` forwards verbatim, and the
/// `message` of a refusal, which the child builds by rendering a dependency's cause
/// chain and which reaches `tracing` through the retry warning. A wallet library that
/// quotes its own configuration in an error would put the key in this node's log by
/// either route. `PublisherConfig`'s `Debug` redacts the seed for exactly this reason;
/// these are the other two paths to the same place.
#[derive(Clone)]
struct SeedRedactor(Vec<String>);

impl SeedRedactor {
    fn new(seed: &str) -> Self {
        let seed = seed.trim();
        // A hex seed is at least 16 bytes, so anything shorter is not one and must not be
        // blanked out of a message: the empty string sits between every pair of
        // characters, and a two-character "secret" would redact half the text it appears
        // in, destroying the diagnostic this exists to preserve. A node that only indexes
        // legitimately has no seed at all. The child applies the same floor to its own
        // redaction, and the two have to agree or a line scrubbed on one side arrives
        // intact on the other.
        if seed.len() < SHORTEST_SEED_HEX {
            return Self(Vec::new());
        }
        // Every spelling the seed parser accepts, because substring matching is the whole
        // technique: it catches the seed rendered literally, which is what a config echo
        // or a "bad key" error does, and only in the spelling it was rendered in.
        let bare = seed.strip_prefix("0x").unwrap_or(seed);
        Self(vec![
            seed.to_string(),
            bare.to_lowercase(),
            bare.to_uppercase(),
        ])
    }

    fn scrub(&self, text: &str) -> String {
        let mut out = text.to_string();
        for form in &self.0 {
            if out.contains(form.as_str()) {
                out = out.replace(form.as_str(), "<redacted>");
            }
        }
        out
    }
}

/// What the child is being asked to do.
///
/// The two differ in more than their budget. Building an intent is a pure function of
/// what it is handed, so an answer lost to a dead pipe can simply be asked for again.
/// Submitting spends the funding wallet's single dust UTXO, so a lost answer means the
/// transaction may already be on chain, and asking again is precisely how a second post
/// races the first onto that one coin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    BuildIntent,
    Submit,
}

impl Operation {
    /// How long the child gets.
    ///
    /// Per-operation because one budget cannot serve both: a build is milliseconds and a
    /// submit is minutes. Bounding a submit by the build's budget kills the child
    /// mid-prove every time, throws the proof away, strands the balanced coin, and hands
    /// the operator a transport timeout that names none of that.
    ///
    /// These are NOT independent knobs. The submit budget has to stay LONGER than the
    /// dust recipe's TTL, because a deadline blown before the TTL expires means the coin
    /// may be stranded with the recipe still live, which is why a blown submit deadline
    /// is fatal here rather than retryable. The service this replaces paired a 360s
    /// deadline with a 300s recipe TTL for that reason; anyone retuning one must move
    /// the other.
    fn deadline(self, config: &PublisherConfig) -> Duration {
        match self {
            Self::BuildIntent => config.request_timeout,
            Self::Submit => config.submit_timeout,
        }
    }

    /// Whether an answer lost in transit may simply be asked for again.
    fn is_repeatable(self) -> bool {
        matches!(self, Self::BuildIntent)
    }

    /// The `op` the child discriminates on, where absence is itself one of the values.
    ///
    /// A build sends none rather than `"build"`: the child reads a missing `op` as a
    /// build precisely so the second operation could be added to one side at a time, and
    /// spending that now would buy nothing.
    fn wire_op(self) -> Option<&'static str> {
        match self {
            Self::BuildIntent => None,
            Self::Submit => Some("submit"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::BuildIntent => "intent build",
            Self::Submit => "submit",
        }
    }

    /// What a lost answer leaves behind, for whoever reads the error.
    fn lost_answer_warning(self) -> &'static str {
        match self {
            // Nothing was spent and nothing was posted: there is nothing to go and check.
            Self::BuildIntent => "",
            Self::Submit => {
                "; the transaction may still reach the chain, so check it for this request \
                 before posting again, and expect the balanced coin to stay stranded until \
                 its recipe TTL expires"
            }
        }
    }
}

/// Builds intents and posts them, by driving one persistent child process.
pub struct IntentGen {
    config: PublisherConfig,
    /// Passed to every child rather than left to the environment. See `spawn_child`.
    network_id: String,
    redactor: SeedRedactor,
    /// One request at a time. Two requests interleaved on one pipe have no correct
    /// reading, so the lock is the whole concurrency story: callers queue.
    session: Mutex<Option<Session>>,
}

impl IntentGen {
    /// Starts the builder eagerly, so a command that cannot run fails here rather than
    /// on the first signature that needs it.
    pub async fn spawn(config: &PublisherConfig, network_id: &str) -> anyhow::Result<Self> {
        Ok(Self {
            config: config.clone(),
            network_id: network_id.to_string(),
            redactor: SeedRedactor::new(&config.funding_seed),
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

    /// Balances, proves and posts `intent`, answering with what names the transaction on
    /// chain.
    ///
    /// Attempted exactly once, and nothing here says so: `Operation::Submit` carries both
    /// the budget and the answer to a lost reply, so this call site cannot pair a submit
    /// with a build's deadline, or with a retry, however carelessly it is written.
    pub async fn submit(
        &self,
        intent: &[u8],
        cancel: &CancellationToken,
    ) -> anyhow::Result<String> {
        let request = SubmitRequest {
            intent: hex::encode(intent),
        };
        let reply = self.dispatch(&request, cancel, Operation::Submit).await?;
        // The reply also names the block it landed in, which stops here: the child
        // already waited for that block before answering at all, and the identifier is
        // what a lookup takes.
        reply
            .tx_id
            .context("midnight intent builder posted a transaction without naming it")
    }

    /// One operation, start to finish, against at most two children.
    ///
    /// It decides its budget and whether a lost answer may be reissued from `operation`,
    /// never from the caller, so the two cannot be set inconsistently at a call site.
    /// Answers with the reply's framing rather than a payload, because which field
    /// carries a granted answer is the one thing the two operations do not share.
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
        // A child that died between requests costs one respawn, never the caller's post.
        // Exactly one retry: past that the failure is the builder's rather than the
        // pipe's, and repeating a proving run is expensive enough to be deliberate.
        tracing::warn!(
            reason = "respawning",
            "midnight intent builder failed: {error:#}; retrying once on a fresh child"
        );
        match self.attempt(&mut session, request, cancel, operation).await {
            Exchange::Answered(result) => result,
            Exchange::Broken { error, .. } => Err(self.blame_the_command(error)),
        }
    }

    /// Names the configured command on any failure of the child itself.
    ///
    /// Only on those: a request the child considered and refused is answered, and the
    /// command is not what is wrong with it. But a child that died, went silent or
    /// answered nonsense is a failure of the process, and the first thing an operator
    /// needs is which process, since the likeliest cause by far is that
    /// `intent_gen_command` names something this host cannot run. The default is a bare
    /// `midnight-publisher` resolved on PATH, so a container missing that binary hits
    /// this on every publish, and "closed its stdout" alone would not say why.
    fn blame_the_command(&self, error: anyhow::Error) -> anyhow::Error {
        error.context(format!(
            "midnight intent builder command [{}]",
            self.config.intent_gen_command.join(" ")
        ))
    }

    /// One pass: make sure a child is up, then trade one line with it. A pass that
    /// breaks always empties the slot, and emptying the slot kills the child it broke
    /// on, so no later pass can read into what that child left in the pipe.
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
                // The restart budget was already spent inside the spawn, so a second
                // pass would only spend it again.
                Err(error) => return Exchange::give_up(error),
            }
        }
        let live = session
            .as_mut()
            .expect("the slot was just filled or was already full");
        let outcome = exchange(
            live,
            request,
            operation,
            &self.config,
            cancel,
            &self.redactor,
        )
        .await;
        let Exchange::Broken { error, retry } = outcome else {
            return outcome;
        };
        // The child's own account of what went wrong, which otherwise only ever reaches
        // a `tracing` subscriber. A child that cannot start says why and dies, and the
        // pass that notices reports a closed pipe: an operator running the node without
        // a subscriber gets "closed its stdout" for a missing environment variable the
        // child named out loud. Attached before the session is emptied, because emptying
        // it kills the child and takes its stderr with it.
        let error = match live.last_words().await {
            Some(said) => error.context(format!("the midnight intent builder said: {said}")),
            None => error,
        };
        *session = None;
        Exchange::Broken { error, retry }
    }
}

/// One live child and the partially read line buffer over its stdout. Dropping it kills
/// the child, which is what lets every failure path recover by simply forgetting it.
struct Session {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    /// The id namespace belongs to the child: a fresh pipe cannot deliver a previous
    /// child's reply, so counting from zero per session stays unambiguous.
    next_id: u64,
    /// What the drain below has heard, for the error that reports this child's death.
    stderr: StderrTail,
    /// Held only for `kill_on_drop`. Dropped after `stdin`, so a child that exits on
    /// end-of-input gets to do that before the kill lands.
    _child: Child,
    /// Awaited briefly by `last_words` rather than merely aborted on drop: the drain
    /// ending is how this side learns the child has finished saying why it died.
    stderr_drain: AbortOnDrop,
}

impl Session {
    /// What the child said on its stderr, already scrubbed, or `None` if it said
    /// nothing.
    ///
    /// Waits for the drain first, briefly. Stdout reaching end of input and stderr
    /// reaching it are two events on two pipes, so a child that died a moment ago may
    /// still have its explanation in flight when the read that noticed comes back;
    /// without the wait the tail would be empty exactly when it matters most. A child
    /// that is merely wedged never closes its stderr at all, which is what the bound is
    /// for.
    async fn last_words(&mut self) -> Option<String> {
        let _ = tokio::time::timeout(STDERR_TAIL_GRACE, &mut self.stderr_drain.0).await;
        self.stderr.take()
    }
}

/// How many of the child's last stderr lines an error carries. Enough for a refusal and
/// the first frames under it, few enough that a chatty child cannot grow this without
/// bound.
const STDERR_TAIL_LINES: usize = 10;

/// How long a broken pass waits for the drain to finish before reporting what it has.
const STDERR_TAIL_GRACE: Duration = Duration::from_millis(200);

/// The child's last words, scrubbed, on their way into an error rather than a log.
///
/// `drain_stderr` forwards every line to `tracing::warn!`, which reaches nobody in a
/// process running without a subscriber, so a child that refuses to start leaves the
/// caller holding "closed its stdout" while the one message that names what is
/// misconfigured goes nowhere. What it holds is already scrubbed, because `ScrubbedLines`
/// is the only thing that fills it.
#[derive(Clone, Default)]
struct StderrTail(Arc<std::sync::Mutex<VecDeque<String>>>);

impl StderrTail {
    /// Never panics on a poisoned lock: this runs inside a publisher task, and a panic
    /// there takes a runtime worker with it over a diagnostic. Nothing inside the lock
    /// can panic, so the recovered value is the same value.
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

    /// Oldest first, on one line: this becomes an `anyhow` context, and those are read
    /// as a chain of single-line causes.
    fn take(&self) -> Option<String> {
        let lines = self.lines();
        (!lines.is_empty()).then(|| lines.iter().cloned().collect::<Vec<_>>().join("; "))
    }
}

/// What a pass at the child produced.
enum Exchange {
    /// A reply that answers this request, whether it granted it or refused it.
    Answered(anyhow::Result<WireReply>),
    /// The child can no longer be trusted to be in step with us. It is replaced either
    /// way; only a transport fault is worth trying a second time.
    Broken { error: anyhow::Error, retry: bool },
}

impl Exchange {
    /// The pipe failed under us, so the request never got a definitive answer.
    ///
    /// Whether a fresh child is worth one more try is the operation's to say rather than
    /// the pipe's: the answer was lost either way, but only an operation that left
    /// nothing behind on chain can simply be asked for again.
    fn lost(error: anyhow::Error, operation: Operation) -> Self {
        Self::Broken {
            error: unanswered(error, operation),
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

/// `error`, plus what an operation that cannot be asked again leaves behind.
///
/// Applied wherever a pass breaks PAST THE WRITE and nowhere else. From there on a lost
/// answer and a landed transaction are indistinguishable from this side, whichever way
/// the pass broke: the deadline blew, the pipe died, the caller walked away, or the
/// reply came back unpairable. Before the write there is nothing on chain to go and
/// check, and an alarm raised there would be a false one on the single path where an
/// alarm has to mean something.
fn unanswered(error: anyhow::Error, operation: Operation) -> anyhow::Error {
    match operation.lost_answer_warning() {
        "" => error,
        warning => error.context(format!("the answer was lost{warning}")),
    }
}

/// The child's configuration namespace. Every name under it is this process's to supply.
const PUBLISHER_ENV_PREFIX: &str = "MIDNIGHT_PUB_";

/// The names in `names` that fall in that namespace.
fn publisher_vars<I>(names: I) -> Vec<std::ffi::OsString>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    names
        .into_iter()
        .filter(|name| name.to_string_lossy().starts_with(PUBLISHER_ENV_PREFIX))
        .collect()
}

/// Starts the builder under the restart budget, so a child lost to a redeploy or an OOM
/// kill costs a few hundred milliseconds instead of the request.
async fn spawn_session(config: &PublisherConfig, network_id: &str) -> anyhow::Result<Session> {
    // The per-attempt deadline never realistically fires: spawning returns as soon as
    // the fork does. The request budget is simply the largest wait already sanctioned.
    retry_rpc!(
        config.request_timeout,
        config.restart_backoff,
        "midnight_intent_gen_spawn",
        { spawn_child(config, network_id) }
    )
}

fn spawn_child(config: &PublisherConfig, network_id: &str) -> anyhow::Result<Session> {
    let inherited = publisher_vars(std::env::vars_os().map(|(name, _)| name));
    let mut command = intent_gen_command(config, network_id, &inherited)?;
    let mut child = command.spawn().with_context(|| {
        format!(
            "spawning the midnight intent builder ({})",
            config.intent_gen_command.join(" ")
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
        stderr_drain: AbortOnDrop(tokio::spawn(drain_stderr(
            stderr,
            SeedRedactor::new(&config.funding_seed),
            tail,
        ))),
    })
}

/// The child's command, configured but not spawned.
///
/// Split from the spawn so a test can read back the environment the child would get:
/// `inherited` is the set of publisher variables this process holds, and every one of
/// them has to be taken away rather than passed on.
fn intent_gen_command(
    config: &PublisherConfig,
    network_id: &str,
    inherited: &[std::ffi::OsString],
) -> anyhow::Result<Command> {
    let (program, args) = config
        .intent_gen_command
        .split_first()
        .context("midnight publisher config: intent_gen_command is empty")?;
    let mut command = Command::new(program);
    command.args(args);

    // `MIDNIGHT_PUB_*` is the child's configuration namespace, and this process is its
    // only author: every name in it is either set below or removed here, never inherited.
    //
    // Overriding the ones we set would be enough to stop an ambient value winning today.
    // Removing the rest is about what happens next: the child holds a spending key, and
    // the set of names it reads will grow on its own side. A name this process does not
    // yet know about would otherwise be quietly supplied by whatever is in the node's
    // environment, which for a wallet means spending from a key nobody chose. Removed,
    // the child's own required-value check rejects it at startup instead, which is the
    // failure everyone wants.
    //
    // This stays narrower than `env_clear`, deliberately: the child is Node, and taking
    // away PATH or HOME breaks it and everything it shells out to for no gain here.
    for name in inherited {
        command.env_remove(name);
    }

    command
        // The network id decides address encoding and which artifacts the circuit is
        // proved against, and the seed decides which wallet pays. Both are validated on
        // `MidnightConfig`; a second ambient copy of either would be an unvalidated
        // source of truth for a value whose disagreement only shows up on chain.
        .env("MIDNIGHT_PUB_FUNDING_SEED", &config.funding_seed)
        .env("MIDNIGHT_PUB_MANAGED_DIR", &config.managed_dir)
        .env("MIDNIGHT_PUB_NETWORK_ID", network_id)
        // The submit half, which the child needs whole or not at all: it refuses to boot
        // holding a subset, and `MidnightConfig::validate` is what makes sure a subset
        // never gets this far. Written unconditionally rather than only when they are
        // set, because a name left unwritten is a name the `env_remove` above already
        // took away, and blank is how a build-only deployment says it has no wallet.
        .env("MIDNIGHT_PUB_NODE_URL", &config.node_ws_url)
        .env("MIDNIGHT_PUB_PROOF_SERVER_URL", &config.proof_server_url)
        .env("MIDNIGHT_PUB_INDEXER_URL", &config.indexer_url)
        .env("MIDNIGHT_PUB_INDEXER_WS_URL", &config.indexer_ws_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Piped rather than inherited: the child's diagnostics belong in this node's
        // log, and an unread stderr pipe eventually blocks it mid-proof.
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok(command)
}

/// Forwards the child's stderr to the log and keeps the tail of it for whichever error
/// reports the child's death. Both, not either: the log is where a healthy child's
/// diagnostics belong, and the tail is what a caller with no subscriber gets instead.
async fn drain_stderr(stderr: ChildStderr, redactor: SeedRedactor, tail: StderrTail) {
    let mut lines = ScrubbedLines::new(stderr, redactor);
    while let Some(line) = lines.next().await {
        tracing::warn!(source = "midnight-intent-builder", "{line}");
        tail.push(line);
    }
}

/// A child's stderr, as lines with the seed already taken out.
///
/// There is deliberately no way to read an unscrubbed line: the sole consumer logs
/// whatever it is handed, so the scrubbing belongs to the reader rather than to the
/// discipline of whoever writes the next consumer.
struct ScrubbedLines<R> {
    lines: tokio::io::Lines<BufReader<R>>,
    redactor: SeedRedactor,
}

impl<R: tokio::io::AsyncRead + Unpin> ScrubbedLines<R> {
    fn new(reader: R, redactor: SeedRedactor) -> Self {
        Self {
            lines: BufReader::new(reader).lines(),
            redactor,
        }
    }

    /// The next line, or `None` at end of input and equally on a read error: there is no
    /// second stderr to report a failure to read the first one on.
    async fn next(&mut self) -> Option<String> {
        let line = self.lines.next_line().await.ok()??;
        Some(self.redactor.scrub(&line))
    }
}

/// One line out, one line in. Anything that can leave the pipe in an unknown state
/// reports `Broken`, because a new stream is the only cheap way to resynchronize one.
async fn exchange<T: Serialize>(
    session: &mut Session,
    request: &T,
    operation: Operation,
    config: &PublisherConfig,
    cancel: &CancellationToken,
    redactor: &SeedRedactor,
) -> Exchange {
    let deadline = operation.deadline(config);
    let id = session.next_id;
    session.next_id += 1;
    let line = match encode_request(request, id, operation) {
        Ok(line) => line,
        // Nothing reached the pipe, so the child is still in step; the request itself is
        // beyond repair here.
        Err(error) => return Exchange::Answered(Err(error)),
    };

    let reply = tokio::select! {
        // A cancelled call walks away from a request the child may still be working on,
        // and that reply would land on the next caller's read. A shutdown that raced the
        // write is told apart from one that beat it by nothing available here, so a
        // cancelled submit reports what it may have left behind rather than guessing it
        // left nothing.
        _ = cancel.cancelled() => {
            return Exchange::give_up(unanswered(
                anyhow::anyhow!("midnight {} cancelled", operation.name()),
                operation,
            ))
        }
        // A timed-out child is a dead publisher if it is kept. It has no deadline of its
        // own and reads strictly one line at a time, so a circuit run that wedges wedges
        // the process: every later request queues behind a reply that never comes, while
        // the process itself still looks healthy. Reporting `Broken` is what kills it.
        //
        // Killed either way, but a submit is not reissued afterwards: past the write, a
        // lost answer and a landed transaction look identical from here.
        result = tokio::time::timeout(deadline, round_trip(session, &line)) => match result {
            Ok(Ok(reply)) => reply,
            Ok(Err(error)) => return Exchange::lost(error, operation),
            Err(_) => return Exchange::lost(
                anyhow::anyhow!("midnight {} timed out after {deadline:?}", operation.name()),
                operation,
            ),
        },
    };
    match decode_reply(&reply, id, redactor) {
        // The child's own verdict speaks for what it did, granted or refused alike, so it
        // passes through as it is. Anything else is a reply that cannot be paired to this
        // request, which past the write leaves the same doubt a dead pipe does.
        answered @ Exchange::Answered(_) => answered,
        Exchange::Broken { error, retry } => Exchange::Broken {
            error: unanswered(error, operation),
            retry,
        },
    }
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
fn decode_reply(line: &str, id: u64, redactor: &SeedRedactor) -> Exchange {
    let reply: WireReply = match serde_json::from_str(line.trim()) {
        Ok(reply) => reply,
        // Not this wire at all: a diagnostic on the wrong stream, or a line torn in
        // half. Either way the reader's idea of where a line starts is now wrong.
        Err(error) => {
            return Exchange::give_up(
                anyhow::Error::new(error)
                    .context("midnight intent builder sent an unreadable reply"),
            )
        }
    };
    // A rejection carrying no id is this request's own: the child had nothing honest to
    // echo off a line it could not read. A reply naming a different request means the
    // stream has slipped, and one post's signature in another post's intent is the one
    // outcome worth killing a healthy child over.
    match reply.id {
        Some(answered) if answered != id => {
            return Exchange::give_up(anyhow::anyhow!(
                "midnight intent builder answered id {answered}, not the id {id} it was asked"
            ))
        }
        // The child only omits an id when it could not read one, which it can only fail
        // to do on a line it is rejecting. A grant with no id is not an answer to
        // anything nameable.
        None if reply.ok => {
            return Exchange::give_up(anyhow::anyhow!(
                "midnight intent builder granted a request with no id"
            ))
        }
        _ => {}
    }
    Exchange::Answered(granted(reply, redactor))
}

/// The reply as an answer, or the refusal it describes.
///
/// Which field carries a granted answer is the operation's business and is read past
/// here. What both share is that a refusal is an answer too, and that its `message` is
/// the child rendering a cause chain it does not control, so it is the one field on this
/// wire that can carry the key back out.
fn granted(reply: WireReply, redactor: &SeedRedactor) -> anyhow::Result<WireReply> {
    if !reply.ok {
        anyhow::bail!(
            "midnight intent builder refused the request [{}]: {}",
            reply.code.as_deref().unwrap_or("no code"),
            redactor.scrub(reply.message.as_deref().unwrap_or("no message"))
        );
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

/// The request as it goes on the wire: the caller's fields, the id that pairs the reply
/// to them, and the operation the child discriminates on.
#[derive(Serialize)]
struct WireRequest<'a, T> {
    id: u64,
    /// Absent on a build, which is a value rather than an omission. See
    /// `Operation::wire_op`.
    #[serde(skip_serializing_if = "Option::is_none")]
    op: Option<&'static str>,
    #[serde(flatten)]
    request: &'a T,
}

/// Both arms of a reply in one shape, since the arms differ only by which fields carry
/// anything. Unknown fields are ignored on purpose: growing the wire is meant to be
/// additive on one side at a time, and the block a submit landed in is one this side
/// deliberately does not read.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireReply {
    /// Null when the child could not read an id off the line it was rejecting.
    id: Option<u64>,
    ok: bool,
    intent: Option<String>,
    /// What names a posted transaction on chain. The submit arm's own payload.
    tx_id: Option<String>,
    code: Option<String>,
    message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::PublisherConfig;
    use mpc_chain_integration_core::utils::retry::RetryConfig;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use tokio_util::sync::CancellationToken;

    const NETWORK_ID: &str = "undeployed";

    /// A shell stub in place of the real Node child: the wire is the contract under
    /// test, and a stub keeps every case here deterministic and Node-free.
    ///
    /// Only the fields this seam reads are pinned, and the rest are taken from
    /// `Default` deliberately, because they belong to parts of the publisher this file
    /// does not touch. That inheritance is a trap for anything added later: a test of a
    /// path that reads `submit_timeout` or an endpoint would silently be testing the
    /// default rather than a value it chose, so such a test must pin its own.
    fn stub_config(script: &str) -> PublisherConfig {
        PublisherConfig {
            intent_gen_command: vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            managed_dir: "/managed".to_string(),
            request_timeout: Duration::from_secs(5),
            restart_backoff: RetryConfig {
                min_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(5),
                max_times: 2,
                jitter: false,
            },
            ..Default::default()
        }
    }

    async fn spawn_stub(config: &PublisherConfig) -> IntentGen {
        IntentGen::spawn(config, NETWORK_ID)
            .await
            .expect("the stub spawns")
    }

    /// A scratch file a stub counts its own spawns in. A stub script is identical on
    /// every spawn, so state outside it is the only way to write one that behaves
    /// differently on the second child than on the first, which is exactly what the
    /// recovery cases have to observe.
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

        /// How many children have counted themselves so far.
        fn spawns(&self) -> u32 {
            std::fs::read_to_string(&self.0)
                .ok()
                .and_then(|text| text.trim().parse().ok())
                .unwrap_or(0)
        }

        /// Waits until `count` children have counted themselves. `Command::spawn` returns
        /// as soon as the fork does, so a test that kills the first child promptly can
        /// kill it before its shell ever ran, and a child killed before it counted leaves
        /// the next one believing it is the first.
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

    /// The stub's reply to whatever id it was asked, so a stub can serve more than one
    /// request on one child.
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
            serialized_output: None,
            output_len: None,
            contract_state: "beef".to_string(),
            ledger_parameters: "f00d".to_string(),
            coin_public_key: "44".repeat(32),
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
        // A refusal is an answer: the child ran, read the request and declined it, so the
        // command is the one thing that is demonstrably fine. Naming it here would send
        // an operator to check their argv when what is wrong is the deployment.
        assert!(
            !format!("{err:#}").contains("midnight intent builder command"),
            "a refusal must not be blamed on the command: {err:#}"
        );
    }

    #[tokio::test]
    async fn a_null_id_on_the_failure_arm_is_the_in_flight_request_s_own_rejection() {
        // A line that failed to parse has no readable id to echo, so the child sends
        // null rather than inventing one. Treating that as a mismatch would bury the
        // real complaint under a framing error.
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
        // The one guard against a desynchronized stream: without it a late reply from
        // an abandoned request becomes this request's signature.
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
        // The stub exits after its first reply. The second build must still succeed.
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
        // The stub takes the request, closes stdout and lingers, so the process is alive
        // and the pipe is not. Reading end-of-input as a zero-length line would leave
        // this looking like an unreadable reply minutes later instead of a dead pipe now.
        let mut config = stub_config(r#"read line; exec 1>&-; sleep 30"#);
        // Long enough that the timeout cannot be what saves this test, and short enough
        // that losing the end-of-input check reports as a failure rather than as a CI
        // hang. Every stub here is capped for the same reason: the assertions need a
        // child that outlives the deadline, not one that outlives the suite.
        config.request_timeout = Duration::from_secs(30);
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

    #[tokio::test]
    async fn build_returns_promptly_on_cancel_and_does_not_leak_the_child() {
        let cancel = CancellationToken::new();
        let builder = spawn_stub(&stub_config("sleep 30")).await;
        cancel.cancel();
        let started = Instant::now();
        let err = builder.build(&sample_request(), &cancel).await.unwrap_err();
        assert!(format!("{err:#}").contains("cancelled"), "got: {err:#}");
        // The stub outlives the test by minutes: anything but a prompt return means
        // shutdown waits on a child that will never answer.
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "waited on a child that was never going to answer"
        );
    }

    #[tokio::test]
    async fn a_child_that_never_answers_times_out_instead_of_hanging_forever() {
        let mut config = stub_config("sleep 30");
        config.request_timeout = Duration::from_millis(50);
        let builder = spawn_stub(&config).await;
        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("timed out"), "got: {err:#}");
        // A build leaves nothing behind, so sending its operator to inspect the chain
        // would be a false alarm on the one path where alarms have to mean something.
        assert!(
            !format!("{err:#}").contains("may still reach the chain"),
            "a build that timed out spent nothing: {err:#}"
        );
    }

    #[test]
    fn each_operation_takes_its_own_budget_and_its_own_answer_to_a_lost_reply() {
        let config = stub_config("unused");
        assert_eq!(
            Operation::BuildIntent.deadline(&config),
            config.request_timeout
        );
        assert_eq!(Operation::Submit.deadline(&config), config.submit_timeout);
        assert!(Operation::BuildIntent.is_repeatable());
        // The whole reason the two are not one knob: a build can be asked again, a
        // submit cannot, because past the write a lost answer and a landed transaction
        // are indistinguishable from this side.
        assert!(!Operation::Submit.is_repeatable());
    }

    /// Whatever a build answered with. Opaque to this side, so any bytes do.
    const SAMPLE_INTENT: &[u8] = &[0xde, 0xad, 0xbe, 0xef];

    #[tokio::test]
    async fn a_submit_carries_the_intent_and_answers_with_the_transaction_id() {
        // The stub answers only a line that names the operation, and names the
        // transaction after the intent it was handed, so one assertion covers the whole
        // exchange: the child branched where it branches, the bytes reached it as the hex
        // the wire takes, and what it called the transaction reached the caller.
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
    async fn a_submit_the_child_granted_without_naming_the_transaction_is_not_a_receipt() {
        // The identifier is the whole answer. Returning an empty receipt would put
        // "published successfully" in the log for a post nothing can be looked up by,
        // which is the one failure this path must never render as a success.
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
    async fn a_submit_whose_child_dies_before_answering_says_what_may_be_on_chain() {
        // The other way an answer is lost, and the one a deadline never sees: the child
        // took the request and its stdout went away. A dead pipe reads like a transport
        // fault, and reporting it as one would bury the only thing that matters here,
        // which is that the transaction may have been posted before the pipe closed.
        let counter = SpawnCounter::new("submit-dead-pipe");
        let mut config = stub_config(&format!(
            "{} read -r line; exec 1>&-; sleep 30",
            counter.prologue()
        ));
        // Long enough that the deadline cannot be what ends this: the closed pipe has to
        // be what does.
        config.submit_timeout = Duration::from_secs(30);
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
    }

    #[tokio::test]
    async fn a_cancelled_submit_says_what_may_be_on_chain_too() {
        // Shutdown cannot tell a cancel that beat the write from one that raced it, so
        // the same doubt applies: the request may have reached a child that is about to
        // be killed mid-post.
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
        // `wallet_unfunded` is the deployment being out of dust and `state_conflict` is
        // another writer having won the race: both are the operator's to act on, and
        // both arrive as an answer rather than as a fault of the pipe.
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
        // A refusal is an answer: the child considered the submit and declined it, so it
        // knows what it did and nothing here should send an operator to the chain.
        assert!(
            !format!("{err:#}").contains("may still reach the chain"),
            "a refusal spent nothing: {err:#}"
        );
    }

    #[tokio::test]
    async fn a_submit_is_bounded_by_the_submit_budget_and_not_the_build_one() {
        // The budget the deadline comes from is the operation's and not the caller's.
        // Bounding a submit by the build's would kill the child mid-prove on every real
        // post, throw the proof away and strand the balanced coin.
        let mut config = stub_config("sleep 30");
        config.request_timeout = Duration::from_millis(50);
        config.submit_timeout = Duration::from_millis(400);
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
    async fn a_submit_that_loses_its_answer_is_not_asked_again() {
        // The dust wallet has one UTXO. Reissuing a submit whose answer was lost is how
        // a second post races the first onto that coin, and the child may already have
        // put the transaction on chain.
        let counter = SpawnCounter::new("submit-not-repeated");
        let mut config = stub_config(&format!("{} sleep 30", counter.prologue()));
        config.submit_timeout = Duration::from_millis(50);
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

        // The wedged child is still killed, it is simply not asked a second time.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            counter.spawns(),
            1,
            "a submit must not be reissued on a fresh child"
        );
    }

    #[tokio::test]
    async fn a_timed_out_child_is_killed_so_a_later_request_is_served_by_a_fresh_one() {
        // The distinguishing case, and the reason a timeout is not merely an error: the
        // child has no deadline of its own and reads one line at a time, so a wedged
        // circuit run wedges the process. Failing the request and keeping the child gives
        // a publisher that is permanently dead while the process still looks healthy,
        // and every symptom of that is "respond timed out" all over again.
        //
        // The stub hangs on its first two spawns, which is exactly the budget one build
        // spends, and answers on every spawn after that.
        let counter = SpawnCounter::new("timeout-recovery");
        let mut config = stub_config(&format!(
            r#"{} if [ $n -le 2 ]; then sleep 30; else read -r line; {} fi"#,
            counter.prologue(),
            ECHO_ID_REPLY
        ));
        config.request_timeout = Duration::from_millis(50);
        let builder = spawn_stub(&config).await;
        counter.wait_for(1).await;

        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("timed out"), "got: {err:#}");

        let bytes = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .expect("the hung child was killed, so this request gets a fresh one");
        assert_eq!(bytes, vec![0x0a]);
    }

    #[tokio::test]
    async fn a_cancelled_child_is_killed_so_a_later_request_does_not_wait_on_it() {
        // A cancelled build walks away from a request the child is still working on, and
        // that child owes a reply nobody will read. Killing it is the choice here rather
        // than trusting the id check, because the id check turns the stale reply into the
        // NEXT caller's failure, which is a second lost post for one cancellation.
        //
        // Elapsed time is the discriminating observation and there is no other: keeping
        // the cancelled child would still end in success, because the second build would
        // time out on it and then respawn into the answering stub. Only the wait tells
        // the two apart, so the assertion is deliberately far from the timeout.
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
        let err = builder.build(&sample_request(), &cancel).await.unwrap_err();
        assert!(format!("{err:#}").contains("cancelled"), "got: {err:#}");

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
        // The lock is held across the kill and the respawn, which is right (there is only
        // ever one child) but is the shape a deadlock would hide in. The stub hangs on its
        // first spawn and serves every request on the spawns after it, so whichever caller
        // wins the lock pays the timeout, kills that child and is answered by its
        // replacement, and the ones queued behind it are answered by that same child.
        // Every caller therefore succeeds whatever order they arrive in, which is what
        // keeps this deterministic while still exercising a respawn under contention.
        let counter = SpawnCounter::new("queued-callers");
        let mut config = stub_config(&format!(
            r#"{} if [ $n -le 1 ]; then sleep 30; else while read -r line; do {} done fi"#,
            counter.prologue(),
            ECHO_ID_REPLY
        ));
        config.request_timeout = Duration::from_millis(50);
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
        // The likeliest misconfiguration this design has: `intent_gen_command` names
        // something that starts and dies, so every child is dead before a line reaches
        // it. `spawn` cannot catch that, because a process that exits a millisecond
        // after `fork` returns is indistinguishable at that moment from a healthy one.
        // What has to hold instead is that the failure is bounded. A respawn path that
        // keeps trying turns one bad config value into a node that burns a core, never
        // publishes, and never says why, which is strictly worse than failing the post.
        let counter = SpawnCounter::new("exits-at-once");
        let script = format!("{} exit 1", counter.prologue());
        let builder = spawn_stub(&stub_config(&script)).await;

        let started = Instant::now();
        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
        // The failure an operator sees is an end-of-input or a broken pipe, which says
        // nothing about which command produced it. Naming the configured argv is what
        // turns this from "the builder broke" into something actionable.
        assert!(
            format!("{err:#}").contains(&script),
            "the error has to name the command that died: {err:#}"
        );
        // Returning at all is the first half of the claim: a spin would never get here.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a child that dies at once should cost one retry, not a wait"
        );

        // The second half is the exact count: the child from `spawn`, and one respawn.
        // The settle is for the count, not the spawning, which `build` already finished:
        // a child writes its number a moment after it is forked, and a spinning
        // implementation would have written hundreds more by the time this elapses.
        counter.wait_for(2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            counter.spawns(),
            2,
            "one child at startup and exactly one respawn, no more"
        );
    }

    #[tokio::test]
    async fn a_command_that_does_not_exist_fails_at_startup_and_names_itself() {
        // The other half of the same misconfiguration, and the case the eager spawn does
        // catch: an operator whose container has no `node` on PATH learns at startup
        // rather than on the first signature. The restart budget bounds it, so a command
        // that can never run cannot hold startup open indefinitely either.
        let mut config = stub_config("unreachable");
        config.intent_gen_command = vec!["mpc-midnight-no-such-binary".to_string()];

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

    /// A 32-byte hex seed, the shape `validate()` requires when one is present.
    const SEED: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_publisher_namespace_is_selected_by_prefix_and_nothing_else() {
        let names = [
            "PATH",
            "MIDNIGHT_PUB_FUNDING_SEED",
            "MIDNIGHT_PUBLIC",
            "HOME",
        ]
        .into_iter()
        .map(std::ffi::OsString::from);
        // `MIDNIGHT_PUBLIC` is the boundary case, and it is deliberately NOT in the
        // namespace: the trailing underscore in the prefix is what keeps the namespace
        // exact, so a variable that merely shares a stem belongs to whoever set it and
        // reaches the child untouched. Taking it away would be this process reaching
        // outside the configuration it owns.
        assert_eq!(
            publisher_vars(names),
            vec![std::ffi::OsString::from("MIDNIGHT_PUB_FUNDING_SEED")]
        );
    }

    #[tokio::test]
    async fn the_child_s_publisher_namespace_is_exactly_what_this_process_put_there() {
        // Exact, not "contains": an ambient `MIDNIGHT_PUB_*` that survived into the child
        // would show up as an extra name here, and a name this process forgot to set
        // would show up as a missing one. Both are the same defect from the child's side,
        // which is a value it was never given being supplied by the host instead.
        //
        // The count is the load-bearing half. The child needs all seven and validates its
        // submit half all-or-none, so a deployment that reaches it with three of them has
        // a child that refuses to boot on every publish.
        let builder = spawn_stub(&stub_config(
            r#"read -r line; printf '{"id":0,"ok":false,"code":"bad_request","message":"%s"}\n' "$(env | sed -n "s/^\(MIDNIGHT_PUB_[A-Z_]*\)=.*/\1/p" | sort | tr "\n" ",")""#,
        ))
        .await;
        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            "midnight intent builder refused the request [bad_request]: \
             MIDNIGHT_PUB_FUNDING_SEED,MIDNIGHT_PUB_INDEXER_URL,MIDNIGHT_PUB_INDEXER_WS_URL,\
             MIDNIGHT_PUB_MANAGED_DIR,MIDNIGHT_PUB_NETWORK_ID,MIDNIGHT_PUB_NODE_URL,\
             MIDNIGHT_PUB_PROOF_SERVER_URL,"
        );
    }

    #[tokio::test]
    async fn the_child_is_handed_every_endpoint_the_funding_wallet_dials() {
        // The names being present is not enough, which is the trap this covers: an
        // endpoint set to the empty string is a name the child reads as absent, and a
        // blank in any one of the five makes it refuse to boot rather than submit. So
        // the VALUES have to arrive, and each has to be its own, which is why the four
        // here are distinguishable from one another rather than one URL repeated.
        let mut config = stub_config(
            r#"read -r line; printf '{"id":0,"ok":false,"code":"bad_request","message":"node=%s prover=%s indexer=%s ws=%s"}\n' "$MIDNIGHT_PUB_NODE_URL" "$MIDNIGHT_PUB_PROOF_SERVER_URL" "$MIDNIGHT_PUB_INDEXER_URL" "$MIDNIGHT_PUB_INDEXER_WS_URL""#,
        );
        config.node_ws_url = "ws://127.0.0.1:9944".to_string();
        config.proof_server_url = "http://127.0.0.1:6300".to_string();
        config.indexer_url = "http://127.0.0.1:8088/api/v3/graphql".to_string();
        config.indexer_ws_url = "ws://127.0.0.1:8088/api/v3/graphql/ws".to_string();
        let builder = spawn_stub(&config).await;

        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains(
                "node=ws://127.0.0.1:9944 prover=http://127.0.0.1:6300 \
                 indexer=http://127.0.0.1:8088/api/v3/graphql \
                 ws=ws://127.0.0.1:8088/api/v3/graphql/ws"
            ),
            "got: {err:#}"
        );
    }

    #[tokio::test]
    async fn the_child_s_stderr_is_scrubbed_before_it_can_reach_a_log() {
        // The drain forwards these straight to `tracing::warn!`, so whatever survives
        // this reader is in the node's log. The child gains a wallet, and a dependency
        // that quotes its own configuration in a startup line or an error is the ordinary
        // way a key ends up somewhere it was never meant to be.
        let stderr = format!("midnight-publisher: opened wallet {SEED}\nsecond line\n");
        let mut lines = ScrubbedLines::new(stderr.as_bytes(), SeedRedactor::new(SEED));
        assert_eq!(
            lines.next().await.unwrap(),
            "midnight-publisher: opened wallet <redacted>"
        );
        assert_eq!(lines.next().await.unwrap(), "second line");
        assert!(lines.next().await.is_none());
    }

    #[tokio::test]
    async fn a_child_that_dies_at_boot_reports_what_it_said_on_its_way_out() {
        // The failure this exists for. The child validates its configuration before it
        // reads anything, so a misconfigured one names the variable it is missing and
        // exits, and every pass at it after that fails on a pipe that is simply gone.
        // Reported as a closed pipe alone, that sends an operator to read the wire; the
        // child already said which value is wrong, and it went to `tracing::warn!`, which
        // is nowhere at all in a process running without a subscriber.
        //
        // The stub quotes the seed it was handed rather than a literal, because a literal
        // would have to be in `intent_gen_command`, which the error renders verbatim.
        let mut config = stub_config(
            r#"printf 'invalid MIDNIGHT_PUB_* configuration: missing MIDNIGHT_PUB_INDEXER_URL (wallet %s)\n' "$MIDNIGHT_PUB_FUNDING_SEED" >&2; exit 1"#,
        );
        config.funding_seed = SEED.to_string();
        let builder = spawn_stub(&config).await;

        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("missing MIDNIGHT_PUB_INDEXER_URL"),
            "the child's own explanation has to reach whoever asked: {rendered}"
        );
        // The same scrubbing the drain applies, because this is that text taking a second
        // route out. A dependency that quotes its own configuration while refusing to
        // start is the ordinary way a key ends up in a message, and this one is returned
        // to the caller rather than merely logged.
        assert!(
            rendered.contains("wallet <redacted>"),
            "the child was handed the seed and quoted it back: {rendered}"
        );
        assert!(
            !rendered.contains(SEED),
            "the seed reached an error this node reports: {rendered}"
        );
    }

    #[test]
    fn every_publisher_variable_this_process_holds_is_taken_off_the_child() {
        // The set this process supplies is overridden anyway, so removal is about the
        // names it does not yet know: the child's required-value check should reject a
        // missing one loudly, rather than the host quietly supplying it. Synthetic rather
        // than the real environment, because the assertion has to be non-vacuous on a
        // machine that happens to have none of these set.
        let stray = std::ffi::OsString::from("MIDNIGHT_PUB_SOMETHING_ADDED_LATER");
        let seed = std::ffi::OsString::from("MIDNIGHT_PUB_FUNDING_SEED");
        let command = intent_gen_command(
            &stub_config("true"),
            NETWORK_ID,
            &[stray.clone(), seed.clone()],
        )
        .expect("the stub command is well formed");

        let changes: Vec<_> = command.as_std().get_envs().collect();
        assert!(
            changes.iter().any(|(name, value)| *name == stray && value.is_none()),
            "a publisher variable this process does not set must be removed, not inherited: {changes:?}"
        );
        // Ordering, not contradiction: the removal is registered first and the set that
        // follows replaces it, so a name in both ends up supplied by us.
        assert!(
            changes
                .iter()
                .any(|(name, value)| *name == seed && value.is_some()),
            "a publisher variable this process does set must survive its own removal: {changes:?}"
        );
    }

    #[tokio::test]
    async fn the_funding_seed_reaches_the_child_but_not_anything_this_node_says() {
        // Both halves at once. The child can only echo the seed if it was handed one, so
        // the echo proves delivery; the assertion proves that what comes back out of the
        // child, on the one wire field that carries its own rendered cause chain, does
        // not carry the key with it.
        let mut config = stub_config(
            r#"read -r line; printf '{"id":0,"ok":false,"code":"internal","message":"wallet rejected %s"}\n' "$MIDNIGHT_PUB_FUNDING_SEED""#,
        );
        config.funding_seed = SEED.to_string();
        let builder = spawn_stub(&config).await;

        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("wallet rejected <redacted>"),
            "the child was handed the seed and quoted it back: {rendered}"
        );
        assert!(
            !rendered.contains(SEED),
            "the seed reached an error this node reports: {rendered}"
        );
    }

    #[test]
    fn the_seed_is_scrubbed_whichever_case_the_child_quotes_it_in() {
        let redactor = SeedRedactor::new(SEED);
        assert_eq!(
            redactor.scrub(&format!("loaded {SEED} from disk")),
            "loaded <redacted> from disk"
        );
        assert_eq!(redactor.scrub(&SEED.to_uppercase()), "<redacted>");
        assert_eq!(
            redactor.scrub("nothing sensitive here"),
            "nothing sensitive here"
        );
    }

    #[test]
    fn a_seed_written_with_an_0x_prefix_is_scrubbed_in_the_spelling_the_child_uses() {
        // The operator's spelling and the child's need not match: a library that strips
        // the prefix before quoting the key back would otherwise slip straight through a
        // redactor that only knew the configured form.
        let redactor = SeedRedactor::new(&format!("0x{SEED}"));
        assert_eq!(redactor.scrub(&format!("key {SEED}")), "key <redacted>");
        assert_eq!(
            redactor.scrub(&format!("key 0x{SEED}")),
            "key <redacted>".to_string()
        );
    }

    #[test]
    fn something_too_short_to_be_a_seed_is_left_alone() {
        // Redacting a short string would blank out unrelated text wherever it happened to
        // occur, which costs the diagnostic and protects nothing: it is not a key.
        assert_eq!(
            SeedRedactor::new("abcd").scrub("abcdef is not a secret"),
            "abcdef is not a secret"
        );
    }

    #[test]
    fn an_absent_seed_scrubs_nothing() {
        // A node that only indexes has no wallet and a legal empty seed. The empty string
        // occurs between every pair of characters, so a redactor that did not special
        // case it would replace the whole line with separators and destroy the very
        // diagnostic the drain exists to carry.
        assert_eq!(
            SeedRedactor::new("").scrub("midnight-publisher: started"),
            "midnight-publisher: started"
        );
    }

    #[tokio::test]
    async fn the_child_is_told_its_network_and_managed_dir_rather_than_left_to_find_them() {
        // Both values are validated on `MidnightConfig`. An ambient copy would be a
        // second, unvalidated source for the one setting that decides address encoding
        // and which artifacts the circuit proves against, and disagreement between them
        // fails only on chain. The stub reports what it was handed by refusing with it.
        let builder = spawn_stub(&stub_config(
            r#"read -r line; printf '{"id":0,"ok":false,"code":"bad_request","message":"net=%s dir=%s"}\n' "$MIDNIGHT_PUB_NETWORK_ID" "$MIDNIGHT_PUB_MANAGED_DIR""#,
        ))
        .await;
        let err = builder
            .build(&sample_request(), &CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("net=undeployed dir=/managed"),
            "got: {err:#}"
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
                "coinPublicKey": "44".repeat(32),
                "ttlSeconds": 1_800_000_000u64,
            }),
            "the unidirectional circuit carries no output fields, and the child's \
             discriminated union rejects the request outright if it does. No `op` \
             either: the child reads an absent one as a build, and that is what lets a \
             third operation be added to one side at a time"
        );
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

    #[test]
    fn the_bidirectional_circuit_carries_its_output_and_length() {
        let mut request = sample_request();
        request.circuit = "respondBidirectional";
        request.serialized_output = Some("00".repeat(128));
        request.output_len = Some(32);
        let encoded: serde_json::Value =
            serde_json::from_str(&encode_request(&request, 0, Operation::BuildIntent).unwrap())
                .unwrap();
        assert_eq!(encoded["circuit"], "respondBidirectional");
        assert_eq!(encoded["serializedOutput"], "00".repeat(128));
        assert_eq!(encoded["outputLen"], 32);
    }
}
