use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;
use std::time::{Duration, Instant};

use cait_sith::protocol::{Action, MessageData, Participant, ProtocolError};
use mpc_contract::config::ProtocolConfig;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::config::Config;
use crate::mesh::MeshState;
use crate::protocol::message::{Message, MessageChannel, PositMessage, PositProtocolId};
use crate::protocol::posit::PositAction;
use crate::storage::protocol_storage::{ArtifactSlot, ProtocolArtifact};
use crate::util::JoinMap;

/// Delay after threshold accepts before the proposer broadcasts Start.
/// Lets late-arriving accepts join before committing.
const ACCEPT_DELAY: Duration = if cfg!(any(test, feature = "test-feature")) {
    Duration::from_millis(100)
} else {
    Duration::from_secs(5)
};

/// Timeout for the entire posit negotiation from the proposer's perspective.
const POSIT_TIMEOUT: Duration = if cfg!(any(test, feature = "test-feature")) {
    Duration::from_secs(2)
} else {
    Duration::from_secs(10)
};

/// Extra time deliberators wait beyond the proposer's timeout before giving up.
const DELIBERATOR_EXTRA: Duration = Duration::from_secs(2);

pub struct ProtocolProposer;
pub struct ProtocolDeliberator;

pub trait ProtocolTaskState<T: ArtifactProtocol>: Send + 'static {
    type Data: Send + 'static;
}

impl<T: ArtifactProtocol> ProtocolTaskState<T> for ProtocolProposer {
    type Data = (T::ProposerState, Vec<Participant>);
}

impl<T: ArtifactProtocol> ProtocolTaskState<T> for ProtocolDeliberator {
    type Data = Participant;
}

pub enum PokeMode {
    Inline,
    Blocking,
}

pub struct ProtocolGenerator<T: ArtifactProtocol> {
    id: T::TaskId,
    epoch: u64,
    me: Participant,
    owner: Participant,
    participants: Vec<Participant>,
    protocol: Option<T::Protocol>,
    created: Instant,
    timeout: Duration,
    inbox: mpsc::Receiver<T::InMessage>,
    msg: MessageChannel,
    slot: Option<ArtifactSlot<T::Artifact>>,
    state: T::GenerationState,
}

pub struct ProtocolBuildOutput<T: ArtifactProtocol> {
    pub id: T::TaskId,
    pub participants: Vec<Participant>,
    pub protocol: T::Protocol,
    pub inbox: mpsc::Receiver<T::InMessage>,
    pub msg: MessageChannel,
    pub slot: Option<ArtifactSlot<T::Artifact>>,
    pub state: T::GenerationState,
}

impl<T: ArtifactProtocol> ProtocolGenerator<T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: T::TaskId,
        epoch: u64,
        me: Participant,
        owner: Participant,
        participants: Vec<Participant>,
        protocol: T::Protocol,
        timeout: Duration,
        inbox: mpsc::Receiver<T::InMessage>,
        msg: MessageChannel,
        slot: Option<ArtifactSlot<T::Artifact>>,
        state: T::GenerationState,
    ) -> Self {
        Self {
            id,
            epoch,
            me,
            owner,
            participants,
            protocol: Some(protocol),
            created: Instant::now(),
            timeout,
            inbox,
            msg,
            slot,
            state,
        }
    }
}

impl<T: ArtifactProtocol> ProtocolGenerator<T> {
    async fn poke_action(&mut self) -> Result<Action<T::Output>, ()> {
        let mode = T::poke_mode(&self.state);
        let mut protocol = self.protocol.take().expect("protocol must exist");

        let action_res = match mode {
            PokeMode::Inline => T::protocol_poke(&mut protocol),
            PokeMode::Blocking => {
                match tokio::task::spawn_blocking(move || {
                    let out = T::protocol_poke(&mut protocol);
                    (out, protocol)
                })
                .await
                {
                    Ok((res, protocol_back)) => {
                        self.protocol = Some(protocol_back);
                        return match res {
                            Ok(action) => Ok(action),
                            Err(err) => {
                                T::on_poke_protocol_error(
                                    &mut self.state,
                                    self.me,
                                    self.owner,
                                    err,
                                );
                                Err(())
                            }
                        };
                    }
                    Err(err) => {
                        T::on_poke_join_error(&mut self.state, self.me, self.owner, err);
                        return Err(());
                    }
                }
            }
        };

        self.protocol = Some(protocol);
        match action_res {
            Ok(action) => Ok(action),
            Err(err) => {
                T::on_poke_protocol_error(&mut self.state, self.me, self.owner, err);
                Err(())
            }
        }
    }

    async fn wait_message(&mut self) -> bool {
        let remaining = self.timeout.saturating_sub(self.created.elapsed());
        match tokio::time::timeout(remaining, self.inbox.recv()).await {
            Ok(Some(msg)) => {
                let (from, data) = T::split_incoming(msg);
                let mut protocol = self.protocol.take().expect("protocol must exist");
                T::protocol_message(&mut protocol, from, data);
                self.protocol = Some(protocol);
                true
            }
            Ok(None) => {
                T::on_recv_closed(&mut self.state, self.id, self.owner);
                false
            }
            Err(_) => {
                T::on_recv_timeout(&mut self.state, self.id, self.owner);
                false
            }
        }
    }

    async fn send_many(&self, data: MessageData) {
        for &to in &self.participants {
            if to == self.me {
                continue;
            }
            let wire = T::build_message(&self.state, self.id, self.epoch, self.me, to, data.clone());
            T::send_message(&self.state, &self.msg, self.me, to, wire).await;
        }
    }

    async fn send_private(&self, to: Participant, data: MessageData) {
        let wire = T::build_message(&self.state, self.id, self.epoch, self.me, to, data);
        T::send_message(&self.state, &self.msg, self.me, to, wire).await;
    }

    pub async fn run(mut self) {
        let run_start = Instant::now();
        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        T::observe_before_poke_delay(&self.state, self.created);

        loop {
            let poke_start_time = Instant::now();
            let action = match self.poke_action().await {
                Ok(action) => action,
                Err(()) => break,
            };

            total_wait += poke_start_time - poke_last_time;
            total_pokes += 1;
            poke_last_time = Instant::now();
            T::observe_poke_cpu_time(&self.state, poke_start_time.elapsed());

            match action {
                Action::Wait => {
                    if !self.wait_message().await {
                        break;
                    }
                }
                Action::SendMany(data) => {
                    self.send_many(data).await;
                }
                Action::SendPrivate(to, data) => {
                    self.send_private(to, data).await;
                }
                Action::Return(output) => {
                    let artifact = T::finish(
                        &mut self.state,
                            self.id,
                            self.me,
                            self.owner,
                            &self.participants,
                            self.created,
                            output,
                            run_start.elapsed(),
                            total_wait,
                            total_pokes,
                        )
                        .await;

                    if let (Some(slot), Some(artifact)) = (self.slot.as_mut(), artifact) {
                        slot.insert(artifact, self.owner).await;
                    }
                    break;
                }
            }
        }

        T::on_drop(&self.state, self.id, self.msg.clone());
    }
}

async fn run_generation_task<T: ArtifactProtocol>(
    task_id: T::TaskId,
    me: Participant,
    owner: Participant,
    participants: Vec<Participant>,
    threshold: usize,
    epoch: u64,
    proposer_state: Option<T::ProposerState>,
    ctx: T::Context,
    timeout: Duration,
) {
    let Some(dependencies) =
        T::prepare_generation(&ctx, task_id, owner, proposer_state, timeout).await
    else {
        return;
    };

    let Some(build) = T::build_protocol(
        task_id,
        me,
        owner,
        participants,
        threshold,
        epoch,
        dependencies,
        ctx.clone(),
        timeout,
    )
    .await
    else {
        return;
    };

    ProtocolGenerator::<T>::new(
        build.id,
        epoch,
        me,
        owner,
        build.participants,
        build.protocol,
        timeout,
        build.inbox,
        build.msg,
        build.slot,
        build.state,
    )
    .run()
    .await;
}

/// Single protocol task instance handling posit negotiation and generation.
pub struct ProtocolTask<T: ArtifactProtocol, S: ProtocolTaskState<T>> {
    task_id: T::TaskId,
    me: Participant,
    threshold: usize,
    epoch: u64,
    state_data: S::Data,
    posit_rx: mpsc::Receiver<(Participant, PositAction)>,
    ctx: T::Context,
    generation_timeout: Duration,
    msg: MessageChannel,
}

impl<T: ArtifactProtocol> ProtocolTask<T, ProtocolProposer> {
    fn new(
        task_id: T::TaskId,
        me: Participant,
        threshold: usize,
        epoch: u64,
        proposer_state: T::ProposerState,
        participants: Vec<Participant>,
        posit_rx: mpsc::Receiver<(Participant, PositAction)>,
        ctx: T::Context,
        generation_timeout: Duration,
        msg: MessageChannel,
    ) -> Self {
        Self {
            task_id,
            me,
            threshold,
            epoch,
            state_data: (proposer_state, participants),
            posit_rx,
            ctx,
            generation_timeout,
            msg,
        }
    }

    async fn run(mut self) {
        let (proposer_state, participants) = self.state_data;

        for &p in &participants {
            if p == self.me {
                continue;
            }
            self.msg
                .send(
                    self.me,
                    p,
                    PositMessage {
                        id: T::posit_id(self.task_id),
                        from: self.me,
                        action: PositAction::Propose,
                    },
                )
                .await;
        }

        let mut accepts: HashSet<Participant> = HashSet::from([self.me]);
        let mut rejects: HashSet<Participant> = HashSet::new();
        let participant_set: HashSet<Participant> = participants.iter().copied().collect();

        let posit_deadline = tokio::time::sleep(POSIT_TIMEOUT);
        tokio::pin!(posit_deadline);

        let mut threshold_deadline: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;

        let accepted = loop {
            let enough_rejects = rejects.len() > participant_set.len().saturating_sub(self.threshold);
            if enough_rejects {
                tracing::info!(task_id = ?self.task_id, "enough REJECTs received, aborting posit");
                return;
            }

            tokio::select! {
                _ = &mut posit_deadline => {
                    if accepts.len() >= self.threshold {
                        tracing::info!(
                            task_id = ?self.task_id,
                            accepts = accepts.len(),
                            threshold = self.threshold,
                            "posit timeout with enough accepts, starting"
                        );
                        break accepts.into_iter().collect::<Vec<_>>();
                    }
                    tracing::info!(
                        task_id = ?self.task_id,
                        accepts = accepts.len(),
                        threshold = self.threshold,
                        "posit timeout without enough accepts, aborting"
                    );
                    return;
                }

                _ = async {
                    if let Some(ref mut d) = threshold_deadline {
                        d.await
                    } else {
                        std::future::pending::<()>().await
                    }
                } => {
                    tracing::info!(
                        task_id = ?self.task_id,
                        accepts = accepts.len(),
                        "accept delay elapsed, starting protocol"
                    );
                    break accepts.into_iter().collect::<Vec<_>>();
                }

                msg = self.posit_rx.recv() => {
                    let Some((from, action)) = msg else {
                        return;
                    };
                    if !participant_set.contains(&from) {
                        continue;
                    }
                    match action {
                        PositAction::Accept => {
                            accepts.insert(from);
                            if accepts.len() >= self.threshold && threshold_deadline.is_none() {
                                threshold_deadline =
                                    Some(Box::pin(tokio::time::sleep(ACCEPT_DELAY)));
                            }
                        }
                        PositAction::Reject => {
                            rejects.insert(from);
                        }
                        _ => {}
                    }
                }
            }
        };

        if accepted.len() < self.threshold {
            tracing::info!(task_id = ?self.task_id, "not enough accepts, aborting");
            return;
        }

        for &p in &accepted {
            if p == self.me {
                continue;
            }
            self.msg
                .send(
                    self.me,
                    p,
                    PositMessage {
                        id: T::posit_id(self.task_id),
                        from: self.me,
                        action: PositAction::Start(accepted.clone()),
                    },
                )
                .await;
        }

        tracing::info!(task_id = ?self.task_id, ?accepted, "posit complete (proposer), running generation");
        run_generation_task::<T>(
            self.task_id,
            self.me,
            self.me,
            accepted,
            self.threshold,
            self.epoch,
            Some(proposer_state),
            self.ctx,
            self.generation_timeout,
        )
        .await;
    }
}

impl<T: ArtifactProtocol> ProtocolTask<T, ProtocolDeliberator> {
    fn new(
        task_id: T::TaskId,
        me: Participant,
        threshold: usize,
        epoch: u64,
        proposer: Participant,
        posit_rx: mpsc::Receiver<(Participant, PositAction)>,
        ctx: T::Context,
        generation_timeout: Duration,
        msg: MessageChannel,
    ) -> Self {
        Self {
            task_id,
            me,
            threshold,
            epoch,
            state_data: proposer,
            posit_rx,
            ctx,
            generation_timeout,
            msg,
        }
    }

    async fn run(mut self) {
        let proposer = self.state_data;
        let dep_budget = POSIT_TIMEOUT.saturating_sub(Duration::from_secs(2));

        if !T::can_participate(&self.ctx, self.task_id, proposer, dep_budget).await {
            tracing::info!(task_id = ?self.task_id, ?proposer, "cannot participate, sending REJECT");
            self.msg
                .send(
                    self.me,
                    proposer,
                    PositMessage {
                        id: T::posit_id(self.task_id),
                        from: self.me,
                        action: PositAction::Reject,
                    },
                )
                .await;
            return;
        }

        self.msg
            .send(
                self.me,
                proposer,
                PositMessage {
                    id: T::posit_id(self.task_id),
                    from: self.me,
                    action: PositAction::Accept,
                },
            )
            .await;

        let start_deadline = tokio::time::sleep(POSIT_TIMEOUT + DELIBERATOR_EXTRA);
        tokio::pin!(start_deadline);

        let (owner, participants) = loop {
            tokio::select! {
                _ = &mut start_deadline => {
                    tracing::info!(task_id = ?self.task_id, "deliberator timeout waiting for Start");
                    return;
                }

                msg = self.posit_rx.recv() => {
                    let Some((from, action)) = msg else { return; };
                    if from != proposer {
                        continue;
                    }
                    if let PositAction::Start(participants) = action {
                        if !participants.contains(&self.me) {
                            tracing::warn!(task_id = ?self.task_id, "received Start but we are not in participants");
                            return;
                        }
                        if participants.len() < self.threshold {
                            tracing::warn!(task_id = ?self.task_id, "received Start with insufficient participants");
                            return;
                        }
                        break (from, participants);
                    }
                }
            }
        };

        tracing::info!(task_id = ?self.task_id, ?participants, "posit complete (deliberator), running generation");
        run_generation_task::<T>(
            self.task_id,
            self.me,
            owner,
            participants,
            self.threshold,
            self.epoch,
            None,
            self.ctx,
            self.generation_timeout,
        )
        .await;
    }
}

/// Defines the protocol-specific behaviour for artifact generation.
///
/// Types implementing this trait plug into the generic [`ProtocolSpawner`],
/// which handles posit negotiation, task routing, and stockpiling.  Only the
/// artifact-specific concerns (resource acquisition, dependency checks, actual
/// cait-sith generation) belong here.
pub trait ArtifactProtocol: Sized + Send + 'static {
    /// ID used to route posit and protocol messages for each task instance.
    type TaskId: Copy + Eq + Hash + fmt::Debug + Send + Sync + 'static;

    /// Final artifact stored when generation succeeds.
    type Artifact: ProtocolArtifact;

    /// State acquired by the proposer before broadcasting Propose
    /// (e.g. taken triple pairs for presignature generation).
    type ProposerState: Send + 'static;

    /// Generation-time dependencies resolved before the cait-sith protocol runs.
    type GenerationDeps: Send + 'static;

    /// Shared context passed to every task (storage, msg channel, keys, …).
    type Context: Clone + Send + Sync + 'static;

    /// Per-generation mutable state not belonging in shared generator core.
    type GenerationState: Send + Sync + 'static;

    /// Underlying cait-sith protocol object.
    type Protocol: Send + Sync + 'static;

    /// Final cait-sith protocol output.
    type Output: Send + 'static;

    /// Incoming protocol message type.
    type InMessage: Send + 'static;

    /// Outgoing protocol message type.
    type WireMessage: Into<Message> + Send + 'static;

    /// Returns the [`PositProtocolId`] for outgoing posit messages.
    fn posit_id(task_id: Self::TaskId) -> PositProtocolId;

    /// Proposer: acquire resources and choose participants.
    ///
    /// Returns `(task_id, proposer_state, participants)` or `None` if unable
    /// to propose right now.
    fn propose(
        ctx: &Self::Context,
        me: Participant,
        active: &[Participant],
        threshold: usize,
    ) -> impl std::future::Future<
        Output = Option<(Self::TaskId, Self::ProposerState, Vec<Participant>)>,
    > + Send;

    /// Deliberator: decide whether this node can participate.
    ///
    /// Called before sending Accept; may wait up to `budget` for dependencies
    /// to become available (e.g. triple pairs for presignature generation).
    /// Returns `true` to accept, `false` to reject.
    fn can_participate(
        ctx: &Self::Context,
        task_id: Self::TaskId,
        from: Participant,
        budget: Duration,
    ) -> impl std::future::Future<Output = bool> + Send;

    /// Returns `true` if the artifact is already generated or reserved in storage.
    fn is_known(
        ctx: &Self::Context,
        task_id: Self::TaskId,
    ) -> impl std::future::Future<Output = bool> + Send;

    /// Optional structural validation of the task ID (default: always valid).
    fn validate_task_id(_task_id: Self::TaskId) -> bool {
        true
    }

    /// Stockpile check: should we spawn a new proposer task right now?
    fn should_stockpile(
        ctx: &Self::Context,
        cfg: &ProtocolConfig,
        me: Participant,
        ongoing: usize,
        introduced: usize,
    ) -> impl std::future::Future<Output = bool> + Send;

    /// Generation timeout extracted from config.
    fn generation_timeout(cfg: &ProtocolConfig) -> Duration;

    fn poke_mode(_state: &Self::GenerationState) -> PokeMode {
        PokeMode::Inline
    }

    fn protocol_poke(protocol: &mut Self::Protocol) -> Result<Action<Self::Output>, ProtocolError>;

    fn protocol_message(protocol: &mut Self::Protocol, from: Participant, data: MessageData);

    fn split_incoming(msg: Self::InMessage) -> (Participant, MessageData);

    fn build_message(
        state: &Self::GenerationState,
        id: Self::TaskId,
        epoch: u64,
        from: Participant,
        to: Participant,
        data: MessageData,
    ) -> Self::WireMessage;

    fn send_message(
        _state: &Self::GenerationState,
        msg: &MessageChannel,
        from: Participant,
        to: Participant,
        wire: Self::WireMessage,
    ) -> impl std::future::Future<Output = ()> + Send {
        async move {
            msg.send(from, to, wire).await;
        }
    }

    fn observe_before_poke_delay(_state: &Self::GenerationState, _created: Instant) {}

    fn observe_poke_cpu_time(_state: &Self::GenerationState, _elapsed: Duration) {}

    fn on_poke_protocol_error(
        _state: &mut Self::GenerationState,
        _me: Participant,
        _owner: Participant,
        err: ProtocolError,
    ) {
        tracing::warn!(?err, "protocol generation failed");
    }

    fn on_poke_join_error(
        _state: &mut Self::GenerationState,
        _me: Participant,
        _owner: Participant,
        err: tokio::task::JoinError,
    ) {
        tracing::warn!(?err, "protocol generation failed in blocking task");
    }

    fn on_recv_closed(
        _state: &mut Self::GenerationState,
        _id: Self::TaskId,
        _owner: Participant,
    ) {
    }

    fn on_recv_timeout(
        _state: &mut Self::GenerationState,
        _id: Self::TaskId,
        _owner: Participant,
    ) {
    }

    fn on_drop(_state: &Self::GenerationState, _id: Self::TaskId, _msg: MessageChannel) {}

    fn finish(
        _state: &mut Self::GenerationState,
        _id: Self::TaskId,
        _me: Participant,
        _owner: Participant,
        _participants: &[Participant],
        _created: Instant,
        _output: Self::Output,
        _run_elapsed: Duration,
        _total_wait: Duration,
        _total_pokes: usize,
    ) -> impl std::future::Future<Output = Option<Self::Artifact>> + Send {
        async { None }
    }

    /// Resolve dependencies needed to run generation.
    fn prepare_generation(
        ctx: &Self::Context,
        task_id: Self::TaskId,
        owner: Participant,
        proposer_state: Option<Self::ProposerState>,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Option<Self::GenerationDeps>> + Send;

    /// Build protocol + inbox + driver after posit completes.
    fn build_protocol(
        task_id: Self::TaskId,
        me: Participant,
        owner: Participant,
        participants: Vec<Participant>,
        threshold: usize,
        epoch: u64,
        dependencies: Self::GenerationDeps,
        ctx: Self::Context,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Option<ProtocolBuildOutput<Self>>> + Send;

    /// Subscribe to the global posit stream for this protocol type.
    fn subscribe_posit(
        ctx: &Self::Context,
    ) -> impl std::future::Future<
        Output = mpsc::Receiver<(Self::TaskId, Participant, PositAction)>,
    > + Send;

    /// Unsubscribe from the global posit stream.
    fn unsubscribe_posit(ctx: Self::Context) -> impl std::future::Future<Output = ()> + Send;

    /// Update metrics (optional; default is a no-op).
    fn update_metrics(
        _ctx: &Self::Context,
        _me: Participant,
        _ongoing: usize,
        _introduced: usize,
    ) -> impl std::future::Future<Output = ()> + Send {
        async {}
    }

}


// ── ProtocolSpawner ───────────────────────────────────────────────────────────

/// Manages all protocol tasks for artifact type `T`.
///
/// Responsibilities:
/// - Routing incoming posit messages to per-task inboxes.
/// - Spawning proposer tasks when stockpile thresholds are not met.
/// - Spawning deliberator tasks on incoming `Propose` messages.
/// - Tracking ongoing and proposed task counts.
pub struct ProtocolSpawner<T: ArtifactProtocol> {
    me: Participant,
    threshold: usize,
    epoch: u64,
    /// All active tasks (proposer or deliberator, any phase).
    tasks: JoinMap<T::TaskId, ()>,
    /// Subset of `tasks` proposed by us (for `introduced` count).
    proposed: HashSet<T::TaskId>,
    /// Per-task posit inbox senders.
    task_posit_tx: HashMap<T::TaskId, mpsc::Sender<(Participant, PositAction)>>,
    ctx: T::Context,
    msg: MessageChannel,
}

impl<T: ArtifactProtocol> ProtocolSpawner<T> {
    pub fn new(
        me: Participant,
        threshold: usize,
        epoch: u64,
        ctx: T::Context,
        msg: MessageChannel,
    ) -> Self {
        Self {
            me,
            threshold,
            epoch,
            tasks: JoinMap::new(),
            proposed: HashSet::new(),
            task_posit_tx: HashMap::new(),
            ctx,
            msg,
        }
    }

    pub fn len_ongoing(&self) -> usize {
        self.tasks.len()
    }

    /// Number of tasks where we are the proposer (ongoing or in posit phase).
    pub fn len_introduced(&self) -> usize {
        self.proposed.len()
    }

    /// Attempt to propose a new protocol instance.
    async fn try_propose(&mut self, active: &[Participant], generation_timeout: Duration) -> bool {
        let Some((task_id, state, participants)) =
            T::propose(&self.ctx, self.me, active, self.threshold).await
        else {
            return false;
        };

        if self.tasks.contains_key(&task_id) {
            tracing::warn!(?task_id, "task already in progress, skipping new proposal");
            return false;
        }

        let (posit_tx, posit_rx) = mpsc::channel(64);
        self.task_posit_tx.insert(task_id, posit_tx);
        self.proposed.insert(task_id);

        let me = self.me;
        let threshold = self.threshold;
        let epoch = self.epoch;
        let ctx = self.ctx.clone();
        let msg = self.msg.clone();
        let span = tracing::info_span!(
            "protocol_task",
            task_id = ?task_id,
            me = ?me,
            owner = ?me,
            role = "proposer"
        );

        self.tasks.spawn(
            task_id,
            ProtocolTask::<T, ProtocolProposer>::new(
                task_id,
                me,
                threshold,
                epoch,
                state,
                participants,
                posit_rx,
                ctx,
                generation_timeout,
                msg,
            )
            .run()
            .instrument(span),
        );

        true
    }

    /// Route an incoming posit message or spawn a deliberator task.
    async fn handle_posit(
        &mut self,
        task_id: T::TaskId,
        from: Participant,
        action: PositAction,
        generation_timeout: Duration,
    ) {
        match &action {
            PositAction::Propose => {
                if !T::validate_task_id(task_id) {
                    tracing::warn!(?task_id, ?from, "invalid task ID, rejecting Propose");
                    self.reply_posit(task_id, from, PositAction::Reject).await;
                    return;
                }
                if self.tasks.contains_key(&task_id) {
                    tracing::warn!(?task_id, ?from, "task already active, rejecting Propose");
                    self.reply_posit(task_id, from, PositAction::Reject).await;
                    return;
                }
                if T::is_known(&self.ctx, task_id).await {
                    tracing::warn!(?task_id, ?from, "artifact already known, rejecting Propose");
                    self.reply_posit(task_id, from, PositAction::Reject).await;
                    return;
                }

                let (posit_tx, posit_rx) = mpsc::channel(64);
                self.task_posit_tx.insert(task_id, posit_tx);

                let me = self.me;
                let threshold = self.threshold;
                let epoch = self.epoch;
                let ctx = self.ctx.clone();
                let msg = self.msg.clone();
                let span = tracing::info_span!(
                    "protocol_task",
                    task_id = ?task_id,
                    me = ?me,
                    owner = ?from,
                    role = "deliberator"
                );

                self.tasks.spawn(
                    task_id,
                    ProtocolTask::<T, ProtocolDeliberator>::new(
                        task_id,
                        me,
                        threshold,
                        epoch,
                        from,
                        posit_rx,
                        ctx,
                        generation_timeout,
                        msg,
                    )
                    .run()
                    .instrument(span),
                );
            }

            PositAction::Accept | PositAction::Reject => {
                if let Some(tx) = self.task_posit_tx.get(&task_id) {
                    let _ = tx.send((from, action)).await;
                } else {
                    tracing::debug!(
                        ?task_id,
                        ?from,
                        "received Accept/Reject but no proposer task exists"
                    );
                }
            }

            PositAction::Start(participants) => {
                if let Some(tx) = self.task_posit_tx.get(&task_id) {
                    let _ = tx
                        .send((from, PositAction::Start(participants.clone())))
                        .await;
                } else {
                    tracing::debug!(
                        ?task_id,
                        ?from,
                        "received Start but no deliberator task exists"
                    );
                }
            }
        }
    }

    async fn maybe_stockpile(
        &mut self,
        active: &[Participant],
        protocol: &ProtocolConfig,
        last_active_warn: &mut Option<std::time::Instant>,
    ) {
        if active.len() < self.threshold {
            if last_active_warn
                .is_none_or(|i: std::time::Instant| i.elapsed() > Duration::from_secs(60))
            {
                tracing::warn!(
                    ?active,
                    threshold = self.threshold,
                    "not enough active participants"
                );
                *last_active_warn = Some(std::time::Instant::now());
            }
            return;
        }

        *last_active_warn = None;
        let timeout = T::generation_timeout(protocol);

        loop {
            let should = T::should_stockpile(
                &self.ctx,
                protocol,
                self.me,
                self.tasks.len(),
                self.len_introduced(),
            )
            .await;
            if !should {
                break;
            }

            if !self.try_propose(active, timeout).await {
                break;
            }
        }

    }

    async fn publish_ongoing(
        &self,
        ongoing_tx: &watch::Sender<usize>,
        last_ongoing: &mut usize,
    ) {
        let current = self.tasks.len();
        if current != *last_ongoing {
            let _ = ongoing_tx.send(current);
            *last_ongoing = current;
        }
        T::update_metrics(&self.ctx, self.me, current, self.len_introduced()).await;
    }

    async fn reply_posit(&self, task_id: T::TaskId, to: Participant, action: PositAction) {
        self.msg
            .send(
                self.me,
                to,
                PositMessage {
                    id: T::posit_id(task_id),
                    from: self.me,
                    action,
                },
            )
            .await;
    }

    pub async fn run(
        mut self,
        mut mesh_state: watch::Receiver<MeshState>,
        mut cfg: watch::Receiver<Config>,
        ongoing_tx: watch::Sender<usize>,
    ) {
        let mut posit_rx = T::subscribe_posit(&self.ctx).await;

        let mut active = mesh_state.borrow().active().keys_vec();
        let mut protocol = cfg.borrow().protocol.clone();
        let mut last_active_warn: Option<std::time::Instant> = None;
        let mut last_ongoing = self.tasks.len();
        let mut ongoing_rx = ongoing_tx.subscribe();

        self.maybe_stockpile(&active, &protocol, &mut last_active_warn)
            .await;
        self.publish_ongoing(&ongoing_tx, &mut last_ongoing).await;

        loop {
            tokio::select! {
                Some((task_id, from, action)) = posit_rx.recv() => {
                    let timeout = T::generation_timeout(&protocol);
                    self.handle_posit(task_id, from, action, timeout).await;
                    self.publish_ongoing(&ongoing_tx, &mut last_ongoing).await;
                }
                Some(result) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    let task_id = match result {
                        Ok((id, ())) => id,
                        Err(id) => {
                            tracing::warn!(?id, "protocol task interrupted");
                            id
                        }
                    };
                    self.proposed.remove(&task_id);
                    self.task_posit_tx.remove(&task_id);
                    self.publish_ongoing(&ongoing_tx, &mut last_ongoing).await;
                }
                Ok(()) = cfg.changed() => {
                    protocol = cfg.borrow().protocol.clone();
                }
                Ok(()) = mesh_state.changed() => {
                    active = mesh_state.borrow().active().keys_vec();
                }
                Ok(()) = ongoing_rx.changed() => {
                    self.maybe_stockpile(&active, &protocol, &mut last_active_warn)
                        .await;
                    self.publish_ongoing(&ongoing_tx, &mut last_ongoing).await;
                }
            }
        }
    }
}

impl<T: ArtifactProtocol> Drop for ProtocolSpawner<T> {
    fn drop(&mut self) {
        let ctx = self.ctx.clone();
        tokio::spawn(T::unsubscribe_posit(ctx));
    }
}

// ── ProtocolSpawnerTask ───────────────────────────────────────────────────────

/// Owns the spawned [`ProtocolSpawner<T>`] task and exposes minimal monitoring.
pub struct ProtocolSpawnerTask {
    ongoing_rx: watch::Receiver<usize>,
    handle: JoinHandle<()>,
}

impl ProtocolSpawnerTask {
    pub fn new<T: ArtifactProtocol>(
        me: Participant,
        threshold: usize,
        epoch: u64,
        ctx: T::Context,
        msg: MessageChannel,
        mesh_state: watch::Receiver<MeshState>,
        cfg: watch::Receiver<Config>,
    ) -> Self {
        let (ongoing_tx, ongoing_rx) = watch::channel(0);
        let spawner = ProtocolSpawner::<T>::new(me, threshold, epoch, ctx, msg);
        Self {
            ongoing_rx,
            handle: tokio::spawn(spawner.run(mesh_state, cfg, ongoing_tx)),
        }
    }

    /// Snapshot of ongoing task count (non-blocking).
    pub fn len_ongoing(&self) -> usize {
        *self.ongoing_rx.borrow()
    }

    pub fn abort(&self) {
        self.handle.abort();
    }
}

impl Drop for ProtocolSpawnerTask {
    fn drop(&mut self) {
        self.abort();
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cait_sith::protocol::{Participant, Protocol as CaitProtocol};
    use mpc_contract::config::ProtocolConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    struct ImmediateProtocol {
        done: bool,
    }

    impl CaitProtocol for ImmediateProtocol {
        type Output = ();

        fn poke(&mut self) -> Result<Action<Self::Output>, ProtocolError> {
            if self.done {
                return Ok(Action::Wait);
            }
            self.done = true;
            Ok(Action::Return(()))
        }

        fn message(&mut self, _from: Participant, _data: MessageData) {}
    }

    // ── Mock protocol ─────────────────────────────────────────────────────────

    /// A mock artifact protocol that counts successful generations and supports
    /// an optional capacity limit to simulate resource contention.
    struct MockProtocol;

    #[derive(Clone)]
    struct MockContext {
        /// Incremented each time `run_generation` completes.
        completed: Arc<AtomicUsize>,
        /// If set, `propose` fails once capacity is reached.
        capacity: Option<(Arc<AtomicUsize>, usize)>,
    }

    impl MockContext {
        fn new() -> Self {
            Self {
                completed: Arc::new(AtomicUsize::new(0)),
                capacity: None,
            }
        }
    }

    impl ArtifactProtocol for MockProtocol {
        type TaskId = u64;
        type Artifact = crate::storage::triple_storage::TriplePair;
        type ProposerState = ();
        type GenerationDeps = ();
        type Context = MockContext;
        type GenerationState = Arc<AtomicUsize>;
        type Protocol = ImmediateProtocol;
        type Output = ();
        type InMessage = ();
        type WireMessage = crate::protocol::message::TripleMessage;

        fn posit_id(task_id: u64) -> PositProtocolId {
            PositProtocolId::Triple(task_id)
        }

        async fn propose(
            ctx: &MockContext,
            me: Participant,
            active: &[Participant],
            _threshold: usize,
        ) -> Option<(u64, (), Vec<Participant>)> {
            if let Some((count, max)) = &ctx.capacity {
                let prev = count.fetch_add(1, Ordering::SeqCst);
                if prev >= *max {
                    count.fetch_sub(1, Ordering::SeqCst);
                    return None;
                }
            }
            let id: u64 = rand::random();
            let participants: Vec<Participant> = std::iter::once(me)
                .chain(active.iter().copied().filter(|&p| p != me))
                .collect();
            Some((id, (), participants))
        }

        async fn can_participate(
            _ctx: &MockContext,
            _task_id: u64,
            _from: Participant,
            _budget: Duration,
        ) -> bool {
            true
        }

        async fn is_known(_ctx: &MockContext, _task_id: u64) -> bool {
            false
        }

        async fn should_stockpile(
            ctx: &MockContext,
            _cfg: &ProtocolConfig,
            _me: Participant,
            ongoing: usize,
            _introduced: usize,
        ) -> bool {
            if let Some((count, max)) = &ctx.capacity {
                ongoing < *max && count.load(Ordering::SeqCst) < *max
            } else {
                ongoing < 1
            }
        }

        fn generation_timeout(_cfg: &ProtocolConfig) -> Duration {
            Duration::from_secs(5)
        }

        fn protocol_poke(protocol: &mut Self::Protocol) -> Result<Action<Self::Output>, ProtocolError> {
            protocol.poke()
        }

        fn protocol_message(protocol: &mut Self::Protocol, from: Participant, data: MessageData) {
            protocol.message(from, data);
        }

        fn split_incoming(_msg: Self::InMessage) -> (Participant, MessageData) {
            unreachable!()
        }

        fn build_message(
            _state: &Self::GenerationState,
            _id: Self::TaskId,
            _epoch: u64,
            _from: Participant,
            _to: Participant,
            _data: MessageData,
        ) -> Self::WireMessage {
            unreachable!()
        }

        async fn finish(
            state: &mut Self::GenerationState,
            _id: Self::TaskId,
            _me: Participant,
            _owner: Participant,
            _participants: &[Participant],
            _created: Instant,
            _output: Self::Output,
            _run_elapsed: Duration,
            _total_wait: Duration,
            _total_pokes: usize,
        ) -> Option<Self::Artifact> {
            state.fetch_add(1, Ordering::SeqCst);
            None
        }

        async fn prepare_generation(
            _ctx: &MockContext,
            _task_id: u64,
            _owner: Participant,
            _proposer_state: Option<()>,
            _timeout: Duration,
        ) -> Option<()> {
            Some(())
        }

        async fn build_protocol(
            task_id: u64,
            _me: Participant,
            _owner: Participant,
            participants: Vec<Participant>,
            _threshold: usize,
            _epoch: u64,
            _dependencies: (),
            ctx: MockContext,
            _timeout: Duration,
        ) -> Option<ProtocolBuildOutput<Self>> {
            let inbox = mpsc::channel(1).1;
            let (_inbox, _outbox, msg) = crate::protocol::message::MessageChannel::new();
            Some(ProtocolBuildOutput {
                id: task_id,
                participants,
                protocol: ImmediateProtocol { done: false },
                inbox,
                msg,
                slot: None,
                state: ctx.completed,
            })
        }

        async fn subscribe_posit(
            _ctx: &MockContext,
        ) -> mpsc::Receiver<(u64, Participant, PositAction)> {
            mpsc::channel(1).1
        }

        async fn unsubscribe_posit(_ctx: MockContext) {}
    }

    // ── Helper: simulate a complete posit round-trip ──────────────────────────

    /// Drive a proposer task to completion by simulating `n_peers` accepting.
    ///
    /// Returns the task join handle plus the posit sender used to inject
    /// Accept/Reject messages.
    fn spawn_proposer_task(
        me: Participant,
        peers: Vec<Participant>,
        threshold: usize,
        ctx: MockContext,
    ) -> (
        tokio::task::JoinHandle<()>,
        mpsc::Sender<(Participant, PositAction)>,
    ) {
        let (_inbox, _outbox, msg) = crate::protocol::message::MessageChannel::new();
        let (posit_tx, posit_rx) = mpsc::channel(64);
        let task_id: u64 = rand::random();
        let participants: Vec<Participant> = std::iter::once(me)
            .chain(peers.iter().copied())
            .collect();

        let handle = tokio::spawn(
            ProtocolTask::<MockProtocol, ProtocolProposer>::new(
                task_id,
                me,
                threshold,
                0,
                (),
                participants,
                posit_rx,
                ctx,
                Duration::from_secs(5),
                msg,
            )
            .run(),
        );

        (handle, posit_tx)
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn proposer_starts_after_threshold_delay() {
        let me = Participant::from(0);
        let peer1 = Participant::from(1);
        let peer2 = Participant::from(2);
        let threshold = 2;
        let ctx = MockContext::new();
        let completed = ctx.completed.clone();

        let (handle, posit_tx) =
            spawn_proposer_task(me, vec![peer1, peer2], threshold, ctx.clone());

        // Send one accept — not yet threshold (need me + 1 peer = 2 total including self).
        // Self is pre-included, so threshold=2 means we need just 1 more accept.
        posit_tx.send((peer1, PositAction::Accept)).await.unwrap();

        // Wait past ACCEPT_DELAY (test value = 100ms) but well within POSIT_TIMEOUT.
        tokio::time::sleep(Duration::from_millis(250)).await;
        handle.await.unwrap();
        assert_eq!(completed.load(Ordering::SeqCst), 1, "generation should have run");
    }

    #[tokio::test]
    async fn proposer_aborts_on_enough_rejects() {
        let me = Participant::from(0);
        let peer1 = Participant::from(1);
        let peer2 = Participant::from(2);
        let threshold = 2;
        let ctx = MockContext::new();
        let completed = ctx.completed.clone();

        let (handle, posit_tx) =
            spawn_proposer_task(me, vec![peer1, peer2], threshold, ctx.clone());

        // With 3 participants and threshold 2: enough_rejects = rejects > 3-2 = 1.
        // So 2 rejects → abort.
        posit_tx.send((peer1, PositAction::Reject)).await.unwrap();
        posit_tx.send((peer2, PositAction::Reject)).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.await.unwrap();
        assert_eq!(completed.load(Ordering::SeqCst), 0, "generation should NOT have run");
    }

    #[tokio::test]
    async fn proposer_aborts_on_posit_timeout_no_accepts() {
        let me = Participant::from(0);
        let peer1 = Participant::from(1);
        let peer2 = Participant::from(2);
        let threshold = 3; // Need all 3 — impossible since only self is counted
        let ctx = MockContext::new();
        let completed = ctx.completed.clone();

        let (handle, posit_tx) =
            spawn_proposer_task(me, vec![peer1, peer2], threshold, ctx.clone());

        // No peers send anything → timeout.
        drop(posit_tx);

        // POSIT_TIMEOUT in tests = 2s; sleep past it.
        tokio::time::sleep(Duration::from_secs(3)).await;
        handle.await.unwrap();
        assert_eq!(completed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn deliberator_accepts_and_awaits_start() {
        let me = Participant::from(1);
        let proposer = Participant::from(0);
        let threshold = 2;
        let ctx = MockContext::new();
        let completed = ctx.completed.clone();

        let (_inbox, _outbox, msg) = crate::protocol::message::MessageChannel::new();
        let (posit_tx, posit_rx) = mpsc::channel(64);
        let task_id: u64 = rand::random();

        let participants = vec![proposer, me];

        let handle = tokio::spawn(
            ProtocolTask::<MockProtocol, ProtocolDeliberator>::new(
                task_id,
                me,
                threshold,
                0,
                proposer,
                posit_rx,
                ctx.clone(),
                Duration::from_secs(5),
                msg,
            )
            .run(),
        );

        // Give the task time to send Accept and start waiting for Start.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Proposer sends Start.
        posit_tx
            .send((proposer, PositAction::Start(participants)))
            .await
            .unwrap();

        handle.await.unwrap();
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn deliberator_rejects_when_cannot_participate() {
        struct RejectingProtocol;

        #[derive(Clone)]
        struct RejectCtx {
            completed: Arc<AtomicUsize>,
        }

        impl ArtifactProtocol for RejectingProtocol {
            type TaskId = u64;
            type Artifact = crate::storage::triple_storage::TriplePair;
            type ProposerState = ();
            type GenerationDeps = ();
            type Context = RejectCtx;
            type GenerationState = ();
            type Protocol = ImmediateProtocol;
            type Output = ();
            type InMessage = ();
            type WireMessage = crate::protocol::message::TripleMessage;

            fn posit_id(id: u64) -> PositProtocolId {
                PositProtocolId::Triple(id)
            }
            async fn propose(
                _: &RejectCtx,
                _: Participant,
                _: &[Participant],
                _: usize,
            ) -> Option<(u64, (), Vec<Participant>)> {
                None
            }
            async fn can_participate(
                _: &RejectCtx,
                _: u64,
                _: Participant,
                _: Duration,
            ) -> bool {
                false
            }
            async fn is_known(_: &RejectCtx, _: u64) -> bool {
                false
            }
            async fn should_stockpile(
                _: &RejectCtx,
                _: &ProtocolConfig,
                _: Participant,
                _: usize,
                _: usize,
            ) -> bool {
                false
            }
            fn generation_timeout(_: &ProtocolConfig) -> Duration {
                Duration::from_secs(5)
            }
            fn protocol_poke(protocol: &mut Self::Protocol) -> Result<Action<Self::Output>, ProtocolError> {
                protocol.poke()
            }
            fn protocol_message(protocol: &mut Self::Protocol, from: Participant, data: MessageData) {
                protocol.message(from, data);
            }
            fn split_incoming(_: Self::InMessage) -> (Participant, MessageData) {
                unreachable!()
            }
            fn build_message(
                _state: &Self::GenerationState,
                _id: Self::TaskId,
                _epoch: u64,
                _from: Participant,
                _to: Participant,
                _data: MessageData,
            ) -> Self::WireMessage {
                unreachable!()
            }
            async fn prepare_generation(
                _: &RejectCtx,
                _: u64,
                _: Participant,
                _: Option<()>,
                _: Duration,
            ) -> Option<()> {
                Some(())
            }
            async fn build_protocol(
                _: u64,
                _: Participant,
                _: Participant,
                _: Vec<Participant>,
                _: usize,
                _: u64,
                _: (),
                _: RejectCtx,
                _: Duration,
            ) -> Option<ProtocolBuildOutput<Self>> {
                None
            }
            async fn subscribe_posit(_: &RejectCtx) -> mpsc::Receiver<(u64, Participant, PositAction)> {
                mpsc::channel(1).1
            }
            async fn unsubscribe_posit(_: RejectCtx) {}
        }

        let me = Participant::from(1);
        let proposer = Participant::from(0);
        let ctx = RejectCtx {
            completed: Arc::new(AtomicUsize::new(0)),
        };
        let completed = ctx.completed.clone();

        let (_inbox, _outbox, msg) = crate::protocol::message::MessageChannel::new();
        let (_posit_tx, posit_rx) = mpsc::channel(64);
        let task_id: u64 = rand::random();

        let handle = tokio::spawn(
            ProtocolTask::<RejectingProtocol, ProtocolDeliberator>::new(
                task_id,
                me,
                2,
                0,
                proposer,
                posit_rx,
                ctx,
                Duration::from_secs(5),
                msg,
            )
            .run(),
        );

        handle.await.unwrap();
        assert_eq!(completed.load(Ordering::SeqCst), 0, "should NOT generate when cannot participate");
    }

    /// Congestion test: many proposer tasks competing for limited capacity.
    ///
    /// Verifies that many concurrent proposer tasks complete without deadlock.
    /// Capacity enforcement is a spawner-level concern (via `should_stockpile`);
    /// here we just confirm no task hangs.
    #[tokio::test]
    async fn congestion_limited_capacity_no_deadlock() {
        const NUM_TASKS: usize = 10;

        let me = Participant::from(0);
        let peer1 = Participant::from(1);
        let peer2 = Participant::from(2);
        let threshold = 2;
        let ctx = MockContext::new();
        let completed = ctx.completed.clone();

        // Spawn NUM_TASKS proposer tasks concurrently.
        let mut handles = Vec::new();
        for _ in 0..NUM_TASKS {
            let (handle, posit_tx) =
                spawn_proposer_task(me, vec![peer1, peer2], threshold, ctx.clone());
            // Accept from peer1 so tasks can proceed.
            let _ = posit_tx.send((peer1, PositAction::Accept)).await;
            handles.push((handle, posit_tx));
        }

        // All tasks must complete within POSIT_TIMEOUT (test-feature = 2s) + margin.
        for (handle, _tx) in handles {
            tokio::time::timeout(Duration::from_secs(3), handle)
                .await
                .expect("task did not finish within timeout")
                .expect("task panicked");
        }

        // All NUM_TASKS tasks completed without deadlock.
        assert_eq!(completed.load(Ordering::SeqCst), NUM_TASKS);
    }

    /// Congestion test: tasks overwhelm the posit channel under high message volume.
    ///
    /// Exposes brittleness in timeout handling when many accept/reject messages
    /// arrive simultaneously and the runtime is saturated.
    #[tokio::test]
    async fn congestion_high_message_volume() {
        let me = Participant::from(0);
        let threshold = 2;
        let ctx = MockContext::new();
        let completed = ctx.completed.clone();

        // Spawn many proposer tasks, each with 9 peers.
        let peers: Vec<Participant> = (1..10).map(Participant::from).collect();
        const NUM_TASKS: usize = 20;

        let mut handles = Vec::new();
        for _ in 0..NUM_TASKS {
            let (handle, posit_tx) =
                spawn_proposer_task(me, peers.clone(), threshold, ctx.clone());
            handles.push((handle, posit_tx));
        }

        // Flood all tasks with accepts from all peers simultaneously.
        for (_, posit_tx) in &handles {
            for &p in &peers {
                let _ = posit_tx.send((p, PositAction::Accept)).await;
            }
        }

        // All tasks must complete within a reasonable bound.
        for (handle, _tx) in handles {
            tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("task hung — timeout too brittle under load")
                .expect("task panicked");
        }

        // All tasks should have generated.
        assert_eq!(
            completed.load(Ordering::SeqCst),
            NUM_TASKS,
            "expected all {NUM_TASKS} tasks to complete"
        );
    }
}
