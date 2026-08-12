use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;
use std::time::{Duration, Instant};

pub type ProposerId = Participant;

#[derive(Debug)]
pub enum Positor<T> {
    Proposer(ProposerId, T),
    Deliberator(ProposerId),
}

impl<T> Positor<T> {
    pub fn is_proposer(&self) -> bool {
        matches!(self, Positor::Proposer(_, _))
    }

    pub fn id(&self) -> ProposerId {
        match self {
            Positor::Proposer(id, _) => *id,
            Positor::Deliberator(id) => *id,
        }
    }
}

impl<S> Positor<PositCounter<S>> {
    #[cfg(feature = "debug-page")]
    pub fn render_debug(&self, threshold: usize) -> maud::Markup {
        match self {
            Positor::Proposer(_id, counter) => {
                let display = format!(
                    "Proposer accepted={}/{}, rejected={}",
                    counter.accepts.len(),
                    threshold,
                    counter.rejects.len()
                );
                maud::html!((display))
            }
            Positor::Deliberator(_id) => maud::html!("Deliberator"),
        }
    }
}

/// All actions that can be taken when a new posit is introduced for a protocol.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum PositAction {
    Propose,
    Start(Vec<Participant>),
    Accept,
    RejectWithReason(PositRejectReason),
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy, Hash)]
pub enum PositRejectReason {
    Unknown,
    /// The node is already participating in a generation, or has already
    /// finished generation.
    AlreadyGenerating,
    /// The node cannot participate because it doesn't have the required
    /// artifact.
    MissingArtifact,
    /// The posit message is invalid, usually because of bad timing leading to
    /// round / proposer mismatches.
    InvalidRequest,
    /// The message's round is behind the rejector's current round, carried
    /// in `PositMessage::stale_round` so the sender can catch up in one bump.
    StaleRound,
}

impl PositAction {
    pub fn is_accept(&self) -> bool {
        matches!(self, PositAction::Accept)
    }
}

#[derive(Debug)]
pub enum PositInternalAction<S> {
    StartProtocol(Vec<Participant>, Positor<S>),
    Reply(PositAction),
    Abort,
    None,
}

/// A counter for a posit. This is used to track the participants that have
/// accepted the posit alongside storing an intermediary state for the protocol
/// that the proposer needs to keep track of.
pub struct PositCounter<S> {
    pub participants: HashSet<Participant>,
    accepts: HashSet<Participant>,
    rejects: HashSet<Participant>,
    store: S,
}

impl<T> PositCounter<T> {
    pub fn enough_accepts(&self, threshold: usize) -> bool {
        self.accepts.len() >= threshold
    }

    pub fn enough_rejects(&self, threshold: usize) -> bool {
        self.rejects.len() > self.participants.len() - threshold
    }

    pub fn meets_totality(&self) -> bool {
        self.accepts.len() + self.rejects.len() == self.participants.len()
    }
}

/// A collection of posits that are being proposed. This is used to track
/// the posits that are being proposed and the participants that have
/// accepted them.
pub struct Posits<Id, S> {
    me: Participant,

    /// The posits that either our node proposed or that we are a part of.
    posits: HashMap<Id, (Positor<PositCounter<S>>, Instant)>,
}

impl<Id: Copy + Hash + Eq + fmt::Debug, S> Posits<Id, S> {
    pub fn new(me: Participant) -> Self {
        Self {
            me,
            posits: HashMap::new(),
        }
    }

    /// Returns false if there was already an ongoing proposal.
    ///
    /// The return value is only for tests.
    pub fn propose(&mut self, id: Id, store: S, participants: &[Participant]) -> bool {
        let entry = match self.posits.entry(id) {
            Entry::Vacant(entry) => entry,
            Entry::Occupied(_) => {
                tracing::warn!(?id, "PROPOSE protocol already in progress");
                return false;
            }
        };

        let mut accepts = HashSet::new();
        accepts.insert(self.me);
        let positor = Positor::Proposer(
            self.me,
            PositCounter {
                participants: participants.iter().copied().collect(),
                accepts,
                rejects: HashSet::new(),
                store,
            },
        );
        let timestamp = Instant::now();
        entry.insert((positor, timestamp));
        true
    }

    /// Act on the posit action. This will map the action received to a corresponding
    /// action to be sent back to the proposer. This will return a series of internal
    /// actions the node should take.
    pub fn act(
        &mut self,
        id: Id,
        from: Participant,
        threshold: usize,
        action: &PositAction,
    ) -> PositInternalAction<S> {
        // Before getting to this point, we should have already checked storage for the related protocols.
        // All information passed to this function should be valid. The only information that still needs
        // to be checked is the information about the posit itself and whether we're in the right state for
        // it to proceed and be acted upon.

        match action {
            PositAction::Propose => {
                // We have no information about this posit, so we can just accept it.
                let Some((positor, _)) = self.posits.get(&id) else {
                    self.posits
                        .insert(id, (Positor::Deliberator(from), Instant::now()));
                    return PositInternalAction::Reply(PositAction::Accept);
                };

                // Checks:
                // 1. We are not the proposer.
                // 2. Somebody else hasn't also proposed the protocol.
                let proposer = positor.id();
                if positor.is_proposer() {
                    tracing::warn!(?id, ?from, "received INIT on protocol we already proposed");
                    PositInternalAction::Reply(PositAction::RejectWithReason(
                        PositRejectReason::InvalidRequest,
                    ))
                } else if proposer != from {
                    tracing::warn!(
                        ?id,
                        ?from,
                        ?proposer,
                        "received INIT on conflicting proposer"
                    );
                    PositInternalAction::Reply(PositAction::RejectWithReason(
                        PositRejectReason::InvalidRequest,
                    ))
                } else {
                    PositInternalAction::Reply(PositAction::Accept)
                }
            }
            PositAction::Start(participants) => {
                // Checks:
                // 1. We are a participant in the protocol.
                // 2. We are not the proposer.
                // 3. The proposer is the one that started the protocol.

                if !participants.contains(&self.me) {
                    tracing::warn!(
                        ?id,
                        ?from,
                        "received START on protocol we are not a part of"
                    );
                    return PositInternalAction::Reply(PositAction::RejectWithReason(
                        PositRejectReason::InvalidRequest,
                    ));
                }

                if let Some((positor, timestamp)) = self.posits.remove(&id) {
                    let proposer = positor.id();
                    if positor.is_proposer() {
                        tracing::warn!(
                            ?id,
                            ?from,
                            "received START on protocol we already proposed"
                        );
                        self.posits.insert(id, (positor, timestamp));
                        return PositInternalAction::Reply(PositAction::RejectWithReason(
                            PositRejectReason::InvalidRequest,
                        ));
                    } else if proposer != from {
                        tracing::warn!(
                            ?id,
                            ?from,
                            ?proposer,
                            "received START on conflicting proposer"
                        );
                        self.posits.insert(id, (positor, timestamp));
                        return PositInternalAction::Reply(PositAction::RejectWithReason(
                            PositRejectReason::InvalidRequest,
                        ));
                    }
                } else {
                    tracing::warn!(?id, ?from, "received START on protocol we have no info for");
                    return PositInternalAction::Reply(PositAction::RejectWithReason(
                        PositRejectReason::InvalidRequest,
                    ));
                }

                PositInternalAction::StartProtocol(
                    participants.to_vec(),
                    Positor::Deliberator(from),
                )
            }
            PositAction::Accept | PositAction::RejectWithReason(_) => {
                let mut entry = match self.posits.entry(id) {
                    Entry::Occupied(entry) => entry,
                    Entry::Vacant(_) => {
                        tracing::warn!(
                            ?id,
                            ?from,
                            ?action,
                            "received ACCEPT/REJECT on protocol we have no info for",
                        );
                        return PositInternalAction::None;
                    }
                };

                let (Positor::Proposer(_, counter), _) = entry.get_mut() else {
                    tracing::warn!(
                        ?id,
                        ?from,
                        ?action,
                        "received ACCEPT/REJECT on protocol we are not proposer for",
                    );
                    return PositInternalAction::None;
                };

                if !counter.participants.contains(&from) {
                    tracing::warn!(
                        ?id,
                        ?from,
                        ?action,
                        "received ACCEPT/REJECT from participant not in protocol",
                    );
                    return PositInternalAction::None;
                }

                if action.is_accept() {
                    if counter.accepts.insert(from) {
                        tracing::info!(?id, ?from, "posit ACCEPT processed");
                    } else {
                        tracing::warn!(?id, ?from, "posit ACCEPT duplicate ignored");
                    }
                } else if counter.rejects.insert(from) {
                    tracing::info!(?id, ?from, "posit REJECT processed");
                } else {
                    tracing::warn!(?id, ?from, "posit REJECT duplicate ignored");
                }

                // TODO: broadcast aborting the protocol if we have enough rejections
                if counter.enough_rejects(threshold) {
                    tracing::info!(
                        ?id,
                        ?counter.accepts,
                        ?counter.rejects,
                        "received enough REJECTs, aborting protocol",
                    );
                    entry.remove();
                    return PositInternalAction::Abort;
                }

                if !counter.meets_totality() {
                    return PositInternalAction::None;
                }

                tracing::info!(?id, ?counter.accepts, ?counter.rejects, "received enough ACCEPTs, starting protocol");
                let (Positor::Proposer(_, counter), _) = entry.remove() else {
                    unreachable!("we already checked that we are the proposer");
                };
                let participants = counter.accepts.into_iter().collect();
                PositInternalAction::StartProtocol(
                    participants,
                    Positor::Proposer(self.me, counter.store),
                )
            }
        }
    }

    #[cfg(feature = "debug-page")]
    pub fn render_debug(&self, threshold: usize) -> maud::Markup {
        let posits = self
            .posits
            .iter()
            .map(|(id, (positor, _))| (format!("{id:?}"), positor.render_debug(threshold)));

        maud::html! {
            .posits {
                @for (id, posit) in posits {
                    .id {
                        (id)
                    }
                    .posit {
                        (posit)
                    }
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.posits.len()
    }

    pub fn len_proposed(&self) -> usize {
        self.posits
            .values()
            .filter(|(positor, _)| positor.is_proposer())
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.posits.is_empty()
    }

    /// Expire and start protocols on enough accepted votes. Abort protocols action will be returned
    /// if the posit has expired.
    ///
    /// Note on `deliberator_extra_time`:
    ///   Deliberators need to wait longer than the proposer, otherwise
    ///   they have a high chance of aborting just when the proposer
    ///   decides to move forward.
    ///   Once Ts and Ps are generated with a single task, the same way
    ///   signatures are handled, this should be replaced with a round-based
    ///   message buffer.
    pub fn expire_and_start(
        &mut self,
        threshold: usize,
        timeout: Duration,
        deliberator_extra_time: Duration,
    ) -> Vec<(Id, PositInternalAction<S>)> {
        let mut expired = Vec::new();
        for (id, (positor, timestamp)) in &self.posits {
            let final_timeout = if positor.is_proposer() {
                timeout
            } else {
                timeout + deliberator_extra_time
            };
            if timestamp.elapsed() > final_timeout {
                expired.push(*id);
            }
        }

        let mut expired_proposers = Vec::new();
        let mut expired_deliberators = Vec::new();
        let mut expired_and_accepted = Vec::new();
        let mut actions = Vec::new();
        for id in &expired {
            let Some((positor, _)) = self.posits.remove(id) else {
                continue;
            };
            let Positor::Proposer(_, counter) = positor else {
                expired_deliberators.push(*id);
                continue;
            };
            if counter.enough_accepts(threshold) {
                expired_and_accepted.push(*id);
                actions.push((
                    *id,
                    PositInternalAction::StartProtocol(
                        counter.accepts.into_iter().collect(),
                        Positor::Proposer(self.me, counter.store),
                    ),
                ));
            } else {
                expired_proposers.push(*id);
                actions.push((*id, PositInternalAction::Abort));
            }
        }

        if expired_proposers.len() + expired_deliberators.len() + expired_and_accepted.len() > 0 {
            tracing::info!(
                ?expired_deliberators,
                ?expired_proposers,
                ?expired_and_accepted,
                total_expired = expired_proposers.len()
                    + expired_deliberators.len()
                    + expired_and_accepted.len(),
                "expiring posits"
            );
        }
        actions
    }
}

/// The participants observed by a [`PositBarrier`] when it reaches a terminal
/// state. `pending` contains participants that have not sent a usable response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PositBarrierState {
    pub(crate) accepted: HashSet<Participant>,
    pub(crate) rejected: HashMap<Participant, PositRejectReason>,
    pub(crate) pending: HashSet<Participant>,
}

/// The terminal state of a [`PositBarrier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PositBarrierResult {
    Timeout(PositBarrierState),
    TooManyRejects(PositBarrierState),
    EnoughAccepts(PositBarrierState),
}

/// Collects responses to one posit and reports when the posit can be decided.
///
/// Unlike [`tokio::sync::Barrier`], this barrier does not require every
/// participant to respond. The caller owns async I/O and deadlines; this type
/// only tracks votes and computes the current terminal result.
pub(crate) struct PositBarrier {
    participants: HashSet<Participant>,
    threshold: usize,
    accepted: HashSet<Participant>,
    rejected: HashMap<Participant, PositRejectReason>,
}

impl PositBarrier {
    /// Create a barrier with the local participant's implicit accept vote.
    ///
    /// The local participant is inserted into `participants` if it is not
    /// already present. Each participant contributes at most one vote: later
    /// duplicate or contradictory responses are ignored.
    pub(crate) fn new(me: Participant, participants: &[Participant], threshold: usize) -> Self {
        let mut participants: HashSet<_> = participants.iter().copied().collect();
        participants.insert(me);

        let mut accepted = HashSet::new();
        accepted.insert(me);

        Self {
            participants,
            threshold,
            accepted,
            rejected: HashMap::new(),
        }
    }

    /// Record one participant's response. Returns false for non-voting posit
    /// actions or senders outside the participant set.
    ///
    /// Each participant has one vote: the first response wins, and later
    /// duplicate or contradictory responses are accepted as handled but do not
    /// change the recorded result.
    pub(crate) fn process_action(&mut self, from: Participant, action: &PositAction) {
        if !self.participants.contains(&from) {
            return;
        }

        let response_recorded = self.accepted.contains(&from) || self.rejected.contains_key(&from);
        match action {
            PositAction::Accept | PositAction::RejectWithReason(_) if response_recorded => {}
            PositAction::Accept => {
                self.accepted.insert(from);
            }
            PositAction::RejectWithReason(reason) => {
                self.rejected.insert(from, *reason);
            }
            PositAction::Propose | PositAction::Start(_) => {}
        }
    }

    fn enough_accepts(&self) -> bool {
        self.accepted.len() >= self.threshold
    }

    fn enough_rejects(&self) -> bool {
        self.rejected.len() > self.participants.len().saturating_sub(self.threshold)
    }

    fn meets_totality(&self) -> bool {
        self.accepted.len() + self.rejected.len() == self.participants.len()
    }

    pub(crate) fn terminal_result(
        &self,
        accept_deadline_reached: bool,
    ) -> Option<PositBarrierResult> {
        if self.enough_rejects() {
            return Some(PositBarrierResult::TooManyRejects(self.state()));
        }

        if self.enough_accepts() && (accept_deadline_reached || self.meets_totality()) {
            return Some(PositBarrierResult::EnoughAccepts(self.state()));
        }

        None
    }

    pub(crate) fn timeout(&self) -> PositBarrierResult {
        PositBarrierResult::Timeout(self.state())
    }

    fn state(&self) -> PositBarrierState {
        let responded = self
            .accepted
            .iter()
            .copied()
            .chain(self.rejected.keys().copied())
            .collect::<HashSet<_>>();
        let pending = self.participants.difference(&responded).copied().collect();

        PositBarrierState {
            accepted: self.accepted.clone(),
            rejected: self.rejected.clone(),
            pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cait_sith::protocol::Participant;

    type Id = u64;

    #[test]
    fn test_posits_non_proposer() {
        let threshold = 2;
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
        ];
        let mut posits0 = Posits::<Id, ()>::new(Participant::from(0));
        let mut posits1 = Posits::<Id, ()>::new(Participant::from(1));
        let mut posits3 = Posits::<Id, ()>::new(Participant::from(3));

        // Node0 propose a new posit 101
        let id = 101;
        let correct_proposer = Participant::from(0);
        let incorrect_proposer = Participant::from(1);
        let ok = posits0.propose(id, (), &participants);
        assert!(ok);

        // propose: act on posit with correct proposer should be accepted
        let action = posits1.act(id, correct_proposer, threshold, &PositAction::Propose);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Accept)
        ));
        // propose(conflict): a second node claims this posit, but only the first is accepted. reject this one
        let action = posits1.act(id, incorrect_proposer, threshold, &PositAction::Propose);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::RejectWithReason(
                PositRejectReason::InvalidRequest,
            ))
        ));
        // propose: act on posit again should be idempotent
        let action = posits1.act(id, correct_proposer, threshold, &PositAction::Propose);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::Accept)
        ));

        // propose(conflict): proposing a posit that is already in progress should be rejected
        let ok = posits1.propose(id, (), &participants);
        assert!(!ok);

        // start: incorrect proposer should reject
        let start = PositAction::Start(participants);
        let action = posits1.act(id, incorrect_proposer, threshold, &start);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::RejectWithReason(
                PositRejectReason::InvalidRequest,
            ))
        ));
        // start: correct proposer should start the protocol
        let action = posits1.act(id, correct_proposer, threshold, &start);
        assert!(matches!(
            action,
            PositInternalAction::StartProtocol(_, Positor::Deliberator(_))
        ));

        // start: the node is not a part of the participants so reject
        let proposer = Participant::from(0);
        let action = posits3.act(id, proposer, threshold, &start);
        assert!(matches!(
            action,
            PositInternalAction::Reply(PositAction::RejectWithReason(
                PositRejectReason::InvalidRequest,
            ))
        ));
    }

    #[test]
    fn test_posits_proposer() {
        let threshold = 2;
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
        ];
        let mut posits0 = Posits::<Id, ()>::new(Participant::from(0));

        let id = 101;

        // start: on all accept, start the protocol
        posits0.propose(id, (), &participants);
        let action = posits0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));
        // receiving an accept from the same participant will do nothing
        let action = posits0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));
        // everyone has voted, so we can start the protocol
        let action = posits0.act(id, Participant::from(2), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::StartProtocol(_, _)));
        // receiving an accept after the protocol has started will do nothing
        let action = posits0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));

        // start: on threshold amount accept, start the protocol
        posits0.propose(id, (), &participants);
        let action = posits0.act(id, Participant::from(1), threshold, &PositAction::Accept);
        assert!(matches!(action, PositInternalAction::None));
        let action = posits0.act(
            id,
            Participant::from(2),
            threshold,
            &PositAction::RejectWithReason(PositRejectReason::InvalidRequest),
        );
        assert!(matches!(action, PositInternalAction::StartProtocol(_, _)));

        // start: on threshold amount reject, abort the protocol
        posits0.propose(id, (), &participants);
        let action = posits0.act(
            id,
            Participant::from(1),
            threshold,
            &PositAction::RejectWithReason(PositRejectReason::InvalidRequest),
        );
        assert!(matches!(action, PositInternalAction::None));
        let action = posits0.act(
            id,
            Participant::from(2),
            threshold,
            &PositAction::RejectWithReason(PositRejectReason::InvalidRequest),
        );
        assert!(matches!(action, PositInternalAction::Abort));
    }

    #[test]
    fn test_posits_expiration() {
        let threshold = 2;
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
            Participant::from(3),
        ];
        let mut posits0 = Posits::<Id, ()>::new(Participant::from(0));

        // have proposer accept and participants 1 and 2 accept. participant 3 will neither accept or reject.
        let id101 = 101;
        posits0.propose(id101, (), &participants);
        for from in &participants[1..=2] {
            posits0.act(id101, *from, threshold, &PositAction::Accept);
        }

        // have proposer accept, and everyone else not reply at all.
        let id202 = 202;
        posits0.propose(id202, (), &participants);
        // expire the posit. Only the posit for id101 should return to start the protocol.
        let base_delay = Duration::from_secs(1);
        let deliberator_extra_delay = Duration::from_millis(200);
        std::thread::sleep(base_delay + deliberator_extra_delay + Duration::from_millis(100));
        // add a posit that will not expire yet
        posits0.propose(303, (), &participants);
        let mut actions = posits0.expire_and_start(threshold, base_delay, deliberator_extra_delay);
        actions.sort_by_key(|(id, _)| *id);
        assert_eq!(posits0.len(), 1);
        assert_eq!(actions.len(), 2);
        println!("actions: {actions:?}");
        assert!(matches!(
            actions[0],
            (
                101,
                PositInternalAction::StartProtocol(_, Positor::Proposer(_, _))
            ),
        ));
        assert!(matches!(actions[1], (202, PositInternalAction::Abort)));

        // the posit for id101 should have expired after not receiving a start action.
        let mut posits1 = Posits::<Id, ()>::new(Participant::from(1));
        posits1.act(
            id101,
            Participant::from(0),
            threshold,
            &PositAction::Propose,
        );

        std::thread::sleep(base_delay + deliberator_extra_delay + Duration::from_millis(100));
        let actions = posits1.expire_and_start(threshold, base_delay, deliberator_extra_delay);
        assert_eq!(actions.len(), 0);
        assert_eq!(posits1.len(), 0);
    }

    #[test]
    fn test_posit_barrier_keeps_first_vote() {
        let me = Participant::from(0);
        let participants = vec![
            me,
            Participant::from(1),
            Participant::from(2),
            Participant::from(3),
        ];
        let mut barrier = PositBarrier::new(me, &participants, 2);

        barrier.process_action(
            Participant::from(1),
            &PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating),
        );
        barrier.process_action(
            Participant::from(3),
            &PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating),
        );
        assert_eq!(barrier.state().rejected.len(), 2);

        // A participant has one vote. Contradictory or duplicate responses are
        // ignored once that participant has responded.
        barrier.process_action(Participant::from(3), &PositAction::Accept);
        assert!(!barrier.enough_accepts());
        barrier.process_action(
            Participant::from(1),
            &PositAction::RejectWithReason(PositRejectReason::MissingArtifact),
        );
        assert_eq!(barrier.state().rejected.len(), 2);
        assert_eq!(
            barrier.state().rejected[&Participant::from(1)],
            PositRejectReason::AlreadyGenerating
        );

        barrier.process_action(Participant::from(99), &PositAction::Accept);
        barrier.process_action(Participant::from(1), &PositAction::Propose);
    }

    #[test]
    fn test_posit_barrier_returns_enough_accepts_with_pending() {
        let me = Participant::from(0);
        let participants = vec![
            me,
            Participant::from(1),
            Participant::from(2),
            Participant::from(3),
        ];
        let mut barrier = PositBarrier::new(me, &participants, 2);
        barrier.process_action(Participant::from(1), &PositAction::Accept);

        let Some(PositBarrierResult::EnoughAccepts(state)) = barrier.terminal_result(true) else {
            panic!("expected enough accepts");
        };
        assert_eq!(state.accepted.len(), 2);
        assert!(state.rejected.is_empty());
        assert_eq!(state.pending.len(), 2);
    }

    #[test]
    fn test_posit_barrier_returns_too_many_rejects() {
        let me = Participant::from(0);
        let participants = vec![me, Participant::from(1), Participant::from(2)];
        let mut barrier = PositBarrier::new(me, &participants, 2);
        barrier.process_action(
            Participant::from(1),
            &PositAction::RejectWithReason(PositRejectReason::MissingArtifact),
        );
        barrier.process_action(
            Participant::from(2),
            &PositAction::RejectWithReason(PositRejectReason::AlreadyGenerating),
        );

        let Some(PositBarrierResult::TooManyRejects(state)) = barrier.terminal_result(false) else {
            panic!("expected too many rejects");
        };
        assert_eq!(state.accepted, HashSet::from([me]));
        assert_eq!(state.rejected.len(), 2);
        assert!(state.pending.is_empty());
    }

    #[test]
    fn test_posit_barrier_returns_timeout() {
        let me = Participant::from(0);
        let participants = vec![me, Participant::from(1)];
        let barrier = PositBarrier::new(me, &participants, 2);
        let PositBarrierResult::Timeout(state) = barrier.timeout() else {
            panic!("expected timeout");
        };
        assert_eq!(state.accepted, HashSet::from([me]));
        assert!(state.rejected.is_empty());
        assert_eq!(state.pending, HashSet::from([Participant::from(1)]));
    }
}
