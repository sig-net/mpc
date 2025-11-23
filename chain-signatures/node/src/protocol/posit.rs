use cait_sith::protocol::Participant;
use serde::{Deserialize, Serialize};

use std::collections::HashSet;
use std::time::Duration;

pub type ProposerId = Participant;

#[derive(Debug)]
pub enum Positor<T> {
    /// Proposer holds the proposer id and a PositCounter that contains both the participant
    /// vote state and the store associated with the protocol.
    Proposer(ProposerId, PositCounter<T>),
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

    /// Process incoming posit messages for this Positor instance.
    ///
    /// - For `Proposer(_, counter)` this behaves like `proposer_collect`: it will
    ///   process Accept/Reject actions, and when enough accepts are present (or on
    ///   timeout with enough accepts), it will call `send_start` with the selected participant
    ///   list and return it. Returns `None` on abort or insufficient accepts.
    /// - For `Deliberator(proposer)` this behaves like `deliberator_wait_for_start`: it waits
    ///   for a `Start` action from the expected proposer and returns its participant list.
    pub async fn process<TMsg, ExtractFn, SendFn, SendFut, FetchFn, FetchFut>(
        self,
        threshold: usize,
        timeout: Duration,
        task_rx: &mut mpsc::Receiver<TMsg>,
        extract_msg: ExtractFn,
        send_start: SendFn,
        fetch_store: FetchFn,
    ) -> Option<(Vec<Participant>, T)>
    where
        ExtractFn: FnMut(&TMsg) -> Option<(Participant, PositAction)>,
        SendFn: FnMut(&Vec<Participant>) -> SendFut,
        SendFut: Future<Output = ()>,
        FetchFn: FnOnce() -> FetchFut,
        FetchFut: Future<Output = Option<T>>,
    {
        match self {
            Positor::Proposer(_, mut counter) => {
                // Reuse proposer_collect logic
                // When proposer_collect obtains participants, it's responsible for
                // broadcasting `Start` via send_start closure, which caller can
                // implement to also send PositMessage Start to peers.
                // run the proposer collect using a mutable reference to the
                // PositCounter. If the proposer_collect returns a participant
                // list (Some), attempt to take the stored value out of the
                // counter and return it as part of the result. For deliberator
                // path, the store will be None.
                let participants = proposer_collect(
                    &mut counter,
                    threshold,
                    timeout,
                    task_rx,
                    extract_msg,
                    send_start,
                )
                .await?;
                Some((participants, counter.store))
            }
            Positor::Deliberator(expected_proposer) => {
                // Deliberator ignores any action except Start from expected proposer
                // Reuse deliberator_wait_for_start helper with an extractor
                // For deliberator we wait for Start and then try to fetch the
                // store via the provided async fetch_store closure. If the
                // fetch returns None, we abort and return None.
                let participants =
                    deliberator_wait_for_start(task_rx, expected_proposer, timeout, extract_msg)
                        .await?;

                let store = fetch_store().await?;
                Some((participants, store))
            }
        }
    }
}

/// All actions that can be taken when a new posit is introduced for a protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PositAction {
    Propose,
    Start(Vec<Participant>),
    Accept,
    // TODO: Reject can also have a reason
    Reject,
}

impl PositAction {
    pub fn is_accept(&self) -> bool {
        matches!(self, PositAction::Accept)
    }
}

/// A counter for a posit. This is used to track the participants that have
/// accepted the posit alongside storing an intermediary state for the protocol
/// that the proposer needs to keep track of.
#[derive(Debug)]
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

    /// Create a new posit counter with a provided store value.
    pub fn new(me: Participant, participants: &[Participant], store: T) -> Self {
        let mut accepts = HashSet::new();
        accepts.insert(me);
        Self {
            participants: participants.iter().copied().collect(),
            accepts,
            rejects: HashSet::new(),
            store,
        }
    }

    /// Process an Accept/Reject message from `from`. Returns true if the action was a
    /// valid accept/reject from a participant in this counter, false otherwise.
    pub fn process_action(&mut self, from: Participant, action: &PositAction) -> bool {
        if !self.participants.contains(&from) {
            return false;
        }
        match action {
            PositAction::Accept => {
                self.accepts.insert(from);
            }
            PositAction::Reject => {
                self.rejects.insert(from);
            }
            _ => return false,
        }
        true
    }

    /// Return a reference to the accepts set.
    pub fn accepts_set(&self) -> &HashSet<Participant> {
        &self.accepts
    }


    // no `take_store` required - the counter is consumed via `into_store`
}

// Global `Posits` collection removed: posits are now handled inside per-id tasks and
// any logic previously implemented by `Posits` lived only in tests. Keeping posits
// globally no longer matches the new per-id model, so the type and its tests were removed.

// SinglePositCounter removed — use PositCounter<()> for single-task counters.

use std::future::Future;
use tokio::sync::mpsc;

/// Helper for proposer-side posit handling. This encapsulates the common loop used across
/// presignature/signature/triple tasks: process incoming posit messages, update the
/// counter, abort on enough rejects, and once all votes are in (or on timeout with enough
/// accepts) broadcast Start to the selected participants using the provided send_start
/// async closure.
pub async fn proposer_collect<S, TMsg, ExtractFn, SendFn, SendFut>(
    counter: &mut PositCounter<S>,
    threshold: usize,
    timeout: Duration,
    task_rx: &mut mpsc::Receiver<TMsg>,
    mut extract_msg: ExtractFn,
    mut send_start: SendFn,
) -> Option<Vec<Participant>>
where
    ExtractFn: FnMut(&TMsg) -> Option<(Participant, PositAction)>,
    SendFn: FnMut(&Vec<Participant>) -> SendFut,
    SendFut: Future<Output = ()>,
{
    let posit_deadline = tokio::time::sleep(timeout);
    tokio::pin!(posit_deadline);

    loop {
        tokio::select! {
            Some(task_msg) = task_rx.recv() => {
                if let Some((from, action)) = extract_msg(&task_msg) {
                    if !counter.process_action(from, &action) { continue; }

                    if counter.enough_rejects(threshold) {
                        return None;
                    }

                    if counter.meets_totality() {
                        let participants = counter.accepts_set().iter().copied().collect::<Vec<_>>();
                        if participants.len() < threshold {
                            return None;
                        }

                        // broadcast Start to the selected participants
                        send_start(&participants).await;
                        return Some(participants);
                    }
                }
            }
            _ = &mut posit_deadline => {
                if counter.enough_accepts(threshold) {
                    let participants = counter.accepts_set().iter().copied().collect::<Vec<_>>();
                    if participants.len() < threshold {
                        return None;
                    }

                    send_start(&participants).await;
                    return Some(participants);
                } else {
                    return None;
                }
            }
        }
    }
}

/// Helper for deliberator-side posit handling. Waits for a Start message from the
/// expected proposer and returns the participants vector, or None on timeout.
pub async fn deliberator_wait_for_start<TMsg, ExtractFn>(
    task_rx: &mut mpsc::Receiver<TMsg>,
    expected_proposer: Participant,
    timeout: Duration,
    mut extract_msg: ExtractFn,
) -> Option<Vec<Participant>>
where
    ExtractFn: FnMut(&TMsg) -> Option<(Participant, PositAction)>,
{
    let start_deadline = tokio::time::sleep(timeout);
    tokio::pin!(start_deadline);

    loop {
        tokio::select! {
            Some(task_msg) = task_rx.recv() => {
                if let Some((from, action)) = extract_msg(&task_msg) {
                    if let PositAction::Start(participants) = action {
                        if from != expected_proposer {
                            continue;
                        }
                        return Some(participants.clone());
                    }
                }
            }
            _ = &mut start_deadline => {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cait_sith::protocol::Participant;

    // previously used by Posits tests; no longer needed now that Posits is removed

    #[test]
    fn test_single_posit_counter_basic() {
        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
        ];

        let mut counter = PositCounter::new(Participant::from(0), &participants, ());

        // initial state: me has accepted
        assert!(counter.accepts_set().contains(&Participant::from(0)));
        assert!(!counter.meets_totality());

        // accept from participant 1 -> should record and still not meet totality
        assert!(counter.process_action(Participant::from(1), &PositAction::Accept));
        assert!(counter.accepts_set().contains(&Participant::from(1)));
        assert!(counter.enough_accepts(2));

        // reject from participant 2 -> should now meet totality
        assert!(counter.process_action(Participant::from(2), &PositAction::Reject));
        assert!(counter.meets_totality());

        // additional calls from non-participants should be ignored
        assert!(!counter.process_action(Participant::from(99), &PositAction::Accept));
        // actions other than accept/reject return false
        assert!(!counter.process_action(Participant::from(1), &PositAction::Propose));
    }

    #[tokio::test]
    async fn test_proposer_collect() {
        use std::sync::{Arc, Mutex};
        use tokio::sync::mpsc;

        let participants = vec![
            Participant::from(0),
            Participant::from(1),
            Participant::from(2),
        ];
        let mut counter = PositCounter::new(Participant::from(0), &participants, ());

        let (tx, rx) = mpsc::channel::<(Participant, PositAction)>(8);
        let extract = |m: &(Participant, PositAction)| Some((m.0, m.1.clone()));

        let seen = Arc::new(Mutex::new(Vec::<Vec<Participant>>::new()));
        let seen_clone = seen.clone();

        let send_start = move |participants: &Vec<Participant>| {
            let participants = participants.clone();
            let seen_clone = seen_clone.clone();
            async move {
                seen_clone.lock().unwrap().push(participants);
            }
        };

        // drive the proposer logic in the background
        let mut receiver = rx;
        let join = tokio::spawn(async move {
            crate::protocol::posit::proposer_collect(
                &mut counter,
                2,
                Duration::from_secs(1),
                &mut receiver,
                extract,
                send_start,
            )
            .await
        });

        // send accept from participant 1 and reject from 2
        tx.send((Participant::from(1), PositAction::Accept))
            .await
            .unwrap();
        tx.send((Participant::from(2), PositAction::Reject))
            .await
            .unwrap();

        let res = join.await.unwrap();
        assert!(res.is_some());
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
    }

    #[tokio::test]
    async fn test_deliberator_wait_for_start() {
        use tokio::sync::mpsc;

        let (tx, rx) = mpsc::channel::<(Participant, PositAction)>(8);
        let extract = |m: &(Participant, PositAction)| Some((m.0, m.1.clone()));

        let mut receiver = rx;
        let wait = tokio::spawn(async move {
            crate::protocol::posit::deliberator_wait_for_start(
                &mut receiver,
                Participant::from(5),
                Duration::from_secs(1),
                extract,
            )
            .await
        });

        // send wrong proposer - should be ignored
        tx.send((
            Participant::from(1),
            PositAction::Start(vec![Participant::from(1)]),
        ))
        .await
        .unwrap();
        // now send correct proposer
        tx.send((
            Participant::from(5),
            PositAction::Start(vec![Participant::from(5)]),
        ))
        .await
        .unwrap();

        let res = wait.await.unwrap();
        assert!(res.is_some());
    }
}
