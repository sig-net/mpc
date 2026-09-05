use super::{Backlog, BacklogEntry, BacklogError};
use crate::respond_bidirectional::CompletedTx;
use crate::sign_bidirectional::{BidirectionalProgress, PublishState, SignProgress, SignStatus};
use anyhow::Context as _;
use cait_sith::protocol::Participant;
use cait_sith::FullSignature;
use k256::Secp256k1;
use mpc_crypto::{derive_key, reconstruct_signature};
use mpc_primitives::{
    BidirectionalTx, Chain, ExecutionOutcome, IndexedSignRequest, PublicKey, SignId, SignKind,
    Signature,
};
use std::sync::Arc;

/// Type alias for [`SignProgress`], indicating any progress state (generating or publishing).
pub type AnyProgress = SignProgress;

// --- Typestate Markers ---

/// Typestate marker for plain single-phase sign requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign<P>(pub P);

/// Typestate marker for two-phase bidirectional requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bidirectional<P>(pub P);

/// Typestate marker: request is awaiting or actively running Cait-Sith MPC signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generating;

/// Typestate marker: signature has been produced and is ready to publish / awaiting confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publishing(pub Arc<PublishState>);

/// Typestate marker: Phase 1 of bidirectional signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Initial<P = Generating>(pub P);

/// Typestate marker: Phase 1.5 awaiting destination-chain execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Executing(pub Arc<BidirectionalTx>);

/// Typestate marker: Phase 2 signing the final respond transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Final<P = Generating>(pub P);

// --- SignEntry Typestate Handle ---

/// A typed handle to an in-flight backlog request, parameterized by its lifecycle state.
///
/// Every transition consumes `self` and returns the next typestate via `.advance(...)`,
/// keeping the underlying `Backlog` storage in sync automatically without requiring
/// callers to pass raw `Backlog` references across handler functions.
#[derive(Debug, Clone)]
pub struct SignEntry<State = SignStatus> {
    pub(crate) chain: Chain,
    pub(crate) request: Arc<IndexedSignRequest>,
    pub(crate) state: State,
    pub(crate) backlog: Backlog,
}

impl<State> SignEntry<State> {
    pub fn chain(&self) -> Chain {
        self.chain
    }

    pub fn sign_id(&self) -> SignId {
        self.request.id
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.request.id.request_id
    }

    pub fn request(&self) -> &Arc<IndexedSignRequest> {
        &self.request
    }

    pub fn into_request(self) -> Arc<IndexedSignRequest> {
        self.request
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn backlog(&self) -> &Backlog {
        &self.backlog
    }

    fn map_state<Next>(self, f: impl FnOnce(State) -> Next) -> SignEntry<Next> {
        let SignEntry {
            chain,
            request,
            state,
            backlog,
        } = self;
        SignEntry {
            chain,
            request,
            state: f(state),
            backlog,
        }
    }

    fn transition<Next>(self, state: Next) -> SignEntry<Next> {
        self.map_state(|_| state)
    }

    async fn publishing(&self, publish: Arc<PublishState>) -> Result<(), BacklogError> {
        let mut pending = self.backlog.pending(&self.chain).write().await;
        let entry = pending
            .requests
            .get_mut(&self.request.id)
            .ok_or(BacklogError::NotFound {
                chain: self.chain,
                id: self.request.id,
            })?;
        match &mut entry.status {
            SignStatus::Sign(progress)
            | SignStatus::Bidirectional(BidirectionalProgress::Initial(progress))
            | SignStatus::Bidirectional(BidirectionalProgress::Final { progress, .. }) => {
                *progress = SignProgress::Publishing(publish);
            }
            SignStatus::Bidirectional(BidirectionalProgress::Executing(_)) => {}
        }
        Ok(())
    }

    async fn executing(&self, tx: Arc<BidirectionalTx>) -> Result<(), BacklogError> {
        let mut pending = self.backlog.pending(&self.chain).write().await;
        let entry = pending
            .requests
            .get_mut(&self.request.id)
            .ok_or(BacklogError::NotFound {
                chain: self.chain,
                id: self.request.id,
            })?;
        entry.status = SignStatus::Bidirectional(BidirectionalProgress::Executing(tx));
        Ok(())
    }

    async fn responding(
        &self,
        respond_request: Arc<IndexedSignRequest>,
    ) -> Result<(), BacklogError> {
        let mut pending = self.backlog.pending(&self.chain).write().await;
        let entry = pending
            .requests
            .get_mut(&self.request.id)
            .ok_or(BacklogError::NotFound {
                chain: self.chain,
                id: self.request.id,
            })?;
        entry.status = SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request,
            progress: SignProgress::Generating,
        });
        Ok(())
    }

    /// Complete and remove this request from the backlog.
    pub async fn complete(self) -> Option<BacklogEntry> {
        self.backlog.remove(self.chain, &self.request.id).await
    }

    /// Check that a respond event's signature is valid for this entry's active sign request.
    pub fn verify_signature(
        &self,
        root_public_key: PublicKey,
        signature: &Signature,
    ) -> anyhow::Result<()> {
        mpc_crypto::verify_signature(
            root_public_key,
            self.request.args.epsilon,
            self.request.args.payload,
            signature,
        )
        .with_context(|| {
            format!(
                "respond event carried invalid signature for sign id {:?}",
                self.sign_id()
            )
        })
    }
}

impl<State: PartialEq> PartialEq for SignEntry<State> {
    fn eq(&self, other: &Self) -> bool {
        self.chain == other.chain && self.request == other.request && self.state == other.state
    }
}

impl<State: Eq> Eq for SignEntry<State> {}

// --- General Transitions ---

impl SignEntry<Generating> {
    pub fn generating(request: Arc<IndexedSignRequest>, backlog: &Backlog) -> Self {
        Self {
            chain: request.chain,
            request,
            state: Generating,
            backlog: backlog.clone(),
        }
    }

    /// Advance from `Generating` to `Publishing`, reconstructing and validating the signature
    /// against the derived key.
    pub async fn advance(
        self,
        public_key: PublicKey,
        output: &FullSignature<Secp256k1>,
        participants: impl Into<Vec<Participant>>,
        is_proposer: bool,
    ) -> Result<SignEntry<Publishing>, BacklogError> {
        let expected_public_key = derive_key(public_key, self.request.args.epsilon);
        let signature = reconstruct_signature(
            &expected_public_key,
            &output.big_r,
            &output.s,
            self.request.args.payload,
        )
        .map_err(|_| BacklogError::InvalidSignature)?;

        let publish = Arc::new(PublishState {
            signature,
            participants: participants.into(),
            is_proposer,
        });
        self.publishing(Arc::clone(&publish)).await?;
        Ok(self.transition(Publishing(publish)))
    }
}

impl SignEntry<Publishing> {
    pub fn publish_state(&self) -> &Arc<PublishState> {
        &self.state.0
    }
}

// --- Single-phase Sign Transitions ---

impl From<SignEntry<Sign<Generating>>> for SignEntry<Generating> {
    fn from(entry: SignEntry<Sign<Generating>>) -> Self {
        entry.map_state(|_| Generating)
    }
}

impl From<SignEntry<Publishing>> for SignEntry<Sign<Publishing>> {
    fn from(entry: SignEntry<Publishing>) -> Self {
        entry.map_state(Sign)
    }
}

impl SignEntry<Sign<Generating>> {
    pub fn sign(request: Arc<IndexedSignRequest>, backlog: &Backlog) -> Self {
        Self {
            chain: request.chain,
            request,
            state: Sign(Generating),
            backlog: backlog.clone(),
        }
    }

    /// Advance from `Generating` to `Publishing`, reconstructing and validating the signature
    /// against the derived key.
    pub async fn advance(
        self,
        public_key: PublicKey,
        output: &FullSignature<Secp256k1>,
        participants: impl Into<Vec<Participant>>,
        is_proposer: bool,
    ) -> Result<SignEntry<Sign<Publishing>>, BacklogError> {
        SignEntry::<Generating>::from(self)
            .advance(public_key, output, participants, is_proposer)
            .await
            .map(Into::into)
    }
}

impl SignEntry<Sign<Publishing>> {
    pub fn publish_state(&self) -> &Arc<PublishState> {
        &self.state.0 .0
    }
}

// --- Bidirectional Transitions ---

impl From<SignEntry<Bidirectional<Initial<Generating>>>> for SignEntry<Generating> {
    fn from(entry: SignEntry<Bidirectional<Initial<Generating>>>) -> Self {
        entry.map_state(|_| Generating)
    }
}

impl From<SignEntry<Publishing>> for SignEntry<Bidirectional<Initial<Publishing>>> {
    fn from(entry: SignEntry<Publishing>) -> Self {
        entry.map_state(|p| Bidirectional(Initial(p)))
    }
}

impl SignEntry<Bidirectional<Initial<Generating>>> {
    pub fn bidirectional(request: Arc<IndexedSignRequest>, backlog: &Backlog) -> Self {
        Self {
            chain: request.chain,
            request,
            state: Bidirectional(Initial(Generating)),
            backlog: backlog.clone(),
        }
    }

    /// Advance Phase 1 from `Generating` to `Publishing`, reconstructing and validating the signature
    /// against the derived key.
    pub async fn advance(
        self,
        public_key: PublicKey,
        output: &FullSignature<Secp256k1>,
        participants: impl Into<Vec<Participant>>,
        is_proposer: bool,
    ) -> Result<SignEntry<Bidirectional<Initial<Publishing>>>, BacklogError> {
        SignEntry::<Generating>::from(self)
            .advance(public_key, output, participants, is_proposer)
            .await
            .map(Into::into)
    }
}

impl SignEntry<Bidirectional<Initial<Publishing>>> {
    pub fn publish_state(&self) -> &Arc<PublishState> {
        &self.state.0 .0 .0
    }

    /// Advance Phase 1 into destination-chain `Executing`.
    pub async fn advance(
        self,
        tx: Arc<BidirectionalTx>,
    ) -> Result<SignEntry<Bidirectional<Executing>>, BacklogError> {
        self.executing(Arc::clone(&tx)).await?;
        let entry = self.transition(Bidirectional(Executing(tx)));
        entry.watch_execution().await;
        Ok(entry)
    }
}

impl SignEntry<Bidirectional<Initial<AnyProgress>>> {
    /// Advance Phase 1 into destination-chain `Executing`.
    pub async fn advance(
        self,
        tx: Arc<BidirectionalTx>,
    ) -> Result<SignEntry<Bidirectional<Executing>>, BacklogError> {
        self.executing(Arc::clone(&tx)).await?;
        let entry = self.transition(Bidirectional(Executing(tx)));
        entry.watch_execution().await;
        Ok(entry)
    }
}

impl SignEntry<Bidirectional<Executing>> {
    pub fn execution_tx(&self) -> &Arc<BidirectionalTx> {
        &self.state.0 .0
    }

    /// Watch execution of this bidirectional transaction on its target chain.
    pub async fn watch_execution(&self) -> Option<(SignId, Arc<BidirectionalTx>)> {
        self.backlog.watch_execution(self).await
    }

    /// Advance destination-chain `Executing` into Phase 2 response signing based on
    /// the target-chain execution outcome.
    ///
    /// The response sign request is constructed directly from the entry's execution
    /// transaction and original sign request context, guaranteeing by construction
    /// that the sign ID, chain, and `RespondBidirectional` kind match.
    pub async fn advance(
        self,
        outcome: ExecutionOutcome,
    ) -> anyhow::Result<SignEntry<Bidirectional<Final<Generating>>>> {
        let chain_ctx = match &self.request.kind {
            SignKind::SignBidirectional(event) => event.chain_ctx.clone(),
            _ => None,
        };

        let completed_tx = CompletedTx::new(Arc::clone(self.execution_tx()));
        let sign_request = match outcome {
            ExecutionOutcome::Success { output } => completed_tx
                .create_sign_request_from_serialized_output(self.chain, output, chain_ctx)?,
            ExecutionOutcome::Failed => {
                completed_tx
                    .create_failed_sign_request(self.chain, chain_ctx)
                    .await?
            }
        };

        let respond_request = Arc::new(sign_request);
        self.responding(Arc::clone(&respond_request)).await?;
        Ok(SignEntry {
            chain: self.chain,
            request: respond_request,
            state: Bidirectional(Final(Generating)),
            backlog: self.backlog,
        })
    }
}

impl From<SignEntry<Bidirectional<Final<Generating>>>> for SignEntry<Generating> {
    fn from(entry: SignEntry<Bidirectional<Final<Generating>>>) -> Self {
        entry.map_state(|_| Generating)
    }
}

impl From<SignEntry<Publishing>> for SignEntry<Bidirectional<Final<Publishing>>> {
    fn from(entry: SignEntry<Publishing>) -> Self {
        entry.map_state(|p| Bidirectional(Final(p)))
    }
}

impl SignEntry<Bidirectional<Final<Generating>>> {
    /// Advance Phase 2 from `Generating` to `Publishing`, reconstructing and validating the signature
    /// against the derived key.
    pub async fn advance(
        self,
        public_key: PublicKey,
        output: &FullSignature<Secp256k1>,
        participants: impl Into<Vec<Participant>>,
        is_proposer: bool,
    ) -> Result<SignEntry<Bidirectional<Final<Publishing>>>, BacklogError> {
        SignEntry::<Generating>::from(self)
            .advance(public_key, output, participants, is_proposer)
            .await
            .map(Into::into)
    }
}

impl<P> SignEntry<Bidirectional<Final<P>>> {
    pub fn respond_request(&self) -> &Arc<IndexedSignRequest> {
        &self.request
    }
}

impl SignEntry<Bidirectional<Final<Publishing>>> {
    pub fn publish_state(&self) -> &Arc<PublishState> {
        &self.state.0 .0 .0
    }
}

// --- SignState Trait & Backlog Accessor ---

/// Trait for converting a runtime [`SignStatus`] into a typed [`SignEntry`] state.
pub trait SignState: Sized {
    fn try_from_status(status: &SignStatus) -> Option<Self>;
}

impl SignState for Sign<Generating> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Sign(SignProgress::Generating) => Some(Sign(Generating)),
            _ => None,
        }
    }
}

impl SignState for Sign<Publishing> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Sign(SignProgress::Publishing(publish)) => {
                Some(Sign(Publishing(Arc::clone(publish))))
            }
            _ => None,
        }
    }
}

impl SignState for Generating {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        if status.is_pending_generation() {
            Some(Generating)
        } else {
            None
        }
    }
}

impl SignState for Publishing {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        status.publish_state().map(|p| Publishing(Arc::clone(p)))
    }
}

impl SignState for Bidirectional<Initial<Generating>> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Generating)) => {
                Some(Bidirectional(Initial(Generating)))
            }
            _ => None,
        }
    }
}

impl SignState for Bidirectional<Initial<Publishing>> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Bidirectional(BidirectionalProgress::Initial(
                SignProgress::Publishing(publish),
            )) => Some(Bidirectional(Initial(Publishing(Arc::clone(publish))))),
            _ => None,
        }
    }
}

impl SignState for Bidirectional<Executing> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Bidirectional(BidirectionalProgress::Executing(tx)) => {
                Some(Bidirectional(Executing(Arc::clone(tx))))
            }
            _ => None,
        }
    }
}

impl SignState for Bidirectional<Final<Generating>> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                progress: SignProgress::Generating,
                ..
            }) => Some(Bidirectional(Final(Generating))),
            _ => None,
        }
    }
}

impl SignState for Bidirectional<Final<Publishing>> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                progress: SignProgress::Publishing(publish),
                ..
            }) => Some(Bidirectional(Final(Publishing(Arc::clone(publish))))),
            _ => None,
        }
    }
}

impl SignState for Sign<AnyProgress> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Sign(progress) => Some(Sign(progress.clone())),
            _ => None,
        }
    }
}

impl SignState for Bidirectional<Initial<AnyProgress>> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Bidirectional(BidirectionalProgress::Initial(progress)) => {
                Some(Bidirectional(Initial(progress.clone())))
            }
            _ => None,
        }
    }
}

impl SignState for Bidirectional<Final<AnyProgress>> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Bidirectional(BidirectionalProgress::Final { progress, .. }) => {
                Some(Bidirectional(Final(progress.clone())))
            }
            _ => None,
        }
    }
}

impl SignState for SignStatus {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        Some(status.clone())
    }
}

impl SignEntry<SignStatus> {
    /// Return a reference to the entry's [`SignStatus`].
    pub fn status(&self) -> &SignStatus {
        &self.state
    }

    /// Return the execution transaction if this entry is in the executing state.
    pub fn execution_tx(&self) -> Option<&Arc<BidirectionalTx>> {
        self.state.execution_tx()
    }

    /// Try to cast a borrowed dynamic entry into a specific typestate.
    pub fn cast<State: SignState>(&self) -> Option<SignEntry<State>> {
        let state = State::try_from_status(&self.state)?;
        Some(SignEntry {
            chain: self.chain,
            request: Arc::clone(&self.request),
            state,
            backlog: self.backlog.clone(),
        })
    }

    /// Consume and convert this dynamic entry into a specific typestate.
    pub fn try_into<State: SignState>(self) -> Result<SignEntry<State>, Self> {
        if let Some(state) = State::try_from_status(&self.state) {
            Ok(SignEntry {
                chain: self.chain,
                request: self.request,
                state,
                backlog: self.backlog,
            })
        } else {
            Err(self)
        }
    }

    /// Check if this dynamic entry matches a specific typestate without cloning.
    pub fn is<State: SignState>(&self) -> bool {
        State::try_from_status(&self.state).is_some()
    }
}

impl Backlog {
    /// Retrieve an in-flight entry matching the requested typestate `State`.
    pub async fn get_by<State: SignState>(
        &self,
        chain: Chain,
        id: &SignId,
    ) -> Option<SignEntry<State>> {
        self.get(chain, id).await?.try_into().ok()
    }

    /// Insert a single-phase sign request into the backlog and return its initial [`SignEntry`].
    pub async fn insert_sign(
        &self,
        request: Arc<IndexedSignRequest>,
    ) -> SignEntry<Sign<Generating>> {
        self.insert(Arc::clone(&request)).await;
        SignEntry::sign(request, self)
    }

    /// Insert a two-phase bidirectional sign request into the backlog and return its initial [`SignEntry`].
    pub async fn insert_bidirectional(
        &self,
        request: Arc<IndexedSignRequest>,
    ) -> SignEntry<Bidirectional<Initial<Generating>>> {
        self.insert(Arc::clone(&request)).await;
        SignEntry::bidirectional(request, self)
    }
}
