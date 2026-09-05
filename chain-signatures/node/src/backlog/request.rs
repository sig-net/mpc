use super::{Backlog, BacklogEntry, BacklogError};
use crate::sign_bidirectional::{BidirectionalProgress, PublishState, SignProgress, SignStatus};
use anyhow::Context as _;
use cait_sith::protocol::Participant;
use cait_sith::FullSignature;
use k256::Secp256k1;
use mpc_crypto::{derive_key, reconstruct_signature};
use mpc_primitives::{BidirectionalTx, Chain, IndexedSignRequest, PublicKey, SignId, Signature};
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
pub struct SignEntry<State> {
    chain: Chain,
    request: Arc<IndexedSignRequest>,
    state: State,
    backlog: Backlog,
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
        entry.publish(publish)
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
        entry.advance(Arc::clone(&tx))?;
        let target_chain = tx.target_chain;
        drop(pending);
        self.backlog
            .watch_execution(target_chain, self.request.id, tx)
            .await;
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
        entry.respond(respond_request)?;
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
        Ok(self.transition(Bidirectional(Executing(tx))))
    }
}

impl SignEntry<Bidirectional<Initial<AnyProgress>>> {
    /// Advance Phase 1 into destination-chain `Executing`.
    pub async fn advance(
        self,
        tx: Arc<BidirectionalTx>,
    ) -> Result<SignEntry<Bidirectional<Executing>>, BacklogError> {
        self.executing(Arc::clone(&tx)).await?;
        Ok(self.transition(Bidirectional(Executing(tx))))
    }
}

impl SignEntry<Bidirectional<Executing>> {
    pub fn execution_tx(&self) -> &Arc<BidirectionalTx> {
        &self.state.0 .0
    }

    /// Advance destination-chain `Executing` into Phase 2 response signing.
    pub async fn advance(
        self,
        respond_request: Arc<IndexedSignRequest>,
    ) -> Result<SignEntry<Bidirectional<Final<Generating>>>, BacklogError> {
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

impl Backlog {
    /// Retrieve an in-flight entry matching the requested typestate `State`.
    pub async fn get_by<State: SignState>(
        &self,
        chain: Chain,
        id: &SignId,
    ) -> Option<SignEntry<State>> {
        let entry = self.get(chain, id).await?;
        let state = State::try_from_status(&entry.status)?;
        Some(SignEntry {
            chain,
            request: Arc::clone(entry.request()),
            state,
            backlog: self.clone(),
        })
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

    /// Insert any sign request into the backlog and return its handle in [`Generating`] state.
    pub async fn insert_generating(
        &self,
        request: Arc<IndexedSignRequest>,
    ) -> SignEntry<Generating> {
        self.insert(Arc::clone(&request)).await;
        SignEntry::generating(request, self)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AnyProgress, Bidirectional, Executing, Final, Generating, Initial, Publishing, Sign,
    };
    use crate::backlog::mock::{
        mock_bidi_request, mock_bidi_response, mock_bidirectional_tx, mock_participants,
        mock_sign_request, mock_signature_output, BacklogTestExt,
    };
    use crate::backlog::{Backlog, BacklogError};
    use mpc_primitives::{Chain, SignId};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_plain_sign_typestate_advance_all_the_way_till_completion() {
        let backlog = Backlog::new();
        let sign_id = SignId::from_u8(1);
        let req = mock_sign_request(sign_id, Chain::Ethereum);

        // 1. Initial entry via Backlog::insert_sign
        let entry = backlog.insert_sign(Arc::clone(&req)).await;
        assert_eq!(entry.sign_id(), sign_id);
        assert_eq!(entry.state(), &Sign(Generating));

        // Verify that querying with the wrong state returns None
        assert!(backlog
            .get_by::<Sign<Publishing>>(Chain::Ethereum, &sign_id)
            .await
            .is_none());

        // 2. Advance to publishing
        let (pk, output) = mock_signature_output(&req.args);
        let pub_entry = entry
            .advance(pk, &output, mock_participants(), true)
            .await
            .expect("advance call should succeed");

        assert_eq!(pub_entry.sign_id(), sign_id);
        assert_eq!(pub_entry.request().id, sign_id);

        // 3. Verify signature
        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let valid_sig = mpc_crypto::generate_signature(&root_sk, &req.args);
        pub_entry
            .verify_signature(root_sk.public_key().into(), &valid_sig)
            .expect("signature should verify");

        // 4. Complete removing from backlog
        let removed = pub_entry.complete().await;
        assert!(removed.is_some());
        assert!(backlog.get(Chain::Ethereum, &sign_id).await.is_none());
    }

    #[tokio::test]
    async fn test_plain_sign_entry_chained_advance() {
        let backlog = Backlog::new();
        let sign_id = SignId::from_u8(11);
        let req = mock_sign_request(sign_id, Chain::Ethereum);

        // Chained advance from sign all the way till completion
        let (pk, output) = mock_signature_output(&req.args);
        let completed = backlog
            .insert_sign(req)
            .await
            .advance(pk, &output, mock_participants(), true)
            .await
            .expect("advance call should succeed")
            .complete()
            .await;

        assert!(completed.is_some());
        assert!(backlog.get(Chain::Ethereum, &sign_id).await.is_none());
    }

    #[tokio::test]
    async fn test_bidirectional_typestate_full_lifecycle() {
        let backlog = Backlog::new();
        let sign_id = SignId::from_u8(2);
        let req = mock_bidi_request(sign_id, Chain::Solana);

        // 1. Initial Generating via insert_bidirectional
        let bidi_entry = backlog.insert_bidirectional(Arc::clone(&req)).await;
        assert_eq!(bidi_entry.sign_id(), sign_id);
        assert_eq!(bidi_entry.state(), &Bidirectional(Initial(Generating)));

        // 2. Advance to Publishing
        let (pk1, output1) = mock_signature_output(&req.args);
        let pub_entry = bidi_entry
            .advance(pk1, &output1, mock_participants(), true)
            .await
            .expect("advance call should succeed");

        // Verify phase 1 signature
        let root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let sig1 = mpc_crypto::generate_signature(&root_sk, &req.args);
        pub_entry
            .verify_signature(root_sk.public_key().into(), &sig1)
            .expect("sig1 should verify");

        // 3. Advance to Executing
        let tx = Arc::new(mock_bidirectional_tx(sign_id, Chain::Solana));
        let exec_entry = pub_entry
            .advance(Arc::clone(&tx))
            .await
            .expect("should advance to executing");
        assert_eq!(exec_entry.execution_tx().id, tx.id);

        // Verify get_by can retrieve Executing state directly from backlog
        assert!(backlog
            .get_by::<Bidirectional<Executing>>(Chain::Solana, &sign_id)
            .await
            .is_some());
        assert!(backlog
            .get_by::<Bidirectional<Initial<Generating>>>(Chain::Solana, &sign_id)
            .await
            .is_none());

        // 4. Advance to Final Generating
        let response_request = mock_bidi_response(&tx);
        let final_entry = exec_entry
            .advance(Arc::clone(&response_request))
            .await
            .expect("should advance to final");
        assert_eq!(final_entry.request().id, sign_id);
        assert_eq!(
            final_entry.request().args.payload,
            response_request.args.payload
        );

        // Verify get_by can retrieve Final<Generating> state directly from backlog
        assert!(backlog
            .get_by::<Bidirectional<Final<Generating>>>(Chain::Solana, &sign_id)
            .await
            .is_some());

        // 5. Advance to Final Publishing
        let (pk2, output2) = mock_signature_output(&response_request.args);
        let final_pub_entry = final_entry
            .advance(pk2, &output2, mock_participants(), true)
            .await
            .expect("advance call should succeed");
        assert_eq!(final_pub_entry.respond_request().id, sign_id);

        // Verify phase 2 signature against response_request
        let sig2 = mpc_crypto::generate_signature(&root_sk, &response_request.args);
        final_pub_entry
            .verify_signature(root_sk.public_key().into(), &sig2)
            .expect("sig2 should verify");

        // 6. Complete removing from backlog
        let completed = final_pub_entry.complete().await;
        assert!(completed.is_some());
        assert!(backlog.get(Chain::Solana, &sign_id).await.is_none());
    }

    #[tokio::test]
    async fn test_bidirectional_entry_chained_advances() {
        let backlog = Backlog::new();
        let sign_id = SignId::from_u8(22);
        let req = mock_bidi_request(sign_id, Chain::Solana);
        let tx = Arc::new(mock_bidirectional_tx(sign_id, Chain::Solana));
        let response_request = mock_bidi_response(&tx);

        // Start from initial entry, and keep calling advance all the way till completion!
        let (pk1, output1) = mock_signature_output(&req.args);
        let (pk2, output2) = mock_signature_output(&response_request.args);
        let completed = backlog
            .insert_bidirectional(req)
            .await
            .advance(pk1, &output1, mock_participants(), true)
            .await
            .expect("advance call should succeed")
            .advance(tx)
            .await
            .expect("advance to executing")
            .advance(response_request)
            .await
            .expect("advance to final generating")
            .advance(pk2, &output2, mock_participants(), true)
            .await
            .expect("advance call should succeed")
            .complete()
            .await;

        assert!(completed.is_some());
        assert!(backlog.get(Chain::Solana, &sign_id).await.is_none());
    }

    #[tokio::test]
    async fn test_any_progress_completion() {
        let backlog = Backlog::new();
        let sign_id = SignId::from_u8(33);

        let entry = backlog.insert_mock_sign(sign_id, Chain::Ethereum).await;
        let (pk, output) = mock_signature_output(&entry.request().args);
        let _ = entry
            .advance(pk, &output, mock_participants(), true)
            .await
            .expect("advance call should succeed");

        // Query with wildcard AnyProgress typestate
        let entry = backlog
            .get_by::<Sign<AnyProgress>>(Chain::Ethereum, &sign_id)
            .await
            .expect("should match AnyProgress");

        // Complete removing from backlog
        let completed = entry.complete().await;
        assert!(completed.is_some());
        assert!(backlog.get(Chain::Ethereum, &sign_id).await.is_none());
    }

    #[tokio::test]
    async fn test_advance_invalid_signature_error() {
        let backlog = Backlog::new();
        let sign_id = SignId::from_u8(99);
        let req = mock_sign_request(sign_id, Chain::Ethereum);
        let entry = backlog.insert_sign(req).await;

        let wrong_root_sk = k256::SecretKey::random(&mut rand::thread_rng());
        let wrong_pk = wrong_root_sk.public_key().into();
        let dummy_output = cait_sith::FullSignature {
            big_r: k256::AffinePoint::GENERATOR,
            s: k256::Scalar::ONE,
        };

        let result = entry
            .advance(wrong_pk, &dummy_output, mock_participants(), true)
            .await;
        assert_eq!(result.unwrap_err(), BacklogError::InvalidSignature);
    }
}
