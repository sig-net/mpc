use super::{Backlog, BacklogEntry, BacklogError};
use crate::sign_bidirectional::{BidirectionalProgress, PublishState, SignProgress, SignStatus};
use mpc_primitives::{BidirectionalTx, Chain, IndexedSignRequest, PublicKey, SignId, Signature};
use std::sync::Arc;

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
pub struct Final<P = Generating> {
    pub respond_request: Arc<IndexedSignRequest>,
    pub progress: P,
}

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

    /// Complete and remove this request from the backlog.
    pub async fn complete(self) -> Option<BacklogEntry> {
        self.backlog.remove(self.chain, &self.request.id).await
    }
}

// --- Single-phase Sign Transitions ---

impl SignEntry<Sign<Generating>> {
    pub fn new_sign(chain: Chain, request: Arc<IndexedSignRequest>, backlog: Backlog) -> Self {
        Self {
            chain,
            request,
            state: Sign(Generating),
            backlog,
        }
    }

    /// Advance from `Generating` to `Publishing`.
    pub async fn advance(
        self,
        publish: Arc<PublishState>,
    ) -> Result<SignEntry<Sign<Publishing>>, BacklogError> {
        self.backlog
            .publish(self.chain, &self.request.id, Arc::clone(&publish))
            .await?;
        Ok(self.transition(Sign(Publishing(publish))))
    }
}

impl SignEntry<Sign<Publishing>> {
    pub fn publish_state(&self) -> &Arc<PublishState> {
        &self.state.0 .0
    }

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
    }
}

// --- Bidirectional Transitions ---

impl SignEntry<Bidirectional<Initial<Generating>>> {
    pub fn new_bidirectional(
        chain: Chain,
        request: Arc<IndexedSignRequest>,
        backlog: Backlog,
    ) -> Self {
        Self {
            chain,
            request,
            state: Bidirectional(Initial(Generating)),
            backlog,
        }
    }

    /// Advance Phase 1 from `Generating` to `Publishing`.
    pub async fn advance(
        self,
        publish: Arc<PublishState>,
    ) -> Result<SignEntry<Bidirectional<Initial<Publishing>>>, BacklogError> {
        self.backlog
            .publish(self.chain, &self.request.id, Arc::clone(&publish))
            .await?;
        Ok(self.transition(Bidirectional(Initial(Publishing(publish)))))
    }
}

impl<P> SignEntry<Bidirectional<Initial<P>>> {
    /// Advance Phase 1 into destination-chain `Executing`.
    pub async fn advance_to_execution(
        self,
        tx: Arc<BidirectionalTx>,
    ) -> Result<SignEntry<Bidirectional<Executing>>, BacklogError> {
        self.backlog
            .advance(self.chain, self.request.id, Arc::clone(&tx))
            .await?;
        Ok(self.transition(Bidirectional(Executing(tx))))
    }
}

impl SignEntry<Bidirectional<Initial<Publishing>>> {
    pub fn publish_state(&self) -> &Arc<PublishState> {
        &self.state.0 .0 .0
    }

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
    }

    /// Advance Phase 1 into destination-chain `Executing`.
    pub async fn advance(
        self,
        tx: Arc<BidirectionalTx>,
    ) -> Result<SignEntry<Bidirectional<Executing>>, BacklogError> {
        self.advance_to_execution(tx).await
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
        self.backlog
            .respond(self.chain, &self.request.id, Arc::clone(&respond_request))
            .await?;
        Ok(self.transition(Bidirectional(Final {
            respond_request,
            progress: Generating,
        })))
    }
}

impl SignEntry<Bidirectional<Final<Generating>>> {
    pub fn respond_request(&self) -> &Arc<IndexedSignRequest> {
        &self.state.0.respond_request
    }

    /// Advance Phase 2 from `Generating` to `Publishing`.
    pub async fn advance(
        self,
        publish: Arc<PublishState>,
    ) -> Result<SignEntry<Bidirectional<Final<Publishing>>>, BacklogError> {
        self.backlog
            .publish(self.chain, &self.request.id, Arc::clone(&publish))
            .await?;
        Ok(self.map_state(|state| {
            Bidirectional(Final {
                respond_request: state.0.respond_request,
                progress: Publishing(publish),
            })
        }))
    }
}

impl SignEntry<Bidirectional<Final<Publishing>>> {
    pub fn respond_request(&self) -> &Arc<IndexedSignRequest> {
        &self.state.0.respond_request
    }

    pub fn publish_state(&self) -> &Arc<PublishState> {
        &self.state.0.progress.0
    }

    pub fn verify_signature(
        &self,
        root_public_key: PublicKey,
        signature: &Signature,
    ) -> anyhow::Result<()> {
        let active = self.respond_request();
        mpc_crypto::verify_signature(
            root_public_key,
            active.args.epsilon,
            active.args.payload,
            signature,
        )
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
                respond_request,
                progress: SignProgress::Generating,
            }) => Some(Bidirectional(Final {
                respond_request: Arc::clone(respond_request),
                progress: Generating,
            })),
            _ => None,
        }
    }
}

impl SignState for Bidirectional<Final<Publishing>> {
    fn try_from_status(status: &SignStatus) -> Option<Self> {
        match status {
            SignStatus::Bidirectional(BidirectionalProgress::Final {
                respond_request,
                progress: SignProgress::Publishing(publish),
            }) => Some(Bidirectional(Final {
                respond_request: Arc::clone(respond_request),
                progress: Publishing(Arc::clone(publish)),
            })),
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
            request: entry.request,
            state,
            backlog: self.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256};
    use cait_sith::protocol::Participant;
    use k256::{AffinePoint, Scalar};
    use mpc_primitives::{
        BidirectionalTx, BidirectionalTxId, RespondBidirectionalTx, SignArgs,
        SignBidirectionalEvent, SignId, SignKind, Signature,
    };

    fn test_sign_args(seed: u8) -> SignArgs {
        SignArgs {
            entropy: [seed; 32],
            epsilon: Scalar::from(seed as u64),
            payload: Scalar::from((seed + 1) as u64),
            path: "test".to_string(),
            key_version: 1,
        }
    }

    fn test_signature() -> Signature {
        Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0)
    }

    fn test_plain_request(id: SignId, chain: Chain) -> Arc<IndexedSignRequest> {
        Arc::new(IndexedSignRequest::new(
            id,
            test_sign_args(1),
            chain,
            100,
            SignKind::Sign,
        ))
    }

    fn test_bidi_request(id: SignId, chain: Chain) -> Arc<IndexedSignRequest> {
        Arc::new(IndexedSignRequest::new(
            id,
            test_sign_args(2),
            chain,
            100,
            SignKind::SignBidirectional(SignBidirectionalEvent {
                sender: Default::default(),
                serialized_transaction: vec![1, 2, 3],
                dest: "ethereum".to_string(),
                caip2_id: "eip155:1".to_string(),
                key_version: 1,
                deposit: 0,
                path: "test".to_string(),
                algo: "secp256k1".to_string(),
                params: "{}".to_string(),
                chain,
                chain_ctx: None,
                output_deserialization_schema: vec![],
                respond_serialization_schema: vec![],
            }),
        ))
    }

    fn test_publish_state() -> Arc<PublishState> {
        Arc::new(PublishState {
            signature: test_signature(),
            participants: vec![Participant::from(0u32), Participant::from(1u32)],
            is_proposer: true,
        })
    }

    fn test_bidirectional_tx(id: SignId, chain: Chain) -> Arc<BidirectionalTx> {
        Arc::new(BidirectionalTx {
            id: BidirectionalTxId(B256::from([7u8; 32]).0),
            sender: [0u8; 32],
            serialized_transaction: vec![1, 2, 3],
            source_chain: chain,
            target_chain: Chain::Ethereum,
            caip2_id: "eip155:1".to_string(),
            key_version: 1,
            deposit: 0,
            path: "test".to_string(),
            algo: "secp256k1".to_string(),
            dest: "ethereum".to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            request_id: id.request_id,
            from_address: **Address::ZERO,
            nonce: 0,
        })
    }

    #[tokio::test]
    async fn test_plain_sign_typestate_advance_and_complete() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([1u8; 32]);
        let req = test_plain_request(sign_id, Chain::Ethereum);

        backlog.insert(Arc::clone(&req)).await;

        let entry = backlog
            .get_by::<Sign<Generating>>(Chain::Ethereum, &sign_id)
            .await
            .expect("should find generating sign entry");

        // Verify that querying with the wrong state returns None
        assert!(backlog
            .get_by::<Sign<Publishing>>(Chain::Ethereum, &sign_id)
            .await
            .is_none());

        // advance to publishing
        let pub_entry = entry
            .advance(test_publish_state())
            .await
            .expect("should advance to publishing");

        assert_eq!(pub_entry.sign_id(), sign_id);
        assert_eq!(pub_entry.request().id, sign_id);

        // complete and remove
        let removed = pub_entry.complete().await;
        assert!(removed.is_some());
        assert!(backlog.get(Chain::Ethereum, &sign_id).await.is_none());
    }

    #[tokio::test]
    async fn test_bidirectional_typestate_full_lifecycle() {
        let backlog = Backlog::new();
        let sign_id = SignId::new([2u8; 32]);
        let req = test_bidi_request(sign_id, Chain::Solana);

        backlog.insert(Arc::clone(&req)).await;

        // 1. Initial Generating
        let bidi_entry = backlog
            .get_by::<Bidirectional<Initial<Generating>>>(Chain::Solana, &sign_id)
            .await
            .expect("should find bidi initial");

        // 2. Advance to Publishing
        let pub_entry = bidi_entry
            .advance(test_publish_state())
            .await
            .expect("should advance to publishing");

        // 3. Advance to Executing
        let tx = test_bidirectional_tx(sign_id, Chain::Solana);
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
        let response_request = Arc::new(IndexedSignRequest::respond_bidirectional(
            sign_id,
            test_sign_args(3),
            Chain::Solana,
            0,
            RespondBidirectionalTx {
                tx_id: tx.id,
                output: vec![9, 9],
                chain_ctx: None,
            },
        ));
        let final_entry = exec_entry
            .advance(Arc::clone(&response_request))
            .await
            .expect("should advance to final");
        assert_eq!(final_entry.request().id, sign_id);

        // Verify get_by can retrieve Final<Generating> state directly from backlog
        assert!(backlog
            .get_by::<Bidirectional<Final<Generating>>>(Chain::Solana, &sign_id)
            .await
            .is_some());

        // 5. Advance to Final Publishing
        let final_pub_entry = final_entry
            .advance(test_publish_state())
            .await
            .expect("should advance final to publishing");
        assert_eq!(final_pub_entry.respond_request().id, sign_id);

        // 6. Complete
        final_pub_entry.complete().await;
        assert!(backlog.get(Chain::Solana, &sign_id).await.is_none());
    }
}
