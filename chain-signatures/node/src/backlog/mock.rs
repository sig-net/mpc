use super::{Backlog, BacklogEntry, Bidirectional, Generating, Initial, Sign, SignEntry};
use crate::sign_bidirectional::{BidirectionalProgress, PublishState, SignProgress, SignStatus};
use cait_sith::protocol::Participant;
use k256::{AffinePoint, Scalar};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, IndexedSignRequest, RespondBidirectionalTx,
    SignArgs, SignBidirectionalEvent, SignId, SignKind, Signature,
};
use std::sync::Arc;

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::backlog::Backlog {}
}

/// Sealed test extension trait providing ergonomic helpers on [`Backlog`] for tests.
#[allow(async_fn_in_trait)]
pub trait BacklogTestExt: sealed::Sealed {
    async fn insert_mock_sign(&self, id: SignId, chain: Chain) -> SignEntry<Sign<Generating>>;

    async fn insert_mock_bidirectional(
        &self,
        id: SignId,
        chain: Chain,
    ) -> SignEntry<Bidirectional<Initial<Generating>>>;
}

impl BacklogTestExt for Backlog {
    async fn insert_mock_sign(&self, id: SignId, chain: Chain) -> SignEntry<Sign<Generating>> {
        self.insert_sign(mock_sign_request(id, chain)).await
    }

    async fn insert_mock_bidirectional(
        &self,
        id: SignId,
        chain: Chain,
    ) -> SignEntry<Bidirectional<Initial<Generating>>> {
        self.insert_bidirectional(mock_bidi_request(id, chain))
            .await
    }
}

/// Create a mock signature for tests.
pub fn mock_signature() -> Signature {
    Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0)
}

/// Create a mock publish state for tests.
pub fn mock_publish_state(is_proposer: bool) -> Arc<PublishState> {
    Arc::new(PublishState {
        signature: mock_signature(),
        participants: vec![Participant::from(0u32), Participant::from(1u32)],
        is_proposer,
    })
}

/// Helper to construct a pending execution status for a bidirectional tx.
pub fn pending_execution_status(tx: &BidirectionalTx) -> SignStatus {
    SignStatus::Bidirectional(BidirectionalProgress::Executing(Arc::new(tx.clone())))
}

/// Helper to construct an initial generating status for bidirectional requests.
pub fn bidi_initial_status() -> SignStatus {
    SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Generating))
}

/// Create a mock single-phase sign request for tests.
pub fn mock_sign_request(id: SignId, chain: Chain) -> Arc<IndexedSignRequest> {
    Arc::new(IndexedSignRequest::new(
        id,
        SignArgs {
            entropy: id.request_id,
            epsilon: k256::Scalar::from(1u64),
            payload: k256::Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        },
        chain,
        0,
        SignKind::Sign,
    ))
}

/// Create a mock bidirectional sign request for tests.
pub fn mock_bidi_request(id: SignId, chain: Chain) -> Arc<IndexedSignRequest> {
    let target_chain = if chain == Chain::Ethereum {
        Chain::Solana
    } else {
        Chain::Ethereum
    };
    Arc::new(IndexedSignRequest::sign_bidirectional(
        id,
        SignArgs {
            entropy: id.request_id,
            epsilon: k256::Scalar::from(1u64),
            payload: k256::Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        },
        chain,
        0,
        SignBidirectionalEvent {
            sender: Default::default(),
            serialized_transaction: vec![1, 2, 3],
            dest: "test_dest".to_string(),
            caip2_id: target_chain.caip2_chain_id().to_string(),
            key_version: 1,
            deposit: 0,
            path: "test".to_string(),
            algo: "ECDSA".to_string(),
            params: "{}".to_string(),
            chain,
            chain_ctx: None,
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        },
    ))
}

/// Create a mock bidirectional transaction for tests.
pub fn mock_bidirectional_tx(id: SignId, source_chain: Chain) -> BidirectionalTx {
    let target_chain = if source_chain == Chain::Ethereum {
        Chain::Solana
    } else {
        Chain::Ethereum
    };
    BidirectionalTx {
        id: BidirectionalTxId(id.request_id),
        sender: [0u8; 32],
        serialized_transaction: vec![1, 2, 3],
        source_chain,
        target_chain,
        caip2_id: target_chain.caip2_chain_id().to_string(),
        key_version: 1,
        deposit: 0,
        path: "test".to_string(),
        algo: "ECDSA".to_string(),
        dest: "test_dest".to_string(),
        params: "{}".to_string(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: br#"[{"name":"output","type":"bool"}]"#.to_vec(),
        request_id: id.request_id,
        from_address: [0u8; 20],
        nonce: 0,
    }
}

/// Create a mock bidirectional transaction from a u8 seed without Arc wrapping.
pub fn mock_tx(id: u8) -> BidirectionalTx {
    mock_bidirectional_tx(SignId::from_u8(id), Chain::Solana)
}

/// Create a mock bidirectional final response request.
pub fn mock_bidi_response_request(
    sign_id: SignId,
    tx_id: BidirectionalTxId,
    chain: Chain,
) -> Arc<IndexedSignRequest> {
    Arc::new(IndexedSignRequest::respond_bidirectional(
        sign_id,
        SignArgs {
            entropy: sign_id.request_id,
            epsilon: k256::Scalar::from(1u64),
            payload: k256::Scalar::from(2u64),
            path: "test".to_string(),
            key_version: 1,
        },
        chain,
        0,
        RespondBidirectionalTx {
            tx_id,
            output: vec![],
            chain_ctx: None,
        },
    ))
}

/// Helper to create a backlog entry with an arbitrary status for bidirectional requests.
pub fn mock_execution_entry(
    tx: &BidirectionalTx,
    chain: Chain,
    status: SignStatus,
) -> BacklogEntry {
    mock_execution_entry_with_timestamp(tx, chain, status, 0)
}

/// Helper to create a backlog entry with a specific timestamp for bidirectional requests.
pub fn mock_execution_entry_with_timestamp(
    tx: &BidirectionalTx,
    chain: Chain,
    status: SignStatus,
    unix_timestamp_indexed: u64,
) -> BacklogEntry {
    let request = if unix_timestamp_indexed == 0 {
        mock_bidi_request(tx.sign_id(), chain)
    } else {
        let mut req = (*mock_bidi_request(tx.sign_id(), chain)).clone();
        req.unix_timestamp_indexed = unix_timestamp_indexed;
        Arc::new(req)
    };

    match &status {
        SignStatus::Bidirectional(BidirectionalProgress::Executing(tx)) => {
            BacklogEntry::pending_execution(request, Arc::clone(tx))
        }
        _ => BacklogEntry::with_status(request, status),
    }
}
