use super::{Backlog, Bidirectional, Generating, Initial, Sign, SignEntry};
use mpc_primitives::{
    Chain, IndexedSignRequest, SignArgs, SignBidirectionalEvent, SignId, SignKind,
};
use std::sync::Arc;

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::backlog::Backlog {}
}

/// Sealed test extension trait providing ergonomic helpers on [`Backlog`] for tests.
#[allow(async_fn_in_trait)]
pub trait BacklogTestExt: sealed::Sealed {
    async fn insert_test_sign(&self, id: SignId, chain: Chain) -> SignEntry<Sign<Generating>>;

    async fn insert_test_bidirectional(
        &self,
        id: SignId,
        chain: Chain,
    ) -> SignEntry<Bidirectional<Initial<Generating>>>;
}

impl BacklogTestExt for Backlog {
    async fn insert_test_sign(&self, id: SignId, chain: Chain) -> SignEntry<Sign<Generating>> {
        self.insert_sign(test_sign_request(id, chain)).await
    }

    async fn insert_test_bidirectional(
        &self,
        id: SignId,
        chain: Chain,
    ) -> SignEntry<Bidirectional<Initial<Generating>>> {
        self.insert_bidirectional(test_bidi_request(id, chain))
            .await
    }
}

/// Create a test single-phase sign request for tests.
pub fn test_sign_request(id: SignId, chain: Chain) -> Arc<IndexedSignRequest> {
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

/// Create a test bidirectional sign request for tests.
pub fn test_bidi_request(id: SignId, chain: Chain) -> Arc<IndexedSignRequest> {
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
