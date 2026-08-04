use crate::sign_bidirectional::SignStatus;
use mpc_primitives::{IndexedSignRequest, SignId};
use sha3::Digest;

/// Independently recoverable local work stages for a request.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum WorkStage {
    Initial,
    Execution,
    Final,
}

/// Stable identity for one local work item.
///
/// The same `SignId` may legitimately appear in both the initial and final
/// bidirectional signing stages, so stage and request content are part of the
/// durable key rather than inferred from `SignId` alone.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct WorkKey {
    pub sign_id: SignId,
    pub stage: WorkStage,
    pub request_digest: [u8; 32],
    pub governance_epoch: u64,
}

impl WorkKey {
    pub fn new(
        sign_id: SignId,
        stage: WorkStage,
        request_digest: [u8; 32],
        governance_epoch: u64,
    ) -> Self {
        Self {
            sign_id,
            stage,
            request_digest,
            governance_epoch,
        }
    }

    /// Derive a work key from identity-bearing indexed request fields.
    ///
    /// The request digest intentionally excludes `unix_timestamp_indexed`,
    /// which is node-local indexing metadata, so observers derive the same key
    /// for the same source request.
    pub fn for_request(
        stage: WorkStage,
        request: &IndexedSignRequest,
        governance_epoch: u64,
    ) -> Self {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(
            &(&request.id, &request.args, request.chain, &request.kind),
            &mut encoded,
        )
        .expect("serialize indexed request identity for work key");
        let request_digest = sha3::Sha3_256::digest(encoded).into();
        Self::new(request.id, stage, request_digest, governance_epoch)
    }

    pub fn stage_for_status(status: &SignStatus) -> WorkStage {
        match status {
            SignStatus::PendingGeneration | SignStatus::PendingPublish { .. } => WorkStage::Initial,
            SignStatus::PendingExecution { .. } => WorkStage::Execution,
            SignStatus::PendingGenerationBidirectional
            | SignStatus::PendingPublishBidirectional { .. } => WorkStage::Final,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign_bidirectional::PublishState;
    use cait_sith::protocol::Participant;
    use k256::{AffinePoint, Scalar};
    use mpc_primitives::{
        BidirectionalTx, BidirectionalTxId, Chain, RespondBidirectionalTx, SignArgs, SignKind,
    };

    fn test_request(id: u8) -> IndexedSignRequest {
        IndexedSignRequest::new(
            SignId::new([id; 32]),
            SignArgs {
                entropy: [id; 32],
                epsilon: Scalar::ONE,
                payload: Scalar::ONE,
                path: "test".to_string(),
                key_version: 1,
            },
            Chain::Solana,
            0,
            SignKind::Sign,
        )
    }

    fn test_publish_state() -> PublishState {
        PublishState {
            signature: mpc_primitives::Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0),
            participants: vec![Participant::from(0u32)],
            is_proposer: true,
        }
    }

    fn test_tx(id: u8) -> BidirectionalTx {
        BidirectionalTx {
            id: BidirectionalTxId([id; 32]),
            sender: [0; 32],
            serialized_transaction: vec![1],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 1,
            deposit: 0,
            path: "test".to_string(),
            algo: "ECDSA".to_string(),
            dest: "dest".to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            request_id: [id; 32],
            from_address: [0; 20],
            nonce: 0,
        }
    }

    #[test]
    fn initial_and_final_work_keys_are_distinct_for_one_sign_id() {
        let request = test_request(7);
        let initial = WorkKey::for_request(WorkStage::Initial, &request, 3);
        let final_key = WorkKey::for_request(WorkStage::Final, &request, 3);

        assert_ne!(initial, final_key);
        assert_ne!(initial.stage, final_key.stage);
    }

    #[test]
    fn work_key_changes_when_request_or_governance_epoch_changes() {
        let request = test_request(8);
        let mut changed_request = request.clone();
        changed_request.args.path.push_str("/changed");

        let original = WorkKey::for_request(WorkStage::Initial, &request, 3);
        let changed_request_key = WorkKey::for_request(WorkStage::Initial, &changed_request, 3);
        let changed_epoch = WorkKey::for_request(WorkStage::Initial, &request, 4);
        let repeated = WorkKey::for_request(WorkStage::Initial, &request, 3);

        assert_eq!(original, repeated);
        assert_ne!(original.request_digest, changed_request_key.request_digest);
        assert_ne!(original.governance_epoch, changed_epoch.governance_epoch);
        assert_ne!(original, changed_request_key);
        assert_ne!(original, changed_epoch);
    }

    #[test]
    fn work_key_ignores_local_indexing_timestamp() {
        let request = test_request(10);
        let mut reindexed = request.clone();
        reindexed.unix_timestamp_indexed = 99;

        assert_eq!(
            WorkKey::for_request(WorkStage::Initial, &request, 3),
            WorkKey::for_request(WorkStage::Initial, &reindexed, 3)
        );
    }

    #[test]
    fn work_key_changes_when_request_kind_changes() {
        let request = test_request(11);
        let mut changed_kind = request.clone();
        changed_kind.kind = SignKind::RespondBidirectional(RespondBidirectionalTx {
            tx_id: test_tx(11).id,
            output: vec![],
            chain_ctx: None,
        });

        assert_ne!(
            WorkKey::for_request(WorkStage::Initial, &request, 3),
            WorkKey::for_request(WorkStage::Initial, &changed_kind, 3)
        );
    }

    #[test]
    fn work_stage_matches_every_runtime_status() {
        let tx = test_tx(9);
        let statuses = [
            (SignStatus::PendingGeneration, WorkStage::Initial),
            (
                SignStatus::PendingPublish {
                    publish: test_publish_state(),
                },
                WorkStage::Initial,
            ),
            (SignStatus::PendingExecution { tx }, WorkStage::Execution),
            (SignStatus::PendingGenerationBidirectional, WorkStage::Final),
            (
                SignStatus::PendingPublishBidirectional {
                    publish: test_publish_state(),
                },
                WorkStage::Final,
            ),
        ];

        for (status, expected) in statuses {
            assert_eq!(WorkKey::stage_for_status(&status), expected);
        }
    }
}
