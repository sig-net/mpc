use crate::backlog::{BacklogEntry, Publishing};
use crate::sign_bidirectional::{BidirectionalProgress, SignProgress, SignStatus};
use mpc_primitives::{BidirectionalTx, IndexedSignRequest, SignKind};
use serde::Deserialize;
use std::sync::Arc;

/// Tagged enum covering both modern and legacy status representations.
///
/// Because all legacy variants (`PendingGeneration`, `PendingPublish`, etc.)
/// and modern variants (`Sign`, `Bidirectional`) have distinct tag names,
/// serde can deserialize either variant without untagged buffering.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum MigratableSignStatus {
    // Modern format variants
    Sign(SignProgress),
    Bidirectional(BidirectionalProgress),

    // Legacy format variants
    PendingGeneration,
    PendingPublish { publish: Publishing },
    PendingExecution { tx: Arc<BidirectionalTx> },
    PendingGenerationBidirectional,
    PendingPublishBidirectional { publish: Publishing },
}

/// Migration deserializer for `BacklogEntry`.
///
/// Deserializes checkpoints written in either the legacy format or the new format,
/// allowing on-the-fly migration of existing Redis checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MigratableBacklogEntry {
    pub request: Arc<IndexedSignRequest>,
    pub status: MigratableSignStatus,
}

impl From<MigratableBacklogEntry> for BacklogEntry {
    fn from(entry: MigratableBacklogEntry) -> Self {
        let status = match entry.status {
            // Modern formats pass through directly
            MigratableSignStatus::Sign(progress) => SignStatus::Sign(progress),
            MigratableSignStatus::Bidirectional(progress) => SignStatus::Bidirectional(progress),

            // Legacy formats mapped according to request kind
            MigratableSignStatus::PendingGeneration => match &entry.request.kind {
                SignKind::Sign => SignStatus::Sign(SignProgress::Generating),
                SignKind::SignBidirectional(_) => SignStatus::Bidirectional(
                    BidirectionalProgress::Initial(SignProgress::Generating),
                ),
                SignKind::RespondBidirectional(_) => {
                    SignStatus::Bidirectional(BidirectionalProgress::Final {
                        respond_request: Arc::clone(&entry.request),
                        progress: SignProgress::Generating,
                    })
                }
            },
            MigratableSignStatus::PendingPublish { publish } => match &entry.request.kind {
                SignKind::Sign => SignStatus::Sign(SignProgress::Publishing(publish)),
                SignKind::SignBidirectional(_) => SignStatus::Bidirectional(
                    BidirectionalProgress::Initial(SignProgress::Publishing(publish)),
                ),
                SignKind::RespondBidirectional(_) => {
                    SignStatus::Bidirectional(BidirectionalProgress::Final {
                        respond_request: Arc::clone(&entry.request),
                        progress: SignProgress::Publishing(publish),
                    })
                }
            },
            MigratableSignStatus::PendingExecution { tx } => {
                SignStatus::Bidirectional(BidirectionalProgress::Executing(tx))
            }
            MigratableSignStatus::PendingGenerationBidirectional => {
                SignStatus::Bidirectional(BidirectionalProgress::Final {
                    respond_request: Arc::clone(&entry.request),
                    progress: SignProgress::Generating,
                })
            }
            MigratableSignStatus::PendingPublishBidirectional { publish } => {
                SignStatus::Bidirectional(BidirectionalProgress::Final {
                    respond_request: Arc::clone(&entry.request),
                    progress: SignProgress::Publishing(publish),
                })
            }
        };

        BacklogEntry::with_status(entry.request, status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cait_sith::protocol::Participant;
    use k256::{AffinePoint, Scalar};
    use mpc_primitives::{
        BidirectionalTxId, Chain, RespondBidirectionalTx, SignArgs, SignId, Signature,
    };

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
    struct LegacyPublishState {
        signature: Signature,
        participants: Vec<Participant>,
        is_proposer: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
    #[allow(clippy::enum_variant_names)]
    enum LegacySignStatus {
        PendingGeneration,
        PendingPublish { publish: LegacyPublishState },
        PendingExecution { tx: Arc<BidirectionalTx> },
        PendingGenerationBidirectional,
        PendingPublishBidirectional { publish: LegacyPublishState },
    }

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
    struct LegacyBacklogEntry {
        request: Arc<IndexedSignRequest>,
        status: LegacySignStatus,
    }

    fn test_signature() -> Signature {
        Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0)
    }

    fn test_publish_state() -> LegacyPublishState {
        LegacyPublishState {
            signature: test_signature(),
            participants: vec![Participant::from(0u32)],
            is_proposer: true,
        }
    }

    fn test_sign_request(kind: SignKind) -> Arc<IndexedSignRequest> {
        Arc::new(IndexedSignRequest::new(
            SignId::new([1u8; 32]),
            SignArgs {
                entropy: [0u8; 32],
                epsilon: Scalar::ONE,
                payload: Scalar::ONE,
                path: String::new(),
                key_version: 0,
            },
            Chain::Ethereum,
            0,
            kind,
        ))
    }

    #[test]
    fn test_legacy_cbor_compat_sign_generating() {
        let req = test_sign_request(SignKind::Sign);
        let legacy_entry = LegacyBacklogEntry {
            request: Arc::clone(&req),
            status: LegacySignStatus::PendingGeneration,
        };

        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&legacy_entry, &mut cbor_bytes).unwrap();

        let decoded: BacklogEntry = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(decoded.status, SignStatus::Sign(SignProgress::Generating));
        assert_eq!(decoded.request(), &req);
    }

    #[test]
    fn test_legacy_cbor_compat_sign_publishing() {
        let req = test_sign_request(SignKind::Sign);
        let publish = test_publish_state();
        let legacy_entry = LegacyBacklogEntry {
            request: Arc::clone(&req),
            status: LegacySignStatus::PendingPublish {
                publish: publish.clone(),
            },
        };

        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&legacy_entry, &mut cbor_bytes).unwrap();

        let decoded: BacklogEntry = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        let pub_handle = decoded
            .status
            .publishing()
            .expect("should be in publishing");
        assert_eq!(pub_handle.signature(), &publish.signature);
        assert_eq!(pub_handle.participants(), &publish.participants);
        assert_eq!(pub_handle.is_proposer(), publish.is_proposer);
        assert_eq!(pub_handle.publishing_since(), None);
        assert!(!pub_handle.publish_dispatched());
        assert_eq!(decoded.request(), &req);
    }

    #[test]
    fn test_legacy_cbor_compat_bidirectional_final() {
        let tx_id = BidirectionalTxId([2u8; 32]);
        let respond_req =
            test_sign_request(SignKind::RespondBidirectional(RespondBidirectionalTx {
                tx_id,
                output: vec![],
                chain_ctx: None,
            }));
        let publish = test_publish_state();

        let legacy_entry = LegacyBacklogEntry {
            request: Arc::clone(&respond_req),
            status: LegacySignStatus::PendingPublishBidirectional {
                publish: publish.clone(),
            },
        };

        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&legacy_entry, &mut cbor_bytes).unwrap();

        let decoded: BacklogEntry = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        let pub_handle = decoded
            .status
            .publishing()
            .expect("should be in publishing");
        assert_eq!(pub_handle.signature(), &publish.signature);
        assert_eq!(pub_handle.participants(), &publish.participants);
        assert_eq!(pub_handle.is_proposer(), publish.is_proposer);
        assert_eq!(pub_handle.publishing_since(), None);
        assert!(!pub_handle.publish_dispatched());
        assert_eq!(decoded.request(), &respond_req);
    }

    #[test]
    fn test_modern_cbor_roundtrip() {
        let req = test_sign_request(SignKind::Sign);
        let publish = Publishing::new(test_signature(), vec![Participant::from(0u32)], true);
        let modern_entry = BacklogEntry::with_status(
            Arc::clone(&req),
            SignStatus::Sign(SignProgress::Publishing(publish.clone())),
        );

        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&modern_entry, &mut cbor_bytes).unwrap();

        let decoded: BacklogEntry = ciborium::from_reader(&cbor_bytes[..]).unwrap();
        assert_eq!(
            decoded.status,
            SignStatus::Sign(SignProgress::Publishing(publish))
        );
        assert_eq!(decoded.request(), &req);
    }
}
