use crate::backlog::{CheckpointEntry, Publishing};
use crate::sign_bidirectional::SignProgress;
use mpc_primitives::{BidirectionalTx, BidirectionalTxId, IndexedSignRequest, SignKind};
use serde::Deserialize;
use std::sync::Arc;

/// A checkpoint entry, or one written with the node's status inside: the status is node-local
/// and dropped, but the transaction id it names came from a published signature and stays.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MigratableCheckpointEntry {
    request: Arc<IndexedSignRequest>,
    #[serde(default)]
    tx_ids: Vec<BidirectionalTxId>,
    #[serde(default)]
    status: Option<LegacySignStatus>,
    #[serde(default)]
    legacy_tag: Option<u8>,
}

/// Status shapes checkpoints carried before they held only source-chain facts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[allow(clippy::enum_variant_names)]
enum LegacySignStatus {
    Sign(SignProgress),
    Bidirectional(LegacyBidirectionalProgress),
    PendingGeneration,
    PendingPublish { publish: Publishing },
    PendingExecution { tx: Arc<BidirectionalTx> },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
enum LegacyBidirectionalProgress {
    Initial(SignProgress),
    Executing(Arc<BidirectionalTx>),
    Final {
        respond_request: Arc<IndexedSignRequest>,
        progress: SignProgress,
    },
    Parked(Arc<BidirectionalTx>),
}

impl From<MigratableCheckpointEntry> for CheckpointEntry {
    fn from(entry: MigratableCheckpointEntry) -> Self {
        let legacy_tag = entry
            .legacy_tag
            .or_else(|| entry.status.as_ref().map(LegacySignStatus::tag));
        let mut tx_ids = entry.tx_ids;
        if let Some(id) = entry.status.and_then(LegacySignStatus::tx_id) {
            tx_ids.push(id);
        }
        tx_ids.sort_by_key(|id| id.0);
        tx_ids.dedup();
        Self {
            request: entry.request,
            tx_ids,
            legacy_tag,
        }
    }
}

impl LegacySignStatus {
    /// What the versions that wrote this status hashed for it: whether a signature was out.
    fn tag(&self) -> u8 {
        match self {
            Self::Sign(_)
            | Self::Bidirectional(LegacyBidirectionalProgress::Initial(_))
            | Self::PendingGeneration
            | Self::PendingPublish { .. } => 0,
            Self::Bidirectional(_) | Self::PendingExecution { .. } => 1,
        }
    }

    /// The transaction a legacy status names: the one watched, or the one a response names.
    fn tx_id(self) -> Option<BidirectionalTxId> {
        match self {
            Self::PendingExecution { tx }
            | Self::Bidirectional(
                LegacyBidirectionalProgress::Executing(tx)
                | LegacyBidirectionalProgress::Parked(tx),
            ) => Some(tx.id),
            Self::Bidirectional(LegacyBidirectionalProgress::Final {
                respond_request, ..
            }) => match &respond_request.kind {
                SignKind::RespondBidirectional(response) => Some(response.tx_id),
                _ => None,
            },
            Self::Sign(_)
            | Self::Bidirectional(LegacyBidirectionalProgress::Initial(_))
            | Self::PendingGeneration
            | Self::PendingPublish { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::mock::{mock_bidi_response, mock_publishing, mock_tx};
    use crate::sign_bidirectional::{BidirectionalProgress, SignStatus};
    use k256::Scalar;
    use mpc_primitives::{Chain, SignArgs, SignId};
    use serde::Serialize;
    use sha3::Digest;

    /// The entry shape checkpoints had before this format.
    #[derive(Serialize)]
    struct StatusEntry<S> {
        request: Arc<IndexedSignRequest>,
        status: S,
    }

    #[derive(Serialize)]
    enum OldProgress {
        Executing(Arc<BidirectionalTx>),
        Parked(Arc<BidirectionalTx>),
    }

    #[derive(Serialize)]
    enum OldStatus {
        Bidirectional(OldProgress),
    }

    fn request(kind: SignKind) -> Arc<IndexedSignRequest> {
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

    fn decode<T: Serialize>(entry: &T) -> CheckpointEntry {
        reencode(entry)
    }

    fn reencode<T: Serialize, D: serde::de::DeserializeOwned>(entry: &T) -> D {
        let mut bytes = Vec::new();
        ciborium::into_writer(entry, &mut bytes).unwrap();
        ciborium::from_reader(&bytes[..]).unwrap()
    }

    #[test]
    fn statuses_keep_only_the_transactions_they_name() {
        let tx = Arc::new(mock_tx(3));
        let req = request(SignKind::Sign);
        let executing = StatusEntry {
            request: Arc::clone(&req),
            status: OldStatus::Bidirectional(OldProgress::Executing(Arc::clone(&tx))),
        };
        assert_eq!(decode(&executing).tx_ids, vec![tx.id]);
        let parked = StatusEntry {
            request: Arc::clone(&req),
            status: OldStatus::Bidirectional(OldProgress::Parked(Arc::clone(&tx))),
        };
        assert_eq!(decode(&parked).tx_ids, vec![tx.id]);

        let answered = StatusEntry {
            request: Arc::clone(&req),
            status: SignStatus::Bidirectional(BidirectionalProgress::Final {
                respond_request: mock_bidi_response(&tx),
                progress: SignProgress::Publishing(mock_publishing()),
            }),
        };
        let decoded = decode(&answered);
        assert_eq!(decoded.tx_ids, vec![tx.id]);
        assert_eq!(decoded.request, req);

        let signing = StatusEntry {
            request: Arc::clone(&req),
            status: SignStatus::Sign(SignProgress::Publishing(mock_publishing())),
        };
        assert!(decode(&signing).tx_ids.is_empty());
    }

    /// A body written before entries held source facts alone keeps the digest it settled
    /// under, also after a round trip, so an upgraded node can still match its peers' votes.
    #[test]
    fn a_legacy_body_keeps_its_settled_digest() {
        #[derive(Serialize)]
        struct LegacyBody {
            chain: Chain,
            block_height: u64,
            pending_requests: Vec<StatusEntry<OldStatus>>,
            #[serde(with = "serde_bytes")]
            cumulative_digest: [u8; 32],
        }
        let tx = Arc::new(mock_tx(3));
        let req = request(SignKind::Sign);
        // One executing entry: earlier versions hashed its tag, 1.
        let cumulative: [u8; 32] = sha3::Sha3_256::digest([1u8]).into();
        let body = LegacyBody {
            chain: Chain::Ethereum,
            block_height: 7,
            pending_requests: vec![StatusEntry {
                request: Arc::clone(&req),
                status: OldStatus::Bidirectional(OldProgress::Executing(tx)),
            }],
            cumulative_digest: cumulative,
        };
        let settled =
            mpc_primitives::checkpoint_digest(Chain::Ethereum, 7, [req.id.request_id], cumulative);

        let decoded: crate::backlog::Checkpoint = reencode(&body);
        assert_eq!(decoded.digest(), settled);
        let again: crate::backlog::Checkpoint = reencode(&decoded);
        assert_eq!(again.digest(), settled);
    }

    #[test]
    fn current_entries_roundtrip() {
        let entry = CheckpointEntry {
            request: request(SignKind::Sign),
            tx_ids: vec![BidirectionalTxId([4; 32])],
            legacy_tag: None,
        };
        assert_eq!(decode(&entry), entry);
    }
}
