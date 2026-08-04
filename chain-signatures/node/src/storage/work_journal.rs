use crate::backlog::{WorkKey, WorkStage};
use cait_sith::protocol::Participant;
use deadpool_redis::Pool;
use mpc_primitives::{BidirectionalTxId, IndexedSignRequest, SignKind, Signature};
use near_account_id::AccountId;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

const WORK_JOURNAL_VERSION: &str = "v1";

/// A target-chain execution result retained for local recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionResult {
    Success { output: Vec<u8> },
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionObservation {
    pub block_height: u64,
    pub result: ExecutionResult,
}

/// Durable local work state. None of these fields participate in checkpoint
/// consensus; they are reconciled against the canonical backlog projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkRecord {
    /// The original source-chain request.
    pub request: IndexedSignRequest,
    pub signature: Option<Signature>,
    pub participants: Vec<Participant>,
    pub publisher: Option<Participant>,
    pub retry_count: u32,
    pub lease_until_unix_secs: Option<u64>,
    pub execution: Option<ExecutionObservation>,
    /// The target-chain transaction identity associated with this work item.
    pub execution_tx_id: Option<BidirectionalTxId>,
    /// The final source-chain request, when target execution has been observed.
    pub final_request: Option<IndexedSignRequest>,
}

impl WorkRecord {
    pub fn new(request: IndexedSignRequest) -> Self {
        Self {
            request,
            signature: None,
            participants: Vec::new(),
            publisher: None,
            retry_count: 0,
            lease_until_unix_secs: None,
            execution: None,
            execution_tx_id: None,
            final_request: None,
        }
    }

    fn request_for_stage(&self, stage: WorkStage) -> anyhow::Result<&IndexedSignRequest> {
        match stage {
            WorkStage::Final => self
                .final_request
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("final work record is missing final request")),
            WorkStage::Initial | WorkStage::Execution => Ok(&self.request),
        }
    }
}

#[derive(Clone, Debug)]
pub enum WorkJournal {
    Redis {
        pool: Pool,
        account_id: AccountId,
    },
    InMemory {
        records: Arc<RwLock<HashMap<WorkKey, WorkRecord>>>,
    },
}

impl Default for WorkJournal {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl WorkJournal {
    pub fn in_memory() -> Self {
        Self::InMemory {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn redis(pool: Pool, account_id: AccountId) -> Self {
        Self::Redis { pool, account_id }
    }

    fn stage_name(stage: WorkStage) -> &'static str {
        match stage {
            WorkStage::Initial => "initial",
            WorkStage::Execution => "execution",
            WorkStage::Final => "final",
        }
    }

    /// Return the stable Redis key used for a work item.
    pub fn storage_key(&self, key: WorkKey) -> String {
        let prefix = match self {
            Self::Redis { account_id, .. } => account_id.to_string(),
            Self::InMemory { .. } => "memory".to_string(),
        };
        format!(
            "{prefix}:work:{WORK_JOURNAL_VERSION}:{}:{}:{}:{}",
            hex::encode(key.sign_id.request_id),
            Self::stage_name(key.stage),
            hex::encode(key.request_digest),
            key.governance_epoch,
        )
    }

    fn validate_key(key: WorkKey, record: &WorkRecord) -> anyhow::Result<()> {
        let request = record.request_for_stage(key.stage)?;
        let derived = WorkKey::for_request(key.stage, request, key.governance_epoch);
        anyhow::ensure!(
            derived == key,
            "work record request does not match its work key"
        );
        anyhow::ensure!(
            record.request.id == key.sign_id,
            "work record original request does not match its work key sign id"
        );
        if key.stage == WorkStage::Final {
            anyhow::ensure!(
                record.execution_tx_id.is_some(),
                "final work record is missing execution transaction id"
            );
        }
        if let Some(final_request) = &record.final_request {
            anyhow::ensure!(
                matches!(record.request.kind, SignKind::SignBidirectional(_)),
                "final work record must originate from a bidirectional sign request"
            );
            anyhow::ensure!(
                final_request.id == record.request.id,
                "work record final request does not match its original sign id"
            );
            let SignKind::RespondBidirectional(response) = &final_request.kind else {
                anyhow::bail!("work record final request must be bidirectional response");
            };
            anyhow::ensure!(
                Some(response.tx_id) == record.execution_tx_id,
                "work record final request transaction does not match execution transaction"
            );
        }
        Ok(())
    }

    pub async fn put(&self, key: WorkKey, record: WorkRecord) -> anyhow::Result<()> {
        Self::validate_key(key, &record)?;
        match self {
            Self::InMemory { records } => {
                records.write().await.insert(key, record);
                Ok(())
            }
            Self::Redis { pool, .. } => {
                let mut conn = pool
                    .get()
                    .await
                    .map_err(|err| anyhow::anyhow!("failed to get redis connection: {err}"))?;
                let mut value = Vec::new();
                ciborium::ser::into_writer(&record, &mut value)?;
                conn.set::<_, _, ()>(self.storage_key(key), value)
                    .await
                    .map_err(|err| anyhow::anyhow!("failed to persist work record: {err}"))?;
                Ok(())
            }
        }
    }

    pub async fn get(&self, key: WorkKey) -> anyhow::Result<Option<WorkRecord>> {
        let record = match self {
            Self::InMemory { records } => records.read().await.get(&key).cloned(),
            Self::Redis { pool, .. } => {
                let mut conn = pool
                    .get()
                    .await
                    .map_err(|err| anyhow::anyhow!("failed to get redis connection: {err}"))?;
                let value: Option<Vec<u8>> = conn
                    .get(self.storage_key(key))
                    .await
                    .map_err(|err| anyhow::anyhow!("failed to load work record: {err}"))?;
                value
                    .map(|value| {
                        ciborium::de::from_reader(value.as_slice()).map_err(anyhow::Error::from)
                    })
                    .transpose()?
            }
        };
        record
            .map(|record| {
                Self::validate_key(key, &record)?;
                Ok(record)
            })
            .transpose()
    }

    pub async fn delete(&self, key: WorkKey) -> anyhow::Result<()> {
        match self {
            Self::InMemory { records } => {
                records.write().await.remove(&key);
                Ok(())
            }
            Self::Redis { pool, .. } => {
                let mut conn = pool
                    .get()
                    .await
                    .map_err(|err| anyhow::anyhow!("failed to get redis connection: {err}"))?;
                conn.del::<_, ()>(self.storage_key(key))
                    .await
                    .map_err(|err| anyhow::anyhow!("failed to delete work record: {err}"))?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backlog::WorkStage;
    use k256::{AffinePoint, Scalar};
    use mpc_primitives::{
        Chain, RespondBidirectionalTx, SignArgs, SignBidirectionalEvent, SignId, SignKind,
    };

    fn request(id: u8) -> IndexedSignRequest {
        IndexedSignRequest::sign(
            SignId::new([id; 32]),
            SignArgs {
                entropy: [id; 32],
                epsilon: Scalar::ONE,
                payload: Scalar::ONE,
                path: "journal".to_string(),
                key_version: 1,
            },
            Chain::Solana,
            0,
        )
    }

    fn bidirectional_request(id: u8) -> IndexedSignRequest {
        IndexedSignRequest::sign_bidirectional(
            SignId::new([id; 32]),
            SignArgs {
                entropy: [id; 32],
                epsilon: Scalar::ONE,
                payload: Scalar::ONE,
                path: "journal".to_string(),
                key_version: 1,
            },
            Chain::Solana,
            0,
            SignBidirectionalEvent {
                sender: [id; 32],
                serialized_transaction: vec![1, 2, 3],
                caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
                key_version: 1,
                deposit: 0,
                path: "journal".to_string(),
                algo: "ECDSA".to_string(),
                dest: "dest".to_string(),
                params: "{}".to_string(),
                output_deserialization_schema: vec![],
                respond_serialization_schema: vec![],
                chain: Chain::Solana,
                chain_ctx: None,
            },
        )
    }

    fn record(id: u8) -> WorkRecord {
        WorkRecord {
            request: request(id),
            signature: Some(Signature::new(AffinePoint::GENERATOR, Scalar::ONE, 0)),
            participants: vec![Participant::from(0u32), Participant::from(1u32)],
            publisher: Some(Participant::from(0u32)),
            retry_count: 2,
            lease_until_unix_secs: Some(99),
            execution: Some(ExecutionObservation {
                block_height: 42,
                result: ExecutionResult::Success {
                    output: vec![1, 2, 3],
                },
            }),
            execution_tx_id: None,
            final_request: None,
        }
    }

    #[tokio::test]
    async fn in_memory_round_trip_and_delete() -> anyhow::Result<()> {
        let journal = WorkJournal::in_memory();
        let record = record(1);
        let key = WorkKey::for_request(WorkStage::Initial, &record.request, 7);

        assert!(journal.get(key).await?.is_none());
        journal.put(key, record.clone()).await?;
        assert_eq!(journal.get(key).await?, Some(record));
        journal.delete(key).await?;
        assert!(journal.get(key).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn rejects_record_for_a_different_work_key() {
        let journal = WorkJournal::in_memory();
        let record = record(2);
        let wrong_key = WorkKey::for_request(WorkStage::Final, &request(3), 7);

        let error = journal.put(wrong_key, record).await.unwrap_err();
        assert!(error.to_string().contains("missing final request"));
    }

    #[tokio::test]
    async fn final_key_validates_final_request_and_original_id() -> anyhow::Result<()> {
        let journal = WorkJournal::in_memory();
        let mut record = record(6);
        record.request = bidirectional_request(6);
        let final_request = IndexedSignRequest::new(
            record.request.id,
            SignArgs {
                entropy: [6; 32],
                epsilon: Scalar::ONE,
                payload: Scalar::ONE,
                path: "final".to_string(),
                key_version: 1,
            },
            Chain::Solana,
            10,
            SignKind::RespondBidirectional(RespondBidirectionalTx {
                tx_id: test_tx_id(6),
                output: vec![4, 5],
                chain_ctx: None,
            }),
        );
        record.execution_tx_id = Some(test_tx_id(6));
        record.final_request = Some(final_request.clone());
        let key = WorkKey::for_request(WorkStage::Final, &final_request, 7);

        journal.put(key, record.clone()).await?;
        assert_eq!(journal.get(key).await?, Some(record));
        Ok(())
    }

    fn test_tx_id(id: u8) -> mpc_primitives::BidirectionalTxId {
        mpc_primitives::BidirectionalTxId([id; 32])
    }

    #[tokio::test]
    async fn final_key_rejects_missing_final_request() {
        let journal = WorkJournal::in_memory();
        let record = record(7);
        let key = WorkKey::for_request(WorkStage::Final, &record.request, 7);

        let error = journal.put(key, record).await.unwrap_err();
        assert!(error.to_string().contains("missing final request"));
    }

    #[test]
    fn storage_key_contains_version_stage_and_epoch() {
        let journal = WorkJournal::in_memory();
        let request = request(4);
        let key = WorkKey::for_request(WorkStage::Final, &request, 12);
        let storage_key = journal.storage_key(key);

        assert!(storage_key.contains(":work:v1:"));
        assert!(storage_key.contains(":final:"));
        assert!(storage_key.ends_with(":12"));
    }

    #[test]
    fn work_record_cbor_round_trips_all_local_recovery_fields() {
        let record = record(5);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&record, &mut encoded).unwrap();
        let decoded: WorkRecord = ciborium::de::from_reader(encoded.as_slice()).unwrap();
        assert_eq!(decoded, record);
        assert!(matches!(decoded.request.kind, SignKind::Sign));
    }
}
