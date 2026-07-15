use std::sync::Arc;

use crate::util::AffinePointExt as _;

use mpc_chain_integration_core::{ChainPublisher, PublishAction, PublisherTelemetry};
use mpc_primitives::{ConsensusCheckpointDigest, SignId, SignKind, Signature};

use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_fetch::result::ExecutionFinalResult;
use serde_json::json;

/// Base delay in milliseconds between NEAR RPC retries
const NEAR_RETRY_BASE_DELAY_MS: u64 = 500;
/// Maximum number of retry attempts for NEAR RPC calls
const NEAR_RESPOND_MAX_RETRIES: usize = 3;

#[derive(Clone)]
pub struct NearClient {
    client: near_fetch::Client,
    contract_id: AccountId,
    signer: InMemorySigner,
    telemetry: Arc<dyn PublisherTelemetry>,
}

impl NearClient {
    pub fn new(
        near_rpc: &str,
        contract_id: &AccountId,
        signer: InMemorySigner,
        telemetry: Arc<dyn PublisherTelemetry>,
    ) -> Self {
        Self {
            client: near_fetch::Client::new(near_rpc),
            contract_id: contract_id.clone(),
            signer,
            telemetry,
        }
    }

    pub fn rpc_addr(&self) -> String {
        self.client.rpc_addr()
    }

    async fn call_respond(
        &self,
        id: &SignId,
        response: &Signature,
    ) -> Result<ExecutionFinalResult, near_fetch::Error> {
        self.client
            .call(&self.signer, &self.contract_id, "respond")
            .args_json(json!({
                "sign_id": id,
                "signature": response,
            }))
            .max_gas()
            .retry_exponential(NEAR_RETRY_BASE_DELAY_MS, NEAR_RESPOND_MAX_RETRIES)
            .transact()
            .await
    }

    async fn call_respond_checkpoint(
        &self,
        checkpoint: &ConsensusCheckpointDigest,
        signature: &Signature,
    ) -> Result<ExecutionFinalResult, near_fetch::Error> {
        self.client
            .call(&self.signer, &self.contract_id, "respond_checkpoint")
            .args_json(json!({
                "checkpoint": checkpoint,
                "signature": signature,
            }))
            .max_gas()
            .retry_exponential(NEAR_RETRY_BASE_DELAY_MS, NEAR_RESPOND_MAX_RETRIES)
            .transact()
            .await
    }
}

#[async_trait::async_trait]
impl ChainPublisher for NearClient {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let timestamp = action.timestamp;
        let signature = &action.signature;
        let outcome = match &action.request.kind {
            SignKind::Checkpoint(checkpoint) => {
                self.call_respond_checkpoint(checkpoint, signature).await
            }
            _ => self.call_respond(&action.request.id, signature).await,
        }
        .map_err(|e| anyhow::anyhow!("near rpc error: {e}"))
        .inspect_err(|err| {
            tracing::error!(
                sign_id = ?action.request.id,
                ?err,
                "failed to publish signature",
            );
        })?;

        outcome
            .json::<()>()
            .map_err(|e| anyhow::anyhow!("contract rejected response: {e}"))
            .inspect_err(|err| {
                tracing::error!(
                    sign_id = ?action.request.id,
                    big_r = signature.big_r.to_base58(),
                    s = ?signature.s,
                    ?err,
                    "smart contract threw error",
                );
            })?;

        tracing::info!(
            sign_id = ?action.request.id,
            big_r = signature.big_r.to_base58(),
            s = ?signature.s,
            elapsed = ?timestamp.elapsed(),
            "published signature sucessfully",
        );

        self.telemetry.record_publish_metrics(action);

        Ok(())
    }
}
