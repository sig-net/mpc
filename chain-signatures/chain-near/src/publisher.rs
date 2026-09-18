use std::sync::Arc;
use std::time::Duration;

use crate::gates::NearRpcGates;
use crate::util::AffinePointExt as _;

use mpc_chain_integration_core::utils::retry::{retry_rpc_gated, RetryConfig};
use mpc_chain_integration_core::{ChainPublisher, PublishAction, PublisherTelemetry};
use mpc_primitives::{RequestId, Signature};

use near_account_id::AccountId;
use near_crypto::InMemorySigner;
use near_fetch::result::ExecutionFinalResult;
use serde_json::json;

/// Retries for one `respond` submission; the RPC executor retries the publish
/// itself on top of this.
const NEAR_RESPOND_RETRY: RetryConfig = RetryConfig {
    min_delay: Duration::from_millis(500),
    max_delay: Duration::from_secs(5),
    max_times: 3,
    jitter: true,
};

#[derive(Clone)]
pub struct NearClient {
    client: near_fetch::Client,
    contract_id: AccountId,
    signer: InMemorySigner,
    gates: NearRpcGates,
    telemetry: Arc<dyn PublisherTelemetry>,
}

impl NearClient {
    pub fn new(
        client: near_fetch::Client,
        contract_id: &AccountId,
        signer: InMemorySigner,
        gates: NearRpcGates,
        telemetry: Arc<dyn PublisherTelemetry>,
    ) -> Self {
        Self {
            client,
            contract_id: contract_id.clone(),
            signer,
            gates,
            telemetry,
        }
    }

    pub fn rpc_addr(&self) -> String {
        self.client.rpc_addr()
    }

    async fn call_respond(
        &self,
        id: &RequestId,
        response: &Signature,
    ) -> anyhow::Result<ExecutionFinalResult> {
        let call = self
            .client
            .call(&self.signer, &self.contract_id, "respond")
            .args_json(json!({
                "sign_id": id,
                "signature": response,
            }))
            .max_gas();
        self.gates.transact(call).await
    }
}

#[async_trait::async_trait]
impl ChainPublisher for NearClient {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let timestamp = action.timestamp;
        let signature = &action.signature;
        let outcome = retry_rpc_gated!(
            Duration::MAX, // the RPC's own timeout bounds a send
            NEAR_RESPOND_RETRY,
            self.gates.provider,
            "near_respond",
            { self.call_respond(&action.request.id, signature).await }
        )
        .map_err(|e| anyhow::anyhow!("near rpc error: {e}"))
        .inspect_err(|err| {
            tracing::error!(
                request_id = ?action.request.id,
                ?err,
                "failed to publish signature",
            );
        })?;

        outcome
            .json::<()>()
            .map_err(|e| anyhow::anyhow!("contract rejected response: {e}"))
            .inspect_err(|err| {
                tracing::error!(
                    request_id = ?action.request.id,
                    big_r = signature.big_r.to_base58(),
                    s = ?signature.s,
                    ?err,
                    "smart contract threw error",
                );
            })?;

        tracing::info!(
            request_id = ?action.request.id,
            big_r = signature.big_r.to_base58(),
            s = ?signature.s,
            elapsed = ?timestamp.elapsed(),
            "published signature sucessfully",
        );

        self.telemetry.record_publish_metrics(action);

        Ok(())
    }
}
