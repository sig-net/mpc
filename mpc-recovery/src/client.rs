use near_jsonrpc_client::{methods, JsonRpcClient, MethodCallResult};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::SignedTransaction;
use near_primitives::types::{AccountId, Finality};
use near_primitives::views::{AccessKeyView, FinalExecutionOutcomeView, QueryRequest};

#[derive(Clone)]
pub struct NearRpcClient {
    rpc_client: JsonRpcClient,
}

impl NearRpcClient {
    pub fn testnet() -> Self {
        Self {
            rpc_client: JsonRpcClient::connect("https://rpc.testnet.near.org"),
        }
    }

    async fn access_key(
        &self,
        account_id: AccountId,
        public_key: near_crypto::PublicKey,
    ) -> anyhow::Result<(AccessKeyView, CryptoHash)> {
        let query_resp = self
            .rpc_client
            .call(&methods::query::RpcQueryRequest {
                block_reference: Finality::None.into(),
                request: QueryRequest::ViewAccessKey {
                    account_id,
                    public_key,
                },
            })
            .await
            .map_err(|e| anyhow::anyhow!("failed to query access key {}", e))?;

        match query_resp.kind {
            QueryResponseKind::AccessKey(access_key) => Ok((access_key, query_resp.block_hash)),
            _ => Err(anyhow::anyhow!(
                "query returned invalid data while querying access key"
            )),
        }
    }

    async fn query_broadcast_tx(
        &self,
        method: &methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest,
    ) -> MethodCallResult<
        FinalExecutionOutcomeView,
        near_jsonrpc_primitives::types::transactions::RpcTransactionError,
    > {
        let result = self.rpc_client.call(method).await;
        match &result {
            Ok(response) => {
                tracing::debug!(
                    target: "client",
                    "Submitting transaction with actions {:?} succeeded with status {:?}",
                    method.signed_transaction.transaction.actions,
                    response.status
                );
            }
            Err(error) => {
                tracing::error!(
                    target: "client",
                    "Calling RPC method {:?} resulted in error {:?}",
                    method,
                    error
                );
            }
        };
        result
    }

    pub async fn access_key_nonce(
        &self,
        account_id: AccountId,
        public_key: near_crypto::PublicKey,
    ) -> anyhow::Result<u64> {
        let key = self.access_key(account_id, public_key).await?;
        Ok(key.0.nonce)
    }

    pub async fn latest_block_hash(&self) -> anyhow::Result<CryptoHash> {
        let block_view = self
            .rpc_client
            .call(&methods::block::RpcBlockRequest {
                block_reference: Finality::Final.into(),
            })
            .await?;
        Ok(block_view.header.hash)
    }

    pub async fn send_tx(
        &self,
        signed_transaction: SignedTransaction,
    ) -> anyhow::Result<FinalExecutionOutcomeView> {
        let result = self
            .query_broadcast_tx(&methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                signed_transaction,
            })
            .await?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_latest_block() -> anyhow::Result<()> {
        let testnet = NearRpcClient::testnet();
        let block_hash = testnet.latest_block_hash().await?;

        assert!(block_hash.0.len() == 32);
        Ok(())
    }

    #[tokio::test]
    async fn test_access_key() -> anyhow::Result<()> {
        let testnet = NearRpcClient::testnet();
        let nonce = testnet
            .access_key_nonce(
                "dev-1636354824855-78504059330123".parse()?,
                "ed25519:8n5HXTibTDtXKAnEUPFUXXJoKqa5A1c2vWXt6LbRAcGn".parse()?,
            )
            .await?;

        // Assuming no one will use this account ever again
        assert_eq!(nonce, 70526114000002);
        Ok(())
    }
}
