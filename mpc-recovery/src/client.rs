use hyper::{Body, Client, Method, Request};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::delegate_action::SignedDelegateAction;
use near_primitives::hash::CryptoHash;
use near_primitives::types::{AccountId, BlockHeight, Finality};
use near_primitives::views::{AccessKeyView, QueryRequest};
use serde_json::json;

#[derive(Clone)]
pub struct NearRpcClient {
    rpc_client: JsonRpcClient,
    relayer_url: String,
}

impl NearRpcClient {
    pub fn connect(near_rpc: &str, relayer_url: String) -> Self {
        Self {
            rpc_client: JsonRpcClient::connect(near_rpc),
            relayer_url,
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

    pub async fn access_key_nonce(
        &self,
        account_id: AccountId,
        public_key: near_crypto::PublicKey,
    ) -> anyhow::Result<u64> {
        let key = self.access_key(account_id, public_key).await?;
        Ok(key.0.nonce)
    }

    pub async fn latest_block_height(&self) -> anyhow::Result<BlockHeight> {
        let block_view = self
            .rpc_client
            .call(&methods::block::RpcBlockRequest {
                block_reference: Finality::Final.into(),
            })
            .await?;
        Ok(block_view.header.height)
    }

    #[tracing::instrument(level = "debug", skip_all, fields(account_id))]
    pub async fn register_account_with_relayer(&self, account_id: AccountId) -> anyhow::Result<()> {
        let json_payload = json!({
            "account_id": account_id.to_string(),
            "allowance": 300000000000000u64
        })
        .to_string();

        tracing::debug!(
            "constructed json payload, {} bytes total",
            json_payload.len()
        );

        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/register_account", self.relayer_url))
            .header("content-type", "application/json")
            .body(Body::from(json_payload))
            .unwrap();

        tracing::debug!("constructed http request to {}", self.relayer_url);
        let client = Client::new();
        let response = client.request(request).await?;

        if response.status().is_success() {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            tracing::debug!("success: {}", std::str::from_utf8(&response_body)?)
        } else {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            anyhow::bail!(
                "transaction failed: {}",
                std::str::from_utf8(&response_body)?
            )
        }

        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all, fields(receiver_id = signed_delegate_action.delegate_action.receiver_id.to_string()))]
    pub async fn send_tx_via_relayer(
        &self,
        signed_delegate_action: SignedDelegateAction,
    ) -> anyhow::Result<()> {
        let json_payload = serde_json::to_vec(&signed_delegate_action)?;

        tracing::debug!(
            "constructed json payload, {} bytes total",
            json_payload.len()
        );

        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/send_meta_tx", self.relayer_url))
            .header("content-type", "application/json")
            .body(Body::from(json_payload))
            .unwrap();

        tracing::debug!("constructed http request to {}", self.relayer_url);
        let client = Client::new();
        let response = client.request(request).await?;

        if response.status().is_success() {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            tracing::debug!("success: {}", std::str::from_utf8(&response_body)?)
        } else {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            anyhow::bail!(
                "transaction failed: {}",
                std::str::from_utf8(&response_body)?
            )
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAYER_URI: &str = "http://34.70.226.83:3030";

    #[tokio::test]
    async fn test_latest_block() -> anyhow::Result<()> {
        let testnet =
            NearRpcClient::connect("https://rpc.testnet.near.org", RELAYER_URI.to_string());
        let block_height = testnet.latest_block_height().await?;

        assert!(block_height > 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_access_key() -> anyhow::Result<()> {
        let testnet =
            NearRpcClient::connect("https://rpc.testnet.near.org", RELAYER_URI.to_string());
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
