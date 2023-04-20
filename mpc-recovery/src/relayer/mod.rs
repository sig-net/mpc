pub mod error;
pub mod msg;

use hyper::{Body, Client, Method, Request};
use near_jsonrpc_client::errors::{JsonRpcError, JsonRpcServerError};
use near_jsonrpc_client::methods::query::RpcQueryError;
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::hash::CryptoHash;
use near_primitives::types::{AccountId, BlockHeight, Finality};
use near_primitives::views::{AccessKeyView, QueryRequest};

use self::error::RelayerError;
use self::msg::{RegisterAccountRequest, SendMetaTxRequest, SendMetaTxResponse};

#[derive(Clone)]
pub struct NearRpcAndRelayerClient {
    rpc_client: JsonRpcClient,
    relayer_url: String,
}

impl NearRpcAndRelayerClient {
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
    ) -> Result<(AccessKeyView, CryptoHash), RelayerError> {
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
            .map_err(|e| match e {
                JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
                    RpcQueryError::UnknownAccount {
                        requested_account_id,
                        ..
                    },
                )) => RelayerError::UnknownAccount(requested_account_id),
                JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
                    RpcQueryError::UnknownAccessKey { public_key, .. },
                )) => RelayerError::UnknownAccessKey(public_key),
                _ => anyhow::anyhow!(e).into(),
            })?;

        match query_resp.kind {
            QueryResponseKind::AccessKey(access_key) => Ok((access_key, query_resp.block_hash)),
            _ => {
                Err(anyhow::anyhow!("query returned invalid data while querying access key").into())
            }
        }
    }

    pub async fn access_key_nonce(
        &self,
        account_id: AccountId,
        public_key: near_crypto::PublicKey,
    ) -> Result<u64, RelayerError> {
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

    #[tracing::instrument(level = "debug", skip_all, fields(account_id = request.account_id.to_string()))]
    pub async fn register_account(&self, request: RegisterAccountRequest) -> anyhow::Result<()> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/register_account", self.relayer_url))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&request)?))
            .unwrap();

        tracing::debug!("constructed http request to {}", self.relayer_url);
        let client = Client::new();
        let response = client.request(request).await?;

        if response.status().is_success() {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            tracing::debug!("success: {}", std::str::from_utf8(&response_body)?);
            Ok(())
        } else {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            Err(anyhow::anyhow!(
                "fail: {}",
                std::str::from_utf8(&response_body)?
            ))
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(receiver_id = request.delegate_action.receiver_id.to_string()))]
    pub async fn send_meta_tx(
        &self,
        request: SendMetaTxRequest,
    ) -> anyhow::Result<SendMetaTxResponse> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/send_meta_tx", self.relayer_url))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&request)?))
            .unwrap();

        tracing::debug!("constructed http request to {}", self.relayer_url);
        let client = Client::new();
        let response = client.request(request).await?;

        if response.status().is_success() {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            tracing::debug!("body: {}", std::str::from_utf8(&response_body)?);
            let response: SendMetaTxResponse = serde_json::from_slice(&response_body)?;
            tracing::debug!("success: {:?}", response);

            Ok(response)
        } else {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            Err(anyhow::anyhow!(
                "fail: {}",
                std::str::from_utf8(&response_body)?
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAYER_URI: &str = "http://34.70.226.83:3030";
    const TESTNET_URL: &str = "https://rpc.testnet.near.org";

    #[tokio::test]
    async fn test_latest_block() -> anyhow::Result<()> {
        let testnet = NearRpcAndRelayerClient::connect(TESTNET_URL, RELAYER_URI.to_string());
        let block_height = testnet.latest_block_height().await?;

        assert!(block_height > 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_access_key() -> anyhow::Result<()> {
        let testnet = NearRpcAndRelayerClient::connect(TESTNET_URL, RELAYER_URI.to_string());
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
