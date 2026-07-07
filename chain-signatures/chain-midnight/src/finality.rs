//! Finality gate: nothing may reach the sign queue before its block is
//! finalized, checked directly against the operator's own node RPC (never the
//! indexer's claim). Once the MPC signs, the signature exists off-chain
//! forever — a request that reorgs away still got its signature.

use serde_json::{json, Value};
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(2);

pub(crate) struct FinalityGate {
    http: reqwest::Client,
    node_rpc_url: String,
    cached: Option<(Instant, u64)>,
}

impl FinalityGate {
    pub fn new(node_rpc_url: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            node_rpc_url: node_rpc_url.to_string(),
            cached: None,
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let resp = self
            .http
            .post(&self.node_rpc_url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await?;
        anyhow::ensure!(
            resp.status().is_success(),
            "node RPC {method}: {}",
            resp.status()
        );
        let body: Value = resp.json().await?;
        if let Some(err) = body.get("error").filter(|e| !e.is_null()) {
            anyhow::bail!("node RPC {method} error: {err}");
        }
        Ok(body["result"].clone())
    }

    pub async fn finalized_height(&mut self) -> anyhow::Result<u64> {
        if let Some((at, height)) = self.cached {
            if at.elapsed() < CACHE_TTL {
                return Ok(height);
            }
        }
        let hash = self
            .rpc("chain_getFinalizedHead", json!([]))
            .await?
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("chain_getFinalizedHead: non-string result"))?
            .to_string();
        let header = self.rpc("chain_getHeader", json!([hash])).await?;
        let number = header["number"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("chain_getHeader: missing number"))?;
        let height = u64::from_str_radix(number.trim_start_matches("0x"), 16)?;
        self.cached = Some((Instant::now(), height));
        Ok(height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_and_caches_finalized_height() {
        let mut server = mockito::Server::new_async().await;
        let head = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex("chain_getFinalizedHead".into()))
            .with_status(200)
            .with_body(json!({"jsonrpc": "2.0", "id": 1, "result": "0xabcd"}).to_string())
            .expect(1)
            .create_async()
            .await;
        let header = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Regex("chain_getHeader".into()))
            .with_status(200)
            .with_body(
                json!({"jsonrpc": "2.0", "id": 1, "result": {"number": "0x41b"}}).to_string(),
            )
            .expect(1)
            .create_async()
            .await;

        let mut gate = FinalityGate::new(&server.url());
        assert_eq!(gate.finalized_height().await.unwrap(), 0x41b);
        // Second call inside the TTL is served from cache (mocks expect(1)).
        assert_eq!(gate.finalized_height().await.unwrap(), 0x41b);
        head.assert_async().await;
        header.assert_async().await;
    }

    #[tokio::test]
    async fn surfaces_rpc_errors() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/")
            .with_status(200)
            .with_body(
                json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no"}})
                    .to_string(),
            )
            .create_async()
            .await;
        let mut gate = FinalityGate::new(&server.url());
        assert!(gate.finalized_height().await.is_err());
    }
}
