use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::env;

/// Minimal Hydration sandbox handle for integration-tests.
///
/// Two ways to enable in your test environment:
/// 1. Provide `HYDRATION_RPC_WS_URL` pointing at a running Hydration node (recommended for CI).
/// 2. Provide `HYDRATION_BINARY` (path) and `HYDRATION_RPC_WS_URL` (where it will bind) so the harness
///    can detect readiness. Starting the binary is intentionally left to the operator since command
///    line args for Hydration node vary between releases.
#[derive(Clone, Debug, Deserialize)]
pub struct HydrationHandle {
    /// websocket RPC endpoint (ws://...)
    pub rpc_ws_url: String,
    /// optional signer URI to be passed to indexer config (may be empty)
    pub signer_uri: Option<String>,
}

impl HydrationHandle {
    /// Try to construct a handle from environment. Returns Err if the environment
    /// does not contain `HYDRATION_RPC_WS_URL`.
    pub async fn from_env() -> Result<Self> {
        if let Ok(ws) = env::var("HYDRATION_RPC_WS_URL") {
            let signer = env::var("HYDRATION_SIGNER_URI").ok();
            // basic readiness probe: try to connect to the ws URL using a timeout
            let ok = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                // simple TCP connect for ws host:port
                if let Ok(url) = url::Url::parse(&ws) {
                    if let Some(host) = url.host_str() {
                        let port = url.port().unwrap_or(80);
                        let addr = format!("{}:{}", host, port);
                        tokio::net::TcpStream::connect(addr).await.is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .await
            .unwrap_or(false);

            if !ok {
                return Err(anyhow!("HYDRATION_RPC_WS_URL is set but not reachable: {}", ws));
            }

            Ok(HydrationHandle {
                rpc_ws_url: ws,
                signer_uri: signer,
            })
        } else {
            Err(anyhow!("no HYDRATION_RPC_WS_URL in environment"))
        }
    }

    /// Convert to `mpc_node::indexer_hydration::HydrationConfig` for indexer tests.
    pub fn into_indexer_config(self) -> mpc_node::indexer_hydration::HydrationConfig {
        mpc_node::indexer_hydration::HydrationConfig {
            rpc_ws_url: self.rpc_ws_url,
            signer_uri: self.signer_uri.unwrap_or_else(|| String::from("http://127.0.0.1:0")),
            total_timeout: 60,
        }
    }
}
