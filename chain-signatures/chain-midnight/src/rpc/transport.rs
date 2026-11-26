//! Request-only HTTP transport: the midnight node's raw JSON-RPC client, its
//! response caps, and the backend rotation a failed request relies on.

use anyhow::Context as _;
use jsonrpsee::core::client::{ClientT as _, Error as JsonrpseeClientError};
use jsonrpsee::core::traits::ToRpcParams;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use subxt::backend::rpc::{RawRpcFuture, RawRpcSubscription, RawValue, RpcClient, RpcClientT};
use subxt::ext::subxt_rpcs::{Error as RawRpcError, UserError};
use subxt::utils::H256;

use crate::config::{MidnightConfig, RpcConfig};
use crate::types::BlockHash;

/// Largest caller contract state the protocol admits, in decoded bytes. Every node
/// applies the same limit, so admission does not depend on any node's RPC cap. The
/// node serves the state as hex inside JSON, so the response is a little over twice
/// this; the limit must sit below half the RPC node's response cap (15 MiB by
/// default) and well below half of [`MAX_RESPONSE_SIZE`].
pub(super) const MAX_CALLER_STATE_BYTES: usize = 7 * 1024 * 1024;

/// The client's own response cap. A constant rather than a config field: a response
/// the client refuses is over 16 MiB of state, so over [`MAX_CALLER_STATE_BYTES`],
/// and that verdict is only safe if every node refuses at the same size.
pub(super) const MAX_RESPONSE_SIZE: u32 = 32 * 1024 * 1024;

/// Generous bound on the JSON around the hex state in a `midnight_contractState`
/// response.
const RESPONSE_ENVELOPE_BYTES: usize = 1024;

/// Smallest RPC node response cap that fits every admissible state: the hex doubles
/// the bytes, plus the envelope. A size refusal under a cap at least this large
/// proves the state is over the limit.
pub(super) const MIN_PROVING_RESPONSE_CAP: usize =
    2 * MAX_CALLER_STATE_BYTES + RESPONSE_ENVELOPE_BYTES;

// The client's own refusal proves excess only if the client admits every proving cap.
const _: () = assert!(MIN_PROVING_RESPONSE_CAP <= MAX_RESPONSE_SIZE as usize);

struct Params(Option<Box<RawValue>>);

impl ToRpcParams for Params {
    fn to_rpc_params(self) -> Result<Option<Box<RawValue>>, serde_json::Error> {
        Ok(self.0)
    }
}

/// Request-only jsonrpsee HTTP transport behind Subxt's raw client seam.
///
/// A load balancer keeps one keep-alive connection on one node, so a node that has
/// fallen out of sync would fail every request for as long as the connection lives. A
/// failed request therefore replaces the client and its connection pool, and the next
/// request dials afresh.
struct HttpRpcClient {
    node_url: String,
    config: RpcConfig,
    max_response_size: u32,
    /// The client plus a generation, so concurrent failures replace it once.
    current: std::sync::RwLock<(u64, HttpClient)>,
}

impl HttpRpcClient {
    fn new(node_url: &str, config: &RpcConfig) -> anyhow::Result<Self> {
        Self::with_response_cap(node_url, config, MAX_RESPONSE_SIZE)
    }

    fn with_response_cap(
        node_url: &str,
        config: &RpcConfig,
        max_response_size: u32,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            current: std::sync::RwLock::new((
                0,
                build_http_client(node_url, config, max_response_size)?,
            )),
            node_url: node_url.to_owned(),
            config: config.clone(),
            max_response_size,
        })
    }

    fn current(&self) -> (u64, HttpClient) {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Replaces the client generation `failed` unless another failure already has. The
    /// build loads TLS roots, so it runs outside the lock every request takes. A client
    /// that cannot be rebuilt is kept: it is no worse than before the failure.
    fn replace(&self, failed: u64) {
        if self.current().0 != failed {
            return;
        }
        let client = match build_http_client(&self.node_url, &self.config, self.max_response_size) {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "keeping the midnight HTTP RPC client after a failed request"
                );
                return;
            }
        };
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.0 != failed {
            return;
        }
        let generation = current.0 + 1;
        *current = (generation, client);
        drop(current);
        tracing::info!(
            generation,
            "replaced the midnight HTTP RPC client after a failed request"
        );
    }
}

fn build_http_client(
    node_url: &str,
    config: &RpcConfig,
    max_response_size: u32,
) -> anyhow::Result<HttpClient> {
    HttpClientBuilder::default()
        .max_response_size(max_response_size)
        .request_timeout(config.request_timeout)
        .build(node_url)
        .context("failed to build the midnight HTTP RPC client")
}

impl RpcClientT for HttpRpcClient {
    fn request_raw<'a>(
        &'a self,
        method: &'a str,
        params: Option<Box<RawValue>>,
    ) -> RawRpcFuture<'a, Box<RawValue>> {
        Box::pin(async move {
            let (generation, client) = self.current();
            let result = client.request(method, Params(params)).await;
            if result.is_err() {
                self.replace(generation);
            }
            result.map_err(|error| match error {
                JsonrpseeClientError::Call(error) => RawRpcError::User(UserError {
                    code: error.code(),
                    message: error.message().to_owned(),
                    data: error.data().map(ToOwned::to_owned),
                }),
                error => RawRpcError::Client(Box::new(error)),
            })
        })
    }

    fn subscribe_raw<'a>(
        &'a self,
        _sub: &'a str,
        _params: Option<Box<RawValue>>,
        _unsub: &'a str,
    ) -> RawRpcFuture<'a, RawRpcSubscription> {
        Box::pin(async {
            Err(RawRpcError::Client(Box::new(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "midnight HTTP RPC transport does not support subscriptions",
            ))))
        })
    }
}

/// Subxt↔domain hash bridging; the impls are crate-scoped, so every rpc module
/// that holds both types uses them without an import.
impl From<H256> for BlockHash {
    fn from(hash: H256) -> Self {
        BlockHash::from_bytes(hash.0)
    }
}

impl From<BlockHash> for H256 {
    fn from(hash: BlockHash) -> Self {
        H256(*hash.as_bytes())
    }
}

pub(super) fn connect_http(config: &MidnightConfig) -> anyhow::Result<RpcClient> {
    connect_http_endpoint(config.node_url.as_str(), &config.rpc)
}

pub(super) fn connect_http_endpoint(
    node_url: &str,
    config: &RpcConfig,
) -> anyhow::Result<RpcClient> {
    Ok(RpcClient::new(HttpRpcClient::new(node_url, config)?))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::support::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use crate::rpc::reads::{NETWORK_ID_ENTRY, Reads, is_oversized_contract_state};
    use crate::types::BlockHash;
    use jsonrpsee::RpcModule;
    use jsonrpsee::server::ServerBuilder;
    use jsonrpsee::types::ErrorObjectOwned;
    use jsonrpsee::types::error::INVALID_PARAMS_CODE;
    use serde_json::json;
    use subxt::SubstrateConfig;
    use subxt::backend::legacy::LegacyRpcMethods;
    use subxt::backend::legacy::rpc_methods::NumberOrHex;
    use subxt::ext::subxt_rpcs::rpc_params;
    use subxt::utils::H256;

    /// A keep-alive HTTP server whose first connection reaches a node that has fallen
    /// out of sync: every request on that connection fails as such a node fails, and
    /// every later connection answers like a healthy node. A load balancer keeps one
    /// connection on one backend, as this server does.
    async fn stale_first_backend_server()
    -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind keep-alive HTTP server");
        let address = listener
            .local_addr()
            .expect("keep-alive HTTP server address");
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.expect("accept HTTP connection");
                let stale = accepted.fetch_add(1, Ordering::SeqCst) == 0;
                tokio::spawn(serve_keep_alive(stream, stale));
            }
        });
        (address, connections, server)
    }

    async fn serve_keep_alive(mut stream: tokio::net::TcpStream, stale: bool) {
        let mut buffer = Vec::new();
        loop {
            let body_start = loop {
                if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
                let mut chunk = [0; 1024];
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                }
            };
            let headers = String::from_utf8_lossy(&buffer[..body_start]).to_ascii_lowercase();
            let length: usize = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map(|value| value.trim().parse().expect("numeric content-length"))
                .unwrap_or(0);
            while buffer.len() < body_start + length {
                let mut chunk = [0; 1024];
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                }
            }
            let request: serde_json::Value =
                serde_json::from_slice(&buffer[body_start..body_start + length])
                    .expect("JSON-RPC request body");
            buffer.drain(..body_start + length);
            let reply = if stale {
                json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "error": {
                        "code": INVALID_PARAMS_CODE,
                        "message": "Unable to get requested contract state",
                    },
                })
            } else {
                json!({"jsonrpc": "2.0", "id": request["id"], "result": hash_of_byte(0x22)})
            }
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{reply}",
                reply.len()
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    #[tokio::test]
    async fn a_failed_request_moves_off_the_backend_its_connection_reached() {
        let (address, connections, server) = stale_first_backend_server().await;
        let reads = Reads::new(
            connect_http(&http_config(address)).expect("build request-only client"),
            Duration::from_secs(1),
            attempts(0),
        );

        let stale = reads.finalized_head().await;
        let recovered = reads.finalized_head().await;
        let kept = reads.finalized_head().await;
        server.abort();

        stale.expect_err("the first connection reaches the stale backend");
        for read in [recovered, kept] {
            let head = read.expect("a request after the failure reached the stale backend again");
            assert_eq!(BlockHash::from(head).to_string(), hash_of_byte(0x22));
        }
        assert_eq!(
            connections.load(Ordering::SeqCst),
            2,
            "a failure must open one new connection and a success must keep it"
        );
    }

    #[tokio::test]
    async fn a_retried_read_recovers_from_the_backend_its_connection_reached() {
        let (address, connections, server) = stale_first_backend_server().await;
        let reads = Reads::new(
            connect_http(&http_config(address)).expect("build request-only client"),
            Duration::from_secs(1),
            attempts(2),
        );

        let head = reads.finalized_head().await;
        server.abort();

        let head = head.expect("the retry reached the stale backend again");
        assert_eq!(BlockHash::from(head).to_string(), hash_of_byte(0x22));
        assert_eq!(connections.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_late_failure_does_not_replace_the_client_that_replaced_its_own() {
        let client = HttpRpcClient::new("http://127.0.0.1:1", &RpcConfig::default())
            .expect("build request-only client");

        client.replace(0);
        client.replace(0);

        assert_eq!(client.current().0, 1);
    }

    #[tokio::test]
    async fn http_adapter_drives_legacy_state_and_raw_requests() {
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_method("chain_getFinalizedHead", |_, _, _| hash_of_byte(0x55))
            .expect("register finalized head");
        module
            .register_method("chain_getHeader", |_, _, _| {
                json!({
                    "parentHash": hash_of_byte(0x44),
                    "number": "0x2a",
                    "stateRoot": hash_of_byte(0x66),
                    "extrinsicsRoot": hash_of_byte(0x77),
                    "digest": { "logs": [] }
                })
            })
            .expect("register header");
        module
            .register_method("chain_getBlockHash", |_, _, _| hash_of_byte(0x55))
            .expect("register block hash");
        module
            .register_method("state_call", |_, _, _| "0x0102")
            .expect("register state call");
        module
            .register_method("midnight_contractState", |_, _, _| "0xcafe")
            .expect("register contract state");
        module
            .register_method("fails", |_, _, _| -> Result<(), ErrorObjectOwned> {
                Err(ErrorObjectOwned::owned(
                    -32042,
                    "kept message",
                    Some(json!({"detail": "kept data"})),
                ))
            })
            .expect("register failing method");
        let _handle = server.start(module);

        let rpc = connect_http(&http_config(address)).expect("build HTTP transport");
        let legacy = LegacyRpcMethods::<SubstrateConfig>::new(rpc.clone());
        let finalized = legacy
            .chain_get_finalized_head()
            .await
            .expect("finalized head");
        assert_eq!(finalized, H256([0x55; 32]));
        let header = legacy
            .chain_get_header(Some(finalized))
            .await
            .expect("header")
            .expect("header present");
        assert_eq!(u64::from(header.number), 42);
        assert_eq!(header.parent_hash, H256([0x44; 32]));
        assert_eq!(
            legacy
                .chain_get_block_hash(Some(NumberOrHex::Number(42)))
                .await
                .expect("block hash"),
            Some(finalized)
        );
        assert_eq!(
            legacy
                .state_call(NETWORK_ID_ENTRY, Some(&[]), Some(finalized))
                .await
                .expect("state call"),
            vec![1, 2]
        );
        let state: String = rpc
            .request("midnight_contractState", rpc_params![ADDRESS, AT_HASH])
            .await
            .expect("raw contract-state request");
        assert_eq!(state, "0xcafe");

        let err = rpc
            .request::<String>("fails", rpc_params![])
            .await
            .expect_err("server user error must escape");
        let RawRpcError::User(user) = err else {
            panic!("expected Subxt user error, got {err:?}");
        };
        assert_eq!(user.code, -32042);
        assert_eq!(user.message, "kept message");
        assert_eq!(
            user.data.as_deref().map(RawValue::get),
            Some(r#"{"detail":"kept data"}"#)
        );
    }

    #[tokio::test]
    async fn http_adapter_enforces_request_timeout_and_response_cap() {
        let server = ServerBuilder::default()
            .build("127.0.0.1:0")
            .await
            .expect("bind HTTP rpc server");
        let address = server.local_addr().expect("HTTP rpc server address");
        let mut module = RpcModule::new(());
        module
            .register_async_method("park", |_, _, _| async {
                std::future::pending::<String>().await
            })
            .expect("register parked method");
        module
            .register_method("midnight_contractState", |_, _, _| "ab".repeat(4096))
            .expect("register state method");
        let _handle = server.start(module);

        let mut timeout_config = http_config(address);
        timeout_config.rpc.request_timeout = Duration::from_millis(25);
        let timeout_rpc = connect_http(&timeout_config).expect("build timeout transport");
        let timeout_error = tokio::time::timeout(
            Duration::from_millis(250),
            timeout_rpc.request::<String>("park", rpc_params![]),
        )
        .await
        .expect("transport did not enforce its request timeout")
        .expect_err("parked request must time out");
        assert!(
            timeout_error.to_string().contains("Request timeout"),
            "unexpected timeout error: {timeout_error}"
        );

        // A response over the client cap is the real jsonrpsee refusal, classified as
        // a definitive oversized state and not retried.
        let capped_config = http_config(address);
        let capped_rpc = RpcClient::new(
            HttpRpcClient::with_response_cap(
                capped_config.node_url.as_str(),
                &capped_config.rpc,
                128,
            )
            .expect("build capped transport"),
        );
        let reads = Reads::new(capped_rpc, READ_TIMEOUT, attempts(2));
        let capped_error = reads
            .contract_state(&test_address(), &test_at_hash())
            .await
            .expect_err("oversized response must be refused");
        assert!(
            is_oversized_contract_state(&capped_error),
            "unexpected response cap error: {capped_error:#}"
        );
    }

    /// A body without `Content-Length` overflows the client cap while streaming,
    /// a different jsonrpsee error from the up-front refusal; both are drops.
    #[tokio::test]
    async fn chunked_response_over_the_client_cap_is_a_drop() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind raw HTTP server");
        let address = listener.local_addr().expect("raw HTTP server address");
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept HTTP request");
                read_http_request(&mut stream).await;
                let body = format!(
                    r#"{{"jsonrpc":"2.0","id":0,"result":"{}"}}"#,
                    "ab".repeat(4096)
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
                     {:x}\r\n{body}\r\n0\r\n\r\n",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write chunked response");
            }
        });

        let config = http_config(address);
        let rpc = RpcClient::new(
            HttpRpcClient::with_response_cap(config.node_url.as_str(), &config.rpc, 128)
                .expect("build capped transport"),
        );
        let reads = Reads::new(rpc, READ_TIMEOUT, attempts(2));
        let err = reads
            .contract_state(&test_address(), &test_at_hash())
            .await
            .expect_err("the streamed body overflows the client cap");
        assert!(
            is_oversized_contract_state(&err),
            "unexpected streaming cap error: {err:#}"
        );
        server.abort();
    }

    /// Reads one HTTP request to its end, so closing the socket after the reply
    /// sends FIN rather than an RST that could discard the reply.
    async fn read_http_request(stream: &mut tokio::net::TcpStream) {
        let mut request = Vec::new();
        let mut byte = [0; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream
                .read_exact(&mut byte)
                .await
                .expect("read HTTP header");
            request.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
        let body_len: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .map_or(0, |value| value.trim().parse().expect("content-length"));
        let mut body = vec![0; body_len];
        stream.read_exact(&mut body).await.expect("read HTTP body");
    }
}
