use crate::backlog::Checkpoint;
use crate::protocol::message::cbor_to_bytes;
use crate::protocol::sync::SyncUpdate;
use crate::protocol::Chain;
use crate::web::{CheckpointResponse, StateView, StatusResponse};

use hyper::StatusCode;
use mpc_keys::hpke::Ciphered;
use reqwest::IntoUrl;
use serde::de::DeserializeOwned;
use serde::Serialize;
use url::Url;

use std::collections::HashMap;
use std::str::Utf8Error;
use std::time::Duration;

#[derive(Debug, Clone, clap::Parser)]
#[group(id = "message_options")]
pub struct Options {
    /// Default timeout used for all outbound requests to other nodes.
    #[clap(long, env("MPC_NODE_TIMEOUT"), default_value = "1000")]
    pub timeout: u64,

    /// Timeout used for fetching the state of a node.
    #[clap(long, env("MPC_NODE_STATE_TIMEOUT"), default_value = "1000")]
    pub state_timeout: u64,

    /// Timeout used for sync requests to other nodes.
    #[clap(long, env("MPC_NODE_SYNC_TIMEOUT"), default_value = "60000")]
    pub sync_timeout: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        vec![
            "--timeout".to_string(),
            self.timeout.to_string(),
            "--state-timeout".to_string(),
            self.state_timeout.to_string(),
            "--sync-timeout".to_string(),
            self.sync_timeout.to_string(),
        ]
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            timeout: 1000,
            state_timeout: 1000,
            sync_timeout: 60000,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("http request was unsuccessful: {0} => {1}")]
    Unsuccessful(StatusCode, String, Option<String>),
    #[error("http client error: {0}")]
    ReqwestClient(#[from] reqwest::Error),
    #[error("http response could not be parsed: {0}")]
    MalformedBody(reqwest::Error),
    #[error("http response body is not valid utf-8: {0}")]
    MalformedResponse(Utf8Error),
    #[error("io error: {0}")]
    Conversion(String),
    #[error("peer returned checkpoint version {0}")]
    MismatchCheckpointVersion(u64),
    #[error("checkpoint payload too large: {size} bytes exceeds the limit of {limit} bytes")]
    PayloadTooLarge { size: usize, limit: usize },
}

#[derive(Debug, Clone)]
pub struct NodeClient {
    http: reqwest::Client,
    options: Options,
}

/// Timeout for a single `/checkpoint` fetch, long enough to transfer the
/// maximum payload size over a slow link.
const CHECKPOINT_FETCH_TIMEOUT: Duration = Duration::from_secs(90);

fn check_checkpoint_version(version: u64) -> Result<(), RequestError> {
    if version != crate::CHECKPOINT_VERSION {
        return Err(RequestError::MismatchCheckpointVersion(version));
    }
    Ok(())
}

fn decode_checkpoint_response(body: &[u8]) -> Result<CheckpointResponse, RequestError> {
    let resp: CheckpointResponse =
        ciborium::from_reader(body).map_err(|err| RequestError::Conversion(err.to_string()))?;
    check_checkpoint_version(resp.version)?;
    Ok(resp)
}

/// Read a response body into memory, refusing payloads above `limit` bytes.
///
/// Checkpoint payloads embed full backlog entries, so a peer with a large
/// backlog (or a misbehaving peer) can send a huge body. Reading it
/// unbounded would let a single response exhaust this node's memory, so the
/// body is streamed and truncated at the limit instead.
async fn read_bounded(mut resp: reqwest::Response, limit: usize) -> Result<Vec<u8>, RequestError> {
    if let Some(size) = resp.content_length() {
        if size > limit as u64 {
            return Err(RequestError::PayloadTooLarge {
                size: size as usize,
                limit,
            });
        }
    }

    let mut buf = Vec::new();
    loop {
        let chunk = resp.chunk().await.map_err(RequestError::ReqwestClient)?;
        let Some(chunk) = chunk else {
            break;
        };
        if buf.len() + chunk.len() > limit {
            return Err(RequestError::PayloadTooLarge {
                size: buf.len() + chunk.len(),
                limit,
            });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

impl NodeClient {
    pub fn new(options: &Options) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_millis(options.timeout))
                .build()
                .unwrap(),
            options: options.clone(),
        }
    }

    fn extract_request_id(resp: &reqwest::Response) -> Option<String> {
        resp.headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string())
    }

    pub async fn post_json<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        url: &Url,
        payload: &T,
    ) -> Result<R, RequestError> {
        let resp = self
            .http
            .post(url.clone())
            .header("content-type", "application/json")
            .json(payload)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            Ok(resp.json::<R>().await?)
        } else {
            // TODO: parse response body and convert to mpc_node::Error type.
            let request_id = Self::extract_request_id(&resp);
            let bytes = resp.bytes().await.map_err(RequestError::MalformedBody)?;
            let resp = std::str::from_utf8(&bytes).map_err(RequestError::MalformedResponse)?;
            tracing::warn!(
                request_id = ?request_id,
                "failed to send a message to {url} with code {status}: {resp}"
            );
            Err(RequestError::Unsuccessful(status, resp.into(), request_id))
        }
    }

    pub async fn post_cbor<T: Serialize + ?Sized>(
        &self,
        url: &Url,
        payload: &T,
    ) -> Result<(), RequestError> {
        let resp = self
            .http
            .post(url.clone())
            .header("content-type", "application/cbor")
            .body(cbor_to_bytes(payload).map_err(|err| RequestError::Conversion(err.to_string()))?)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            // TODO: parse response body and convert to mpc_node::Error type.
            let request_id = Self::extract_request_id(&resp);
            let bytes = resp.bytes().await.map_err(RequestError::MalformedBody)?;
            let resp = std::str::from_utf8(&bytes).map_err(RequestError::MalformedResponse)?;
            Err(RequestError::Unsuccessful(status, resp.into(), request_id))
        }
    }

    pub async fn post_cbor_response<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        url: &Url,
        payload: &T,
        timeout: Duration,
    ) -> Result<R, RequestError> {
        let resp = self
            .http
            .post(url.clone())
            .header("content-type", "application/cbor")
            .body(cbor_to_bytes(payload).map_err(|err| RequestError::Conversion(err.to_string()))?)
            .timeout(timeout)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let body = resp.bytes().await.map_err(RequestError::MalformedBody)?;
            ciborium::from_reader(body.as_ref())
                .map_err(|err| RequestError::Conversion(err.to_string()))
        } else {
            let request_id = Self::extract_request_id(&resp);
            let bytes = resp.bytes().await.map_err(RequestError::MalformedBody)?;
            let resp = std::str::from_utf8(&bytes).map_err(RequestError::MalformedResponse)?;
            tracing::warn!(
                request_id = ?request_id,
                "failed to send a message to {url} with code {status}: {resp}"
            );
            Err(RequestError::Unsuccessful(status, resp.into(), request_id))
        }
    }

    async fn post_msg(&self, url: &Url, msg: &[&Ciphered]) -> Result<(), RequestError> {
        self.post_cbor(url, msg).await
    }

    pub async fn msg(&self, base: impl IntoUrl, msg: &[&Ciphered]) -> Result<(), RequestError> {
        let mut url = base.into_url()?;
        url.set_path("msg");
        self.post_msg(&url, msg).await
    }

    pub async fn state(&self, base: impl IntoUrl) -> Result<StateView, RequestError> {
        let mut url = base.into_url()?;
        url.set_path("state");

        let resp = self
            .http
            .get(url)
            .timeout(Duration::from_millis(self.options.state_timeout))
            .send()
            .await?;

        Ok(resp.json::<StateView>().await?)
    }

    pub async fn status(&self, base: impl IntoUrl) -> Result<StatusResponse, RequestError> {
        let mut url = base.into_url()?;
        url.set_path("status");

        let resp = self
            .http
            .get(url)
            .timeout(Duration::from_millis(self.options.state_timeout))
            .send()
            .await?;

        Ok(resp.json().await?)
    }

    pub async fn sync(
        &self,
        base: impl IntoUrl,
        update: &SyncUpdate,
    ) -> Result<SyncUpdate, RequestError> {
        let mut url = base.into_url()?;
        url.set_path("sync");
        self.post_cbor_response(
            &url,
            update,
            Duration::from_millis(self.options.sync_timeout),
        )
        .await
    }

    pub async fn checkpoint(
        &self,
        base: impl IntoUrl,
        chains: &[Chain],
    ) -> Result<HashMap<Chain, Checkpoint>, RequestError> {
        let mut url = base.into_url()?;
        url.set_path("checkpoint");
        if !chains.is_empty() {
            url.set_query(Some(&format!(
                "query={}",
                chains
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            )));
        };

        let resp = self
            .http
            .get(url)
            .timeout(CHECKPOINT_FETCH_TIMEOUT)
            .send()
            .await?;

        let status = resp.status();
        let request_id = Self::extract_request_id(&resp);
        let body = read_bounded(resp, crate::checkpoint_max_payload_size()).await?;

        if status.is_success() {
            let response = decode_checkpoint_response(body.as_ref())?;
            Ok(response.checkpoints)
        } else {
            let resp = std::str::from_utf8(&body).map_err(RequestError::MalformedResponse)?;
            Err(RequestError::Unsuccessful(status, resp.into(), request_id))
        }
    }

    pub async fn fetch_checkpoint_by_digest(
        &self,
        base: impl IntoUrl,
        chain: Chain,
        digest: [u8; 32],
    ) -> Result<Option<Checkpoint>, RequestError> {
        let mut url = base.into_url()?;
        url.set_path("checkpoint");
        url.set_query(Some(&format!(
            "query={}:0x{}",
            chain.as_str(),
            hex::encode(digest)
        )));

        let resp = self
            .http
            .get(url)
            .timeout(CHECKPOINT_FETCH_TIMEOUT)
            .send()
            .await?;

        let status = resp.status();
        let request_id = Self::extract_request_id(&resp);
        let body = read_bounded(resp, crate::checkpoint_max_payload_size()).await?;

        if status.is_success() {
            let response = decode_checkpoint_response(body.as_ref())?;
            Ok(response.checkpoints.get(&chain).cloned())
        } else {
            let resp = std::str::from_utf8(&body).map_err(RequestError::MalformedResponse)?;
            Err(RequestError::Unsuccessful(status, resp.into(), request_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_versioned_checkpoint_responses_decode() {
        let mut checkpoints = HashMap::new();
        checkpoints.insert(Chain::Ethereum, Checkpoint::empty(Chain::Ethereum));

        let versioned = CheckpointResponse {
            version: crate::CHECKPOINT_VERSION,
            checkpoints: checkpoints.clone(),
        };
        let mut versioned_body = Vec::new();
        ciborium::into_writer(&versioned, &mut versioned_body).unwrap();
        assert_eq!(
            decode_checkpoint_response(&versioned_body).unwrap().version,
            crate::CHECKPOINT_VERSION
        );

        #[derive(serde::Serialize)]
        struct MissingVersionResponse {
            checkpoints: HashMap<Chain, Checkpoint>,
        }

        let mut missing_version_body = Vec::new();
        ciborium::into_writer(
            &MissingVersionResponse { checkpoints },
            &mut missing_version_body,
        )
        .unwrap();

        let decoded_missing = decode_checkpoint_response(&missing_version_body).unwrap();
        assert_eq!(decoded_missing.version, 0);

        let mut legacy_body = Vec::new();
        ciborium::into_writer(&HashMap::<Chain, Checkpoint>::new(), &mut legacy_body).unwrap();
        assert!(decode_checkpoint_response(&legacy_body).is_err());
    }

    #[tokio::test]
    async fn test_fetch_checkpoint_reports_newer_version() {
        let mut server = mockito::Server::new_async().await;
        let response = CheckpointResponse {
            version: crate::CHECKPOINT_VERSION + 1,
            checkpoints: HashMap::new(),
        };
        let mut body = Vec::new();
        ciborium::into_writer(&response, &mut body).unwrap();
        let mock = server
            .mock("GET", "/checkpoint")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/cbor")
            .with_body(body)
            .create_async()
            .await;

        let client = NodeClient::new(&Options::default());
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            client.fetch_checkpoint_by_digest(server.url(), Chain::Ethereum, [0u8; 32]),
        )
        .await
        .expect("newer checkpoint version should not stall");

        assert!(matches!(
            result,
            Err(RequestError::MismatchCheckpointVersion(version))
                if version == crate::CHECKPOINT_VERSION + 1
        ));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_read_bounded_rejects_oversized_content_length() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/checkpoint")
            .with_status(200)
            .with_header("content-type", "application/cbor")
            .with_body(vec![0u8; 8192])
            .create_async()
            .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/checkpoint", server.url()))
            .send()
            .await
            .unwrap();
        let err = read_bounded(resp, 1024).await.unwrap_err();

        assert_eq!(
            err.to_string(),
            "checkpoint payload too large: 8192 bytes exceeds the limit of 1024 bytes"
        );
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_read_bounded_streams_and_rejects_oversized_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limit = 100;

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Drain the request so dropping the socket at the end sends a
            // clean FIN instead of an RST.
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.as_slice().windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/cbor\r\ntransfer-encoding: chunked\r\n\r\n",
                )
                .await
                .unwrap();
            socket
                .write_all(format!("{:X}\r\n", 4096).as_bytes())
                .await
                .unwrap();
            socket.write_all(&vec![0u8; 4096]).await.unwrap();
            socket.write_all(b"\r\n0\r\n\r\n").await.unwrap();
        });

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{addr}/checkpoint"))
            .send()
            .await
            .unwrap();
        let err = read_bounded(resp, limit).await.unwrap_err();
        assert!(
            matches!(
                err,
                RequestError::PayloadTooLarge { size, limit: l } if size > limit && l == limit
            ),
            "unexpected error: {err:?}"
        );
        server.await.unwrap();
    }
}
