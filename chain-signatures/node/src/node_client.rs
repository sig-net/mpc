use crate::protocol::sync::{SyncUpdate, SyncView};
use crate::web::StateView;
use hyper::StatusCode;
use mpc_keys::hpke::Ciphered;
use reqwest::IntoUrl;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::str::Utf8Error;
use std::time::Duration;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;
use url::Url;

#[derive(Debug, Clone, clap::Parser)]
#[group(id = "message_options")]
pub struct Options {
    /// Default timeout used for all outbound requests to other nodes.
    #[clap(long, env("MPC_NODE_TIMEOUT"), default_value = "1000")]
    pub timeout: u64,

    /// Timeout used for fetching the state of a node.
    #[clap(long, env("MPC_NODE_STATE_TIMEOUT"), default_value = "1000")]
    pub state_timeout: u64,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        vec![
            "--timeout".to_string(),
            self.timeout.to_string(),
            "--state-timeout".to_string(),
            self.state_timeout.to_string(),
        ]
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("http request was unsuccessful: {0} => {1}")]
    Unsuccessful(StatusCode, String),
    #[error("http client error: {0}")]
    ReqwestClient(#[from] reqwest::Error),
    #[error("http response could not be parsed: {0}")]
    MalformedBody(reqwest::Error),
    #[error("http response body is not valid utf-8: {0}")]
    MalformedResponse(Utf8Error),
}

#[derive(Debug, Clone)]
pub struct NodeClient {
    http: reqwest::Client,
    options: Options,
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
            let bytes = resp.bytes().await.map_err(RequestError::MalformedBody)?;
            let resp = std::str::from_utf8(&bytes).map_err(RequestError::MalformedResponse)?;
            tracing::warn!("failed to send a message to {url} with code {status}: {resp}");
            Err(RequestError::Unsuccessful(status, resp.into()))
        }
    }

    async fn post_msg(&self, url: &Url, msg: &[&Ciphered]) -> Result<(), RequestError> {
        self.post_json(url, msg).await
    }

    pub async fn msg(&self, base: impl IntoUrl, msg: &[&Ciphered]) -> Result<(), RequestError> {
        let mut url = base.into_url()?;
        url.set_path("msg");

        let strategy = ExponentialBackoff::from_millis(10).map(jitter).take(3);
        Retry::spawn(strategy, || self.post_msg(&url, msg)).await
    }

    pub async fn msg_empty(&self, base: impl IntoUrl) -> Result<(), RequestError> {
        self.msg(base, &[]).await
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

    pub async fn sync(
        &self,
        base: impl IntoUrl,
        update: &SyncUpdate,
    ) -> Result<SyncView, RequestError> {
        let mut url = base.into_url()?;
        url.set_path("sync");

        self.post_json(&url, update).await
    }
}
