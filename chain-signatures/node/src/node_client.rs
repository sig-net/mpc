use crate::web::StateView;
use mpc_keys::hpke::Ciphered;
use reqwest::IntoUrl;
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
pub enum SendError {
    #[error("http request was unsuccessful: {0}")]
    Unsuccessful(String),
    #[error("serialization unsuccessful: {0}")]
    DataConversionError(serde_json::Error),
    #[error("http client error: {0}")]
    ReqwestClientError(#[from] reqwest::Error),
    #[error("http response could not be parsed: {0}")]
    ReqwestBodyError(reqwest::Error),
    #[error("http response body is not valid utf-8: {0}")]
    MalformedResponse(Utf8Error),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("http request timeout: {0}")]
    Timeout(String),
    #[error("participant is not alive: {0}")]
    ParticipantNotAlive(String),
    #[error("cannot convert into json: {0}")]
    Conversion(#[from] serde_json::Error),
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

    async fn post_msg(&self, url: &Url, msg: &[Ciphered]) -> Result<(), SendError> {
        let resp = self
            .http
            .post(url.clone())
            .header("content-type", "application/json")
            .json(&msg)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let bytes = resp.bytes().await.map_err(SendError::ReqwestBodyError)?;
            let resp = std::str::from_utf8(&bytes).map_err(SendError::MalformedResponse)?;
            tracing::warn!("failed to send a message to {url} with code {status}: {resp}");
            Err(SendError::Unsuccessful(resp.into()))
        }
    }

    pub async fn msg(&self, base: impl IntoUrl, msg: &[Ciphered]) -> Result<(), SendError> {
        let mut url = base.into_url()?;
        url.set_path("msg");

        let strategy = ExponentialBackoff::from_millis(10).map(jitter).take(3);
        Retry::spawn(strategy, || self.post_msg(&url, msg)).await
    }

    pub async fn msg_empty(&self, base: impl IntoUrl) -> Result<(), SendError> {
        self.msg(base, &[]).await
    }

    pub async fn state(&self, base: impl IntoUrl) -> Result<StateView, SendError> {
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
}
