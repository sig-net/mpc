use crate::protocol::contract::primitives::Participants;
use crate::protocol::message::SignedMessage;
use crate::protocol::MpcMessage;
use crate::web::StateView;
use cait_sith::protocol::Participant;
use mpc_contract::config::ProtocolConfig;
use mpc_keys::hpke::Ciphered;
use reqwest::IntoUrl;
use std::collections::{HashMap, HashSet, VecDeque};
use std::str::Utf8Error;
use std::time::{Duration, Instant};
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

// TODO: add in retry logic either in struct or at call site.
// TODO: add check for participant list to see if the messages to be sent are still valid.
pub struct MessageQueue {
    client: NodeClient,
    deque: VecDeque<(Participant, MpcMessage, Instant)>,
    seen_counts: HashSet<String>,
}

impl MessageQueue {
    pub fn new(client: NodeClient) -> Self {
        Self {
            client,
            deque: VecDeque::default(),
            seen_counts: HashSet::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.deque.len()
    }

    pub fn is_empty(&self) -> bool {
        self.deque.is_empty()
    }

    pub fn push(&mut self, to: Participant, msg: MpcMessage) {
        self.deque.push_back((to, msg, Instant::now()));
    }

    pub async fn send_encrypted(
        &mut self,
        from: Participant,
        sign_sk: &near_crypto::SecretKey,
        active: &Participants,
        cfg: &ProtocolConfig,
    ) -> Vec<SendError> {
        let mut failed = VecDeque::new();
        let mut errors = Vec::new();
        let mut participant_counter = HashMap::new();

        let outer = Instant::now();
        let uncompacted = self.deque.len();
        let mut encrypted = HashMap::new();
        while let Some((id, msg, instant)) = self.deque.pop_front() {
            if instant.elapsed() > timeout(&msg, cfg) {
                errors.push(SendError::Timeout(format!(
                    "{} message has timed out for node={id:?}",
                    msg.typename(),
                )));
                continue;
            }

            let Some(info) = active.get(&id) else {
                let counter = participant_counter.entry(id).or_insert(0);
                *counter += 1;
                failed.push_back((id, msg, instant));
                continue;
            };

            let encrypted_msg = match SignedMessage::encrypt(&msg, from, sign_sk, &info.cipher_pk) {
                Ok(encrypted) => encrypted,
                Err(err) => {
                    errors.push(SendError::EncryptionError(err.to_string()));
                    continue;
                }
            };
            let encrypted = encrypted.entry(info.id).or_insert_with(Vec::new);
            encrypted.push((encrypted_msg, (id, msg, instant)));
        }

        let mut compacted = 0;
        for (id, encrypted) in encrypted {
            for partition in partition_ciphered_256kb(encrypted) {
                let (encrypted_partition, msgs): (Vec<_>, Vec<_>) = partition.into_iter().unzip();
                // guaranteed to unwrap due to our previous loop check:
                let info = active.get(&Participant::from(id)).unwrap();
                let account_id = &info.account_id;
                let number_of_messages = encrypted_partition.len() as f64;

                let start = Instant::now();
                crate::metrics::NUM_SEND_ENCRYPTED_TOTAL
                    .with_label_values(&[account_id.as_str()])
                    .inc_by(number_of_messages);
                if let Err(err) = self.client.msg(&info.url, &encrypted_partition).await {
                    crate::metrics::NUM_SEND_ENCRYPTED_FAILURE
                        .with_label_values(&[account_id.as_str()])
                        .inc_by(number_of_messages);
                    crate::metrics::FAILED_SEND_ENCRYPTED_LATENCY
                        .with_label_values(&[account_id.as_str()])
                        .observe(start.elapsed().as_millis() as f64);

                    // since we failed, put back all the messages related to this
                    failed.extend(msgs);
                    errors.push(err);
                } else {
                    compacted += msgs.len();
                    crate::metrics::SEND_ENCRYPTED_LATENCY
                        .with_label_values(&[account_id.as_str()])
                        .observe(start.elapsed().as_millis() as f64);
                }
            }
        }

        if uncompacted > 0 {
            tracing::debug!(
                uncompacted,
                compacted,
                "{from:?} sent messages in {:?};",
                outer.elapsed()
            );
        }
        // only add the participant count if it hasn't been seen before.
        let counts = format!("{participant_counter:?}");
        if !participant_counter.is_empty() && self.seen_counts.insert(counts.clone()) {
            errors.push(SendError::ParticipantNotAlive(format!(
                "participants not responding: {counts:?}",
            )));
        }

        // Add back the failed attempts for next time.
        self.deque = failed;
        if !errors.is_empty() {
            tracing::warn!("got errors when sending encrypted messages: {errors:?}");
        }
        errors
    }
}

/// Encrypted message with a reference to the old message. Only the ciphered portion of this
/// type will be sent over the wire, while the original message is kept just in case things
/// go wrong somewhere and the message needs to be requeued to be sent later.
type EncryptedMessage = (Ciphered, (Participant, MpcMessage, Instant));

fn partition_ciphered_256kb(encrypted: Vec<EncryptedMessage>) -> Vec<Vec<EncryptedMessage>> {
    let mut result = Vec::new();
    let mut current_partition = Vec::new();
    let mut current_size: usize = 0;

    for ciphered in encrypted {
        let bytesize = ciphered.0.text.len();
        if current_size + bytesize > 256 * 1024 {
            // If adding this byte vector exceeds 256kb, start a new partition
            result.push(current_partition);
            current_partition = Vec::new();
            current_size = 0;
        }
        current_partition.push(ciphered);
        current_size += bytesize;
    }

    if !current_partition.is_empty() {
        // Add the last partition
        result.push(current_partition);
    }

    result
}

fn timeout(msg: &MpcMessage, cfg: &ProtocolConfig) -> Duration {
    match msg {
        MpcMessage::Generating(_) => Duration::from_millis(cfg.message_timeout),
        MpcMessage::Resharing(_) => Duration::from_millis(cfg.message_timeout),
        MpcMessage::Triple(_) => Duration::from_millis(cfg.triple.generation_timeout),
        MpcMessage::Presignature(_) => Duration::from_millis(cfg.presignature.generation_timeout),
        MpcMessage::Signature(_) => Duration::from_millis(cfg.signature.generation_timeout),
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::message::GeneratingMessage;
    use crate::protocol::MpcMessage;

    #[test]
    fn test_sending_encrypted_message() {
        let associated_data = b"";
        let (sk, pk) = mpc_keys::hpke::generate();
        let starting_message = MpcMessage::Generating(GeneratingMessage {
            from: cait_sith::protocol::Participant::from(0),
            data: vec![],
        });

        let message = serde_json::to_vec(&starting_message).unwrap();
        let message = pk.encrypt(&message, associated_data).unwrap();

        let message = serde_json::to_vec(&message).unwrap();
        let cipher = serde_json::from_slice(&message).unwrap();
        let message = sk.decrypt(&cipher, associated_data).unwrap();
        let message: MpcMessage = serde_json::from_slice(&message).unwrap();

        assert_eq!(starting_message, message);
    }
}
