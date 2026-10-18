//! The indexer's `dustLedgerEvents` subscription over `graphql-transport-ws`: every
//! DUST ledger event, in order, with the newest id the indexer has seen.

use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::{SinkExt as _, StreamExt as _};
use mpc_utils::task::AbortOnDrop;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

/// A connection that answers no keepalive within this long is dead.
const KEEPALIVE: Duration = Duration::from_secs(30);
/// Events buffered between the socket and the replay.
const BUFFER: usize = 4096;

const SUBSCRIPTION: &str =
    "subscription DustLedgerEvents($id: Int) { dustLedgerEvents(id: $id) { id maxId raw } }";

/// One event as the indexer serves it: the ledger's own tagged `Event` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DustEventUpdate {
    pub id: u64,
    pub max_id: u64,
    pub raw: Vec<u8>,
}

#[async_trait]
pub(crate) trait DustEventSource: Send + Sync + 'static {
    /// Every event from id `from` on, inclusive, or from the first event when `None`.
    /// The stream ends or yields an error when the source can no longer deliver.
    async fn subscribe(
        &self,
        from: Option<u64>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>>;
}

pub(crate) struct IndexerDustEvents {
    url: String,
}

impl IndexerDustEvents {
    pub(crate) fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireEvent {
    id: u64,
    max_id: u64,
    raw: String,
}

#[async_trait]
impl DustEventSource for IndexerDustEvents {
    async fn subscribe(
        &self,
        from: Option<u64>,
    ) -> anyhow::Result<BoxStream<'static, anyhow::Result<DustEventUpdate>>> {
        let mut request = self
            .url
            .as_str()
            .into_client_request()
            .context("the indexer subscription URL is not a websocket URL")?;
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("graphql-transport-ws"),
        );
        let connect = tokio_tungstenite::connect_async_tls_with_config(
            request,
            None,
            false,
            Some(tokio_tungstenite::Connector::Rustls(tls()?)),
        );
        let (mut socket, _) = tokio::time::timeout(KEEPALIVE, connect)
            .await
            .context("timed out connecting to the indexer subscription")?
            .context("connecting to the indexer subscription")?;
        socket
            .send(Message::text(
                json!({ "type": "connection_init" }).to_string(),
            ))
            .await
            .context("opening the indexer subscription")?;
        loop {
            let frame = tokio::time::timeout(KEEPALIVE, socket.next())
                .await
                .context("the indexer did not acknowledge the subscription")?
                .context("the indexer closed the subscription before acknowledging it")?
                .context("reading the indexer's acknowledgement")?;
            if let Message::Text(text) = frame {
                let message: serde_json::Value = serde_json::from_str(&text)
                    .context("the indexer sent a message that is not JSON")?;
                match message["type"].as_str() {
                    Some("connection_ack") => break,
                    Some("ping") => {
                        socket
                            .send(Message::text(json!({ "type": "pong" }).to_string()))
                            .await?;
                    }
                    _ => anyhow::bail!("the indexer refused the subscription: {text}"),
                }
            }
        }
        socket
            .send(Message::text(
                json!({
                    "id": "1",
                    "type": "subscribe",
                    "payload": { "query": SUBSCRIPTION, "variables": { "id": from } },
                })
                .to_string(),
            ))
            .await
            .context("subscribing to the DUST ledger events")?;

        let (sender, receiver) = mpsc::channel(BUFFER);
        let pump = AbortOnDrop(tokio::spawn(async move {
            if let Err(error) = pump(socket, &sender).await {
                let _ = sender.send(Err(error)).await;
            }
        }));
        Ok(
            futures_util::stream::unfold((receiver, pump), |(mut receiver, pump)| async move {
                receiver.recv().await.map(|item| (item, (receiver, pump)))
            })
            .boxed(),
        )
    }
}

fn tls() -> anyhow::Result<std::sync::Arc<rustls::ClientConfig>> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("configuring TLS for the indexer subscription")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(std::sync::Arc::new(config))
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Forwards events until the socket fails, the subscription ends, or a keepalive
/// goes unanswered: a silent connection is otherwise indistinguishable from a quiet
/// chain.
async fn pump(
    mut socket: Socket,
    sender: &mpsc::Sender<anyhow::Result<DustEventUpdate>>,
) -> anyhow::Result<()> {
    let mut keepalive = tokio::time::interval(KEEPALIVE);
    keepalive.tick().await;
    let mut answered = true;
    loop {
        tokio::select! {
            _ = keepalive.tick() => {
                anyhow::ensure!(answered, "the indexer subscription answered no keepalive");
                answered = false;
                socket.send(Message::Ping(Vec::new().into())).await.context("pinging the indexer")?;
            }
            frame = socket.next() => {
                let frame = frame
                    .context("the indexer closed the subscription")?
                    .context("reading the indexer subscription")?;
                answered = true;
                let Message::Text(text) = frame else {
                    if let Message::Close(close) = frame {
                        anyhow::bail!("the indexer closed the subscription: {close:?}");
                    }
                    continue;
                };
                let message: serde_json::Value = serde_json::from_str(&text)
                    .context("the indexer sent a message that is not JSON")?;
                match message["type"].as_str() {
                    Some("next") => {
                        if let Some(errors) = message["payload"].get("errors") {
                            anyhow::bail!("the DUST event subscription failed: {errors}");
                        }
                        let event: WireEvent =
                            serde_json::from_value(message["payload"]["data"]["dustLedgerEvents"].clone())
                                .context("the indexer sent a malformed DUST event")?;
                        let raw = hex::decode(event.raw.trim_start_matches("0x"))
                            .with_context(|| format!("DUST event {} is not hex", event.id))?;
                        let update = DustEventUpdate { id: event.id, max_id: event.max_id, raw };
                        if sender.send(Ok(update)).await.is_err() {
                            return Ok(());
                        }
                    }
                    Some("ping") => {
                        socket.send(Message::text(json!({ "type": "pong" }).to_string())).await?;
                    }
                    Some("pong") => {}
                    Some("error") => anyhow::bail!("the DUST event subscription failed: {text}"),
                    Some("complete") => anyhow::bail!("the indexer ended the DUST event subscription"),
                    _ => anyhow::bail!("the indexer sent an unexpected message: {text}"),
                }
            }
        }
    }
}
