//! The indexer's `dustLedgerEvents` subscription over `graphql-transport-ws`: every
//! DUST ledger event, in order, with the newest id the indexer has seen.

use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::{SinkExt as _, StreamExt as _};
use midnight_base_crypto::time::Timestamp;
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

    /// The block time of the newest block the source has indexed.
    async fn indexed_time(&self) -> anyhow::Result<Timestamp>;
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
        let mut socket = open(&self.url).await?;
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

    async fn indexed_time(&self) -> anyhow::Result<Timestamp> {
        let query = async {
            let mut socket = open(&self.url).await?;
            socket
                .send(Message::text(
                    json!({
                        "id": "1",
                        "type": "subscribe",
                        "payload": { "query": "query { block { timestamp } }" },
                    })
                    .to_string(),
                ))
                .await
                .context("asking the indexer for its newest block")?;
            loop {
                let frame = socket
                    .next()
                    .await
                    .context("the indexer closed the connection before answering")?
                    .context("reading the indexer's newest block")?;
                let Message::Text(text) = frame else {
                    continue;
                };
                let message: serde_json::Value = serde_json::from_str(&text)
                    .context("the indexer sent a message that is not JSON")?;
                match message["type"].as_str() {
                    Some("next") => {
                        let millis = message["payload"]["data"]["block"]["timestamp"]
                            .as_u64()
                            .with_context(|| {
                                format!("the indexer's newest block has no time: {text}")
                            })?;
                        return anyhow::Ok(Timestamp::from_secs(millis / 1000));
                    }
                    Some("ping") => {
                        socket
                            .send(Message::text(json!({ "type": "pong" }).to_string()))
                            .await?;
                    }
                    _ => anyhow::bail!("the indexer did not answer with its newest block: {text}"),
                }
            }
        };
        tokio::time::timeout(KEEPALIVE, query)
            .await
            .context("timed out asking the indexer for its newest block")?
    }
}

/// A `graphql-transport-ws` connection, past its acknowledgement.
async fn open(url: &str) -> anyhow::Result<Socket> {
    let mut request = url
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
    Ok(socket)
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

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use tokio_tungstenite::WebSocketStream;

    type ServerSocket = WebSocketStream<tokio::net::TcpStream>;

    /// The events as the indexer serves them, `dustLedgerEvents` payloads verbatim.
    fn fixture_events() -> Vec<serde_json::Value> {
        serde_json::from_str(include_str!("../fixtures/dust-events-undeployed.json")).unwrap()
    }

    /// One `graphql-transport-ws` server connection running `script`, at the URL
    /// returned.
    async fn indexer<F, Fut>(script: F) -> (String, tokio::task::JoinHandle<()>)
    where
        F: FnOnce(ServerSocket) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let socket = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &Request, mut response: Response| {
                    assert_eq!(
                        request.headers()["Sec-WebSocket-Protocol"],
                        "graphql-transport-ws"
                    );
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        HeaderValue::from_static("graphql-transport-ws"),
                    );
                    Ok(response)
                },
            )
            .await
            .unwrap();
            script(socket).await;
        });
        (url, server)
    }

    async fn receive(socket: &mut ServerSocket) -> serde_json::Value {
        loop {
            if let Message::Text(text) = socket.next().await.unwrap().unwrap() {
                return serde_json::from_str(&text).unwrap();
            }
        }
    }

    async fn send(socket: &mut ServerSocket, message: serde_json::Value) {
        socket
            .send(Message::text(message.to_string()))
            .await
            .unwrap();
    }

    /// Acknowledges the connection after a ping the client must answer first.
    async fn accept(socket: &mut ServerSocket) {
        assert_eq!(receive(socket).await["type"], "connection_init");
        send(socket, json!({ "type": "ping" })).await;
        assert_eq!(receive(socket).await["type"], "pong");
        send(socket, json!({ "type": "connection_ack" })).await;
    }

    #[tokio::test]
    async fn the_subscription_delivers_the_indexer_s_events_in_order_until_it_ends() {
        let events: Vec<_> = fixture_events().into_iter().take(3).collect();
        let served = events.clone();
        let (url, server) = indexer(move |mut socket| async move {
            accept(&mut socket).await;
            let subscribe = receive(&mut socket).await;
            assert_eq!(subscribe["type"], "subscribe");
            assert_eq!(subscribe["payload"]["variables"]["id"], 1);
            for (index, event) in served.into_iter().enumerate() {
                send(
                    &mut socket,
                    json!({ "id": "1", "type": "next", "payload": { "data": { "dustLedgerEvents": event } } }),
                )
                .await;
                if index == 0 {
                    send(&mut socket, json!({ "type": "ping" })).await;
                    assert_eq!(receive(&mut socket).await["type"], "pong");
                }
            }
            send(&mut socket, json!({ "id": "1", "type": "complete" })).await;
        })
        .await;

        let updates: Vec<_> = IndexerDustEvents::new(url)
            .subscribe(Some(1))
            .await
            .unwrap()
            .collect()
            .await;
        server.await.unwrap();

        assert_eq!(updates.len(), 4, "three events, then the end");
        for (update, event) in updates.iter().zip(&events) {
            let update = update.as_ref().unwrap();
            assert_eq!(update.id, event["id"].as_u64().unwrap());
            assert_eq!(update.max_id, event["maxId"].as_u64().unwrap());
            assert_eq!(
                update.raw,
                hex::decode(event["raw"].as_str().unwrap()).unwrap()
            );
        }
        let end = updates[3].as_ref().unwrap_err();
        assert!(format!("{end:#}").contains("ended"), "{end:#}");
    }

    #[tokio::test]
    async fn an_errors_payload_ends_the_subscription_with_an_error() {
        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            receive(&mut socket).await;
            send(
                &mut socket,
                json!({ "id": "1", "type": "next", "payload": { "errors": [{ "message": "boom" }] } }),
            )
            .await;
            // Held open: the error alone must end the stream.
            let _ = socket.next().await;
        })
        .await;

        let mut stream = IndexerDustEvents::new(url).subscribe(None).await.unwrap();
        let error = stream.next().await.unwrap().unwrap_err();
        assert!(format!("{error:#}").contains("boom"), "{error:#}");
        assert!(stream.next().await.is_none());
        drop(stream);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn the_indexed_time_is_the_newest_block_s_milliseconds_in_seconds() {
        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            let query = receive(&mut socket).await;
            assert_eq!(query["payload"]["query"], "query { block { timestamp } }");
            send(
                &mut socket,
                json!({ "id": "1", "type": "next", "payload": { "data": { "block": { "timestamp": 1_761_400_000_999u64 } } } }),
            )
            .await;
        })
        .await;

        let time = IndexerDustEvents::new(url).indexed_time().await.unwrap();
        server.await.unwrap();
        assert_eq!(time, Timestamp::from_secs(1_761_400_000));
    }
}
