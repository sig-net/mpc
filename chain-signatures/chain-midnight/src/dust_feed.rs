//! The indexer's `dustLedgerEvents` subscription over `graphql-transport-ws`: every
//! DUST ledger event, in order, with the newest id the indexer has seen.

use std::time::Duration;
use url::Url;

use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};
use midnight_base_crypto::time::Timestamp;
use mpc_utils::task::AbortOnDrop;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// A connection that answers no keepalive within this long is dead.
const KEEPALIVE: Duration = Duration::from_secs(30);
/// How long answering the indexer's close may take: well inside the newest-block query's
/// own timeout, so a close that cannot be answered still reports its code there unless it
/// comes in that query's last few seconds. The newest-event query waits no longer than
/// this, so a close there that cannot be answered ends as that query's timeout.
const CLOSE_REPLY: Duration = Duration::from_secs(5);
const _: () = assert!(CLOSE_REPLY.as_secs() < KEEPALIVE.as_secs());
/// Events buffered between the socket and the replay; with `MAX_MESSAGE`, it bounds
/// what an indexer can make the node hold.
const BUFFER: usize = 512;
/// The largest message or frame accepted from the indexer. One message carries one
/// hex-encoded DUST event; the largest in the captured fixture is about 2.7 KB.
const MAX_MESSAGE: usize = 1 << 20;
/// How long the indexer may take to name its newest event once it has answered its
/// newest block; past it, the answer goes without one.
const NEWEST_EVENT_TIMEOUT: Duration = Duration::from_secs(5);

const SUBSCRIPTION: &str =
    "subscription DustLedgerEvents($id: Int) { dustLedgerEvents(id: $id) { id maxId raw } }";
const NEWEST_EVENT: &str =
    "subscription DustLedgerEvents($id: Int) { dustLedgerEvents(id: $id) { maxId } }";

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

    /// The newest block's time and, asked after it from event `from` on, the newest
    /// event id the source holds, when it names one.
    async fn indexed(&self, _from: Option<u64>) -> anyhow::Result<Indexed> {
        Ok(Indexed {
            time: self.indexed_time().await?,
            newest_event: None,
        })
    }
}

/// What the source has indexed, as [`DustEventSource::indexed`] reads it.
pub(crate) struct Indexed {
    pub time: Timestamp,
    /// Covers every event of the block at `time`, as it was asked after it.
    pub newest_event: Option<u64>,
}

pub(crate) struct IndexerDustEvents {
    url: Url,
}

impl IndexerDustEvents {
    pub(crate) fn new(url: Url) -> Self {
        Self { url }
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
            newest_block(&mut socket).await
        };
        tokio::time::timeout(KEEPALIVE, query)
            .await
            .context("timed out asking the indexer for its newest block")?
    }

    /// Both questions go over one connection of their own, never the live one, which
    /// may have stalled: the first event the subscription from `from` serves carries the
    /// newest id when it is served.
    async fn indexed(&self, from: Option<u64>) -> anyhow::Result<Indexed> {
        let query = async {
            let mut socket = open(&self.url).await?;
            let time = newest_block(&mut socket).await?;
            anyhow::Ok((socket, time))
        };
        let (mut socket, time) = tokio::time::timeout(KEEPALIVE, query)
            .await
            .context("timed out asking the indexer for its newest block")??;
        let newest_event =
            match tokio::time::timeout(NEWEST_EVENT_TIMEOUT, newest_event(&mut socket, from)).await
            {
                Ok(Ok(newest)) => Some(newest),
                Ok(Err(error)) => {
                    tracing::warn!(
                        error = %format_args!("{error:#}"),
                        "midnight funding wallet: the indexer named no newest DUST event"
                    );
                    None
                }
                Err(_) => {
                    tracing::warn!(
                        "midnight funding wallet: the indexer named no newest DUST event in time"
                    );
                    None
                }
            };
        Ok(Indexed { time, newest_event })
    }
}

async fn newest_block(socket: &mut Socket) -> anyhow::Result<Timestamp> {
    let data = first_result(
        socket,
        "1",
        json!({ "query": "query { block { timestamp } }" }),
        "its newest block",
    )
    .await?;
    let millis = data["block"]["timestamp"]
        .as_u64()
        .with_context(|| format!("the indexer's newest block has no time: {data}"))?;
    Ok(Timestamp::from_secs(millis / 1000))
}

async fn newest_event(socket: &mut Socket, from: Option<u64>) -> anyhow::Result<u64> {
    let data = first_result(
        socket,
        "2",
        json!({ "query": NEWEST_EVENT, "variables": { "id": from } }),
        "its newest DUST event",
    )
    .await?;
    data["dustLedgerEvents"]["maxId"]
        .as_u64()
        .with_context(|| format!("the indexer's DUST event names no newest id: {data}"))
}

/// The `data` of operation `id`'s first result. Messages of the connection's other
/// operations, such as an earlier query's `complete`, are passed over.
async fn first_result(
    socket: &mut Socket,
    id: &str,
    payload: serde_json::Value,
    what: &str,
) -> anyhow::Result<serde_json::Value> {
    socket
        .send(Message::text(
            json!({ "id": id, "type": "subscribe", "payload": payload }).to_string(),
        ))
        .await
        .with_context(|| format!("asking the indexer for {what}"))?;
    loop {
        let frame = socket
            .next()
            .await
            .context("the indexer closed the connection before answering")?
            .with_context(|| format!("reading the indexer's answer for {what}"))?;
        let Message::Text(text) = frame else {
            if let Message::Close(close) = frame {
                return Err(closed(socket, "the connection", close).await);
            }
            continue;
        };
        let mut message: serde_json::Value =
            serde_json::from_str(&text).context("the indexer sent a message that is not JSON")?;
        if message["id"].as_str().is_some_and(|other| other != id) {
            continue;
        }
        match message["type"].as_str() {
            Some("next") => {
                if let Some(errors) = message["payload"].get("errors") {
                    anyhow::bail!("the indexer answered {what} with errors: {errors}");
                }
                return Ok(message["payload"]["data"].take());
            }
            Some("ping") => {
                socket
                    .send(Message::text(json!({ "type": "pong" }).to_string()))
                    .await?;
            }
            Some("pong") => {}
            _ => anyhow::bail!("the indexer did not answer with {what}: {text}"),
        }
    }
}

/// A `graphql-transport-ws` connection, past its acknowledgement.
async fn open(url: &Url) -> anyhow::Result<Socket> {
    let mut request = url
        .as_str()
        .into_client_request()
        .context("the indexer subscription URL is not a websocket URL")?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static("graphql-transport-ws"),
    );
    let limits = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let connect = tokio_tungstenite::connect_async_tls_with_config(
        request,
        Some(limits),
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
        if let Message::Close(close) = frame {
            return Err(closed(&mut socket, "the subscription", close).await);
        }
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

/// Sends the reply tungstenite queued on reading the indexer's close, which it would only
/// send on a next read, flush or close, and renders why the indexer closed `what`: the code
/// as a number and the reason quoted, so it stays on one log line. tungstenite hands over a
/// code the protocol reserves or forbids (1005, 1006, 1015, 5000, ...) as 1002 "Protocol
/// violation".
async fn closed<S>(socket: &mut S, what: &str, close: Option<CloseFrame>) -> anyhow::Error
where
    S: Sink<Message> + Unpin,
{
    // Best effort: a peer that stopped reading must not hold the caller.
    let _ = tokio::time::timeout(CLOSE_REPLY, socket.close()).await;
    match close {
        Some(frame) => anyhow::anyhow!(
            "the indexer closed {what} with code {} and reason {:?}",
            frame.code,
            frame.reason.as_str()
        ),
        None => anyhow::anyhow!("the indexer closed {what} without a close code"),
    }
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Forwards events until the socket fails, the subscription ends, or a keepalive
/// goes unanswered: a silent connection is otherwise indistinguishable from a quiet
/// chain.
async fn pump<S>(
    mut socket: S,
    sender: &mpsc::Sender<anyhow::Result<DustEventUpdate>>,
) -> anyhow::Result<()>
where
    S: Stream<Item = Result<Message, WsError>> + Sink<Message, Error = WsError> + Unpin,
{
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
                        return Err(closed(&mut socket, "the subscription", close).await);
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

    /// Bounds the tests that talk over a real socket, so a hang fails by name.
    const TEST_TIMEOUT: Duration = Duration::from_secs(30);

    /// The events as the indexer serves them, `dustLedgerEvents` payloads verbatim.
    fn fixture_events() -> Vec<serde_json::Value> {
        serde_json::from_str(include_str!("../fixtures/dust-events-undeployed.json")).unwrap()
    }

    /// One `graphql-transport-ws` server connection running `script`, at the URL
    /// returned.
    // tungstenite fixes the handshake callback's error type.
    #[allow(clippy::result_large_err)]
    async fn indexer<F, Fut>(script: F) -> (Url, tokio::task::JoinHandle<()>)
    where
        F: FnOnce(ServerSocket) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
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

        let updates: Vec<_> = tokio::time::timeout(TEST_TIMEOUT, async {
            IndexerDustEvents::new(url)
                .subscribe(Some(1))
                .await
                .unwrap()
                .collect()
                .await
        })
        .await
        .expect("the subscription ends when the indexer completes it");
        tokio::time::timeout(TEST_TIMEOUT, server)
            .await
            .expect("the indexer script ends")
            .unwrap();

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

    /// A client websocket over an in-memory pipe, and the indexer's end of it.
    async fn pipe() -> (
        WebSocketStream<tokio::io::DuplexStream>,
        WebSocketStream<tokio::io::DuplexStream>,
    ) {
        use tokio_tungstenite::tungstenite::protocol::Role;
        let (client, server) = tokio::io::duplex(64 * 1024);
        (
            WebSocketStream::from_raw_socket(client, Role::Client, None).await,
            WebSocketStream::from_raw_socket(server, Role::Server, None).await,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn an_indexer_answering_keepalives_keeps_a_quiet_subscription_open() {
        let (client, mut server) = pipe().await;
        let event = fixture_events().remove(0);
        let served = event.clone();
        let indexer = tokio::spawn(async move {
            // Reading answers each keepalive ping; nothing else is sent for a while.
            let quiet_until = tokio::time::Instant::now() + KEEPALIVE * 5;
            while let Ok(frame) = tokio::time::timeout_at(quiet_until, server.next()).await {
                frame.unwrap().unwrap();
            }
            let next = json!({ "id": "1", "type": "next", "payload": { "data": { "dustLedgerEvents": served } } });
            server.send(Message::text(next.to_string())).await.unwrap();
            // Held open: only the event may end the wait below.
            let _ = server.next().await;
        });
        let (sender, mut receiver) = mpsc::channel(1);
        let pumping = AbortOnDrop(tokio::spawn(async move {
            // Ending drops the sender, which ends the wait below without an event.
            let _ = pump(client, &sender).await;
        }));

        let update = receiver
            .recv()
            .await
            .expect("the subscription outlived the quiet stretch")
            .unwrap();
        assert_eq!(update.id, event["id"].as_u64().unwrap());
        drop(pumping);
        indexer.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn an_indexer_answering_no_keepalive_ends_the_subscription() {
        // Never read, so the indexer's end never answers a ping.
        let (client, _server) = pipe().await;
        let (sender, _receiver) = mpsc::channel(1);
        let error = tokio::time::timeout(KEEPALIVE * 3, pump(client, &sender))
            .await
            .expect("the second unanswered keepalive ends it")
            .unwrap_err();
        assert!(format!("{error:#}").contains("keepalive"), "{error:#}");
    }

    #[tokio::test(start_paused = true)]
    async fn an_unanswerable_close_holds_the_subscription_for_its_reply_timeout_at_most() {
        use tokio_tungstenite::tungstenite::protocol::Role;
        // Too small for the close reply, and never read.
        let (client, server) = tokio::io::duplex(8);
        let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let mut server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let indexer = tokio::spawn(async move {
            let close = CloseFrame {
                code: 4003.into(),
                reason: "full".into(),
            };
            server.send(Message::Close(Some(close))).await.unwrap();
            // Held open and never read.
            std::future::pending::<()>().await;
        });
        let (sender, _receiver) = mpsc::channel(1);

        let started = tokio::time::Instant::now();
        let error = tokio::time::timeout(CLOSE_REPLY * 2, pump(client, &sender))
            .await
            .expect("answering the close gives up after its timeout")
            .unwrap_err();
        assert!(started.elapsed() <= CLOSE_REPLY, "{:?}", started.elapsed());
        assert!(format!("{error:#}").contains("code 4003"), "{error:#}");
        indexer.abort();
    }

    #[tokio::test]
    async fn an_oversized_message_ends_the_subscription_with_an_error() {
        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            receive(&mut socket).await;
            // Twice the 1 MiB limit, fixed rather than derived from the constant.
            let raw = "00".repeat(1 << 20);
            let event = json!({ "id": 1, "maxId": 1, "raw": raw });
            // The client drops the connection mid-message, so the send may fail.
            let _ = socket
                .send(Message::text(
                    json!({ "id": "1", "type": "next", "payload": { "data": { "dustLedgerEvents": event } } })
                        .to_string(),
                ))
                .await;
            let _ = socket.next().await;
        })
        .await;

        let mut stream = IndexerDustEvents::new(url).subscribe(None).await.unwrap();
        let error = tokio::time::timeout(TEST_TIMEOUT, stream.next())
            .await
            .expect("an oversized message ends the subscription")
            .unwrap()
            .unwrap_err();
        assert!(format!("{error:#}").contains("too long"), "{error:#}");
        drop(stream);
        server.abort();
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
        let error = tokio::time::timeout(TEST_TIMEOUT, stream.next())
            .await
            .expect("the errors payload ends the subscription")
            .unwrap()
            .unwrap_err();
        assert!(format!("{error:#}").contains("boom"), "{error:#}");
        assert!(tokio::time::timeout(TEST_TIMEOUT, stream.next())
            .await
            .expect("the stream ends after the error")
            .is_none());
        drop(stream);
        tokio::time::timeout(TEST_TIMEOUT, server)
            .await
            .expect("the indexer script ends")
            .unwrap();
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
        tokio::time::timeout(TEST_TIMEOUT, server)
            .await
            .expect("the indexer script ends")
            .unwrap();
        assert_eq!(time, Timestamp::from_secs(1_761_400_000));
    }

    /// Answers the newest-block query as operation 1, then completes it.
    async fn answer_newest_block(socket: &mut ServerSocket) {
        let query = receive(socket).await;
        assert_eq!(query["id"], "1");
        assert_eq!(query["payload"]["query"], "query { block { timestamp } }");
        send(
            socket,
            json!({ "id": "1", "type": "next", "payload": { "data": { "block": { "timestamp": 1_761_400_000_999u64 } } } }),
        )
        .await;
        send(socket, json!({ "id": "1", "type": "complete" })).await;
    }

    #[tokio::test]
    async fn the_newest_event_is_asked_after_the_newest_block_on_the_same_connection() {
        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            answer_newest_block(&mut socket).await;
            let question = receive(&mut socket).await;
            assert_eq!(question["id"], "2");
            assert_eq!(question["payload"]["query"], NEWEST_EVENT);
            assert_eq!(question["payload"]["variables"]["id"], 117);
            send(&mut socket, json!({ "type": "ping" })).await;
            assert_eq!(receive(&mut socket).await["type"], "pong");
            send(
                &mut socket,
                json!({ "id": "2", "type": "next", "payload": { "data": { "dustLedgerEvents": { "maxId": 119 } } } }),
            )
            .await;
        })
        .await;

        // The script's server accepts one connection only.
        let indexed = IndexerDustEvents::new(url)
            .indexed(Some(117))
            .await
            .unwrap();
        tokio::time::timeout(TEST_TIMEOUT, server)
            .await
            .expect("the indexer script ends")
            .unwrap();
        assert_eq!(indexed.time, Timestamp::from_secs(1_761_400_000));
        assert_eq!(indexed.newest_event, Some(119));
    }

    #[tokio::test]
    async fn an_indexer_that_refuses_to_name_its_newest_event_still_answers_its_newest_block() {
        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            answer_newest_block(&mut socket).await;
            receive(&mut socket).await;
            send(
                &mut socket,
                json!({ "id": "2", "type": "error", "payload": [{ "message": "boom" }] }),
            )
            .await;
            // The connection stays open: only the refusal can end the wait early.
            std::future::pending::<()>().await;
        })
        .await;

        let asked = std::time::Instant::now();
        let indexed = IndexerDustEvents::new(url).indexed(None).await.unwrap();
        assert!(
            asked.elapsed() < Duration::from_secs(2),
            "a refusal ends the wait at once"
        );
        server.abort();
        assert_eq!(indexed.time, Timestamp::from_secs(1_761_400_000));
        assert_eq!(indexed.newest_event, None);
    }

    #[tokio::test]
    async fn a_newest_event_the_indexer_answers_with_errors_is_none_at_once() {
        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            answer_newest_block(&mut socket).await;
            receive(&mut socket).await;
            send(
                &mut socket,
                json!({ "id": "2", "type": "next", "payload": { "data": null, "errors": [{ "message": "boom" }] } }),
            )
            .await;
            std::future::pending::<()>().await;
        })
        .await;

        let asked = std::time::Instant::now();
        let indexed = IndexerDustEvents::new(url).indexed(Some(3)).await.unwrap();
        assert!(
            asked.elapsed() < Duration::from_secs(2),
            "{:?}",
            asked.elapsed()
        );
        server.abort();
        assert_eq!(indexed.time, Timestamp::from_secs(1_761_400_000));
        assert_eq!(indexed.newest_event, None);
    }

    #[tokio::test]
    async fn a_newest_block_the_indexer_answers_with_errors_fails_and_names_them() {
        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            receive(&mut socket).await;
            send(
                &mut socket,
                json!({ "id": "1", "type": "next", "payload": { "data": null, "errors": [{ "message": "database unavailable" }] } }),
            )
            .await;
            std::future::pending::<()>().await;
        })
        .await;

        let error = tokio::time::timeout(TEST_TIMEOUT, IndexerDustEvents::new(url).indexed(None))
            .await
            .expect("answers in time")
            .err()
            .expect("a newest block with errors is no newest block");
        server.abort();
        assert!(
            format!("{error:#}").contains("database unavailable"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn operation_one_s_complete_and_heartbeats_after_operation_two_is_asked_pass_over() {
        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            let query = receive(&mut socket).await;
            assert_eq!(query["id"], "1");
            send(
                &mut socket,
                json!({ "id": "1", "type": "next", "payload": { "data": { "block": { "timestamp": 1_761_400_000_999u64 } } } }),
            )
            .await;
            assert_eq!(receive(&mut socket).await["id"], "2");
            send(&mut socket, json!({ "type": "ping" })).await;
            send(&mut socket, json!({ "type": "pong" })).await;
            send(&mut socket, json!({ "id": "1", "type": "complete" })).await;
            assert_eq!(receive(&mut socket).await["type"], "pong");
            for newest in [7, 8] {
                send(
                    &mut socket,
                    json!({ "id": "2", "type": "next", "payload": { "data": { "dustLedgerEvents": { "maxId": newest } } } }),
                )
                .await;
            }
        })
        .await;

        let indexed = IndexerDustEvents::new(url).indexed(Some(3)).await.unwrap();
        let _ = tokio::time::timeout(TEST_TIMEOUT, server).await;
        assert_eq!(indexed.newest_event, Some(7), "the first result only");
    }

    #[tokio::test]
    async fn an_indexer_silent_about_its_newest_event_is_waited_for_no_longer_than_its_timeout() {
        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            answer_newest_block(&mut socket).await;
            receive(&mut socket).await;
            std::future::pending::<()>().await;
        })
        .await;

        let asked = std::time::Instant::now();
        let indexed = IndexerDustEvents::new(url).indexed(None).await.unwrap();
        let took = asked.elapsed();
        server.abort();
        assert_eq!(indexed.newest_event, None);
        assert!(
            took >= NEWEST_EVENT_TIMEOUT && took < NEWEST_EVENT_TIMEOUT + Duration::from_secs(3),
            "{took:?}"
        );
    }

    /// Closes the connection, and checks the client answers the close as RFC 6455 asks
    /// instead of dropping the connection.
    async fn close(socket: &mut ServerSocket, close: Option<(u16, &'static str)>) {
        let frame = close.map(|(code, reason)| CloseFrame {
            code: code.into(),
            reason: reason.into(),
        });
        socket.send(Message::Close(frame)).await.unwrap();
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
                other => panic!("the client dropped the connection unanswered: {other:?}"),
            }
        }
    }

    /// The indexer's close code and reason reach the error wherever it closes.
    #[tokio::test]
    async fn the_indexer_s_close_code_and_reason_reach_the_error() {
        let (url, server) = indexer(|mut socket| async move {
            assert_eq!(receive(&mut socket).await["type"], "connection_init");
            close(
                &mut socket,
                Some((4429, "Too many initialisation requests")),
            )
            .await;
        })
        .await;
        let refused =
            tokio::time::timeout(TEST_TIMEOUT, IndexerDustEvents::new(url).subscribe(None))
                .await
                .expect("a close ends the handshake")
                .err()
                .expect("a closed handshake opens no subscription");
        server.await.unwrap();

        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            receive(&mut socket).await;
            close(&mut socket, Some((1013, "try again later"))).await;
        })
        .await;
        let unanswered =
            tokio::time::timeout(TEST_TIMEOUT, IndexerDustEvents::new(url).indexed_time())
                .await
                .expect("a close ends the query")
                .unwrap_err();
        server.await.unwrap();

        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            receive(&mut socket).await;
            close(&mut socket, Some((1001, "going\naway"))).await;
        })
        .await;
        let mut stream = IndexerDustEvents::new(url).subscribe(None).await.unwrap();
        let dropped = tokio::time::timeout(TEST_TIMEOUT, stream.next())
            .await
            .expect("a close ends the subscription")
            .unwrap()
            .unwrap_err();
        server.await.unwrap();

        let (url, server) = indexer(|mut socket| async move {
            assert_eq!(receive(&mut socket).await["type"], "connection_init");
            close(&mut socket, None).await;
        })
        .await;
        let bare = tokio::time::timeout(TEST_TIMEOUT, IndexerDustEvents::new(url).subscribe(None))
            .await
            .expect("a close ends the handshake")
            .err()
            .expect("a closed handshake opens no subscription");
        server.await.unwrap();
        assert!(
            format!("{bare:#}").contains("without a close code"),
            "{bare:#}"
        );

        for (error, code, reason) in [
            (refused, "4429", "Too many initialisation requests"),
            (unanswered, "1013", "try again later"),
            (dropped, "1001", r#""going\naway""#),
        ] {
            let error = format!("{error:#}");
            assert!(error.contains(code) && error.contains(reason), "{error}");
            assert!(!error.contains('\n'), "one log line: {error}");
        }
    }

    #[tokio::test]
    async fn a_close_while_naming_the_newest_event_is_answered_at_once() {
        let (url, server) = indexer(|mut socket| async move {
            accept(&mut socket).await;
            answer_newest_block(&mut socket).await;
            receive(&mut socket).await;
            close(&mut socket, Some((1013, "try again later"))).await;
            // The connection stays open: only answering the close can end the wait early.
            std::future::pending::<()>().await;
        })
        .await;

        let asked = std::time::Instant::now();
        let indexed = IndexerDustEvents::new(url).indexed(Some(3)).await.unwrap();
        assert!(
            asked.elapsed() < Duration::from_secs(2),
            "{:?}",
            asked.elapsed()
        );
        server.abort();
        assert_eq!(indexed.time, Timestamp::from_secs(1_761_400_000));
        assert_eq!(indexed.newest_event, None);
    }
}
