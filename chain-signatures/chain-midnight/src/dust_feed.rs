//! The indexer's `dustLedgerEvents` subscription over `graphql-transport-ws`: every
//! DUST ledger event, in order, with the newest id the indexer has seen.

use std::time::Duration;
use url::Url;

use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::stream::BoxStream;
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};
use midnight_base_crypto::time::Timestamp;
use mpc_chain_integration_core::utils::retry::{run_gated, RpcFailure, SharedBackoff};
use mpc_utils::task::AbortOnDrop;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

/// A connection that answers no keepalive within this long is dead.
const KEEPALIVE: Duration = Duration::from_secs(30);
/// Events buffered between the socket and the replay; with `MAX_MESSAGE`, it bounds
/// what an indexer can make the node hold.
const BUFFER: usize = 512;
/// The largest message or frame accepted from the indexer. One message carries one
/// hex-encoded DUST event; the largest in the captured fixture is about 2.7 KB.
const MAX_MESSAGE: usize = 1 << 20;

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
    url: Url,
    gate: SharedBackoff,
}

impl IndexerDustEvents {
    /// Opens every connection under `gate`, which the node's other Midnight callers share.
    pub(crate) fn gated(url: Url, gate: SharedBackoff) -> Self {
        Self { url, gate }
    }

    #[cfg(test)]
    pub(crate) fn new(url: Url) -> Self {
        Self::gated(url, SharedBackoff::new())
    }

    async fn open(&self) -> anyhow::Result<Socket> {
        open(&self.url, &self.gate).await
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
        let mut socket = self.open().await?;
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
        // The gate's cooldown is waited out before the query's timeout starts.
        crate::rpc::wait_out(&self.gate, "midnight_indexer_ws").await;
        let query = async {
            let mut socket = self.open().await?;
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

/// A `graphql-transport-ws` connection, past its acknowledgement. The handshake runs
/// under `gate`: only the HTTP status it is refused with can engage it.
async fn open(url: &Url, gate: &SharedBackoff) -> anyhow::Result<Socket> {
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
    crate::rpc::wait_out(gate, "midnight_indexer_ws").await;
    let (mut socket, _) = run_gated(gate, "midnight_indexer_ws", async {
        tokio::time::timeout(KEEPALIVE, connect)
            .await
            .context("timed out connecting to the indexer subscription")?
            .map_err(handshake_failure)
            .context("connecting to the indexer subscription")
    })
    .await?;
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

/// A failed handshake as the gate reads it: with the HTTP status the indexer refused it
/// with, or none, so a number in the message is never read as a status.
fn handshake_failure(error: WsError) -> anyhow::Error {
    let status = match &error {
        WsError::Http(response) => Some(response.status()),
        _ => None,
    };
    let message = error.to_string();
    anyhow::Error::new(match status {
        Some(status) => RpcFailure::read_status(status, message),
        None => RpcFailure::retryable(message),
    })
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
    /// A handshake waits out a cooldown another caller's throttle extends while it waits.
    #[tokio::test]
    async fn a_handshake_waits_out_a_cooldown_extended_while_it_waits() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: Url = format!("ws://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let arrived = std::time::Instant::now();
            let mut request = [0; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
            tokio::io::AsyncWriteExt::write_all(
                &mut stream,
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
            arrived
        });
        let gate =
            SharedBackoff::with_cooldowns(Duration::from_millis(400), Duration::from_secs(5));
        gate.extend_cooldown();
        let throttled = gate.clone();
        let started = std::time::Instant::now();
        let extend = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            for _ in 0..3 {
                throttled.extend_cooldown();
            }
        });
        let _ = IndexerDustEvents::gated(url, gate).subscribe(None).await;
        extend.await.unwrap();
        let went_out = server.await.unwrap() - started;
        assert!(
            went_out >= Duration::from_millis(3200),
            "the handshake went out {went_out:?} in, inside a window extended to about 3.3 s"
        );
    }

    /// What the indexer says after the handshake never engages the gate, whatever
    /// digits its text carries.
    #[tokio::test]
    async fn a_refusal_after_the_handshake_leaves_the_gate_open() {
        let (url, server) = indexer(|mut socket| async move {
            assert_eq!(receive(&mut socket).await["type"], "connection_init");
            send(
                &mut socket,
                json!({ "type": "connection_error", "payload": { "message": "limit 429" } }),
            )
            .await;
        })
        .await;
        let gate = SharedBackoff::with_cooldowns(Duration::from_secs(5), Duration::from_secs(5));
        let error = IndexerDustEvents::gated(url, gate.clone())
            .subscribe(None)
            .await
            .err()
            .expect("the indexer refuses the subscription");
        server.await.unwrap();
        assert!(format!("{error:#}").contains("429"), "{error:#}");
        assert_eq!(gate.remaining(), Duration::ZERO, "{error:#}");
    }

    /// An indexer that refuses the websocket handshake with 429 engages the gate it
    /// shares with the node's other Midnight callers, and the next connection waits it
    /// out; a refusal for another status does not.
    #[tokio::test]
    async fn a_throttled_handshake_holds_the_next_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: Url = format!("ws://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let statuses = [
            "429 Too Many Requests",
            "429 Too Many Requests",
            "503 Service Unavailable",
        ];
        let arrivals = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let arrived = arrivals.clone();
        let server = tokio::spawn(async move {
            for status in statuses {
                let (mut stream, _) = listener.accept().await.unwrap();
                arrived.lock().unwrap().push(std::time::Instant::now());
                let mut request = [0; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut request).await;
                let response = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
                tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes())
                    .await
                    .unwrap();
            }
        });
        let cooldown = Duration::from_millis(400);
        let gate = SharedBackoff::with_cooldowns(cooldown, Duration::from_secs(5));
        let events = IndexerDustEvents::gated(url, gate.clone());

        events
            .subscribe(None)
            .await
            .err()
            .expect("the indexer throttles");
        assert!(
            gate.remaining() > Duration::ZERO,
            "a 429 handshake engaged no gate"
        );
        events
            .indexed_time()
            .await
            .expect_err("the indexer still throttles");
        // Waits out the second 429's cooldown, so the 503 is answered on an open gate.
        tokio::time::sleep(gate.remaining()).await;
        events
            .subscribe(None)
            .await
            .err()
            .expect("the indexer is unavailable");
        server.await.unwrap();
        let arrivals = arrivals.lock().unwrap().clone();

        assert!(
            arrivals[1] - arrivals[0] >= cooldown - Duration::from_millis(100),
            "the second connection came {:?} after a 429",
            arrivals[1] - arrivals[0]
        );
        assert_eq!(
            gate.remaining(),
            Duration::ZERO,
            "a 503 handshake engaged the gate"
        );
    }
}
