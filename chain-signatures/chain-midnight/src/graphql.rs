//! Midnight indexer GraphQL access: HTTP queries for the anchor/backfill and a
//! `graphql-transport-ws` subscription for live `contractEvents`. Schema pinned
//! at midnight-indexer commit c7c267cc (see the pins doc).

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);

const EVENT_FIELDS: &str = "__typename ... on MiscContractEvent { id maxId name payload transactionId transaction { block { height } } }";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawContractEvent {
    pub id: u64,
    pub max_id: u64,
    pub name: Vec<u8>,
    pub payload: Vec<u8>,
    pub transaction_id: u64,
    pub block_height: u64,
}

impl RawContractEvent {
    /// Parse the GraphQL object for one event. Returns None for non-Misc
    /// variants (the filter already narrows to MISC; this is a backstop).
    fn from_json(v: &Value) -> anyhow::Result<Option<Self>> {
        if v["__typename"].as_str() != Some("MiscContractEvent") {
            return Ok(None);
        }
        let field_u64 = |k: &str| -> anyhow::Result<u64> {
            v[k].as_u64()
                .ok_or_else(|| anyhow::anyhow!("missing/invalid {k} in contract event"))
        };
        let field_hex = |k: &str| -> anyhow::Result<Vec<u8>> {
            hex::decode(
                v[k].as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing {k} in contract event"))?,
            )
            .map_err(|e| anyhow::anyhow!("invalid hex in {k}: {e}"))
        };
        Ok(Some(Self {
            id: field_u64("id")?,
            max_id: field_u64("maxId")?,
            name: field_hex("name")?,
            payload: field_hex("payload")?,
            transaction_id: field_u64("transactionId")?,
            block_height: v["transaction"]["block"]["height"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("missing transaction.block.height"))?,
        }))
    }
}

#[derive(Clone)]
pub struct MidnightGraphql {
    http: reqwest::Client,
    http_url: String,
    ws_url: String,
    contract_address: String,
}

impl MidnightGraphql {
    pub fn new(http_url: &str, ws_url: &str, contract_address: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("reqwest client"),
            http_url: http_url.to_string(),
            ws_url: ws_url.to_string(),
            contract_address: contract_address.to_string(),
        }
    }

    fn filter(&self) -> Value {
        json!({ "contractAddress": self.contract_address, "types": ["MISC"] })
    }

    async fn post_query(&self, query: String, variables: Value) -> anyhow::Result<Value> {
        let resp = self
            .http
            .post(&self.http_url)
            .json(&json!({ "query": query, "variables": variables }))
            .send()
            .await?;
        anyhow::ensure!(
            resp.status().is_success(),
            "indexer query failed: {}",
            resp.status()
        );
        let body: Value = resp.json().await?;
        if let Some(errors) = body.get("errors").filter(|e| !e.is_null()) {
            anyhow::bail!("indexer GraphQL errors: {errors}");
        }
        Ok(body["data"].clone())
    }

    /// The current global contract-event ledger end (`maxId`), or 0 when this
    /// contract has never emitted an event. Used as the livestream anchor and
    /// the catchup-completion poll.
    pub async fn latest_max_id(&self) -> anyhow::Result<u64> {
        let data = self
            .post_query(
                format!(
                    "query($filter: ContractEventFilter!) {{ contractEvents(filter: $filter, limit: 1) {{ {EVENT_FIELDS} }} }}"
                ),
                json!({ "filter": self.filter() }),
            )
            .await?;
        let events = data["contractEvents"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("contractEvents is not an array"))?;
        match events.first() {
            Some(ev) => Ok(RawContractEvent::from_json(ev)?
                .map(|e| e.max_id)
                .unwrap_or(0)),
            None => Ok(0),
        }
    }

    /// Ascending page of this contract's Misc events (test/e2e helper).
    pub async fn fetch_events(
        &self,
        limit: u32,
        offset: u32,
    ) -> anyhow::Result<Vec<RawContractEvent>> {
        let data = self
            .post_query(
                format!(
                    "query($filter: ContractEventFilter!, $limit: Int, $offset: Int) {{ contractEvents(filter: $filter, limit: $limit, offset: $offset) {{ {EVENT_FIELDS} }} }}"
                ),
                json!({ "filter": self.filter(), "limit": limit, "offset": offset }),
            )
            .await?;
        let mut out = Vec::new();
        for ev in data["contractEvents"].as_array().into_iter().flatten() {
            if let Some(parsed) = RawContractEvent::from_json(ev)? {
                out.push(parsed);
            }
        }
        Ok(out)
    }

    /// Open a `graphql-transport-ws` subscription starting at the given id
    /// (inclusive — the indexer streams monotonically from there).
    pub async fn subscribe(&self, from_id_inclusive: u64) -> anyhow::Result<EventSubscription> {
        let mut request = self.ws_url.as_str().into_client_request()?;
        request.headers_mut().insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            "graphql-transport-ws".parse()?,
        );
        let (ws, _) = timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(request))
            .await
            .map_err(|_| anyhow::anyhow!("midnight indexer WS connect timeout"))??;
        let (mut write, mut read) = ws.split();

        timeout(
            CONNECT_TIMEOUT,
            write.send(Message::text(
                json!({"type": "connection_init"}).to_string(),
            )),
        )
        .await
        .map_err(|_| anyhow::anyhow!("connection_init send timeout"))??;

        // Await connection_ack (answer pings meanwhile).
        loop {
            let msg = timeout(CONNECT_TIMEOUT, read.next())
                .await
                .map_err(|_| anyhow::anyhow!("connection_ack timeout"))?
                .ok_or_else(|| anyhow::anyhow!("WS closed before connection_ack"))??;
            if let Message::Text(text) = msg {
                let v: Value = serde_json::from_str(&text)?;
                match v["type"].as_str() {
                    Some("connection_ack") => break,
                    Some("ping") => {
                        write
                            .send(Message::text(json!({"type": "pong"}).to_string()))
                            .await?;
                    }
                    other => anyhow::bail!("expected connection_ack, got {other:?}"),
                }
            }
        }

        let subscribe = json!({
            "type": "subscribe",
            "id": "1",
            "payload": {
                "query": format!(
                    "subscription($filter: ContractEventFilter!, $id: Int) {{ contractEvents(filter: $filter, id: $id) {{ {EVENT_FIELDS} }} }}"
                ),
                "variables": { "filter": self.filter(), "id": from_id_inclusive },
            }
        });
        timeout(
            CONNECT_TIMEOUT,
            write.send(Message::text(subscribe.to_string())),
        )
        .await
        .map_err(|_| anyhow::anyhow!("subscribe send timeout"))??;
        tracing::info!(
            from_id_inclusive,
            "midnight contractEvents subscription opened"
        );

        Ok(EventSubscription { read, write })
    }
}

pub struct EventSubscription {
    read: SplitStream<Ws>,
    write: SplitSink<Ws, Message>,
}

impl EventSubscription {
    /// Next Misc event, or None when the socket closed/stalled/completed —
    /// the caller resubscribes from its resume cursor.
    pub async fn next(&mut self) -> Option<RawContractEvent> {
        loop {
            let msg = match timeout(MESSAGE_TIMEOUT, self.read.next()).await {
                Ok(Some(Ok(msg))) => msg,
                Ok(Some(Err(err))) => {
                    tracing::warn!(%err, "midnight indexer WS error");
                    return None;
                }
                Ok(None) => return None,
                Err(_) => {
                    tracing::debug!("midnight indexer WS quiet for 60s; recycling connection");
                    return None;
                }
            };
            let Message::Text(text) = msg else {
                if matches!(msg, Message::Close(_)) {
                    return None;
                }
                continue;
            };
            let v: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(err) => {
                    tracing::warn!(%err, "unparseable WS message from indexer");
                    continue;
                }
            };
            match v["type"].as_str() {
                Some("next") => {
                    let payload = &v["payload"]["data"]["contractEvents"];
                    match RawContractEvent::from_json(payload) {
                        Ok(Some(ev)) => return Some(ev),
                        Ok(None) => continue,
                        Err(err) => {
                            tracing::warn!(%err, "dropping malformed contract event");
                            continue;
                        }
                    }
                }
                Some("ping") => {
                    let _ = self
                        .write
                        .send(Message::text(json!({"type": "pong"}).to_string()))
                        .await;
                }
                Some("complete") | Some("error") => {
                    tracing::warn!(msg = %text, "midnight subscription ended by server");
                    return None;
                }
                _ => continue,
            }
        }
    }

    pub async fn close(&mut self) {
        let _ = timeout(Duration::from_secs(5), self.write.close()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_misc_event_json() {
        let v = json!({
            "__typename": "MiscContractEvent",
            "id": 52, "maxId": 60,
            "name": hex::encode(b"SGN1:PING"),
            "payload": "00ff",
            "transactionId": 9,
            "transaction": { "block": { "height": 1051 } }
        });
        let ev = RawContractEvent::from_json(&v).unwrap().unwrap();
        assert_eq!(ev.id, 52);
        assert_eq!(ev.max_id, 60);
        assert_eq!(ev.name, b"SGN1:PING");
        assert_eq!(ev.payload, vec![0x00, 0xff]);
        assert_eq!(ev.transaction_id, 9);
        assert_eq!(ev.block_height, 1051);
        // Non-Misc variants are skipped, not errors.
        assert!(
            RawContractEvent::from_json(&json!({"__typename": "PausedEvent"}))
                .unwrap()
                .is_none()
        );
    }

    /// Full protocol round-trip against an in-process graphql-transport-ws
    /// server: init/ack handshake, subscribe frame shape, next → event.
    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite's handshake callback type
    async fn subscription_handshake_and_next() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Echo the graphql-transport-ws subprotocol like the real indexer;
            // the client refuses a server that ignores its requested protocol.
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let mut ws = tokio_tungstenite::accept_hdr_async(
                stream,
                |_req: &Request, mut resp: Response| {
                    resp.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        "graphql-transport-ws".parse().unwrap(),
                    );
                    Ok(resp)
                },
            )
            .await
            .unwrap();
            // connection_init → ack
            let init = ws.next().await.unwrap().unwrap();
            let init: Value = serde_json::from_str(init.to_text().unwrap()).unwrap();
            assert_eq!(init["type"], "connection_init");
            ws.send(Message::text(json!({"type": "connection_ack"}).to_string()))
                .await
                .unwrap();
            // subscribe → assert filter + resume id, then emit one event
            let sub = ws.next().await.unwrap().unwrap();
            let sub: Value = serde_json::from_str(sub.to_text().unwrap()).unwrap();
            assert_eq!(sub["type"], "subscribe");
            assert_eq!(sub["payload"]["variables"]["id"], 7);
            assert_eq!(
                sub["payload"]["variables"]["filter"]["contractAddress"],
                "ab".repeat(32)
            );
            ws.send(Message::text(
                json!({
                    "type": "next", "id": "1",
                    "payload": { "data": { "contractEvents": {
                        "__typename": "MiscContractEvent",
                        "id": 7, "maxId": 7,
                        "name": hex::encode(b"SGN1:SIGN"),
                        "payload": "aa",
                        "transactionId": 3,
                        "transaction": { "block": { "height": 12 } }
                    }}}
                })
                .to_string(),
            ))
            .await
            .unwrap();
        });

        let gql = MidnightGraphql::new(
            "http://unused.invalid",
            &format!("ws://{addr}"),
            &"ab".repeat(32),
        );
        let mut sub = gql.subscribe(7).await.unwrap();
        let ev = sub.next().await.unwrap();
        assert_eq!(ev.id, 7);
        assert_eq!(ev.block_height, 12);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn latest_max_id_handles_empty_history() {
        let mut server = mockito::Server::new_async().await;
        let m = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(json!({"data": {"contractEvents": []}}).to_string())
            .create_async()
            .await;
        let gql = MidnightGraphql::new(&server.url(), "ws://unused.invalid", &"ab".repeat(32));
        assert_eq!(gql.latest_max_id().await.unwrap(), 0);
        m.assert_async().await;
    }
}
