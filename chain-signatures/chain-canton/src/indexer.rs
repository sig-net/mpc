//! Canton indexer implementation.

use crate::client::CantonClient;
use crate::config::CantonConfig;
use crate::events::process_canton_event;
use crate::ledger_api;

use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::stream::{Empty, SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use mpc_chain_integration_core::{
    ChainIndexer, ChainTelemetry, NoopPublisherTelemetry, StateManager,
};
use mpc_primitives::{Chain, ChainEvent};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tokio_util::sync::CancellationToken;

type CantonWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
type CantonWsRead = SplitStream<CantonWs>;
type CantonWsWrite = SplitSink<CantonWs, Message>;

enum CantonConnection {
    Connected(CantonWsRead, CantonWsWrite),
    Disconnected,
}

impl CantonConnection {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    // TODO: this 60s message stall overlaps with the supervisor's per-chain
    // `live_block_timeout` watchdog. Consolidate into one stall authority
    const MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);
    const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    async fn connect(
        ws_url: &str,
        jwt_token: &str,
        party_id: &str,
        signer_template_id: &str,
        begin_exclusive: u64,
    ) -> anyhow::Result<Self> {
        let mut request = ws_url.into_client_request()?;
        request.headers_mut().insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            format!("jwt.token.{jwt_token}, daml.ws.auth").parse()?,
        );

        let request = tokio_tungstenite::connect_async(request);
        let (ws_stream, _) = timeout(Self::CONNECT_TIMEOUT, request)
            .await
            .map_err(|_| anyhow::anyhow!("canton WebSocket connect timeout"))??;
        let (mut ws_write, ws_read) = ws_stream.split();
        tracing::info!(begin_exclusive, "canton WebSocket connected");

        // Subscribe to only the Signer package's templates (not every contract visible to
        // the party) — enforces the package at the ledger; the client-side suffix match in
        // process_canton_event stays as a second layer.
        let party_filter = ledger_api::template_party_filter(
            &ledger_api::signer_subscription_template_ids(signer_template_id),
        );
        let mut filters_by_party = serde_json::Map::new();
        filters_by_party.insert(party_id.to_string(), serde_json::to_value(party_filter)?);

        let subscribe_msg = ledger_api::GetUpdatesRequest {
            begin_exclusive,
            update_format: ledger_api::UpdateFormat {
                include_transactions: ledger_api::TransactionFormat {
                    transaction_shape: "TRANSACTION_SHAPE_LEDGER_EFFECTS".to_string(),
                    event_format: ledger_api::EventFormat {
                        filters_by_party,
                        verbose: true,
                    },
                },
            },
        };
        let subscribe_msg = serde_json::to_string(&subscribe_msg)?;
        let subscribe_task = ws_write.send(Message::Text(subscribe_msg.into()));
        timeout(Self::CONNECT_TIMEOUT, subscribe_task)
            .await
            .map_err(|_| anyhow::anyhow!("canton WebSocket subscription send timeout"))??;

        Ok(Self::Connected(ws_read, ws_write))
    }

    /// Read the next message from the WebSocket. Returns `None` (transitioning to
    /// `Disconnected`) on close, error, or a 60s message stall.
    async fn next(&mut self) -> Option<Message> {
        let Self::Connected(ws_read, _) = self else {
            tracing::warn!("canton WebSocket not initialized");
            return None;
        };
        let Ok(maybe_msg) = timeout(Self::MESSAGE_TIMEOUT, ws_read.next()).await else {
            tracing::warn!("canton WebSocket stalled: no message for 60s");
            return None;
        };

        let Some(msg) = maybe_msg else {
            *self = Self::Disconnected;
            return None;
        };
        let msg = match msg {
            Ok(msg) => msg,
            Err(err) => {
                tracing::warn!(%err, "canton WebSocket error");
                return None;
            }
        };

        if matches!(msg, Message::Close(_)) {
            tracing::info!("canton WebSocket received close frame");
            if let Err(err) = self.close().await {
                tracing::debug!(%err, "failed to flush canton WebSocket close reply");
            }
            return None;
        }

        Some(msg)
    }

    async fn close(&mut self) -> anyhow::Result<()> {
        let Self::Connected(_, ws_write) = self else {
            tracing::warn!("canton WebSocket close on already disconnected connection");
            return Ok(());
        };

        timeout(Self::DISCONNECT_TIMEOUT, ws_write.close())
            .await
            .map_err(|_| anyhow::anyhow!("canton WebSocket close reply timeout"))?
            .map_err(|e| anyhow::anyhow!("failed to flush canton WebSocket close reply: {e}"))?;
        *self = Self::Disconnected;
        Ok(())
    }
}

pub struct CantonIndexer<S: StateManager, T: ChainTelemetry> {
    client: CantonClient,
    state_manager: S,
    telemetry: T,
}

impl<S: StateManager, T: ChainTelemetry> CantonIndexer<S, T> {
    pub async fn new(config: CantonConfig, state_manager: S, telemetry: T) -> anyhow::Result<Self> {
        let client = CantonClient::new(&config, Arc::new(NoopPublisherTelemetry)).await?; // Indexer does not publish
        Ok(Self {
            client,
            state_manager,
            telemetry,
        })
    }

    // TODO: ws_conn + last_seen_offset are threaded as explicit params because
    // `run(&self)` is immutable. A cleaner shape (matching Solana/Ethereum) would
    // spawn a WS-driver task owning the connection and emitting Updates on a
    // channel, leaving `run()` to drain it; CantonClient is Clone so this is
    // feasible. Revisit post-migration.
    async fn connect_and_subscribe(
        &self,
        ws_conn: &mut CantonConnection,
        begin_exclusive: u64,
    ) -> anyhow::Result<()> {
        let jwt_token = self.client.bearer_token().await?;
        let ws_url = format!("{}/v2/updates", self.client.config.json_api_ws_url);
        let party_id = &self.client.config.party_id;
        *ws_conn = CantonConnection::connect(
            &ws_url,
            &jwt_token,
            party_id,
            &self.client.config.signer_template_id,
            begin_exclusive,
        )
        .await?;
        Ok(())
    }

    async fn reconnect(&self, ws_conn: &mut CantonConnection, resume_offset: u64) {
        let mut backoff = Duration::from_secs(1);
        loop {
            match self.connect_and_subscribe(ws_conn, resume_offset).await {
                Ok(()) => {
                    tracing::info!(resume_offset, "canton WebSocket reconnected");
                    return;
                }
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        resume_offset,
                        backoff_secs = backoff.as_secs(),
                        "canton WebSocket reconnect failed; retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    async fn next_update(
        &self,
        ws_conn: &mut CantonConnection,
        last_seen_offset: u64,
    ) -> Option<ledger_api::Update> {
        loop {
            let Some(msg) = ws_conn.next().await else {
                self.reconnect(ws_conn, last_seen_offset).await;
                continue;
            };
            let Message::Text(text) = msg else {
                continue;
            };

            // TODO: need to fix this in case we are not able to parse
            // https://github.com/sig-net/mpc/issues/815
            let msg: ledger_api::UpdateMessage = match serde_json::from_str(&text) {
                Ok(msg) => msg,
                Err(err) => {
                    tracing::warn!(%err, "failed to parse canton WebSocket message");
                    continue;
                }
            };

            if let Some(err) = &msg.error {
                tracing::warn!(?err, "canton ledger stream error");
            }

            if let Some(update) = msg.update {
                return Some(update);
            }
        }
    }

    /// Decode a ledger update, emit its events + a `Block(offset)`, and report the
    /// offset so the caller can advance its cursor. Errors only when `events_tx` is
    /// closed (supervisor shutdown) — there is no transient failure worth retrying.
    async fn process_update(
        &self,
        events_tx: &mpsc::Sender<ChainEvent>,
        update: &ledger_api::Update,
    ) -> anyhow::Result<u64> {
        let offset = match update {
            ledger_api::Update::Transaction { value } => {
                for event in &value.events {
                    process_canton_event(
                        event,
                        &value.events,
                        events_tx,
                        &self.client.config.signer_contract_id,
                    )
                    .await;
                }
                value.offset
            }
            ledger_api::Update::OffsetCheckpoint { value } => value.offset,
        };

        self.telemetry.block_indexed(offset);
        events_tx.send(ChainEvent::Block(offset)).await?;
        Ok(offset)
    }

    /// Drive the WebSocket until `last_seen_offset >= target_offset`. A 2s per-pull
    /// timeout falls back to checking the ledger end: if the global ledger has passed
    /// the target with no events for our party, catchup completes without emitting.
    async fn process_catchup_offset(
        &self,
        ws_conn: &mut CantonConnection,
        events_tx: &mpsc::Sender<ChainEvent>,
        last_seen_offset: &mut u64,
        target_offset: u64,
        cancel: &CancellationToken,
    ) -> anyhow::Result<()> {
        if *last_seen_offset >= target_offset {
            return Ok(());
        }

        loop {
            // Try to get the next update with a conservative timeout during catchup.
            // If the WebSocket is silent for a short period, we check the current ledger end.
            let outcome = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                r = tokio::time::timeout(
                    Duration::from_secs(2),
                    self.next_update(ws_conn, *last_seen_offset),
                ) => r,
            };
            match outcome {
                Ok(Some(update)) => {
                    let offset = self.process_update(events_tx, &update).await?;
                    *last_seen_offset = offset;
                    if offset >= target_offset {
                        return Ok(());
                    }
                }
                Ok(None) => {
                    anyhow::bail!("canton WebSocket closed during catchup; reconnecting");
                }
                Err(_) => {
                    // Timeout elapsed. Check if the global ledger end has progressed past target_offset.
                    // This is necessary in cases where we have no catchup events in this period of time.
                    // next_update only gives us an update when there is a new event, so this timeout
                    // allows us to transition to live streaming
                    let current_ledger_end = self.client.fetch_ledger_end().await?;
                    if current_ledger_end >= target_offset {
                        tracing::info!(
                            current_ledger_end,
                            target_offset,
                            "catchup timeout: ledger has passed target offset with no new updates for our party"
                        );
                        *last_seen_offset = target_offset;
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[async_trait]
impl<S: StateManager, T: ChainTelemetry> ChainIndexer for CantonIndexer<S, T> {
    const CHAIN: Chain = Chain::Canton;

    // TODO: not used, required by trait, remove later
    type Block = ();
    type Iter = Empty<()>;

    // TODO: add unit tests for `run()` mirroring Ethereum's `RunFixture`
    // (catchup ordering, live-after-catchup, cancel-during-catchup, cancel-while-live).
    async fn run(
        &self,
        events_tx: mpsc::Sender<ChainEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let checkpoint = self
            .state_manager
            .get_processed_block(Chain::Canton)
            .await
            .unwrap_or(0);
        let mut last_seen_offset = checkpoint;

        let anchor = self.client.fetch_ledger_end().await?;
        let mut ws_conn = CantonConnection::Disconnected;
        self.reconnect(&mut ws_conn, last_seen_offset).await;

        self.process_catchup_offset(
            &mut ws_conn,
            &events_tx,
            &mut last_seen_offset,
            anchor,
            &cancel,
        )
        .await?;

        events_tx
            .send(ChainEvent::CatchupCompleted)
            .await
            .context("failed to send canton catchup completed event")?;

        loop {
            let update = tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                u = self.next_update(&mut ws_conn, last_seen_offset) => match u {
                    Some(u) => u,
                    None => anyhow::bail!("canton WebSocket producer terminated"),
                },
            };
            last_seen_offset = self.process_update(&events_tx, &update).await?;
        }
    }
}
