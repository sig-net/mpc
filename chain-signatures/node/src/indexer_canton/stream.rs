use crate::backlog::Backlog;
use crate::protocol::Chain;
use crate::rpc::CantonClient;
use crate::stream::{ChainIndexer, ChainStream};

use alloy::primitives::keccak256;
use async_trait::async_trait;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use mpc_primitives::{
    ChainEvent, RespondBidirectionalEvent, ScalarExt, Signature, SignatureRespondedEvent,
};
use std::collections::HashSet;
use std::ops::Range;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::{contracts, ledger_api, CantonConfig, CantonSignBidirectionalRequestedEvent};

type CantonWs = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
type CantonWsRead = SplitStream<CantonWs>;
type CantonWsWrite = SplitSink<CantonWs, Message>;

pub struct CantonStream {
    config: CantonConfig,
    backlog: Backlog,
    events_rx: mpsc::Receiver<ChainEvent>,
    events_tx: Option<mpsc::Sender<ChainEvent>>,
}

impl CantonStream {
    pub fn new(config: Option<CantonConfig>, backlog: Backlog) -> Option<Self> {
        let config = match config {
            Some(c) => c,
            None => {
                tracing::warn!("canton indexer is disabled");
                return None;
            }
        };

        let (events_tx, events_rx) = crate::stream::channel();

        Some(CantonStream {
            config,
            backlog,
            events_rx,
            events_tx: Some(events_tx),
        })
    }
}

#[async_trait]
impl ChainStream for CantonStream {
    type Indexer = CantonIndexer;

    async fn start(&mut self) -> anyhow::Result<Self::Indexer> {
        let Some(events_tx) = self.events_tx.take() else {
            anyhow::bail!("canton stream already started");
        };

        let client = CantonClient::new(&self.config).await?;
        Ok(Self::Indexer::new(client, self.backlog.clone(), events_tx))
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        self.events_rx.recv().await
    }
}

enum CantonConnection {
    Connected(CantonWsRead, CantonWsWrite),
    Disconnected,
}

impl CantonConnection {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    const MESSAGE_TIMEOUT: Duration = Duration::from_secs(60);
    const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    async fn connect(
        ws_url: &str,
        jwt_token: &str,
        party_id: &str,
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

        let mut filters_by_party = serde_json::Map::new();
        filters_by_party.insert(party_id.to_string(), serde_json::json!({}));

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

    /// Read the next message from the WebSocket. Closes the connection if the WebSocket is closed.
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

pub struct CantonIndexer {
    client: CantonClient,
    backlog: Backlog,
    events_tx: mpsc::Sender<ChainEvent>,
    ws_conn: CantonConnection,
    last_seen_offset: u64,
}

impl CantonIndexer {
    pub fn new(
        client: CantonClient,
        backlog: Backlog,
        events_tx: mpsc::Sender<ChainEvent>,
    ) -> Self {
        Self {
            client,
            backlog,
            events_tx,
            ws_conn: CantonConnection::Disconnected,
            last_seen_offset: 0,
        }
    }

    async fn connect_and_subscribe(&mut self, begin_exclusive: u64) -> anyhow::Result<()> {
        let jwt_token = self.client.bearer_token().await?;
        let ws_url = format!("{}/v2/updates", self.client.config.json_api_ws_url);
        let party_id = &self.client.config.party_id;
        self.ws_conn =
            CantonConnection::connect(&ws_url, &jwt_token, party_id, begin_exclusive).await?;
        Ok(())
    }

    async fn reconnect(&mut self, begin_exclusive: u64) {
        let mut backoff = Duration::from_secs(1);

        loop {
            match self.connect_and_subscribe(begin_exclusive).await {
                Ok(()) => {
                    tracing::info!(
                        resume_offset = self.last_seen_offset,
                        "canton WebSocket reconnected"
                    );
                    return;
                }
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        resume_offset = self.last_seen_offset,
                        backoff_secs = backoff.as_secs(),
                        "canton WebSocket reconnect failed; retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    async fn next_update(&mut self) -> Option<ledger_api::Update> {
        loop {
            let Some(msg) = self.ws_conn.next().await else {
                self.reconnect(self.last_seen_offset).await;
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

    async fn process_update(&mut self, update: &ledger_api::Update) -> anyhow::Result<u64> {
        let offset = match update {
            ledger_api::Update::Transaction { value } => {
                for event in &value.events {
                    process_canton_event(
                        event,
                        &value.events,
                        &self.events_tx,
                        &self.client.config.signer_contract_id,
                    )
                    .await;
                }
                value.offset
            }
            ledger_api::Update::OffsetCheckpoint { value } => value.offset,
        };

        self.events_tx.send(ChainEvent::Block(offset)).await?;
        self.last_seen_offset = offset;
        Ok(offset)
    }

    async fn process_catchup_offset(&mut self, target_offset: u64) -> anyhow::Result<()> {
        // If we're already at or past the target offset, we're done
        if self.last_seen_offset >= target_offset {
            return Ok(());
        }

        loop {
            let Some(update) = self.next_update().await else {
                anyhow::bail!("canton WebSocket closed during catchup; reconnecting");
            };
            let offset = self.process_update(&update).await?;
            if offset >= target_offset {
                return Ok(());
            }
        }
    }
}

fn catchup_offset_range(checkpoint: u64, anchor_height: u64) -> Range<u64> {
    let start = checkpoint.saturating_add(1).min(anchor_height);
    start..anchor_height
}

#[async_trait]
impl ChainIndexer for CantonIndexer {
    const CHAIN: Chain = Chain::Canton;
    type Block = u64;
    type Iter = Range<u64>;

    async fn livestream(&mut self) -> anyhow::Result<Option<u64>> {
        let checkpoint = self
            .backlog
            .processed_block(Chain::Canton)
            .await
            .unwrap_or(0);
        self.last_seen_offset = checkpoint;
        let anchor_height = self.client.fetch_ledger_end().await?;
        self.reconnect(self.last_seen_offset).await;
        Ok(Some(anchor_height))
    }

    async fn catchup_range(&self, anchor_height: u64) -> Self::Iter {
        // After a reconnect, we resume from last_seen_offset, so catchup should start there.
        catchup_offset_range(self.last_seen_offset, anchor_height)
    }

    async fn process_catchup(&mut self, &item: &Self::Block) -> anyhow::Result<()> {
        self.process_catchup_offset(item).await
    }

    async fn notify_catchup_completed(&mut self) -> anyhow::Result<()> {
        self.events_tx.send(ChainEvent::CatchupCompleted).await?;
        Ok(())
    }

    async fn process_next_block(&mut self) -> bool {
        let Some(update) = self.next_update().await else {
            return false;
        };

        while let Err(err) = self.process_update(&update).await {
            tracing::warn!(?err, "live block processing failed; retrying");
            tokio::time::sleep(Self::RETRY_DELAY).await;
        }

        true
    }
}

/// Process a single Canton event from a WebSocket transaction update.
///
/// `tx_events` is the full list of events in the transaction, used for
/// defense-in-depth verification (signatory checks, ExercisedEvent check).
async fn process_canton_event(
    event: &ledger_api::Event,
    tx_events: &[ledger_api::Event],
    events_tx: &mpsc::Sender<ChainEvent>,
    signer_contract_id: &str,
) {
    let created = match event {
        ledger_api::Event::CreatedEvent(created) => created,
        ledger_api::Event::ArchivedEvent(_) | ledger_api::Event::ExercisedEvent(_) => return,
    };

    let template_id = &created.template_id;

    if ledger_api::template_suffix_matches(
        template_id,
        ledger_api::templates::SIGN_BIDIRECTIONAL_EVENT,
    ) {
        match serde_json::from_value::<contracts::SignBidirectionalRequestedEvent>(
            created.payload.clone(),
        ) {
            Ok(raw) => {
                if let Err(e) = verify_sign_event(&raw, created, tx_events, signer_contract_id) {
                    tracing::warn!(%e, "canton SignBidirectionalEvent failed verification — dropping");
                    return;
                }

                let canton_event = match CantonSignBidirectionalRequestedEvent::from_created(
                    created.contract_id.clone(),
                    raw,
                ) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::warn!(%e, "failed to parse SignBidirectionalEvent");
                        return;
                    }
                };
                let request_id = canton_event.generate_request_id();
                let entropy: [u8; 32] = keccak256(request_id).into();
                match canton_event.generate_sign_request(entropy) {
                    Ok(indexed) => {
                        if events_tx
                            .send(ChainEvent::SignRequest(indexed))
                            .await
                            .is_err()
                        {
                            tracing::error!("canton event channel closed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%e, "failed to generate canton sign request");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(%e, "failed to parse SignBidirectionalEvent");
            }
        }
    } else if ledger_api::template_suffix_matches(
        template_id,
        ledger_api::templates::SIGNATURE_RESPONDED_EVENT,
    ) {
        match parse_signature_responded_event(created) {
            Ok(event) => {
                if events_tx.send(ChainEvent::Respond(event)).await.is_err() {
                    tracing::error!("canton event channel closed");
                }
            }
            Err(e) => {
                tracing::warn!(%e, "failed to parse SignatureRespondedEvent");
            }
        }
    } else if ledger_api::template_suffix_matches(
        template_id,
        ledger_api::templates::RESPOND_BIDIRECTIONAL_EVENT,
    ) {
        match serde_json::from_value::<contracts::RespondBidirectionalEventPayload>(
            created.payload.clone(),
        ) {
            Ok(payload) => {
                let mut request_id = [0u8; 32];
                if let Err(e) = hex::decode_to_slice(&payload.request_id, &mut request_id) {
                    tracing::warn!(%e, "invalid request_id hex");
                } else {
                    let signature = match parse_canton_signature(&payload.signature) {
                        Ok(signature) => signature,
                        Err(e) => {
                            tracing::warn!(%e, "invalid signature in canton RespondBidirectionalEvent");
                            return;
                        }
                    };
                    if events_tx
                        .send(ChainEvent::RespondBidirectional(
                            RespondBidirectionalEvent {
                                request_id,
                                signature,
                                chain: crate::protocol::Chain::Canton,
                            },
                        ))
                        .await
                        .is_err()
                    {
                        tracing::error!("canton event channel closed");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(%e, "failed to parse RespondBidirectionalEvent");
            }
        }
    }
}

/// Verify a SignBidirectionalEvent before processing it.
///
/// These checks are defense-in-depth on top of the Daml ledger guarantees:
/// 1. Operators from the payload must be actual signatories on the CreatedEvent
/// 2. Requester must be a signatory
/// 3. An ExercisedEvent with choice "SignBidirectional" on Signer:Signer must
///    exist in the same transaction — proves the event was created through the
///    correct Daml code path, not fabricated
fn verify_sign_event(
    event: &contracts::SignBidirectionalRequestedEvent,
    created: &ledger_api::CreatedEvent,
    tx_events: &[ledger_api::Event],
    signer_contract_id: &str,
) -> anyhow::Result<()> {
    let signatories: HashSet<&str> = created.signatories.iter().map(|s| s.as_str()).collect();

    // Check 1: operators must be signatories (hard error)
    for op in &event.operators {
        if !signatories.contains(op.as_str()) {
            anyhow::bail!(
                "operator {op} is in contract payload but not in CreatedEvent.signatories — possible forgery"
            );
        }
    }

    // Check 2: requester must be a signatory (hard error)
    if !signatories.contains(event.requester.as_str()) {
        anyhow::bail!(
            "requester {} is not in CreatedEvent.signatories — possible forgery",
            event.requester
        );
    }

    // Check 3: ExercisedEvent with choice "SignBidirectional" on the pinned
    // Signer contract must exist in the same transaction. Exact contract ID
    // match since the operator pinned it via CLI.
    // NOTE: after a DAR upgrade/redeployment the contract ID changes — this
    // check will reject all events until the node is restarted with the new ID.
    let has_exercise = tx_events.iter().any(|e| {
        matches!(
            e,
            ledger_api::Event::ExercisedEvent(ex)
                if ex.choice == "SignBidirectional"
                    && ex.contract_id == signer_contract_id
        )
    });
    if !has_exercise {
        anyhow::bail!(
            "no ExercisedEvent with choice SignBidirectional on contract {signer_contract_id} found in transaction"
        );
    }

    Ok(())
}

fn parse_signature_responded_event(
    created: &ledger_api::CreatedEvent,
) -> anyhow::Result<SignatureRespondedEvent> {
    let payload: contracts::SignatureRespondedEventPayload =
        serde_json::from_value(created.payload.clone())?;
    let mut request_id = [0u8; 32];
    hex::decode_to_slice(&payload.request_id, &mut request_id)
        .map_err(|e| anyhow::anyhow!("invalid request_id hex: {e}"))?;

    Ok(SignatureRespondedEvent {
        request_id,
        signature: parse_canton_signature(&payload.signature)?,
        chain: Chain::Canton,
    })
}

/// Parse a CantonSignature (union type) into an MPC Signature.
pub fn parse_canton_signature(sig: &contracts::CantonSignature) -> anyhow::Result<Signature> {
    match sig {
        contracts::CantonSignature::EcdsaSig(data) => {
            parse_der_signature_with_recovery(&data.der, data.recovery_id)
        }
    }
}

/// Parse a DER-encoded ECDSA signature with known recovery ID.
pub fn parse_der_signature_with_recovery(
    hex_str: &str,
    recovery_id: u8,
) -> anyhow::Result<Signature> {
    use k256::elliptic_curve::{point::DecompressPoint, subtle::Choice};

    let sig = k256::ecdsa::Signature::from_der(&hex::decode(hex_str)?)?;
    let (r, s) = sig.split_scalars();

    anyhow::ensure!(
        recovery_id <= 1,
        "invalid recovery_id {recovery_id}: expected 0 or 1"
    );
    let parity = Choice::from(recovery_id);

    Ok(Signature {
        big_r: k256::AffinePoint::decompress(&r.to_bytes(), parity)
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("invalid r"))?,
        s: <k256::Scalar as ScalarExt>::from_bytes(s.to_bytes().into())
            .ok_or_else(|| anyhow::anyhow!("invalid s"))?,
        recovery_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer_canton::der_encode_signature;
    use k256::AffinePoint;
    use serde_json::json;

    fn sample_tx_params() -> contracts::TxParams {
        contracts::TxParams::EvmType2TxParams(contracts::EvmType2TransactionParams {
            chain_id: format!("{:064x}", 1u64),
            nonce: format!("{:064x}", 0u64),
            max_priority_fee_per_gas: format!("{:064x}", 1u64),
            max_fee_per_gas: format!("{:064x}", 2u64),
            gas_limit: format!("{:064x}", 21_000u64),
            to: Some(hex::encode([3u8; 20])),
            value: format!("{:064x}", 0u64),
            calldata: String::new(),
            access_list: Vec::new(),
        })
    }

    fn sample_sign_event() -> contracts::SignBidirectionalRequestedEvent {
        contracts::SignBidirectionalRequestedEvent {
            operators: vec!["operator-1".to_string()],
            sender: hex::encode([7u8; 32]),
            requester: "requester-1".to_string(),
            sig_network: "testnet".to_string(),
            tx_params: sample_tx_params(),
            caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
            key_version: 0,
            path: "m/0".to_string(),
            algo: "secp256k1".to_string(),
            dest: Chain::Ethereum.to_string(),
            params: "{}".to_string(),
            output_deserialization_schema: "[]".to_string(),
            respond_serialization_schema: "[]".to_string(),
        }
    }

    fn sample_created_event(signatories: &[&str]) -> ledger_api::CreatedEvent {
        ledger_api::CreatedEvent {
            contract_id: "cid-1".to_string(),
            template_id: ledger_api::templates::SIGN_BIDIRECTIONAL_EVENT.to_string(),
            payload: json!({}),
            created_event_blob: None,
            signatories: signatories.iter().map(|s| (*s).to_string()).collect(),
            witness_parties: Vec::new(),
            node_id: Some(1),
            package_name: None,
        }
    }

    fn sample_exercised_event(contract_id: &str) -> ledger_api::Event {
        ledger_api::Event::ExercisedEvent(ledger_api::ExercisedEvent {
            contract_id: contract_id.to_string(),
            template_id: "pkg:Signer:Signer".to_string(),
            choice: "SignBidirectional".to_string(),
            acting_parties: Vec::new(),
            consuming: false,
            node_id: Some(2),
            last_descendant_node_id: Some(2),
            package_name: None,
        })
    }

    fn sample_canton_signature() -> contracts::CantonSignature {
        let signature = Signature::new(AffinePoint::GENERATOR, k256::Scalar::from(9u64), 0);
        let der = hex::encode(der_encode_signature(&signature).expect("signature should encode"));
        contracts::CantonSignature::EcdsaSig(contracts::EcdsaSigData {
            der,
            recovery_id: 0,
        })
    }

    #[test]
    fn catchup_range_without_checkpoint_starts_at_one() {
        let offsets: Vec<_> = catchup_offset_range(0, 5).collect();
        assert_eq!(offsets, vec![1, 2, 3, 4]);
    }

    #[test]
    fn catchup_range_uses_checkpoint_plus_one() {
        let offsets: Vec<_> = catchup_offset_range(5, 9).collect();
        assert_eq!(offsets, vec![6, 7, 8]);
    }

    #[test]
    fn catchup_range_empty_when_caught_up() {
        let offsets: Vec<_> = catchup_offset_range(9, 9).collect();
        assert!(offsets.is_empty());
    }

    #[test]
    fn catchup_range_empty_when_checkpoint_past_anchor() {
        let offsets: Vec<_> = catchup_offset_range(12, 9).collect();
        assert!(offsets.is_empty());
    }

    #[test]
    fn verify_sign_event_rejects_missing_operator_signatory() {
        let event = sample_sign_event();
        let created = sample_created_event(&["requester-1"]);
        let tx_events = vec![sample_exercised_event("signer-contract")];

        let err = verify_sign_event(&event, &created, &tx_events, "signer-contract")
            .expect_err("verification should fail");
        assert!(err.to_string().contains("operator operator-1"));
    }

    #[test]
    fn verify_sign_event_rejects_missing_requester_signatory() {
        let event = sample_sign_event();
        let created = sample_created_event(&["operator-1"]);
        let tx_events = vec![sample_exercised_event("signer-contract")];

        let err = verify_sign_event(&event, &created, &tx_events, "signer-contract")
            .expect_err("verification should fail");
        assert!(err.to_string().contains("requester requester-1"));
    }

    #[test]
    fn verify_sign_event_rejects_missing_exercised_event() {
        let event = sample_sign_event();
        let created = sample_created_event(&["operator-1", "requester-1"]);
        let tx_events = Vec::new();

        let err = verify_sign_event(&event, &created, &tx_events, "signer-contract")
            .expect_err("verification should fail");
        assert!(err.to_string().contains("no ExercisedEvent"));
    }

    #[test]
    fn parse_signature_responded_event_rejects_invalid_hex() {
        let created = ledger_api::CreatedEvent {
            contract_id: "cid-respond".to_string(),
            template_id: ledger_api::templates::SIGNATURE_RESPONDED_EVENT.to_string(),
            payload: json!({
                "requestId": "zz",
                "responder": "alice",
                "signature": {
                    "tag": "EcdsaSig",
                    "value": {
                        "der": "00",
                        "recoveryId": "0"
                    }
                }
            }),
            created_event_blob: None,
            signatories: Vec::new(),
            witness_parties: Vec::new(),
            node_id: None,
            package_name: None,
        };

        let err = parse_signature_responded_event(&created).expect_err("invalid hex should fail");
        assert!(err.to_string().contains("invalid request_id hex"));
    }

    #[test]
    fn parse_respond_bidirectional_event_parses_valid_payload() {
        let created = ledger_api::CreatedEvent {
            contract_id: "cid-respond-bidir".to_string(),
            template_id: ledger_api::templates::RESPOND_BIDIRECTIONAL_EVENT.to_string(),
            payload: json!({
                "requestId": hex::encode([5u8; 32]),
                "responder": "alice",
                "serializedOutput": hex::encode([8u8, 9u8]),
                "signature": sample_canton_signature(),
            }),
            created_event_blob: None,
            signatories: Vec::new(),
            witness_parties: Vec::new(),
            node_id: None,
            package_name: None,
        };

        let payload: contracts::RespondBidirectionalEventPayload =
            serde_json::from_value(created.payload.clone()).expect("payload should parse");
        let mut request_id = [0u8; 32];
        hex::decode_to_slice(&payload.request_id, &mut request_id).unwrap();
        assert_eq!(request_id, [5u8; 32]);
        assert_eq!(payload.responder, "alice");
        assert_eq!(
            hex::decode(&payload.serialized_output).unwrap(),
            vec![8u8, 9u8]
        );
    }

    #[tokio::test]
    async fn process_canton_event_routes_respond_without_catchup_completed() {
        let created = ledger_api::CreatedEvent {
            contract_id: "cid-respond".to_string(),
            template_id: ledger_api::templates::SIGNATURE_RESPONDED_EVENT.to_string(),
            payload: json!({
                "requestId": hex::encode([6u8; 32]),
                "responder": "alice",
                "signature": sample_canton_signature(),
            }),
            created_event_blob: None,
            signatories: Vec::new(),
            witness_parties: Vec::new(),
            node_id: None,
            package_name: None,
        };
        let (events_tx, mut events_rx) = crate::stream::channel();

        process_canton_event(
            &ledger_api::Event::CreatedEvent(created),
            &[],
            &events_tx,
            "signer-contract",
        )
        .await;

        match events_rx.recv().await {
            Some(ChainEvent::Respond(event)) => {
                assert_eq!(event.chain, Chain::Canton);
                assert_eq!(event.request_id, [6u8; 32]);
            }
            other => panic!("expected Canton respond event, got {other:?}"),
        }
        assert!(
            events_rx.try_recv().is_err(),
            "unexpected extra event emitted"
        );
    }
}
