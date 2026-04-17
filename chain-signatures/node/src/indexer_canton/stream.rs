use crate::backlog::Backlog;
use crate::protocol::Chain;
use crate::rpc::CantonClient;
use crate::stream::ops::{RespondBidirectionalEvent, SignatureEvent, SignatureRespondedEvent};
use crate::stream::{ChainEvent, ChainStream};

use alloy::primitives::{keccak256, B256};

use futures_util::{SinkExt, StreamExt};
use mpc_primitives::{ScalarExt, Signature};
use std::collections::HashSet;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;
use tokio_tungstenite::tungstenite::Message;

use super::{
    contracts, ledger_api, CantonConfig, CantonRespondBidirectionalEvent,
    CantonSignBidirectionalRequestedEvent, CantonSignatureRespondedEvent,
};

struct CantonStreamStartState {
    config: CantonConfig,
    tx: mpsc::Sender<ChainEvent>,
    backlog: Backlog,
}

pub struct CantonStream {
    rx: mpsc::Receiver<ChainEvent>,
    start_state: Option<CantonStreamStartState>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for CantonStream {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
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

        let (tx, rx) = crate::stream::channel();

        Some(CantonStream {
            rx,
            start_state: Some(CantonStreamStartState {
                config,
                tx,
                backlog,
            }),
            tasks: Vec::new(),
        })
    }
}

impl ChainStream for CantonStream {
    const CHAIN: Chain = Chain::Canton;

    async fn start(&mut self) {
        let Some(state) = self.start_state.take() else {
            return;
        };

        self.tasks.push(tokio::spawn(async move {
            run_canton_event_loop(state.config, state.tx, state.backlog).await;
        }));
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        self.rx.recv().await
    }
}

/// Main event loop with reconnection logic and exponential backoff.
async fn run_canton_event_loop(
    config: CantonConfig,
    tx: mpsc::Sender<ChainEvent>,
    backlog: Backlog,
) {
    let client = match CantonClient::new(&config).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(%e, "failed to create canton client — canton indexer disabled");
            return;
        }
    };

    // Seed counter from backlog checkpoint
    let mut counter = backlog.processed_block(Chain::Canton).await.unwrap_or(0);

    tracing::info!(initial_offset = counter, "canton event loop starting");

    let catchup_target = match client.fetch_ledger_end().await {
        Ok(offset) => offset,
        Err(e) => {
            tracing::warn!(%e, "failed to fetch ledger end — assuming already caught up");
            counter
        }
    };

    // Track whether we've emitted CatchupCompleted
    let mut catchup_completed = false;

    // If already at or past the ledger end, emit CatchupCompleted immediately
    if counter >= catchup_target {
        tracing::info!(counter, catchup_target, "canton already caught up");
        if tx.send(ChainEvent::CatchupCompleted).await.is_err() {
            tracing::error!("canton event channel closed");
            return;
        }
        catchup_completed = true;
    } else {
        tracing::info!(counter, catchup_target, "canton catching up");
    }

    // Exponential backoff: 1s, 2s, 4s, 8s, 16s, capped at 30s
    const MIN_BACKOFF_SECS: u64 = 1;
    const MAX_BACKOFF_SECS: u64 = 30;
    let mut backoff_secs = MIN_BACKOFF_SECS;

    loop {
        match subscribe_and_process(
            &client,
            &tx,
            &mut counter,
            catchup_target,
            &mut catchup_completed,
        )
        .await
        {
            Ok(()) => {
                tracing::info!("canton WebSocket stream ended cleanly, reconnecting...");
                // Reset backoff on clean disconnect
                backoff_secs = MIN_BACKOFF_SECS;
            }
            Err(e) => {
                tracing::warn!(%e, backoff_secs, "canton WebSocket error, reconnecting...");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        // Exponential backoff with cap
        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
    }
}

/// Connect to the Canton WebSocket, subscribe, and process events until disconnection.
async fn subscribe_and_process(
    client: &CantonClient,
    tx: &mpsc::Sender<ChainEvent>,
    counter: &mut u64,
    catchup_target: u64,
    catchup_completed: &mut bool,
) -> anyhow::Result<()> {
    let jwt_token = client.generate_jwt()?;

    let ws_url = format!("{}/v2/updates", client.json_api_ws_url);

    // Build request with subprotocol header
    let mut request = ws_url.into_client_request()?;
    request
        .headers_mut()
        .insert(header::SEC_WEBSOCKET_PROTOCOL, "daml.ws.auth".parse()?);
    request.headers_mut().insert(
        header::AUTHORIZATION,
        format!("Bearer {jwt_token}").parse()?,
    );

    let (ws_stream, _) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio_tungstenite::connect_async(request),
    )
    .await
    .map_err(|_| anyhow::anyhow!("canton WebSocket connect timed out"))??;
    let (mut write, mut read) = ws_stream.split();

    tracing::info!("canton WebSocket connected");

    // Send subscription message using updateFormat (Canton 3.4+).
    // TRANSACTION_SHAPE_LEDGER_EFFECTS gives us ExercisedEvent which we use
    // to verify the SignBidirectional choice was exercised on a Signer:Signer.
    let mut filters_by_party = serde_json::Map::new();
    filters_by_party.insert(client.party_id.clone(), serde_json::json!({}));

    let subscribe_msg = ledger_api::GetUpdatesRequest {
        begin_exclusive: *counter,
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
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        write.send(Message::Text(serde_json::to_string(&subscribe_msg)?.into())),
    )
    .await
    .map_err(|_| anyhow::anyhow!("canton WebSocket subscription send timed out"))??;

    // Process incoming messages with stall watchdog (matches Solana pattern)
    let stall_timeout = std::time::Duration::from_secs(60);
    let mut last_ws_msg = tokio::time::Instant::now();
    let mut watchdog = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        let msg = tokio::select! {
            maybe = read.next() => {
                match maybe {
                    Some(msg) => {
                        last_ws_msg = tokio::time::Instant::now();
                        msg?
                    }
                    None => break,
                }
            }
            _ = watchdog.tick() => {
                if last_ws_msg.elapsed() > stall_timeout {
                    anyhow::bail!("canton WebSocket stalled: no message for {stall_timeout:?}");
                }
                continue;
            }
        };
        let text = match msg {
            Message::Text(t) => t,
            // tokio-tungstenite auto-sends pong replies; manual Pong would double-respond
            Message::Close(_) => {
                tracing::info!("canton WebSocket received close frame");
                break;
            }
            _ => continue,
        };

        let msg: ledger_api::UpdateMessage = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%e, "failed to parse canton WebSocket message");
                continue;
            }
        };

        match msg.update {
            Some(ledger_api::Update::Transaction { value }) => {
                *counter = value.offset;

                for event in &value.events {
                    process_canton_event(
                        event,
                        &value.events,
                        tx,
                        &client.party_id,
                        &client.signer_cid,
                    )
                    .await;
                }
            }
            Some(ledger_api::Update::OffsetCheckpoint { value }) => {
                *counter = value.offset;
            }
            None => {
                if msg.error.is_some() {
                    tracing::warn!(error = ?msg.error, "canton ledger stream error");
                }
                continue;
            }
        }

        if tx.send(ChainEvent::Block(*counter)).await.is_err() {
            tracing::error!("canton event channel closed");
            return Ok(());
        }

        if !*catchup_completed && *counter >= catchup_target {
            tracing::info!(
                counter = *counter,
                catchup_target,
                "canton catchup completed"
            );
            if tx.send(ChainEvent::CatchupCompleted).await.is_err() {
                tracing::error!("canton event channel closed");
                return Ok(());
            }
            *catchup_completed = true;
        }
    }

    Ok(())
}

/// Process a single Canton event from a WebSocket transaction update.
///
/// `tx_events` is the full list of events in the transaction, used for
/// defense-in-depth verification (signatory checks, ExercisedEvent check).
///
/// NOTE: integration tests (`canton_stream.rs`) cover `SignBidirectionalEvent`
/// and `SignatureRespondedEvent` parsing against a real sandbox, but
/// `RespondBidirectionalEvent` parsing and the downstream bidirectional
/// execution flow (recovery ID fix, EVM tx construction, backlog advance)
/// are not yet tested end-to-end.
async fn process_canton_event(
    event: &ledger_api::Event,
    tx_events: &[ledger_api::Event],
    tx: &mpsc::Sender<ChainEvent>,
    node_party_id: &str,
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
        match parse_sign_bidirectional_event(created) {
            Ok(canton_event) => {
                if let Err(e) = verify_sign_event(
                    &canton_event,
                    created,
                    tx_events,
                    node_party_id,
                    signer_contract_id,
                ) {
                    tracing::warn!(%e, "canton SignBidirectionalEvent failed verification — dropping");
                    return;
                }

                let request_id = canton_event.generate_request_id();
                let entropy: [u8; 32] = keccak256(request_id).into();
                let boxed: crate::stream::ops::SignatureEventBox = Box::new(canton_event);
                match boxed.generate_sign_request(entropy) {
                    Ok(indexed) => {
                        if tx.send(ChainEvent::SignRequest(indexed)).await.is_err() {
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
            Ok(responded) => {
                let event = SignatureRespondedEvent::Canton(responded);
                if tx.send(ChainEvent::Respond(event)).await.is_err() {
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
        match parse_respond_bidirectional_event(created) {
            Ok(respond) => {
                let event = RespondBidirectionalEvent::Canton(respond);
                if tx
                    .send(ChainEvent::RespondBidirectional(event))
                    .await
                    .is_err()
                {
                    tracing::error!("canton event channel closed");
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
///
/// TODO(test): unit test each check in isolation — craft events where one
/// check fails and verify the correct error is returned. Test: mismatched
/// sig_network, non-signatory operator, non-signatory requester, missing
/// ExercisedEvent, missing nonce consumption, empty nonceCidText.
fn verify_sign_event(
    event: &contracts::SignBidirectionalRequestedEvent,
    created: &ledger_api::CreatedEvent,
    tx_events: &[ledger_api::Event],
    node_party_id: &str,
    signer_contract_id: &str,
) -> anyhow::Result<()> {
    // Check 0: sig_network must match this node's party ID
    if event.sig_network != node_party_id {
        anyhow::bail!(
            "sig_network {} does not match node party_id {node_party_id} — event is for a different MPC network",
            event.sig_network
        );
    }

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
    // See CantonConfig migration TODO.
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

    // Check 4: nonceCidText must correspond to a consuming ExercisedEvent on a
    // SigningNonce template in the same transaction. With LEDGER_EFFECTS, nonce
    // archival appears as a consuming exercise (not an ArchivedEvent).
    // This ensures: (a) the nonce was actually consumed (replay prevention),
    // and (b) it's a SigningNonce — not an arbitrary string.
    // NOTE: uses suffix matching for the template ID. Could be tightened to an
    // exact match by deriving the SigningNonce template ID from the Signer
    // package hash (same DAR, different module path).
    let nonce_cid = &event.nonce_cid_text;
    if nonce_cid.is_empty() {
        anyhow::bail!("nonceCidText is empty — malformed SignBidirectionalEvent");
    }
    let nonce_consumed = tx_events.iter().any(|e| matches!(
        e,
        ledger_api::Event::ExercisedEvent(ex)
            if ex.consuming
                && ex.contract_id == *nonce_cid
                && ledger_api::template_suffix_matches(&ex.template_id, ledger_api::templates::SIGNING_NONCE)
    ));
    if !nonce_consumed {
        anyhow::bail!(
            "nonceCidText {nonce_cid} does not match any consuming ExercisedEvent on SigningNonce in the transaction — possible replay or forged nonce"
        );
    }

    Ok(())
}

/// Parse a hex-encoded request ID into a 32-byte array.
fn parse_request_id_hex(s: &str) -> anyhow::Result<[u8; 32]> {
    s.parse::<B256>()
        .map_err(|e| anyhow::anyhow!("invalid request_id hex: {e}"))
        .map(|b| b.0)
}

fn parse_sign_bidirectional_event(
    created: &ledger_api::CreatedEvent,
) -> anyhow::Result<CantonSignBidirectionalRequestedEvent> {
    let event: contracts::SignBidirectionalRequestedEvent =
        serde_json::from_value(created.payload.clone())?;
    Ok(event)
}

fn parse_signature_responded_event(
    created: &ledger_api::CreatedEvent,
) -> anyhow::Result<CantonSignatureRespondedEvent> {
    let payload: contracts::SignatureRespondedEventPayload =
        serde_json::from_value(created.payload.clone())?;

    Ok(CantonSignatureRespondedEvent {
        request_id: parse_request_id_hex(&payload.request_id)?,
        responder: payload.responder,
        signature: parse_canton_signature(&payload.signature)?,
    })
}

fn parse_respond_bidirectional_event(
    created: &ledger_api::CreatedEvent,
) -> anyhow::Result<CantonRespondBidirectionalEvent> {
    let payload: contracts::RespondBidirectionalEventPayload =
        serde_json::from_value(created.payload.clone())?;

    let serialized_output = hex::decode(&payload.serialized_output)
        .map_err(|e| anyhow::anyhow!("invalid serializedOutput hex: {e}"))?;

    Ok(CantonRespondBidirectionalEvent {
        request_id: parse_request_id_hex(&payload.request_id)?,
        responder: payload.responder,
        serialized_output,
        signature: parse_canton_signature(&payload.signature)?,
    })
}

/// Parse a CantonSignature (union type) into an MPC Signature.
///
/// The recovery_id from the CantonSignature is preserved, allowing correct
/// reconstruction of the full `big_r` point with the right y-parity.
pub fn parse_canton_signature(sig: &contracts::CantonSignature) -> anyhow::Result<Signature> {
    match sig {
        contracts::CantonSignature::EcdsaSig(data) => {
            parse_der_signature_with_recovery(&data.der, data.recovery_id)
        }
    }
}

/// Parse a DER-encoded ECDSA signature with known recovery ID.
///
/// The recovery_id determines the y-parity for reconstructing `big_r`:
/// - 0 = even parity (0x02 compressed prefix)
/// - 1 = odd parity (0x03 compressed prefix)
pub fn parse_der_signature_with_recovery(
    hex_str: &str,
    recovery_id: u8,
) -> anyhow::Result<Signature> {
    use k256::elliptic_curve::{point::DecompressPoint, subtle::Choice};

    let sig = k256::ecdsa::Signature::from_der(&hex::decode(
        hex_str.strip_prefix("0x").unwrap_or(hex_str),
    )?)?;
    let (r, s) = sig.split_scalars();

    // Use correct parity based on recovery_id
    let parity = Choice::from(recovery_id & 1);

    Ok(Signature {
        big_r: k256::AffinePoint::decompress(&r.to_bytes(), parity)
            .into_option()
            .ok_or_else(|| anyhow::anyhow!("invalid r"))?,
        s: <k256::Scalar as ScalarExt>::from_bytes(s.to_bytes().into())
            .ok_or_else(|| anyhow::anyhow!("invalid s"))?,
        recovery_id,
    })
}
