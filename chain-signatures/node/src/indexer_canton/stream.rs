use crate::backlog::Backlog;
use crate::protocol::Chain;
use crate::stream::ops::{RespondBidirectionalEvent, SignatureEvent, SignatureRespondedEvent};
use crate::stream::{ChainEvent, ChainStream};

use alloy::primitives::{keccak256, B256};

use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::EncodingKey;
use mpc_primitives::{ScalarExt, Signature};
use std::collections::HashSet;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;
use tokio_tungstenite::tungstenite::Message;

use super::api::generate_jwt_with_key;
use super::{
    contracts, ledger_api, CantonConfig, CantonRespondBidirectionalEvent,
    CantonSignBidirectionalRequestedEvent, CantonSignatureRespondedEvent,
};

// ---------------------------------------------------------------------------
// WebSocket event stream
// ---------------------------------------------------------------------------

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

/// Main event loop with reconnection logic.
async fn run_canton_event_loop(
    config: CantonConfig,
    tx: mpsc::Sender<ChainEvent>,
    backlog: Backlog,
) {
    // Read PEM once at startup and parse the key (no re-parsing per reconnect)
    let encoding_key = match tokio::fs::read(&config.jwt_private_key_path).await {
        Ok(pem) => match EncodingKey::from_ec_pem(&pem) {
            Ok(key) => key,
            Err(e) => {
                tracing::error!(%e, "failed to parse canton JWT private key — canton indexer disabled");
                return;
            }
        },
        Err(e) => {
            tracing::error!(%e, "failed to read canton JWT private key — canton indexer disabled");
            return;
        }
    };

    // Seed counter from backlog checkpoint
    let mut counter = backlog.processed_block(Chain::Canton).await.unwrap_or(0);

    tracing::info!(initial_offset = counter, "canton event loop starting");

    loop {
        match subscribe_and_process(&config, &encoding_key, &tx, &mut counter).await {
            Ok(()) => {
                tracing::info!("canton WebSocket stream ended cleanly, reconnecting...");
            }
            Err(e) => {
                tracing::warn!(%e, "canton WebSocket error, reconnecting in 1s...");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// Connect to the Canton WebSocket, subscribe, and process events until disconnection.
async fn subscribe_and_process(
    config: &CantonConfig,
    encoding_key: &EncodingKey,
    tx: &mpsc::Sender<ChainEvent>,
    counter: &mut u64,
) -> anyhow::Result<()> {
    let jwt_token = generate_jwt_with_key(encoding_key, &config.jwt_subject)?;

    let ws_url = format!("{}/v2/updates", config.json_api_ws_url);

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
    filters_by_party.insert(config.party_id.clone(), serde_json::json!({}));

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
    write
        .send(Message::Text(serde_json::to_string(&subscribe_msg)?.into()))
        .await?;

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
                        &config.party_id,
                        &config.signer_contract_id,
                    )
                    .await;
                }

                // Emit Block event for checkpoint tracking
                if tx.send(ChainEvent::Block(*counter)).await.is_err() {
                    tracing::error!("canton event channel closed");
                    return Ok(());
                }
            }
            Some(ledger_api::Update::OffsetCheckpoint { value }) => {
                *counter = value.offset;
                if tx.send(ChainEvent::Block(*counter)).await.is_err() {
                    tracing::error!("canton event channel closed");
                    return Ok(());
                }
            }
            None => {
                if msg.error.is_some() {
                    tracing::warn!(error = ?msg.error, "canton ledger stream error");
                }
            }
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
                    tracing::error!(%e, "canton SignBidirectionalEvent failed verification — dropping");
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

// ---------------------------------------------------------------------------
// Defense-in-depth verification (mirrors canton-mpc-poc TS tx-handler.ts)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Event parsing from Canton JSON payloads
// ---------------------------------------------------------------------------

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

    let request_id: [u8; 32] = payload
        .request_id
        .parse::<B256>()
        .map_err(|e| anyhow::anyhow!("invalid request_id hex: {e}"))?
        .0;
    let signature = parse_der_signature(&payload.signature)?;

    Ok(CantonSignatureRespondedEvent {
        request_id,
        responder: payload.responder,
        signature,
    })
}

fn parse_respond_bidirectional_event(
    created: &ledger_api::CreatedEvent,
) -> anyhow::Result<CantonRespondBidirectionalEvent> {
    let payload: contracts::RespondBidirectionalEventPayload =
        serde_json::from_value(created.payload.clone())?;

    let request_id: [u8; 32] = payload
        .request_id
        .parse::<B256>()
        .map_err(|e| anyhow::anyhow!("invalid request_id hex: {e}"))?
        .0;
    let serialized_output = hex::decode(&payload.serialized_output)
        .map_err(|e| anyhow::anyhow!("invalid serializedOutput hex: {e}"))?;
    let signature = parse_der_signature(&payload.signature)?;

    Ok(CantonRespondBidirectionalEvent {
        request_id,
        responder: payload.responder,
        serialized_output,
        signature,
    })
}

/// Parse a DER-encoded ECDSA signature (hex string) back into an MPC Signature.
///
/// Canton emits signatures in DER format (see [`der_encode_signature`] for why).
/// We extract r and s via k256's DER parser, then reconstruct `big_r` by
/// decompressing the r scalar as a secp256k1 x-coordinate with even parity.
///
/// **Important:** DER does not encode the recovery ID (y-parity). The returned
/// `recovery_id` defaults to `0` (even parity) and may be incorrect for ~50%
/// of signatures. Callers that need the correct recovery ID must determine it
/// themselves by recovering the public key from the message hash — see
/// [`crate::kdf::into_signature`] for the canonical approach.
///
/// TODO(test): test with known DER signatures (both even and odd y-parity).
/// Verify that recovery_id=0 is correctly resolved downstream when the public
/// key is known. Test the encode→parse roundtrip preserves (r, s) scalars.
pub fn parse_der_signature(hex_str: &str) -> anyhow::Result<Signature> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;

    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).map_err(|e| anyhow::anyhow!("invalid DER hex: {e}"))?;

    let ecdsa_sig = k256::ecdsa::Signature::from_der(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid DER signature: {e}"))?;

    let (r_scalar, s_scalar) = ecdsa_sig.split_scalars();
    let r_bytes = r_scalar.to_bytes();
    let s_bytes: [u8; 32] = s_scalar.to_bytes().into();
    let s = <k256::Scalar as ScalarExt>::from_bytes(s_bytes)
        .ok_or_else(|| anyhow::anyhow!("s is not a valid scalar"))?;

    // Reconstruct big_r from the x-coordinate with even parity (0x02).
    // Both parities always yield valid secp256k1 points, so the old loop
    // that checked `from_encoded_point` was a no-op — it always took the
    // first branch.  The actual recovery_id must be resolved later against
    // the expected public key and message hash.
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02; // even parity
    compressed[1..].copy_from_slice(&r_bytes);
    let encoded = EncodedPoint::from_bytes(compressed)
        .map_err(|e| anyhow::anyhow!("r is not valid compressed point bytes: {e}"))?;
    let big_r = Option::from(k256::AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| anyhow::anyhow!("r is not a valid point on secp256k1"))?;

    Ok(Signature {
        big_r,
        s,
        recovery_id: 0,
    })
}
