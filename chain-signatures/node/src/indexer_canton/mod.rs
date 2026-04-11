mod api;
mod request_id;
use request_id::compute_request_id;

pub use api::{der_encode_signature, discover_signer_cid};
pub(crate) use api::generate_jwt_with_key;

use crate::backlog::Backlog;
use mpc_primitives::MAX_SECP256K1_SCALAR;
use crate::protocol::Chain;
use crate::sign_bidirectional::hash_rlp_data;
use crate::stream::ops::{
    RespondBidirectionalEvent, SignBidirectionalEvent, SignatureEvent, SignatureRespondedEvent,
};
use crate::stream::{ChainEvent, ChainStream};

use alloy::consensus::TxEip1559;
use alloy::primitives::{keccak256, Address, B256, Bytes, TxKind, U256};
use canton_types::{contracts, ledger_api};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashSet;
use jsonwebtoken::EncodingKey;
use k256::Scalar;
use mpc_primitives::{ScalarExt, SignArgs, SignId, Signature, LATEST_MPC_KEY_VERSION};
use std::fmt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;
use tokio_tungstenite::tungstenite::Message;

// ---------------------------------------------------------------------------
// Canton event structs
// ---------------------------------------------------------------------------

pub use canton_types::contracts::EvmTransactionParams as CantonEvmTransactionParams;
pub use canton_types::contracts::SignBidirectionalRequestedEvent as CantonSignBidirectionalRequestedEvent;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CantonRespondBidirectionalEvent {
    pub request_id: [u8; 32],
    pub responder: String,
    pub serialized_output: Vec<u8>,
    pub signature: Signature,
}
// NOTE: No Hash derive — Signature contains k256 types that don't impl Hash

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CantonSignatureRespondedEvent {
    pub request_id: [u8; 32],
    pub responder: String,
    pub signature: Signature,
}
// NOTE: No Hash, PartialEq, Eq derives — matches HydrationSignatureRespondedEvent

// ---------------------------------------------------------------------------
// RLP encoding of unsigned EIP-1559 transaction
// ---------------------------------------------------------------------------

/// Build calldata from function signature and args.
/// calldata = keccak256("function " + sig)[0..4] ++ concat(args)
fn build_calldata(function_signature: &str, args: &[String]) -> Vec<u8> {
    // EVM selector = first 4 bytes of keccak256 of the bare signature,
    // e.g. "transfer(address,uint256)", NOT prefixed with "function ".
    let selector: [u8; 4] = keccak256(function_signature.as_bytes()).0[..4]
        .try_into()
        .unwrap();
    let mut calldata = selector.to_vec();
    for arg in args {
        calldata.extend_from_slice(&hex::decode(arg).unwrap_or_default());
    }
    calldata
}

/// Convert Canton EvmTransactionParams to an alloy TxEip1559.
fn to_tx_eip1559(p: &CantonEvmTransactionParams) -> anyhow::Result<TxEip1559> {
    let to_bytes = hex::decode(&p.to)?;
    // Canton pads to 64 hex chars (32 bytes) — take last 20 for the address
    let addr_bytes = if to_bytes.len() > 20 {
        &to_bytes[to_bytes.len() - 20..]
    } else {
        &to_bytes
    };

    Ok(TxEip1559 {
        chain_id: u64::from_str_radix(&p.chain_id, 16).unwrap_or(0),
        nonce: u64::from_str_radix(&p.nonce, 16).unwrap_or(0),
        gas_limit: u64::from_str_radix(&p.gas_limit, 16).unwrap_or(0),
        max_fee_per_gas: u128::from_str_radix(&p.max_fee_per_gas, 16).unwrap_or(0),
        max_priority_fee_per_gas: u128::from_str_radix(&p.max_priority_fee, 16).unwrap_or(0),
        to: TxKind::Call(Address::from_slice(addr_bytes)),
        value: U256::from_str_radix(&p.value, 16).unwrap_or(U256::ZERO),
        input: Bytes::from(build_calldata(&p.function_signature, &p.args)),
        access_list: Default::default(),
    })
}

/// RLP-encode an unsigned EIP-1559 transaction using alloy.
pub fn rlp_encode_unsigned_eip1559(params: &CantonEvmTransactionParams) -> Vec<u8> {
    match to_tx_eip1559(params) {
        Ok(tx) => {
            use alloy::consensus::transaction::SignableTransaction;
            let mut out = Vec::new();
            tx.encode_for_signing(&mut out);
            out
        }
        Err(e) => {
            tracing::warn!(%e, "failed to build TxEip1559 from Canton params");
            vec![]
        }
    }
}

// ---------------------------------------------------------------------------
// SignatureEvent impl for Canton sign bidirectional
// ---------------------------------------------------------------------------

impl SignatureEvent for CantonSignBidirectionalRequestedEvent {
    fn generate_request_id(&self) -> [u8; 32] {
        compute_request_id(self)
    }

    fn generate_sign_request(&self, entropy: [u8; 32]) -> anyhow::Result<crate::protocol::IndexedSignRequest> {
        tracing::info!("found canton event: {:?}", self);

        if self.key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!("unsupported key version: {}", self.key_version);
            anyhow::bail!("unsupported key version");
        }

        let request_id = self.generate_request_id();

        let epsilon = mpc_crypto::kdf::derive_epsilon_canton(
            self.key_version,
            &self.sender,
            &self.path,
        );

        let rlp_encoded_tx = rlp_encode_unsigned_eip1559(&self.evm_tx_params);
        let unsigned_tx_hash = hash_rlp_data(rlp_encoded_tx);

        let Some(payload) = Scalar::from_bytes(unsigned_tx_hash) else {
            anyhow::bail!(
                "failed to convert unsigned_tx_hash to scalar: {unsigned_tx_hash:?}"
            );
        };

        if payload > *MAX_SECP256K1_SCALAR {
            tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
            anyhow::bail!("payload exceeds secp256k1 curve order");
        }

        let sign_id = SignId::new(request_id);
        tracing::info!(?sign_id, "canton signature requested");

        Ok(crate::protocol::IndexedSignRequest::sign_bidirectional(
            sign_id,
            SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            Chain::Canton,
            crate::util::current_unix_timestamp(),
            SignBidirectionalEvent::Canton(self.clone()),
        ))
    }

    fn source_chain(&self) -> Chain {
        Chain::Canton
    }

    fn sender_string(&self) -> String {
        self.sender.clone()
    }
}

// ---------------------------------------------------------------------------
// Configuration & CLI args
// ---------------------------------------------------------------------------

/// Canton JSON Ledger API configuration.
#[derive(Clone)]
pub struct CantonConfig {
    pub json_api_url: String,
    pub json_api_ws_url: String,
    pub jwt_private_key_path: String,
    pub jwt_subject: String,
    pub party_id: String,
    /// The Signer contract ID on the Canton ledger. Must be updated if the contract is re-deployed.
    pub signer_contract_id: String,
    /// The full template ID of the Signer contract (e.g. "<packageHash>:Signer:Signer").
    /// Must be updated if the DAR is upgraded.
    pub signer_template_id: String,
}

impl fmt::Debug for CantonConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CantonConfig")
            .field("json_api_url", &self.json_api_url)
            .field("json_api_ws_url", &self.json_api_ws_url)
            .field("jwt_private_key_path", &"<hidden>")
            .field("jwt_subject", &self.jwt_subject)
            .field("party_id", &self.party_id)
            .field("signer_contract_id", &self.signer_contract_id)
            .field("signer_template_id", &self.signer_template_id)
            .finish()
    }
}

/// CLI arguments for the Canton indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_canton_options")]
pub struct CantonArgs {
    #[arg(
        long,
        env("MPC_CANTON_JSON_API_URL"),
        requires_all = [
            "canton_json_api_ws_url",
            "canton_jwt_private_key_path",
            "canton_jwt_subject",
            "canton_party_id",
            "canton_signer_contract_id",
            "canton_signer_template_id",
        ]
    )]
    pub canton_json_api_url: Option<String>,
    #[arg(long, env("MPC_CANTON_JSON_API_WS_URL"), requires = "canton_json_api_url")]
    pub canton_json_api_ws_url: Option<String>,
    #[arg(long, env("MPC_CANTON_JWT_PRIVATE_KEY_PATH"), requires = "canton_json_api_url")]
    pub canton_jwt_private_key_path: Option<String>,
    #[arg(long, env("MPC_CANTON_JWT_SUBJECT"), requires = "canton_json_api_url")]
    pub canton_jwt_subject: Option<String>,
    #[arg(long, env("MPC_CANTON_PARTY_ID"), requires = "canton_json_api_url")]
    pub canton_party_id: Option<String>,
    /// The Signer contract ID on the Canton ledger. Must be updated if the contract is re-deployed.
    #[arg(long, env("MPC_CANTON_SIGNER_CONTRACT_ID"), requires = "canton_json_api_url")]
    pub canton_signer_contract_id: Option<String>,
    /// The full template ID of the Signer contract (e.g. "<packageHash>:Signer:Signer").
    /// Must be updated if the DAR is upgraded.
    #[arg(long, env("MPC_CANTON_SIGNER_TEMPLATE_ID"), requires = "canton_json_api_url")]
    pub canton_signer_template_id: Option<String>,
}

impl CantonArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(16);
        if let Some(v) = self.canton_json_api_url {
            args.extend(["--canton-json-api-url".to_string(), v]);
        }
        if let Some(v) = self.canton_json_api_ws_url {
            args.extend(["--canton-json-api-ws-url".to_string(), v]);
        }
        if let Some(v) = self.canton_jwt_private_key_path {
            args.extend(["--canton-jwt-private-key-path".to_string(), v]);
        }
        if let Some(v) = self.canton_jwt_subject {
            args.extend(["--canton-jwt-subject".to_string(), v]);
        }
        if let Some(v) = self.canton_party_id {
            args.extend(["--canton-party-id".to_string(), v]);
        }
        if let Some(v) = self.canton_signer_contract_id {
            args.extend(["--canton-signer-contract-id".to_string(), v]);
        }
        if let Some(v) = self.canton_signer_template_id {
            args.extend(["--canton-signer-template-id".to_string(), v]);
        }
        args
    }

    pub fn into_config(self) -> Option<CantonConfig> {
        Some(CantonConfig {
            json_api_url: self.canton_json_api_url?,
            json_api_ws_url: self.canton_json_api_ws_url?,
            jwt_private_key_path: self.canton_jwt_private_key_path?,
            jwt_subject: self.canton_jwt_subject?,
            party_id: self.canton_party_id?,
            signer_contract_id: self.canton_signer_contract_id?,
            signer_template_id: self.canton_signer_template_id?,
        })
    }

    pub fn from_config(config: Option<CantonConfig>) -> Self {
        match config {
            Some(c) => CantonArgs {
                canton_json_api_url: Some(c.json_api_url),
                canton_json_api_ws_url: Some(c.json_api_ws_url),
                canton_jwt_private_key_path: Some(c.jwt_private_key_path),
                canton_jwt_subject: Some(c.jwt_subject),
                canton_party_id: Some(c.party_id),

                canton_signer_contract_id: Some(c.signer_contract_id),
                canton_signer_template_id: Some(c.signer_template_id),
            },
            None => CantonArgs {
                canton_json_api_url: None,
                canton_json_api_ws_url: None,
                canton_jwt_private_key_path: None,
                canton_jwt_subject: None,
                canton_party_id: None,

                canton_signer_contract_id: None,
                canton_signer_template_id: None,
            },
        }
    }
}

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

        let config = state.config;
        let tx = state.tx;
        let backlog = state.backlog;

        self.tasks.push(tokio::spawn(async move {
            run_canton_event_loop(config, tx, backlog).await;
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
    let mut counter = backlog
        .processed_block(Chain::Canton)
        .await
        .unwrap_or(0);

    tracing::info!(
        initial_offset = counter,
        "canton event loop starting"
    );

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
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        "daml.ws.auth".parse()?,
    );
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
                    process_canton_event(event, &value.events, tx, &config.party_id, &config.signer_template_id).await;
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
async fn process_canton_event(
    event: &ledger_api::Event,
    tx_events: &[ledger_api::Event],
    tx: &mpsc::Sender<ChainEvent>,
    node_party_id: &str,
    signer_template_id: &str,
) {
    let created = match event {
        ledger_api::Event::CreatedEvent(created) => created,
        ledger_api::Event::ArchivedEvent(_) | ledger_api::Event::ExercisedEvent(_) => return,
    };

    let template_id = &created.template_id;

    if ledger_api::template_suffix_matches(template_id, ledger_api::templates::SIGN_BIDIRECTIONAL_EVENT) {
        match parse_sign_bidirectional_event(created) {
            Ok(canton_event) => {
                if let Err(e) = verify_sign_event(&canton_event, created, tx_events, node_party_id, signer_template_id) {
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
                            return;
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
    } else if ledger_api::template_suffix_matches(template_id, ledger_api::templates::SIGNATURE_RESPONDED_EVENT) {
        match parse_signature_responded_event(created) {
            Ok(responded) => {
                let event = SignatureRespondedEvent::Canton(responded);
                if tx.send(ChainEvent::Respond(event)).await.is_err() {
                    tracing::error!("canton event channel closed");
                    return;
                }
            }
            Err(e) => {
                tracing::warn!(%e, "failed to parse SignatureRespondedEvent");
            }
        }
    } else if ledger_api::template_suffix_matches(template_id, ledger_api::templates::RESPOND_BIDIRECTIONAL_EVENT) {
        match parse_respond_bidirectional_event(created) {
            Ok(respond) => {
                let event = RespondBidirectionalEvent::Canton(respond);
                if tx.send(ChainEvent::RespondBidirectional(event)).await.is_err() {
                    tracing::error!("canton event channel closed");
                    return;
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
fn verify_sign_event(
    event: &contracts::SignBidirectionalRequestedEvent,
    created: &ledger_api::CreatedEvent,
    tx_events: &[ledger_api::Event],
    node_party_id: &str,
    signer_template_id: &str,
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
    // Signer template must exist in the same transaction. Exact template ID
    // match (not suffix) since the operator pinned it via CLI.
    let has_exercise = tx_events.iter().any(|e| matches!(
        e,
        ledger_api::Event::ExercisedEvent(ex)
            if ex.choice == "SignBidirectional" && ex.template_id == signer_template_id
    ));
    if !has_exercise {
        anyhow::bail!(
            "no ExercisedEvent with choice SignBidirectional on {signer_template_id} found in transaction"
        );
    }

    // Check 4: nonceCidText must correspond to a consuming ExercisedEvent on a
    // SigningNonce template in the same transaction. With LEDGER_EFFECTS, nonce
    // archival appears as a consuming exercise (not an ArchivedEvent).
    // This ensures: (a) the nonce was actually consumed (replay prevention),
    // and (b) it's a SigningNonce — not an arbitrary string.
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

    let request_id: [u8; 32] = payload.request_id.parse::<B256>()
        .map_err(|e| anyhow::anyhow!("invalid request_id hex: {e}"))?.0;
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

    let request_id: [u8; 32] = payload.request_id.parse::<B256>()
        .map_err(|e| anyhow::anyhow!("invalid request_id hex: {e}"))?.0;
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
fn parse_der_signature(hex_str: &str) -> anyhow::Result<Signature> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;

    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped)
        .map_err(|e| anyhow::anyhow!("invalid DER hex: {e}"))?;

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
    let encoded = EncodedPoint::from_bytes(&compressed)
        .map_err(|e| anyhow::anyhow!("r is not valid compressed point bytes: {e}"))?;
    let big_r = Option::from(k256::AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| anyhow::anyhow!("r is not a valid point on secp256k1"))?;

    Ok(Signature {
        big_r,
        s,
        recovery_id: 0,
    })
}
