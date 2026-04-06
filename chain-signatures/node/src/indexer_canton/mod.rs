use crate::backlog::Backlog;
use crate::indexer_sol::MAX_SECP256K1_SCALAR;
use crate::protocol::Chain;
use crate::sign_bidirectional::hash_rlp_data;
use crate::stream::ops::{
    RespondBidirectionalEvent, SignBidirectionalEvent, SignatureEvent, SignatureRespondedEvent,
};
use crate::stream::{ChainEvent, ChainStream};

use alloy::primitives::{keccak256, Address, U256};
use alloy_sol_types::sol;
use canton_types::{contracts, ledger_api};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use k256::elliptic_curve::point::AffineCoordinates;
use k256::Scalar;
use mpc_primitives::{ScalarExt, SignArgs, SignId, Signature, LATEST_MPC_KEY_VERSION};
use std::fmt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header;
use tokio_tungstenite::tungstenite::Message;

// ---------------------------------------------------------------------------
// EIP-712 types via alloy sol! macro
// ---------------------------------------------------------------------------

sol! {
    #[derive(Debug)]
    struct EvmTransactionParams {
        address to;
        string functionSignature;
        bytes[] args;
        uint256 value;
        uint256 nonce;
        uint256 gasLimit;
        uint256 maxFeePerGas;
        uint256 maxPriorityFee;
        uint256 chainId;
    }

    #[derive(Debug)]
    struct CantonMpcSignRequest {
        string sender;
        EvmTransactionParams evmParams;
        string caip2Id;
        uint32 keyVersion;
        string path;
        string algo;
        string dest;
        string params;
        string nonceCidText;
    }
}

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
// JWT token generation (ES256)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct JwtClaims {
    sub: String,
    scope: String,
    iat: u64,
    exp: u64,
}

pub(crate) fn generate_jwt(private_key_pem: &[u8], subject: &str) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = JwtClaims {
        sub: subject.to_string(),
        scope: "daml_ledger_api".to_string(),
        iat: now,
        exp: now + 30,
    };
    let key = EncodingKey::from_ec_pem(private_key_pem)?;
    let header = Header::new(Algorithm::ES256);
    Ok(encode(&header, &claims, &key)?)
}

// ---------------------------------------------------------------------------
// EIP-712 request ID computation
// ---------------------------------------------------------------------------

/// Compute the EIP-712 request ID for a Canton sign request.
///
/// Domain: { name: "CantonMpc", version: "1" } (no chainId, no verifyingContract)
fn compute_request_id(event: &CantonSignBidirectionalRequestedEvent) -> [u8; 32] {
    use alloy_sol_types::eip712_domain;
    use alloy_sol_types::SolStruct;

    let domain = eip712_domain! {
        name: "CantonMpc",
        version: "1",
    };

    let p = &event.evm_tx_params;
    let evm_params = EvmTransactionParams {
        to: format!("0x{}", p.to)
            .parse::<Address>()
            .unwrap_or_default(),
        functionSignature: p.function_signature.clone(),
        args: p
            .args
            .iter()
            .map(|a| hex::decode(a).unwrap_or_default().into())
            .collect(),
        value: U256::from_str_radix(&p.value, 16).unwrap_or_default(),
        nonce: U256::from_str_radix(&p.nonce, 16).unwrap_or_default(),
        gasLimit: U256::from_str_radix(&p.gas_limit, 16).unwrap_or_default(),
        maxFeePerGas: U256::from_str_radix(&p.max_fee_per_gas, 16).unwrap_or_default(),
        maxPriorityFee: U256::from_str_radix(&p.max_priority_fee, 16).unwrap_or_default(),
        chainId: U256::from_str_radix(&p.chain_id, 16).unwrap_or_default(),
    };

    let msg = CantonMpcSignRequest {
        sender: event.sender.clone(),
        evmParams: evm_params,
        caip2Id: event.caip2_id.clone(),
        keyVersion: event.key_version,
        path: event.path.clone(),
        algo: event.algo.clone(),
        dest: event.dest.clone(),
        params: event.params.clone(),
        nonceCidText: event.nonce_cid_text.clone(),
    };

    let signing_hash = msg.eip712_signing_hash(&domain);
    signing_hash.into()
}

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

/// RLP-encode an unsigned EIP-1559 transaction from CantonEvmTransactionParams.
/// Output: 0x02 || RLP([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas,
///                       gasLimit, to, value, data, accessList])
pub fn rlp_encode_unsigned_eip1559(params: &CantonEvmTransactionParams) -> Vec<u8> {
    use rlp::RlpStream;

    let chain_id = u64::from_str_radix(&params.chain_id, 16).unwrap_or(0);
    let nonce = u64::from_str_radix(&params.nonce, 16).unwrap_or(0);
    let max_priority_fee =
        U256::from_str_radix(&params.max_priority_fee, 16).unwrap_or(U256::ZERO);
    let max_fee_per_gas = U256::from_str_radix(&params.max_fee_per_gas, 16).unwrap_or(U256::ZERO);
    let gas_limit = U256::from_str_radix(&params.gas_limit, 16).unwrap_or(U256::ZERO);
    let to_addr = hex::decode(&params.to).unwrap_or_default();
    let value = U256::from_str_radix(&params.value, 16).unwrap_or(U256::ZERO);
    let calldata = build_calldata(&params.function_signature, &params.args);

    let mut stream = RlpStream::new_list(9);
    stream.append(&chain_id);
    stream.append(&nonce);
    append_u256(&mut stream, max_priority_fee);
    append_u256(&mut stream, max_fee_per_gas);
    append_u256(&mut stream, gas_limit);
    stream.append(&to_addr);
    append_u256(&mut stream, value);
    stream.append(&calldata);
    // accessList = empty list
    stream.begin_list(0);

    let rlp_bytes = stream.out();
    let mut result = Vec::with_capacity(1 + rlp_bytes.len());
    result.push(0x02u8); // EIP-1559 type byte
    result.extend_from_slice(&rlp_bytes);
    result
}

/// Append a U256 as minimal big-endian bytes to an RLP stream.
fn append_u256(stream: &mut rlp::RlpStream, val: U256) {
    let be = val.to_be_bytes::<32>();
    // Strip leading zeros for RLP encoding
    let first_nonzero = be.iter().position(|&b| b != 0);
    match first_nonzero {
        Some(pos) => stream.append(&&be[pos..]),
        None => stream.append(&vec![0u8; 0].as_slice()), // zero value -> empty bytes
    };
}

// ---------------------------------------------------------------------------
// DER signature encoding
// ---------------------------------------------------------------------------

/// DER-encode an ECDSA signature from an MPC Signature (big_r, s).
/// ASN.1 DER: 30 <len> 02 <r_len> <r_bytes> 02 <s_len> <s_bytes>
pub fn der_encode_signature(signature: &Signature) -> Vec<u8> {
    let r_bytes = signature.big_r.x().to_vec();
    let s_bytes = signature.s.to_bytes();

    // Encode r — DER integers are signed, so prepend 0x00 if high bit set
    let r_der = der_encode_integer(&r_bytes);
    let s_der = der_encode_integer(&s_bytes);

    let inner_len = r_der.len() + s_der.len();
    let mut result = Vec::with_capacity(2 + inner_len);
    result.push(0x30); // SEQUENCE tag
    result.push(inner_len as u8);
    result.extend_from_slice(&r_der);
    result.extend_from_slice(&s_der);
    result
}

fn der_encode_integer(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros, keeping at least one byte
    let stripped = match bytes.iter().position(|&b| b != 0) {
        Some(pos) => &bytes[pos..],
        None => &[0u8],
    };

    // Prepend 0x00 if high bit is set (DER integers are signed)
    let needs_pad = stripped[0] & 0x80 != 0;
    let len = stripped.len() + if needs_pad { 1 } else { 0 };

    let mut result = Vec::with_capacity(2 + len);
    result.push(0x02); // INTEGER tag
    result.push(len as u8);
    if needs_pad {
        result.push(0x00);
    }
    result.extend_from_slice(stripped);
    result
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
            self.predecessor_id(),
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
}

impl fmt::Debug for CantonConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CantonConfig")
            .field("json_api_url", &self.json_api_url)
            .field("json_api_ws_url", &self.json_api_ws_url)
            .field("jwt_private_key_path", &"<hidden>")
            .field("jwt_subject", &self.jwt_subject)
            .field("party_id", &self.party_id)
            .finish()
    }
}

/// CLI arguments for the Canton indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_canton_options")]
pub struct CantonArgs {
    #[arg(long, env("MPC_CANTON_JSON_API_URL"))]
    pub canton_json_api_url: Option<String>,
    #[arg(long, env("MPC_CANTON_JSON_API_WS_URL"), requires = "canton_json_api_url")]
    pub canton_json_api_ws_url: Option<String>,
    #[arg(long, env("MPC_CANTON_JWT_PRIVATE_KEY_PATH"), requires = "canton_json_api_url")]
    pub canton_jwt_private_key_path: Option<String>,
    #[arg(long, env("MPC_CANTON_JWT_SUBJECT"), requires = "canton_json_api_url")]
    pub canton_jwt_subject: Option<String>,
    #[arg(long, env("MPC_CANTON_PARTY_ID"), requires = "canton_json_api_url")]
    pub canton_party_id: Option<String>,
}

impl CantonArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(10);
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
        args
    }

    pub fn into_config(self) -> Option<CantonConfig> {
        Some(CantonConfig {
            json_api_url: self.canton_json_api_url?,
            json_api_ws_url: self.canton_json_api_ws_url?,
            jwt_private_key_path: self.canton_jwt_private_key_path?,
            jwt_subject: self.canton_jwt_subject?,
            party_id: self.canton_party_id?,
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
            },
            None => CantonArgs {
                canton_json_api_url: None,
                canton_json_api_ws_url: None,
                canton_jwt_private_key_path: None,
                canton_jwt_subject: None,
                canton_party_id: None,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Signer CID discovery
// ---------------------------------------------------------------------------

/// Discover the Signer contract ID by querying active contracts.
/// Returns (contractId, templateId) for the unique Signer:Signer contract.
pub async fn discover_signer_cid(
    http_client: &reqwest::Client,
    json_api_url: &str,
    jwt_token: &str,
    party_id: &str,
) -> anyhow::Result<(String, String)> {
    let url = format!("{json_api_url}/v2/state/active-contracts");

    let mut filters_by_party = serde_json::Map::new();
    filters_by_party.insert(party_id.to_string(), serde_json::json!({}));

    let body = ledger_api::GetActiveContractsRequest {
        active_at_offset: 0,
        event_format: ledger_api::EventFormat {
            filters_by_party,
            verbose: false,
        },
    };

    let resp = http_client
        .post(&url)
        .bearer_auth(jwt_token)
        .json(&body)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("active-contracts query failed: {status} {text}");
    }

    let items: Vec<ledger_api::ActiveContractEntry> = resp.json().await?;

    let mut signer_contracts: Vec<(String, String)> = Vec::new();
    for item in &items {
        if let Some(entry) = &item.contract_entry {
            let ledger_api::ContractEntry::JsActiveContract(active) = entry;
            let ce = &active.created_event;
            if ledger_api::template_suffix_matches(&ce.template_id, "Signer:Signer") {
                signer_contracts.push((ce.contract_id.clone(), ce.template_id.clone()));
            }
        }
    }

    match signer_contracts.len() {
        0 => anyhow::bail!("no active Signer:Signer contract found"),
        1 => Ok(signer_contracts.into_iter().next().unwrap()),
        n => anyhow::bail!("expected 1 Signer:Signer contract, found {n}"),
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
        match subscribe_and_process(&config, &tx, &mut counter).await {
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
    tx: &mpsc::Sender<ChainEvent>,
    counter: &mut u64,
) -> anyhow::Result<()> {
    let jwt_pem = std::fs::read(&config.jwt_private_key_path)?;
    let jwt_token = generate_jwt(&jwt_pem, &config.jwt_subject)?;

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

    let (ws_stream, _) = tokio_tungstenite::connect_async(request).await?;
    let (mut write, mut read) = ws_stream.split();

    tracing::info!("canton WebSocket connected");

    // Send subscription message
    let mut filters_by_party = serde_json::Map::new();
    filters_by_party.insert(config.party_id.clone(), serde_json::json!({}));

    let subscribe_msg = ledger_api::GetUpdatesRequest {
        begin_exclusive: *counter,
        verbose: true,
        filter: ledger_api::UpdatesFilter { filters_by_party },
    };
    write
        .send(Message::Text(serde_json::to_string(&subscribe_msg)?.into()))
        .await?;

    // Process incoming messages
    while let Some(msg) = read.next().await {
        let msg = msg?;
        let text = match msg {
            Message::Text(t) => t,
            Message::Ping(data) => {
                write.send(Message::Pong(data)).await?;
                continue;
            }
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
                    process_canton_event(event, tx, counter).await;
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
async fn process_canton_event(
    event: &ledger_api::Event,
    tx: &mpsc::Sender<ChainEvent>,
    _counter: &u64,
) {
    let created = match event {
        ledger_api::Event::CreatedEvent(created) => created,
        ledger_api::Event::ArchivedEvent(_) | ledger_api::Event::ExercisedEvent(_) => return,
    };

    let template_id = &created.template_id;

    if ledger_api::template_suffix_matches(template_id, "Signer:SignBidirectionalEvent") {
        match parse_sign_bidirectional_event(created) {
            Ok(canton_event) => {
                let entropy: [u8; 32] = rand::random();
                let boxed: crate::stream::ops::SignatureEventBox = Box::new(canton_event);
                match boxed.generate_sign_request(entropy) {
                    Ok(indexed) => {
                        if tx
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
    } else if ledger_api::template_suffix_matches(template_id, "Signer:SignatureRespondedEvent") {
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
    } else if ledger_api::template_suffix_matches(template_id, "Signer:RespondBidirectionalEvent") {
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

    let request_id = hex_to_32_bytes(&payload.request_id)?;
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

    let request_id = hex_to_32_bytes(&payload.request_id)?;
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

fn hex_to_32_bytes(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped)
        .map_err(|e| anyhow::anyhow!("invalid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got different length"))
}

/// Parse a DER-encoded ECDSA signature into an MPC Signature (big_r, s).
///
/// The DER format is: 30 <len> 02 <r_len> <r> 02 <s_len> <s>
/// We extract r and s, then reconstruct big_r as a compressed point.
/// Since DER only gives us the x-coordinate (r), we decompress with
/// even parity (the recovery bit is not in DER).
fn parse_der_signature(hex_str: &str) -> anyhow::Result<Signature> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;

    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped)
        .map_err(|e| anyhow::anyhow!("invalid DER hex: {e}"))?;

    // Parse DER structure manually
    if bytes.len() < 6 || bytes[0] != 0x30 {
        anyhow::bail!("invalid DER signature: bad header");
    }

    let mut pos = 2; // skip SEQUENCE tag + length
    if bytes[pos] != 0x02 {
        anyhow::bail!("invalid DER signature: expected INTEGER tag for r");
    }
    pos += 1;
    let r_len = bytes[pos] as usize;
    pos += 1;
    let r_bytes = &bytes[pos..pos + r_len];
    pos += r_len;

    if bytes[pos] != 0x02 {
        anyhow::bail!("invalid DER signature: expected INTEGER tag for s");
    }
    pos += 1;
    let s_len = bytes[pos] as usize;
    pos += 1;
    let s_bytes = &bytes[pos..pos + s_len];

    // Strip leading zero byte from DER signed integers
    let r_trimmed = if !r_bytes.is_empty() && r_bytes[0] == 0x00 {
        &r_bytes[1..]
    } else {
        r_bytes
    };
    let s_trimmed = if !s_bytes.is_empty() && s_bytes[0] == 0x00 {
        &s_bytes[1..]
    } else {
        s_bytes
    };

    // Pad r to 32 bytes
    let mut r_32 = [0u8; 32];
    let offset = 32_usize.saturating_sub(r_trimmed.len());
    r_32[offset..].copy_from_slice(r_trimmed);

    // Pad s to 32 bytes
    let mut s_32 = [0u8; 32];
    let offset = 32_usize.saturating_sub(s_trimmed.len());
    s_32[offset..].copy_from_slice(s_trimmed);

    // Reconstruct big_r as compressed point (02 || x-coordinate) — even parity
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&r_32);
    let encoded = EncodedPoint::from_bytes(&compressed)
        .map_err(|e| anyhow::anyhow!("invalid r point: {e}"))?;
    let big_r = Option::from(k256::AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| anyhow::anyhow!("r is not a valid point on secp256k1"))?;

    let s = <k256::Scalar as ScalarExt>::from_bytes(s_32)
        .ok_or_else(|| anyhow::anyhow!("s is not a valid scalar"))?;

    // recovery_id is not encoded in DER; use 0 (even parity) as default.
    Ok(Signature {
        big_r,
        s,
        recovery_id: 0,
    })
}
