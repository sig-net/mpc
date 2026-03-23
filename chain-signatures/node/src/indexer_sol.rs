use crate::protocol::{Chain, IndexedSignRequest};
use crate::sign_bidirectional::hash_rlp_data;
use crate::stream::ops::{SignatureEvent, SignatureEventBox};
use crate::stream::{ChainEvent, ChainStream};
use crate::util::retry::{retry_async, RetryConfig, RetryError, RetryReason};

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use alloy_sol_types::SolValue;
use anchor_client::anchor_lang::AnchorDeserialize;
use anchor_lang::solana_program::keccak;
use anchor_lang::Discriminator;
use ethabi::{encode, Token};
use futures_util::StreamExt;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, Scalar};
use mpc_crypto::kdf::derive_epsilon_sol;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use signet_program::{
    RespondBidirectionalEvent, SignBidirectionalEvent, SignatureRequestedEvent,
    SignatureRespondedEvent,
};
use solana_client::{
    nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient},
    rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter},
};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use tokio::sync::mpsc;

pub(crate) static MAX_SECP256K1_SCALAR: LazyLock<Scalar> = LazyLock::new(|| {
    Scalar::from_bytes(
        hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
});

const CPI_EVENT_HINTS: &[&str] = &[
    "Program log: Instruction: Sign",
    "Program log: Instruction: SignBidirectional",
];

#[derive(Clone)]
pub struct SolConfig {
    /// The solana account secret key used to sign solana respond txn.
    pub account_sk: String,
    /// Solana RPC http URL
    pub rpc_http_url: String,
    /// Solana RPC websocket URL
    pub rpc_ws_url: String,
    /// The program address to watch
    pub program_address: String,
}

impl fmt::Debug for SolConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolConfig")
            .field("account_sk", &"<hidden>")
            .field("rpc_http_url", &self.rpc_http_url)
            .field("rpc_ws_url", &self.rpc_ws_url)
            .field("program_address", &self.program_address)
            .finish()
    }
}

/// Configures Solana indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_sol_options")]
pub struct SolArgs {
    /// The solana account secret key used to sign solana respond txn.
    #[arg(long, env("MPC_SOL_ACCOUNT_SK"))]
    pub sol_account_sk: Option<String>,
    /// Solana RPC HTTP URL
    #[clap(long, env("MPC_SOL_RPC_HTTP_URL"), requires = "sol_account_sk")]
    pub sol_rpc_http_url: Option<String>,
    /// Solana RPC WS URL
    #[clap(long, env("MPC_SOL_RPC_WS_URL"), requires = "sol_account_sk")]
    pub sol_rpc_ws_url: Option<String>,
    /// The program address to watch
    #[clap(long, env("MPC_SOL_PROGRAM_ADDRESS"), requires = "sol_account_sk")]
    pub sol_program_address: Option<String>,
}

impl SolArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(6);
        if let Some(sol_account_sk) = self.sol_account_sk {
            args.extend(["--sol-account-sk".to_string(), sol_account_sk]);
        }
        if let Some(sol_rpc_http_url) = self.sol_rpc_http_url {
            args.extend(["--sol-rpc-http-url".to_string(), sol_rpc_http_url]);
        }
        if let Some(sol_rpc_ws_url) = self.sol_rpc_ws_url {
            args.extend(["--sol-rpc-ws-url".to_string(), sol_rpc_ws_url]);
        }
        if let Some(sol_program_address) = self.sol_program_address {
            args.extend(["--sol-program-address".to_string(), sol_program_address]);
        }
        args
    }

    pub fn into_config(self) -> Option<SolConfig> {
        Some(SolConfig {
            account_sk: self.sol_account_sk?,
            rpc_http_url: self.sol_rpc_http_url?,
            rpc_ws_url: self.sol_rpc_ws_url?,
            program_address: self.sol_program_address?,
        })
    }

    pub fn from_config(config: Option<SolConfig>) -> Self {
        match config {
            Some(config) => SolArgs {
                sol_account_sk: Some(config.account_sk),
                sol_rpc_http_url: Some(config.rpc_http_url),
                sol_rpc_ws_url: Some(config.rpc_ws_url),
                sol_program_address: Some(config.program_address),
            },
            None => SolArgs {
                sol_account_sk: None,
                sol_rpc_http_url: None,
                sol_rpc_ws_url: None,
                sol_program_address: None,
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SolSignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

impl SignatureEvent for SignatureRequestedEvent {
    fn generate_request_id(&self) -> [u8; 32] {
        // Encode the event data in ABI format
        let encoded = encode(&[
            Token::String(self.sender.to_string()),
            Token::Bytes(self.payload.to_vec()),
            Token::String(self.path.clone()),
            Token::Uint(self.key_version.into()),
            Token::String(self.chain_id.clone()),
            Token::String(self.algo.clone()),
            Token::String(self.dest.clone()),
            Token::String(self.params.clone()),
        ]);
        // Calculate keccak256 hash
        let mut hasher = Keccak256::new();
        hasher.update(&encoded);
        hasher.finalize().into()
    }

    fn generate_sign_request(&self, entropy: [u8; 32]) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("found solana event: {:?}", self);
        if self.deposit == 0 {
            tracing::warn!("deposit is 0, skipping sign request");
            anyhow::bail!("deposit is 0");
        }

        if self.key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!("unsupported key version: {}", self.key_version);
            anyhow::bail!("unsupported key version");
        }

        let Some(payload) = Scalar::from_bytes(self.payload) else {
            tracing::warn!(
                "solana `sign` did not produce payload hash correctly: {:?}",
                self.payload,
            );
            anyhow::bail!("failed to convert event payload hash to scalar");
        };

        if payload > *MAX_SECP256K1_SCALAR {
            tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
            anyhow::bail!("payload exceeds secp256k1 curve order");
        }

        // Call the existing derive_epsilon_sol function with the correct parameters
        // to match the TypeScript implementation
        let epsilon = derive_epsilon_sol(self.key_version, &self.sender_string(), &self.path);

        let sign_id = SignId::new(self.generate_request_id());
        tracing::info!(?sign_id, "solana signature requested");

        Ok(IndexedSignRequest::sign(
            sign_id,
            SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            Chain::Solana,
            crate::util::current_unix_timestamp(),
        ))
    }

    fn source_chain(&self) -> Chain {
        Chain::Solana
    }

    fn sender_string(&self) -> String {
        self.sender.to_string()
    }
}

impl SignatureEvent for SignBidirectionalEvent {
    fn generate_request_id(&self) -> [u8; 32] {
        // Match TypeScript implementation using ABI encoding
        let encoded = (
            self.sender.to_string(),
            self.serialized_transaction.clone(),
            self.caip2_id.clone(),
            self.key_version,
            self.path.clone(),
            self.algo.clone(),
            self.dest.clone(),
            self.params.clone(),
        )
            .abi_encode_packed();

        keccak::hash(&encoded).to_bytes()
    }

    fn generate_sign_request(&self, entropy: [u8; 32]) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("found solana event: {:?}", self);
        if self.deposit == 0 {
            tracing::warn!("deposit is 0, skipping sign request");
            anyhow::bail!("deposit is 0");
        }

        if self.key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!("unsupported key version: {}", self.key_version);
            anyhow::bail!("unsupported key version");
        }

        let request_id = self.generate_request_id();
        let rlp_encoded_tx = self.serialized_transaction.clone();

        // Call the existing derive_epsilon_sol function with the correct parameters
        // to match the TypeScript implementation
        let epsilon = derive_epsilon_sol(self.key_version, &self.sender_string(), &self.path);

        let sign_id = SignId::new(request_id);
        tracing::info!(?sign_id, "solana signature requested");
        let unsigned_tx_hash = hash_rlp_data(rlp_encoded_tx);
        let Some(payload) = Scalar::from_bytes(unsigned_tx_hash) else {
            anyhow::bail!("Failed to convert unsigned_tx_hash to scalar: {unsigned_tx_hash:?}");
        };

        if payload > *MAX_SECP256K1_SCALAR {
            tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
            anyhow::bail!("payload exceeds secp256k1 curve order");
        }

        Ok(IndexedSignRequest::sign_bidirectional(
            sign_id,
            SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            Chain::Solana,
            crate::util::current_unix_timestamp(),
            crate::stream::ops::SignBidirectionalEvent::Solana(self.clone()),
        ))
    }

    fn source_chain(&self) -> Chain {
        Chain::Solana
    }

    fn sender_string(&self) -> String {
        self.sender.to_string()
    }
}

type Result<T> = anyhow::Result<T>;

/// Solana stream that implements the new ChainStream abstraction
pub struct SolanaStream {
    rx: mpsc::Receiver<ChainEvent>,
    start_state: Option<SolanaStreamStartState>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

struct SolanaStreamStartState {
    program_id: Pubkey,
    rpc_http_url: String,
    rpc_ws_url: String,
    tx: mpsc::Sender<ChainEvent>,
}

impl Drop for SolanaStream {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl SolanaStream {
    pub fn new(sol: Option<SolConfig>) -> Option<Self> {
        let Some(sol) = sol else {
            tracing::warn!("solana indexer is disabled");
            return None;
        };

        let Ok(program_id) = Pubkey::from_str(&sol.program_address) else {
            tracing::error!("Failed to parse program address: {}", sol.program_address);
            return None;
        };

        let (tx, rx) = crate::stream::channel();

        Some(SolanaStream {
            rx,
            start_state: Some(SolanaStreamStartState {
                program_id,
                rpc_http_url: sol.rpc_http_url.clone(),
                rpc_ws_url: sol.rpc_ws_url.clone(),
                tx,
            }),
            tasks: Vec::new(),
        })
    }
}

impl ChainStream for SolanaStream {
    const CHAIN: Chain = Chain::Solana;

    async fn start(&mut self) {
        let Some(start_state) = self.start_state.take() else {
            return;
        };

        self.tasks.push(spawn_cpi_sign_events(
            start_state.program_id,
            start_state.rpc_http_url.clone(),
            start_state.rpc_ws_url.clone(),
            start_state.tx.clone(),
        ));
        self.tasks.push(spawn_respond_events(
            start_state.program_id,
            start_state.rpc_http_url,
            start_state.rpc_ws_url,
            start_state.tx,
        ));
    }

    async fn next_event(&mut self) -> Option<ChainEvent> {
        self.rx.recv().await
    }
}

// Version of respond subscription that pushes ChainEvent into a channel instead of calling processing directly
async fn subscribe_to_program_respond_events(
    program_id: Pubkey,
    rpc_url: &str,
    ws_url: &str,
    events_tx: mpsc::Sender<ChainEvent>,
) -> Result<()> {
    let rpc_client = RpcClient::new(rpc_url.to_string());
    let pubsub_client = PubsubClient::new(ws_url).await?;

    let filter = RpcTransactionLogsFilter::Mentions(vec![program_id.to_string()]);
    let config = RpcTransactionLogsConfig {
        commitment: Some(CommitmentConfig::confirmed()),
    };

    let (mut stream, _unsubscriber) = pubsub_client.logs_subscribe(filter, config).await?;

    // TTL cache: avoid repeated getTransaction on same sig
    let mut seen: std::collections::HashMap<Signature, Instant> = std::collections::HashMap::new();
    let ttl = Duration::from_secs(30);

    // Watchdog
    let stall_timeout = Duration::from_secs(60);
    let mut last_ws_msg = Instant::now();
    let mut watchdog = tokio::time::interval(Duration::from_secs(5));

    let program_invoke_log = format!("Program {program_id} invoke [");

    loop {
        cleanup_seen_cache(&mut seen, ttl);

        tokio::select! {
            maybe = stream.next() => {
                match maybe {
                    Some(response) => {
                        last_ws_msg = Instant::now();

                        if response.value.err.is_some() {
                            continue;
                        }

                        let logs = &response.value.logs;
                        if !has_log_starts_with(logs, &program_invoke_log) {
                            continue;
                        }

                        let Ok(signature) = Signature::from_str(&response.value.signature) else {
                            tracing::warn!("Invalid signature format");
                            continue;
                        };

                        if seen.contains_key(&signature) {
                            continue;
                        }

                        let tx_res = match get_tx(&rpc_client, &signature, RetryConfig::default()).await {
                            Ok(tx) => tx,
                            Err(e) => {
                                tracing::warn!("Failed to fetch transaction {}: {}", signature, e);
                                continue;
                            }
                        };

                        let now = Instant::now();
                        seen.insert(signature, now);

                        let (respond_bidirectional_events, respond_events) = match parse_cpi_respond_events(tx_res, &program_id) {
                            Ok(v) => v,
                            Err(err) => {
                                tracing::warn!(?err, sig = %signature, "failed to parse respond events (will skip this signature)");
                                continue;
                            }
                        };

                        for ev in respond_bidirectional_events {
                            let _ = events_tx.send(ChainEvent::RespondBidirectional(crate::stream::ops::RespondBidirectionalEvent::Solana(ev))).await;
                        }

                        for ev in respond_events {
                            let _ = events_tx.send(ChainEvent::Respond(crate::stream::ops::SignatureRespondedEvent::Solana(ev))).await;
                        }
                    }
                    None => {
                        anyhow::bail!("solana respond logs stream ended (None), reconnecting");
                    }
                }
            }

            _ = watchdog.tick() => {
                if last_ws_msg.elapsed() > stall_timeout {
                    anyhow::bail!("solana respond logs subscription stalled: no ws message for {:?}", stall_timeout);
                }
            }
        }
    }
}

fn spawn_cpi_sign_events(
    program_id: Pubkey,
    rpc_url: String,
    ws_url: String,
    events_tx: mpsc::Sender<ChainEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(subscribe_and_process_sign_events(
        program_id,
        rpc_url.clone(),
        ws_url.clone(),
        events_tx.clone(),
    ))
}

fn spawn_respond_events(
    program_id: Pubkey,
    rpc_url: String,
    ws_url: String,
    events_tx: mpsc::Sender<ChainEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Err(err) = subscribe_to_program_respond_events(
                program_id,
                &rpc_url,
                &ws_url,
                events_tx.clone(),
            )
            .await
            {
                tracing::warn!("Failed to subscribe to solana respond events: {:?}", err);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

fn build_sign_request(
    sign_event: SignatureEventBox,
    tx_sig: Vec<u8>,
) -> anyhow::Result<IndexedSignRequest> {
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&tx_sig[..32]);
    sign_event.generate_sign_request(entropy)
}

// Reference: https://github.com/solana-foundation/anchor/blob/a5df519319ac39cff21191f2b09d54eda42c5716/client/src/lib.rs#L31
async fn subscribe_and_process_sign_events(
    program_id: Pubkey,
    rpc_url: String,
    ws_url: String,
    events_tx: mpsc::Sender<ChainEvent>,
) {
    loop {
        let events_tx_clone = events_tx.clone();
        let result = subscribe_to_program_cpi_events(
            program_id,
            &rpc_url,
            &ws_url,
            events_tx.clone(),
            move |event, signature: solana_sdk::signature::Signature, _slot| {
                tracing::info!("got event: {:?}", event);
                let tx_sig: Vec<u8> = signature.as_ref().to_vec();
                let events_tx = events_tx_clone.clone();
                tokio::spawn(async move {
                    match build_sign_request(event, tx_sig) {
                        Ok(req) => {
                            let _ = events_tx.send(ChainEvent::SignRequest(req)).await;
                        }
                        Err(err) => tracing::warn!("Failed to process event: {:?}", err),
                    }
                });
            },
        )
        .await;

        if let Err(err) = result {
            tracing::warn!("Failed to subscribe to solana events: {:?}", err);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn parse_cpi_events(
    tx: solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta,
    target_program_id: &Pubkey,
) -> Result<Vec<SignatureEventBox>> {
    use solana_transaction_status::{UiInstruction, UiParsedInstruction};

    let Some(meta) = tx.transaction.meta else {
        return Ok(Vec::new());
    };

    let target_program_str = target_program_id.to_string();
    let mut out = Vec::<SignatureEventBox>::new();

    // Small helper closure to try decoding both event types from raw data
    let try_parse_events = |data: &str| -> Result<Vec<SignatureEventBox>> {
        let Ok(ix_data) = solana_sdk::bs58::decode(data).into_vec() else {
            tracing::warn!("Failed to decode instruction data for target program");
            return Ok(Vec::new());
        };

        // Ensure this is an Anchor emit_cpi! instruction
        if !ix_data.starts_with(anchor_lang::event::EVENT_IX_TAG_LE) {
            return Ok(Vec::new());
        }

        let event_discriminator = &ix_data[8..16];
        let event_data = &ix_data[16..];

        let mut acc = Vec::new();

        // handle both event types
        if event_discriminator == SignatureRequestedEvent::DISCRIMINATOR {
            match SignatureRequestedEvent::deserialize(&mut &event_data[..]) {
                Ok(ev) => acc.push(Box::new(ev) as SignatureEventBox),
                Err(e) => tracing::warn!("Failed to deserialize SignatureRequestedEvent: {e}"),
            }
        } else if event_discriminator == SignBidirectionalEvent::DISCRIMINATOR {
            match <SignBidirectionalEvent as AnchorDeserialize>::deserialize(&mut &event_data[..]) {
                Ok(ev) => acc.push(Box::new(ev) as SignatureEventBox),
                Err(e) => {
                    tracing::warn!("Failed to deserialize SignBidirectionalEvent: {e}")
                }
            }
        }

        Ok(acc)
    };

    // Look into inner instructions for CPI calls
    let inner_ixs = match meta.inner_instructions {
        solana_transaction_status::option_serializer::OptionSerializer::Some(ixs) => ixs,
        _ => return Ok(Vec::new()),
    };

    for (set_idx, inner_ix_set) in inner_ixs.iter().enumerate() {
        for (ix_idx, instruction) in inner_ix_set.instructions.iter().enumerate() {
            if let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ui)) = instruction {
                if ui.program_id == target_program_str {
                    match try_parse_events(&ui.data) {
                        Ok(mut v) => {
                            if !v.is_empty() {
                                tracing::info!(
                                    "parsed {} event(s) from {}.{}",
                                    v.len(),
                                    set_idx,
                                    ix_idx
                                );
                            }
                            out.append(&mut v);
                        }
                        Err(e) => tracing::warn!(
                            "Error processing inner instruction {}.{}: {}",
                            set_idx,
                            ix_idx,
                            e
                        ),
                    }
                }
            }
        }
    }

    Ok(out)
}

// Reference: https://github.com/solana-foundation/anchor/blob/a5df519319ac39cff21191f2b09d54eda42c5716/client/src/lib.rs#L311
async fn subscribe_to_program_cpi_events<F>(
    program_id: Pubkey,
    rpc_url: &str,
    ws_url: &str,
    events_tx: mpsc::Sender<ChainEvent>,
    mut event_handler: F,
) -> Result<()>
where
    F: FnMut(SignatureEventBox, Signature, u64) + Send,
{
    let rpc_client = RpcClient::new(rpc_url.to_string());
    let pubsub_client = PubsubClient::new(ws_url).await?;

    let filter = RpcTransactionLogsFilter::Mentions(vec![program_id.to_string()]);
    let config = RpcTransactionLogsConfig {
        commitment: Some(CommitmentConfig::confirmed()),
    };

    let (mut stream, _unsubscriber) = pubsub_client.logs_subscribe(filter, config).await?;

    // stall watchdog
    let stall_timeout = Duration::from_secs(60);
    let mut last_ws_msg = Instant::now();
    let mut watchdog = tokio::time::interval(Duration::from_secs(5));

    // Simple TTL cache to avoid multiple getTransaction calls for the same signature
    let mut seen: HashMap<Signature, Instant> = HashMap::new();
    let ttl = Duration::from_secs(30);

    let target_program_str = program_id.to_string();
    let program_invoke_str = format!("Program {} invoke [", target_program_str);

    loop {
        cleanup_seen_cache(&mut seen, ttl);
        tokio::select! {
            // Receive WS logs
            maybe = stream.next() => {
                match maybe {
                    Some(response) => {
                        last_ws_msg = Instant::now();

                        if response.value.err.is_some() {
                            continue;
                        }

                        let logs = &response.value.logs;
                        if !looks_like_cpi_sign_event(logs) || !has_log_starts_with(logs, &program_invoke_str) {
                            continue;
                        }

                        let Ok(signature) = Signature::from_str(&response.value.signature) else {
                            tracing::warn!("Invalid signature format");
                            continue;
                        };

                        if seen.contains_key(&signature) {
                            continue;
                        }

                        let tx_req = match get_tx(&rpc_client, &signature, RetryConfig::default()).await {
                            Ok(tx) => tx,
                            Err(e) => {
                                tracing::warn!("Failed to fetch transaction {}: {}", signature, e);
                                continue;
                            }
                        };

                        let now = Instant::now();
                        seen.insert(signature, now);

                        match parse_cpi_events(tx_req, &program_id) {
                            Ok(events) => {
                                for ev in events {
                                    event_handler(ev, signature, response.context.slot);
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to parse cpi events for {}: {}", signature, e);
                                continue;
                            }
                        }

                        // Emit block event for every observed slot
                        if let Err(err) = events_tx.send(ChainEvent::Block(response.context.slot)).await {
                            tracing::warn!(?err, "failed to send block event");
                        }
                    }
                    None => {
                        // stream ended => force reconnect
                        anyhow::bail!("solana logs stream ended (None), reconnecting");
                    }
                }
            }

            // Watchdog tick
            _ = watchdog.tick() => {
                if last_ws_msg.elapsed() > stall_timeout {
                    anyhow::bail!(
                        "solana logs subscription stalled: no ws message for {:?}",
                        stall_timeout
                    );
                }
            }
        }
    }
}

fn looks_like_cpi_sign_event(logs: &[String]) -> bool {
    logs.iter()
        .any(|l| CPI_EVENT_HINTS.iter().any(|h| l.contains(h)))
}

fn has_log_starts_with(logs: &[String], start_with: &str) -> bool {
    logs.iter().any(|l| l.starts_with(start_with))
}

fn parse_cpi_respond_events(
    tx: solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta,
    target_program_id: &Pubkey,
) -> Result<(Vec<RespondBidirectionalEvent>, Vec<SignatureRespondedEvent>)> {
    use solana_transaction_status::{UiInstruction, UiParsedInstruction};

    let Some(meta) = tx.transaction.meta else {
        return Ok((Vec::new(), Vec::new()));
    };

    let target_program_str = target_program_id.to_string();
    let mut respond_bidirectional_events = Vec::<RespondBidirectionalEvent>::new();
    let mut signature_responded_events = Vec::<SignatureRespondedEvent>::new();

    // Helper closure to try decoding RespondBidirectionalEvent and SignatureRespondedEvent from raw data
    let try_parse_respond_event =
        |data: &str| -> Result<(Vec<RespondBidirectionalEvent>, Vec<SignatureRespondedEvent>)> {
            let Ok(ix_data) = solana_sdk::bs58::decode(data).into_vec() else {
                tracing::warn!("Failed to decode instruction data for target program");
                return Ok((Vec::new(), Vec::new()));
            };

            // Ensure this is an Anchor event instruction
            if !ix_data.starts_with(anchor_lang::event::EVENT_IX_TAG_LE) {
                return Ok((Vec::new(), Vec::new()));
            }

            let event_discriminator = &ix_data[8..16];
            let event_data = &ix_data[16..];

            let mut respond_bdx = Vec::new();
            let mut sig_resp = Vec::new();

            // Handle RespondBidirectionalEvent
            if event_discriminator == RespondBidirectionalEvent::DISCRIMINATOR {
                match RespondBidirectionalEvent::deserialize(&mut &event_data[..]) {
                    Ok(ev) => respond_bdx.push(ev),
                    Err(e) => {
                        tracing::warn!("Failed to deserialize RespondBidirectionalEvent: {e}")
                    }
                }
            }

            // Handle SignatureRespondedEvent
            if event_discriminator == SignatureRespondedEvent::DISCRIMINATOR {
                match SignatureRespondedEvent::deserialize(&mut &event_data[..]) {
                    Ok(ev) => sig_resp.push(ev),
                    Err(e) => {
                        tracing::warn!("Failed to deserialize SignatureRespondedEvent: {e}")
                    }
                }
            }

            Ok((respond_bdx, sig_resp))
        };

    // Look into inner instructions for CPI calls
    let inner_ixs = match meta.inner_instructions {
        solana_transaction_status::option_serializer::OptionSerializer::Some(ixs) => ixs,
        _ => return Ok((Vec::new(), Vec::new())),
    };

    for (set_idx, inner_ix_set) in inner_ixs.iter().enumerate() {
        for (ix_idx, instruction) in inner_ix_set.instructions.iter().enumerate() {
            if let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ui)) = instruction {
                if ui.program_id == target_program_str {
                    match try_parse_respond_event(&ui.data) {
                        Ok((mut r_bdx, mut s_resp)) => {
                            if !r_bdx.is_empty() {
                                tracing::info!(
                                    "parsed {} RespondBidirectionalEvent(s) from {}.{}",
                                    r_bdx.len(),
                                    set_idx,
                                    ix_idx
                                );
                            }
                            if !s_resp.is_empty() {
                                tracing::info!(
                                    "parsed {} SignatureRespondedEvent(s) from {}.{}",
                                    s_resp.len(),
                                    set_idx,
                                    ix_idx
                                );
                            }
                            respond_bidirectional_events.append(&mut r_bdx);
                            signature_responded_events.append(&mut s_resp);
                        }
                        Err(e) => tracing::warn!(
                            "Error processing inner instruction {}.{}: {}",
                            set_idx,
                            ix_idx,
                            e
                        ),
                    }
                }
            }
        }
    }

    Ok((respond_bidirectional_events, signature_responded_events))
}

// Clean up seen cache based on TTL
fn cleanup_seen_cache(seen: &mut HashMap<Signature, Instant>, ttl: Duration) {
    let now = Instant::now();
    seen.retain(|_, &mut t| now.duration_since(t) < ttl);
}

pub fn to_mpc_signature(
    sig: signet_program::Signature,
) -> anyhow::Result<mpc_primitives::Signature> {
    // Create a 65-byte uncompressed point representation (0x04 || x || y)
    let mut big_r = [0u8; 65];
    big_r[0] = 0x04;
    big_r[1..33].copy_from_slice(&sig.big_r.x);
    big_r[33..65].copy_from_slice(&sig.big_r.y);

    let big_r = k256::EncodedPoint::from_bytes(big_r)
        .map_err(|err| anyhow::anyhow!("unable to parse big_r for encoded point: {err}"))?;
    let big_r_ct_opt = AffinePoint::from_encoded_point(&big_r);
    let big_r = big_r_ct_opt
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("failed to create AffinePoint from encoded point"))?;

    let s = Scalar::from_bytes(sig.s)
        .ok_or_else(|| anyhow::anyhow!("failed to create Scalar from s bytes"))?;

    Ok(mpc_primitives::Signature {
        big_r,
        s,
        recovery_id: sig.recovery_id,
    })
}

/// Fetch transaction with timeout + retry.
/// Returns the same type as `RpcClient::get_transaction_with_config`.
async fn get_tx(
    rpc_client: &RpcClient,
    signature: &Signature,
    retry_cfg: RetryConfig,
) -> anyhow::Result<solana_transaction_status::EncodedConfirmedTransactionWithStatusMeta> {
    let max_attempts = retry_cfg.max_attempts;

    let res = retry_async(
        retry_cfg,
        |attempt| async move {
            rpc_client
                .get_transaction_with_config(
                    signature,
                    solana_client::rpc_config::RpcTransactionConfig {
                        encoding: Some(solana_transaction_status::UiTransactionEncoding::JsonParsed),
                        commitment: Some(CommitmentConfig::confirmed()),
                        max_supported_transaction_version: Some(0),
                    },
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!(e).context(format!(
                        "getTransaction failed (attempt {attempt}/{}) for {}",
                        max_attempts, signature
                    ))
                })
        },
        |_attempt, _reason| true,
        |attempt, reason, sleep| match reason {
            RetryReason::Error(e) => {
                tracing::warn!(
                    "getTransaction failed (attempt {attempt}/{}) for {}: {e:#}; retrying in {sleep:?}",
                    max_attempts,
                    signature
                );
            }
            RetryReason::Timeout(t) => {
                tracing::warn!(
                    "getTransaction timed out after {t:?} (attempt {attempt}/{}) for {}; retrying in {sleep:?}",
                    max_attempts,
                    signature
                );
            }
        },
    )
    .await;

    match res {
        Ok(tx) => Ok(tx),
        Err(RetryError::Exhausted { last_error, .. }) => Err(last_error),
        Err(RetryError::TimeoutExhausted {
            attempts,
            last_timeout,
        }) => Err(anyhow::anyhow!(
            "getTransaction timed out after {:?} (attempt {attempts}/{}) for {}",
            last_timeout,
            max_attempts,
            signature
        )),
    }
}
