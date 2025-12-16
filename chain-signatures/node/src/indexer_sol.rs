use crate::backlog::{Backlog, BacklogTransaction, SignTx};
use crate::mesh::{wait_threshold_active, MeshState};
use crate::node_client::NodeClient;
use crate::protocol::{Chain, IndexedSignRequest, Sign, SignRequestType};
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::{
    hash_rlp_data, BidirectionalTx, BidirectionalTxId, PendingRequestStatus,
};

use alloy_sol_types::SolValue;
use anchor_client::anchor_lang::AnchorDeserialize;
use anchor_client::{Client, Cluster, Program};
use anchor_lang::solana_program::keccak;
use anchor_lang::Discriminator;
use ethabi::{encode, Token};
use futures_util::StreamExt;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, Scalar};
use mpc_crypto::kdf::derive_epsilon_sol;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use near_account_id::AccountId;
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
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use std::collections::HashMap;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

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
    /// total timeout for a sign request starting from indexed time in seconds
    pub total_timeout: u64,
}

impl fmt::Debug for SolConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SolConfig")
            .field("account_sk", &"<hidden>")
            .field("rpc_http_url", &self.rpc_http_url)
            .field("rpc_ws_url", &self.rpc_ws_url)
            .field("program_address", &self.program_address)
            .field("total_timeout", &self.total_timeout)
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
    /// total timeout for a sign request starting from indexed time in seconds
    #[clap(long, env("MPC_SOL_TOTAL_TIMEOUT"), default_value = "200")]
    pub sol_total_timeout: Option<u64>,
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
        if let Some(sol_total_timeout) = self.sol_total_timeout {
            args.extend([
                "--sol-total-timeout".to_string(),
                sol_total_timeout.to_string(),
            ]);
        }
        args
    }

    pub fn into_config(self) -> Option<SolConfig> {
        Some(SolConfig {
            account_sk: self.sol_account_sk?,
            rpc_http_url: self.sol_rpc_http_url?,
            rpc_ws_url: self.sol_rpc_ws_url?,
            program_address: self.sol_program_address?,
            total_timeout: self.sol_total_timeout?,
        })
    }

    pub fn from_config(config: Option<SolConfig>) -> Self {
        match config {
            Some(config) => SolArgs {
                sol_account_sk: Some(config.account_sk),
                sol_rpc_http_url: Some(config.rpc_http_url),
                sol_rpc_ws_url: Some(config.rpc_ws_url),
                sol_program_address: Some(config.program_address),
                sol_total_timeout: Some(config.total_timeout),
            },
            None => SolArgs {
                sol_account_sk: None,
                sol_rpc_http_url: None,
                sol_rpc_ws_url: None,
                sol_program_address: None,
                sol_total_timeout: None,
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

trait SignatureEventTrait {
    fn generate_request_id(&self) -> [u8; 32];
    fn generate_sign_request(
        &self,
        tx_sig: Vec<u8>,
        total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest>;
}

trait SignatureEvent: SignatureEventTrait + std::fmt::Debug {}

type SignatureEventBox = Box<dyn SignatureEvent + Send>;

impl SignatureEvent for SignatureRequestedEvent {}

impl SignatureEventTrait for SignatureRequestedEvent {
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

    fn generate_sign_request(
        &self,
        tx_sig: Vec<u8>,
        total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
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
        let epsilon = derive_epsilon_sol(self.key_version, &self.sender.to_string(), &self.path);

        // Use transaction signature as entropy
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&tx_sig[..32]);

        let sign_id = SignId::new(self.generate_request_id());
        tracing::info!(?sign_id, "solana signature requested");

        Ok(IndexedSignRequest {
            id: sign_id,
            args: SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            chain: Chain::Solana,
            timestamp_sign_queue: Instant::now(),
            unix_timestamp_indexed: crate::util::current_unix_timestamp(),
            total_timeout,
            sign_request_type: SignRequestType::Sign,
        })
    }
}

impl SignatureEvent for SignBidirectionalEvent {}

impl SignatureEventTrait for SignBidirectionalEvent {
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

    fn generate_sign_request(
        &self,
        tx_sig: Vec<u8>,
        total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
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
        let epsilon = derive_epsilon_sol(self.key_version, &self.sender.to_string(), &self.path);

        // Use transaction signature as entropy
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&tx_sig[..32]);

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

        Ok(IndexedSignRequest {
            id: sign_id,
            args: SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            chain: Chain::Solana,
            timestamp_sign_queue: Instant::now(),
            unix_timestamp_indexed: crate::util::current_unix_timestamp(),
            total_timeout,
            sign_request_type: SignRequestType::SignBidirectional(self.clone()),
        })
    }
}

type Result<T> = anyhow::Result<T>;

pub async fn run(
    sol: Option<SolConfig>,
    sign_tx: mpsc::Sender<Sign>,
    node_near_account_id: AccountId,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
) {
    let Some(sol) = sol else {
        tracing::warn!("solana indexer is disabled");
        return;
    };

    tracing::info!("running solana indexer");
    let Ok(program_id) = Pubkey::from_str(&sol.program_address) else {
        tracing::error!("Failed to parse program address: {}", sol.program_address);
        return;
    };

    // Wait for threshold to be available
    let threshold = contract_watcher.wait_threshold().await;
    if threshold > 0 {
        wait_threshold_active(&mut mesh_state, threshold).await;
        let mesh_state = mesh_state.borrow().clone();
        backlog
            .recover(&mesh_state, &node_client, threshold, &[Chain::Solana])
            .await;
    }
    let keypair = Keypair::from_base58_string(&sol.account_sk);
    let cluster = Cluster::Custom(sol.rpc_http_url.clone(), sol.rpc_ws_url.clone());
    let client =
        Client::new_with_options(cluster, Arc::new(keypair), CommitmentConfig::confirmed());

    tracing::info!(
        "rpc http url: {}, rpc websocket url: {}, program id: {}",
        sol.rpc_http_url,
        sol.rpc_ws_url,
        program_id
    );

    let total_timeout = Duration::from_secs(sol.total_timeout);

    // Clone sol for respond events subscription
    let sol_for_respond = sol.clone();
    let backlog_for_respond = backlog.clone();
    let contract_watcher_for_respond = contract_watcher.clone();
    let sign_tx_for_respond = sign_tx.clone();

    tokio::spawn(subscribe_and_process_sign_events(
        program_id,
        sol.rpc_http_url.clone(),
        sol.rpc_ws_url.clone(),
        sign_tx.clone(),
        node_near_account_id.clone(),
        total_timeout,
        backlog.clone(),
    ));

    // Subscribe to respond bidirectional events
    tokio::spawn(async move {
        loop {
            if let Err(err) = subscribe_to_program_respond_events(
                program_id,
                &sol_for_respond.rpc_http_url,
                &sol_for_respond.rpc_ws_url,
                backlog_for_respond.clone(),
                contract_watcher_for_respond.clone(),
                sign_tx_for_respond.clone(),
            )
            .await
            {
                tracing::warn!("Failed to subscribe to solana respond events: {:?}", err);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // Subscribe to non-CPI sign events
    loop {
        let Ok(program) = client.program(program_id) else {
            tracing::error!("Failed to get program");
            return;
        };
        let total_timeout = Duration::from_secs(sol.total_timeout);
        let unsub = subscribe_to_program_non_cpi_events(
            &program,
            sign_tx.clone(),
            node_near_account_id.clone(),
            total_timeout,
            backlog.clone(),
        )
        .await;
        if let Err(err) = unsub {
            tracing::warn!("Failed to subscribe to solana non-CPI events: {:?}", err);
        } else {
            unsub.unwrap().unsubscribe().await;
            tracing::info!("unsubscribing to solana non-CPIevents");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn subscribe_to_program_non_cpi_events<C: Deref<Target = Keypair> + Clone>(
    program: &Program<C>,
    sign_tx: mpsc::Sender<Sign>,
    node_near_account_id: AccountId,
    total_timeout: Duration,
    backlog: Backlog,
) -> anyhow::Result<anchor_client::EventUnsubscriber<'_>> {
    tracing::info!("Subscribing to program events");
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let event_unsubscriber = program
        .on(move |ctx, event: SignatureRequestedEvent| {
            let tx_sig: Vec<u8> = ctx.signature.as_ref().to_vec();
            tracing::info!("Received event: {:?}", event);
            if sender.send((event, tx_sig)).is_err() {
                tracing::error!("Error while transferring the event.");
            }
        })
        .await?;

    tracing::info!("Subscribed to program events");
    while let Some((event, tx_sig)) = receiver.recv().await {
        if let Err(err) = process_anchor_sign_event(
            Box::new(event),
            tx_sig,
            sign_tx.clone(),
            node_near_account_id.clone(),
            total_timeout,
            backlog.clone(),
        )
        .await
        {
            tracing::warn!("Failed to process event: {:?}", err);
        }
    }

    Ok(event_unsubscriber)
}

async fn process_anchor_sign_event(
    sign_event: SignatureEventBox,
    tx_sig: Vec<u8>,
    sign_tx: mpsc::Sender<Sign>,
    node_near_account_id: AccountId,
    total_timeout: Duration,
    backlog: Backlog,
) -> anyhow::Result<()> {
    let sign_request = sign_event.generate_sign_request(tx_sig, total_timeout)?;

    // Insert the transaction into the backlog when we first see the sign request
    let sign_id = sign_request.id;
    let sign_request_type = sign_request.sign_request_type.clone();

    // Create the appropriate BacklogTransaction based on the sign request type
    let backlog_tx = match &sign_request_type {
        SignRequestType::Sign => BacklogTransaction::Sign(SignTx {
            request_id: sign_id.request_id,
            source_chain: Chain::Solana,
            key_version: sign_request.args.key_version,
            status: PendingRequestStatus::AwaitingResponse,
        }),
        SignRequestType::SignBidirectional(_event) => {
            // For bidirectional requests, start with a Sign transaction
            // The protocol will advance it to Bidirectional after generating the signature
            BacklogTransaction::Sign(SignTx {
                request_id: sign_id.request_id,
                source_chain: Chain::Solana,
                key_version: sign_request.args.key_version,
                status: PendingRequestStatus::AwaitingResponse,
            })
        }
        _ => anyhow::bail!("Unexpected sign request type"),
    };

    backlog
        .insert(Chain::Solana, sign_id, backlog_tx, sign_request_type)
        .await;

    if let Err(err) = sign_tx.send(Sign::Request(sign_request)).await {
        // TODO: handle error to ensure 100% success rate
        tracing::error!(?err, "Failed to send Solana sign request into queue");
    } else {
        crate::metrics::requests::NUM_SIGN_REQUESTS
            .with_label_values(&[Chain::Solana.as_str(), node_near_account_id.as_str()])
            .inc();
    }

    Ok(())
}

// Reference: https://github.com/solana-foundation/anchor/blob/a5df519319ac39cff21191f2b09d54eda42c5716/client/src/lib.rs#L31
#[allow(clippy::too_many_arguments)]
async fn subscribe_and_process_sign_events(
    program_id: Pubkey,
    rpc_url: String,
    ws_url: String,
    sign_tx: mpsc::Sender<Sign>,
    node_near_account_id: AccountId,
    total_timeout: Duration,
    backlog: Backlog,
) {
    loop {
        let sign_tx_clone = sign_tx.clone();
        let node_near_account_id_clone = node_near_account_id.clone();
        let backlog = backlog.clone();

        let result = subscribe_to_program_cpi_events(
            program_id,
            &rpc_url,
            &ws_url,
            backlog.clone(),
            move |event, signature: solana_sdk::signature::Signature, _slot| {
                tracing::info!("got event: {:?}", event);
                let tx_sig: Vec<u8> = signature.as_ref().to_vec();

                let sign_tx_inner = sign_tx_clone.clone();
                let node_near_account_id_inner = node_near_account_id_clone.clone();
                let backlog = backlog.clone();

                tokio::spawn(async move {
                    if let Err(err) = process_anchor_sign_event(
                        event,
                        tx_sig,
                        sign_tx_inner,
                        node_near_account_id_inner,
                        total_timeout,
                        backlog,
                    )
                    .await
                    {
                        tracing::warn!("Failed to process event: {:?}", err);
                    }
                });
            },
            node_near_account_id.clone(),
        )
        .await;

        if let Err(err) = result {
            tracing::warn!("Failed to subscribe to solana events: {:?}", err);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn parse_cpi_events(
    rpc_client: &RpcClient,
    signature: &Signature,
    target_program_id: &Pubkey,
) -> Result<Vec<SignatureEventBox>> {
    use solana_transaction_status::{UiInstruction, UiParsedInstruction};

    let tx = rpc_client
        .get_transaction_with_config(
            signature,
            solana_client::rpc_config::RpcTransactionConfig {
                encoding: Some(solana_transaction_status::UiTransactionEncoding::JsonParsed),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )
        .await?;

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
            match SignBidirectionalEvent::deserialize(&mut &event_data[..]) {
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
    backlog: Backlog,
    mut event_handler: F,
    node_near_account_id: AccountId,
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

    // Simple TTL cache to avoid multiple getTransaction calls for the same signature
    let mut seen: HashMap<Signature, Instant> = HashMap::new();
    let ttl = Duration::from_secs(30);

    let target_program_str = program_id.to_string();
    let program_invoke_str = format!("Program {} invoke [", target_program_str);
    while let Some(response) = stream.next().await {
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
        let now = Instant::now();
        // Periodic cleanup of expired entries in the TTL cache
        seen.retain(|_, &mut timestamp| now.duration_since(timestamp) < ttl);
        if seen.contains_key(&signature) {
            continue;
        }
        seen.insert(signature, now);

        if let Ok(events) = parse_cpi_events(&rpc_client, &signature, &program_id).await {
            for ev in events {
                event_handler(ev, signature, response.context.slot);
            }
        }

        // Create checkpoint if one was created at this slot
        if let Some(checkpoint) = backlog
            .set_processed_block(Chain::Solana, response.context.slot)
            .await
        {
            tracing::info!(
                slot = response.context.slot,
                ?checkpoint,
                "created Solana checkpoint"
            );
        }

        // Update block height metric
        crate::metrics::indexers::LATEST_BLOCK_NUMBER
            .with_label_values(&[Chain::Solana.as_str(), node_near_account_id.as_str()])
            .set(response.context.slot as i64);
    }

    Ok(())
}

fn looks_like_cpi_sign_event(logs: &[String]) -> bool {
    logs.iter()
        .any(|l| CPI_EVENT_HINTS.iter().any(|h| l.contains(h)))
}

fn has_log_starts_with(logs: &[String], start_with: &str) -> bool {
    logs.iter().any(|l| l.starts_with(start_with))
}

async fn parse_cpi_respond_events(
    rpc_client: &RpcClient,
    signature: &Signature,
    target_program_id: &Pubkey,
) -> Result<(Vec<RespondBidirectionalEvent>, Vec<SignatureRespondedEvent>)> {
    use solana_transaction_status::{UiInstruction, UiParsedInstruction};

    let tx = rpc_client
        .get_transaction_with_config(
            signature,
            solana_client::rpc_config::RpcTransactionConfig {
                encoding: Some(solana_transaction_status::UiTransactionEncoding::JsonParsed),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )
        .await?;

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

async fn subscribe_to_program_respond_events(
    program_id: Pubkey,
    rpc_url: &str,
    ws_url: &str,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    sign_tx: mpsc::Sender<Sign>,
) -> Result<()> {
    let rpc_client = RpcClient::new(rpc_url.to_string());
    let pubsub_client = PubsubClient::new(ws_url).await?;

    let filter = RpcTransactionLogsFilter::Mentions(vec![program_id.to_string()]);
    let config = RpcTransactionLogsConfig {
        commitment: Some(CommitmentConfig::confirmed()),
    };

    let (mut stream, _unsubscriber) = pubsub_client.logs_subscribe(filter, config).await?;

    // Simple TTL cache to avoid multiple getTransaction calls for the same signature
    let mut seen: HashMap<Signature, Instant> = HashMap::new();
    let ttl = Duration::from_secs(30);

    let program_invoke_log = format!("Program {program_id} invoke [");
    while let Some(response) = stream.next().await {
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
        let now = Instant::now();
        // Periodic cleanup of expired entries in the TTL cache
        seen.retain(|_, &mut timestamp| now.duration_since(timestamp) < ttl);
        if seen.contains_key(&signature) {
            continue;
        }
        seen.insert(signature, now);

        let Ok((respond_bidirectional_events, respond_events)) =
            parse_cpi_respond_events(&rpc_client, &signature, &program_id).await
        else {
            continue;
        };
        for ev in respond_bidirectional_events {
            let sign_id = SignId::new(ev.request_id);
            tracing::info!(?sign_id, "processing RespondBidirectionalEvent");
            if backlog.remove(Chain::Solana, &sign_id).await.is_some() {
                tracing::info!(?sign_id, "bidirectional tx completed");
            } else {
                tracing::warn!(?sign_id, "bidirectional tx not found on completion");
            }

            if let Err(err) = sign_tx.send(Sign::Completion(sign_id)).await {
                tracing::error!(
                    ?sign_id,
                    ?err,
                    "failed to send completion for respond bidirectional"
                );
            }
        }

        for ev in respond_events {
            let sign_id = SignId::new(ev.request_id);

            let Some(sign_type) = backlog.sign_type(Chain::Solana, &sign_id).await else {
                tracing::warn!(
                    ?sign_id,
                    "sign type not found for respond event (may have already been processed)"
                );
                continue;
            };
            let event = match sign_type {
                SignRequestType::SignBidirectional(event) => event,
                SignRequestType::Sign => {
                    tracing::info!(?sign_id, "sign request completed successfully");
                    backlog.remove(Chain::Solana, &sign_id).await;
                    if let Err(err) = sign_tx.send(Sign::Completion(sign_id)).await {
                        tracing::error!(
                            ?sign_id,
                            ?err,
                            "failed to send completion for respond event"
                        );
                    }
                    continue;
                }
                SignRequestType::RespondBidirectional(_) => {
                    tracing::warn!(?sign_id, "RespondBidirectional received respond event?");
                    continue;
                }
            };

            tracing::info!(?sign_id, "bidirectional processing initial respond event");
            let Ok(target_chain) = Chain::from_str(&event.dest).inspect_err(|err| {
                tracing::warn!(?sign_id, %err, "unable to parse target chain from dest");
            }) else {
                continue;
            };

            let Some(BacklogTransaction::Sign(_)) = backlog.get(Chain::Solana, &sign_id).await
            else {
                tracing::warn!(?sign_id, "bidirectional tx not found for advancement");
                continue;
            };

            // Create a 65-byte uncompressed point representation (0x04 || x || y)
            let mut big_r = [0u8; 65];
            big_r[0] = 0x04;
            big_r[1..33].copy_from_slice(&ev.signature.big_r.x);
            big_r[33..65].copy_from_slice(&ev.signature.big_r.y);

            let Ok(big_r) = k256::EncodedPoint::from_bytes(big_r).inspect_err(|err| {
                tracing::warn!(?sign_id, %err, "unable to parse big_r for encoded point");
            }) else {
                continue;
            };
            let big_r_ct_opt = AffinePoint::from_encoded_point(&big_r);
            let big_r = if bool::from(big_r_ct_opt.is_some()) {
                big_r_ct_opt.unwrap()
            } else {
                tracing::warn!(?sign_id, "failed to create AffinePoint from encoded point");
                continue;
            };

            let Some(s) = Scalar::from_bytes(ev.signature.s) else {
                tracing::warn!(?sign_id, "failed to create Scalar from s bytes");
                continue;
            };

            let mpc_sig = mpc_primitives::Signature {
                big_r,
                s,
                recovery_id: ev.signature.recovery_id,
            };

            // Sign and hash the transaction to get the correct tx_id and nonce
            let (signed_tx_hash, nonce) = crate::sign_bidirectional::sign_and_hash_transaction(
                &event.serialized_transaction,
                mpc_sig,
            )?;

            let tx_id = BidirectionalTxId(signed_tx_hash.into());

            // Get the MPC public key and derive the from_address
            let root_public_key = contract_watcher.wait_public_key().await;
            let epsilon = mpc_crypto::kdf::derive_epsilon_sol(
                event.key_version,
                &event.sender.to_string(),
                &event.path,
            );
            let from_address =
                crate::sign_bidirectional::derive_user_address(root_public_key, epsilon);

            let bidirectional_tx = BidirectionalTx {
                id: tx_id,
                sender: event.sender,
                serialized_transaction: event.serialized_transaction,
                source_chain: Chain::Solana,
                target_chain,
                caip2_id: event.caip2_id,
                key_version: event.key_version,
                deposit: event.deposit,
                path: event.path.clone(),
                algo: event.algo.clone(),
                dest: event.dest.clone(),
                params: event.params.clone(),
                output_deserialization_schema: event.output_deserialization_schema.clone(),
                respond_serialization_schema: event.respond_serialization_schema.clone(),
                request_id: ev.request_id,
                from_address,
                nonce,
                status: PendingRequestStatus::AwaitingResponse,
            };

            tracing::info!(
                ?sign_id,
                ?tx_id,
                nonce = ?bidirectional_tx.nonce,
                from_address = ?bidirectional_tx.from_address,
                "bidirectional tx details before advancement",
            );

            match backlog
                .advance(Chain::Solana, sign_id, bidirectional_tx)
                .await
            {
                Ok(_) => {
                    tracing::info!(
                        ?sign_id,
                        ?tx_id,
                        ?target_chain,
                        "advance bidirectional tx to execution successful"
                    );
                }
                Err(err) => {
                    tracing::error!(
                        ?sign_id,
                        ?tx_id,
                        ?target_chain,
                        ?err,
                        "advance bidirectional tx to execution failed"
                    );
                }
            }
        }
    }

    Ok(())
}
