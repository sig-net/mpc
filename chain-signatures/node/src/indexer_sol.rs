use crate::protocol::{Chain, IndexedSignRequest};
use anchor_lang::prelude::*;
use anchor_lang::Discriminator;
use base64::engine::general_purpose;
use base64::prelude::Engine as _;
use futures_util::StreamExt;
use k256::Scalar;
use mpc_crypto::kdf::derive_epsilon_sol;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{SignArgs, SignId};
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use solana_client::{
    nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient},
    rpc_config::{RpcTransactionLogsConfig, RpcTransactionLogsFilter},
};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use solana_transaction_status::option_serializer::OptionSerializer;
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use web3::ethabi::{encode, Token};

// Needed for anchor_client/lang to operate well. They use a different version of borsh
// than the one we use in MPC. This older version can have security implications but for
// now only effects Solana.
use borsh_sol as borsh;

pub(crate) static MAX_SECP256K1_SCALAR: LazyLock<Scalar> = LazyLock::new(|| {
    Scalar::from_bytes(
        hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140")
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap()
});

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

#[event]
#[derive(Clone, Debug)]
pub struct SignatureRequestedEvent {
    pub sender: Pubkey,
    pub payload: [u8; 32],
    pub key_version: u32,
    pub deposit: u64,
    pub chain_id: u64,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub fee_payer: Option<Pubkey>,
}

fn sign_request_from_event(
    event: SignatureRequestedEvent,
    tx_sig: Vec<u8>,
    total_timeout: Duration,
) -> anyhow::Result<IndexedSignRequest> {
    tracing::info!("found solana event: {:?}", event);
    if event.deposit == 0 {
        tracing::warn!("deposit is 0, skipping sign request");
        return Err(anyhow::anyhow!("deposit is 0"));
    }

    if event.key_version != 0 {
        tracing::warn!("unsupported key version: {}", event.key_version);
        return Err(anyhow::anyhow!("unsupported key version"));
    }

    let Some(payload) = Scalar::from_bytes(event.payload) else {
        tracing::warn!(
            "solana `sign` did not produce payload hash correctly: {:?}",
            event.payload,
        );
        return Err(anyhow::anyhow!(
            "failed to convert event payload hash to scalar"
        ));
    };

    if payload > *MAX_SECP256K1_SCALAR {
        tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
        anyhow::bail!("payload exceeds secp256k1 curve order");
    }

    // Call the existing derive_epsilon_sol function with the correct parameters
    // to match the TypeScript implementation
    let epsilon = derive_epsilon_sol(&event.sender.to_string(), &event.path);

    // Use transaction signature as entropy
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&tx_sig[..32]);

    let sign_id = SignId::new(calculate_request_id(&event));
    tracing::info!(?sign_id, "solana signature requested");

    Ok(IndexedSignRequest {
        id: sign_id,
        args: SignArgs {
            entropy,
            epsilon,
            payload,
            path: event.path,
            key_version: 0,
        },
        chain: Chain::Solana,
        timestamp_sign_queue: Some(Instant::now()),
        unix_timestamp_indexed: crate::util::current_unix_timestamp(),
        total_timeout,
    })
}

fn calculate_request_id(event: &SignatureRequestedEvent) -> [u8; 32] {
    // Encode the event data in ABI format
    let encoded = encode(&[
        Token::String(event.sender.to_string()),
        Token::Bytes(event.payload.to_vec()),
        Token::String(event.path.clone()),
        Token::Uint(event.key_version.into()),
        Token::Uint(event.chain_id.into()),
        Token::String(event.algo.clone()),
        Token::String(event.dest.clone()),
        Token::String(event.params.clone()),
    ]);
    // Calculate keccak256 hash
    let mut hasher = Keccak256::new();
    hasher.update(&encoded);
    hasher.finalize().into()
}

type Result<T> = anyhow::Result<T>;

// Parse Anchor events from a single transaction signature, covering both:
// - `emit!` events (emitted via logs, base64 payload in `Program data: ...`)
// - `emit_cpi!` events (emitted via an inner CPI instruction, base58-encoded with EVENT_IX_TAG_LE)
// Only events whose discriminator matches `T::DISCRIMINATOR` are returned.
pub async fn parse_anchor_events<T>(
    rpc_client: &RpcClient,
    signature: &Signature,
    target_program_id: &Pubkey,
) -> Result<Vec<T>>
where
    T: anchor_lang::Event
        + anchor_lang::AnchorDeserialize
        + anchor_lang::Discriminator
        + Clone
        + std::fmt::Debug,
{
    let tx = rpc_client
        .get_transaction_with_config(
            signature,
            solana_client::rpc_config::RpcTransactionConfig {
                // Use JsonParsed so that inner instructions surface as PartiallyDecoded
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
    let mut out = Vec::<T>::new();

    // -------- Path 1: emit_cpi! (inner instructions / base58 / has EVENT_IX_TAG prefix) --------
    // Decode a CPI instruction data payload; if it represents our event, deserialize it.
    let process_cpi_ix_data = |data_b58: &str| -> Result<Option<T>> {
        let ix_data = match solana_sdk::bs58::decode(data_b58).into_vec() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        // Layout: 8-byte EVENT_IX_TAG_LE + 8-byte event discriminator + payload
        if !ix_data.starts_with(anchor_lang::event::EVENT_IX_TAG_LE) {
            return Ok(None);
        }
        if ix_data.len() < 16 {
            return Ok(None);
        }
        let event_disc = &ix_data[8..16];
        if event_disc != T::DISCRIMINATOR {
            return Ok(None);
        }
        let mut payload = &ix_data[16..];
        match T::deserialize(&mut payload) {
            Ok(ev) => Ok(Some(ev)),
            Err(e) => {
                tracing::warn!("CPI event deserialize failed: {e}");
                Ok(None)
            }
        }
    };

    if let solana_transaction_status::option_serializer::OptionSerializer::Some(ix_sets) =
        &meta.inner_instructions
    {
        for (set_idx, set) in ix_sets.iter().enumerate() {
            for (ix_idx, ui_ix) in set.instructions.iter().enumerate() {
                use solana_transaction_status::{UiInstruction, UiParsedInstruction};
                if let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ix)) = ui_ix {
                    if ix.program_id == target_program_str {
                        if let Some(ev) = process_cpi_ix_data(&ix.data)? {
                            tracing::debug!("matched emit_cpi! at {set_idx}.{ix_idx}");
                            out.push(ev);
                        }
                    }
                }
            }
        }
    }

    // -------- Path 2: emit! (log_messages / base64 / "Program data: ...") --------
    // Maintain a program call stack via "Program <pid> invoke/success/failed" lines,
    // and only decode data logs when the current executing program matches our target.
    if let OptionSerializer::Some(logs) = &meta.log_messages {
        let mut callstack: Vec<String> = Vec::new();
        for (ln, line) in logs.iter().enumerate() {
            // Maintain call stack
            if let Some(rest) = line.strip_prefix("Program ") {
                if let Some((pid, tail)) = rest.split_once(' ') {
                    if tail.starts_with("invoke [") {
                        callstack.push(pid.to_string());
                        continue;
                    } else if tail.starts_with("success") || tail.starts_with("failed:") {
                        if callstack.last().map(|s| s == pid).unwrap_or(false) {
                            callstack.pop();
                        }
                        continue;
                    }
                }
            }

            // Parse only data logs produced by the target program at the current stack top
            if !line.starts_with("Program data: ") {
                continue;
            }
            if callstack
                .last()
                .map(|s| s != &target_program_str)
                .unwrap_or(true)
            {
                continue;
            }

            // `sol_log_data` may split payload into multiple base64 chunks:
            // "Program data: <b64a>, <b64b>, ..."
            let payload_str = &line["Program data: ".len()..];
            let mut buf = Vec::<u8>::new();
            for seg in payload_str.split(", ") {
                match general_purpose::STANDARD.decode(seg) {
                    Ok(mut part) => buf.append(&mut part),
                    Err(e) => {
                        tracing::warn!("base64 decode failed at log #{ln}: {e}");
                        buf.clear();
                        break;
                    }
                }
            }
            if buf.len() < 8 {
                continue;
            }
            if &buf[..8] != T::DISCRIMINATOR {
                continue;
            }
            let mut data = &buf[8..];
            match T::deserialize(&mut data) {
                Ok(ev) => {
                    tracing::debug!("matched emit! at log #{ln}");
                    out.push(ev)
                }
                Err(e) => tracing::warn!("log event deserialize failed at log #{ln}: {e}"),
            }
        }
    }

    Ok(out)
}

pub async fn run(
    sol: Option<SolConfig>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
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
    tracing::info!(
        "rpc http url: {}, rpc websocket url: {}, program id: {}",
        sol.rpc_http_url,
        sol.rpc_ws_url,
        program_id
    );
    loop {
        let total_timeout = Duration::from_secs(sol.total_timeout);
        let sign_tx_clone = sign_tx.clone();
        let node_near_account_id_clone = node_near_account_id.clone();

        let result = subscribe_to_program_logs::<SignatureRequestedEvent, _>(
            program_id,
            &sol.rpc_http_url,
            &sol.rpc_ws_url,
            move |event, signature, _slot| {
                let tx_sig: Vec<u8> = signature.as_ref().to_vec();

                let sign_tx_inner = sign_tx_clone.clone();
                let node_near_account_id_inner = node_near_account_id_clone.clone();

                tokio::spawn(async move {
                    if let Err(err) = process_anchor_event(
                        event,
                        tx_sig,
                        sign_tx_inner,
                        node_near_account_id_inner,
                        total_timeout,
                    )
                    .await
                    {
                        tracing::warn!("Failed to process event: {:?}", err);
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

// Reference: https://github.com/solana-foundation/anchor/blob/a5df519319ac39cff21191f2b09d54eda42c5716/client/src/lib.rs#L311
async fn subscribe_to_program_logs<T, F>(
    program_id: Pubkey,
    rpc_url: &str,
    ws_url: &str,
    mut event_handler: F,
) -> Result<()>
where
    T: anchor_lang::Event
        + anchor_lang::AnchorDeserialize
        + anchor_lang::Discriminator
        + Clone
        + std::fmt::Debug,
    F: FnMut(T, Signature, u64) + Send,
{
    let rpc_client = RpcClient::new(rpc_url.to_string());
    let pubsub_client = PubsubClient::new(ws_url).await?;

    let filter = RpcTransactionLogsFilter::Mentions(vec![program_id.to_string()]);
    let config = RpcTransactionLogsConfig {
        commitment: Some(CommitmentConfig::confirmed()),
    };

    let (mut stream, _unsubscriber) = pubsub_client.logs_subscribe(filter, config).await?;

    while let Some(response) = stream.next().await {
        // Skip failed transactions immediately
        // Anchor's emit_cpi! performs validation of event authority:
        // 1. Verifies event_authority is a transaction signer
        // 2. Validates event_authority matches the expected PDA derived from program seeds
        // 3. Ensures only the program itself can emit events via emit_cpi!
        // Transaction fails with ConstraintSigner/ConstraintSeeds errors if validation fails.
        // Reference: https://github.com/solana-foundation/anchor/blob/a5df519319ac39cff21191f2b09d54eda42c5716/lang/syn/src/codegen/program/handlers.rs#L208
        if response.value.err.is_some() {
            continue;
        }

        let Ok(signature) = Signature::from_str(&response.value.signature) else {
            tracing::warn!("Invalid signature format received");
            continue;
        };

        match parse_anchor_events::<T>(&rpc_client, &signature, &program_id).await {
            Ok(events) => {
                for event in events {
                    event_handler(event, signature, response.context.slot);
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to parse transaction {}: {}", signature, e);
            }
        }
    }

    Ok(())
}

async fn process_anchor_event(
    event: SignatureRequestedEvent,
    tx_sig: Vec<u8>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
    total_timeout: Duration,
) -> anyhow::Result<()> {
    let sign_request = sign_request_from_event(event, tx_sig, total_timeout)?;

    if let Err(err) = sign_tx.send(sign_request).await {
        tracing::error!(?err, "Failed to send Solana sign request into queue");
    } else {
        crate::metrics::NUM_SIGN_REQUESTS
            .with_label_values(&[Chain::Solana.as_str(), node_near_account_id.as_str()])
            .inc();
    }

    Ok(())
}
