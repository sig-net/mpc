use crate::protocol::{Chain, IndexedSignRequest};
use anchor_client::{
    anchor_lang::{AnchorDeserialize, AnchorSerialize},
    Client, Cluster, Program,
};
use anchor_lang::prelude::event;
use anchor_lang::Discriminator;
use k256::Scalar;
use mpc_crypto::kdf::derive_epsilon_sol;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{SignArgs, SignId};
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
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
#[derive(Debug)]
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
        tracing::error!("Failed to parse program address");
        return;
    };
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
    loop {
        let Ok(program) = client.program(program_id) else {
            tracing::error!("Failed to get program");
            return;
        };
        let total_timeout = Duration::from_secs(sol.total_timeout);
        let unsub = subscribe_to_program_events(
            &program,
            sign_tx.clone(),
            node_near_account_id.clone(),
            total_timeout,
        )
        .await;
        if let Err(err) = unsub {
            tracing::warn!("Failed to subscribe to solana events: {:?}", err);
        } else {
            unsub.unwrap().unsubscribe().await;
            tracing::info!("unsubscribing to solana events");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn subscribe_to_program_events<C: Deref<Target = Keypair> + Clone>(
    program: &Program<C>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
    total_timeout: Duration,
) -> anyhow::Result<anchor_client::EventUnsubscriber> {
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
        if let Err(err) = process_anchor_event(
            event,
            tx_sig,
            sign_tx.clone(),
            node_near_account_id.clone(),
            total_timeout,
        )
        .await
        {
            tracing::warn!("Failed to process event: {:?}", err);
        }
    }

    Ok(event_unsubscriber)
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
