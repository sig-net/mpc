use crate::protocol::{Chain, IndexedSignRequest};
use hex::ToHex;
use k256::Scalar;
use mpc_crypto::kdf::derive_epsilon_eth;
use mpc_crypto::ScalarExt as _;
use mpc_primitives::{SignArgs, SignId};
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use web3::ethabi::{encode, Token};
use web3::futures::StreamExt;
use web3::transports::WebSocket;
use web3::types::{BlockNumber, FilterBuilder, Log, H160, H256, U256};
use web3::Web3;

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
pub struct EthConfig {
    /// The ethereum account secret key used to sign eth respond txn.
    pub account_sk: String,
    /// Ethereum WebSocket RPC URL
    pub rpc_ws_url: String,
    /// Ethereum HTTP RPC URL
    pub rpc_http_url: String,
    /// The contract address to watch without the `0x` prefix
    pub contract_address: String,
}

impl fmt::Debug for EthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthConfig")
            .field("account_sk", &"<hidden>")
            .field("rpc_ws_url", &self.rpc_ws_url)
            .field("rpc_http_url", &self.rpc_http_url)
            .field("contract_address", &self.contract_address)
            .finish()
    }
}

/// Configures Ethereum indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_eth_options")]
pub struct EthArgs {
    /// The ethereum account secret key used to sign eth respond txn.
    #[arg(long, env("MPC_ETH_ACCOUNT_SK"))]
    pub eth_account_sk: Option<String>,
    /// Ethereum WebSocket RPC URL
    #[clap(long, env("MPC_ETH_RPC_WS_URL"), requires = "eth_account_sk")]
    pub eth_rpc_ws_url: Option<String>,
    /// Ethereum HTTP RPC URL
    #[clap(long, env("MPC_ETH_RPC_HTTP_URL"), requires = "eth_account_sk")]
    pub eth_rpc_http_url: Option<String>,
    /// The contract address to watch without the `0x` prefix
    #[clap(long, env("MPC_ETH_CONTRACT_ADDRESS"), requires = "eth_account_sk")]
    pub eth_contract_address: Option<String>,
}

impl EthArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(10);
        if let Some(eth_account_sk) = self.eth_account_sk {
            args.extend(["--eth-account-sk".to_string(), eth_account_sk]);
        }
        if let Some(eth_rpc_ws_url) = self.eth_rpc_ws_url {
            args.extend(["--eth-rpc-ws-url".to_string(), eth_rpc_ws_url]);
        }
        if let Some(eth_rpc_http_url) = self.eth_rpc_http_url {
            args.extend(["--eth-rpc-http-url".to_string(), eth_rpc_http_url]);
        }
        if let Some(eth_contract_address) = self.eth_contract_address {
            args.extend(["--eth-contract-address".to_string(), eth_contract_address]);
        }
        args
    }

    pub fn into_config(self) -> Option<EthConfig> {
        Some(EthConfig {
            account_sk: self.eth_account_sk?,
            rpc_ws_url: self.eth_rpc_ws_url?,
            rpc_http_url: self.eth_rpc_http_url?,
            contract_address: self.eth_contract_address?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EthSignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

fn sign_request_from_filtered_log(log: web3::types::Log) -> anyhow::Result<IndexedSignRequest> {
    let event = parse_event(&log)?;
    tracing::debug!("found eth event: {:?}", event);
    if event.deposit == U256::from_dec_str("0").unwrap() {
        tracing::warn!("deposit is 0, skipping sign request");
        return Err(anyhow::anyhow!("deposit is 0"));
    }

    if event.key_version != 0 {
        tracing::warn!("unsupported key version: {}", event.key_version);
        return Err(anyhow::anyhow!("unsupported key version"));
    }

    // Create sign request from event
    let Some(payload) = Scalar::from_bytes(event.payload_hash) else {
        tracing::warn!(
            "eth `sign` did not produce payload hash correctly: {:?}",
            event.payload_hash,
        );
        return Err(anyhow::anyhow!(
            "failed to convert event payload hash to scalar"
        ));
    };

    if payload > *MAX_SECP256K1_SCALAR {
        tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
        anyhow::bail!("payload exceeds secp256k1 curve order");
    }

    let epsilon = derive_epsilon_eth(
        format!("0x{}", event.requester.encode_hex::<String>()),
        &event.path,
    );

    // Use transaction hash as entropy
    let entropy = log
        .transaction_hash
        .map(|h| *h.as_fixed_bytes())
        .unwrap_or([0u8; 32]);

    let sign_id = SignId::new(calculate_request_id(&event));
    tracing::info!(?sign_id, "eth signature requested");

    Ok(IndexedSignRequest {
        id: sign_id,
        args: SignArgs {
            entropy,
            epsilon,
            payload,
            path: event.path,
            key_version: 0,
        },
        chain: Chain::Ethereum,
        // TODO: use indexer timestamp instead.
        timestamp: Instant::now(),
    })
}

fn encode_abi(event: &SignatureRequestedEvent) -> Vec<u8> {
    encode(&[
        Token::Address(event.requester),         // Solidity `address`
        Token::Bytes(event.payload_hash.into()), // Solidity `bytes`
        Token::String(event.path.clone()),       // Solidity `string`
        Token::Uint(event.key_version.into()),   // Solidity `uint32`
        Token::Uint(event.chain_id),             // Solidity `uint256`
        Token::String(event.algo.clone()),       // Solidity `string`
        Token::String(event.dest.clone()),       // Solidity `string`
        Token::String(event.params.clone()),     // Solidity `string`
    ])
}

fn calculate_request_id(event: &SignatureRequestedEvent) -> [u8; 32] {
    let abi_encoded = encode_abi(event);
    let mut hasher = Keccak256::new();
    hasher.update(abi_encoded);
    let output: [u8; 32] = hasher.finalize().into();
    output
}

// Helper function to parse event logs
fn parse_event(log: &Log) -> anyhow::Result<SignatureRequestedEvent> {
    // Parse data fields
    let data = log.data.0.as_slice();

    // Parse requester address (20 bytes)
    let requester = H160::from_slice(&data[12..32]);

    // Parse payload hash (32 bytes)
    let mut payload_hash = [0u8; 32];
    payload_hash.copy_from_slice(&data[32..64]);

    let key_version = U256::from_big_endian(&data[64..96]).as_u32();

    let deposit = U256::from_big_endian(&data[96..128]);

    let chain_id = U256::from_big_endian(&data[128..160]);

    let path = parse_string_args(data, 160);

    let algo = parse_string_args(data, 192);

    let dest = parse_string_args(data, 224);

    let params = parse_string_args(data, 256);

    tracing::info!(
        "Parsed event: requester={}, payload_hash={}, path={}, deposit={}, chain_id={}, algo={}, dest={}, params={}",
        requester,
        hex::encode(payload_hash),
        path,
        deposit,
        chain_id,
        algo,
        dest,
        params
    );

    Ok(SignatureRequestedEvent {
        requester,
        payload_hash,
        path,
        key_version,
        deposit,
        chain_id,
        algo,
        dest,
        params,
    })
}

fn parse_string_args(data: &[u8], offset_start: usize) -> String {
    let offset = U256::from_big_endian(&data[offset_start..offset_start + 32]).as_usize();
    let length = U256::from_big_endian(&data[offset..offset + 32]).as_usize();
    if length == 0 {
        return String::new();
    }
    let bytes = &data[offset + 32..offset + 32 + length];
    String::from_utf8(bytes.to_vec()).unwrap_or_default()
}

pub async fn run(
    eth: Option<EthConfig>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
) -> anyhow::Result<()> {
    let Some(eth) = eth else {
        tracing::warn!("ethereum indexer is disabled");
        return Ok(());
    };

    tracing::info!("running ethereum indexer");
    let contract_address = H160::from_str(&eth.contract_address)?;
    let signature_requested_topic = H256::from_slice(&web3::signing::keccak256(
        b"SignatureRequested(address,bytes32,uint32,uint256,uint256,string,string,string,string)",
    ));

    let filter_builer = FilterBuilder::default()
        .address(vec![contract_address])
        .topics(Some(vec![signature_requested_topic]), None, None, None);

    let filter = filter_builer.clone().build();
    let mut latest_block_number: u64 = 0;

    loop {
        match web3::transports::WebSocket::new(&eth.rpc_ws_url).await {
            Ok(ws) => {
                let web3_ws = web3::Web3::new(ws);
                tracing::info!("Connected to Ethereum WebSocket");

                loop {
                    match web3_ws.eth().block_number().await {
                        Ok(block_number) => {
                            let end_block = block_number.as_u64();
                            if latest_block_number == 0 {
                                latest_block_number = block_number.as_u64();
                                tracing::info!("Latest eth block number: {latest_block_number}");
                                crate::metrics::LATEST_BLOCK_NUMBER_ETH
                                    .with_label_values(&[node_near_account_id.as_str()])
                                    .set(latest_block_number as i64);
                            } else if latest_block_number < end_block {
                                if let Err(err) = catchup(
                                    latest_block_number,
                                    end_block,
                                    web3_ws.clone(),
                                    sign_tx.clone(),
                                    filter_builer.clone(),
                                    node_near_account_id.clone(),
                                )
                                .await
                                {
                                    tracing::warn!("Failed to catch up: {:?}", err);
                                } else {
                                    latest_block_number = end_block;
                                    tracing::info!(
                                        "Latest eth block number: {latest_block_number}"
                                    );
                                    crate::metrics::LATEST_BLOCK_NUMBER_ETH
                                        .with_label_values(&[node_near_account_id.as_str()])
                                        .set(latest_block_number as i64);
                                }
                            } else {
                                tracing::info!(
                                    "Latest eth block number: {end_block}, is not greater than last time: {latest_block_number}"
                                );
                                break;
                            }
                        }
                        Err(err) => {
                            tracing::warn!(
                                "Eth indexer failed to get latest block number: {:?}",
                                err
                            );
                            break;
                        }
                    }
                    let subscribe_end_result = match web3_ws
                        .eth_subscribe()
                        .subscribe_logs(filter.clone())
                        .await
                    {
                        Ok(mut filtered_logs_sub) => {
                            tracing::info!("Ethereum indexer subscribed and listening for logs");

                            let mut heartbeat_interval =
                                tokio::time::interval(Duration::from_secs(60));
                            heartbeat_interval.tick().await;
                            let mut latest_sign_request_time = Instant::now();

                            loop {
                                tokio::select! {
                                    Some(log) = filtered_logs_sub.next() => {
                                        let Ok(log) = log.inspect_err(|err| {
                                            tracing::warn!("Ethereum log subscription error: {:?}", err);
                                        }) else {
                                            break;
                                        };
                                        if let Err(err) = process_filtered_log(log.clone(), sign_tx.clone(), node_near_account_id.clone()) {
                                            tracing::warn!("Failed to process eth sign request: {:?}", err);
                                            break;
                                        } else {
                                            latest_sign_request_time = Instant::now();
                                            latest_block_number = log.block_number.unwrap().as_u64();
                                            tracing::info!("Latest eth sign request block number: {latest_block_number}");
                                            crate::metrics::LATEST_BLOCK_NUMBER_ETH
                                                .with_label_values(&[node_near_account_id.as_str()])
                                                .set(latest_block_number as i64);
                                        }
                                    }
                                    _ = heartbeat_interval.tick() => {
                                        if latest_sign_request_time.elapsed() > heartbeat_interval.period() {
                                            tracing::warn!("No sign request received in the last 60 seconds, unsubscribing...");
                                            break;
                                        }
                                    }
                                }
                            }
                            Ok(filtered_logs_sub)
                        }
                        Err(err) => {
                            tracing::warn!(
                                "Failed to subscribe to logs: {:?}, will reconnect to websocket",
                                err
                            );
                            Err(err)
                        }
                    };
                    if let Ok(filtered_logs_sub) = subscribe_end_result {
                        if let Err(err) = filtered_logs_sub.unsubscribe().await {
                            tracing::warn!("Failed to unsubscribe from logs: {:?}, will reconnect to websocket", err);
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
            Err(err) => tracing::error!("Failed to connect to Ethereum WebSocket: {:?}", err),
        }
        tracing::warn!("Ethereum WebSocket disconnected, reconnecting in 2 seconds...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn process_filtered_log(
    log: web3::types::Log,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    node_near_account_id: AccountId,
) -> anyhow::Result<()> {
    tracing::info!("Received new Ethereum sign request: {:?}", log);
    crate::metrics::NUM_SIGN_REQUESTS_ETH
        .with_label_values(&[node_near_account_id.as_str()])
        .inc();
    let sign_request = sign_request_from_filtered_log(log)?;
    let sign_tx = sign_tx.clone();
    tokio::spawn(async move {
        if let Err(err) = sign_tx.send(sign_request).await {
            tracing::error!(?err, "Failed to send ETH sign request into queue");
        }
    });
    Ok(())
}

async fn catchup(
    start_block: u64,
    end_block: u64,
    ws: Web3<WebSocket>,
    sign_tx: mpsc::Sender<IndexedSignRequest>,
    filter_builder: FilterBuilder,
    node_near_account_id: AccountId,
) -> anyhow::Result<()> {
    tracing::info!("Catching up from block {start_block} to block {end_block}");
    let filter = filter_builder
        .from_block(BlockNumber::Number(start_block.into()))
        .to_block(BlockNumber::Number(end_block.into()))
        .build();

    let logs = ws.eth().logs(filter).await?;
    for log in logs {
        process_filtered_log(log, sign_tx.clone(), node_near_account_id.clone())?;
    }
    Ok(())
}

#[derive(Debug)]
struct SignatureRequestedEvent {
    requester: H160,
    payload_hash: [u8; 32],
    path: String,
    key_version: u32,
    deposit: U256,
    chain_id: U256,
    algo: String,
    dest: String,
    params: String,
}
