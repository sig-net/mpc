use crate::indexer::ContractSignRequest;
use crate::protocol::Chain::Ethereum;
use crate::protocol::SignRequest;
use hex::ToHex;
use k256::Scalar;
use mpc_crypto::kdf::derive_epsilon_eth;
use mpc_crypto::ScalarExt;
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use web3::futures::StreamExt;
use web3::types::{FilterBuilder, Log, H160, H256, U256};

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

fn sign_request_from_filtered_log(log: web3::types::Log) -> anyhow::Result<SignRequest> {
    let event = parse_event(&log)?;
    tracing::debug!("found eth event: {:?}", event);
    if event.deposit < 1 {
        tracing::warn!("insufficient deposit: {}", event.deposit);
        return Err(anyhow::anyhow!("insufficient deposit"));
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

    // if payload > Scalar::from_bytes(hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141").unwrap().try_into().unwrap()).unwrap() {
    //     tracing::warn!("Payload exceeds secp256k1 curve order: {:?}", payload);
    //     return Err(anyhow::anyhow!("Payload exceeds secp256k1 curve order"));
    // }

    let request = ContractSignRequest {
        payload,
        path: event.path,
        key_version: event.key_version,
        chain: Ethereum,
    };

    let epsilon = derive_epsilon_eth(
        format!("0x{}", event.requester.encode_hex::<String>()),
        &request.path,
    );

    // Use transaction hash as entropy
    let entropy = log
        .transaction_hash
        .map(|h| *h.as_fixed_bytes())
        .unwrap_or([0u8; 32]);

    Ok(SignRequest {
        request_id: event.request_id,
        request,
        epsilon,
        entropy,
        // TODO: use indexer timestamp instead.
        time_added: Instant::now(),
    })
}

// Helper function to parse event logs
fn parse_event(log: &Log) -> anyhow::Result<SignatureRequestedEvent> {
    // Ensure we have enough topics
    if log.topics.len() < 2 {
        anyhow::bail!("Invalid number of topics");
    }

    // Parse request_id from topics[1]
    let mut request_id = [0u8; 32];
    request_id.copy_from_slice(log.topics[1].as_bytes());

    // Parse data fields
    let data = log.data.0.as_slice();

    // Parse requester address (20 bytes)
    let requester = H160::from_slice(&data[12..32]);

    // Parse payload hash (32 bytes)
    let mut payload_hash = [0u8; 32];
    payload_hash.copy_from_slice(&data[32..64]);

    let key_version = U256::from_big_endian(&data[64..96]).as_u32();

    let deposit = U256::from_big_endian(&data[96..128]).as_usize();

    // Parse path string
    let path_offset = U256::from_big_endian(&data[128..160]).as_usize();
    let path_length = U256::from_big_endian(&data[path_offset..path_offset + 32]).as_usize();
    let path_bytes = &data[path_offset + 32..path_offset + 32 + path_length];
    let path = String::from_utf8(path_bytes.to_vec())?;

    // // Parse algo string
    // let algo_offset = U256::from_big_endian(&data[160..192]).as_usize();
    // let algo_length = U256::from_big_endian(&data[algo_offset..algo_offset + 32]).as_usize();
    // let algo_bytes = &data[algo_offset + 32..algo_offset + 32 + algo_length];
    // let algo = String::from_utf8(algo_bytes.to_vec())?;

    // // Parse dest string
    // let dest_offset = U256::from_big_endian(&data[192..224]).as_usize();
    // let dest_length = U256::from_big_endian(&data[dest_offset..dest_offset + 32]).as_usize();
    // let dest_bytes = &data[dest_offset + 32..dest_offset + 32 + dest_length];
    // let dest = String::from_utf8(dest_bytes.to_vec())?;

    // // Parse params string
    // let params_offset = U256::from_big_endian(&data[224..256]).as_usize();
    // let dest_length = U256::from_big_endian(&data[dest_offset..dest_offset + 32]).as_usize();
    // let dest_bytes = &data[dest_offset + 32..dest_offset + 32 + dest_length];
    // let dest = String::from_utf8(dest_bytes.to_vec())?;

    tracing::info!(
        "Parsed event: request_id={}, requester={}, payload_hash={}, path={}, deposit={}",
        hex::encode(request_id),
        requester,
        hex::encode(payload_hash),
        path,
        deposit,
    );

    Ok(SignatureRequestedEvent {
        request_id,
        requester,
        payload_hash,
        path,
        key_version,
        deposit,
    })
}

pub async fn run(
    eth: Option<EthConfig>,
    sign_tx: mpsc::Sender<SignRequest>,
    node_near_account_id: AccountId,
) -> anyhow::Result<()> {
    let Some(eth) = eth else {
        tracing::warn!("ethereum indexer is disabled");
        return Ok(());
    };

    tracing::info!("running ethereum indexer");
    let contract_address = H160::from_str(&eth.contract_address)?;
    let signature_requested_topic = H256::from_slice(&web3::signing::keccak256(
        b"SignatureRequested(bytes32,address,bytes32,uint32,uint256,string,string,string,string)",
    ));

    let filter = FilterBuilder::default()
        .address(vec![contract_address])
        .topics(Some(vec![signature_requested_topic]), None, None, None)
        .build();

    loop {
        match web3::transports::WebSocket::new(&eth.rpc_ws_url).await {
            Ok(ws) => {
                let web3_ws = web3::Web3::new(ws);
                match web3_ws.eth_subscribe().subscribe_logs(filter.clone()).await {
                    Ok(mut filtered_logs_sub) => {
                        tracing::info!("Ethereum indexer connected and listening for logs");

                        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(60));

                        loop {
                            tokio::select! {
                                Some(log) = filtered_logs_sub.next() => {
                                    let Ok(log) = log.inspect_err(|err| {
                                        tracing::warn!("Ethereum log subscription error: {:?}", err);
                                    }) else {
                                        break;
                                    };
                                    tracing::info!("Received new Ethereum sign request: {:?}", log);
                                    crate::metrics::NUM_SIGN_REQUESTS_ETH
                                        .with_label_values(&[node_near_account_id.as_str()])
                                        .inc();
                                    if let Ok(sign_request) = sign_request_from_filtered_log(log) {
                                        let sign_tx = sign_tx.clone();
                                        tokio::spawn(async move {
                                            if let Err(err) = sign_tx.send(sign_request).await {
                                                tracing::error!(?err, "Failed to send ETH sign request into queue");
                                            }
                                        });
                                    }
                                }
                                _ = heartbeat_interval.tick() => {
                                    tracing::info!("Ethereum indexer is still running...");
                                }
                            }
                        }
                    }
                    Err(err) => tracing::warn!("Failed to subscribe to logs: {:?}", err),
                }
            }
            Err(err) => tracing::error!("Failed to connect to Ethereum WebSocket: {:?}", err),
        }

        tracing::warn!("Ethereum WebSocket disconnected, reconnecting in 2 seconds...");
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[derive(Debug)]
struct SignatureRequestedEvent {
    request_id: [u8; 32],
    requester: H160,
    payload_hash: [u8; 32],
    path: String,
    key_version: u32,
    deposit: usize,
}
