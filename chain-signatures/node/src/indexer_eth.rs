use crate::indexer::ContractSignRequest;
use crate::protocol::Chain::Ethereum;
use crate::protocol::SignRequest;
use crypto_shared::kdf::derive_epsilon_eth;
use crypto_shared::ScalarExt;
use hex::ToHex;
use k256::Scalar;
use near_account_id::AccountId;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use web3::futures::StreamExt;
use web3::types::{FilterBuilder, Log, H160, H256, U256};

/// Configures Ethereum indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_eth_options")]
pub struct Options {
    /// Ethereum WebSocket RPC URL
    #[clap(long, env("MPC_INDEXER_ETH_RPC_WS_URL"))]
    pub eth_rpc_ws_url: String,

    /// Ethereum HTTP RPC URL
    #[clap(long, env("MPC_INDEXER_ETH_RPC_HTTP_URL"))]
    pub eth_rpc_http_url: String,

    /// The contract address to watch without the `0x` prefix
    #[clap(long, env("MPC_INDEXER_ETH_CONTRACT_ADDRESS"))]
    pub eth_contract_address: String,
}

impl Options {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::new();
        args.extend([
            "--eth-rpc-ws-url".to_string(),
            self.eth_rpc_ws_url,
            "--eth-rpc-http-url".to_string(),
            self.eth_rpc_http_url,
            "--eth-contract-address".to_string(),
            self.eth_contract_address,
        ]);
        args
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
    let request = ContractSignRequest {
        payload,
        path: event.path,
        key_version: 0,
        chain: Ethereum,
    };
    let epsilon = derive_epsilon_eth(
        format!("0x{}", event.requester.encode_hex::<String>()),
        &request.path,
    );
    let mut event_epsilon_bytes: [u8; 32] = [0; 32];
    event.epsilon.to_big_endian(&mut event_epsilon_bytes);
    let event_epsilon_scalar = Scalar::from_bytes(event_epsilon_bytes)
        .ok_or(anyhow::anyhow!("failed to convert event epsilon to scalar"))?;
    if epsilon != event_epsilon_scalar {
        tracing::warn!(
            "epsilon mismatch: derived={:?}, event={:?}",
            epsilon,
            event.epsilon
        );
        return Err(anyhow::anyhow!("epsilon mismatch"));
    }
    tracing::debug!(
        "from epsilon: {:?} event epsilon: {:?}",
        epsilon,
        event.epsilon
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

    // Parse epsilon (32 bytes)
    let epsilon = U256::from_big_endian(&data[32..64]);

    // Parse payload hash (32 bytes)
    let mut payload_hash = [0u8; 32];
    payload_hash.copy_from_slice(&data[64..96]);

    // Parse path string
    let path_offset = U256::from_big_endian(&data[96..128]).as_usize();
    let path_length = U256::from_big_endian(&data[path_offset..path_offset + 32]).as_usize();
    let path_bytes = &data[path_offset + 32..path_offset + 32 + path_length];
    let path = String::from_utf8(path_bytes.to_vec())?;

    Ok(SignatureRequestedEvent {
        request_id,
        requester,
        epsilon,
        payload_hash,
        path,
    })
}

pub async fn run(
    options: &Options,
    sign_tx: mpsc::Sender<SignRequest>,
    node_near_account_id: &AccountId,
) -> anyhow::Result<()> {
    let contract_address = H160::from_str(&options.eth_contract_address)?;

    let signature_requested_topic = H256::from_slice(&web3::signing::keccak256(
        b"SignatureRequested(bytes32,address,uint256,uint256,string)",
    ));

    let filter = FilterBuilder::default()
        .address(vec![contract_address])
        .topics(Some(vec![signature_requested_topic]), None, None, None)
        .build();

    loop {
        match web3::transports::WebSocket::new(&options.eth_rpc_ws_url).await {
            Ok(ws) => {
                let web3_ws = web3::Web3::new(ws);
                match web3_ws.eth_subscribe().subscribe_logs(filter.clone()).await {
                    Ok(mut filtered_logs_sub) => {
                        tracing::info!("Ethereum indexer connected and listening for logs");

                        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));

                        loop {
                            tokio::select! {
                                Some(log) = filtered_logs_sub.next() => {
                                    match log {
                                        Ok(log) => {
                                            tracing::info!("Received new Ethereum sign request: {:?}", log);
                                            crate::metrics::NUM_SIGN_REQUESTS_ETH
                                                .with_label_values(&[node_near_account_id.as_str()])
                                                .inc();
                                            let sign_tx = sign_tx.clone();
                                            if let Ok(sign_request) = sign_request_from_filtered_log(log) {
                                                tokio::spawn(async move {
                                                    if let Err(err) = sign_tx.send(sign_request).await {
                                                        tracing::error!(?err, "Failed to send ETH sign request into queue");
                                                    }
                                                });
                                            }
                                        }
                                        Err(err) => {
                                            tracing::warn!("Ethereum log subscription error: {:?}", err);
                                            break;
                                        }
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
    epsilon: U256,
    payload_hash: [u8; 32],
    path: String,
}
