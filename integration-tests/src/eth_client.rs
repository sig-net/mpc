use anyhow::{anyhow, Result};
use rlp::RlpStream;
use reqwest::Client as HttpClient;
use serde_json::json;
use sha3::{Digest, Keccak256};
use secp256k1::{Secp256k1, Message, SecretKey};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use std::time::Duration;

use alloy::primitives::Address;

pub struct EthClient {
    endpoint: String,
    http: HttpClient,
    signing_key_bytes: Vec<u8>,
    pub address: Address,
    pub chain_id: u64,
}

impl EthClient {
    pub fn new(endpoint: &str, private_key_hex: &str, chain_id: u64) -> Result<Self> {
        let http = HttpClient::new();
        let pk = private_key_hex.trim_start_matches("0x");
        let pk_bytes = hex::decode(pk).map_err(|e| anyhow!("invalid private key hex: {e:?}"))?;
        // store private key bytes
        let signing_key_bytes = pk_bytes.clone();

        // compute address using secp256k1 public key
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&signing_key_bytes).map_err(|e| anyhow!("invalid secret key: {e:?}"))?;
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pub_bytes = pk.serialize_uncompressed();
        let mut hasher = Keccak256::new();
        hasher.update(&pub_bytes[1..]);
        let hash = hasher.finalize();
        let address_bytes = &hash[12..];
        let mut addr = [0u8; 20];
        addr.copy_from_slice(address_bytes);
        let address = Address::from(addr);

        Ok(Self {
            endpoint: endpoint.to_string(),
            http,
            signing_key_bytes,
            address,
            chain_id,
        })
    }

    pub async fn get_nonce(&self) -> Result<u64> {
        let params = json!([format!("0x{}", hex::encode(self.address)), "pending"]);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionCount","params":params});
        let resp = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        if let Some(err) = resp.get("error") {
            return Err(anyhow!("rpc error: {}", err));
        }
        let result = resp.get("result").ok_or_else(|| anyhow!("no result in rpc: {}", resp))?;
        let s = result.as_str().ok_or_else(|| anyhow!("invalid result type"))?;
        let nonce = u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0);
        Ok(nonce)
    }

    /// Sign and send a legacy transaction (simple use for tests)
    pub async fn send_raw_tx(&self, to: Option<Address>, value: u64, data: Vec<u8>) -> Result<String> {
        let nonce = self.get_nonce().await?;
        let gas_price = 1_000_000_000u64; // 1 gwei
        let gas_limit = 3_000_000u64;

        // RLP encode: [nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0]
        let mut stream = RlpStream::new();
        stream.begin_list(9);
        stream.append(&nonce);
        stream.append(&gas_price);
        stream.append(&gas_limit);
        if let Some(addr) = to {
            let addr_hex = format!("{}", addr);
            let addr_bytes = hex::decode(addr_hex.trim_start_matches("0x"))?;
            stream.append(&addr_bytes);
        } else {
            stream.append_empty_data();
        }
        stream.append(&value);
        stream.append(&data);
        stream.append(&self.chain_id);
        stream.append(&0u8);
        stream.append(&0u8);
        let preimage = stream.out().to_vec();

        // hash
        let mut hasher = Keccak256::new();
        hasher.update(&preimage);
        let digest = hasher.finalize();

        // sign digest using secp256k1 recoverable signature
        let secp = Secp256k1::new();
        let msg = Message::from_slice(&digest).map_err(|e| anyhow!("invalid digest: {e:?}"))?;
        let sk = SecretKey::from_slice(&self.signing_key_bytes).map_err(|e| anyhow!("invalid secret key: {e:?}"))?;
        let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&msg, &sk);
        let (rid, out) = sig.serialize_compact();
        let recid = rid.to_i32() as u8;
        let sigbytes = out;

        let r = &sigbytes[0..32];
        let s = &sigbytes[32..64];

        // compute v
        let v = recid as u64 + 35 + self.chain_id * 2;

        // RLP encode signed tx: [nonce, gas_price, gas_limit, to, value, data, v, r, s]
        let mut s2 = RlpStream::new();
        s2.begin_list(9);
        s2.append(&nonce);
        s2.append(&gas_price);
        s2.append(&gas_limit);
        if let Some(addr) = to {
            let addr_hex = format!("{}", addr);
            let addr_bytes = hex::decode(addr_hex.trim_start_matches("0x"))?;
            s2.append(&addr_bytes);
        } else {
            s2.append_empty_data();
        }
        s2.append(&value);
        s2.append(&data);
        s2.append(&v);
        s2.append(&r);
        s2.append(&s);
        let tx_bytes = s2.out().to_vec();

        let tx_hex = format!("0x{}", hex::encode(tx_bytes));
        let params = json!([tx_hex]);
        let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":params});
        let resp = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        if let Some(err) = resp.get("error") {
            return Err(anyhow!("rpc error: {}", err));
        }
        let result = resp.get("result").ok_or_else(|| anyhow!("no result in rpc: {}", resp))?;
        let tx_hash = result.as_str().ok_or_else(|| anyhow!("invalid tx hash type"))?;
        Ok(tx_hash.to_string())
    }

    pub async fn wait_for_receipt(&self, tx_hash: &str, timeout: Duration) -> Result<serde_json::Value> {
        let start = std::time::Instant::now();
        loop {
            let params = json!([tx_hash]);
            let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":params});
            let resp = self
                .http
                .post(&self.endpoint)
                .json(&body)
                .send()
                .await?
                .json::<serde_json::Value>()
                .await?;
            if let Some(result) = resp.get("result") {
                if !result.is_null() {
                    return Ok(result.clone());
                }
            }
            if start.elapsed() > timeout {
                return Err(anyhow!("timeout waiting for receipt"));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn get_logs(&self, from_block: u64, to_block: u64, address: Option<Address>, topics: Vec<Option<String>>) -> Result<Vec<serde_json::Value>> {
        let mut filter = serde_json::Map::new();
        filter.insert("fromBlock".to_string(), serde_json::Value::String(format!("0x{:x}", from_block)));
        filter.insert("toBlock".to_string(), serde_json::Value::String(format!("0x{:x}", to_block)));
        if let Some(addr) = address {
            filter.insert("address".to_string(), serde_json::Value::String(format!("0x{}", hex::encode(format!("{}", addr).trim_start_matches("0x")))));
        }
        if !topics.is_empty() {
            let t: Vec<serde_json::Value> = topics.into_iter().map(|opt| match opt {
                Some(s) => serde_json::Value::String(s),
                None => serde_json::Value::Null,
            }).collect();
            filter.insert("topics".to_string(), serde_json::Value::Array(t));
        }
        let body = json!({"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[filter]});
        let resp = self
            .http
            .post(&self.endpoint)
            .json(&body)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        if let Some(err) = resp.get("error") {
            return Err(anyhow!("rpc error: {}", err));
        }
        let result = resp.get("result").ok_or_else(|| anyhow!("no result in rpc: {}", resp))?;
        let arr = result.as_array().ok_or_else(|| anyhow!("invalid logs result"))?.clone();
        Ok(arr)
    }
}
