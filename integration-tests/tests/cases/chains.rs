use alloy::primitives::{keccak256, Address as AlloyAddress, U256};
use anyhow::Context as _;
use anyhow::Result;
use cait_sith::FullSignature;
use integration_tests::{actions, cluster};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use k256::Secp256k1;
use mpc_crypto::kdf::check_ec_signature;
use mpc_crypto::{derive_epsilon_sol, derive_key, near_public_key_to_affine_point};
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use reqwest::Client;
use rlp::RlpStream;
use secp256k1::PublicKey as SecpPublicKey;
use secp256k1::{Secp256k1 as LibSecp256k1, SecretKey as SecpSecretKey};
use serde_json::json;
use sha3::{Digest, Keccak256};
use solana_sdk::signer::Signer as _;
use std::time::Duration;
use test_log::test;
use tokio::time::sleep;

const FUNDING_TOP_UP_WEI: u128 = 200_000_000_000_000; // 0.0002 ETH
const FUNDING_GAS_LIMIT: u64 = 21_000;
const FUNDING_POLL_INTERVAL_SECS: u64 = 6;
const FUNDING_MAX_ATTEMPTS: usize = 20;

const TX_RECEIPT_POLL_INTERVAL_SECS: u64 = 6;
const TX_RECEIPT_MAX_ATTEMPTS: usize = 40;

#[test(tokio::test)]
async fn test_solana_eth_bidirectional_flow() -> anyhow::Result<()> {
    let key_version = LATEST_MPC_KEY_VERSION;
    let nodes = cluster::spawn().solana().ethereum().await?;

    nodes.wait().signable().await?;

    let ctx = nodes.nodes.ctx();
    let eth_ctx = ctx
        .ethereum
        .as_ref()
        .context("ethereum sandbox not initialized")?;
    let execution_rpc_http_url = eth_ctx.sandbox.external_http_endpoint.clone();
    let account_sk = eth_ctx.sandbox.secret_key.clone();
    let chain_id = eth_ctx.sandbox.chain_id;
    let parameters = serde_json::to_string(&json!({ "network": "sandbox" }))?;

    let solana = nodes
        .solana
        .as_ref()
        .context("solana instance not available")?;

    let signer_account = solana.payer_keypair.pubkey().to_string();

    let path = "solana::ethereum::bridge";

    let root_pk_near = nodes.root_public_key().await?;
    let root_pk = near_public_key_to_affine_point(root_pk_near);
    let epsilon = derive_epsilon_sol(key_version, &signer_account, path);
    let user_pk = derive_key(root_pk, epsilon);
    let user_pk_bytes = user_pk.to_encoded_point(false);
    let user_secp_pk = SecpPublicKey::from_slice(user_pk_bytes.as_bytes())
        .context("failed to convert user public key")?;
    let user_address = actions::public_key_to_address(&user_secp_pk);
    let user_alloy_address = AlloyAddress::from_slice(user_address.as_bytes());

    let legacy_tx = EthereumTransaction {
        nonce: U256::from(0u8),
        gas_price: U256::from(1_500_000_000u64),
        gas_limit: U256::from(FUNDING_GAS_LIMIT),
        to: user_alloy_address,
        value: U256::from(0u8),
        data: Vec::new(),
    };

    let client = Client::new();
    ensure_eth_signer_funded(
        &client,
        &execution_rpc_http_url,
        &account_sk,
        user_alloy_address,
        legacy_tx.gas_price * legacy_tx.gas_limit,
        legacy_tx.gas_price,
        chain_id,
    )
    .await?;

    let unsigned_rlp = encode_unsigned_legacy_tx(&legacy_tx, chain_id);
    let msg_hash = keccak256(&unsigned_rlp);
    let msg_hash_bytes: [u8; 32] = msg_hash.into();

    let sol_outcome = nodes
        .sign()
        .solana()
        .bidirectional()
        .transaction_data(unsigned_rlp.clone())
        .caip2_id("eip155:60")
        .output_deserialization_schema(Vec::new())
        .respond_serialization_schema(Vec::new())
        .payload(msg_hash_bytes)
        .payload_hash(msg_hash_bytes)
        .path(path)
        .key_version(key_version)
        .algorithm("ECDSA")
        .destination("ethereum")
        .parameters(&parameters)
        .await?;

    assert_eq!(
        sol_outcome.payload_hash, msg_hash_bytes,
        "payload hash mismatch"
    );
    assert_eq!(sol_outcome.signer_account, signer_account);

    let payload_scalar = <k256::Scalar as Reduce<
        <Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes((&msg_hash_bytes).into());
    let signature_valid = check_ec_signature(
        &user_pk,
        &sol_outcome.signature.big_r,
        &sol_outcome.signature.s,
        payload_scalar,
        sol_outcome.recovery_id,
    )
    .is_ok();
    assert!(
        signature_valid,
        "mpc signature did not verify against derived user key"
    );

    let (r, s_u256) = signature_components(&sol_outcome.signature);
    let signed_rlp = encode_signed_legacy_tx_components(
        &legacy_tx,
        chain_id,
        r,
        s_u256,
        sol_outcome.recovery_id,
    );
    let raw_tx_hex = format!("0x{}", hex::encode(&signed_rlp));

    tracing::info!(
        signed_tx = %raw_tx_hex,
        "broadcasting signed ethereum transaction produced by MPC"
    );

    let send_value = eth_rpc_call(
        &client,
        &execution_rpc_http_url,
        "eth_sendRawTransaction",
        json!([raw_tx_hex]),
    )
    .await?;
    let tx_hash = send_value
        .as_str()
        .context("eth_sendRawTransaction missing result")?
        .to_string();

    let receipt = wait_for_transaction_receipt(
        &client,
        &execution_rpc_http_url,
        &tx_hash,
        TX_RECEIPT_MAX_ATTEMPTS,
        Duration::from_secs(TX_RECEIPT_POLL_INTERVAL_SECS),
    )
    .await?;

    let status = receipt
        .get("status")
        .and_then(|value| value.as_str())
        .context("transaction receipt missing status")?;

    if status != "0x1" {
        anyhow::bail!(
            "ethereum transaction {} failed with status {}",
            tx_hash,
            status
        );
    }

    let read_outcome = actions::sign::wait_for_respond_bidirectional(
        solana,
        sol_outcome.request_id,
        Duration::from_secs(120),
    )
    .await?;

    assert_eq!(
        read_outcome.request_id, sol_outcome.request_id,
        "respond bidirectional event request_id mismatch"
    );

    Ok(())
}

struct EthereumTransaction {
    nonce: U256,
    gas_price: U256,
    gas_limit: U256,
    to: AlloyAddress,
    value: U256,
    data: Vec<u8>,
}

fn encode_unsigned_legacy_tx(tx: &EthereumTransaction, chain_id: u64) -> Vec<u8> {
    let mut stream = RlpStream::new_list(9);
    append_u256(&mut stream, &tx.nonce);
    append_u256(&mut stream, &tx.gas_price);
    append_u256(&mut stream, &tx.gas_limit);
    stream.append(&tx.to.as_slice().to_vec());
    append_u256(&mut stream, &tx.value);
    stream.append(&tx.data);
    append_u256(&mut stream, &U256::from(chain_id));
    append_u256(&mut stream, &U256::from(0u8));
    append_u256(&mut stream, &U256::from(0u8));
    stream.out().to_vec()
}

fn encode_signed_legacy_tx_components(
    tx: &EthereumTransaction,
    chain_id: u64,
    r: U256,
    s: U256,
    recovery_id: u8,
) -> Vec<u8> {
    let mut stream = RlpStream::new_list(9);
    append_u256(&mut stream, &tx.nonce);
    append_u256(&mut stream, &tx.gas_price);
    append_u256(&mut stream, &tx.gas_limit);
    stream.append(&tx.to.as_slice().to_vec());
    append_u256(&mut stream, &tx.value);
    stream.append(&tx.data);
    let v = U256::from(chain_id * 2 + 35 + recovery_id as u64);
    append_u256(&mut stream, &v);
    append_u256(&mut stream, &r);
    append_u256(&mut stream, &s);
    stream.out().to_vec()
}

fn append_u256(stream: &mut RlpStream, value: &U256) {
    if *value == U256::from(0u8) {
        stream.append_empty_data();
    } else {
        let bytes = value.to_be_bytes::<32>();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        stream.append(&bytes[first..].to_vec());
    }
}

fn signature_components(signature: &FullSignature<Secp256k1>) -> (U256, U256) {
    let r_scalar = actions::x_coordinate::<Secp256k1>(&signature.big_r);
    let r_bytes = r_scalar.to_bytes();
    let r = U256::from_be_slice(r_bytes.as_slice());
    let s_bytes = signature.s.to_bytes();
    let s = U256::from_be_slice(s_bytes.as_slice());
    (r, s)
}

async fn ensure_eth_signer_funded(
    client: &Client,
    rpc_url: &str,
    payer_sk_hex: &str,
    recipient: AlloyAddress,
    min_balance: U256,
    default_gas_price: U256,
    chain_id: u64,
) -> Result<()> {
    let payer_sk_bytes = hex::decode(payer_sk_hex.trim_start_matches("0x"))?;
    let payer_sk_array: [u8; 32] = payer_sk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32-byte ethereum secret key"))?;
    let payer_sk = SecpSecretKey::from_slice(&payer_sk_array)?;
    let secp = LibSecp256k1::signing_only();
    let payer_pk = SecpPublicKey::from_secret_key(&secp, &payer_sk);
    let payer_address = actions::public_key_to_address(&payer_pk);
    let payer_alloy = AlloyAddress::from_slice(payer_address.as_bytes());
    let signing_key = SigningKey::from_bytes(&payer_sk_array.into())?;

    let mut gas_price = fetch_gas_price(client, rpc_url).await?;
    if gas_price < default_gas_price {
        gas_price = default_gas_price;
    }

    let recipient_hex = format_alloy_address(&recipient);
    let current_balance = get_eth_balance(client, rpc_url, &recipient_hex).await?;
    let required_balance = min_balance;
    if current_balance >= required_balance {
        tracing::info!(
            address = %recipient_hex,
            balance = %format_u256_hex(current_balance),
            "signer already funded"
        );
        return Ok(());
    }

    let top_up = {
        let deficit = required_balance.saturating_sub(current_balance);
        let top_up_default = U256::from(FUNDING_TOP_UP_WEI);
        if deficit > top_up_default {
            deficit
        } else {
            top_up_default
        }
    };

    let gas_limit = U256::from(FUNDING_GAS_LIMIT);
    let payer_hex = format_alloy_address(&payer_alloy);
    let payer_balance = get_eth_balance(client, rpc_url, &payer_hex).await?;
    let total_cost = gas_price * gas_limit + top_up;
    anyhow::ensure!(
        payer_balance >= total_cost,
        "payer account {} has insufficient balance for funding: needs {}, has {}",
        payer_hex,
        format_u256_hex(total_cost),
        format_u256_hex(payer_balance)
    );

    let nonce = get_transaction_count(client, rpc_url, &payer_hex).await?;

    let funding_tx = EthereumTransaction {
        nonce,
        gas_price,
        gas_limit,
        to: recipient,
        value: top_up,
        data: Vec::new(),
    };

    let unsigned_rlp = encode_unsigned_legacy_tx(&funding_tx, chain_id);
    let digest = Keccak256::new_with_prefix(&unsigned_rlp);
    let (signature, recovery_id) = signing_key.sign_digest_recoverable(digest)?;
    let sig_bytes = signature.to_bytes();
    let r = U256::from_be_slice(&sig_bytes[..32]);
    let s = U256::from_be_slice(&sig_bytes[32..]);
    let signed_rlp =
        encode_signed_legacy_tx_components(&funding_tx, chain_id, r, s, recovery_id.to_byte());
    let raw_tx_hex = format!("0x{}", hex::encode(&signed_rlp));

    let send_value = eth_rpc_call(
        client,
        rpc_url,
        "eth_sendRawTransaction",
        json!([raw_tx_hex]),
    )
    .await?;
    let tx_hash = send_value
        .as_str()
        .context("eth_sendRawTransaction missing result")?;
    tracing::info!(
        payer = %payer_hex,
        recipient = %recipient_hex,
        top_up = %format_u256_hex(top_up),
        tx_hash,
        "submitted funding transaction"
    );

    for attempt in 0..FUNDING_MAX_ATTEMPTS {
        let balance = get_eth_balance(client, rpc_url, &recipient_hex).await?;
        if balance >= required_balance {
            tracing::info!(
                address = %recipient_hex,
                balance = %format_u256_hex(balance),
                attempts = attempt,
                "signer funding confirmed"
            );
            return Ok(());
        }

        sleep(Duration::from_secs(FUNDING_POLL_INTERVAL_SECS)).await;
    }

    anyhow::bail!(
        "timed out waiting for signer funding; address {} still below required balance {}",
        recipient_hex,
        format_u256_hex(required_balance)
    );
}

async fn fetch_gas_price(client: &Client, rpc_url: &str) -> Result<U256> {
    let value = eth_rpc_call(client, rpc_url, "eth_gasPrice", json!([])).await?;
    parse_u256_from_result(&value)
}

async fn get_eth_balance(client: &Client, rpc_url: &str, address: &str) -> Result<U256> {
    let value = eth_rpc_call(
        client,
        rpc_url,
        "eth_getBalance",
        json!([address, "latest"]),
    )
    .await?;
    parse_u256_from_result(&value)
}

async fn get_transaction_count(client: &Client, rpc_url: &str, address: &str) -> Result<U256> {
    let value = eth_rpc_call(
        client,
        rpc_url,
        "eth_getTransactionCount",
        json!([address, "latest"]),
    )
    .await?;
    parse_u256_from_result(&value)
}

fn parse_u256_from_result(value: &serde_json::Value) -> Result<U256> {
    let hex_str = value
        .as_str()
        .context("expected hex string from ethereum rpc")?;
    parse_u256_from_hex(hex_str)
}

fn parse_u256_from_hex(hex_str: &str) -> Result<U256> {
    let stripped = hex_str.trim_start_matches("0x");
    if stripped.is_empty() {
        return Ok(U256::ZERO);
    }
    let padded = if stripped.len() % 2 == 1 {
        format!("0{}", stripped)
    } else {
        stripped.to_string()
    };
    let bytes = hex::decode(padded)?;
    Ok(U256::from_be_slice(&bytes))
}

fn format_alloy_address(address: &AlloyAddress) -> String {
    format!("0x{}", hex::encode(address.as_slice()))
}

fn format_u256_hex(value: U256) -> String {
    format!("0x{:x}", value)
}

async fn eth_rpc_call(
    client: &Client,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let response = client
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        }))
        .send()
        .await?
        .error_for_status()?;

    let value: serde_json::Value = response.json().await?;
    if let Some(error) = value.get("error") {
        anyhow::bail!("ethereum rpc {} returned error: {}", method, error);
    }

    value
        .get("result")
        .cloned()
        .context("ethereum rpc response missing result field")
}

async fn wait_for_transaction_receipt(
    client: &Client,
    rpc_url: &str,
    tx_hash: &str,
    max_attempts: usize,
    poll_interval: Duration,
) -> Result<serde_json::Value> {
    for attempt in 0..max_attempts {
        let receipt = eth_rpc_call(
            client,
            rpc_url,
            "eth_getTransactionReceipt",
            json!([tx_hash]),
        )
        .await?;

        if !receipt.is_null() {
            return Ok(receipt);
        }

        tracing::info!(
            tx_hash,
            attempt,
            max_attempts,
            "waiting for ethereum transaction receipt"
        );
        sleep(poll_interval).await;
    }

    anyhow::bail!(
        "timed out waiting for transaction receipt for {} after {} attempts",
        tx_hash,
        max_attempts
    );
}
