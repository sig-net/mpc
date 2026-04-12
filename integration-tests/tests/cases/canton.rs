use alloy::consensus::transaction::SignableTransaction;
use alloy::consensus::TxEip1559;
use alloy::primitives::{Address, Bytes, TxKind, U256};
use anyhow::{Context as _, Result};
use integration_tests::cluster;
use mpc_node::util::NearPublicKeyExt;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use reqwest::Client;
use rlp::{Rlp, RlpStream};
use serde_json::json;
use std::time::Duration;
use test_log::test;

#[ignore] // requires dpm + openssl + Docker (for Ethereum)
#[test(tokio::test)]
async fn test_canton_eth_bidirectional_flow() -> Result<()> {
    // 1. Spawn cluster with Canton + Ethereum
    let nodes = cluster::spawn()
        .disable_prestockpile()
        .canton()
        .ethereum()
        .await?;

    nodes.wait().signable().await?;

    // 2. Get Canton and Ethereum contexts
    let canton = nodes
        .canton
        .as_ref()
        .context("canton sandbox not available")?;
    // 3. Submit sign request directly via Signer (bypasses Vault)
    let client = &canton.client;
    let evm_tx_params = json!({
        "to": "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "functionSignature": "transfer(address,uint256)",
        "args": [
            "0".repeat(64),
            "0000000000000000000000000000000000000000000000000000000005f5e100"
        ],
        "value": "0".repeat(64),
        "nonce": format!("{:0>64}", "0"),
        "gasLimit": format!("{:0>64}", "186a0"),
        "maxFeePerGas": format!("{:0>64}", "3b9aca00"),
        "maxPriorityFee": format!("{:0>64}", "3b9aca00"),
        // Anvil uses chain ID 31337 (0x7A69), not Sepolia
        "chainId": format!("{:0>64}", "7a69"),
    });

    let sign_request = client
        .create_contract(
            &[&canton.operator_party],
            "#daml-signer:Signer:SignRequest",
            json!({
                "operators": [&canton.operator_party],
                "requester": &canton.requester_party,
                "sigNetwork": &canton.party_id,
                "sender": "test-sender",
                "txParams": { "tag": "EvmTxParams", "value": evm_tx_params },
                "caip2Id": "eip155:31337",
                "keyVersion": LATEST_MPC_KEY_VERSION,
                "path": &canton.requester_party,
                "algo": "ECDSA",
                "dest": "ethereum",
                "params": "",
                "nonceCidText": &canton.nonce_cid,
                "outputDeserializationSchema": r#"[{"name":"","type":"bool"}]"#,
                "respondSerializationSchema": r#"[{"name":"","type":"bool"}]"#,
            }),
        )
        .await?;
    let sign_request_cid =
        integration_tests::canton::find_created_contract(&sign_request, "SignRequest")?.0;
    let sign_request_disclosure = client
        .get_disclosed_contract(
            &[&canton.operator_party],
            "#daml-signer:Signer:SignRequest",
            &sign_request_cid,
        )
        .await?;

    client
        .exercise_choice(
            &[&canton.requester_party],
            &canton.signer_template_id,
            &canton.signer_cid,
            "SignBidirectional",
            json!({
                "signRequestCid": sign_request_cid,
                "nonceCid": &canton.nonce_cid,
                "requester": &canton.requester_party,
            }),
            &[canton.signer_disclosure.clone(), sign_request_disclosure],
        )
        .await?;
    tracing::info!("canton sign request submitted via Signer");

    // 4. Poll for SignatureRespondedEvent (MPC node signs and responds)
    let sig_event = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:SignatureRespondedEvent",
            |payload| {
                payload
                    .get("signature")
                    .and_then(|s| s.as_str())
                    .is_some_and(|s| !s.is_empty())
            },
            Duration::from_secs(120),
        )
        .await
        .context("timeout waiting for SignatureRespondedEvent")?;
    let request_id = sig_event.created_event.payload["requestId"]
        .as_str()
        .context("no requestId in SignatureRespondedEvent")?;
    tracing::info!(%request_id, "received SignatureRespondedEvent");

    // 5. Relay the signed EVM transaction to Anvil
    //
    // The MPC node produced a DER-encoded ECDSA signature but does not submit the
    // Ethereum transaction itself — the test acts as the relayer.
    let eth_ctx = nodes
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum not available")?;
    let anvil_rpc_url = eth_ctx.sandbox.external_http_endpoint.clone();

    // Parse DER signature from SignatureRespondedEvent → (r, s) scalars
    let signature_hex = sig_event.created_event.payload["signature"]
        .as_str()
        .context("missing signature in SignatureRespondedEvent")?;
    let der_stripped = signature_hex.strip_prefix("0x").unwrap_or(signature_hex);
    let der_bytes = hex::decode(der_stripped).context("invalid hex in DER signature")?;
    let ecdsa_sig = k256::ecdsa::Signature::from_der(&der_bytes)
        .map_err(|e| anyhow::anyhow!("invalid DER signature: {e}"))?;
    let (r_scalar, s_scalar) = ecdsa_sig.split_scalars();
    let r_bytes: [u8; 32] = r_scalar.to_bytes().into();
    let s_bytes: [u8; 32] = s_scalar.to_bytes().into();

    // Reconstruct the unsigned EIP-1559 RLP from the test's evm_tx_params
    // (mirrors indexer_canton::to_tx_eip1559 + rlp_encode_unsigned_eip1559)
    let unsigned_tx = build_eip1559_from_test_params(&evm_tx_params)?;
    let mut unsigned_rlp = Vec::new();
    unsigned_tx.encode_for_signing(&mut unsigned_rlp);

    // Recover sender address from the signature (try both parities) and fund it on Anvil.
    // TODO: derive the expected address from the MPC public key +
    // derive_epsilon_canton(key_version, sender, path) and assert the recovered
    // address matches. Currently we only verify the signature is valid (Anvil
    // accepts the tx), not that it was signed by the correct KDF-derived key.
    let signing_hash: [u8; 32] = alloy::primitives::keccak256(&unsigned_rlp).into();
    let http_client = Client::new();

    for y in [0u8, 1u8] {
        if let Ok(rid) = k256::ecdsa::RecoveryId::try_from(y) {
            if let Ok(recovered) =
                k256::ecdsa::VerifyingKey::recover_from_prehash(&signing_hash, &ecdsa_sig, rid)
            {
                let pk_bytes = recovered.to_encoded_point(false);
                let addr_hash = alloy::primitives::keccak256(&pk_bytes.as_bytes()[1..]);
                let sender_addr = format!("0x{}", hex::encode(&addr_hash[12..]));
                // Fund sender with 10 ETH via anvil_setBalance
                let _ = eth_rpc_call(
                    &http_client,
                    &anvil_rpc_url,
                    "anvil_setBalance",
                    json!([sender_addr, "0x8AC7230489E80000"]),
                )
                .await;
            }
        }
    }

    // Build signed EIP-1559 bytes for both y_parity values and try submitting.
    // DER encoding does not carry the recovery ID, so we try both.
    let mut relay_tx_hash: Option<String> = None;

    for y_parity in [0u8, 1u8] {
        let signed_bytes =
            build_signed_eip1559_bytes(&unsigned_rlp, &r_bytes, &s_bytes, y_parity == 1);
        let raw_tx_hex = format!("0x{}", hex::encode(&signed_bytes));

        match eth_rpc_call(
            &http_client,
            &anvil_rpc_url,
            "eth_sendRawTransaction",
            json!([raw_tx_hex]),
        )
        .await
        {
            Ok(value) => {
                let hash = value
                    .as_str()
                    .context("eth_sendRawTransaction missing result")?
                    .to_string();
                tracing::info!(
                    tx_hash = %hash,
                    y_parity,
                    "relayed signed EIP-1559 transaction to Anvil"
                );
                relay_tx_hash = Some(hash);
                break;
            }
            Err(e) => {
                tracing::info!(
                    y_parity,
                    error = %e,
                    "eth_sendRawTransaction failed with y_parity={}, trying next",
                    y_parity
                );
            }
        }
    }

    let _tx_hash = relay_tx_hash.context("failed to relay tx with either y_parity (0 and 1)")?;

    // Pump blocks on Anvil so the MPC node's Ethereum execution watcher reliably
    // detects the relayed transaction. Without continuous block production, the
    // indexer can miss the single auto-mined block in a polling race.
    let pump_client = http_client.clone();
    let pump_url = anvil_rpc_url.clone();
    let block_pumper = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let _ = eth_rpc_call(&pump_client, &pump_url, "evm_mine", json!([])).await;
        }
    });

    // 6. Poll for RespondBidirectionalEvent (MPC posted the outcome)
    let respond_event = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:RespondBidirectionalEvent",
            |payload| payload["requestId"].as_str() == Some(request_id),
            Duration::from_secs(300),
        )
        .await
        .context("timeout waiting for RespondBidirectionalEvent")?;

    tracing::info!("received RespondBidirectionalEvent");

    // 7. Verify the Phase 2 response signature against the MPC-derived public key
    let respond_payload = &respond_event.created_event.payload;
    let serialized_output = respond_payload["serializedOutput"]
        .as_str()
        .context("RespondBidirectionalEvent missing serializedOutput")?;
    let respond_sig_hex = respond_payload["signature"]
        .as_str()
        .context("RespondBidirectionalEvent missing signature")?;
    let respond_der = hex::decode(
        respond_sig_hex
            .strip_prefix("0x")
            .unwrap_or(respond_sig_hex),
    )?;
    let respond_ecdsa = k256::ecdsa::Signature::from_der(&respond_der)
        .map_err(|e| anyhow::anyhow!("invalid DER: {e}"))?;

    // Recompute the message hash: keccak256(requestId ++ serializedOutput)
    let request_id_bytes = hex::decode(request_id)?;
    let serialized_output_bytes = hex::decode(serialized_output)?;
    let mut combined = Vec::with_capacity(request_id_bytes.len() + serialized_output_bytes.len());
    combined.extend_from_slice(&request_id_bytes);
    combined.extend_from_slice(&serialized_output_bytes);
    let response_hash: [u8; 32] = alloy::primitives::keccak256(&combined).into();

    // Derive the expected Canton public key for Phase 2 response signing.
    // Phase 2 uses "canton response key" as the path (not the original requester path).
    let root_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();
    let epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        "test-sender",
        "canton response key",
    );
    let derived_pk = mpc_crypto::derive_key(root_pk, epsilon);

    // Verify the signature against the derived public key
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let verifying_key = k256::ecdsa::VerifyingKey::from_affine(derived_pk)
        .map_err(|e| anyhow::anyhow!("invalid derived public key: {e}"))?;
    verifying_key
        .verify_prehash(&response_hash, &respond_ecdsa)
        .map_err(|e| anyhow::anyhow!("RespondBidirectional signature verification failed: {e}"))?;
    tracing::info!("RespondBidirectional signature verified against MPC-derived key");

    block_pumper.abort();
    tracing::info!("Canton bidirectional flow completed successfully");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: build TxEip1559 from the test's JSON evm_tx_params
// ---------------------------------------------------------------------------

fn build_eip1559_from_test_params(params: &serde_json::Value) -> Result<TxEip1559> {
    let to_hex = params["to"].as_str().context("missing to")?;
    let to_bytes = hex::decode(to_hex)?;
    // Canton pads to 64 hex chars (32 bytes) -- take last 20 for the address
    let addr_bytes = if to_bytes.len() > 20 {
        &to_bytes[to_bytes.len() - 20..]
    } else {
        &to_bytes
    };

    let function_signature = params["functionSignature"]
        .as_str()
        .context("missing functionSignature")?;
    let args: Vec<String> = params["args"]
        .as_array()
        .context("missing args")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    // Build calldata: selector(4 bytes) ++ concat(args)
    let selector: [u8; 4] = alloy::primitives::keccak256(function_signature.as_bytes()).0[..4]
        .try_into()
        .unwrap();
    let mut calldata = selector.to_vec();
    for arg in &args {
        calldata.extend_from_slice(&hex::decode(arg).unwrap_or_default());
    }

    Ok(TxEip1559 {
        chain_id: u64::from_str_radix(params["chainId"].as_str().unwrap_or("0"), 16).unwrap_or(0),
        nonce: u64::from_str_radix(params["nonce"].as_str().unwrap_or("0"), 16).unwrap_or(0),
        gas_limit: u64::from_str_radix(params["gasLimit"].as_str().unwrap_or("0"), 16).unwrap_or(0),
        max_fee_per_gas: u128::from_str_radix(params["maxFeePerGas"].as_str().unwrap_or("0"), 16)
            .unwrap_or(0),
        max_priority_fee_per_gas: u128::from_str_radix(
            params["maxPriorityFee"].as_str().unwrap_or("0"),
            16,
        )
        .unwrap_or(0),
        to: TxKind::Call(Address::from_slice(addr_bytes)),
        value: U256::from_str_radix(params["value"].as_str().unwrap_or("0"), 16)
            .unwrap_or(U256::ZERO),
        input: Bytes::from(calldata),
        access_list: Default::default(),
    })
}

// ---------------------------------------------------------------------------
// Helper: build signed EIP-1559 bytes from unsigned RLP + signature components
// ---------------------------------------------------------------------------

/// Reconstruct signed EIP-1559 bytes: `0x02 || RLP([9 unsigned fields, yParity, r, s])`.
///
/// `unsigned_rlp` is the output of `TxEip1559::encode_for_signing`, which is
/// `0x02 || RLP(chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, input, accessList)`.
fn build_signed_eip1559_bytes(
    unsigned_rlp: &[u8],
    r: &[u8; 32],
    s: &[u8; 32],
    y_parity: bool,
) -> Vec<u8> {
    // Strip the 0x02 type prefix to get the RLP body
    let body = if unsigned_rlp.first().copied() == Some(0x02) {
        &unsigned_rlp[1..]
    } else {
        unsigned_rlp
    };

    let rlp = Rlp::new(body);
    // Re-encode with 12 fields: 9 unsigned fields + yParity + r + s
    let mut srlp = RlpStream::new_list(12);
    for i in 0..9 {
        srlp.append_raw(rlp.at(i).expect("unsigned EIP-1559 field").as_raw(), 1);
    }
    let y: u8 = if y_parity { 1 } else { 0 };
    srlp.append(&y);
    srlp.append(&r.as_ref());
    srlp.append(&s.as_ref());

    let mut signed = Vec::with_capacity(1 + srlp.as_raw().len());
    signed.push(0x02);
    signed.extend_from_slice(srlp.as_raw());
    signed
}

// ---------------------------------------------------------------------------
// Helper: JSON-RPC call to an Ethereum node
// ---------------------------------------------------------------------------

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
