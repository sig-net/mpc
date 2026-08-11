//! `ChainSignatures` contract operations for tests/dev (deploy + sign-request
//! submission).

use crate::abi::{ChainSignatures, ChainSignaturesConstructor};
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{Provider, WalletProvider};
use alloy::rpc::types::request::TransactionRequest;
use alloy::sol_types::SolValue;
use anyhow::{Context, Result};
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde_json::Value;
use std::time::Duration;

/// Deploy `ChainSignatures` via raw bytecode + constructor args.
pub async fn deploy_chain_signatures<P>(
    provider: P,
    deployer: Address,
    mpc_address: Address,
    signature_deposit: U256,
) -> Result<Address>
where
    P: Provider + Clone + 'static,
{
    let artifact: Value = serde_json::from_slice(include_bytes!(
        "../../../contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json"
    ))?;

    let bytecode = artifact
        .get("bytecode")
        .and_then(Value::as_str)
        .context("bytecode missing from artifact")?;
    let mut deployment = hex::decode(bytecode.trim_start_matches("0x"))?;
    deployment.extend_from_slice(
        &ChainSignaturesConstructor {
            mpcNetwork: mpc_address,
            signatureDeposit: signature_deposit,
        }
        .abi_encode(),
    );

    let tx = TransactionRequest::default()
        .into_create()
        .with_from(deployer)
        .with_input(Bytes::from(deployment));

    let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
    receipt
        .contract_address
        .context("deployment receipt missing contract address")
}

/// Submit a `sign` request on-chain and return its derived `request_id`.
pub async fn submit_sign_request<P>(
    contract: &ChainSignatures::ChainSignaturesInstance<P>,
    seed: usize,
) -> Result<B256>
where
    P: Provider + WalletProvider + Clone + Send + Sync + 'static,
{
    const MAX_ATTEMPTS: usize = 3;
    let provider = contract.provider();
    let sender = provider.default_signer_address();
    let chain_id = provider.get_chain_id().await?;

    let payload = [seed as u8; 32];
    let path = format!("offline_test_{seed}");
    let key_version = LATEST_MPC_KEY_VERSION;
    let algo = "secp256k1";
    let dest = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
    let params = "{}";
    let request_id = B256::from(crate::generate_request_id(
        sender,
        &payload,
        &path,
        key_version,
        U256::from(chain_id),
        algo,
        dest,
        params,
    ));

    for attempt in 1..=MAX_ATTEMPTS {
        let request = ChainSignatures::SignRequest {
            payload: payload.into(),
            path: path.clone(),
            keyVersion: key_version,
            algo: algo.to_string(),
            dest: dest.to_string(),
            params: params.to_string(),
        };
        let nonce = provider
            .get_transaction_count(sender)
            .pending()
            .await
            .context("fetch nonce")?;

        match contract
            .sign(request)
            .value(U256::from(1_u64))
            .nonce(nonce)
            .send()
            .await
        {
            Ok(pending) => {
                pending.get_receipt().await.context("sign receipt")?;
                return Ok(request_id);
            }
            Err(err) => {
                let retryable = err.to_string().contains("nonce too low")
                    || err
                        .to_string()
                        .contains("replacement transaction underpriced");
                if retryable && attempt < MAX_ATTEMPTS {
                    tracing::warn!(attempt, nonce, %err, "retrying ethereum sign after nonce conflict");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                return Err(err.into());
            }
        }
    }

    unreachable!("retry loop returns on its final attempt")
}
