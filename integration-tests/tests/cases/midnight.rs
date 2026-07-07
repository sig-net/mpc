//! Midnight full-cluster e2e. Heavy: real MPC cluster + l9 stack + proving.
//! test_midnight_sign_e2e needs ~16 GiB; test_midnight_eth_bidirectional_e2e
//! needs ~32 GiB (user-side sign_bidirectional prove ≈ 24 GiB RSS, native).
//! Run: cargo test -p integration-tests --test lib -- cases::midnight --ignored --test-threads 1

use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, Bytes, FixedBytes, Signature as AlloySignature, TxKind, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context as _, Result};
use integration_tests::cluster;
use integration_tests::midnight::{MidnightBiParams, GOLDEN_COMMITMENT_HEX, GOLDEN_SIGN_PAYLOAD_0};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use mpc_chain_midnight::wire::{EventPart, RequestKind};
use mpc_chain_midnight::{requests, RawContractEvent};
use mpc_node::respond_bidirectional::MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH;
use mpc_node::sign_bidirectional::derive_user_address;
use mpc_node::util::NearPublicKeyExt;
use mpc_primitives::{Signature, LATEST_MPC_KEY_VERSION};
use serial_test::serial;
use std::time::Duration;
use test_log::test;

const RETURN_TRUE_RUNTIME_BYTECODE: &str = "600160005260206000f3";
const EVM_TEST_CONTRACT: &str = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

/// Poll the indexer for a responded-event group answering `rid`.
async fn wait_for_responded(
    graphql: &mpc_chain_midnight::MidnightGraphql,
    kind: RequestKind,
    rid: [u8; 32],
    limit: Duration,
) -> Result<Vec<EventPart>> {
    let start = std::time::Instant::now();
    loop {
        anyhow::ensure!(
            start.elapsed() < limit,
            "timeout waiting for {kind:?} of {}",
            hex::encode(rid)
        );
        let events: Vec<RawContractEvent> = graphql.fetch_events(500, 0).await?;
        let parts: Vec<EventPart> = events
            .iter()
            .filter_map(|ev| EventPart::parse(&ev.name, &ev.payload).ok())
            .filter(|p| p.kind == kind && p.request_id == rid)
            .collect();
        if parts.len() == kind.part_count() {
            return Ok(parts);
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn verify_prehash_signature(
    root_pk: k256::AffinePoint,
    epsilon: k256::Scalar,
    prehash: &[u8; 32],
    signature: &Signature,
) -> Result<()> {
    let derived = mpc_crypto::derive_key(root_pk, epsilon);
    let ecdsa = k256::ecdsa::Signature::from_scalars(
        mpc_crypto::x_coordinate(&signature.big_r),
        signature.s,
    )
    .context("invalid signature scalars")?;
    let key = k256::ecdsa::VerifyingKey::from_affine(derived)
        .map_err(|e| anyhow::anyhow!("invalid derived key: {e}"))?;
    key.verify_prehash(prehash, &ecdsa)
        .context("signature does not verify")
}

#[ignore] // requires docker + l9 stack prereqs + MPC cluster
#[serial]
#[test(tokio::test)]
async fn test_midnight_sign_e2e() -> Result<()> {
    let nodes = cluster::spawn().disable_prestockpile().midnight().await?;
    nodes.wait().signable().await?;
    let sandbox = nodes
        .midnight
        .as_ref()
        .context("midnight sandbox missing")?;
    let root_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();

    sandbox
        .submit_sign(GOLDEN_SIGN_PAYLOAD_0, LATEST_MPC_KEY_VERSION)
        .await?;

    // The rid is deployment-independent (hash of the tails); fresh chain →
    // nonce 0 → the golden rid.
    let rid =
        integration_tests::utils::hex32(integration_tests::midnight::GOLDEN_SIGN_REQUEST_ID_0);
    let parts = wait_for_responded(
        &sandbox.graphql(),
        RequestKind::Respond,
        rid,
        Duration::from_secs(900),
    )
    .await?;
    let signature = requests::decode_respond(&parts)?;

    let epsilon = mpc_crypto::kdf::derive_epsilon_midnight(
        LATEST_MPC_KEY_VERSION,
        &sandbox.contract_address,
        GOLDEN_COMMITMENT_HEX,
    );
    let payload = integration_tests::utils::hex32(GOLDEN_SIGN_PAYLOAD_0);
    verify_prehash_signature(root_pk, epsilon, &payload, &signature)
        .context("sign e2e: MPC signature must verify against the midnight-derived key")?;
    tracing::info!("midnight sign e2e verified");
    Ok(())
}

#[ignore] // requires ≥32 GiB host (sign_bidirectional prove)
#[serial]
#[test(tokio::test)]
async fn test_midnight_eth_bidirectional_e2e() -> Result<()> {
    let nodes = cluster::spawn()
        .disable_prestockpile()
        .midnight()
        .ethereum()
        .await?;
    nodes.wait().signable().await?;
    let sandbox = nodes
        .midnight
        .as_ref()
        .context("midnight sandbox missing")?;
    let root_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();

    // Anvil with manual mining + a return-true contract (Canton recipe).
    let eth_ctx = nodes
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum missing")?;
    let anvil =
        ProviderBuilder::new().connect_http(eth_ctx.sandbox.external_http_endpoint.parse()?);
    anvil.anvil_set_auto_mine(false).await?;
    anvil.anvil_set_interval_mining(0).await?;
    let contract_addr = Address::from_slice(&hex::decode(EVM_TEST_CONTRACT)?);
    anvil
        .anvil_set_code(
            contract_addr,
            Bytes::from(hex::decode(RETURN_TRUE_RUNTIME_BYTECODE)?),
        )
        .await?;

    let params = MidnightBiParams {
        evm_to: EVM_TEST_CONTRACT.into(),
        evm_chain_id: 31_337,
        evm_nonce: 0,
        evm_gas_limit: 100_000,
        evm_max_fee: 100_000_000_000,
        evm_priority_fee: 1_000_000_000,
        evm_value: 0,
        func_sig: "transfer(address,uint256)".into(),
        args: vec![
            format!("{:0>64}", "2222222222222222222222222222222222222222"),
            format!("{:0>64x}", 100_000_000u64),
        ],
        arg_count: 2,
        caip2: mpc_node::protocol::Chain::Ethereum.caip2_chain_id().into(),
        key_version: LATEST_MPC_KEY_VERSION,
        dest: "ethereum".into(),
        params: String::new(),
        // The eth execution watcher's contract-call decoder requires the
        // object schema form (Vec<AbiField>); the bare ["bool"] shorthand is
        // only accepted on the respond-serialization side.
        output_schema: r#"[{"name":"output","type":"bool"}]"#.into(),
        respond_schema: r#"[{"name":"output","type":"bool"}]"#.into(),
    };
    sandbox.submit_sign_bidirectional(&params).await?;

    // Recover the rid from the emitted request itself (nonce-dependent).
    let graphql = sandbox.graphql();
    let rid = {
        let start = std::time::Instant::now();
        loop {
            anyhow::ensure!(
                start.elapsed() < Duration::from_secs(600),
                "request events never appeared"
            );
            let events = graphql.fetch_events(500, 0).await?;
            let part1 = events.iter().find_map(|ev| {
                EventPart::parse(&ev.name, &ev.payload)
                    .ok()
                    .filter(|p| p.kind == RequestKind::SignBidirectional && p.part_index == 1)
            });
            if let Some(p) = part1 {
                break p.request_id;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    };

    // Phase 1: MPC publishes the tx signature back on Midnight.
    let parts = wait_for_responded(
        &graphql,
        RequestKind::Respond,
        rid,
        Duration::from_secs(900),
    )
    .await?;
    let mpc_signature = requests::decode_respond(&parts)?;

    // Relay the signed EIP-1559 tx to anvil ourselves (Canton recipe — the
    // node watches execution, it does not broadcast).
    let calldata = {
        let mut words = [[0u8; 32]; 4];
        for (i, w) in params.args.iter().enumerate() {
            words[i] = integration_tests::utils::hex32(w);
        }
        requests::build_calldata(&params.func_sig, &words, params.arg_count)?
    };
    let tx = TxEip1559 {
        chain_id: params.evm_chain_id,
        nonce: params.evm_nonce,
        gas_limit: params.evm_gas_limit,
        max_fee_per_gas: params.evm_max_fee,
        max_priority_fee_per_gas: params.evm_priority_fee,
        to: TxKind::Call(contract_addr),
        value: U256::from(params.evm_value),
        access_list: Default::default(),
        input: Bytes::from(calldata),
    };
    let epsilon = mpc_crypto::kdf::derive_epsilon_midnight(
        LATEST_MPC_KEY_VERSION,
        &sandbox.contract_address,
        GOLDEN_COMMITMENT_HEX,
    );
    let sender = derive_user_address(root_pk, epsilon);
    anvil
        .anvil_set_balance(sender, U256::from(10_000_000_000_000_000_000u128))
        .await?;
    let r: [u8; 32] = mpc_crypto::x_coordinate(&mpc_signature.big_r)
        .to_bytes()
        .into();
    let s: [u8; 32] = mpc_signature.s.to_bytes().into();
    let signed = tx
        .clone()
        .into_signed(AlloySignature::from_scalars_and_parity(
            FixedBytes::from_slice(&r),
            FixedBytes::from_slice(&s),
            mpc_signature.recovery_id == 1,
        ))
        .encoded_2718();
    let _pending = anvil.send_raw_transaction(&signed).await?;
    anvil.evm_mine(None).await?;

    // Phase 2: MPC observes execution and publishes respond_bidirectional.
    let parts = wait_for_responded(
        &graphql,
        RequestKind::RespondBidirectional,
        rid,
        Duration::from_secs(1800),
    )
    .await?;
    let (output, phase2_sig) = requests::decode_respond_bidirectional(&parts)?;
    let mut abi_true = vec![0u8; 32];
    abi_true[31] = 1;
    assert_eq!(output, abi_true, "expected ABI bool true output");

    let mut preimage = rid.to_vec();
    preimage.extend_from_slice(&output);
    let message: [u8; 32] = alloy::primitives::keccak256(&preimage).into();
    let respond_epsilon = mpc_crypto::kdf::derive_epsilon_midnight(
        LATEST_MPC_KEY_VERSION,
        &sandbox.contract_address,
        MIDNIGHT_RESPOND_BIDIRECTIONAL_PATH,
    );
    verify_prehash_signature(root_pk, respond_epsilon, &message, &phase2_sig)
        .context("phase-2 signature must verify under 'midnight response key'")?;
    tracing::info!("midnight bidirectional e2e verified");
    Ok(())
}
