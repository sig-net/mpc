use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, B256, Bytes, FixedBytes, Signature, U256, keccak256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use anyhow::{Context as _, Result};
use integration_tests::canton::{CantonTestClient, compute_operators_hash, find_created_contract};
use integration_tests::cluster;
use mpc_node::indexer_canton::contracts::{
    EvmType2TransactionParams, RespondBidirectionalEventPayload, SignatureRespondedEventPayload,
};
use mpc_node::indexer_canton::ledger_api::{
    ContractEntry, Event, SubmitAndWaitForTransactionResponse,
};
use mpc_node::indexer_canton::{CantonAuthConfig, CantonConfig, parse_canton_signature};
use mpc_node::respond_bidirectional::CANTON_RESPOND_BIDIRECTIONAL_PATH;
use mpc_node::rpc::CantonClient;
use mpc_node::sign_bidirectional::{derive_user_address, sign_and_hash_transaction};
use mpc_node::util::NearPublicKeyExt;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde_json::json;
use serial_test::serial;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use test_log::test;
use url::Url;

const MOCK_ERC20_RUNTIME_BYTECODE: &str = "608060405234801561000f575f80fd5b5060043610610034575f3560e01c806370a0823114610038578063a9059cbb1461006a575b5f80fd5b610057610046366004610138565b5f6020819052908152604090205481565b6040519081526020015b60405180910390f35b61007d610078366004610158565b61008d565b6040519015158152602001610061565b335f908152602081905260408120548211156100d95760405162461bcd60e51b815260206004820152600760248201526662616c616e636560c81b604482015260640160405180910390fd5b335f90815260208190526040808220805485900390556001600160a01b03851682528120805484929061010d908490610180565b9091555060019150505b92915050565b80356001600160a01b0381168114610133575f80fd5b919050565b5f60208284031215610148575f80fd5b6101518261011d565b9392505050565b5f8060408385031215610169575f80fd5b6101728361011d565b946020939093013593505050565b8082018082111561011757634e487b7160e01b5f52601160045260245ffdfea264697066735822122094ff0cc29a3937308067e382ca5094e4c01439ad9a607a527bc03de7ed6fb1ad64736f6c634300081a0033";
const ABI_ENCODED_BOOL_TRUE_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
const EVM_TYPE2_BOOL_OUTPUT_SCHEMA: &str = r#"[{"name":"output","type":"bool"}]"#;
const LIVE_MOCK_ERC20_ADDRESS: &str = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const ERC20_TRANSFER_SELECTOR: &str = "a9059cbb";
const ERC20_BALANCE_OF_SELECTOR: &str = "70a08231";
const LIVE_EVM_CHAIN_ID: u64 = 1;
const MOCK_DEPOSIT_AMOUNT: u64 = 100_000_000;

struct LiveCanton {
    config: CantonConfig,
    client: CantonTestClient,
    party_id: String,
    signer_cid: String,
}

impl LiveCanton {
    async fn from_env() -> Result<Self> {
        anyhow::ensure!(
            std::env::var("MPC_CANTON_LIVE_MUTATE").as_deref() == Ok("1"),
            "set MPC_CANTON_LIVE_MUTATE=1 to run this live, ledger-mutating test"
        );

        let json_api_url = trim_url(required_env("MPC_CANTON_JSON_API_URL")?);
        ensure_remote_ledger_url(&json_api_url)?;
        let json_api_ws_url = match optional_env("MPC_CANTON_JSON_API_WS_URL") {
            Some(value) => trim_url(value),
            None => default_ws_url(&json_api_url)?,
        };
        let ledger_api_user = required_env("MPC_CANTON_LEDGER_API_USER")?;
        let party_id = required_env("MPC_CANTON_PARTY_ID")?;

        let mut config = CantonConfig {
            json_api_url,
            json_api_ws_url,
            auth: CantonAuthConfig {
                token_url: required_env("MPC_CANTON_OIDC_TOKEN_URL")?,
                client_id: required_env("MPC_CANTON_OIDC_CLIENT_ID")?,
                client_secret: required_env("MPC_CANTON_OIDC_CLIENT_SECRET")?,
                audience: required_env("MPC_CANTON_OIDC_AUDIENCE")?,
                scope: optional_env("MPC_CANTON_OIDC_SCOPE"),
            },
            ledger_api_user,
            party_id: party_id.clone(),
            signer_contract_id: String::new(),
            signer_template_id: String::new(),
        };

        let client = CantonTestClient::new(config.clone())
            .await
            .context("create live Canton test client")?;
        let (signer_cid, signer_template_id) = match configured_signer()? {
            Some(signer) => signer,
            None => create_live_signer(&client, &party_id)
                .await
                .context("create live Canton Signer contract")?,
        };
        config.signer_contract_id = signer_cid.clone();
        config.signer_template_id = signer_template_id.clone();
        validate_live_signer(&client, &party_id, &signer_cid, &signer_template_id).await?;

        Ok(Self {
            config,
            client,
            party_id,
            signer_cid,
        })
    }
}

// TODO: Remove this live-ledger test once the local mock-oauth2-server Canton
// sandbox covers the same production-shaped OIDC flow.
#[ignore = "requires live Canton credentials and mutates the configured ledger"]
#[serial]
#[test(tokio::test)]
async fn test_live_canton_mpc_bidirectional_flow() -> Result<()> {
    let live = LiveCanton::from_env().await?;

    run_live_canton_vault_deposit_flow(live)
        .await
        .context("live Canton Vault deposit flow failed")?;

    Ok(())
}

async fn run_live_canton_vault_deposit_flow(live: LiveCanton) -> Result<()> {
    let test_id = live_test_id()?;
    let vault_id = format!("live-vault-{test_id}");
    let deposit_path = format!("deposit-{test_id}");
    let operators = vec![live.party_id.clone()];
    let sender = compute_operators_hash(&operators);

    // Free-mode CC fee: reuse the deployed FeeCollectorRegistration + FeePriceConfig
    // (feeAmount = 0). The signet-fee-amulet charge validates the price config and returns
    // before reading inputs/factory, so empty inputs + the price-config context suffice.
    let fee_registration_cid = required_env("MPC_CANTON_FEE_REGISTRATION_CID")?;
    let fee_price_config_cid = required_env("MPC_CANTON_FEE_PRICE_CONFIG_CID")?;

    let nodes = cluster::spawn()
        .disable_prestockpile()
        .live_canton(live.config.clone())
        .ethereum()
        .await
        .context("spawn MPC cluster with live Canton and Ethereum")?;

    nodes
        .wait()
        .signable()
        .await
        .context("wait for MPC cluster to become signable")?;

    let root_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();

    let eth_ctx = nodes
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum not available")?;
    let anvil_rpc_url = &eth_ctx.sandbox.external_http_endpoint;
    let anvil = ProviderBuilder::new().connect_http(anvil_rpc_url.parse()?);
    anvil.anvil_set_chain_id(LIVE_EVM_CHAIN_ID).await?;
    anvil.anvil_set_auto_mine(false).await?;
    anvil.anvil_set_interval_mining(0).await?;

    let token_address = Address::from_slice(&hex::decode(LIVE_MOCK_ERC20_ADDRESS)?);
    anvil
        .anvil_set_code(
            token_address,
            Bytes::from(hex::decode(MOCK_ERC20_RUNTIME_BYTECODE)?),
        )
        .await?;

    let vault_root_path = format!("{vault_id},root");
    let vault_address = derive_canton_address(root_pk, &sender, &vault_root_path);
    let response_pk = derive_canton_response_public_key(root_pk, &sender);
    let response_spki = secp256k1_spki_hex(response_pk);
    let vault_address_slot = abi_address_slot(vault_address);

    let vault_create = live
        .client
        .create_contract(
            &[&live.party_id],
            "#signet-vault-v1:Erc20Vault:Vault",
            json!({
                "operators": &operators,
                "sigNetwork": &live.party_id,
                "evmVaultAddress": &vault_address_slot,
                "mpcResponseVerifyKey": &response_spki,
                "vaultId": &vault_id,
            }),
        )
        .await
        .context("create live Vault contract")?;
    let (vault_cid, vault_template_id) = find_created_contract(&vault_create, "Vault")?;

    let full_deposit_path = format!("{vault_id},{},{}", live.party_id, deposit_path);
    let user_address = derive_canton_address(root_pk, &sender, &full_deposit_path);
    anvil
        .anvil_set_balance(user_address, U256::from(10_000_000_000_000_000_000u128))
        .await?;

    let deposit_amount = U256::from(MOCK_DEPOSIT_AMOUNT);
    let seeded = anvil
        .anvil_set_storage_at(
            token_address,
            erc20_balance_slot(user_address),
            B256::from(deposit_amount.to_be_bytes()),
        )
        .await?;
    anyhow::ensure!(seeded, "failed to seed mock ERC20 user balance");

    let deposit_params = vault_deposit_evm_params(token_address, vault_address, deposit_amount);
    let deposit_result = live
        .client
        .exercise_choice(
            &[&live.party_id],
            &vault_template_id,
            &vault_cid,
            "RequestDeposit",
            json!({
                "requester": &live.party_id,
                "signerCid": &live.signer_cid,
                "path": deposit_path,
                "evmTxParams": deposit_params.clone(),
                "keyVersion": LATEST_MPC_KEY_VERSION.to_string(),
                "algo": "",
                "dest": "",
                "params": "",
                "outputDeserializationSchema": EVM_TYPE2_BOOL_OUTPUT_SCHEMA,
                "respondSerializationSchema": EVM_TYPE2_BOOL_OUTPUT_SCHEMA,
                "feeRegistrationCid": fee_registration_cid,
                "feeInputs": [],
                "feeExtraArgs": {
                    "context": {
                        "values": {
                            "signet.network/fee/price-config": {
                                "tag": "AV_ContractId",
                                "value": fee_price_config_cid
                            }
                        }
                    },
                    "meta": { "values": {} }
                },
            }),
            &[],
        )
        .await
        .context("exercise Vault.RequestDeposit")?;
    let (pending_deposit_cid, _) = find_created_contract(&deposit_result, "PendingDeposit")?;
    let pending_deposit_payload =
        created_payload(&deposit_result, &pending_deposit_cid).context("PendingDeposit payload")?;
    let request_id = pending_deposit_payload
        .get("requestId")
        .and_then(|v| v.as_str())
        .context("PendingDeposit.requestId")?
        .to_string();
    tracing::info!(
        request_id = %request_id,
        vault_id = %vault_id,
        "live Vault.RequestDeposit submitted"
    );

    let sig_payload: SignatureRespondedEventPayload = live
        .client
        .poll_for_contract(
            &[&live.party_id],
            "#signet-signer-v1:Signer:SignatureRespondedEvent",
            |p: &SignatureRespondedEventPayload| p.request_id == request_id,
            Duration::from_secs(180),
        )
        .await
        .context("timeout waiting for live Vault deposit SignatureRespondedEvent")?;
    tracing::info!(
        request_id = %sig_payload.request_id,
        "received live Vault deposit SignatureRespondedEvent"
    );

    let mpc_signature = parse_canton_signature(&sig_payload.signature)?;
    let y_parity = mpc_signature.recovery_id == 1;
    let r_bytes: [u8; 32] = mpc_crypto::x_coordinate(&mpc_signature.big_r)
        .to_bytes()
        .into();
    let s_bytes: [u8; 32] = mpc_signature.s.to_bytes().into();
    let signed_bytes = encode_signed_eip1559(&deposit_params, y_parity, &r_bytes, &s_bytes)?;
    let unsigned_bytes = TxEip1559::try_from(&deposit_params)?.encoded_for_signing();
    let (watched_tx_hash, _) = sign_and_hash_transaction(&unsigned_bytes, mpc_signature)?;
    let watched_tx_hash = B256::from(watched_tx_hash);

    let pending_tx = anvil.send_raw_transaction(&signed_bytes).await?;
    let tx_hash = *pending_tx.tx_hash();
    assert_eq!(
        tx_hash, watched_tx_hash,
        "MPC watcher tx hash mismatch for live Vault deposit"
    );

    anvil.evm_mine(None).await?;

    let respond_payload: RespondBidirectionalEventPayload = live
        .client
        .poll_for_contract(
            &[&live.party_id],
            "#signet-signer-v1:Signer:RespondBidirectionalEvent",
            |p: &RespondBidirectionalEventPayload| p.request_id == request_id,
            Duration::from_secs(300),
        )
        .await
        .context("timeout waiting for live Vault deposit RespondBidirectionalEvent")?;
    tracing::info!(
        request_id = %respond_payload.request_id,
        "received live Vault deposit RespondBidirectionalEvent"
    );

    let submitted_receipt = anvil
        .get_transaction_receipt(tx_hash)
        .await?
        .context("submitted live Vault deposit receipt not found")?;
    assert!(
        submitted_receipt.status(),
        "submitted live Vault deposit receipt failed; tx_hash={tx_hash:?}"
    );
    assert_eq!(
        respond_payload.serialized_output, ABI_ENCODED_BOOL_TRUE_HEX,
        "expected ABI-encoded bool true output for live Vault deposit"
    );

    let user_balance = erc20_balance_of(&anvil, token_address, user_address).await?;
    let vault_balance = erc20_balance_of(&anvil, token_address, vault_address).await?;
    assert_eq!(
        user_balance,
        U256::ZERO,
        "mock ERC20 user balance should be empty after Vault deposit"
    );
    assert_eq!(
        vault_balance, deposit_amount,
        "mock ERC20 vault balance should equal deposit amount"
    );

    verify_response_signature(root_pk, &sender, &respond_payload)
        .context("verify live Vault deposit response signature")?;

    let ledger_client = CantonClient::new(&live.config).await?;
    let signature_event_cid = find_active_contract_cid(
        &ledger_client,
        &[&live.party_id],
        "#signet-signer-v1:Signer:SignatureRespondedEvent",
        |payload| payload.get("requestId").and_then(|v| v.as_str()) == Some(request_id.as_str()),
    )
    .await?;
    let respond_event_cid = find_active_contract_cid(
        &ledger_client,
        &[&live.party_id],
        "#signet-signer-v1:Signer:RespondBidirectionalEvent",
        |payload| payload.get("requestId").and_then(|v| v.as_str()) == Some(request_id.as_str()),
    )
    .await?;

    let claim_result = live
        .client
        .exercise_choice(
            &[&live.party_id],
            &vault_template_id,
            &vault_cid,
            "ClaimDeposit",
            json!({
                "requester": &live.party_id,
                "pendingDepositCid": pending_deposit_cid,
                "respondBidirectionalEventCid": respond_event_cid,
                "signatureRespondedEventCid": signature_event_cid,
            }),
            &[],
        )
        .await
        .context("exercise Vault.ClaimDeposit")?;
    let (holding_cid, _) = find_created_contract(&claim_result, "Erc20Holding")?;
    let holding_payload = created_payload(&claim_result, &holding_cid)?;
    assert_eq!(
        holding_payload.get("owner").and_then(|v| v.as_str()),
        Some(live.party_id.as_str())
    );
    assert_eq!(
        holding_payload.get("operators"),
        Some(&serde_json::to_value(&operators)?)
    );
    assert_eq!(
        holding_payload.get("erc20Address").and_then(|v| v.as_str()),
        Some(hex::encode(token_address.as_slice()).as_str())
    );
    assert_eq!(
        holding_payload.get("amount").and_then(|v| v.as_str()),
        Some(evm_u256_hex(MOCK_DEPOSIT_AMOUNT as u128).as_str())
    );
    tracing::info!(
        holding_cid = %holding_cid,
        request_id = %request_id,
        "live Vault.ClaimDeposit created Erc20Holding"
    );

    Ok(())
}

fn vault_deposit_evm_params(
    token_address: Address,
    vault_address: Address,
    amount: U256,
) -> EvmType2TransactionParams {
    EvmType2TransactionParams {
        chain_id: evm_u256_hex(LIVE_EVM_CHAIN_ID as u128),
        nonce: evm_u256_hex(0),
        max_priority_fee_per_gas: evm_u256_hex(1_000_000_000),
        max_fee_per_gas: evm_u256_hex(100_000_000_000),
        gas_limit: evm_u256_hex(200_000),
        to: Some(hex::encode(token_address.as_slice())),
        value: evm_u256_hex(0),
        calldata: erc20_transfer_calldata(vault_address, amount),
        access_list: vec![],
    }
}

fn erc20_transfer_calldata(to: Address, amount: U256) -> String {
    format!(
        "{ERC20_TRANSFER_SELECTOR}{}{}",
        abi_address_slot(to),
        hex::encode(amount.to_be_bytes::<32>())
    )
}

fn abi_address_slot(address: Address) -> String {
    format!("{:0>64}", hex::encode(address.as_slice()))
}

fn evm_u256_hex(value: u128) -> String {
    format!("{value:064x}")
}

fn derive_canton_address(root_pk: k256::AffinePoint, sender: &str, path: &str) -> Address {
    let epsilon = mpc_crypto::derive_epsilon_canton(LATEST_MPC_KEY_VERSION, sender, path);
    derive_user_address(root_pk, epsilon)
}

fn derive_canton_response_public_key(
    root_pk: k256::AffinePoint,
    sender: &str,
) -> k256::AffinePoint {
    let epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        sender,
        CANTON_RESPOND_BIDIRECTIONAL_PATH,
    );
    mpc_crypto::derive_key(root_pk, epsilon)
}

fn secp256k1_spki_hex(pk: k256::AffinePoint) -> String {
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let encoded = pk.to_encoded_point(false);
    let raw = &encoded.as_bytes()[1..];
    let mut spki = Vec::with_capacity(88);
    spki.extend_from_slice(&[
        0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
        0x2b, 0x81, 0x04, 0x00, 0x0a, 0x03, 0x42, 0x00, 0x04,
    ]);
    spki.extend_from_slice(raw);
    hex::encode(spki)
}

fn erc20_balance_slot(owner: Address) -> U256 {
    let mut input = [0u8; 64];
    input[12..32].copy_from_slice(owner.as_slice());
    U256::from_be_bytes(*keccak256(input))
}

async fn erc20_balance_of<P>(provider: &P, token: Address, owner: Address) -> Result<U256>
where
    P: Provider,
{
    let calldata = format!("{ERC20_BALANCE_OF_SELECTOR}{}", abi_address_slot(owner));
    let tx = TransactionRequest::default()
        .to(token)
        .input(Bytes::from(hex::decode(calldata)?).into());
    let raw = provider.call(tx).await?;
    Ok(U256::from_be_slice(raw.as_ref()))
}

fn created_payload<'a>(
    response: &'a SubmitAndWaitForTransactionResponse,
    contract_id: &str,
) -> Result<&'a serde_json::Value> {
    response
        .transaction
        .events
        .iter()
        .find_map(|event| match event {
            Event::CreatedEvent(created) if created.contract_id == contract_id => {
                Some(&created.payload)
            }
            _ => None,
        })
        .with_context(|| format!("created payload not found for {contract_id}"))
}

async fn find_active_contract_cid<F>(
    client: &CantonClient,
    parties: &[&str],
    template_id: &str,
    predicate: F,
) -> Result<String>
where
    F: Fn(&serde_json::Value) -> bool,
{
    let entries = client
        .fetch_active_contracts(parties, Some(template_id), false)
        .await?;
    for entry in &entries {
        if let Some(ContractEntry::JsActiveContract(ac)) = &entry.contract_entry {
            if predicate(&ac.created_event.payload) {
                return Ok(ac.created_event.contract_id.clone());
            }
        }
    }
    anyhow::bail!("no active contract for {template_id} matching predicate")
}

fn verify_response_signature(
    root_pk: k256::AffinePoint,
    sender: &str,
    respond_payload: &RespondBidirectionalEventPayload,
) -> Result<()> {
    let respond_signature = parse_canton_signature(&respond_payload.signature)?;
    let response_hash =
        mpc_node::respond_bidirectional::calculate_respond_bidirectional_hash_message(
            &hex::decode(&respond_payload.request_id)?,
            &hex::decode(&respond_payload.serialized_output)?,
        );

    let respond_derived_pk = derive_canton_response_public_key(root_pk, sender);
    let respond_ecdsa = k256::ecdsa::Signature::from_scalars(
        mpc_crypto::x_coordinate(&respond_signature.big_r),
        respond_signature.s,
    )
    .context("invalid signature scalars")?;

    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    let verifying_key = k256::ecdsa::VerifyingKey::from_affine(respond_derived_pk)
        .map_err(|e| anyhow::anyhow!("invalid derived public key: {e}"))?;
    verifying_key
        .verify_prehash(&response_hash, &respond_ecdsa)
        .context("RespondBidirectional signature verification failed")
}

fn encode_signed_eip1559(
    params: &EvmType2TransactionParams,
    y_parity: bool,
    r: &[u8],
    s: &[u8],
) -> Result<Vec<u8>> {
    let signature = Signature::from_scalars_and_parity(
        FixedBytes::from_slice(r),
        FixedBytes::from_slice(s),
        y_parity,
    );

    Ok(TxEip1559::try_from(params)?
        .into_signed(signature)
        .encoded_2718())
}

async fn create_live_signer(client: &CantonTestClient, party_id: &str) -> Result<(String, String)> {
    let signer_result = client
        .create_contract(
            &[party_id],
            "#signet-signer-v1:Signer:Signer",
            json!({ "sigNetwork": party_id }),
        )
        .await?;
    find_created_contract(&signer_result, "Signer")
}

async fn validate_live_signer(
    client: &CantonTestClient,
    party_id: &str,
    signer_cid: &str,
    signer_template_id: &str,
) -> Result<()> {
    let signer = client
        .get_disclosed_contract(&[party_id], "#signet-signer-v1:Signer:Signer", signer_cid)
        .await
        .with_context(|| format!("live Signer contract is not active or visible: {signer_cid}"))?;
    anyhow::ensure!(
        signer.template_id.ends_with(":Signer:Signer")
            && signer_template_id.ends_with(":Signer:Signer"),
        "configured live Signer is not a Signer template: env={signer_template_id}, ledger={}",
        signer.template_id
    );
    Ok(())
}

fn configured_signer() -> Result<Option<(String, String)>> {
    let signer_cid = optional_env("MPC_CANTON_SIGNER_CONTRACT_ID");
    let signer_template_id = optional_env("MPC_CANTON_SIGNER_TEMPLATE_ID");
    match (signer_cid, signer_template_id) {
        (Some(cid), Some(template_id)) => Ok(Some((cid, template_id))),
        (None, None) => Ok(None),
        _ => anyhow::bail!(
            "set both MPC_CANTON_SIGNER_CONTRACT_ID and MPC_CANTON_SIGNER_TEMPLATE_ID, or neither"
        ),
    }
}

fn live_test_id() -> Result<String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string())
}

fn required_env(name: &str) -> Result<String> {
    optional_env(name).with_context(|| format!("{name} must be set"))
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn ensure_remote_ledger_url(url: &str) -> Result<()> {
    let parsed = Url::parse(url).context("invalid MPC_CANTON_JSON_API_URL")?;
    let host = parsed
        .host_str()
        .context("MPC_CANTON_JSON_API_URL must include a host")?;
    anyhow::ensure!(
        host != "localhost",
        "live Canton test must point at a remote ledger, not localhost"
    );
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        anyhow::ensure!(
            !addr.is_loopback(),
            "live Canton test must point at a remote ledger, not loopback"
        );
    }
    Ok(())
}

fn default_ws_url(http_url: &str) -> Result<String> {
    let mut url = Url::parse(http_url).context("invalid MPC_CANTON_JSON_API_URL")?;
    let ws_scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => anyhow::bail!("cannot derive WebSocket URL from {other} URL"),
    };
    url.set_scheme(ws_scheme)
        .map_err(|_| anyhow::anyhow!("failed to set WebSocket URL scheme"))?;
    Ok(trim_url(url.to_string()))
}

fn trim_url(url: String) -> String {
    url.trim_end_matches('/').to_string()
}
