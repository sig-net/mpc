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
    ContractEntry, CreatedEvent, DisclosedContract, Event, SubmitAndWaitForTransactionResponse,
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

// CC signature-fee plumbing (mirrors canton-sig fee.ts / Signet.Fee.Amulet).
const FEE_PRICE_CONFIG_TID: &str = "#signet-fee-amulet:Signet.Fee.Amulet:FeePriceConfig";
const AMULET_TID: &str = "#splice-amulet:Splice.Amulet:Amulet";
const PRICE_CONFIG_CONTEXT_KEY: &str = "signet.network/fee/price-config";
const TRANSFER_FACTORY_CONTEXT_KEY: &str = "signet.network/fee/transfer-factory";
const TRANSFER_FACTORY_REGISTRY_PATH: &str = "/registry/transfer-instruction/v1/transfer-factory";
// Signer package-NAME ref: the MPC indexer subscribes to the Signer package by name (a
// package-id hash is rejected); the disclosure envelope carries the hash form separately.
const SIGNER_TID: &str = "#signet-signer-v1:Signer:Signer";

struct LiveCanton {
    config: CantonConfig,
    client: CantonTestClient,
    party_id: String,
    signer_cid: String,
    // Disclosures sourced from the public endpoint (requester view), passed on RequestDeposit.
    signer_disclosure: DisclosedContract,
    fee_registration_cid: String,
    fee_price_config_cid: String,
    fee_disclosures: Vec<DisclosedContract>,
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

        let disclosure_api_url = required_env("MPC_CANTON_DISCLOSURE_API_URL")?;
        // Source the deployed disclosures the way an external requester does — the
        // sigNetwork-only Signer and the FA-signed fee infra it cannot read from its own ACS.
        let endpoint = fetch_endpoint_disclosures(&disclosure_api_url)
            .await
            .context("fetch deployed disclosures from MPC_CANTON_DISCLOSURE_API_URL")?;
        anyhow::ensure!(
            endpoint.signer.template_id.ends_with(":Signer:Signer"),
            "disclosure API signer is not a Signer template: {}",
            endpoint.signer.template_id
        );
        let signer_cid = endpoint.signer.contract_id.clone();
        let fee_registration_cid = find_fee_cid(&endpoint.fee, ":FeeCollectorRegistration")?;
        let fee_price_config_cid = find_fee_cid(&endpoint.fee, ":FeePriceConfig")?;

        let config = CantonConfig {
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
            signer_contract_id: signer_cid.clone(),
            // Name ref for the indexer subscription; the disclosure's hash templateId is used
            // only for the disclosed contract on RequestDeposit.
            signer_template_id: SIGNER_TID.to_string(),
        };

        let client = CantonTestClient::new(config.clone())
            .await
            .context("create live Canton test client")?;

        Ok(Self {
            config,
            client,
            party_id,
            signer_cid,
            signer_disclosure: endpoint.signer,
            fee_registration_cid,
            fee_price_config_cid,
            fee_disclosures: endpoint.fee,
        })
    }
}

/// The subset of the disclosure-API response (`{ network, signer, vault, fee }`) the test
/// needs: the Signer envelope and the FA-signed fee infra disclosures.
struct EndpointDisclosures {
    signer: DisclosedContract,
    fee: Vec<DisclosedContract>,
}

/// GET the deployed apps/disclosure-api endpoint the way a requester does — it serves the
/// ledger-public disclosure envelopes (no auth).
async fn fetch_endpoint_disclosures(url: &str) -> Result<EndpointDisclosures> {
    let body: serde_json::Value = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?
        .error_for_status()
        .with_context(|| format!("disclosure API {url}"))?
        .json()
        .await
        .context("parse disclosure API response")?;
    let signer: DisclosedContract = body
        .get("signer")
        .cloned()
        .context("disclosure API response missing signer")
        .and_then(|v| serde_json::from_value(v).context("parse signer disclosure"))?;
    anyhow::ensure!(
        !signer.created_event_blob.is_empty(),
        "disclosure API signer has no createdEventBlob"
    );
    let fee: Vec<DisclosedContract> = body
        .get("fee")
        .map(|f| serde_json::from_value(f.clone()))
        .transpose()
        .context("parse fee disclosures")?
        .unwrap_or_default();
    Ok(EndpointDisclosures { signer, fee })
}

/// The contract id of the fee disclosure whose template id ends with `suffix`.
fn find_fee_cid(fee: &[DisclosedContract], suffix: &str) -> Result<String> {
    fee.iter()
        .find(|d| d.template_id.ends_with(suffix))
        .map(|d| d.contract_id.clone())
        .with_context(|| format!("disclosure API fee[] missing a {suffix} entry"))
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

    // CC signature fee. The fee infra (registration + price config) is sourced from the
    // disclosure endpoint (live.fee_*); prepare_fee_inputs reads the FeePriceConfig and picks
    // the mode: free (feeAmount = 0) → empty inputs + price-config-only context; paid
    // (feeAmount > 0) → cover the fee from Amulet holdings and resolve the CC TransferFactory
    // + disclosures from the token-standard registry (MPC_CANTON_CC_REGISTRY_URL).
    let fee_registry_url = optional_env("MPC_CANTON_CC_REGISTRY_URL");

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

    // Resolve the CC fee just before RequestDeposit so the registry's open mining round
    // (a per-submission disclosure that rotates) is fresh at charge time.
    let ledger_client = CantonClient::new(&live.config).await?;
    let fee = prepare_fee_inputs(
        &ledger_client,
        &live.party_id,
        &live.fee_price_config_cid,
        fee_registry_url.as_deref(),
    )
    .await
    .context("prepare CC fee inputs")?;

    // Requester-view disclosures: the endpoint-sourced Signer + FA-signed fee infra (which a
    // requester can't read from its own ACS), plus the registry's CC contracts resolved above.
    let mut request_disclosures = vec![live.signer_disclosure.clone()];
    request_disclosures.extend(live.fee_disclosures.iter().cloned());
    request_disclosures.extend(fee.disclosures.iter().cloned());
    tracing::info!(
        fee_inputs = fee.inputs.len(),
        disclosures = request_disclosures.len(),
        "prepared requester-view CC fee inputs for live Vault.RequestDeposit"
    );

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
                "feeRegistrationCid": live.fee_registration_cid.clone(),
                "feeInputs": fee.inputs.clone(),
                "feeExtraArgs": fee.extra_args.clone(),
            }),
            &request_disclosures,
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

/// The CC fee inputs threaded into `Vault.RequestDeposit`.
struct FeeInputs {
    inputs: Vec<String>,
    extra_args: serde_json::Value,
    disclosures: Vec<DisclosedContract>,
}

/// Assemble the CC signature-fee inputs for the configured `FeePriceConfig`.
///
/// Mirrors `canton-sig`'s `prepareFeeInputs`: free mode (feeAmount = 0) returns empty
/// inputs and a price-config-only context (the `signet-fee-amulet` charge returns before
/// reading inputs/factory); paid mode (feeAmount > 0) covers the fee from the party's
/// Amulet holdings and resolves the CC `TransferFactory` + disclosures from the
/// token-standard registry, then folds them into the opaque `feeExtraArgs` context.
async fn prepare_fee_inputs(
    ledger: &CantonClient,
    party: &str,
    fee_price_config_cid: &str,
    registry_url: Option<&str>,
) -> Result<FeeInputs> {
    let cfg = fetch_price_config(ledger, party, fee_price_config_cid).await?;

    let mut context = serde_json::Map::new();
    context.insert(
        PRICE_CONFIG_CONTEXT_KEY.to_string(),
        json!({ "tag": "AV_ContractId", "value": fee_price_config_cid }),
    );

    let fee_amount: f64 = cfg.fee_amount.parse().context("parse FeePriceConfig.feeAmount")?;
    if fee_amount <= 0.0 {
        return Ok(FeeInputs {
            inputs: vec![],
            extra_args: json!({ "context": { "values": context }, "meta": { "values": {} } }),
            disclosures: vec![],
        });
    }

    // Paid mode.
    let registry_url =
        registry_url.context("paid fee (feeAmount > 0) requires MPC_CANTON_CC_REGISTRY_URL")?;
    let inputs = fetch_amulet_holdings(ledger, party).await?;
    anyhow::ensure!(
        !inputs.is_empty(),
        "no Amulet holdings to cover the {} CC fee for {party}",
        cfg.fee_amount
    );
    let token = ledger.bearer_token().await?;
    let factory = resolve_transfer_factory(registry_url, &token, party, &cfg, &inputs).await?;

    // Merge the price-config key, the registry's context keys (AmuletRules / OpenMiningRound),
    // and the transfer-factory key — exactly what `feeCollector_chargeImpl` reads.
    if let Some(obj) = factory.context_values.as_object() {
        for (k, v) in obj {
            context.insert(k.clone(), v.clone());
        }
    }
    context.insert(
        TRANSFER_FACTORY_CONTEXT_KEY.to_string(),
        json!({ "tag": "AV_ContractId", "value": factory.factory_id }),
    );

    Ok(FeeInputs {
        inputs,
        extra_args: json!({ "context": { "values": context }, "meta": { "values": {} } }),
        disclosures: factory.disclosures,
    })
}

/// The active `CreatedEvent`s for a template visible to `parties` — the shape every live
/// query here reduces to.
async fn active_events(
    ledger: &CantonClient,
    parties: &[&str],
    template_id: &str,
) -> Result<Vec<CreatedEvent>> {
    Ok(ledger
        .fetch_active_contracts(parties, Some(template_id), false)
        .await?
        .into_iter()
        .filter_map(|entry| match entry.contract_entry {
            Some(ContractEntry::JsActiveContract(ac)) => Some(ac.created_event),
            _ => None,
        })
        .collect())
}

struct PriceConfig {
    fee_amount: String,
    instrument_admin: String,
    instrument_id: String,
    fee_receiver: String,
}

async fn fetch_price_config(ledger: &CantonClient, party: &str, cid: &str) -> Result<PriceConfig> {
    let event = active_events(ledger, &[party], FEE_PRICE_CONFIG_TID)
        .await?
        .into_iter()
        .find(|ce| ce.contract_id == cid)
        .with_context(|| format!("FeePriceConfig {cid} not active or visible to {party}"))?;
    let field = |k: &str| -> Result<String> {
        event
            .payload
            .get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .with_context(|| format!("FeePriceConfig.{k}"))
    };
    Ok(PriceConfig {
        fee_amount: field("feeAmount")?,
        instrument_admin: field("instrumentAdmin")?,
        instrument_id: field("instrumentId")?,
        fee_receiver: field("feeReceiver")?,
    })
}

/// All the party's Amulet holding cids — the inputs for the CC fee transfer. The Amulet
/// template excludes locked holdings (those are `LockedAmulet`), so all are spendable; the
/// transfer consumes only what the fee needs and returns the rest as change.
async fn fetch_amulet_holdings(ledger: &CantonClient, party: &str) -> Result<Vec<String>> {
    Ok(active_events(ledger, &[party], AMULET_TID)
        .await?
        .into_iter()
        .map(|ce| ce.contract_id)
        .collect())
}

struct ResolvedFactory {
    factory_id: String,
    context_values: serde_json::Value,
    disclosures: Vec<DisclosedContract>,
}

/// Resolve the CC `TransferFactory` for the fee transfer via the token-standard registry
/// (the validator scan-proxy, authed with the ledger bearer). Mirrors canton-sig's
/// `getTransferFactoryForFee` request/response shape.
async fn resolve_transfer_factory(
    registry_url: &str,
    token: &str,
    party: &str,
    cfg: &PriceConfig,
    inputs: &[String],
) -> Result<ResolvedFactory> {
    let now = chrono::Utc::now();
    let requested_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let execute_before =
        (now + chrono::Duration::hours(24)).to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let body = json!({
        "choiceArguments": {
            "expectedAdmin": cfg.instrument_admin,
            "transfer": {
                "sender": party,
                "receiver": cfg.fee_receiver,
                "amount": cfg.fee_amount,
                "instrumentId": { "admin": cfg.instrument_admin, "id": cfg.instrument_id },
                "lock": null,
                "requestedAt": requested_at,
                "executeBefore": execute_before,
                "inputHoldingCids": inputs,
                "meta": { "values": { "splice.lfdecentralizedtrust.org/reason": "sigNetwork CC signature fee" } }
            },
            "extraArgs": { "context": { "values": {} }, "meta": { "values": {} } }
        },
        "excludeDebugFields": true
    });

    let url = format!("{registry_url}{TRANSFER_FACTORY_REGISTRY_PATH}");
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    anyhow::ensure!(status.is_success(), "registry {url} returned {status}: {text}");

    let parsed: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parse registry response: {text}"))?;
    let factory_id = parsed
        .get("factoryId")
        .and_then(|v| v.as_str())
        .context("registry response missing factoryId")?
        .to_string();
    let choice_context = parsed
        .get("choiceContext")
        .context("registry response missing choiceContext")?;
    let context_values = choice_context
        .get("choiceContextData")
        .and_then(|d| d.get("values"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let disclosures: Vec<DisclosedContract> = choice_context
        .get("disclosedContracts")
        .map(|d| serde_json::from_value(d.clone()))
        .transpose()
        .context("parse registry disclosedContracts")?
        .unwrap_or_default();

    Ok(ResolvedFactory {
        factory_id,
        context_values,
        disclosures,
    })
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
    active_events(client, parties, template_id)
        .await?
        .into_iter()
        .find(|ce| predicate(&ce.payload))
        .map(|ce| ce.contract_id)
        .with_context(|| format!("no active contract for {template_id} matching predicate"))
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
