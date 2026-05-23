use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Address, Bytes, FixedBytes, Signature, B256, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context as _, Result};
use integration_tests::canton::{
    compute_operators_hash, find_created_contract, test_evm_type2_anvil_cases,
    test_sign_request_payload, CantonTestClient, EvmType2AnvilCase,
    EVM_TYPE2_TEST_CONTRACT_ADDRESS,
};
use integration_tests::cluster;
use mpc_node::indexer_canton::contracts::{
    EvmType2TransactionParams, RespondBidirectionalEventPayload, SignBidirectionalRequestedEvent,
    SignatureRespondedEventPayload, TxParams,
};
use mpc_node::indexer_canton::{
    compute_request_id, parse_canton_signature, CantonAuthConfig, CantonConfig,
};
use mpc_node::protocol::Chain;
use mpc_node::respond_bidirectional::CANTON_RESPOND_BIDIRECTIONAL_PATH;
use mpc_node::sign_bidirectional::{derive_user_address, sign_and_hash_transaction};
use mpc_node::util::NearPublicKeyExt;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde_json::json;
use serial_test::serial;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use test_log::test;
use url::Url;

const RETURN_TRUE_RUNTIME_BYTECODE: &str = "600160005260206000f3";
const ABI_ENCODED_BOOL_TRUE_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
const EVM_TYPE2_BOOL_OUTPUT_SCHEMA: &str = r#"[{"name":"output","type":"bool"}]"#;

struct LiveCanton {
    config: CantonConfig,
    client: CantonTestClient,
    party_id: String,
    signer_cid: String,
    signer_template_id: String,
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
            signer_template_id,
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
    let case = test_evm_type2_anvil_cases()[0].clone().with_nonce(0);

    run_live_canton_eth_bidirectional_flow_case(live, case)
        .await
        .context("live Canton Ethereum bidirectional flow failed")?;

    Ok(())
}

async fn run_live_canton_eth_bidirectional_flow_case(
    live: LiveCanton,
    case: EvmType2AnvilCase,
) -> Result<()> {
    let case_name = case.name;
    let path = live_test_path(&live.party_id)?;
    let expected_event = live_test_sign_request_event(&live, &case, path);
    let expected_request_id = hex::encode(compute_request_id(&expected_event)?);

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
    anvil.anvil_set_auto_mine(false).await?;
    anvil.anvil_set_interval_mining(0).await?;

    let contract_call_address = Address::from_slice(&hex::decode(EVM_TYPE2_TEST_CONTRACT_ADDRESS)?);
    anvil
        .anvil_set_code(
            contract_call_address,
            Bytes::from(hex::decode(RETURN_TRUE_RUNTIME_BYTECODE)?),
        )
        .await?;

    let evm_params = case.params.clone();

    let sign_request = live
        .client
        .create_contract(
            &[&live.party_id],
            "#daml-signer:Signer:SignRequest",
            serde_json::to_value(test_sign_request_payload(&expected_event))?,
        )
        .await?;
    let (sign_request_cid, _) = find_created_contract(&sign_request, "SignRequest")?;

    live.client
        .exercise_choice(
            &[&live.party_id],
            &live.signer_template_id,
            &live.signer_cid,
            "SignBidirectional",
            json!({
                "signRequestCid": sign_request_cid,
                "requester": &live.party_id,
            }),
            &[],
        )
        .await?;
    tracing::info!(case_name, "live canton sign request submitted via Signer");

    let sig_payload: SignatureRespondedEventPayload = live
        .client
        .poll_for_contract(
            &[&live.party_id],
            "#daml-signer:Signer:SignatureRespondedEvent",
            |p: &SignatureRespondedEventPayload| p.request_id == expected_request_id,
            Duration::from_secs(180),
        )
        .await
        .with_context(|| {
            format!("timeout waiting for live SignatureRespondedEvent ({case_name})")
        })?;
    tracing::info!(
        case_name,
        request_id = %sig_payload.request_id,
        "received live SignatureRespondedEvent"
    );

    let mpc_signature = parse_canton_signature(&sig_payload.signature)?;
    let sign_epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        &expected_event.sender,
        &expected_event.path,
    );
    let expected_sender_addr = derive_user_address(root_pk, sign_epsilon);

    anvil
        .anvil_set_balance(
            expected_sender_addr,
            U256::from(10_000_000_000_000_000_000u128),
        )
        .await?;

    let y_parity = mpc_signature.recovery_id == 1;
    let r_bytes: [u8; 32] = mpc_crypto::x_coordinate(&mpc_signature.big_r)
        .to_bytes()
        .into();
    let s_bytes: [u8; 32] = mpc_signature.s.to_bytes().into();
    let signed_bytes = encode_signed_eip1559(&evm_params, y_parity, &r_bytes, &s_bytes)?;
    let unsigned_bytes = TxEip1559::try_from(&evm_params)?.encoded_for_signing();
    let (watched_tx_hash, _) = sign_and_hash_transaction(&unsigned_bytes, mpc_signature)?;
    let watched_tx_hash = B256::from(watched_tx_hash);

    let pending_tx = anvil.send_raw_transaction(&signed_bytes).await?;
    let tx_hash = *pending_tx.tx_hash();
    assert_eq!(
        tx_hash, watched_tx_hash,
        "MPC watcher tx hash mismatch ({case_name})"
    );

    anvil.evm_mine(None).await?;

    let respond_payload = live
        .client
        .poll_for_contract(
            &[&live.party_id],
            "#daml-signer:Signer:RespondBidirectionalEvent",
            |p: &RespondBidirectionalEventPayload| p.request_id == expected_request_id,
            Duration::from_secs(300),
        )
        .await
        .with_context(|| {
            format!("timeout waiting for live RespondBidirectionalEvent ({case_name})")
        })?;
    tracing::info!(
        case_name,
        request_id = %respond_payload.request_id,
        "received live RespondBidirectionalEvent"
    );

    let submitted_receipt = anvil
        .get_transaction_receipt(tx_hash)
        .await?
        .with_context(|| format!("submitted Anvil receipt not found ({case_name})"))?;
    assert!(
        submitted_receipt.status(),
        "submitted Anvil receipt failed ({case_name}); tx_hash={tx_hash:?}"
    );

    assert_eq!(
        respond_payload.serialized_output, ABI_ENCODED_BOOL_TRUE_HEX,
        "expected ABI-encoded bool true output ({case_name})"
    );

    let respond_signature = parse_canton_signature(&respond_payload.signature)?;
    let response_hash =
        mpc_node::respond_bidirectional::calculate_respond_bidirectional_hash_message(
            &hex::decode(&respond_payload.request_id)?,
            &hex::decode(&respond_payload.serialized_output)?,
        );

    let respond_epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        &expected_event.sender,
        CANTON_RESPOND_BIDIRECTIONAL_PATH,
    );
    let respond_derived_pk = mpc_crypto::derive_key(root_pk, respond_epsilon);

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
        .with_context(|| {
            format!("live RespondBidirectional signature verification failed ({case_name})")
        })?;

    Ok(())
}

fn live_test_sign_request_event(
    live: &LiveCanton,
    case: &EvmType2AnvilCase,
    path: String,
) -> SignBidirectionalRequestedEvent {
    let operators = vec![live.party_id.clone()];
    let sender = compute_operators_hash(&operators);

    // The dev credentials authorize one party. Reusing it for sigNetwork,
    // operator, and requester keeps this live test focused on the external
    // ledger/MPC handshake; the local sandbox test covers cross-party disclosure.
    SignBidirectionalRequestedEvent {
        operators,
        requester: live.party_id.clone(),
        sig_network: live.party_id.clone(),
        sender,
        tx_params: TxParams::EvmType2TxParams(case.params.clone()),
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        path,
        algo: String::new(),
        dest: String::new(),
        params: String::new(),
        output_deserialization_schema: EVM_TYPE2_BOOL_OUTPUT_SCHEMA.to_string(),
        respond_serialization_schema: EVM_TYPE2_BOOL_OUTPUT_SCHEMA.to_string(),
    }
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
            "#daml-signer:Signer:Signer",
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
        .get_disclosed_contract(&[party_id], "#daml-signer:Signer:Signer", signer_cid)
        .await
        .with_context(|| format!("live Signer contract is not active or visible: {signer_cid}"))?;
    anyhow::ensure!(
        signer.template_id == signer_template_id,
        "configured live Signer template mismatch: env has {signer_template_id}, ledger has {}",
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

fn live_test_path(party_id: &str) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok(format!("{party_id}:live-canton-mpc:{now}"))
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
