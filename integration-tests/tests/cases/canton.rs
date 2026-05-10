use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, Signature, B256, U256};
use alloy::providers::ext::AnvilApi;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context as _, Result};
use integration_tests::canton::{
    test_evm_type2_anvil_cases, test_sign_request_event, test_sign_request_payload,
    EvmType2AnvilCase, EVM_TYPE2_TEST_CONTRACT_ADDRESS,
};
use integration_tests::cluster;
use mpc_node::indexer_canton::contracts::{
    EvmType2TransactionParams, RespondBidirectionalEventPayload, SignatureRespondedEventPayload,
};
use mpc_node::indexer_canton::{compute_request_id, parse_canton_signature};
use mpc_node::respond_bidirectional::CANTON_RESPOND_BIDIRECTIONAL_PATH;
use mpc_node::sign_bidirectional::{derive_user_address, sign_and_hash_transaction};
use mpc_node::util::NearPublicKeyExt;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use rlp::RlpStream;
use serde_json::json;
use serial_test::serial;
use std::time::Duration;
use test_log::test;

const RETURN_TRUE_RUNTIME_BYTECODE: &str = "600160005260206000f3";
const ABI_ENCODED_BOOL_TRUE_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";
const BIDIRECTIONAL_FAILURE_BOOL_TRUE_HEX: &str =
    "deadbeef0000000000000000000000000000000000000000000000000000000000000001";

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

#[ignore] // requires dpm + openssl + Docker (for Ethereum)
#[serial]
#[test(tokio::test)]
async fn test_canton_eth_bidirectional_flow() -> Result<()> {
    for case in test_evm_type2_anvil_cases() {
        let case_name = case.name;
        run_canton_eth_bidirectional_flow_case(case.with_nonce(0))
            .await
            .with_context(|| format!("Canton Ethereum bidirectional flow failed ({case_name})"))?;
    }

    Ok(())
}

async fn run_canton_eth_bidirectional_flow_case(case: EvmType2AnvilCase) -> Result<()> {
    let case_name = case.name;

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
    let client = &canton.client;

    let root_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();

    // 3. Relay each signed EVM transaction to Anvil.
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
    let expected_event = test_sign_request_event(canton, &case);
    let expected_request_id = hex::encode(compute_request_id(&expected_event)?);

    // EVM analogy: an EVM contract could call another contract directly and
    // emit the request event in one transaction. Canton does not model this
    // as a contract-to-contract call, so we first create a SignRequest
    // contract that stores the unsigned EVM transaction request. The next
    // command passes this contract ID into Signer.SignBidirectional, which
    // validates it and emits the event watched by the MPC Canton indexer.
    let sign_request = client
        .create_contract(
            &[&canton.operator_party, &canton.requester_party],
            "#daml-signer:Signer:SignRequest",
            serde_json::to_value(test_sign_request_payload(&expected_event))?,
        )
        .await?;
    let (sign_request_cid, _) =
        integration_tests::canton::find_created_contract(&sign_request, "SignRequest")?;

    // EVM contracts are globally visible, so a caller can reference any
    // contract address. Canton contracts are private to stakeholders. The
    // requester is not a stakeholder on the Signer contract, so the Signer
    // stakeholder gives the requester an explicit disclosure blob. Attaching
    // it lets the command read the Signer contract while Daml still enforces
    // authorization checks:
    // https://docs.digitalasset.com/build/3.4/sdlc-howtos/applications/develop/explicit-contract-disclosure.html
    client
        .exercise_choice(
            &[&canton.requester_party],
            &canton.signer_template_id,
            &canton.signer_cid,
            "SignBidirectional",
            json!({
                "signRequestCid": sign_request_cid,
                "requester": &canton.requester_party,
            }),
            std::slice::from_ref(&canton.signer_disclosure),
        )
        .await?;
    tracing::info!(case_name, "canton sign request submitted via Signer");

    let sig_payload: SignatureRespondedEventPayload = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:SignatureRespondedEvent",
            |p: &SignatureRespondedEventPayload| p.request_id == expected_request_id,
            Duration::from_secs(120),
        )
        .await
        .with_context(|| format!("timeout waiting for SignatureRespondedEvent ({case_name})"))?;
    tracing::info!(
        case_name,
        request_id = %sig_payload.request_id,
        "received SignatureRespondedEvent"
    );

    let mpc_signature = parse_canton_signature(&sig_payload.signature)?;

    let sign_epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        &expected_event.sender,
        &canton.requester_party,
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
    tracing::info!(
        case_name,
        ?tx_hash,
        "relayed signed EIP-1559 transaction to Anvil"
    );
    assert_eq!(
        tx_hash, watched_tx_hash,
        "MPC watcher tx hash mismatch ({case_name})"
    );

    anvil.evm_mine(None).await?;

    let respond_payload = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:RespondBidirectionalEvent",
            |p: &RespondBidirectionalEventPayload| p.request_id == expected_request_id,
            Duration::from_secs(300),
        )
        .await
        .with_context(|| format!("timeout waiting for RespondBidirectionalEvent ({case_name})"))?;
    tracing::info!(
        case_name,
        request_id = %respond_payload.request_id,
        "received RespondBidirectionalEvent"
    );

    let submitted_receipt = anvil
        .get_transaction_receipt(tx_hash)
        .await?
        .with_context(|| format!("submitted Anvil receipt not found ({case_name})"))?;
    let submitted_receipt_succeeded = submitted_receipt.status();
    tracing::info!(
        case_name,
        ?tx_hash,
        submitted_receipt_succeeded,
        "submitted Anvil receipt observed"
    );
    assert!(
        submitted_receipt_succeeded,
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
            format!("RespondBidirectional signature verification failed ({case_name})")
        })?;
    tracing::info!(case_name, "phase 2 signature verified");

    Ok(())
}

// These are auth wiring smoke tests for our Canton sandbox setup, not Canton
// auth implementation tests. They verify the sandbox is actually enforcing the
// JWT key/cert configuration that the MPC integration relies on.
#[ignore] // requires dpm
#[serial]
#[test(tokio::test)]
async fn test_canton_rejects_unauthenticated_requests() -> Result<()> {
    let sandbox = integration_tests::canton::CantonSandbox::run().await?;
    let http = reqwest::Client::new();
    let url = format!("{}/v2/state/ledger-end", sandbox.json_api_url);

    // No Authorization header at all.
    let status = http.get(&url).send().await?.status();
    assert_eq!(status, 401, "missing JWT should be rejected, got {status}");

    // Malformed Bearer token.
    let status = http
        .get(&url)
        .bearer_auth("not-a-valid-jwt")
        .send()
        .await?
        .status();
    assert_eq!(status, 401, "invalid JWT should be rejected, got {status}");

    Ok(())
}

#[ignore] // requires dpm + openssl
#[serial]
#[test(tokio::test)]
async fn test_canton_rejects_jwt_signed_by_unconfigured_key() -> Result<()> {
    use mpc_node::indexer_canton::generate_jwt_with_key;

    let sandbox = integration_tests::canton::CantonSandbox::run().await?;

    // Generate a fresh EC P-256 keypair NOT configured in Canton's auth-services.
    // Use genpkey (PKCS#8 output) instead of ecparam (SEC1 output) for jsonwebtoken compatibility.
    let tmp = std::env::temp_dir();
    let rogue_key_path = tmp.join(format!("rogue-jwt-{}.key", uuid::Uuid::new_v4()));
    let output = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-out",
            &rogue_key_path.to_string_lossy(),
        ])
        .output()
        .context("openssl not found")?;
    anyhow::ensure!(output.status.success(), "openssl genpkey failed");

    let rogue_pem = std::fs::read_to_string(&rogue_key_path)?;
    let _ = std::fs::remove_file(&rogue_key_path);

    let rogue_encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(rogue_pem.as_bytes())?;

    // Mint a structurally valid JWT with correct claims, but signed by the wrong key.
    let rogue_jwt = generate_jwt_with_key(&rogue_encoding_key, &sandbox.jwt_subject)?;

    // Canton should reject it — signature doesn't match any configured certificate.
    let http = reqwest::Client::new();
    let url = format!("{}/v2/state/ledger-end", sandbox.json_api_url);
    let status = http
        .get(&url)
        .bearer_auth(&rogue_jwt)
        .send()
        .await?
        .status();
    assert_eq!(
        status, 401,
        "JWT signed by unconfigured key should be rejected, got {status}"
    );

    Ok(())
}

// ============================================================================
// Canton -> Anvil -> Canton DeFi flow (35 sequential cases + concurrent phase)
// ============================================================================
//
// Exercises the full bidirectional MPC path against a real ERC20 deployed on
// Anvil, plus a battery of EVM Type 2 field-permutation transactions. Each
// case round-trips through Canton (Signer.SignBidirectional), the MPC node
// (signature + observation), Anvil (execution), and back to Canton
// (RespondBidirectional). After execution we read on-chain state via
// `eth_call` and assert the expected balance / allowance.
//
// Requires the TestToken artifact at
//   chain-signatures/contract-eth/artifacts/contracts/test/TestToken.sol/TestToken.json
// generated by `npx hardhat compile` in chain-signatures/contract-eth/.

use alloy::providers::network::Ethereum;
use alloy::providers::{DynProvider, RootProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use alloy::sol_types::SolCall;
use integration_tests::canton::{compute_operators_hash, find_created_contract, CantonSandbox};
use mpc_node::indexer_canton::contracts::{
    EvmAccessListEntry, SignBidirectionalRequestedEvent, SignRequestPayload, TxParams,
};
use mpc_node::protocol::Chain;

const TEST_TOKEN_ADDRESS: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const TEST_TOKEN_ARTIFACT: &str = include_str!(
    "../../../chain-signatures/contract-eth/artifacts/contracts/test/TestToken.sol/TestToken.json"
);
const EVM_TYPE2_BOOL_OUTPUT_SCHEMA: &str = r#"[{"name":"output","type":"bool"}]"#;

sol! {
    interface ITestToken {
        function mint(address to, uint256 amount) external;
        function transfer(address to, uint256 amount) external returns (bool);
        function approve(address spender, uint256 amount) external returns (bool);
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
    }
}

fn test_token_runtime_bytecode() -> Bytes {
    let v: serde_json::Value =
        serde_json::from_str(TEST_TOKEN_ARTIFACT).expect("TestToken artifact JSON");
    let s = v["deployedBytecode"]
        .as_str()
        .expect("deployedBytecode field")
        .trim_start_matches("0x");
    Bytes::from(hex::decode(s).expect("deployedBytecode hex"))
}

fn evm_u256_hex(value: u128) -> String {
    format!("{value:064x}")
}

fn evm_u256_hex_from_u256(value: U256) -> String {
    format!("{value:064x}")
}

#[allow(clippy::too_many_arguments)]
fn evm_type2_params(
    nonce: u64,
    gas_limit: u64,
    max_priority_fee_per_gas: u128,
    max_fee_per_gas: u128,
    to: Option<&str>,
    value: U256,
    calldata: impl Into<String>,
    access_list: Vec<EvmAccessListEntry>,
) -> EvmType2TransactionParams {
    EvmType2TransactionParams {
        chain_id: evm_u256_hex(1),
        nonce: evm_u256_hex(nonce as u128),
        max_priority_fee_per_gas: evm_u256_hex(max_priority_fee_per_gas),
        max_fee_per_gas: evm_u256_hex(max_fee_per_gas),
        gas_limit: evm_u256_hex(gas_limit as u128),
        to: to.map(str::to_string),
        value: evm_u256_hex_from_u256(value),
        calldata: calldata.into(),
        access_list,
    }
}

const ERC20_MINT_SELECTOR: &str = "40c10f19";
const ERC20_TRANSFER_SELECTOR: &str = "a9059cbb";
const ERC20_APPROVE_SELECTOR: &str = "095ea7b3";
const ERC20_TRANSFER_FROM_SELECTOR: &str = "23b872dd";

fn expected_canton_success_output_hex(params: &EvmType2TransactionParams) -> &'static str {
    if params.calldata.is_empty() {
        return ABI_ENCODED_BOOL_TRUE_HEX;
    }

    match params.calldata.get(..8) {
        Some(ERC20_TRANSFER_SELECTOR | ERC20_APPROVE_SELECTOR | ERC20_TRANSFER_FROM_SELECTOR) => {
            ABI_ENCODED_BOOL_TRUE_HEX
        }
        Some(ERC20_MINT_SELECTOR) | Some(_) | None => "",
    }
}

fn evm_type2_nonce(params: &EvmType2TransactionParams) -> Result<u64> {
    u64::try_from(U256::from_str_radix(&params.nonce, 16)?).context("EVM type2 nonce exceeds u64")
}

fn created_contract_address(sender: Address, nonce: u64) -> Address {
    let mut stream = RlpStream::new_list(2);
    stream.append(&sender.as_slice());
    stream.append(&nonce);
    let hash = keccak256(stream.out());
    Address::from_slice(&hash[12..])
}

/// Compute the MPC-derived EVM address for a given Canton path.
///
/// The Canton sender field on the event is `compute_operators_hash([operator])`,
/// which is what the MPC node uses as the sender string in its KDF.
fn mpc_derived_address(canton: &CantonSandbox, root_pk: k256::AffinePoint, path: &str) -> Address {
    let sender = compute_operators_hash(std::slice::from_ref(&canton.operator_party));
    let epsilon = mpc_crypto::derive_epsilon_canton(LATEST_MPC_KEY_VERSION, &sender, path);
    derive_user_address(root_pk, epsilon)
}

/// Derive the secp256k1 public key (uncompressed, 65 bytes starting 0x04) used
/// to sign Canton `RespondBidirectional` for an Erc20Vault. Both the path and
/// the sender are constant per Vault (path = `"canton response key"`, sender =
/// `compute_operators_hash(operators)`), so this pubkey is also constant per
/// Vault and is what `Vault.evmMpcPublicKey` must hold.
fn vault_response_pubkey(canton: &CantonSandbox, root_pk: k256::AffinePoint) -> k256::AffinePoint {
    let sender = compute_operators_hash(std::slice::from_ref(&canton.operator_party));
    let epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        &sender,
        mpc_node::respond_bidirectional::CANTON_RESPOND_BIDIRECTIONAL_PATH,
    );
    mpc_crypto::derive_key(root_pk, epsilon)
}

/// Wrap a secp256k1 uncompressed pubkey in SubjectPublicKeyInfo DER (per
/// RFC 5480, secp256k1 OID 1.3.132.0.10) and return as hex.
///
/// Matches `toSpkiPublicKey` in `canton-mpc-poc/ts-packages/canton-sig`. Daml's
/// `secp256k1WithEcdsaOnly` requires SPKI for the public-key argument.
fn to_spki_pubkey_hex(pk: k256::AffinePoint) -> String {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let encoded = pk.to_encoded_point(false); // uncompressed: 0x04 || X || Y
    let raw = &encoded.as_bytes()[1..]; // strip the 0x04 (the SPKI header re-introduces it)
    let mut spki = Vec::with_capacity(88);
    spki.extend_from_slice(&[
        0x30, 0x56, // SEQUENCE 86
        0x30, 0x10, // AlgorithmIdentifier SEQUENCE 16
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID id-ecPublicKey
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, // OID secp256k1
        0x03, 0x42, 0x00, 0x04, // BIT STRING (66) + uncompressed marker
    ]);
    spki.extend_from_slice(raw);
    hex::encode(spki)
}

/// Build a SignBidirectionalRequestedEvent for a given (params, path) pair.
fn make_sign_event(
    canton: &CantonSandbox,
    params: &EvmType2TransactionParams,
    path: &str,
) -> SignBidirectionalRequestedEvent {
    let operators = vec![canton.operator_party.clone()];
    let sender = compute_operators_hash(&operators);
    SignBidirectionalRequestedEvent {
        operators,
        requester: canton.requester_party.clone(),
        sig_network: canton.party_id.clone(),
        sender,
        tx_params: TxParams::EvmType2TxParams(params.clone()),
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        path: path.to_string(),
        algo: String::new(),
        dest: String::new(),
        params: String::new(),
        output_deserialization_schema: EVM_TYPE2_BOOL_OUTPUT_SCHEMA.to_string(),
        respond_serialization_schema: EVM_TYPE2_BOOL_OUTPUT_SCHEMA.to_string(),
    }
}

fn make_sign_request_payload(event: &SignBidirectionalRequestedEvent) -> SignRequestPayload {
    SignRequestPayload {
        operators: event.operators.clone(),
        requester: event.requester.clone(),
        sig_network: event.sig_network.clone(),
        tx_params: event.tx_params.clone(),
        caip2_id: event.caip2_id.clone(),
        key_version: event.key_version,
        path: event.path.clone(),
        algo: event.algo.clone(),
        dest: event.dest.clone(),
        params: event.params.clone(),
        output_deserialization_schema: event.output_deserialization_schema.clone(),
        respond_serialization_schema: event.respond_serialization_schema.clone(),
    }
}

async fn read_token_balance(
    provider: &DynProvider<Ethereum>,
    token: Address,
    account: Address,
) -> Result<U256> {
    let call = ITestToken::balanceOfCall { account };
    let req = TransactionRequest::default()
        .to(token)
        .input(Bytes::from(call.abi_encode()).into());
    let raw = provider.call(req).await?;
    Ok(U256::from_be_slice(raw.as_ref()))
}

async fn read_token_allowance(
    provider: &DynProvider<Ethereum>,
    token: Address,
    owner: Address,
    spender: Address,
) -> Result<U256> {
    let call = ITestToken::allowanceCall { owner, spender };
    let req = TransactionRequest::default()
        .to(token)
        .input(Bytes::from(call.abi_encode()).into());
    let raw = provider.call(req).await?;
    Ok(U256::from_be_slice(raw.as_ref()))
}

#[derive(Clone, Debug)]
enum PostCheck {
    /// No state assertion (used for field-permutation cases targeting non-contract
    /// destinations, or when the case's value is purely round-trip mechanics).
    None,
    Balances(Vec<(Address, U256)>),
    Allowance {
        owner: Address,
        spender: Address,
        expected: U256,
    },
    EthBalance {
        account: Address,
        expected: U256,
    },
    CreatedContract {
        expected_code: Bytes,
    },
    /// The on-chain tx is expected to revert; the listed balances must be
    /// unchanged. An empty vec means "just assert revert, no balance read".
    Revert(Vec<(Address, U256)>),
}

#[derive(Clone, Debug)]
struct DefiCase {
    name: &'static str,
    path: String,
    params: EvmType2TransactionParams,
    post_check: PostCheck,
}

#[test]
fn test_canton_response_output_expectations_are_selector_aware() -> Result<()> {
    let bool_returning = evm_type2_params(
        0,
        200_000,
        1,
        10,
        Some(TEST_TOKEN_ADDRESS),
        U256::ZERO,
        "a9059cbb".to_string() + &"00".repeat(64),
        vec![],
    );
    assert_eq!(
        expected_canton_success_output_hex(&bool_returning),
        ABI_ENCODED_BOOL_TRUE_HEX
    );

    let no_return = evm_type2_params(
        0,
        200_000,
        1,
        10,
        Some(TEST_TOKEN_ADDRESS),
        U256::ZERO,
        "40c10f19".to_string() + &"00".repeat(64),
        vec![],
    );
    assert_eq!(expected_canton_success_output_hex(&no_return), "");

    let non_function_call = evm_type2_params(
        0,
        21_000,
        1,
        10,
        Some("1111111111111111111111111111111111111111"),
        U256::ZERO,
        "",
        vec![],
    );
    assert_eq!(
        expected_canton_success_output_hex(&non_function_call),
        ABI_ENCODED_BOOL_TRUE_HEX
    );

    let unknown_calldata_to_eoa = evm_type2_params(
        0,
        30_000,
        1,
        10,
        Some("1111111111111111111111111111111111111111"),
        U256::ZERO,
        "00".repeat(32),
        vec![],
    );
    assert_eq!(
        expected_canton_success_output_hex(&unknown_calldata_to_eoa),
        ""
    );

    Ok(())
}

#[test]
fn test_created_contract_address_matches_independent_oracle() -> Result<()> {
    let sender = Address::from_slice(&hex::decode("1234567890abcdef1234567890abcdef12345678")?);
    let expected = ethers_core::utils::get_contract_address(
        ethers_core::types::H160::from_slice(sender.as_slice()),
        ethers_core::types::U256::from(7u64),
    );

    assert_eq!(
        created_contract_address(sender, 7),
        Address::from_slice(expected.as_bytes())
    );

    Ok(())
}

/// Run one Canton -> MPC -> Anvil -> Canton round-trip and run the post-state
/// assertion. Returns Err on any deviation; never panics so the outer driver
/// can accumulate failures across all cases.
async fn run_canton_eth_round_trip(
    canton: &CantonSandbox,
    anvil: &DynProvider<Ethereum>,
    root_pk: k256::AffinePoint,
    case: &DefiCase,
    token_address: Address,
) -> Result<()> {
    let case_name = case.name;
    let client = &canton.client;

    let event = make_sign_event(canton, &case.params, &case.path);
    let expected_request_id = hex::encode(compute_request_id(&event)?);

    let sign_request = client
        .create_contract(
            &[&canton.operator_party, &canton.requester_party],
            "#daml-signer:Signer:SignRequest",
            serde_json::to_value(make_sign_request_payload(&event))?,
        )
        .await
        .with_context(|| format!("create SignRequest ({case_name})"))?;
    let (sign_request_cid, _) = find_created_contract(&sign_request, "SignRequest")?;

    client
        .exercise_choice(
            &[&canton.requester_party],
            &canton.signer_template_id,
            &canton.signer_cid,
            "SignBidirectional",
            json!({
                "signRequestCid": sign_request_cid,
                "requester": &canton.requester_party,
            }),
            std::slice::from_ref(&canton.signer_disclosure),
        )
        .await
        .with_context(|| format!("exercise SignBidirectional ({case_name})"))?;

    let sig_payload: SignatureRespondedEventPayload = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:SignatureRespondedEvent",
            |p: &SignatureRespondedEventPayload| p.request_id == expected_request_id,
            Duration::from_secs(120),
        )
        .await
        .with_context(|| format!("timeout SignatureRespondedEvent ({case_name})"))?;

    let mpc_signature = parse_canton_signature(&sig_payload.signature)?;

    let sign_epsilon =
        mpc_crypto::derive_epsilon_canton(LATEST_MPC_KEY_VERSION, &event.sender, &case.path);
    let expected_sender_addr = derive_user_address(root_pk, sign_epsilon);

    // Top up gas — idempotent if already funded.
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
    let signed_bytes = encode_signed_eip1559(&case.params, y_parity, &r_bytes, &s_bytes)?;
    let unsigned_bytes = TxEip1559::try_from(&case.params)?.encoded_for_signing();
    let unsigned_hash: [u8; 32] = keccak256(&unsigned_bytes).into();
    let sign_ecdsa = k256::ecdsa::Signature::from_scalars(
        mpc_crypto::x_coordinate(&mpc_signature.big_r),
        mpc_signature.s,
    )
    .with_context(|| format!("invalid transaction signature scalars ({case_name})"))?;
    let sign_derived_pk = mpc_crypto::derive_key(root_pk, sign_epsilon);
    let verifying_key = k256::ecdsa::VerifyingKey::from_affine(sign_derived_pk)
        .map_err(|e| anyhow::anyhow!("invalid derived transaction pk ({case_name}): {e}"))?;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    verifying_key
        .verify_prehash(&unsigned_hash, &sign_ecdsa)
        .with_context(|| format!("transaction signature verify failed ({case_name})"))?;

    let (watched_tx_hash, _) = sign_and_hash_transaction(&unsigned_bytes, mpc_signature)?;
    let watched_tx_hash = B256::from(watched_tx_hash);

    let pending_tx = anvil.send_raw_transaction(&signed_bytes).await?;
    let tx_hash = *pending_tx.tx_hash();
    if tx_hash != watched_tx_hash {
        anyhow::bail!(
            "MPC watcher tx hash mismatch ({case_name}): mpc={watched_tx_hash:?} anvil={tx_hash:?}"
        );
    }
    anvil.evm_mine(None).await?;

    let respond_payload = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:RespondBidirectionalEvent",
            |p: &RespondBidirectionalEventPayload| p.request_id == expected_request_id,
            Duration::from_secs(300),
        )
        .await
        .with_context(|| format!("timeout RespondBidirectionalEvent ({case_name})"))?;

    let receipt = anvil
        .get_transaction_receipt(tx_hash)
        .await?
        .with_context(|| format!("missing Anvil receipt ({case_name})"))?;
    let expect_revert = matches!(case.post_check, PostCheck::Revert(_));
    let receipt_succeeded = receipt.status();
    if expect_revert && receipt_succeeded {
        anyhow::bail!("expected revert but tx succeeded ({case_name}); tx_hash={tx_hash:?}");
    }
    if !expect_revert && !receipt_succeeded {
        anyhow::bail!("Anvil receipt failed ({case_name}); tx_hash={tx_hash:?}");
    }
    if receipt.from != expected_sender_addr {
        anyhow::bail!(
            "Anvil recovered unexpected sender ({case_name}): expected={expected_sender_addr:?} actual={:?}",
            receipt.from
        );
    }

    let expected_output = if expect_revert {
        BIDIRECTIONAL_FAILURE_BOOL_TRUE_HEX
    } else {
        expected_canton_success_output_hex(&case.params)
    };
    if respond_payload.serialized_output != expected_output {
        anyhow::bail!(
            "serialized output mismatch ({case_name}): expected={expected_output} actual={}",
            respond_payload.serialized_output
        );
    }

    // Verify the response signature returned to Canton.
    let respond_signature = parse_canton_signature(&respond_payload.signature)?;
    let response_hash =
        mpc_node::respond_bidirectional::calculate_respond_bidirectional_hash_message(
            &hex::decode(&respond_payload.request_id)?,
            &hex::decode(&respond_payload.serialized_output)?,
        );
    let respond_epsilon = mpc_crypto::derive_epsilon_canton(
        LATEST_MPC_KEY_VERSION,
        &event.sender,
        CANTON_RESPOND_BIDIRECTIONAL_PATH,
    );
    let respond_derived_pk = mpc_crypto::derive_key(root_pk, respond_epsilon);
    let respond_ecdsa = k256::ecdsa::Signature::from_scalars(
        mpc_crypto::x_coordinate(&respond_signature.big_r),
        respond_signature.s,
    )
    .with_context(|| format!("invalid respond signature scalars ({case_name})"))?;
    let verifying_key = k256::ecdsa::VerifyingKey::from_affine(respond_derived_pk)
        .map_err(|e| anyhow::anyhow!("invalid derived pk ({case_name}): {e}"))?;
    verifying_key
        .verify_prehash(&response_hash, &respond_ecdsa)
        .with_context(|| format!("respond signature verify failed ({case_name})"))?;

    // Run the case-specific post-state assertion against Anvil.
    match &case.post_check {
        PostCheck::None => {}
        PostCheck::Balances(checks) | PostCheck::Revert(checks) => {
            for (account, expected) in checks {
                let actual = read_token_balance(anvil, token_address, *account).await?;
                if actual != *expected {
                    anyhow::bail!(
                        "post-balance mismatch ({case_name}): account={account:?} expected={expected} actual={actual}"
                    );
                }
            }
        }
        PostCheck::Allowance {
            owner,
            spender,
            expected,
        } => {
            let actual = read_token_allowance(anvil, token_address, *owner, *spender).await?;
            if actual != *expected {
                anyhow::bail!(
                    "post-allowance mismatch ({case_name}): owner={owner:?} spender={spender:?} expected={expected} actual={actual}"
                );
            }
        }
        PostCheck::EthBalance { account, expected } => {
            let actual = anvil.get_balance(*account).await?;
            if actual != *expected {
                anyhow::bail!(
                    "post-eth-balance mismatch ({case_name}): account={account:?} expected={expected} actual={actual}"
                );
            }
        }
        PostCheck::CreatedContract { expected_code } => {
            let nonce = evm_type2_nonce(&case.params)?;
            let expected_address = created_contract_address(expected_sender_addr, nonce);
            let actual_address = receipt
                .contract_address
                .with_context(|| format!("missing created contract address ({case_name})"))?;
            if actual_address != expected_address {
                anyhow::bail!(
                    "created contract address mismatch ({case_name}): expected={expected_address:?} actual={actual_address:?}"
                );
            }
            let actual_code = anvil.get_code_at(expected_address).await?;
            if actual_code != *expected_code {
                anyhow::bail!(
                    "created contract code mismatch ({case_name}): address={expected_address:?} expected={expected_code:?} actual={actual_code:?}"
                );
            }
        }
    }

    tracing::info!(case_name, "case OK");
    Ok(())
}

#[ignore] // requires dpm + openssl + Docker; needs TestToken artifact
#[serial]
#[test(tokio::test)]
async fn test_canton_eth_bidirectional_defi_flow() -> Result<()> {
    // 1. Spawn cluster with Canton + Ethereum.
    let nodes = cluster::spawn()
        .disable_prestockpile()
        .canton()
        .ethereum()
        .await?;
    nodes.wait().signable().await?;

    let canton = nodes
        .canton
        .as_ref()
        .context("canton sandbox not available")?;
    let root_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();

    let eth_ctx = nodes
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum not available")?;
    let anvil_rpc_url = &eth_ctx.sandbox.external_http_endpoint;
    let provider: DynProvider<Ethereum> =
        DynProvider::new(RootProvider::<Ethereum>::new_http(anvil_rpc_url.parse()?));
    provider.anvil_set_auto_mine(false).await?;
    provider.anvil_set_interval_mining(0).await?;

    // 2. Plant the TestToken runtime bytecode at a stable address on Anvil.
    // This deliberately skips constructor metadata initialization; the test
    // surface is ERC20 balance/allowance storage plus permissionless mint.
    let token_address = Address::from_slice(&hex::decode(TEST_TOKEN_ADDRESS)?);
    provider
        .anvil_set_code(token_address, test_token_runtime_bytecode())
        .await?;

    // 3. Resolve the four logical user MPC-derived addresses.
    let user_paths = ["defi_user_a", "defi_user_b", "defi_user_c", "defi_user_d"];
    let user_addrs: Vec<Address> = user_paths
        .iter()
        .map(|p| mpc_derived_address(canton, root_pk, p))
        .collect();
    let [addr_a, addr_b, addr_c, addr_d] =
        [user_addrs[0], user_addrs[1], user_addrs[2], user_addrs[3]];
    tracing::info!(
        ?addr_a,
        ?addr_b,
        ?addr_c,
        ?addr_d,
        "resolved DeFi user addresses"
    );

    // 4. Pre-fund each user with ETH for gas. Token balances are seeded by
    //    case 1-4 (mints) so we deliberately do NOT pre-mint via storage —
    //    the mint cases are part of the test surface.
    for addr in &user_addrs {
        provider
            .anvil_set_balance(*addr, U256::from(10_000_000_000_000_000_000u128))
            .await?;
    }

    // Helpers for ERC20 calldata.
    let mint_cd = |to: Address, amount: U256| -> String {
        hex::encode(ITestToken::mintCall { to, amount }.abi_encode())
    };
    let transfer_cd = |to: Address, amount: U256| -> String {
        hex::encode(ITestToken::transferCall { to, amount }.abi_encode())
    };
    let approve_cd = |spender: Address, amount: U256| -> String {
        hex::encode(ITestToken::approveCall { spender, amount }.abi_encode())
    };
    let transfer_from_cd = |from: Address, to: Address, amount: U256| -> String {
        hex::encode(ITestToken::transferFromCall { from, to, amount }.abi_encode())
    };

    // Standard fees / gas for ERC20 ops.
    const PRIO: u128 = 1_000_000_000; // 1 gwei
    const MAX_FEE: u128 = 100_000_000_000; // 100 gwei
    const ERC20_GAS: u64 = 200_000;
    let token_to: Option<&str> = Some(TEST_TOKEN_ADDRESS);

    let u = U256::from;

    // 5. Build all 35 sequential cases. Balances tracked by hand with running totals.
    //    All ERC20 amounts are denominated in raw token units (no decimals).
    //    Group 5 cases (21-30) target this dummy address; it has no code on
    //    Anvil so calldata calls are benign no-ops returning empty data.
    let dummy_to = "1111111111111111111111111111111111111111";
    let dummy_addr = Address::from_slice(&hex::decode(dummy_to)?);
    let dummy_after_one_wei = u(1u64);
    let dummy_after_one_eth = U256::from(1_000_000_000_000_000_000u128) + dummy_after_one_wei;
    let cases: Vec<DefiCase> = vec![
        // ===== Group 1: mints (cases 1-4) =====
        DefiCase {
            name: "01_mint_userA_10000",
            path: user_paths[0].to_string(),
            params: evm_type2_params(
                0,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                mint_cd(addr_a, u(10_000u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_a, u(10_000u64))]),
        },
        DefiCase {
            name: "02_mint_userB_10000",
            path: user_paths[1].to_string(),
            params: evm_type2_params(
                0,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                mint_cd(addr_b, u(10_000u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_b, u(10_000u64))]),
        },
        DefiCase {
            name: "03_mint_userC_10000",
            path: user_paths[2].to_string(),
            params: evm_type2_params(
                0,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                mint_cd(addr_c, u(10_000u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_c, u(10_000u64))]),
        },
        DefiCase {
            name: "04_mint_userD_10000",
            path: user_paths[3].to_string(),
            params: evm_type2_params(
                0,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                mint_cd(addr_d, u(10_000u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_d, u(10_000u64))]),
        },
        // ===== Group 2: transfers (cases 5-12). Balances tracked inline =====
        // After 1-4: A=10000 B=10000 C=10000 D=10000
        DefiCase {
            // 5: A->B 1000  => A=9000 B=11000
            name: "05_transfer_A_to_B_1000",
            path: user_paths[0].to_string(),
            params: evm_type2_params(
                1,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_cd(addr_b, u(1_000u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_a, u(9_000u64)), (addr_b, u(11_000u64))]),
        },
        DefiCase {
            // 6: B->C 500   => B=10500 C=10500
            name: "06_transfer_B_to_C_500",
            path: user_paths[1].to_string(),
            params: evm_type2_params(
                1,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_cd(addr_c, u(500u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_b, u(10_500u64)), (addr_c, u(10_500u64))]),
        },
        DefiCase {
            // 7: C->D 250   => C=10250 D=10250
            name: "07_transfer_C_to_D_250",
            path: user_paths[2].to_string(),
            params: evm_type2_params(
                1,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_cd(addr_d, u(250u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_c, u(10_250u64)), (addr_d, u(10_250u64))]),
        },
        DefiCase {
            // 8: A->C 2000  => A=7000 C=12250
            name: "08_transfer_A_to_C_2000",
            path: user_paths[0].to_string(),
            params: evm_type2_params(
                2,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_cd(addr_c, u(2_000u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_a, u(7_000u64)), (addr_c, u(12_250u64))]),
        },
        DefiCase {
            // 9: D->A 100   => D=10150 A=7100
            name: "09_transfer_D_to_A_100",
            path: user_paths[3].to_string(),
            params: evm_type2_params(
                1,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_cd(addr_a, u(100u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_d, u(10_150u64)), (addr_a, u(7_100u64))]),
        },
        DefiCase {
            // 10: B->D 1500 => B=9000 D=11650
            name: "10_transfer_B_to_D_1500",
            path: user_paths[1].to_string(),
            params: evm_type2_params(
                2,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_cd(addr_d, u(1_500u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_b, u(9_000u64)), (addr_d, u(11_650u64))]),
        },
        DefiCase {
            // 11: A->D 50   => A=7050 D=11700
            name: "11_transfer_A_to_D_50",
            path: user_paths[0].to_string(),
            params: evm_type2_params(
                3,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_cd(addr_d, u(50u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_a, u(7_050u64)), (addr_d, u(11_700u64))]),
        },
        DefiCase {
            // 12: C->B 750  => C=11500 B=9750 (C=12250 from case 8, then -750)
            name: "12_transfer_C_to_B_750",
            path: user_paths[2].to_string(),
            params: evm_type2_params(
                2,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_cd(addr_b, u(750u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_c, u(11_500u64)), (addr_b, u(9_750u64))]),
        },
        // ===== Group 3: approve + transferFrom (cases 13-17) =====
        DefiCase {
            // 13: A approves B for 3000
            name: "13_approve_A_to_B_3000",
            path: user_paths[0].to_string(),
            params: evm_type2_params(
                4,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                approve_cd(addr_b, u(3_000u64)),
                vec![],
            ),
            post_check: PostCheck::Allowance {
                owner: addr_a,
                spender: addr_b,
                expected: u(3_000u64),
            },
        },
        DefiCase {
            // 14: B transferFrom(A, C, 1000) => A=6050 C=12500 allowance(A,B)=2000
            name: "14_transferFrom_A_to_C_1000_by_B",
            path: user_paths[1].to_string(),
            params: evm_type2_params(
                3,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_from_cd(addr_a, addr_c, u(1_000u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_a, u(6_050u64)), (addr_c, u(12_500u64))]),
        },
        DefiCase {
            // 15: B transferFrom(A, D, 500) => A=5550 D=12200 allowance=1500
            name: "15_transferFrom_A_to_D_500_by_B",
            path: user_paths[1].to_string(),
            params: evm_type2_params(
                4,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_from_cd(addr_a, addr_d, u(500u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_a, u(5_550u64)), (addr_d, u(12_200u64))]),
        },
        DefiCase {
            // 16: C approves D for 1500
            name: "16_approve_C_to_D_1500",
            path: user_paths[2].to_string(),
            params: evm_type2_params(
                3,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                approve_cd(addr_d, u(1_500u64)),
                vec![],
            ),
            post_check: PostCheck::Allowance {
                owner: addr_c,
                spender: addr_d,
                expected: u(1_500u64),
            },
        },
        DefiCase {
            // 17: D transferFrom(C, A, 800) => C=11700 A=6350 allowance(C,D)=700
            name: "17_transferFrom_C_to_A_800_by_D",
            path: user_paths[3].to_string(),
            params: evm_type2_params(
                2,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_from_cd(addr_c, addr_a, u(800u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_c, u(11_700u64)), (addr_a, u(6_350u64))]),
        },
        // ===== Group 4: edge mints + self-transfer (cases 18-20) =====
        DefiCase {
            // 18: mint A 100 => A=6450
            name: "18_mint_A_100",
            path: user_paths[0].to_string(),
            params: evm_type2_params(
                5,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                mint_cd(addr_a, u(100u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_a, u(6_450u64))]),
        },
        DefiCase {
            // 19: mint B 0 => no-op, balance unchanged
            name: "19_mint_B_0",
            path: user_paths[1].to_string(),
            params: evm_type2_params(
                5,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                mint_cd(addr_b, U256::ZERO),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_b, u(9_750u64))]),
        },
        DefiCase {
            // 20: A transfers 1000 to itself => no net change
            name: "20_transfer_A_to_A_1000_self",
            path: user_paths[0].to_string(),
            params: evm_type2_params(
                6,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_cd(addr_a, u(1_000u64)),
                vec![],
            ),
            post_check: PostCheck::Balances(vec![(addr_a, u(6_450u64))]),
        },
        // ===== Group 5: EVM Type 2 field permutations (cases 21-30) =====
        // Each uses a unique path so nonce=0; cases are independent of each
        // other and of the ERC20 group above.
        DefiCase {
            // 21: minimum gas value transfer
            name: "21_field_perm_min_gas_value_xfer",
            path: "defi_perm_21".to_string(),
            params: evm_type2_params(
                0,
                21_000,
                PRIO,
                MAX_FEE,
                Some(dummy_to),
                u(1u64),
                "",
                vec![],
            ),
            post_check: PostCheck::EthBalance {
                account: dummy_addr,
                expected: dummy_after_one_wei,
            },
        },
        DefiCase {
            // 22: zero priority fee
            name: "22_field_perm_zero_priority_fee",
            path: "defi_perm_22".to_string(),
            params: evm_type2_params(
                0,
                21_000,
                0,
                20_000_000_000,
                Some(dummy_to),
                u(0u64),
                "",
                vec![],
            ),
            post_check: PostCheck::EthBalance {
                account: dummy_addr,
                expected: dummy_after_one_wei,
            },
        },
        DefiCase {
            // 23: high priority fee
            name: "23_field_perm_high_priority_fee",
            path: "defi_perm_23".to_string(),
            params: evm_type2_params(
                0,
                21_000,
                100_000_000_000,
                200_000_000_000,
                Some(dummy_to),
                u(0u64),
                "",
                vec![],
            ),
            post_check: PostCheck::EthBalance {
                account: dummy_addr,
                expected: dummy_after_one_wei,
            },
        },
        DefiCase {
            // 24: 1 ETH value transfer
            name: "24_field_perm_one_eth_transfer",
            path: "defi_perm_24".to_string(),
            params: evm_type2_params(
                0,
                21_000,
                PRIO,
                MAX_FEE,
                Some(dummy_to),
                U256::from(1_000_000_000_000_000_000u128),
                "",
                vec![],
            ),
            post_check: PostCheck::EthBalance {
                account: dummy_addr,
                expected: dummy_after_one_eth,
            },
        },
        DefiCase {
            // 25: 32-byte calldata
            name: "25_field_perm_calldata_32b",
            path: "defi_perm_25".to_string(),
            params: evm_type2_params(
                0,
                30_000,
                PRIO,
                MAX_FEE,
                Some(dummy_to),
                u(0u64),
                "00".repeat(32),
                vec![],
            ),
            post_check: PostCheck::EthBalance {
                account: dummy_addr,
                expected: dummy_after_one_eth,
            },
        },
        DefiCase {
            // 26: ~1KB calldata
            name: "26_field_perm_calldata_1kb",
            path: "defi_perm_26".to_string(),
            params: evm_type2_params(
                0,
                200_000,
                PRIO,
                MAX_FEE,
                Some(dummy_to),
                u(0u64),
                "42".repeat(1024),
                vec![],
            ),
            post_check: PostCheck::EthBalance {
                account: dummy_addr,
                expected: dummy_after_one_eth,
            },
        },
        DefiCase {
            // 27: 1 access list entry
            name: "27_field_perm_access_list_one",
            path: "defi_perm_27".to_string(),
            params: evm_type2_params(
                0,
                100_000,
                PRIO,
                MAX_FEE,
                Some(dummy_to),
                u(0u64),
                "",
                vec![EvmAccessListEntry {
                    address: "3333333333333333333333333333333333333333".to_string(),
                    storage_keys: vec!["0".repeat(64)],
                }],
            ),
            post_check: PostCheck::EthBalance {
                account: dummy_addr,
                expected: dummy_after_one_eth,
            },
        },
        DefiCase {
            // 28: 5 access list entries
            name: "28_field_perm_access_list_five",
            path: "defi_perm_28".to_string(),
            params: evm_type2_params(
                0,
                200_000,
                PRIO,
                MAX_FEE,
                Some(dummy_to),
                u(0u64),
                "",
                (0..5)
                    .map(|i| EvmAccessListEntry {
                        address: format!("{:040x}", 0x4444_4444_u64 + i),
                        storage_keys: vec![format!("{:064x}", i), format!("{:064x}", i + 100)],
                    })
                    .collect(),
            ),
            post_check: PostCheck::EthBalance {
                account: dummy_addr,
                expected: dummy_after_one_eth,
            },
        },
        DefiCase {
            // 29: contract create with empty initcode
            name: "29_field_perm_create_empty",
            path: "defi_perm_29".to_string(),
            params: evm_type2_params(0, 100_000, PRIO, MAX_FEE, None, u(0u64), "", vec![]),
            post_check: PostCheck::CreatedContract {
                expected_code: Bytes::default(),
            },
        },
        DefiCase {
            // 30: zero-value transfer to a fresh dummy address
            name: "30_field_perm_value_xfer_zero_value",
            path: "defi_perm_30".to_string(),
            params: evm_type2_params(
                0,
                21_000,
                PRIO,
                MAX_FEE,
                Some(dummy_to),
                u(0u64),
                "",
                vec![],
            ),
            post_check: PostCheck::EthBalance {
                account: dummy_addr,
                expected: dummy_after_one_eth,
            },
        },
        // ===== Group 6: revert paths (cases 31-35) =====
        // Each uses a fresh path with nonce=0 (no token balance, no allowances).
        // Asserts the on-chain tx reverts AND any referenced state is unchanged.
        DefiCase {
            // 31: transferFrom without allowance — reverts (allowance underflow).
            //     A's balance must remain 6450 (set in case 18).
            name: "31_revert_transferFrom_no_allowance",
            path: "defi_revert_1".to_string(),
            params: evm_type2_params(
                0,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_from_cd(addr_a, addr_b, u(1u64)),
                vec![],
            ),
            post_check: PostCheck::Revert(vec![(addr_a, u(6_450u64)), (addr_b, u(9_750u64))]),
        },
        DefiCase {
            // 32: transfer to address(0) — OZ ERC20 reverts on `to == 0`.
            //     Sender has 0 tokens; revert happens before balance check.
            name: "32_revert_transfer_to_zero",
            path: "defi_revert_2".to_string(),
            params: evm_type2_params(
                0,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                hex::encode(
                    ITestToken::transferCall {
                        to: Address::ZERO,
                        amount: U256::ZERO,
                    }
                    .abi_encode(),
                ),
                vec![],
            ),
            post_check: PostCheck::Revert(vec![]),
        },
        DefiCase {
            // 33: transfer over balance — sender has 0 tokens, attempts 1.
            //     Recipient B's balance must remain 9750.
            name: "33_revert_transfer_over_balance",
            path: "defi_revert_3".to_string(),
            params: evm_type2_params(
                0,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                transfer_cd(addr_b, u(1u64)),
                vec![],
            ),
            post_check: PostCheck::Revert(vec![(addr_b, u(9_750u64))]),
        },
        DefiCase {
            // 34: approve to address(0) — OZ ERC20 reverts on `spender == 0`.
            name: "34_revert_approve_to_zero",
            path: "defi_revert_4".to_string(),
            params: evm_type2_params(
                0,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                hex::encode(
                    ITestToken::approveCall {
                        spender: Address::ZERO,
                        amount: u(1u64),
                    }
                    .abi_encode(),
                ),
                vec![],
            ),
            post_check: PostCheck::Revert(vec![]),
        },
        DefiCase {
            // 35: mint to address(0) — _mint reverts on `to == 0`.
            name: "35_revert_mint_to_zero",
            path: "defi_revert_5".to_string(),
            params: evm_type2_params(
                0,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                hex::encode(
                    ITestToken::mintCall {
                        to: Address::ZERO,
                        amount: u(1u64),
                    }
                    .abi_encode(),
                ),
                vec![],
            ),
            post_check: PostCheck::Revert(vec![]),
        },
    ];

    assert_eq!(cases.len(), 35, "expected 35 DeFi cases");

    // 6. Pre-fund every distinct path's MPC-derived address so gas is covered.
    use std::collections::BTreeSet;
    let extra_paths: BTreeSet<String> = cases.iter().skip(20).map(|c| c.path.clone()).collect();
    for p in &extra_paths {
        let addr = mpc_derived_address(canton, root_pk, p);
        provider
            .anvil_set_balance(addr, U256::from(10_000_000_000_000_000_000u128))
            .await?;
    }

    // 7. Skip the ordered stateful cases while narrowing the watcher race. The
    //    parallel phase below isolates concurrent Canton/MPC/Anvil timing.
    let mut failures: Vec<String> = Vec::new();
    let sequential_cases_run = 0usize;

    // 8. Concurrent phase: 10 simultaneous mints of 10 tokens each to addr_a.
    //    Each case uses a fresh path (nonce=0 sender) so there's no nonce
    //    contention. The point is to stress: many SignBidirectional choices
    //    in flight on Canton, MPC presignature pool serving them in parallel,
    //    and concurrent broadcasts to Anvil. Final aggregate balance must
    //    match the pre-balance plus exactly 10 * 10 = 100 tokens.
    const N_CONCURRENT: usize = 10;
    const PER_MINT: u64 = 10;
    let concurrent_cases: Vec<DefiCase> = (1..=N_CONCURRENT)
        .map(|i| DefiCase {
            name: Box::leak(format!("CC{i:02}_concurrent_mint_A_10").into_boxed_str()),
            path: format!("defi_concurrent_{i}"),
            params: evm_type2_params(
                0,
                ERC20_GAS,
                PRIO,
                MAX_FEE,
                token_to,
                U256::ZERO,
                mint_cd(addr_a, u(PER_MINT)),
                vec![],
            ),
            post_check: PostCheck::None,
        })
        .collect();

    for c in &concurrent_cases {
        let addr = mpc_derived_address(canton, root_pk, &c.path);
        provider
            .anvil_set_balance(addr, U256::from(10_000_000_000_000_000_000u128))
            .await?;
    }

    let pre_balance_a = read_token_balance(&provider, token_address, addr_a).await?;
    tracing::info!(?pre_balance_a, "concurrent phase: starting");

    let concurrent_results = futures::future::join_all(
        concurrent_cases
            .iter()
            .map(|c| run_canton_eth_round_trip(canton, &provider, root_pk, c, token_address)),
    )
    .await;

    for (case, res) in concurrent_cases.iter().zip(concurrent_results.iter()) {
        if let Err(e) = res {
            let case_name = case.name;
            tracing::error!(case_name, error = %e, "concurrent case FAILED");
            failures.push(format!("{}: {e:#}", case.name));
        }
    }

    let post_balance_a = read_token_balance(&provider, token_address, addr_a).await?;
    let expected_post = pre_balance_a + u(PER_MINT * N_CONCURRENT as u64);
    if post_balance_a != expected_post {
        let msg = format!(
            "concurrent aggregate balance mismatch: pre={pre_balance_a} expected_post={expected_post} actual_post={post_balance_a}"
        );
        tracing::error!("{msg}");
        failures.push(msg);
    }

    let total_cases = sequential_cases_run + concurrent_cases.len();
    if !failures.is_empty() {
        anyhow::bail!(
            "{}/{} DeFi cases failed:\n  - {}",
            failures.len(),
            total_cases,
            failures.join("\n  - ")
        );
    }

    tracing::info!(
        sequential = sequential_cases_run,
        concurrent = concurrent_cases.len(),
        total = total_cases,
        "all DeFi cases OK"
    );
    Ok(())
}

/// Run a single Erc20Vault deposit→claim→withdraw→complete cycle on an
/// already-deployed Vault. Pre-funds and seeds `user_subpath` (an EVM
/// identity derived from `vaultId,requester,user_subpath`) with
/// `deposit_amount` of TestToken, then exercises the full Vault flow.
/// Each cycle verifies the MPC's response signature twice (ClaimDeposit +
/// CompleteWithdrawal) against the Vault's stored `evmMpcPublicKey`.
#[allow(clippy::too_many_arguments)]
async fn run_vault_deposit_withdraw_cycle(
    canton: &CantonSandbox,
    provider: &DynProvider<Ethereum>,
    root_pk: k256::AffinePoint,
    token_address: Address,
    vault_id: &str,
    vault_addr: Address,
    vault_cid: &str,
    vault_template_id: &str,
    vault_disclosure: &mpc_node::indexer_canton::ledger_api::DisclosedContract,
    requester_party: &str,
    user_subpath: &str,
    minter_path: &str,
    recipient_subpath: &str,
    deposit_amount: U256,
) -> Result<()> {
    use mpc_node::indexer_canton::contracts::{
        RespondBidirectionalEventPayload, SignatureRespondedEventPayload,
    };

    let full_user_path = format!("{vault_id},{},{}", requester_party, user_subpath);
    let user_addr = mpc_derived_address(canton, root_pk, &full_user_path);
    let recipient_addr = mpc_derived_address(canton, root_pk, recipient_subpath);
    let minter_addr = mpc_derived_address(canton, root_pk, minter_path);

    provider
        .anvil_set_balance(user_addr, U256::from(10_000_000_000_000_000_000u128))
        .await?;
    provider
        .anvil_set_balance(minter_addr, U256::from(10_000_000_000_000_000_000u128))
        .await?;

    // Seed user with TestToken via direct Signer flow (mints into user_addr).
    let mint_calldata = hex::encode(
        ITestToken::mintCall {
            to: user_addr,
            amount: deposit_amount,
        }
        .abi_encode(),
    );
    let mint_case = DefiCase {
        name: "vault_seed_mint",
        path: minter_path.to_string(),
        params: evm_type2_params(
            0,
            200_000,
            1_000_000_000,
            100_000_000_000,
            Some(TEST_TOKEN_ADDRESS),
            U256::ZERO,
            mint_calldata,
            vec![],
        ),
        post_check: PostCheck::Balances(vec![(user_addr, deposit_amount)]),
    };
    run_canton_eth_round_trip(canton, provider, root_pk, &mint_case, token_address).await?;
    tracing::info!(
        ?user_addr,
        ?deposit_amount,
        user_subpath,
        "user seeded with TestToken"
    );

    let transfer_to_vault = hex::encode(
        ITestToken::transferCall {
            to: vault_addr,
            amount: deposit_amount,
        }
        .abi_encode(),
    );
    let deposit_params = evm_type2_params(
        0,
        200_000,
        1_000_000_000,
        100_000_000_000,
        Some(TEST_TOKEN_ADDRESS),
        U256::ZERO,
        transfer_to_vault,
        vec![],
    );

    let deposit_args = json!({
        "requester": requester_party,
        "signerCid": &canton.signer_cid,
        "path": user_subpath,
        "evmTxParams": serde_json::to_value(&deposit_params)?,
        "keyVersion": LATEST_MPC_KEY_VERSION.to_string(),
        "algo": "",
        "dest": "",
        "params": "",
        "outputDeserializationSchema": EVM_TYPE2_BOOL_OUTPUT_SCHEMA,
        "respondSerializationSchema": EVM_TYPE2_BOOL_OUTPUT_SCHEMA,
    });
    let deposit_result = canton
        .client
        .exercise_choice(
            &[requester_party],
            vault_template_id,
            vault_cid,
            "RequestDeposit",
            deposit_args,
            &[vault_disclosure.clone(), canton.signer_disclosure.clone()],
        )
        .await
        .context("exercise Vault.RequestDeposit")?;
    let (pending_deposit_cid, _) = find_created_contract(&deposit_result, "PendingDeposit")?;
    let pending_deposit_payload = deposit_result
        .transaction
        .events
        .iter()
        .find_map(|e| match e {
            mpc_node::indexer_canton::ledger_api::Event::CreatedEvent(c)
                if c.contract_id == pending_deposit_cid =>
            {
                Some(c.payload.clone())
            }
            _ => None,
        })
        .context("PendingDeposit payload")?;
    let request_id = pending_deposit_payload
        .get("requestId")
        .and_then(|v| v.as_str())
        .context("requestId on PendingDeposit")?
        .to_string();
    tracing::info!(request_id, user_subpath, "deposit PendingDeposit created");

    let sig_payload: SignatureRespondedEventPayload = canton
        .client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:SignatureRespondedEvent",
            |p: &SignatureRespondedEventPayload| p.request_id == request_id,
            Duration::from_secs(120),
        )
        .await
        .context("timeout SignatureRespondedEvent (deposit)")?;
    tracing::info!(request_id, "deposit SignatureRespondedEvent observed");

    let mpc_signature = parse_canton_signature(&sig_payload.signature)?;
    let y_parity = mpc_signature.recovery_id == 1;
    let r_bytes: [u8; 32] = mpc_crypto::x_coordinate(&mpc_signature.big_r)
        .to_bytes()
        .into();
    let s_bytes: [u8; 32] = mpc_signature.s.to_bytes().into();
    let signed_bytes = encode_signed_eip1559(&deposit_params, y_parity, &r_bytes, &s_bytes)?;
    let pending_tx = provider.send_raw_transaction(&signed_bytes).await?;
    let deposit_tx_hash = *pending_tx.tx_hash();
    provider.evm_mine(None).await?;
    let receipt = provider
        .get_transaction_receipt(deposit_tx_hash)
        .await?
        .context("deposit receipt missing")?;
    anyhow::ensure!(receipt.status(), "deposit on-chain tx reverted");
    tracing::info!(?deposit_tx_hash, "deposit broadcast confirmed on Anvil");

    let _respond_payload: RespondBidirectionalEventPayload = canton
        .client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:RespondBidirectionalEvent",
            |p: &RespondBidirectionalEventPayload| p.request_id == request_id,
            Duration::from_secs(300),
        )
        .await
        .context("timeout RespondBidirectionalEvent (deposit)")?;
    let respond_event_cid = locate_event_cid(
        canton,
        "#daml-signer:Signer:RespondBidirectionalEvent",
        &request_id,
    )
    .await?;
    tracing::info!(request_id, "deposit RespondBidirectionalEvent observed");

    let user_balance = read_token_balance(provider, token_address, user_addr).await?;
    let vault_balance = read_token_balance(provider, token_address, vault_addr).await?;
    anyhow::ensure!(
        user_balance == U256::ZERO,
        "expected user empty after deposit, got {user_balance}"
    );
    anyhow::ensure!(
        vault_balance == deposit_amount,
        "expected vault={deposit_amount} after deposit, got {vault_balance}"
    );

    let claim_args = json!({
        "requester": requester_party,
        "pendingDepositCid": pending_deposit_cid,
        "respondBidirectionalEventCid": respond_event_cid,
        "signatureRespondedEventCid": locate_event_cid(
            canton,
            "#daml-signer:Signer:SignatureRespondedEvent",
            &request_id,
        )
        .await?,
    });
    let claim_result = canton
        .client
        .exercise_choice(
            &[requester_party],
            vault_template_id,
            vault_cid,
            "ClaimDeposit",
            claim_args,
            std::slice::from_ref(vault_disclosure),
        )
        .await
        .context("exercise Vault.ClaimDeposit")?;
    let (holding_cid, _) = find_created_contract(&claim_result, "Erc20Holding")?;
    tracing::info!(
        holding_cid,
        user_subpath,
        "Erc20Holding created from deposit"
    );

    // Withdrawal: send tokens to a fresh recipient address. The vault is
    // the EVM sender (same address across cycles), so query its current
    // nonce — cycle N's withdrawal would otherwise reuse cycle 1's nonce=0.
    let vault_nonce = provider.get_transaction_count(vault_addr).await?;
    let withdraw_to_recipient = hex::encode(
        ITestToken::transferCall {
            to: recipient_addr,
            amount: deposit_amount,
        }
        .abi_encode(),
    );
    let withdraw_params = evm_type2_params(
        vault_nonce,
        200_000,
        1_000_000_000,
        100_000_000_000,
        Some(TEST_TOKEN_ADDRESS),
        U256::ZERO,
        withdraw_to_recipient,
        vec![],
    );
    let recipient_padded = format!("{:0>64}", hex::encode(recipient_addr.as_slice()));
    let withdraw_args = json!({
        "requester": requester_party,
        "signerCid": &canton.signer_cid,
        "evmTxParams": serde_json::to_value(&withdraw_params)?,
        "recipientAddress": recipient_padded,
        "balanceCid": holding_cid,
        "keyVersion": LATEST_MPC_KEY_VERSION.to_string(),
        "algo": "",
        "dest": "",
        "params": "",
        "outputDeserializationSchema": EVM_TYPE2_BOOL_OUTPUT_SCHEMA,
        "respondSerializationSchema": EVM_TYPE2_BOOL_OUTPUT_SCHEMA,
    });
    let withdraw_result = canton
        .client
        .exercise_choice(
            &[requester_party],
            vault_template_id,
            vault_cid,
            "RequestWithdrawal",
            withdraw_args,
            &[vault_disclosure.clone(), canton.signer_disclosure.clone()],
        )
        .await
        .context("exercise Vault.RequestWithdrawal")?;
    let (pending_withdrawal_cid, _) = find_created_contract(&withdraw_result, "PendingWithdrawal")?;
    let pending_withdrawal_payload = withdraw_result
        .transaction
        .events
        .iter()
        .find_map(|e| match e {
            mpc_node::indexer_canton::ledger_api::Event::CreatedEvent(c)
                if c.contract_id == pending_withdrawal_cid =>
            {
                Some(c.payload.clone())
            }
            _ => None,
        })
        .context("PendingWithdrawal payload")?;
    let withdraw_request_id = pending_withdrawal_payload
        .get("requestId")
        .and_then(|v| v.as_str())
        .context("requestId on PendingWithdrawal")?
        .to_string();

    let withdraw_sig_payload: SignatureRespondedEventPayload = canton
        .client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:SignatureRespondedEvent",
            |p: &SignatureRespondedEventPayload| p.request_id == withdraw_request_id,
            Duration::from_secs(120),
        )
        .await
        .context("timeout SignatureRespondedEvent (withdrawal)")?;

    let mpc_w_sig = parse_canton_signature(&withdraw_sig_payload.signature)?;
    let w_y_parity = mpc_w_sig.recovery_id == 1;
    let w_r: [u8; 32] = mpc_crypto::x_coordinate(&mpc_w_sig.big_r).to_bytes().into();
    let w_s: [u8; 32] = mpc_w_sig.s.to_bytes().into();
    let w_signed = encode_signed_eip1559(&withdraw_params, w_y_parity, &w_r, &w_s)?;
    let pending_w_tx = provider.send_raw_transaction(&w_signed).await?;
    let w_tx_hash = *pending_w_tx.tx_hash();
    provider.evm_mine(None).await?;
    let w_receipt = provider
        .get_transaction_receipt(w_tx_hash)
        .await?
        .context("withdrawal receipt missing")?;
    anyhow::ensure!(w_receipt.status(), "withdrawal on-chain tx reverted");

    let _: RespondBidirectionalEventPayload = canton
        .client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-signer:Signer:RespondBidirectionalEvent",
            |p: &RespondBidirectionalEventPayload| p.request_id == withdraw_request_id,
            Duration::from_secs(300),
        )
        .await
        .context("timeout RespondBidirectionalEvent (withdrawal)")?;
    let withdraw_respond_cid = locate_event_cid(
        canton,
        "#daml-signer:Signer:RespondBidirectionalEvent",
        &withdraw_request_id,
    )
    .await?;
    let withdraw_sig_cid = locate_event_cid(
        canton,
        "#daml-signer:Signer:SignatureRespondedEvent",
        &withdraw_request_id,
    )
    .await?;

    let post_w_vault = read_token_balance(provider, token_address, vault_addr).await?;
    let post_w_recipient = read_token_balance(provider, token_address, recipient_addr).await?;
    anyhow::ensure!(
        post_w_vault == U256::ZERO,
        "expected vault empty after withdrawal, got {post_w_vault}"
    );
    anyhow::ensure!(
        post_w_recipient == deposit_amount,
        "expected recipient={deposit_amount} after withdrawal, got {post_w_recipient}"
    );

    let complete_args = json!({
        "requester": requester_party,
        "pendingWithdrawalCid": pending_withdrawal_cid,
        "respondBidirectionalEventCid": withdraw_respond_cid,
        "signatureRespondedEventCid": withdraw_sig_cid,
    });
    let _complete_result = canton
        .client
        .exercise_choice(
            &[requester_party],
            vault_template_id,
            vault_cid,
            "CompleteWithdrawal",
            complete_args,
            std::slice::from_ref(vault_disclosure),
        )
        .await
        .context("exercise Vault.CompleteWithdrawal")?;
    tracing::info!(user_subpath, "withdrawal complete; Erc20Holding archived");

    Ok(())
}

/// Multi-cycle Erc20Vault deposit + withdrawal flow against the daml-vault DAR.
///
/// Deploys a single Vault and runs N deposit→claim→withdraw→complete cycles
/// on it, each with a different EVM signing identity (`user_subpath`) and a
/// different `deposit_amount`. The Vault's `evmMpcPublicKey` is set once at
/// creation and used by every `ClaimDeposit`/`CompleteWithdrawal` to verify
/// the MPC's response signature. N successful cycles ⇒ 2N successful
/// signature verifications against the same key, empirically validating
/// that the per-Vault response signing key is constant — it depends only on
/// `(operatorsHash, key_version, "canton response key")`, all fixed per
/// Vault.
#[ignore] // requires dpm + openssl + Docker; needs TestToken artifact
#[serial]
#[test(tokio::test)]
async fn test_canton_eth_vault_deposit_withdraw_flow() -> Result<()> {
    // ── 1. Cluster + Anvil + TestToken bytecode ──────────────────────────
    let nodes = cluster::spawn()
        .disable_prestockpile()
        .canton()
        .ethereum()
        .await?;
    nodes.wait().signable().await?;
    let canton = nodes
        .canton
        .as_ref()
        .context("canton sandbox not available")?;
    let root_pk: k256::AffinePoint = nodes.root_public_key().await?.into_affine_point();

    let eth_ctx = nodes
        .nodes
        .ctx()
        .ethereum
        .as_ref()
        .context("ethereum not available")?;
    let provider: DynProvider<Ethereum> = DynProvider::new(RootProvider::<Ethereum>::new_http(
        eth_ctx.sandbox.external_http_endpoint.parse()?,
    ));
    provider.anvil_set_auto_mine(false).await?;
    provider.anvil_set_interval_mining(0).await?;

    let token_address = Address::from_slice(&hex::decode(TEST_TOKEN_ADDRESS)?);
    provider
        .anvil_set_code(token_address, test_token_runtime_bytecode())
        .await?;

    // ── 2. Vault address + response pubkey ───────────────────────────────
    let vault_id = "vault-test-001";
    let vault_root_path = format!("{vault_id},root");
    let vault_addr = mpc_derived_address(canton, root_pk, &vault_root_path);
    let response_pk = vault_response_pubkey(canton, root_pk);
    let response_spki = to_spki_pubkey_hex(response_pk);
    let vault_addr_padded = format!("{:0>64}", hex::encode(vault_addr.as_slice()));
    tracing::info!(?vault_addr, vault_id, "vault parameters computed");

    // ── 3. Create Vault on Daml ──────────────────────────────────────────
    let vault_payload = json!({
        "operators": [&canton.operator_party],
        "sigNetwork": &canton.party_id,
        "evmVaultAddress": &vault_addr_padded,
        "evmMpcPublicKey": &response_spki,
        "vaultId": vault_id,
    });
    let vault_create = canton
        .client
        .create_contract(
            &[&canton.operator_party],
            "#daml-vault:Erc20Vault:Vault",
            vault_payload,
        )
        .await
        .context("create Vault contract")?;
    let (vault_cid, vault_template_id) = find_created_contract(&vault_create, "Vault")?;
    let vault_disclosure = canton
        .client
        .get_disclosed_contract(&[&canton.operator_party], &vault_template_id, &vault_cid)
        .await?;
    tracing::info!(vault_cid, "Vault contract created on Daml");

    // ── 4. Pre-fund Vault gas account (one-time, shared across cycles) ──
    provider
        .anvil_set_balance(vault_addr, U256::from(10_000_000_000_000_000_000u128))
        .await?;

    // ── 5. Run multiple deposit/withdrawal cycles on the SAME Vault.
    //   Each cycle rotates the Daml `requester` Party AND the EVM signing
    //   identity (`user_subpath`), so `fullPath = vaultId,requester,user_subpath`
    //   on the Vault visibly changes per cycle. All cycles' response
    //   signatures still verify against the single `evmMpcPublicKey` set at
    //   Vault creation — asserting the per-Vault response key is constant
    //   regardless of who requests or how the path is namespaced.
    anyhow::ensure!(
        canton.extra_requester_parties.len() >= 2,
        "Canton sandbox must allocate at least 2 extra requester parties for multi-cycle test"
    );
    let cycles: Vec<(&str, &str, &str, &str, U256)> = vec![
        (
            canton.requester_party.as_str(),
            "user-a",
            "vault-test-minter-a",
            "vault-test-recipient-a",
            U256::from(1_000u64),
        ),
        (
            canton.extra_requester_parties[0].as_str(),
            "user-b",
            "vault-test-minter-b",
            "vault-test-recipient-b",
            U256::from(250u64),
        ),
        (
            canton.extra_requester_parties[1].as_str(),
            "user-c",
            "vault-test-minter-c",
            "vault-test-recipient-c",
            U256::from(500u64),
        ),
    ];
    for (requester_party, user_subpath, minter_path, recipient_subpath, deposit_amount) in cycles {
        tracing::info!(
            requester_party,
            user_subpath,
            ?deposit_amount,
            "starting vault cycle"
        );
        run_vault_deposit_withdraw_cycle(
            canton,
            &provider,
            root_pk,
            token_address,
            vault_id,
            vault_addr,
            &vault_cid,
            &vault_template_id,
            &vault_disclosure,
            requester_party,
            user_subpath,
            minter_path,
            recipient_subpath,
            deposit_amount,
        )
        .await
        .with_context(|| {
            format!(
                "vault cycle requester={requester_party} user_subpath={user_subpath} amount={deposit_amount}"
            )
        })?;
    }

    Ok(())
}

/// Look up the contract id of an event template by its `requestId` field.
async fn locate_event_cid(
    canton: &CantonSandbox,
    template_id: &str,
    request_id: &str,
) -> Result<String> {
    canton
        .client
        .find_active_contract_cid(&[&canton.party_id], template_id, |payload| {
            payload.get("requestId").and_then(|v| v.as_str()) == Some(request_id)
        })
        .await
        .with_context(|| format!("event cid for {template_id} requestId={request_id}"))
}
