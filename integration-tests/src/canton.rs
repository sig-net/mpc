use crate::canton_auth::{
    OidcTestProvider, LOCAL_OIDC_AUDIENCE, LOCAL_OIDC_CLIENT_SECRET, LOCAL_OIDC_SCOPE,
};
use alloy::primitives::keccak256;
use anyhow::{Context as _, Result};
use async_process::{Child, Command};
use mpc_chain_integration_core::NoopPublisherTelemetry;
use mpc_node::indexer_canton::contracts::{
    EvmAccessListEntry, EvmType2TransactionParams, SignBidirectionalRequestedEvent, TxParams,
};
use mpc_node::indexer_canton::ledger_api::{
    self, AllocatePartyRequest, AllocatePartyResponse, ContractEntry, CreateUserRequest,
    DisclosedContract, JsCommands, SubmitAndWaitForTransactionResponse, UserInfo,
};
use mpc_node::indexer_canton::{CantonAuthConfig, CantonConfig};
use mpc_node::protocol::Chain;
use mpc_node::rpc::CantonClient;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const CANTON_JSON_API_PORT: u16 = 7575;
const DEFAULT_DAR_RELATIVE_PATH: &str = "fixtures/canton/signet-signer-v1-0.0.1.dar";
const DEFAULT_FEE_DAR_RELATIVE_PATH: &str = "fixtures/canton/signet-fee-amulet-0.0.1.dar";

/// Charge-context key; mirrors Daml `Signet.Fee.Amulet.priceConfigContextKey`.
const PRICE_CONFIG_CONTEXT_KEY: &str = "signet.network/fee/price-config";

// Package-name template refs (stable across DAR upgrades), used at create + disclosure sites.
const SIGNER_TEMPLATE_ID: &str = "#signet-signer-v1:Signer:Signer";
const SIGNER_PROPOSAL_TEMPLATE_ID: &str = "#signet-signer-v1:Signer:SignerProposal";
const FEE_REGISTRATION_TEMPLATE_ID: &str =
    "#signet-api-fee-v1:Signet.Api.Fee.V1:FeeCollectorRegistration";
const CC_FEE_COLLECTOR_TEMPLATE_ID: &str = "#signet-fee-amulet:Signet.Fee.Amulet:CcFeeCollector";
const FEE_PRICE_CONFIG_TEMPLATE_ID: &str = "#signet-fee-amulet:Signet.Fee.Amulet:FeePriceConfig";
pub const EVM_TYPE2_TEST_CONTRACT_ADDRESS: &str = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const EVM_TYPE2_BOOL_OUTPUT_SCHEMA: &str = r#"[{"name":"output","type":"bool"}]"#;

/// Mirror of Daml `computeOperatorsHash` (Signer.daml → RequestId.daml):
/// `keccak256(mconcat(map (keccak256 . toHex) (sort operatorTexts)))`.
///
/// Golden vector verified in TS+Daml: `["Alice","Bob"]` →
/// `9b1a0a45cfdc60f45820808958c1895d44da61c8f804f5560020a373b23ad51e`.
pub fn compute_operators_hash(operators: &[String]) -> String {
    let mut sorted: Vec<&String> = operators.iter().collect();
    sorted.sort();
    let mut concat = Vec::with_capacity(sorted.len() * 32);
    for op in sorted {
        concat.extend_from_slice(keccak256(op.as_bytes()).as_slice());
    }
    hex::encode(keccak256(&concat))
}

fn evm_u256_hex(value: u128) -> String {
    format!("{value:064x}")
}

fn evm_type2_anvil_params(
    nonce: u64,
    gas_limit: u64,
    to: Option<&str>,
    value: u128,
    calldata: impl Into<String>,
    access_list: Vec<EvmAccessListEntry>,
) -> EvmType2TransactionParams {
    EvmType2TransactionParams {
        chain_id: evm_u256_hex(31_337),
        nonce: evm_u256_hex(nonce as u128),
        max_priority_fee_per_gas: evm_u256_hex(1_000_000_000),
        max_fee_per_gas: evm_u256_hex(100_000_000_000),
        gas_limit: evm_u256_hex(gas_limit as u128),
        to: to.map(str::to_string),
        value: evm_u256_hex(value),
        calldata: calldata.into(),
        access_list,
    }
}

#[derive(Clone)]
pub struct EvmType2AnvilCase {
    pub name: &'static str,
    pub params: EvmType2TransactionParams,
}

impl EvmType2AnvilCase {
    pub fn with_nonce(mut self, nonce: u64) -> Self {
        self.params.nonce = evm_u256_hex(nonce as u128);
        self
    }
}

/// Valid EIP-1559 variants that should all pass Daml `EvmType2TransactionParams`
/// validation, Rust `TxEip1559` construction, Anvil execution, and Canton
/// response publication.
pub fn test_evm_type2_anvil_cases() -> Vec<EvmType2AnvilCase> {
    vec![
        EvmType2AnvilCase {
            name: "evm_type2_call_contract_erc20_transfer_calldata",
            params: evm_type2_anvil_params(
                0,
                100_000,
                Some(EVM_TYPE2_TEST_CONTRACT_ADDRESS),
                0,
                format!(
                    "{}{}{}",
                    "a9059cbb",
                    "0".repeat(64),
                    "0000000000000000000000000000000000000000000000000000000005f5e100"
                ),
                vec![],
            ),
        },
        EvmType2AnvilCase {
            name: "evm_type2_call_value_transfer_empty_calldata",
            params: evm_type2_anvil_params(
                1,
                21_000,
                Some("1111111111111111111111111111111111111111"),
                1,
                "",
                vec![],
            ),
        },
        EvmType2AnvilCase {
            name: "evm_type2_call_access_list",
            params: evm_type2_anvil_params(
                2,
                100_000,
                Some("2222222222222222222222222222222222222222"),
                0,
                "",
                vec![EvmAccessListEntry {
                    address: "3333333333333333333333333333333333333333".to_string(),
                    storage_keys: vec!["0".repeat(64), "f".repeat(64)],
                }],
            ),
        },
        // TODO(#808): re-enable when CREATE is supported. The node bails on
        // CREATE in chain-signatures/node/src/respond_bidirectional.rs:150,
        // which leaves the bidirectional watcher pending indefinitely and the
        // test times out waiting for RespondBidirectionalEvent.
        // EvmType2AnvilCase {
        //     name: "evm_type2_create_empty_initcode",
        //     params: evm_type2_anvil_params(3, 100_000, None, 0, "", vec![]),
        // },
    ]
}

/// Build a test SignBidirectionalRequestedEvent for Canton.
///
/// `sender` is set to `computeOperatorsHash([operator])` — exactly what
/// `Signer.RequestSignature` will compute on-ledger, so the locally computed
/// request_id matches the one the MPC node derives from the emitted event.
pub fn test_sign_request_event(
    sandbox: &CantonSandbox,
    case: &EvmType2AnvilCase,
) -> SignBidirectionalRequestedEvent {
    let operators = vec![sandbox.operator_party.clone()];
    let sender = compute_operators_hash(&operators);
    SignBidirectionalRequestedEvent {
        operators,
        requester: sandbox.requester_party.clone(),
        sig_network: sandbox.party_id.clone(),
        sender,
        tx_params: TxParams::EvmType2TxParams(case.params.clone()),
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        path: sandbox.requester_party.clone(),
        algo: String::new(),
        dest: String::new(),
        params: String::new(),
        output_deserialization_schema: EVM_TYPE2_BOOL_OUTPUT_SCHEMA.to_string(),
        respond_serialization_schema: EVM_TYPE2_BOOL_OUTPUT_SCHEMA.to_string(),
    }
}

/// A running Canton sandbox process with OAuth token retrieval and deployed Daml contracts.
pub struct CantonSandbox {
    process: Child,
    auth_conf_path: PathBuf,
    oidc_provider: OidcTestProvider,
    pub json_api_url: String,
    pub json_api_ws_url: String,
    pub app_ledger_api_user: String,
    pub ledger_api_user: String,
    pub party_id: String,
    pub sig_network_fa_party: String,
    pub operator_party: String,
    pub requester_party: String,
    pub signer_cid: String,
    pub signer_template_id: String,
    pub signer_disclosure: DisclosedContract,
    /// Active `FeeCollectorRegistration` cid — the `feeRegistrationCid` choice arg.
    pub fee_registration_cid: String,
    /// Current `FeePriceConfig` cid — referenced via the fee charge context.
    pub fee_price_config_cid: String,
    /// Disclosures a fee-bearing submission attaches: registration, collector, price config.
    pub fee_disclosures: Vec<DisclosedContract>,
    pub sig_network_runtime_client: CantonTestClient,
    pub requester_workflow_client: CantonTestClient,
}

impl CantonSandbox {
    pub async fn run() -> Result<Self> {
        // Ensure Canton ports are free (previous sandbox may still be shutting down).
        for port in [CANTON_JSON_API_PORT, 6868] {
            for _ in 0..40 {
                if tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            anyhow::ensure!(
                tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_err(),
                "port {port} still in use — previous Canton did not exit"
            );
        }

        // Two DARs: signer (Signer + frozen fee API) and fee impl (CcFeeCollector/FeePriceConfig).
        let dar_path = match std::env::var("CANTON_DAR_PATH") {
            Ok(p) => PathBuf::from(p),
            Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_DAR_RELATIVE_PATH),
        };
        anyhow::ensure!(dar_path.exists(), "DAR not found at {}", dar_path.display());
        let fee_dar_path = match std::env::var("CANTON_FEE_DAR_PATH") {
            Ok(p) => PathBuf::from(p),
            Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_FEE_DAR_RELATIVE_PATH),
        };
        anyhow::ensure!(
            fee_dar_path.exists(),
            "fee DAR not found at {}",
            fee_dar_path.display()
        );

        // Start the local OAuth/JWKS test provider before writing Canton auth config.
        // Canton will validate bearer tokens by fetching this provider's JWKS.
        let oidc_provider = OidcTestProvider::run().await?;

        let tmp_dir = std::env::temp_dir();
        let id = uuid::Uuid::new_v4();
        let auth_conf_path = tmp_dir.join(format!("canton-oauth-auth-{id}.conf"));

        // Generate HOCON auth config that matches the production-shaped Auth0 flow:
        // OAuth client credentials for token retrieval, JWKS for token verification.
        // Real Canton node auth wiring is generated by DA's splice Helm charts from:
        // - https://github.com/sig-net/sig-kustomize/blob/5d2dff84eb243cc3ac1eec9f6ff042dbd731e0ec/kustomize/Canton/canton-validator/overlays/mainnet/values/participant-values.yaml
        // - https://github.com/sig-net/sig-kustomize/blob/5d2dff84eb243cc3ac1eec9f6ff042dbd731e0ec/kustomize/Canton/canton-validator/overlays/mainnet/values/validator-values.yaml
        // - https://github.com/sig-net/sig-kustomize/blob/5d2dff84eb243cc3ac1eec9f6ff042dbd731e0ec/kustomize/Canton/canton-validator/overlays/mainnet/values/standalone-participant-values.yaml
        // - https://github.com/sig-net/sig-kustomize/blob/5d2dff84eb243cc3ac1eec9f6ff042dbd731e0ec/kustomize/Canton/canton-validator/overlays/mainnet/validator-external-secrets/validator-ledger-api-auth-external-secret.yaml
        std::fs::write(
            &auth_conf_path,
            format!(
                r#"canton.parameters.enable-alpha-state-via-config = yes
canton.parameters.non-standard-config = yes
canton.parameters.state-refresh-interval = 5s
canton.participants.sandbox.alpha-dynamic {{
  dars = [
    {{ location = "{}" }},
    {{ location = "{}" }}
  ]
  # The local client-credentials tokens resolve against Canton's default
  # identity provider, so the bootstrap admin user must remain in Default.
  users = [
    {{
      user = "participant_admin"
      rights = {{ participant-admin = true }}
    }}
  ]
}}
canton.participants.sandbox.ledger-api {{
  auth-services = [
    {{ type = jwt-jwks, url = "{}", target-audience = "{}" }}
  ]
  admin-token-config.admin-claim = true
  jwt-timestamp-leeway.default = 10
}}"#,
                dar_path.display(),
                fee_dar_path.display(),
                oidc_provider.jwks_url(),
                LOCAL_OIDC_AUDIENCE
            ),
        )?;

        // Start dpm sandbox with auth + declarative DAR loading.
        let process = Command::new("dpm")
            .arg("sandbox")
            .arg("--json-api-port")
            .arg(CANTON_JSON_API_PORT.to_string())
            .arg("-c")
            .arg(&auth_conf_path)
            .spawn()
            .context("failed to start dpm sandbox")?;

        let base_url = format!("http://127.0.0.1:{CANTON_JSON_API_PORT}");
        let ws_url = format!("ws://127.0.0.1:{CANTON_JSON_API_PORT}");

        // Wait for synchronizer readiness (covers HTTP not up + auth loading + synchronizer).
        let admin_client = CantonTestClient::new(canton_test_client_config(
            &base_url,
            &ws_url,
            oidc_provider.token_url(),
            "participant_admin",
            "",
        ))
        .await?;
        let probe = AllocatePartyRequest {
            party_id_hint: "_readiness_probe".to_string(),
            identity_provider_id: Some(String::new()),
            synchronizer_id: Some(String::new()),
            user_id: Some(String::new()),
        };
        for attempt in 0..120u32 {
            // Only 200 (party created) or 409 (already exists) mean fully ready.
            // Everything else (401 auth loading, 403 admin not ready, 400
            // synchronizer not connected, connection refused) = retry.
            let ready = match admin_client
                .auth_post("/v2/parties")
                .await?
                .json(&probe)
                .send()
                .await
            {
                Ok(r) => r.status().as_u16() == 200 || r.status().as_u16() == 409,
                Err(_) => false,
            };
            if ready {
                tracing::info!("canton ready after {attempt} attempts");
                break;
            }
            anyhow::ensure!(
                attempt < 119,
                "canton sandbox did not become ready within 60s"
            );
            if attempt % 10 == 0 {
                tracing::debug!("waiting for canton (attempt {attempt})...");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Setup parties, runtime/app users, and contracts.
        let sig_network_runtime_user_id =
            format!("mpc-sig-network-runtime-{}", uuid::Uuid::new_v4());
        let fa_admin_user_id = format!("mpc-fa-admin-{}", uuid::Uuid::new_v4());
        let requester_workflow_user_id = format!("mpc-requester-workflow-{}", uuid::Uuid::new_v4());
        let sig_network = admin_client.allocate_party("SigNetwork").await?;
        let sig_network_fa = admin_client.allocate_party("SigNetworkFA").await?;
        let operator = admin_client.allocate_party("Operator").await?;
        let requester = admin_client.allocate_party("Requester").await?;

        // Runtime user is the MPC node identity. It should only act/read as
        // the SigNetwork party used by Signer runtime choices.
        let runtime_rights = vec![
            ledger_api::can_act_as(&sig_network),
            ledger_api::can_read_as(&sig_network),
        ];
        admin_client
            .create_user(&sig_network_runtime_user_id, &sig_network, runtime_rights)
            .await?;

        // FA admin = featured-app/fee identity: co-signs the Signer and owns the fee contracts.
        let fa_rights = vec![
            ledger_api::can_act_as(&sig_network_fa),
            ledger_api::can_read_as(&sig_network_fa),
        ];
        admin_client
            .create_user(&fa_admin_user_id, &sig_network_fa, fa_rights)
            .await?;

        // App/test user drives requester/operator workflow traffic and can read
        // SigNetwork events, but it is not the runtime signer identity.
        let app_rights = vec![
            ledger_api::can_act_as(&operator),
            ledger_api::can_read_as(&operator),
            ledger_api::can_act_as(&requester),
            ledger_api::can_read_as(&requester),
            ledger_api::can_read_as(&sig_network),
        ];
        admin_client
            .create_user(&requester_workflow_user_id, &requester, app_rights)
            .await?;

        let sig_network_runtime_client = CantonTestClient::new(canton_test_client_config(
            &base_url,
            &ws_url,
            oidc_provider.token_url(),
            &sig_network_runtime_user_id,
            &sig_network,
        ))
        .await?;

        let fa_admin_client = CantonTestClient::new(canton_test_client_config(
            &base_url,
            &ws_url,
            oidc_provider.token_url(),
            &fa_admin_user_id,
            &sig_network_fa,
        ))
        .await?;

        let requester_workflow_client = CantonTestClient::new(canton_test_client_config(
            &base_url,
            &ws_url,
            oidc_provider.token_url(),
            &requester_workflow_user_id,
            &requester,
        ))
        .await?;

        // Two-party Signer ceremony (SignerProposal → AcceptSigner). The proposal uses the
        // runtime client so later runtime choices share its party/user pair.
        let proposal_result = sig_network_runtime_client
            .create_contract(
                &[&sig_network],
                SIGNER_PROPOSAL_TEMPLATE_ID,
                json!({ "sigNetwork": &sig_network, "sigNetworkFA": &sig_network_fa }),
            )
            .await?;
        let (proposal_cid, _) = find_created_contract(&proposal_result, "SignerProposal")?;
        let accept_result = fa_admin_client
            .exercise_choice(
                &[&sig_network_fa],
                SIGNER_PROPOSAL_TEMPLATE_ID,
                &proposal_cid,
                "AcceptSigner",
                json!({}),
                &[],
            )
            .await?;
        let (signer_cid, _) = find_created_contract(&accept_result, "Signer")?;
        let signer_template_id = SIGNER_TEMPLATE_ID.to_string();

        let signer_disclosure = sig_network_runtime_client
            .get_disclosed_contract(&[&sig_network], &signer_template_id, &signer_cid)
            .await?;

        // Fee infrastructure (sigNetworkFA-signed). A zero-fee FeePriceConfig is the
        // production "free mode" that skips the CC transfer, keeping tests off Splice Amulet.
        let collector_result = fa_admin_client
            .create_contract(
                &[&sig_network_fa],
                CC_FEE_COLLECTOR_TEMPLATE_ID,
                json!({
                    "sigNetworkFA": &sig_network_fa,
                    "feeReceiver": &sig_network_fa,
                    "meta": { "values": {} },
                }),
            )
            .await?;
        let (collector_cid, _) = find_created_contract(&collector_result, "CcFeeCollector")?;

        let registration_result = fa_admin_client
            .create_contract(
                &[&sig_network_fa],
                FEE_REGISTRATION_TEMPLATE_ID,
                json!({
                    "sigNetworkFA": &sig_network_fa,
                    "collector": &collector_cid,
                    "meta": { "values": {} },
                }),
            )
            .await?;
        let (fee_registration_cid, _) =
            find_created_contract(&registration_result, "FeeCollectorRegistration")?;

        // Wide validity window (wall-clock sandbox); window-edge cases live in the canton Daml tests.
        let price_config_result = fa_admin_client
            .create_contract(
                &[&sig_network_fa],
                FEE_PRICE_CONFIG_TEMPLATE_ID,
                json!({
                    "sigNetworkFA": &sig_network_fa,
                    "feeReceiver": &sig_network_fa,
                    "instrumentAdmin": &sig_network_fa,
                    "instrumentId": "Amulet",
                    "feeAmount": "0.0",
                    "validFrom": "2020-01-01T00:00:00Z",
                    "validUntil": "2099-01-01T00:00:00Z",
                    // Send Int64 as a string (JSON API canonical form).
                    "version": "0",
                    "meta": { "values": {} },
                }),
            )
            .await?;
        let (fee_price_config_cid, _) =
            find_created_contract(&price_config_result, "FeePriceConfig")?;

        // Fee disclosures attached per submission (the FA fee endpoint serves these in prod).
        let mut fee_disclosures = Vec::new();
        for (template_id, cid) in [
            (FEE_REGISTRATION_TEMPLATE_ID, &fee_registration_cid),
            (CC_FEE_COLLECTOR_TEMPLATE_ID, &collector_cid),
            (FEE_PRICE_CONFIG_TEMPLATE_ID, &fee_price_config_cid),
        ] {
            fee_disclosures.push(
                fa_admin_client
                    .get_disclosed_contract(&[&sig_network_fa], template_id, cid)
                    .await?,
            );
        }

        Ok(CantonSandbox {
            process,
            auth_conf_path,
            oidc_provider,
            json_api_url: base_url,
            json_api_ws_url: ws_url,
            app_ledger_api_user: requester_workflow_user_id,
            ledger_api_user: sig_network_runtime_user_id,
            party_id: sig_network,
            sig_network_fa_party: sig_network_fa,
            operator_party: operator,
            requester_party: requester,
            signer_cid,
            signer_template_id,
            signer_disclosure,
            fee_registration_cid,
            fee_price_config_cid,
            fee_disclosures,
            sig_network_runtime_client,
            requester_workflow_client,
        })
    }

    /// Produce the CantonConfig for MPC node CLI args.
    pub fn get_config(&self) -> CantonConfig {
        // MPC runtime config must use the runtime user plus the SigNetwork party,
        // not the app/test user that submits SignRequest workflow commands.
        CantonConfig {
            json_api_url: self.json_api_url.clone(),
            json_api_ws_url: self.json_api_ws_url.clone(),
            auth: CantonAuthConfig {
                token_url: self.oidc_provider.token_url().to_string(),
                client_id: self.ledger_api_user.clone(),
                client_secret: LOCAL_OIDC_CLIENT_SECRET.to_string(),
                audience: LOCAL_OIDC_AUDIENCE.to_string(),
                scope: Some(LOCAL_OIDC_SCOPE.to_string()),
            },
            ledger_api_user: self.ledger_api_user.clone(),
            party_id: self.party_id.clone(),
            signer_contract_id: self.signer_cid.clone(),
            signer_template_id: self.signer_template_id.clone(),
        }
    }

    pub async fn generate_untrusted_test_access_token(&self, subject: &str) -> Result<String> {
        self.oidc_provider.untrusted_access_token(subject).await
    }

    /// Submit a test sign request. `nonce = None` uses the default (0); tests
    /// that need distinct request_ids across multiple submissions pass
    /// different `Some(n)` values so each submission hashes to a unique id.
    pub async fn submit_sign_request(&self, nonce: Option<u64>) -> Result<()> {
        let case = test_evm_type2_anvil_cases()[0]
            .clone()
            .with_nonce(nonce.unwrap_or(0));
        self.submit_sign_request_case(&case).await
    }

    /// Exercise `Signer.RequestSignature` for an EVM case — one atomic tx that charges
    /// the (zero) CC fee and emits the `SignBidirectionalEvent` the MPC watches. Acts as
    /// operators + requester (the controllers); the Signer + fee disclosures ride along.
    pub async fn submit_sign_request_case(&self, case: &EvmType2AnvilCase) -> Result<()> {
        let event = test_sign_request_event(self, case);
        let args = self.request_signature_args(&event);
        let mut disclosures = vec![self.signer_disclosure.clone()];
        disclosures.extend(self.fee_disclosures.iter().cloned());
        self.requester_workflow_client
            .exercise_choice(
                &[&self.operator_party, &self.requester_party],
                &self.signer_template_id,
                &self.signer_cid,
                "RequestSignature",
                args,
                &disclosures,
            )
            .await?;
        Ok(())
    }

    /// `Signer.RequestSignature` args for a test event: request fields mirror the event
    /// (minus the ledger-derived `sender`/`sigNetwork`/`sigNetworkFA`) plus zero-fee args
    /// (registration + price config, no holdings). A non-zero fee needs more (see `Signet.Fee.Amulet`).
    fn request_signature_args(&self, event: &SignBidirectionalRequestedEvent) -> Value {
        json!({
            "operators": event.operators,
            "requester": event.requester,
            "txParams": event.tx_params,
            "caip2Id": event.caip2_id,
            // Send Int64 as a string (JSON API canonical form).
            "keyVersion": event.key_version.to_string(),
            "path": event.path,
            "algo": event.algo,
            "dest": event.dest,
            "params": event.params,
            "outputDeserializationSchema": event.output_deserialization_schema,
            "respondSerializationSchema": event.respond_serialization_schema,
            "feeRegistrationCid": self.fee_registration_cid,
            "feeInputs": [],
            "feeExtraArgs": {
                "context": {
                    "values": {
                        PRICE_CONFIG_CONTEXT_KEY: {
                            "tag": "AV_ContractId",
                            "value": self.fee_price_config_cid,
                        },
                    },
                },
                "meta": { "values": {} },
            },
        })
    }
}

impl Drop for CantonSandbox {
    fn drop(&mut self) {
        // Kill the dpm process tree. `pkill -P` gets children first.
        let pid = self.process.id();
        let _ = std::process::Command::new("pkill")
            .args(["-9", "-P", &pid.to_string()])
            .output();
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output();
        // Also kill any orphaned JVMs from this sandbox (reparented to init).
        // Use `pkill -f` with the specific config path to avoid killing unrelated processes.
        let conf = self.auth_conf_path.to_string_lossy();
        let _ = std::process::Command::new("pkill")
            .args(["-9", "-f", &conf])
            .output();
        // Wait for ports to be released.
        for port in [CANTON_JSON_API_PORT, 6868] {
            for _ in 0..40 {
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
        tracing::info!("canton sandbox cleaned up (pid {pid})");
        let _ = std::fs::remove_file(&self.auth_conf_path);
    }
}

#[derive(Clone)]
pub struct CantonTestClient {
    ledger_client: CantonClient,
}

impl CantonTestClient {
    pub async fn new(config: CantonConfig) -> Result<Self> {
        Ok(Self {
            ledger_client: CantonClient::new(&config, Arc::new(NoopPublisherTelemetry)).await?,
        })
    }

    async fn auth_post(&self, path: &str) -> Result<reqwest::RequestBuilder> {
        self.ledger_client.auth_post(path).await
    }

    pub async fn allocate_party(&self, hint: &str) -> Result<String> {
        let body: AllocatePartyResponse = self
            .auth_post("/v2/parties")
            .await?
            .json(&AllocatePartyRequest {
                party_id_hint: hint.to_string(),
                identity_provider_id: None,
                synchronizer_id: None,
                user_id: None,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(body.party_details.party)
    }

    pub async fn create_user(
        &self,
        user_id: &str,
        primary_party: &str,
        rights: Vec<ledger_api::UserRight>,
    ) -> Result<()> {
        self.auth_post("/v2/users")
            .await?
            .json(&CreateUserRequest {
                user: UserInfo {
                    id: user_id.to_string(),
                    primary_party: primary_party.to_string(),
                    is_deactivated: false,
                    identity_provider_id: String::new(),
                },
                rights,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn create_contract(
        &self,
        act_as: &[&str],
        template_id: &str,
        args: Value,
    ) -> Result<SubmitAndWaitForTransactionResponse> {
        // Retry while alpha-dynamic.dars is still vetting packages.
        for attempt in 0..30u32 {
            match self
                .submit_command(
                    act_as,
                    ledger_api::Command::CreateCommand {
                        template_id: template_id.to_string(),
                        create_arguments: args.clone(),
                    },
                    &[],
                )
                .await
            {
                Ok(resp) => return Ok(resp),
                Err(e) if attempt < 29 && is_package_not_ready(&e) => {
                    if attempt % 5 == 0 {
                        tracing::debug!(
                            "create_contract({template_id}) retrying (attempt {attempt})"
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    pub async fn exercise_choice(
        &self,
        act_as: &[&str],
        template_id: &str,
        contract_id: &str,
        choice: &str,
        choice_argument: Value,
        disclosed_contracts: &[DisclosedContract],
    ) -> Result<SubmitAndWaitForTransactionResponse> {
        self.submit_command(
            act_as,
            ledger_api::Command::ExerciseCommand {
                template_id: template_id.to_string(),
                contract_id: contract_id.to_string(),
                choice: choice.to_string(),
                choice_argument,
            },
            disclosed_contracts,
        )
        .await
    }

    async fn submit_command(
        &self,
        act_as: &[&str],
        command: ledger_api::Command,
        disclosed_contracts: &[DisclosedContract],
    ) -> Result<SubmitAndWaitForTransactionResponse> {
        let parties: Vec<String> = act_as.iter().map(|s| s.to_string()).collect();
        let commands = JsCommands {
            command_id: uuid::Uuid::new_v4().to_string(),
            user_id: self.ledger_client.ledger_api_user().to_string(),
            act_as: parties.clone(),
            read_as: parties,
            commands: vec![command],
            disclosed_contracts: disclosed_contracts.to_vec(),
        };
        self.ledger_client
            .submit_and_wait(commands, "command")
            .await
    }

    pub async fn get_disclosed_contract(
        &self,
        parties: &[&str],
        template_id: &str,
        contract_id: &str,
    ) -> Result<DisclosedContract> {
        let entries = self
            .ledger_client
            .fetch_active_contracts(parties, Some(template_id), true)
            .await?;
        for entry in &entries {
            if let Some(ContractEntry::JsActiveContract(ac)) = &entry.contract_entry {
                if ac.created_event.contract_id == contract_id {
                    return Ok(DisclosedContract {
                        template_id: ac.created_event.template_id.clone(),
                        contract_id: ac.created_event.contract_id.clone(),
                        created_event_blob: ac
                            .created_event
                            .created_event_blob
                            .clone()
                            .unwrap_or_default(),
                        synchronizer_id: ac.synchronizer_id.clone(),
                    });
                }
            }
        }
        anyhow::bail!("disclosed contract not found for {contract_id}")
    }

    /// Poll for a contract matching the given predicate, returning the typed payload.
    ///
    /// Deserializes each contract's payload into `T` and passes it to the predicate.
    /// Returns the first payload where the predicate returns `true`.
    pub async fn poll_for_contract<T>(
        &self,
        parties: &[&str],
        template_id: &str,
        predicate: impl Fn(&T) -> bool,
        timeout: Duration,
    ) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("timeout waiting for {template_id} after {timeout:?}");
            }
            let entries = self
                .ledger_client
                .fetch_active_contracts(parties, Some(template_id), false)
                .await?;
            for entry in &entries {
                if let Some(ContractEntry::JsActiveContract(ac)) = &entry.contract_entry {
                    if let Ok(payload) =
                        serde_json::from_value::<T>(ac.created_event.payload.clone())
                    {
                        if predicate(&payload) {
                            return Ok(payload);
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}

fn is_package_not_ready(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("PACKAGE_SELECTION_FAILED")
        || msg.contains("JSON_API_PACKAGE_SELECTION_FAILED")
        || msg.contains("PACKAGE_NAMES_NOT_FOUND")
        || msg.contains("TEMPLATES_OR_INTERFACES_NOT_FOUND")
}

fn canton_test_client_config(
    base_url: &str,
    ws_url: &str,
    token_url: &str,
    ledger_api_user: &str,
    party_id: &str,
) -> CantonConfig {
    CantonConfig {
        json_api_url: base_url.to_string(),
        json_api_ws_url: ws_url.to_string(),
        auth: CantonAuthConfig {
            token_url: token_url.to_string(),
            client_id: ledger_api_user.to_string(),
            client_secret: LOCAL_OIDC_CLIENT_SECRET.to_string(),
            audience: LOCAL_OIDC_AUDIENCE.to_string(),
            scope: Some(LOCAL_OIDC_SCOPE.to_string()),
        },
        ledger_api_user: ledger_api_user.to_string(),
        party_id: party_id.to_string(),
        signer_contract_id: String::new(),
        signer_template_id: String::new(),
    }
}

pub fn find_created_contract(
    resp: &SubmitAndWaitForTransactionResponse,
    suffix: &str,
) -> Result<(String, String)> {
    for event in &resp.transaction.events {
        if let ledger_api::Event::CreatedEvent(created) = event {
            if ledger_api::template_suffix_matches(&created.template_id, suffix) {
                return Ok((created.contract_id.clone(), created.template_id.clone()));
            }
        }
    }
    anyhow::bail!("no CreatedEvent for {suffix}")
}
