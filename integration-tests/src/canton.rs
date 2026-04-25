use alloy::primitives::keccak256;
use anyhow::{Context as _, Result};
use async_process::{Child, Command};
use mpc_node::indexer_canton::contracts::{
    EvmTransactionParams, SignBidirectionalRequestedEvent, SignRequestPayload, TxParams,
};
use mpc_node::indexer_canton::ledger_api::{
    self, AllocatePartyRequest, AllocatePartyResponse, ContractEntry, CreateUserRequest,
    DisclosedContract, JsCommands, SubmitAndWaitForTransactionResponse, UserInfo,
};
use mpc_node::indexer_canton::{CantonConfig, CantonConn};
use mpc_node::protocol::Chain;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

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

const CANTON_JSON_API_PORT: u16 = 7575;
const DEFAULT_DAR_RELATIVE_PATH: &str = "fixtures/canton/daml-vault-0.0.1.dar";

/// Test EVM transaction params (USDC transfer on Anvil). Callers that need
/// distinct request_ids across submissions (e.g. concurrency tests) pass
/// different `nonce` values.
pub fn test_evm_params(nonce: u64) -> EvmTransactionParams {
    EvmTransactionParams {
        to: "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
        function_signature: "transfer(address,uint256)".to_string(),
        encoded_args: format!(
            "{}{}",
            "0".repeat(64),
            "0000000000000000000000000000000000000000000000000000000005f5e100"
        ),
        value: "0".repeat(64),
        nonce: format!("{:0>64x}", nonce),
        gas_limit: format!("{:0>64}", "186a0"),
        max_fee_per_gas: format!("{:0>64}", "3b9aca00"),
        max_priority_fee_per_gas: format!("{:0>64}", "3b9aca00"),
        chain_id: format!("{:0>64}", "7a69"), // Anvil 31337
    }
}

/// Build a test SignBidirectionalRequestedEvent for Canton.
/// Uses Anvil chain ID (31337) and default test EVM params.
///
/// `sender` is set to `computeOperatorsHash([operator])` — exactly what
/// `SignRequest.Execute` will compute on-ledger, so the locally computed
/// request_id matches the one the MPC node derives from the emitted event.
pub fn test_sign_request_event(
    sandbox: &CantonSandbox,
    nonce: Option<u64>,
) -> SignBidirectionalRequestedEvent {
    let operators = vec![sandbox.operator_party.clone()];
    let sender = compute_operators_hash(&operators);
    SignBidirectionalRequestedEvent {
        operators,
        requester: sandbox.requester_party.clone(),
        sig_network: sandbox.party_id.clone(),
        sender,
        tx_params: TxParams::EvmTxParams(test_evm_params(nonce.unwrap_or(0))),
        caip2_id: Chain::Ethereum.caip2_chain_id().to_string(),
        key_version: LATEST_MPC_KEY_VERSION,
        path: sandbox.requester_party.clone(),
        algo: String::new(),
        dest: String::new(),
        params: String::new(),
        output_deserialization_schema: r#"[{"name":"output","type":"bool"}]"#.to_string(),
        respond_serialization_schema: r#"[{"name":"respond","type":"bool"}]"#.to_string(),
    }
}

/// Build the SignRequest create payload from the test event (same fields minus `sender`).
pub fn test_sign_request_payload(event: &SignBidirectionalRequestedEvent) -> SignRequestPayload {
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

/// A running Canton sandbox process with JWT auth and deployed Daml contracts.
pub struct CantonSandbox {
    process: Child,
    jwt_key_path: PathBuf,
    jwt_cert_path: PathBuf,
    auth_conf_path: PathBuf,
    pub json_api_url: String,
    pub json_api_ws_url: String,
    pub jwt_private_key_pem: String,
    pub jwt_subject: String,
    pub party_id: String,
    pub operator_party: String,
    pub requester_party: String,
    pub signer_cid: String,
    pub signer_template_id: String,
    pub signer_disclosure: DisclosedContract,
    pub client: CantonTestClient,
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

        // Resolve DAR path (env var with fallback).
        let dar_path = match std::env::var("CANTON_DAR_PATH") {
            Ok(p) => PathBuf::from(p),
            Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_DAR_RELATIVE_PATH),
        };
        anyhow::ensure!(dar_path.exists(), "DAR not found at {}", dar_path.display());

        // Generate JWT key + cert + HOCON auth config.
        let tmp_dir = std::env::temp_dir();
        let id = uuid::Uuid::new_v4();
        let jwt_key_path = tmp_dir.join(format!("canton-jwt-{id}.key"));
        let jwt_cert_path = tmp_dir.join(format!("canton-jwt-{id}.crt"));
        let auth_conf_path = tmp_dir.join(format!("canton-auth-{id}.conf"));

        let output = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-noenc",
                "-days",
                "3650",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-keyout",
                &jwt_key_path.to_string_lossy(),
                "-out",
                &jwt_cert_path.to_string_lossy(),
                "-subj",
                "/CN=mpc-test-node",
            ])
            .output()
            .context("openssl not found — needed to generate JWT cert")?;
        anyhow::ensure!(output.status.success(), "openssl cert generation failed");

        let jwt_private_key_pem = std::fs::read_to_string(&jwt_key_path)?;
        std::fs::write(
            &auth_conf_path,
            format!(
                r#"canton.parameters.enable-alpha-state-via-config = yes
canton.parameters.state-refresh-interval = 5s
canton.participants.sandbox.alpha-dynamic.dars = [
  {{ location = "{}" }}
]
canton.participants.sandbox.ledger-api {{
  auth-services = [
    {{ type = jwt-es-256-crt, certificate = "{}" }}
  ]
  jwt-timestamp-leeway.default = 10
}}"#,
                dar_path.display(),
                jwt_cert_path.to_string_lossy()
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
        let admin_client =
            CantonTestClient::new(&base_url, "participant_admin", &jwt_private_key_pem)?;
        let probe_url = format!("{base_url}/v2/parties");
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
                .auth_post(&probe_url)?
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

        // Setup parties, user, and contracts.
        let user_id = format!("mpc-test-{}", uuid::Uuid::new_v4());
        let sig_network = admin_client.allocate_party("SigNetwork").await?;
        let operator = admin_client.allocate_party("Operator").await?;
        let requester = admin_client.allocate_party("Requester").await?;

        let mut rights = Vec::new();
        for party in [&sig_network, &operator, &requester] {
            rights.push(ledger_api::can_act_as(party));
            rights.push(ledger_api::can_read_as(party));
        }
        admin_client
            .auth_post(&format!("{base_url}/v2/users"))?
            .json(&CreateUserRequest {
                user: UserInfo {
                    id: user_id.clone(),
                    primary_party: sig_network.clone(),
                    is_deactivated: false,
                    identity_provider_id: String::new(),
                },
                rights,
            })
            .send()
            .await?
            .error_for_status()?;

        let client = CantonTestClient::new(&base_url, &user_id, &jwt_private_key_pem)?;

        let signer_result = client
            .create_contract(
                &[&sig_network],
                "#daml-signer:Signer:Signer",
                json!({ "sigNetwork": &sig_network }),
            )
            .await?;
        let (signer_cid, signer_template_id) = find_created_contract(&signer_result, "Signer")?;

        let signer_disclosure = client
            .get_disclosed_contract(&[&sig_network], "#daml-signer:Signer:Signer", &signer_cid)
            .await?;

        Ok(CantonSandbox {
            process,
            jwt_key_path,
            jwt_cert_path,
            auth_conf_path,
            json_api_url: base_url,
            json_api_ws_url: ws_url,
            jwt_private_key_pem,
            jwt_subject: user_id,
            party_id: sig_network,
            operator_party: operator,
            requester_party: requester,
            signer_cid,
            signer_template_id,
            signer_disclosure,
            client,
        })
    }

    /// Produce the CantonConfig for MPC node CLI args.
    pub fn get_config(&self) -> CantonConfig {
        CantonConfig {
            json_api_url: self.json_api_url.clone(),
            json_api_ws_url: self.json_api_ws_url.clone(),
            jwt_private_key_path: self.jwt_key_path.to_string_lossy().to_string(),
            jwt_subject: self.jwt_subject.clone(),
            party_id: self.party_id.clone(),
            signer_contract_id: self.signer_cid.clone(),
            signer_template_id: self.signer_template_id.clone(),
        }
    }

    /// Submit a test sign request. `nonce = None` uses the default (0); tests
    /// that need distinct request_ids across multiple submissions pass
    /// different `Some(n)` values so each submission hashes to a unique id.
    pub async fn submit_sign_request(&self, nonce: Option<u64>) -> Result<()> {
        let event = test_sign_request_event(self, nonce);
        let payload = test_sign_request_payload(&event);
        let sign_request = self
            .client
            .create_contract(
                &[&self.operator_party, &self.requester_party],
                "#daml-signer:Signer:SignRequest",
                serde_json::to_value(&payload)?,
            )
            .await?;
        let sign_request_cid = find_created_contract(&sign_request, "SignRequest")?.0;

        self.client
            .exercise_choice(
                &[&self.requester_party],
                &self.signer_template_id,
                &self.signer_cid,
                "SignBidirectional",
                json!({
                    "signRequestCid": sign_request_cid,
                    "requester": &self.requester_party,
                }),
                std::slice::from_ref(&self.signer_disclosure),
            )
            .await?;
        Ok(())
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
        let _ = std::fs::remove_file(&self.jwt_key_path);
        let _ = std::fs::remove_file(&self.jwt_cert_path);
        let _ = std::fs::remove_file(&self.auth_conf_path);
    }
}

#[derive(Clone)]
pub struct CantonTestClient {
    http: reqwest::Client,
    base_url: String,
    user_id: String,
    encoding_key: jsonwebtoken::EncodingKey,
}

impl CantonTestClient {
    pub fn new(base_url: &str, user_id: &str, jwt_private_key_pem: &str) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::new(),
            base_url: base_url.to_string(),
            user_id: user_id.to_string(),
            encoding_key: jsonwebtoken::EncodingKey::from_ec_pem(jwt_private_key_pem.as_bytes())?,
        })
    }

    fn auth_post(&self, url: &str) -> Result<reqwest::RequestBuilder> {
        Ok(self.http.post(url).bearer_auth(self.generate_jwt()?))
    }

    pub async fn allocate_party(&self, hint: &str) -> Result<String> {
        let body: AllocatePartyResponse = self
            .auth_post(&format!("{}/v2/parties", self.base_url))?
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
                    vec![],
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
            disclosed_contracts.to_vec(),
        )
        .await
    }

    async fn submit_command(
        &self,
        act_as: &[&str],
        command: ledger_api::Command,
        disclosed_contracts: Vec<DisclosedContract>,
    ) -> Result<SubmitAndWaitForTransactionResponse> {
        let parties: Vec<String> = act_as.iter().map(|s| s.to_string()).collect();
        let commands = JsCommands {
            command_id: uuid::Uuid::new_v4().to_string(),
            user_id: self.user_id.clone(),
            act_as: parties.clone(),
            read_as: parties,
            commands: vec![command],
            disclosed_contracts,
        };
        self.submit_and_wait(commands, "command").await
    }

    pub async fn get_disclosed_contract(
        &self,
        parties: &[&str],
        template_id: &str,
        contract_id: &str,
    ) -> Result<DisclosedContract> {
        let entries = self
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

impl CantonConn for CantonTestClient {
    fn http(&self) -> &reqwest::Client {
        &self.http
    }
    fn json_api_url(&self) -> &str {
        &self.base_url
    }
    fn jwt_encoding_key(&self) -> &jsonwebtoken::EncodingKey {
        &self.encoding_key
    }
    fn jwt_subject(&self) -> &str {
        &self.user_id
    }
}

fn is_package_not_ready(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("PACKAGE_SELECTION_FAILED")
        || msg.contains("JSON_API_PACKAGE_SELECTION_FAILED")
        || msg.contains("PACKAGE_NAMES_NOT_FOUND")
        || msg.contains("TEMPLATES_OR_INTERFACES_NOT_FOUND")
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
