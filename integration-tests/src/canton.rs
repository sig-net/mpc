use anyhow::{Context as _, Result};
use async_process::{Child, Command};
use mpc_node::indexer_canton::ledger_api::{
    self, AllocatePartyRequest, AllocatePartyResponse, ContractEntry, CreateUserRequest,
    DisclosedContract, JsActiveContract, JsCommands, SubmitAndWaitForTransactionRequest,
    SubmitAndWaitForTransactionResponse, UserInfo,
};
use mpc_node::indexer_canton::{self, CantonConfig};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

const CANTON_JSON_API_PORT: u16 = 7575;
const DEFAULT_DAR_RELATIVE_PATH: &str = "fixtures/canton/daml-vault-0.0.1.dar";

// ---------------------------------------------------------------------------
// CantonSandbox
// ---------------------------------------------------------------------------

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
    pub vault_cid: String,
    pub vault_disclosure: DisclosedContract,
    pub signer_disclosure: DisclosedContract,
    pub nonce_cid: String,
    pub client: CantonTestClient,
}

impl CantonSandbox {
    pub async fn run() -> Result<Self> {
        // 0. Ensure Canton ports are free (previous sandbox may still be shutting down).
        for port in [CANTON_JSON_API_PORT, 6868] {
            for _ in 0..40 {
                if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            anyhow::ensure!(
                tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err(),
                "port {port} still in use — previous Canton did not exit"
            );
        }

        // 1. Resolve DAR path (env var with fallback)
        let dar_path = match std::env::var("CANTON_DAR_PATH") {
            Ok(p) => PathBuf::from(p),
            Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_DAR_RELATIVE_PATH),
        };
        anyhow::ensure!(dar_path.exists(), "DAR not found at {}", dar_path.display());

        // 2. Generate JWT key + cert + HOCON auth config (includes alpha-dynamic.dars).
        let tmp_dir = std::env::temp_dir();
        let id = uuid::Uuid::new_v4();
        let jwt_key_path = tmp_dir.join(format!("canton-jwt-{id}.key"));
        let jwt_cert_path = tmp_dir.join(format!("canton-jwt-{id}.crt"));
        let auth_conf_path = tmp_dir.join(format!("canton-auth-{id}.conf"));

        let output = std::process::Command::new("openssl")
            .args([
                "req", "-x509", "-noenc", "-days", "3650", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-keyout", &jwt_key_path.to_string_lossy(),
                "-out", &jwt_cert_path.to_string_lossy(),
                "-subj", "/CN=mpc-test-node",
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

        // 3. Start dpm sandbox with auth + declarative DAR loading.
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

        // 4. Wait for synchronizer readiness (covers HTTP not up + auth loading + synchronizer).
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
            let ready = match admin_client.auth_post(&probe_url)?.json(&probe).send().await {
                Ok(r) => r.status().as_u16() == 200 || r.status().as_u16() == 409,
                Err(_) => false,
            };
            if ready {
                tracing::info!("canton ready after {attempt} attempts");
                break;
            }
            anyhow::ensure!(attempt < 119, "canton sandbox did not become ready within 60s");
            if attempt % 10 == 0 {
                tracing::debug!("waiting for canton (attempt {attempt})...");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // 5. Setup parties, user, and contracts.
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

        let vault_result = client
            .create_contract(
                &[&operator],
                "#daml-vault:Erc20Vault:Vault",
                json!({
                    "operators": [&operator],
                    "sigNetwork": &sig_network,
                    "evmVaultAddress": "0".repeat(64),
                    "evmMpcPublicKey": "",
                    "vaultId": "test-vault",
                }),
            )
            .await?;
        let (vault_cid, _) = find_created_contract(&vault_result, "Vault")?;

        let vault_disclosure = client
            .get_disclosed_contract(&[&operator], "#daml-vault:Erc20Vault:Vault", &vault_cid)
            .await?;
        let signer_disclosure = client
            .get_disclosed_contract(&[&sig_network], "#daml-signer:Signer:Signer", &signer_cid)
            .await?;

        let nonce_result = client
            .exercise_choice(
                &[&requester],
                &signer_template_id,
                &signer_cid,
                "IssueNonce",
                json!({ "requester": &requester }),
                std::slice::from_ref(&signer_disclosure),
            )
            .await?;
        let (nonce_cid, _) = find_created_contract(&nonce_result, "SigningNonce")?;

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
            vault_cid,
            vault_disclosure,
            signer_disclosure,
            nonce_cid,
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

// ---------------------------------------------------------------------------
// CantonTestClient
// ---------------------------------------------------------------------------

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
            encoding_key: jsonwebtoken::EncodingKey::from_ec_pem(
                jwt_private_key_pem.as_bytes(),
            )?,
        })
    }

    fn generate_jwt(&self) -> Result<String> {
        Ok(indexer_canton::generate_jwt_with_key(&self.encoding_key, &self.user_id)?)
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
                        tracing::debug!("create_contract({template_id}) retrying (attempt {attempt})");
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
        let resp = self
            .auth_post(&format!(
                "{}/v2/commands/submit-and-wait-for-transaction",
                self.base_url
            ))?
            .json(&SubmitAndWaitForTransactionRequest {
                commands: JsCommands {
                    command_id: uuid::Uuid::new_v4().to_string(),
                    user_id: self.user_id.clone(),
                    act_as: parties.clone(),
                    read_as: parties,
                    commands: vec![command],
                    disclosed_contracts,
                },
            })
            .send()
            .await?;
        if resp.status().is_success() {
            return Ok(resp.json().await?);
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("command failed: HTTP {status} — {body}")
    }

    async fn fetch_active_contracts(
        &self,
        parties: &[&str],
        template_id: &str,
        include_blob: bool,
    ) -> Result<Vec<ledger_api::ActiveContractEntry>> {
        let jwt = self.generate_jwt()?;
        Ok(indexer_canton::fetch_active_contracts(
            &self.http,
            &self.base_url,
            &jwt,
            parties,
            template_id,
            include_blob,
        )
        .await?)
    }

    pub async fn get_disclosed_contract(
        &self,
        parties: &[&str],
        template_id: &str,
        contract_id: &str,
    ) -> Result<DisclosedContract> {
        let entries = self.fetch_active_contracts(parties, template_id, true).await?;
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

    pub async fn poll_for_contract(
        &self,
        parties: &[&str],
        template_id: &str,
        predicate: impl Fn(&Value) -> bool,
        timeout: Duration,
    ) -> Result<JsActiveContract> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("timeout waiting for {template_id} after {timeout:?}");
            }
            let entries = self.fetch_active_contracts(parties, template_id, false).await?;
            for entry in &entries {
                if let Some(ContractEntry::JsActiveContract(ac)) = &entry.contract_entry {
                    if predicate(&ac.created_event.payload) {
                        return Ok(ac.clone());
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_package_not_ready(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("PACKAGE_SELECTION_FAILED")
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
