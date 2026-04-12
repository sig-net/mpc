use anyhow::{Context as _, Result};
use async_process::{Child, Command};
use mpc_node::indexer_canton::ledger_api::{
    self, ActiveContractEntry, AllocatePartyRequest, AllocatePartyResponse, ContractEntry,
    CreateUserRequest, CumulativeFilter, DisclosedContract, EventFormat,
    GetActiveContractsRequest, IdentifierFilter, JsActiveContract, JsCommands, LedgerEndResponse,
    PartyFilter, SubmitAndWaitForTransactionRequest, SubmitAndWaitForTransactionResponse,
    TemplateFilterValue, UserInfo,
};
use mpc_node::indexer_canton::CantonConfig;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;

const CANTON_JSON_API_PORT: u16 = 7575;
const DEFAULT_DAR_RELATIVE_PATH: &str = "fixtures/canton/daml-vault-0.0.1.dar";

// ---------------------------------------------------------------------------
// JWT auth material generation
// ---------------------------------------------------------------------------

pub struct JwtAuthMaterial {
    pub private_key_pem: String,
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
    pub auth_conf_path: PathBuf,
}

/// Generate P-256 private key + self-signed X.509 cert + HOCON auth config.
/// The config includes `alpha-dynamic.dars` so the sandbox loads the DAR
/// declaratively as the synchronizer connects — no separate upload step needed.
fn generate_jwt_auth_material(dar_path: &Path) -> Result<JwtAuthMaterial> {
    let tmp_dir = std::env::temp_dir();
    let id = uuid::Uuid::new_v4();
    let key_path = tmp_dir.join(format!("canton-jwt-{id}.key"));
    let cert_path = tmp_dir.join(format!("canton-jwt-{id}.crt"));
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
            &key_path.to_string_lossy(),
            "-out",
            &cert_path.to_string_lossy(),
            "-subj",
            "/CN=mpc-test-node",
        ])
        .output()
        .context("openssl not found — needed to generate JWT cert")?;
    anyhow::ensure!(output.status.success(), "openssl cert generation failed");

    let private_key_pem = std::fs::read_to_string(&key_path)?;

    let conf = format!(
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
        cert_path.to_string_lossy()
    );
    std::fs::write(&auth_conf_path, &conf)?;

    Ok(JwtAuthMaterial {
        private_key_pem,
        key_path,
        cert_path,
        auth_conf_path,
    })
}

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
    pub vault_disclosure: Value,
    pub signer_disclosure: Value,
    pub nonce_cid: String,
    pub client: CantonTestClient,
}

impl CantonSandbox {
    pub async fn run() -> Result<Self> {
        // 1. Resolve DAR path (env var with fallback)
        let dar_path = match std::env::var("CANTON_DAR_PATH") {
            Ok(p) => PathBuf::from(p),
            Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_DAR_RELATIVE_PATH),
        };
        anyhow::ensure!(dar_path.exists(), "DAR not found at {}", dar_path.display());

        // 2. Generate JWT key + cert + HOCON auth config (includes alpha-dynamic.dars).
        let auth = generate_jwt_auth_material(&dar_path)?;

        // 3. Start dpm sandbox with auth + declarative DAR loading.
        let process = Command::new("dpm")
            .arg("sandbox")
            .arg("--json-api-port")
            .arg(CANTON_JSON_API_PORT.to_string())
            .arg("-c")
            .arg(&auth.auth_conf_path)
            .spawn()
            .context("failed to start dpm sandbox")?;

        let base_url = format!("http://127.0.0.1:{CANTON_JSON_API_PORT}");
        let ws_url = format!("ws://127.0.0.1:{CANTON_JSON_API_PORT}");

        // 4. Wait for synchronizer readiness, then setup parties + contracts.
        let admin_client =
            CantonTestClient::new(&base_url, "participant_admin", auth.private_key_pem.clone());
        wait_for_synchronizer(&admin_client).await?;

        let user_id = format!("mpc-test-{}", uuid::Uuid::new_v4());
        let sig_network = admin_client.allocate_party("SigNetwork").await?;
        let operator = admin_client.allocate_party("Operator").await?;
        let requester = admin_client.allocate_party("Requester").await?;
        admin_client
            .create_user(&user_id, &sig_network, &[&operator, &requester])
            .await?;

        let client = CantonTestClient::new(&base_url, &user_id, auth.private_key_pem.clone());

        let signer_result = client
            .create_contract(
                &[&sig_network],
                "#daml-signer:Signer:Signer",
                json!({ "sigNetwork": &sig_network }),
            )
            .await?;
        let (signer_cid, signer_template_id) = find_created_contract(&signer_result, "Signer")?;

        let vault_id = "test-vault";
        // evmVaultAddress is all zeros — args[0] in test requests must match
        let vault_result = client
            .create_contract(
                &[&operator],
                "#daml-vault:Erc20Vault:Vault",
                json!({
                    "operators": [&operator],
                    "sigNetwork": &sig_network,
                    "evmVaultAddress": "0".repeat(64),
                    "evmMpcPublicKey": "",
                    "vaultId": vault_id,
                }),
            )
            .await?;
        let (vault_cid, _) = find_created_contract(&vault_result, "Vault")?;

        // Fetch disclosed contracts (needed for requester to exercise Vault choices)
        let vault_disclosure = client
            .get_disclosed_contract(&[&operator], "#daml-vault:Erc20Vault:Vault", &vault_cid)
            .await?;
        let signer_disclosure = client
            .get_disclosed_contract(&[&sig_network], "#daml-signer:Signer:Signer", &signer_cid)
            .await?;

        // Issue initial SigningNonce for the requester
        let nonce_result = client
            .exercise_choice(
                &[&requester],
                &signer_template_id,
                &signer_cid,
                "IssueNonce",
                json!({ "requester": &requester }),
                Some(std::slice::from_ref(&signer_disclosure)),
            )
            .await?;
        let nonce_cid = find_created_cid(&nonce_result, "SigningNonce")?;

        Ok(CantonSandbox {
            process,
            jwt_key_path: auth.key_path,
            jwt_cert_path: auth.cert_path,
            auth_conf_path: auth.auth_conf_path,
            json_api_url: base_url,
            json_api_ws_url: ws_url,
            jwt_private_key_pem: auth.private_key_pem,
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
        // Kill the Canton process group. `dpm` spawns a JVM child — killing
        // just the parent leaves it alive. `pkill -P` gets the children first.
        let pid = self.process.id();
        let _ = std::process::Command::new("pkill")
            .args(["-9", "-P", &pid.to_string()])
            .output();
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output();
        // Wait for the JSON API port to be released so sequential tests don't collide.
        for _ in 0..40 {
            if std::net::TcpStream::connect(("127.0.0.1", CANTON_JSON_API_PORT)).is_err() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        tracing::info!("canton sandbox cleaned up (pid {pid})");
        let _ = std::fs::remove_file(&self.jwt_key_path);
        let _ = std::fs::remove_file(&self.jwt_cert_path);
        let _ = std::fs::remove_file(&self.auth_conf_path);
    }
}

/// Wait for the Canton synchronizer to be connected by probing party allocation.
/// Covers both "HTTP server not up yet" (connection refused → retry) and
/// "synchronizer still loading" (400 WITHOUT_CONNECTED_SYNCHRONIZER → retry).
async fn wait_for_synchronizer(client: &CantonTestClient) -> Result<()> {
    let url = format!("{}/v2/parties", client.base_url);
    let probe = AllocatePartyRequest {
        party_id_hint: "_readiness_probe".to_string(),
        identity_provider_id: Some(String::new()),
        synchronizer_id: Some(String::new()),
        user_id: Some(String::new()),
    };
    for attempt in 0..120 {
        match client
            .auth_post(&url)?
            .json(&probe)
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 200 || status == 409 {
                    tracing::info!("canton synchronizer ready after {attempt} attempts");
                    return Ok(());
                }
                // 401 = auth cert not loaded yet (Canton still initializing)
                if status == 401 {
                    if attempt % 10 == 0 {
                        tracing::debug!("waiting for canton auth to initialize (attempt {attempt})...");
                    }
                } else {
                    let body = resp.text().await.unwrap_or_default();
                    if !body.contains("WITHOUT_CONNECTED_SYNCHRONIZER") {
                        return Ok(()); // API is up, non-synchronizer error = ready
                    }
                    if attempt % 10 == 0 {
                        tracing::debug!("waiting for canton synchronizer (attempt {attempt})...");
                    }
                }
            }
            _ => {
                if attempt % 10 == 0 {
                    tracing::debug!("waiting for canton to start (attempt {attempt})...");
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("canton sandbox did not become ready within 60 seconds")
}

// ---------------------------------------------------------------------------
// CantonTestClient with JWT ES256 auth
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct CantonTestClient {
    http: reqwest::Client,
    base_url: String,
    user_id: String,
    jwt_private_key_pem: String,
}

impl CantonTestClient {
    pub fn new(base_url: &str, user_id: &str, jwt_private_key_pem: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.to_string(),
            user_id: user_id.to_string(),
            jwt_private_key_pem,
        }
    }

    fn generate_jwt(&self) -> Result<String> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        #[derive(serde::Serialize)]
        struct Claims {
            sub: String,
            scope: String,
            iat: u64,
            exp: u64,
        }
        let claims = Claims {
            sub: self.user_id.clone(),
            scope: "daml_ledger_api".to_string(),
            iat: now,
            exp: now + 30,
        };
        let key = EncodingKey::from_ec_pem(self.jwt_private_key_pem.as_bytes())?;
        Ok(encode(&Header::new(Algorithm::ES256), &claims, &key)?)
    }

    fn auth_post(&self, url: &str) -> Result<reqwest::RequestBuilder> {
        Ok(self.http.post(url).bearer_auth(self.generate_jwt()?))
    }

    fn auth_get(&self, url: &str) -> Result<reqwest::RequestBuilder> {
        Ok(self.http.get(url).bearer_auth(self.generate_jwt()?))
    }

    pub async fn allocate_party(&self, hint: &str) -> Result<String> {
        let req = AllocatePartyRequest {
            party_id_hint: hint.to_string(),
            identity_provider_id: None,
            synchronizer_id: None,
            user_id: None,
        };
        let resp = self
            .auth_post(&format!("{}/v2/parties", self.base_url))?
            .json(&req)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("allocate_party({hint}) failed: HTTP {status} — {body}");
        }
        let body: AllocatePartyResponse = resp.json().await?;
        Ok(body.party_details.party)
    }

    pub async fn create_user(
        &self,
        user_id: &str,
        primary_party: &str,
        additional: &[&str],
    ) -> Result<()> {
        let mut rights = Vec::new();
        for party in std::iter::once(&primary_party).chain(additional.iter()) {
            rights.push(ledger_api::can_act_as(party));
            rights.push(ledger_api::can_read_as(party));
        }
        let req = CreateUserRequest {
            user: UserInfo {
                id: user_id.to_string(),
                primary_party: primary_party.to_string(),
                is_deactivated: false,
                identity_provider_id: String::new(),
            },
            rights,
        };
        let resp = self
            .auth_post(&format!("{}/v2/users", self.base_url))?
            .json(&req)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("create_user({user_id}) failed: HTTP {status} — {body}");
        }
        Ok(())
    }

    pub async fn create_contract(
        &self,
        act_as: &[&str],
        template_id: &str,
        args: Value,
    ) -> Result<SubmitAndWaitForTransactionResponse> {
        let parties: Vec<String> = act_as.iter().map(|s| s.to_string()).collect();
        // Retry while alpha-dynamic.dars is still vetting packages.
        for attempt in 0..30 {
            let req = SubmitAndWaitForTransactionRequest {
                commands: JsCommands {
                    command_id: uuid::Uuid::new_v4().to_string(),
                    user_id: self.user_id.clone(),
                    act_as: parties.clone(),
                    read_as: parties.clone(),
                    commands: vec![ledger_api::Command::CreateCommand {
                        template_id: template_id.to_string(),
                        create_arguments: args.clone(),
                    }],
                    disclosed_contracts: vec![],
                },
            };
            let resp = self
                .auth_post(&format!(
                    "{}/v2/commands/submit-and-wait-for-transaction",
                    self.base_url
                ))?
                .json(&req)
                .send()
                .await?;
            if resp.status().is_success() {
                return Ok(resp.json().await?);
            }
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let code = status.as_u16();
            if (code == 400 || code == 404)
                && (body.contains("PACKAGE_SELECTION_FAILED")
                    || body.contains("PACKAGE_NAMES_NOT_FOUND")
                    || body.contains("TEMPLATES_OR_INTERFACES_NOT_FOUND"))
            {
                if attempt % 5 == 0 {
                    tracing::debug!(
                        "create_contract({template_id}) retrying: {status} (attempt {attempt})"
                    );
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            anyhow::bail!("create_contract({template_id}) failed: HTTP {status} — {body}");
        }
        anyhow::bail!("create_contract({template_id}) failed after 30 retries")
    }

    pub async fn exercise_choice(
        &self,
        act_as: &[&str],
        template_id: &str,
        contract_id: &str,
        choice: &str,
        choice_argument: Value,
        disclosed_contracts: Option<&[Value]>,
    ) -> Result<SubmitAndWaitForTransactionResponse> {
        let parties: Vec<String> = act_as.iter().map(|s| s.to_string()).collect();
        let disclosed: Vec<DisclosedContract> = disclosed_contracts
            .unwrap_or(&[])
            .iter()
            .map(|v| serde_json::from_value(v.clone()))
            .collect::<Result<Vec<_>, _>>()
            .context("invalid DisclosedContract JSON")?;
        let req = SubmitAndWaitForTransactionRequest {
            commands: JsCommands {
                command_id: uuid::Uuid::new_v4().to_string(),
                user_id: self.user_id.clone(),
                act_as: parties.clone(),
                read_as: parties,
                commands: vec![ledger_api::Command::ExerciseCommand {
                    template_id: template_id.to_string(),
                    contract_id: contract_id.to_string(),
                    choice: choice.to_string(),
                    choice_argument,
                }],
                disclosed_contracts: disclosed,
            },
        };
        let resp = self
            .auth_post(&format!(
                "{}/v2/commands/submit-and-wait-for-transaction",
                self.base_url
            ))?
            .json(&req)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    async fn fetch_active_contracts(
        &self,
        parties: &[&str],
        template_id: &str,
        include_blob: bool,
    ) -> Result<Vec<ActiveContractEntry>> {
        let end: LedgerEndResponse = self
            .auth_get(&format!("{}/v2/state/ledger-end", self.base_url))?
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let mut filters = serde_json::Map::new();
        for party in parties {
            let filter = PartyFilter {
                cumulative: vec![CumulativeFilter {
                    identifier_filter: IdentifierFilter::TemplateFilter {
                        value: TemplateFilterValue {
                            template_id: template_id.to_string(),
                            include_created_event_blob: include_blob,
                        },
                    },
                }],
            };
            filters.insert(party.to_string(), serde_json::to_value(filter)?);
        }
        let req = GetActiveContractsRequest {
            active_at_offset: end.offset,
            event_format: EventFormat {
                filters_by_party: filters,
                verbose: true,
            },
        };
        Ok(self
            .auth_post(&format!("{}/v2/state/active-contracts", self.base_url))?
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// Fetch a disclosed contract blob for cross-party visibility.
    pub async fn get_disclosed_contract(
        &self,
        parties: &[&str],
        template_id: &str,
        contract_id: &str,
    ) -> Result<Value> {
        let entries = self.fetch_active_contracts(parties, template_id, true).await?;
        for entry in &entries {
            if let Some(ContractEntry::JsActiveContract(ac)) = &entry.contract_entry {
                if ac.created_event.contract_id == contract_id {
                    let disclosed = DisclosedContract {
                        template_id: ac.created_event.template_id.clone(),
                        contract_id: ac.created_event.contract_id.clone(),
                        created_event_blob: ac
                            .created_event
                            .created_event_blob
                            .clone()
                            .unwrap_or_default(),
                        synchronizer_id: ac.synchronizer_id.clone(),
                    };
                    return Ok(serde_json::to_value(disclosed)?);
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

fn find_created_contract(
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

/// Extract contract ID from a transaction result. Public for use in test modules.
pub fn find_created_cid(
    resp: &SubmitAndWaitForTransactionResponse,
    suffix: &str,
) -> Result<String> {
    find_created_contract(resp, suffix).map(|(cid, _)| cid)
}
