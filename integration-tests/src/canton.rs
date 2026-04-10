use anyhow::{Context as _, Result};
use async_process::{Child, Command};
use canton_types::ledger_api::{
    self, ActiveContractEntry, AllocatePartyRequest, AllocatePartyResponse, ContractEntry,
    CreateUserRequest, DisclosedContract, EventFormat, GetActiveContractsRequest, JsCommands,
    LedgerEndResponse, SubmitAndWaitForTransactionRequest, SubmitAndWaitForTransactionResponse,
    UserInfo,
};
use mpc_node::indexer_canton::CantonConfig;
use serde_json::{json, Value};
use std::path::PathBuf;
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
fn generate_jwt_auth_material() -> Result<JwtAuthMaterial> {
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

    // JWT auth on ledger-api only. The admin-api stays unauthenticated.
    let conf = format!(
        r#"canton.participants.sandbox.ledger-api {{
  auth-services = [
    {{ type = jwt-es-256-crt, certificate = "{}" }}
  ]
  jwt-timestamp-leeway.default = 10
}}"#,
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
        // 0. Wait for ALL Canton ports to be free (previous sandbox may still be
        //    shutting down). Canton binds 7575 (JSON API), 6865 (gRPC), 6868 (sequencer).
        for port in [CANTON_JSON_API_PORT, 6865, 6868] {
            let mut released = false;
            for i in 0..40 {
                match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                    Ok(_) => {
                        if i % 10 == 0 {
                            tracing::debug!("waiting for port {port} to be free (attempt {i})...");
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    Err(_) => {
                        released = true;
                        break;
                    }
                }
            }
            anyhow::ensure!(released, "port {port} still in use after 20s — previous Canton did not exit");
        }

        // 1. Check dpm is available
        let output = Command::new("dpm").arg("--version").output().await;
        anyhow::ensure!(
            output.is_ok() && output.unwrap().status.success(),
            "dpm CLI not found or broken — install from https://docs.digitalasset.com"
        );

        // 2. Resolve DAR path (env var with fallback)
        let dar_path = match std::env::var("CANTON_DAR_PATH") {
            Ok(p) => PathBuf::from(p),
            Err(_) => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(DEFAULT_DAR_RELATIVE_PATH),
        };
        anyhow::ensure!(dar_path.exists(), "DAR not found at {}", dar_path.display());

        // 3. Generate JWT key + cert + HOCON auth config.
        let auth = generate_jwt_auth_material()?;

        // 4. Start dpm sandbox WITH auth but WITHOUT --dar.
        //    `dpm sandbox --dar` uses the ledger-api gRPC for DAR upload, which
        //    fails with PERMISSION_DENIED when auth is enabled. Instead, we start
        //    without --dar, wait for readiness, then upload the DAR via the HTTP
        //    JSON API with a proper admin JWT. This is the pattern used by the
        //    official cn-quickstart.
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

        // 5. Wait for readiness (docs endpoint + synchronizer connected)
        wait_for_canton_ready(&base_url, &auth.private_key_pem).await?;

        // 6. Upload DAR via HTTP API with admin JWT (two-phase bootstrap).
        let admin_client =
            CantonTestClient::new(&base_url, "participant_admin", auth.private_key_pem.clone());
        admin_client.upload_dar(&dar_path).await?;

        // 7. Setup parties, user, and contracts — all with JWT auth.
        //    Use participant_admin for bootstrap (party/user creation),
        //    then switch to the test user for contract operations.
        let user_id = format!("mpc-test-{}", uuid::Uuid::new_v4());
        let sig_network = admin_client.allocate_party_with_retry("SigNetwork").await?;
        let operator = admin_client.allocate_party_with_retry("Operator").await?;
        let requester = admin_client.allocate_party_with_retry("Requester").await?;
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
            .get_disclosed_contract(
                &[&sig_network],
                "#daml-signer:Signer:Signer",
                &signer_cid,
            )
            .await?;

        // Issue initial SigningNonce for the requester
        let nonce_result = client
            .exercise_choice(
                &[&requester],
                &signer_template_id,
                &signer_cid,
                "IssueNonce",
                json!({ "requester": &requester }),
                Some(&[signer_disclosure.clone()]),
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
        // Kill the Canton process group. `dpm` spawns a Java child process that
        // binds multiple ports (7575, 6865, 6868). Killing just the parent leaves
        // the JVM alive. Use `pkill -P` to kill child processes, then the parent.
        let pid = self.process.id();
        let _ = std::process::Command::new("pkill")
            .args(["-9", "-P", &pid.to_string()])
            .output();
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output();
        tracing::info!("canton sandbox killed (pid {pid} + children), waiting for cleanup");
        // Wait until ALL Canton ports are fully released.
        for port in [CANTON_JSON_API_PORT, 6865, 6868] {
            for i in 0..40 {
                match std::net::TcpStream::connect(("127.0.0.1", port)) {
                    Ok(_) => {
                        if i % 10 == 0 {
                            tracing::debug!("waiting for port {port} to be released...");
                        }
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                    Err(_) => break,
                }
            }
        }
        let _ = std::fs::remove_file(&self.jwt_key_path);
        let _ = std::fs::remove_file(&self.jwt_cert_path);
        let _ = std::fs::remove_file(&self.auth_conf_path);
    }
}

/// Wait for Canton to be fully ready.
/// Phase 1: /docs/openapi (unauthenticated) — confirms the process is listening.
/// Phase 2: Authenticated party allocation probe — confirms the synchronizer is
///           connected. With `alpha-dynamic.dars`, the synchronizer loads
///           asynchronously after the HTTP server starts.
async fn wait_for_canton_ready(base_url: &str, jwt_private_key_pem: &str) -> Result<()> {
    let client = reqwest::Client::new();

    // Phase 1: wait for the HTTP server to start
    let docs_url = format!("{base_url}/docs/openapi");
    for attempt in 0..120 {
        match client.get(&docs_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("canton docs endpoint ready after {attempt} attempts");
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
        if attempt == 119 {
            anyhow::bail!("canton sandbox did not become ready within 60 seconds");
        }
    }

    // Phase 2: wait for the synchronizer to be connected using an authenticated
    // party-allocation probe. Uses `participant_admin` JWT to bypass user checks.
    let probe_client = CantonTestClient::new(base_url, "participant_admin", jwt_private_key_pem.to_string());
    let api_url = format!("{base_url}/v2/parties");
    for attempt in 0..120 {
        match probe_client
            .auth_post(&api_url)?
            .json(&serde_json::json!({
                "partyIdHint": "_readiness_probe",
                "identityProviderId": "",
                "synchronizerId": "",
                "userId": ""
            }))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status == 200 || status == 409 {
                    // 200 = party created (synchronizer up)
                    // 409 = party already exists (synchronizer up)
                    tracing::info!(
                        "canton synchronizer ready after {attempt} additional attempts (status: {status})"
                    );
                    return Ok(());
                }
                if status == 400 {
                    let body = resp.text().await.unwrap_or_default();
                    if body.contains("WITHOUT_CONNECTED_SYNCHRONIZER") {
                        if attempt % 10 == 0 {
                            tracing::debug!("waiting for canton synchronizer (attempt {attempt})...");
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                    // Other 400 = API is ready, request issue
                    tracing::info!(
                        "canton synchronizer ready after {attempt} additional attempts (status: 400)"
                    );
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
    anyhow::bail!("canton synchronizer did not become ready within 60 seconds")
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

    /// Upload a DAR file via the JSON API (POST /v2/packages).
    /// Requires admin JWT (sub: "participant_admin").
    pub async fn upload_dar(&self, dar_path: &std::path::Path) -> Result<()> {
        let dar_bytes = std::fs::read(dar_path)
            .context(format!("failed to read DAR at {}", dar_path.display()))?;
        for attempt in 0..30 {
            let resp = self
                .http
                .post(format!("{}/v2/packages", self.base_url))
                .bearer_auth(self.generate_jwt()?)
                .header("Content-Type", "application/octet-stream")
                .body(dar_bytes.clone())
                .send()
                .await?;
            if resp.status().is_success() {
                tracing::info!("DAR uploaded successfully");
                return Ok(());
            }
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            // Retry on synchronizer not ready
            if body.contains("WITHOUT_CONNECTED_SYNCHRONIZER")
                || body.contains("PACKAGE_SERVICE_CANNOT_AUTODETECT")
            {
                if attempt % 5 == 0 {
                    tracing::debug!("retrying DAR upload (attempt {attempt}): {status}");
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            anyhow::bail!("DAR upload failed: HTTP {status} — {body}");
        }
        anyhow::bail!("DAR upload failed after 30 retries")
    }

    /// Allocate a party, retrying if the synchronizer is still connecting.
    pub async fn allocate_party_with_retry(&self, hint: &str) -> Result<String> {
        for attempt in 0..30 {
            match self.allocate_party(hint).await {
                Ok(party) => return Ok(party),
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("WITHOUT_CONNECTED_SYNCHRONIZER") {
                        if attempt % 5 == 0 {
                            tracing::debug!("retrying allocate_party({hint}), synchronizer not ready (attempt {attempt})");
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        anyhow::bail!("allocate_party({hint}) failed after 30 retries — synchronizer never connected")
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
    ) -> Result<Value> {
        let parties: Vec<String> = act_as.iter().map(|s| s.to_string()).collect();
        // Retry on transient errors (package vetting, synchronizer connectivity).
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
                    || body.contains("TEMPLATES_OR_INTERFACES_NOT_FOUND")
                    || body.contains("WITHOUT_CONNECTED_SYNCHRONIZER"))
            {
                if attempt % 5 == 0 {
                    tracing::debug!("create_contract({template_id}) retrying: {status} (attempt {attempt})");
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
    ) -> Result<Value> {
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

    /// Fetch a disclosed contract blob for cross-party visibility.
    pub async fn get_disclosed_contract(
        &self,
        parties: &[&str],
        template_id: &str,
        contract_id: &str,
    ) -> Result<Value> {
        let end: LedgerEndResponse = self
            .auth_get(&format!("{}/v2/state/ledger-end", self.base_url))?
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let mut filters = serde_json::Map::new();
        for party in parties {
            filters.insert(
                party.to_string(),
                json!({
                    "cumulative": [{ "identifierFilter": { "TemplateFilter": { "value": {
                        "templateId": template_id, "includeCreatedEventBlob": true
                    }}}}]
                }),
            );
        }
        let req = GetActiveContractsRequest {
            active_at_offset: end.offset,
            event_format: EventFormat {
                filters_by_party: filters,
                verbose: true,
            },
        };
        let resp: Vec<ActiveContractEntry> = self
            .auth_post(&format!("{}/v2/state/active-contracts", self.base_url))?
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        for entry in &resp {
            if let Some(ContractEntry::JsActiveContract(ac)) = &entry.contract_entry {
                if ac.created_event.contract_id == contract_id {
                    return Ok(json!({
                        "templateId": ac.created_event.template_id,
                        "contractId": ac.created_event.contract_id,
                        "createdEventBlob": ac.created_event.created_event_blob,
                        "synchronizerId": ac.synchronizer_id,
                    }));
                }
            }
        }
        anyhow::bail!("disclosed contract not found for {contract_id}")
    }

    pub async fn get_active_contracts(
        &self,
        parties: &[&str],
        template_id: &str,
    ) -> Result<Vec<Value>> {
        let end: LedgerEndResponse = self
            .auth_get(&format!("{}/v2/state/ledger-end", self.base_url))?
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let mut filters = serde_json::Map::new();
        for party in parties {
            filters.insert(
                party.to_string(),
                json!({
                    "cumulative": [{ "identifierFilter": { "TemplateFilter": { "value": {
                        "templateId": template_id, "includeCreatedEventBlob": false
                    }}}}]
                }),
            );
        }
        let req = GetActiveContractsRequest {
            active_at_offset: end.offset,
            event_format: EventFormat {
                filters_by_party: filters,
                verbose: true,
            },
        };
        let resp: Vec<Value> = self
            .auth_post(&format!("{}/v2/state/active-contracts", self.base_url))?
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(resp)
    }

    pub async fn poll_for_contract(
        &self,
        parties: &[&str],
        template_id: &str,
        predicate: impl Fn(&Value) -> bool,
        timeout: Duration,
    ) -> Result<Value> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("timeout waiting for {template_id} after {timeout:?}");
            }
            let contracts = self.get_active_contracts(parties, template_id).await?;
            for item in &contracts {
                if let Some(ac) = item
                    .get("contractEntry")
                    .and_then(|e| e.get("JsActiveContract"))
                {
                    let payload = ac["createdEvent"]
                        .get("payload")
                        .or_else(|| ac["createdEvent"].get("createArgument"))
                        .unwrap_or(&ac["createdEvent"]);
                    if predicate(payload) {
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

fn find_created_contract(result: &Value, suffix: &str) -> Result<(String, String)> {
    let resp: SubmitAndWaitForTransactionResponse =
        serde_json::from_value(result.clone()).context("failed to parse transaction response")?;
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
pub fn find_created_cid(result: &Value, suffix: &str) -> Result<String> {
    find_created_contract(result, suffix).map(|(cid, _)| cid)
}
