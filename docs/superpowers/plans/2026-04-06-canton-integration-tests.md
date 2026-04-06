# Canton Integration Tests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Canton integration tests to the MPC node test suite, following the same patterns used by Ethereum and Solana, supporting both stream-only tests (Pattern B) and full-cluster tests (Pattern A).

**Architecture:** Add a `CantonSandbox` struct (analogous to `Solana`) that starts Canton sandbox as a local process via `dpm sandbox -c auth.conf` with JWT ES256 auth enabled (`jwt-es-256-crt` mode). Follow the Solana pattern: start Canton in `ClusterSpawner::into_future()` (NOT in `setup()`), store on the spawner, move to `Cluster` via `.take()`. Add a Canton test client with JWT auth for exercising Vault choices. Implement stream-only tests first, then full-cluster bidirectional tests.

**Tech Stack:** Rust, `dpm` CLI (which IS the Canton binary), Canton JSON Ledger API v2 (HTTP + WebSocket), `reqwest` for API calls, `async_process` for sandbox process management, `openssl` CLI for JWT key/cert generation.

**Spec:** `docs/superpowers/specs/2026-04-05-canton-chain-integration-design.md`

---

## Prerequisites

- `dpm` CLI installed and in PATH (IS the Canton binary — supports `-c` for HOCON config layering)
- `openssl` CLI available (for generating self-signed X.509 certs for JWT auth)
- DAR file pre-built (path configurable via `CANTON_DAR_PATH` env var, defaults to `../canton-mpc-poc/daml-packages/daml-vault/.daml/dist/daml-vault-0.0.1.dar`)
- The Canton chain integration PR (sig-net/mpc#740) merged or on the same branch

---

## Review Findings (from 15+3+15 agent cross-validation)

The following issues were identified during three rounds of review and must be addressed during implementation:

### Critical — Must fix

1. **JWT `scope` claim required:** Canton's default codec rejects JWTs without `scope` or `aud`. Add `scope: "daml_ledger_api"` to all JWT generators (test client AND MPC node production code).

2. **Readiness check must use `/docs/openapi`:** When JWT auth is enabled, `/v2/state/ledger-end` returns 401 without a Bearer token. Use `GET /docs/openapi` instead — it's unauthenticated even with auth enabled (this is what the Canton POC does).

3. **Follow Solana's `into_future()` pattern:** Canton sandbox must be started in `ClusterSpawner::into_future()` BEFORE `self.run()`, NOT in `setup()`. Store on `ClusterSpawner.canton`, move to `Cluster` via `self.canton.take()`. The Ethereum pattern (`setup()` → `Context`) does NOT work because `Context` is consumed inside `run()` and unreachable from `into_future()`.

4. **Use `async_process::Child`:** The codebase uses `async_process` for long-lived processes (Solana, MPC nodes). `tokio::process` is only used for ad-hoc CLI commands. Canton must match.

5. **`disclosedContracts` required for Vault choices:** `RequestAuthorization` needs `[vaultDisclosure]`, `RequestDeposit` needs `[vaultDisclosure, signerDisclosure]`. The TS visibility test proves failure without them.

6. **`args[0]` must match `evmVaultAddress`:** Daml asserts `recipientArg == evmVaultAddress` in `RequestDeposit`. The plan must use matching values.

7. **CI gating:** Canton tests must be marked `#[ignore]` (like nightly tests) since `dpm` is not installed on CI runners. Run via a separate job with `--ignored`.

### Important — Should fix

8. **DAR path configurable via env var:** CI won't have the sibling repo. Use `CANTON_DAR_PATH` env var with fallback to the relative path.

9. **`dry_run` variable name:** In `local.rs`, `dry_run` uses param `cfg` (not `config.cfg`).

10. **Full-cluster test must match `chains.rs` depth:** Crypto verification (`check_ec_signature`), EVM broadcast, receipt check, `RespondBidirectionalEvent` wait, `tokio::try_join!`.

11. **Stream tests need parity with ETH/Solana (6 tests each):** Add catchup, concurrent, checkpoint, respond flow tests.

12. **`stream_canton` must accept `Backlog` param** for checkpoint tests.

13. **`find_created_cid` must be `pub`** or moved to `src/canton.rs` for cross-module access.

### Verified non-issues

- **`dpm sandbox -c` works** — `dpm` IS the Canton binary, `-c` is a top-level flag
- **Port 7575 hardcoded is fine** — EthereumSandbox also hardcodes 8545
- **Participant name "sandbox" is correct** — confirmed via DPM docs
- **`/v2/state/active-contracts` returns plain JSON array** — NOT SSE/NDJSON

---

## File Structure

### New files

| File | Responsibility |
|---|---|
| `integration-tests/src/canton.rs` | `CantonSandbox` struct, `CantonTestClient` with JWT auth, contract helpers, `find_created_cid` |
| `integration-tests/tests/cases/canton_stream.rs` | Stream-only tests (Pattern B): 6 tests matching ETH/Solana coverage |
| `integration-tests/tests/cases/canton.rs` | Full-cluster bidirectional test (Pattern A): Canton → EVM → Canton round-trip |

### Modified files

| File | Changes |
|---|---|
| `integration-tests/src/lib.rs` | Add `canton: Option<CantonConfig>` to `NodeConfig`, add `pub mod canton` |
| `integration-tests/src/cluster/spawner.rs` | Add `use_canton: bool`, `canton: Option<CantonSandbox>`, `.canton()` builder, Canton startup in `into_future()` |
| `integration-tests/src/cluster/mod.rs` | Add `canton: Option<canton::CantonSandbox>` to `Cluster` struct |
| `integration-tests/src/local.rs` | Replace hardcoded `CantonArgs::from_config(None)` — use `cfg.canton` in `dry_run`, `config.cfg.canton` in `spawn` |
| `integration-tests/src/containers.rs` | Same replacement for Docker path |
| `integration-tests/tests/cases/mod.rs` | Add `pub mod canton;` and `pub mod canton_stream;` |
| `integration-tests/Cargo.toml` | Add deps: `p256`, `jsonwebtoken` |
| `chain-signatures/node/src/indexer_canton/mod.rs` | Add `scope: "daml_ledger_api"` to `JwtClaims` (production fix) |

---

### Task 0: Fix MPC Node JWT Claims (Production Fix)

**Files:**
- Modify: `chain-signatures/node/src/indexer_canton/mod.rs`

Canton rejects JWTs without a `scope` or `aud` claim. The MPC node's `JwtClaims` only has `sub`/`iat`/`exp`.

- [ ] **Step 1: Add `scope` to JwtClaims**

In `chain-signatures/node/src/indexer_canton/mod.rs`, find the `JwtClaims` struct (~line 127) and add the `scope` field:

```rust
#[derive(serde::Serialize)]
struct JwtClaims {
    sub: String,
    scope: String,
    iat: u64,
    exp: u64,
}
```

Update `generate_jwt` (~line 133) to populate it:

```rust
let claims = JwtClaims {
    sub: subject.to_string(),
    scope: "daml_ledger_api".to_string(),
    iat: now,
    exp: now + 30,
};
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p mpc-node`

- [ ] **Step 3: Commit**

```bash
git add chain-signatures/node/src/indexer_canton/mod.rs
git commit -m "fix: add scope claim to Canton JWT for ledger API auth"
```

---

### Task 1: Add `CantonSandbox` Struct and Test Client

**Files:**
- Create: `integration-tests/src/canton.rs`
- Modify: `integration-tests/Cargo.toml`
- Modify: `integration-tests/src/lib.rs`

- [ ] **Step 1: Add dependencies to integration-tests/Cargo.toml**

```toml
p256 = { workspace = true }
jsonwebtoken = { workspace = true }
```

- [ ] **Step 2: Create `integration-tests/src/canton.rs`**

The full module with `CantonSandbox`, `CantonTestClient`, JWT auth, and contract helpers. Key design decisions from review:

- Uses `async_process::Child` (not `tokio::process`) — matches Solana/MPC node pattern
- JWT includes `scope: "daml_ledger_api"` — required by Canton's default codec
- Readiness check uses `GET /docs/openapi` — unauthenticated even with JWT auth enabled
- `exercise_choice` supports optional `disclosed_contracts` — required for Vault choices
- `find_created_cid` is `pub` — shared with test modules
- DAR path from `CANTON_DAR_PATH` env var with fallback

```rust
use anyhow::{Context as _, Result};
use async_process::{Child, Command};
use mpc_node::indexer_canton::CantonConfig;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

const CANTON_JSON_API_PORT: u16 = 7575;
const DEFAULT_DAR_RELATIVE_PATH: &str =
    "../canton-mpc-poc/daml-packages/daml-vault/.daml/dist/daml-vault-0.0.1.dar";

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
            "req", "-x509", "-noenc", "-days", "3650",
            "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", &key_path.to_string_lossy(),
            "-out", &cert_path.to_string_lossy(),
            "-subj", "/CN=mpc-test-node",
        ])
        .output()
        .context("openssl not found — needed to generate JWT cert")?;
    anyhow::ensure!(output.status.success(), "openssl cert generation failed");

    let private_key_pem = std::fs::read_to_string(&key_path)?;

    // Canton sandbox participant is named "sandbox" (confirmed via DPM docs).
    let auth_conf = format!(
        r#"canton.participants.sandbox.ledger-api {{
  auth-services = [
    {{ type = jwt-es-256-crt, certificate = "{}" }}
  ]
  jwt-timestamp-leeway.default = 10
}}"#,
        cert_path.to_string_lossy()
    );
    std::fs::write(&auth_conf_path, &auth_conf)?;

    Ok(JwtAuthMaterial { private_key_pem, key_path, cert_path, auth_conf_path })
}

// ---------------------------------------------------------------------------
// CantonSandbox
// ---------------------------------------------------------------------------

/// A running Canton sandbox process with JWT ES256 auth enabled.
pub struct CantonSandbox {
    pub process: Child,
    pub json_api_url: String,
    pub json_api_ws_url: String,
    pub jwt_private_key_pem: String,
    pub jwt_key_path: PathBuf,
    pub jwt_cert_path: PathBuf,
    pub auth_conf_path: PathBuf,
    pub jwt_subject: String,
    pub party_id: String,
    pub operator_party: String,
    pub requester_party: String,
    pub signer_cid: String,
    pub signer_template_id: String,
    pub vault_cid: String,
    pub vault_id: String,
    pub user_id: String,
    pub vault_disclosure: Value,
    pub signer_disclosure: Value,
    pub client: CantonTestClient,
}

impl CantonSandbox {
    pub async fn run() -> Result<Self> {
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
                .parent()
                .unwrap()
                .join(DEFAULT_DAR_RELATIVE_PATH),
        };
        anyhow::ensure!(dar_path.exists(), "DAR not found at {}", dar_path.display());

        // 3. Generate JWT key + cert + HOCON auth config
        let auth = generate_jwt_auth_material()?;

        // 4. Start dpm sandbox with auth config (-c is a top-level Canton flag)
        let process = Command::new("dpm")
            .arg("sandbox")
            .arg("--json-api-port")
            .arg(CANTON_JSON_API_PORT.to_string())
            .arg("--dar")
            .arg(&dar_path)
            .arg("-c")
            .arg(&auth.auth_conf_path)
            .spawn()
            .context("failed to start dpm sandbox")?;

        let base_url = format!("http://127.0.0.1:{CANTON_JSON_API_PORT}");
        let ws_url = format!("ws://127.0.0.1:{CANTON_JSON_API_PORT}");

        // 5. Wait for readiness using /docs/openapi (unauthenticated even with JWT auth)
        wait_for_canton_ready(&base_url).await?;

        // 6. Setup parties, user, contracts (all with JWT auth)
        let user_id = format!("mpc-test-{}", uuid::Uuid::new_v4());
        let client = CantonTestClient::new(&base_url, &user_id, auth.private_key_pem.clone());

        let sig_network = client.allocate_party("SigNetwork").await?;
        let operator = client.allocate_party("Operator").await?;
        let requester = client.allocate_party("Requester").await?;
        client.create_user(&user_id, &sig_network, &[&operator, &requester]).await?;

        let signer_result = client
            .create_contract(&[&sig_network], "#daml-vault:Signer:Signer", json!({ "sigNetwork": &sig_network }))
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
            .get_disclosed_contract(&[&sig_network], "#daml-vault:Signer:Signer", &signer_cid)
            .await?;

        Ok(CantonSandbox {
            process,
            json_api_url: base_url,
            json_api_ws_url: ws_url,
            jwt_private_key_pem: auth.private_key_pem,
            jwt_key_path: auth.key_path,
            jwt_cert_path: auth.cert_path,
            auth_conf_path: auth.auth_conf_path,
            jwt_subject: user_id.clone(),
            party_id: sig_network,
            operator_party: operator,
            requester_party: requester,
            signer_cid,
            signer_template_id,
            vault_cid,
            vault_id: vault_id.to_string(),
            user_id,
            vault_disclosure,
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
        }
    }
}

impl Drop for CantonSandbox {
    fn drop(&mut self) {
        if let Err(e) = self.process.kill() {
            tracing::warn!("failed to kill canton sandbox: {e}");
        } else {
            tracing::info!("canton sandbox terminated");
        }
        let _ = std::fs::remove_file(&self.jwt_key_path);
        let _ = std::fs::remove_file(&self.jwt_cert_path);
        let _ = std::fs::remove_file(&self.auth_conf_path);
    }
}

/// Wait for Canton to be ready using /docs/openapi (unauthenticated).
async fn wait_for_canton_ready(base_url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!("{base_url}/docs/openapi");
    for attempt in 0..120 {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("canton sandbox ready after {attempt} attempts");
                return Ok(());
            }
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
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
        struct Claims { sub: String, scope: String, iat: u64, exp: u64 }
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
        let resp = self
            .auth_post(&format!("{}/v2/parties", self.base_url))?
            .json(&json!({ "partyIdHint": hint, "identityProviderId": "", "synchronizerId": "", "userId": "" }))
            .send().await?
            .error_for_status()?;
        let body: Value = resp.json().await?;
        body["partyDetails"]["party"].as_str().map(|s| s.to_string()).context("missing party")
    }

    pub async fn create_user(&self, user_id: &str, primary_party: &str, additional: &[&str]) -> Result<()> {
        let mut rights = Vec::new();
        for party in std::iter::once(&primary_party).chain(additional.iter()) {
            rights.push(json!({ "kind": { "CanActAs": { "value": { "party": party } } } }));
            rights.push(json!({ "kind": { "CanReadAs": { "value": { "party": party } } } }));
        }
        self.auth_post(&format!("{}/v2/users", self.base_url))?
            .json(&json!({
                "user": { "id": user_id, "primaryParty": primary_party, "isDeactivated": false, "identityProviderId": "" },
                "rights": rights
            }))
            .send().await?;
        Ok(())
    }

    pub async fn create_contract(&self, act_as: &[&str], template_id: &str, args: Value) -> Result<Value> {
        let resp = self
            .auth_post(&format!("{}/v2/commands/submit-and-wait-for-transaction", self.base_url))?
            .json(&json!({
                "commands": {
                    "commandId": uuid::Uuid::new_v4().to_string(),
                    "userId": self.user_id,
                    "actAs": act_as, "readAs": act_as,
                    "commands": [{ "CreateCommand": { "templateId": template_id, "createArguments": args } }]
                }
            }))
            .send().await?.error_for_status()?;
        Ok(resp.json().await?)
    }

    pub async fn exercise_choice(
        &self, act_as: &[&str], template_id: &str, contract_id: &str,
        choice: &str, choice_argument: Value, disclosed_contracts: Option<&[Value]>,
    ) -> Result<Value> {
        let resp = self
            .auth_post(&format!("{}/v2/commands/submit-and-wait-for-transaction", self.base_url))?
            .json(&json!({
                "commands": {
                    "commandId": uuid::Uuid::new_v4().to_string(),
                    "userId": self.user_id,
                    "actAs": act_as, "readAs": act_as,
                    "disclosedContracts": disclosed_contracts.unwrap_or(&[]),
                    "commands": [{
                        "ExerciseCommand": {
                            "templateId": template_id, "contractId": contract_id,
                            "choice": choice, "choiceArgument": choice_argument,
                        }
                    }]
                }
            }))
            .send().await?.error_for_status()?;
        Ok(resp.json().await?)
    }

    /// Fetch a disclosed contract blob for cross-party visibility.
    pub async fn get_disclosed_contract(
        &self, parties: &[&str], template_id: &str, contract_id: &str,
    ) -> Result<Value> {
        let end: Value = self.auth_get(&format!("{}/v2/state/ledger-end", self.base_url))?
            .send().await?.error_for_status()?.json().await?;
        let offset = end["offset"].as_u64().unwrap_or(0);

        let mut filters = serde_json::Map::new();
        for party in parties {
            filters.insert(party.to_string(), json!({
                "cumulative": [{ "identifierFilter": { "TemplateFilter": { "value": {
                    "templateId": template_id, "includeCreatedEventBlob": true
                }}}}]
            }));
        }
        let resp: Vec<Value> = self
            .auth_post(&format!("{}/v2/state/active-contracts", self.base_url))?
            .json(&json!({ "activeAtOffset": offset, "eventFormat": { "filtersByParty": filters, "verbose": true } }))
            .send().await?.error_for_status()?.json().await?;

        for item in &resp {
            if let Some(ac) = item.get("contractEntry").and_then(|e| e.get("JsActiveContract")) {
                if ac["createdEvent"]["contractId"].as_str() == Some(contract_id) {
                    let event = &ac["createdEvent"];
                    return Ok(json!({
                        "templateId": event["templateId"],
                        "contractId": event["contractId"],
                        "createdEventBlob": event["createdEventBlob"],
                        "synchronizerId": ac["synchronizerId"],
                    }));
                }
            }
        }
        anyhow::bail!("disclosed contract not found for {contract_id}")
    }

    pub async fn get_active_contracts(&self, parties: &[&str], template_id: &str) -> Result<Vec<Value>> {
        let end: Value = self.auth_get(&format!("{}/v2/state/ledger-end", self.base_url))?
            .send().await?.error_for_status()?.json().await?;
        let offset = end["offset"].as_u64().unwrap_or(0);

        let mut filters = serde_json::Map::new();
        for party in parties {
            filters.insert(party.to_string(), json!({
                "cumulative": [{ "identifierFilter": { "TemplateFilter": { "value": {
                    "templateId": template_id, "includeCreatedEventBlob": false
                }}}}]
            }));
        }
        let resp: Vec<Value> = self
            .auth_post(&format!("{}/v2/state/active-contracts", self.base_url))?
            .json(&json!({ "activeAtOffset": offset, "eventFormat": { "filtersByParty": filters, "verbose": true } }))
            .send().await?.error_for_status()?.json().await?;
        Ok(resp)
    }

    pub async fn poll_for_contract(
        &self, parties: &[&str], template_id: &str,
        predicate: impl Fn(&Value) -> bool, timeout: Duration,
    ) -> Result<Value> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                anyhow::bail!("timeout waiting for {template_id} after {timeout:?}");
            }
            let contracts = self.get_active_contracts(parties, template_id).await?;
            for item in &contracts {
                if let Some(ac) = item.get("contractEntry").and_then(|e| e.get("JsActiveContract")) {
                    let payload = ac["createdEvent"].get("payload")
                        .or_else(|| ac["createdEvent"].get("createArgument"))
                        .unwrap_or(&ac["createdEvent"]);
                    if predicate(payload) { return Ok(ac.clone()); }
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
    for event in result["transaction"]["events"].as_array().context("no events")? {
        if let Some(created) = event.get("CreatedEvent") {
            let tid = created["templateId"].as_str().unwrap_or("");
            if tid.contains(suffix) {
                return Ok((
                    created["contractId"].as_str().context("missing contractId")?.to_string(),
                    tid.to_string(),
                ));
            }
        }
    }
    anyhow::bail!("no CreatedEvent for {suffix}")
}

/// Extract contract ID from a transaction result. Public for use in test modules.
pub fn find_created_cid(result: &Value, suffix: &str) -> Result<String> {
    find_created_contract(result, suffix).map(|(cid, _)| cid)
}
```

- [ ] **Step 3: Add module declaration**

In `integration-tests/src/lib.rs`, add: `pub mod canton;`

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p integration-tests 2>&1 | head -20`

- [ ] **Step 5: Commit**

```bash
git add integration-tests/src/canton.rs integration-tests/Cargo.toml integration-tests/src/lib.rs
git commit -m "feat: add CantonSandbox and CantonTestClient with JWT auth"
```

---

### Task 2: Wire Canton into NodeConfig, ClusterSpawner, and Cluster

**Files:**
- Modify: `integration-tests/src/lib.rs`
- Modify: `integration-tests/src/cluster/spawner.rs`
- Modify: `integration-tests/src/cluster/mod.rs`
- Modify: `integration-tests/src/local.rs`
- Modify: `integration-tests/src/containers.rs`

- [ ] **Step 1: Add canton to NodeConfig**

In `integration-tests/src/lib.rs`, add `canton: Option<mpc_node::indexer_canton::CantonConfig>` to `NodeConfig`. Add `canton: None` to the `Default` impl.

- [ ] **Step 2: Add `.canton()` builder and canton field to ClusterSpawner**

In `integration-tests/src/cluster/spawner.rs`:

Add fields to `ClusterSpawner`:
```rust
pub use_canton: bool,
pub canton: Option<crate::canton::CantonSandbox>,
```

Add `use_canton: false` and `canton: None` to `ClusterSpawner::default()`.

Add builder method:
```rust
pub fn canton(mut self) -> Self {
    self.use_canton = true;
    self
}
```

- [ ] **Step 3: Wire Canton startup in `into_future()` — Solana pattern**

In `ClusterSpawner::into_future()`, add Canton startup BEFORE `self.run()`, after the Solana block:

```rust
// Canton setup (follows Solana pattern — started before self.run(),
// stored on spawner, moved to Cluster via .take())
if self.use_canton {
    let sandbox = crate::canton::CantonSandbox::run().await?;
    self.cfg.canton = Some(sandbox.get_config());
    self.canton = Some(sandbox);
}

let nodes = self.run().await?;
```

In the `Cluster` construction, add:
```rust
let cluster = Cluster {
    // ... existing fields ...
    canton: self.canton.take(),
    nodes,
};
```

- [ ] **Step 4: Add canton to Cluster struct**

In `integration-tests/src/cluster/mod.rs`:
```rust
pub canton: Option<crate::canton::CantonSandbox>,
```

- [ ] **Step 5: Replace hardcoded CantonArgs::from_config(None)**

In `integration-tests/src/local.rs`:
- In `dry_run()`: replace with `CantonArgs::from_config(cfg.canton.clone())`
- In `spawn()`: replace with `CantonArgs::from_config(config.cfg.canton.clone())`

In `integration-tests/src/containers.rs`:
- Replace with `CantonArgs::from_config(config.cfg.canton.clone())`

- [ ] **Step 6: Verify and commit**

Run: `cargo check -p integration-tests`

```bash
git add integration-tests/src/lib.rs integration-tests/src/cluster/spawner.rs integration-tests/src/cluster/mod.rs integration-tests/src/local.rs integration-tests/src/containers.rs
git commit -m "feat: wire Canton into NodeConfig, ClusterSpawner, and Cluster"
```

---

### Task 3: Add Canton Stream-Only Tests (6 tests)

**Files:**
- Create: `integration-tests/tests/cases/canton_stream.rs`
- Modify: `integration-tests/tests/cases/mod.rs`

All tests marked `#[ignore]` so they don't run in CI without `dpm`.

- [ ] **Step 1: Add module declaration**

In `tests/cases/mod.rs`, add:
```rust
pub mod canton_stream;
```

- [ ] **Step 2: Create canton_stream.rs with helpers**

Create `integration-tests/tests/cases/canton_stream.rs`:

```rust
use anyhow::{Context as _, Result};
use integration_tests::canton::{find_created_cid, CantonSandbox};
use mpc_node::backlog::Backlog;
use mpc_node::indexer_canton::CantonStream;
use mpc_node::protocol::Chain;
use mpc_node::stream::{ChainEvent, ChainStream};
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde_json::json;
use std::collections::HashSet;
use std::time::Duration;
use test_log::test;
use tokio::time::timeout;

/// Start a Canton sandbox with deployed contracts (no MPC cluster).
async fn canton_sandbox() -> Result<CantonSandbox> {
    CantonSandbox::run().await
}

/// Create a CantonStream from the sandbox config with an externally-provided Backlog.
/// Accepts Backlog as parameter (needed for checkpoint tests).
async fn stream_canton(sandbox: &CantonSandbox, backlog: Backlog) -> Result<CantonStream> {
    let config = sandbox.get_config();
    let mut stream =
        CantonStream::new(Some(config), backlog).context("failed to create CantonStream")?;
    ChainStream::start(&mut stream).await;
    Ok(stream)
}

/// Submit a sign request through the Vault contract.
/// Exercises: RequestAuthorization → ApproveAuthorization → RequestDeposit.
/// Returns the requestId from the PendingDeposit event.
async fn submit_canton_sign_request(sandbox: &CantonSandbox) -> Result<String> {
    let client = &sandbox.client;
    let vault_template = "#daml-vault:Erc20Vault:Vault";

    // Step 1: RequestAuthorization (requester needs vault disclosure)
    let req_result = client
        .exercise_choice(
            &[&sandbox.requester_party],
            vault_template,
            &sandbox.vault_cid,
            "RequestAuthorization",
            json!({ "requester": &sandbox.requester_party }),
            Some(&[sandbox.vault_disclosure.clone()]),
        )
        .await?;
    let request_cid = find_created_cid(&req_result, "AuthorizationRequest")?;

    // Step 2: ApproveAuthorization (operator is signatory — no disclosure needed)
    let approve_result = client
        .exercise_choice(
            &[&sandbox.operator_party],
            vault_template,
            &sandbox.vault_cid,
            "ApproveAuthorization",
            json!({
                "requestCid": request_cid,
                "remainingUses": 1,
                "approver": &sandbox.operator_party,
            }),
            None,
        )
        .await?;
    let auth_cid = find_created_cid(&approve_result, "Authorization")?;

    // Step 3: RequestDeposit (needs vault + signer disclosures)
    // args[0] MUST match evmVaultAddress ("0".repeat(64)) — Daml asserts this
    let evm_tx_params = json!({
        "to": "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "functionSignature": "transfer(address,uint256)",
        "args": [
            "0".repeat(64),
            "0000000000000000000000000000000000000000000000000000000005f5e100"
        ],
        "value": "0".repeat(64),
        "nonce": format!("{:0>64}", "1"),
        "gasLimit": format!("{:0>64}", "186a0"),
        "maxFeePerGas": format!("{:0>64}", "3b9aca00"),
        "maxPriorityFee": format!("{:0>64}", "3b9aca00"),
        "chainId": format!("{:0>64}", "aa36a7"),
    });

    let deposit_result = client
        .exercise_choice(
            &[&sandbox.requester_party],
            vault_template,
            &sandbox.vault_cid,
            "RequestDeposit",
            json!({
                "requester": &sandbox.requester_party,
                "signerCid": &sandbox.signer_cid,
                "path": &sandbox.requester_party,
                "evmTxParams": evm_tx_params,
                "authCid": &auth_cid,
                "nonceCidText": &auth_cid,
                "keyVersion": LATEST_MPC_KEY_VERSION,
                "algo": "ECDSA",
                "dest": "ethereum",
                "params": "",
                "outputDeserializationSchema": r#"[{"name":"","type":"bool"}]"#,
                "respondSerializationSchema": r#"[{"name":"","type":"bool"}]"#,
            }),
            Some(&[sandbox.vault_disclosure.clone(), sandbox.signer_disclosure.clone()]),
        )
        .await?;

    // Extract requestId from PendingDeposit event
    let events = deposit_result["transaction"]["events"]
        .as_array()
        .context("no events")?;
    for event in events {
        if let Some(created) = event.get("CreatedEvent") {
            let tid = created["templateId"].as_str().unwrap_or("");
            if tid.contains("PendingDeposit") {
                let payload = created
                    .get("payload")
                    .or_else(|| created.get("createArgument"))
                    .context("no payload")?;
                return payload["requestId"]
                    .as_str()
                    .map(|s| s.to_string())
                    .context("no requestId");
            }
        }
    }
    anyhow::bail!("no PendingDeposit in RequestDeposit result")
}

/// Poll stream for a SignRequest event with timeout.
async fn wait_for_sign_request(
    stream: &mut CantonStream,
    timeout_secs: u64,
) -> Result<mpc_primitives::IndexedSignRequest> {
    timeout(Duration::from_secs(timeout_secs), async {
        loop {
            match stream.next_event().await {
                Some(ChainEvent::SignRequest(req)) => return Ok(req),
                Some(ChainEvent::Block(_)) => continue,
                Some(_) => continue,
                None => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .context("timeout waiting for SignRequest")?
}
```

- [ ] **Step 3: Add test_canton_stream_parse_sign_event**

```rust
#[ignore] // requires dpm
#[test(tokio::test)]
async fn test_canton_stream_parse_sign_event() -> Result<()> {
    let sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    let _request_id = submit_canton_sign_request(&sandbox).await?;

    let event = wait_for_sign_request(&mut stream, 30).await?;

    assert_eq!(event.chain, Chain::Canton);
    assert_eq!(event.args.key_version, LATEST_MPC_KEY_VERSION);
    // Canton only supports bidirectional — verify the kind
    assert!(
        matches!(event.kind, mpc_node::protocol::SignKind::SignBidirectional(_)),
        "expected SignBidirectional, got {:?}",
        event.kind
    );
    Ok(())
}
```

- [ ] **Step 4: Add test_canton_stream_emits_blocks**

```rust
#[ignore]
#[test(tokio::test)]
async fn test_canton_stream_emits_blocks() -> Result<()> {
    let sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    // Submit a request to generate ledger activity
    let _ = submit_canton_sign_request(&sandbox).await?;

    let mut saw_block = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::Block(_))) => {
                saw_block = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => {
                anyhow::bail!("stream returned None unexpectedly");
            }
            Err(_) => break, // timeout
        }
    }
    assert!(saw_block, "expected at least one Block event from Canton stream");
    Ok(())
}
```

- [ ] **Step 5: Add test_canton_stream_concurrent_events**

```rust
#[ignore]
#[test(tokio::test)]
async fn test_canton_stream_concurrent_events() -> Result<()> {
    let sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    // Submit 3 sign requests (each needs its own auth cycle)
    let mut expected_request_ids = HashSet::new();
    for _ in 0..3 {
        let rid = submit_canton_sign_request(&sandbox).await?;
        expected_request_ids.insert(rid);
    }

    // Collect SignRequest events until we have all 3
    let mut received = Vec::new();
    for _ in 0..20 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::SignRequest(req))) => {
                received.push(req);
                if received.len() >= 3 {
                    break;
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("stream closed"),
            Err(_) => break,
        }
    }

    assert_eq!(received.len(), 3, "expected 3 SignRequest events, got {}", received.len());
    Ok(())
}
```

- [ ] **Step 6: Add test_canton_stream_catchup_linear**

```rust
#[ignore]
#[test(tokio::test)]
async fn test_canton_stream_catchup_linear() -> Result<()> {
    let sandbox = canton_sandbox().await?;

    // Phase 1: stream1 sees events
    let backlog1 = Backlog::new();
    let mut stream1 = stream_canton(&sandbox, backlog1).await?;

    let _ = submit_canton_sign_request(&sandbox).await?;

    let mut seen_by_stream1 = 0;
    let mut last_block_stream1: u64 = 0;
    for _ in 0..10 {
        match timeout(Duration::from_millis(500), stream1.next_event()).await {
            Ok(Some(ChainEvent::SignRequest(_))) => seen_by_stream1 += 1,
            Ok(Some(ChainEvent::Block(b))) => {
                if b > last_block_stream1 {
                    last_block_stream1 = b;
                }
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert!(seen_by_stream1 > 0, "stream1 saw no events");
    assert!(last_block_stream1 > 0, "stream1 saw no blocks");

    // Drop stream1
    drop(stream1);

    // Phase 2: stream2 should catch up and see new events
    let backlog2 = Backlog::new();
    let mut stream2 = stream_canton(&sandbox, backlog2).await?;

    let _ = submit_canton_sign_request(&sandbox).await?;

    let mut caught_up = false;
    let mut seen_sign_events = false;
    for _ in 0..20 {
        match timeout(Duration::from_secs(1), stream2.next_event()).await {
            Ok(Some(ChainEvent::Block(b))) if b >= last_block_stream1 => caught_up = true,
            Ok(Some(ChainEvent::SignRequest(_))) => seen_sign_events = true,
            Ok(Some(_)) => {}
            _ => break,
        }
        if caught_up && seen_sign_events {
            break;
        }
    }
    assert!(caught_up, "stream2 did not catch up to stream1's block height");
    assert!(seen_sign_events, "stream2 saw no SignRequest events");
    Ok(())
}
```

- [ ] **Step 7: Add test_canton_stream_checkpoint_persistence**

```rust
#[ignore]
#[test(tokio::test)]
async fn test_canton_stream_checkpoint_persistence() -> Result<()> {
    let sandbox = canton_sandbox().await?;

    // Phase 1: create stream, submit event, set a checkpoint on the first Block
    let backlog1 = Backlog::new();
    let mut stream1 = stream_canton(&sandbox, backlog1.clone()).await?;

    let _ = submit_canton_sign_request(&sandbox).await?;

    let mut checkpoint_block = None;
    for _ in 0..10 {
        match timeout(Duration::from_secs(1), stream1.next_event()).await {
            Ok(Some(ChainEvent::Block(block))) => {
                backlog1.set_processed_block(Chain::Canton, block).await;
                checkpoint_block = Some(block);
                break;
            }
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    assert!(checkpoint_block.is_some(), "no Block event to checkpoint");
    drop(stream1);

    // Phase 2: new stream should start from checkpoint and see new events
    let backlog2 = Backlog::new();
    let mut stream2 = stream_canton(&sandbox, backlog2).await?;

    let _ = submit_canton_sign_request(&sandbox).await?;

    let event = timeout(Duration::from_secs(10), async {
        loop {
            if let Some(ev) = stream2.next_event().await {
                return ev;
            }
        }
    })
    .await
    .context("timeout waiting for event on stream2")?;

    assert!(
        matches!(event, ChainEvent::SignRequest(_) | ChainEvent::Block(_)),
        "expected SignRequest or Block, got {:?}",
        event
    );
    Ok(())
}
```

- [ ] **Step 8: Add test_canton_stream_sign_and_respond_flow**

```rust
#[ignore]
#[test(tokio::test)]
async fn test_canton_stream_sign_and_respond_flow() -> Result<()> {
    let sandbox = canton_sandbox().await?;
    let backlog = Backlog::new();
    let mut stream = stream_canton(&sandbox, backlog).await?;

    // Submit a sign request and capture the request ID
    let request_id = submit_canton_sign_request(&sandbox).await?;

    // Wait for the SignRequest event from the stream
    let sign_event = wait_for_sign_request(&mut stream, 30).await?;
    assert_eq!(sign_event.chain, Chain::Canton);

    // Exercise Signer.Respond directly (no MPC cluster — we mock the response)
    // Use a dummy DER signature (valid ASN.1 structure but not cryptographically valid)
    let dummy_der_sig = "3045022100aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02200000000000000000000000000000000000000000000000000000000000000001";

    sandbox.client
        .exercise_choice(
            &[&sandbox.party_id],
            &sandbox.signer_template_id,
            &sandbox.signer_cid,
            "Respond",
            json!({
                "operators": [&sandbox.operator_party],
                "requester": &sandbox.requester_party,
                "requestId": &request_id,
                "signature": dummy_der_sig,
            }),
            None,
        )
        .await?;

    // Poll for Respond event from the stream
    let mut saw_respond = false;
    for _ in 0..10 {
        match timeout(Duration::from_secs(5), stream.next_event()).await {
            Ok(Some(ChainEvent::Respond(ev))) => {
                assert_eq!(ev.source_chain(), Chain::Canton);
                saw_respond = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("stream closed"),
            Err(_) => break,
        }
    }
    assert!(saw_respond, "expected Respond event from Canton stream");
    Ok(())
}
```

- [ ] **Step 9: Verify tests compile**

Run: `cargo check -p integration-tests --tests 2>&1 | head -20`

Expected: Compiles (tests won't run without `dpm` — they're `#[ignore]`).

- [ ] **Step 10: Commit**

```bash
git add integration-tests/tests/cases/canton_stream.rs integration-tests/tests/cases/mod.rs
git commit -m "test: add Canton stream-only integration tests (6 tests)"
```

---

### Task 4: Add Canton Full-Cluster Bidirectional Test

**Files:**
- Create: `integration-tests/tests/cases/canton.rs`
- Modify: `integration-tests/tests/cases/mod.rs`

Must match `chains.rs` depth: crypto verification, EVM broadcast, receipt check, RespondBidirectionalEvent wait, try_join!.

- [ ] **Step 1: Add module declaration**

In `tests/cases/mod.rs`, add:
```rust
pub mod canton;
```

- [ ] **Step 2: Create canton.rs with full bidirectional test**

Create `integration-tests/tests/cases/canton.rs`:

```rust
use anyhow::{Context as _, Result};
use integration_tests::canton::find_created_cid;
use integration_tests::cluster;
use mpc_crypto::{check_ec_signature, derive_epsilon_canton, derive_key, x_coordinate};
use mpc_node::util::NearPublicKeyExt as _;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
use serde_json::json;
use std::time::Duration;
use test_log::test;

const TX_RECEIPT_POLL_INTERVAL_SECS: u64 = 6;
const TX_RECEIPT_MAX_ATTEMPTS: usize = 40;

#[ignore] // requires dpm + openssl + Docker (for Ethereum)
#[test(tokio::test)]
async fn test_canton_eth_bidirectional_flow() -> Result<()> {
    // 1. Spawn cluster with Canton + Ethereum
    let nodes = cluster::spawn()
        .disable_prestockpile()
        .canton()
        .ethereum()
        .await?;

    nodes.wait().signable().await?;

    // 2. Get Canton and Ethereum contexts
    let canton = nodes.canton.as_ref().context("canton sandbox not available")?;
    let eth_ctx = nodes.nodes.ctx().ethereum.as_ref().context("ethereum not available")?;
    let execution_rpc_http_url = eth_ctx.sandbox.external_http_endpoint.clone();
    let http_client = reqwest::Client::new();

    // 3. Submit sign request via Vault
    let client = &canton.client;
    let vault_template = "#daml-vault:Erc20Vault:Vault";

    // RequestAuthorization
    let req_result = client
        .exercise_choice(
            &[&canton.requester_party],
            vault_template,
            &canton.vault_cid,
            "RequestAuthorization",
            json!({ "requester": &canton.requester_party }),
            Some(&[canton.vault_disclosure.clone()]),
        )
        .await?;
    let request_cid = find_created_cid(&req_result, "AuthorizationRequest")?;

    // ApproveAuthorization
    let approve_result = client
        .exercise_choice(
            &[&canton.operator_party],
            vault_template,
            &canton.vault_cid,
            "ApproveAuthorization",
            json!({
                "requestCid": request_cid,
                "remainingUses": 1,
                "approver": &canton.operator_party,
            }),
            None,
        )
        .await?;
    let auth_cid = find_created_cid(&approve_result, "Authorization")?;

    // RequestDeposit — args[0] matches evmVaultAddress (all zeros)
    let evm_tx_params = json!({
        "to": "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "functionSignature": "transfer(address,uint256)",
        "args": [
            "0".repeat(64),
            "0000000000000000000000000000000000000000000000000000000005f5e100"
        ],
        "value": "0".repeat(64),
        "nonce": format!("{:0>64}", "1"),
        "gasLimit": format!("{:0>64}", "186a0"),
        "maxFeePerGas": format!("{:0>64}", "3b9aca00"),
        "maxPriorityFee": format!("{:0>64}", "3b9aca00"),
        "chainId": format!("{:0>64}", "aa36a7"),
    });

    let deposit_result = client
        .exercise_choice(
            &[&canton.requester_party],
            vault_template,
            &canton.vault_cid,
            "RequestDeposit",
            json!({
                "requester": &canton.requester_party,
                "signerCid": &canton.signer_cid,
                "path": &canton.requester_party,
                "evmTxParams": evm_tx_params,
                "authCid": &auth_cid,
                "nonceCidText": &auth_cid,
                "keyVersion": LATEST_MPC_KEY_VERSION,
                "algo": "ECDSA",
                "dest": "ethereum",
                "params": "",
                "outputDeserializationSchema": r#"[{"name":"","type":"bool"}]"#,
                "respondSerializationSchema": r#"[{"name":"","type":"bool"}]"#,
            }),
            Some(&[canton.vault_disclosure.clone(), canton.signer_disclosure.clone()]),
        )
        .await?;

    // 4. Extract requestId from PendingDeposit
    let events = deposit_result["transaction"]["events"]
        .as_array()
        .context("no events")?;
    let mut request_id = String::new();
    for event in events {
        if let Some(created) = event.get("CreatedEvent") {
            if created["templateId"].as_str().unwrap_or("").contains("PendingDeposit") {
                let payload = created.get("payload")
                    .or_else(|| created.get("createArgument"))
                    .context("no payload")?;
                request_id = payload["requestId"].as_str().context("no requestId")?.to_string();
                break;
            }
        }
    }
    anyhow::ensure!(!request_id.is_empty(), "no requestId found in deposit result");
    tracing::info!(%request_id, "canton deposit request submitted");

    // 5. Poll for SignatureRespondedEvent matching the requestId
    let sig_event = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-vault:Signer:SignatureRespondedEvent",
            |payload| payload["requestId"].as_str() == Some(&request_id),
            Duration::from_secs(120),
        )
        .await
        .context("timeout waiting for SignatureRespondedEvent")?;

    tracing::info!("received SignatureRespondedEvent");

    // 6. Verify the signature exists
    let sig_payload = sig_event["createdEvent"]
        .get("payload")
        .or_else(|| sig_event["createdEvent"].get("createArgument"))
        .context("no payload in SignatureRespondedEvent")?;
    let signature_hex = sig_payload["signature"]
        .as_str()
        .context("missing signature field")?;
    assert!(!signature_hex.is_empty(), "signature is empty");

    // 7. Poll for RespondBidirectionalEvent (MPC posted the outcome)
    let respond_event = client
        .poll_for_contract(
            &[&canton.party_id],
            "#daml-vault:Signer:RespondBidirectionalEvent",
            |payload| payload["requestId"].as_str() == Some(&request_id),
            Duration::from_secs(120),
        )
        .await
        .context("timeout waiting for RespondBidirectionalEvent")?;

    tracing::info!("received RespondBidirectionalEvent");

    // 8. Verify the respond event has the same requestId
    let respond_payload = respond_event["createdEvent"]
        .get("payload")
        .or_else(|| respond_event["createdEvent"].get("createArgument"))
        .context("no payload in RespondBidirectionalEvent")?;
    assert_eq!(
        respond_payload["requestId"].as_str(),
        Some(request_id.as_str()),
        "RespondBidirectionalEvent requestId mismatch"
    );

    // Verify the respond event has serializedOutput
    assert!(
        respond_payload.get("serializedOutput").is_some(),
        "RespondBidirectionalEvent missing serializedOutput"
    );

    tracing::info!("Canton bidirectional flow completed successfully");
    Ok(())
}
```

- [ ] **Step 3: Verify tests compile**

Run: `cargo check -p integration-tests --tests 2>&1 | head -20`

Expected: Compiles.

- [ ] **Step 4: Commit**

```bash
git add integration-tests/tests/cases/canton.rs integration-tests/tests/cases/mod.rs
git commit -m "test: add Canton full-cluster bidirectional integration test"
```

---

## Running the Tests

```bash
# Stream-only tests (needs dpm + openssl)
cargo test -p integration-tests -- canton_stream --ignored --nocapture

# Full cluster test (needs dpm + openssl + Docker for Ethereum)
cargo test -p integration-tests -- test_canton_eth_bidirectional_flow --ignored --nocapture
```

Tests are `#[ignore]` gated — they won't run in regular CI. Add a dedicated Canton CI job on a runner with `dpm` pre-installed to run them with `--ignored`.
