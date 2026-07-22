//! Respond-publishing flow: the exact Phase-3 driver-script sequence
//! (contract-state → generate-intent circuit → send-intent) as subprocesses.
//! generate-intent inherently needs node/toolkit-js, so docker mode runs it in
//! the pinned toolkit-033 image; everything else uses the native toolkit
//! binary built from this workspace's seeded lockfile.

use anyhow::Context as _;
use std::path::PathBuf;
use std::process::Command;

/// Mirror of `mpc_chain_midnight::MidnightRespondRequest` — the two workspaces
/// cannot share a crate; the JSON contract is pinned by identical fixtures in
/// both test suites.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RespondRequest {
    pub contract_address: String,
    pub circuit: String,
    pub request_id: String,
    // postRespond fields: the ECDSA nonce point + scalar + recovery id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub big_r_x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub big_r_y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
    // postRespondBidirectional fields: the attestation digest + the secp256k1
    // signature scalars in LITTLE-ENDIAN byte order (the circuit's
    // `Bytes<32> as Secp256k1Scalar` cast), verified in-circuit against the hub's
    // fixed MPC key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_r: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_s: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub work_dir: PathBuf,
    pub node_url: String,
    pub node_url_docker: String,
    pub toolkit_bin: PathBuf,
    pub intent_mode: IntentMode,
    pub toolkit_image: String,
    pub docker_network: String,
    pub toolkit_js_path: String,
    pub funding_seed: String,
    pub coin_public: String,
    pub signer_secret_key: String,
    pub compactc_version: String,
    /// JSON-RPC client for the `GET /state` read path (finalized head, header,
    /// `midnight_contractState`). A subprocess like the toolkit — no async HTTP
    /// stack pulled into this nested workspace. Overridable for tests.
    pub curl_bin: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentMode {
    Docker,
    Native,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_required(key: &str) -> anyhow::Result<String> {
    std::env::var(key).with_context(|| format!("{key} must be set"))
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let intent_mode = match env_or("MIDNIGHT_PUB_INTENT_MODE", "docker").as_str() {
            "docker" => IntentMode::Docker,
            "native" => IntentMode::Native,
            other => anyhow::bail!("MIDNIGHT_PUB_INTENT_MODE must be docker|native, got {other}"),
        };
        let node_url = env_required("MIDNIGHT_PUB_NODE_URL")?;
        Ok(Self {
            port: env_or("MIDNIGHT_PUB_PORT", "8790").parse()?,
            work_dir: PathBuf::from(env_required("MIDNIGHT_PUB_WORK_DIR")?),
            node_url_docker: env_or("MIDNIGHT_PUB_NODE_URL_DOCKER", &node_url),
            node_url,
            toolkit_bin: PathBuf::from(env_required("MIDNIGHT_PUB_TOOLKIT_BIN")?),
            intent_mode,
            toolkit_image: env_or(
                "MIDNIGHT_PUB_TOOLKIT_IMAGE",
                "signet/midnight-node-toolkit:2.0.0-rc.3-compact033",
            ),
            docker_network: env_or("MIDNIGHT_PUB_DOCKER_NETWORK", "midnight-l9"),
            toolkit_js_path: env_or("MIDNIGHT_PUB_TOOLKIT_JS_PATH", ""),
            funding_seed: env_required("MIDNIGHT_PUB_FUNDING_SEED")?,
            coin_public: env_required("MIDNIGHT_PUB_COIN_PUBLIC")?,
            signer_secret_key: env_or("MIDNIGHT_PUB_SIGNER_SECRET_KEY", &"11".repeat(32)),
            compactc_version: env_or("MIDNIGHT_PUB_COMPACTC_VERSION", "0.33.0"),
            curl_bin: PathBuf::from(env_or("MIDNIGHT_PUB_CURL_BIN", "curl")),
        })
    }

    fn run_dir(&self) -> PathBuf {
        // Own subdir: never collide with the driver scripts' .run/ files.
        self.work_dir.join(".run/publisher")
    }
}

fn is_hex(s: &str, bytes: usize) -> bool {
    s.len() == bytes * 2
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn validate(req: &RespondRequest) -> anyhow::Result<()> {
    anyhow::ensure!(
        is_hex(&req.contract_address, 32),
        "contract_address must be 64 lowercase hex"
    );
    anyhow::ensure!(is_hex(&req.request_id, 32), "request_id must be 64 hex");
    let is_hex32 = |field: &Option<String>| field.as_deref().is_some_and(|v| is_hex(v, 32));
    match req.circuit.as_str() {
        "postRespond" => {
            anyhow::ensure!(
                is_hex32(&req.big_r_x) && is_hex32(&req.big_r_y) && is_hex32(&req.s),
                "postRespond needs big_r_x/big_r_y/s as 64 lowercase hex each"
            );
            anyhow::ensure!(
                req.recovery_id.is_some_and(|r| r <= 1),
                "postRespond recovery_id must be 0|1"
            );
            anyhow::ensure!(
                req.output_hash.is_none() && req.sig_r.is_none() && req.sig_s.is_none(),
                "postRespond takes no bidirectional fields"
            );
        }
        "postRespondBidirectional" => {
            anyhow::ensure!(
                is_hex32(&req.output_hash) && is_hex32(&req.sig_r) && is_hex32(&req.sig_s),
                "postRespondBidirectional needs output_hash/sig_r/sig_s as 64 lowercase hex each"
            );
            anyhow::ensure!(
                req.big_r_x.is_none()
                    && req.big_r_y.is_none()
                    && req.s.is_none()
                    && req.recovery_id.is_none(),
                "postRespondBidirectional takes no postRespond fields"
            );
        }
        other => anyhow::bail!("unknown circuit {other}"),
    }
    Ok(())
}

/// Circuit CLI args in the toolkit-js codec: Bytes<N> = full lowercase hex,
/// Uint<N> = decimal. `sig_r`/`sig_s` are already the little-endian byte order
/// the hub circuit's `Bytes<32> as Secp256k1Scalar` cast expects — the node-side
/// client byte-reverses k256's big-endian scalars before POSTing.
pub fn circuit_args(req: &RespondRequest) -> Vec<String> {
    let field = |f: &Option<String>| f.clone().expect("validated");
    match req.circuit.as_str() {
        "postRespond" => vec![
            req.request_id.clone(),
            field(&req.big_r_x),
            field(&req.big_r_y),
            field(&req.s),
            req.recovery_id.expect("validated").to_string(),
        ],
        "postRespondBidirectional" => vec![
            req.request_id.clone(),
            field(&req.output_hash),
            field(&req.sig_r),
            field(&req.sig_s),
        ],
        _ => unreachable!("validated"),
    }
}

fn run(mut cmd: Command, what: &str) -> anyhow::Result<()> {
    let output = cmd.output().with_context(|| format!("spawning {what}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: String = stderr
            .chars()
            .rev()
            .take(2000)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        anyhow::bail!("{what} failed ({}): {tail}", output.status);
    }
    Ok(())
}

fn toolkit_cmd(cfg: &Config) -> Command {
    let mut cmd = Command::new(&cfg.toolkit_bin);
    let cache = cfg.work_dir.join(".cache-native");
    cmd.env("MIDNIGHT_PP", cache.join("zk-params"))
        .env(
            "MN_FETCH_CACHE",
            format!("redb:{}", cache.join("toolkit_fetch_cache.db").display()),
        )
        .env("MN_LEDGER_CACHE_DB", cache.join("toolkit_ledger_cache_db"));
    cmd
}

/// The full Phase-3 respond sequence. Blocking (minutes — proving).
pub fn run_respond_flow(cfg: &Config, req: &RespondRequest) -> anyhow::Result<()> {
    let run_dir = cfg.run_dir();
    std::fs::create_dir_all(&run_dir)?;
    std::fs::create_dir_all(cfg.work_dir.join(".cache-native"))?;
    std::fs::create_dir_all(cfg.work_dir.join(".cache"))?; // docker-mode mount target
    // Private state is an empty record for this contract; keep our own copy so
    // driver-script runs never race us.
    let private_state = run_dir.join("private-state.json");
    if !private_state.exists() {
        std::fs::copy(cfg.work_dir.join(".run/private-state.json"), &private_state)
            .context("copying private state (run deploy.sh first)")?;
    }

    // 1. Fetch current contract state.
    let mut fetch = toolkit_cmd(cfg);
    fetch.args([
        "contract-state",
        "--src-url",
        &cfg.node_url,
        "--contract-address",
        &req.contract_address,
        "--dest-file",
        &run_dir.join("state.mn").display().to_string(),
    ]);
    run(fetch, "toolkit contract-state")?;

    // 2. Generate the circuit intent (needs toolkit-js).
    let args = circuit_args(req);
    let intent = match cfg.intent_mode {
        IntentMode::Docker => {
            let mut cmd = Command::new("docker");
            cmd.args([
                "run",
                "--rm",
                "--network",
                &cfg.docker_network,
                "-e",
                &format!("COMPACTC_VERSION={}", cfg.compactc_version),
                "-e",
                &format!("SIGNER_SECRET_KEY={}", cfg.signer_secret_key),
                "-v",
                &format!("{}:/work", cfg.work_dir.display()),
                "-v",
                &format!("{}:/.cache", cfg.work_dir.join(".cache").display()),
                "-w",
                "/work",
                &cfg.toolkit_image,
                "generate-intent",
                "circuit",
                "--toolkit-js-path",
                "/toolkit-js",
                "--config",
                "/work/signer.config.ts",
                "--src-url",
                &cfg.node_url_docker,
                "--coin-public",
                &cfg.coin_public,
                "--input-onchain-state",
                "/work/.run/publisher/state.mn",
                "--input-private-state",
                "/work/.run/publisher/private-state.json",
                "--output-intent",
                "/work/.run/publisher/publish.intent",
                "--output-private-state",
                "/work/.run/publisher/private-state.json",
                "--output-zswap-state",
                "/work/.run/publisher/publish.zswap.json",
                "--output-result",
                "/work/.run/publisher/publish-result.json",
                "--contract-address",
                &req.contract_address,
                &req.circuit,
            ]);
            cmd.args(&args);
            cmd
        }
        IntentMode::Native => {
            anyhow::ensure!(
                !cfg.toolkit_js_path.is_empty(),
                "MIDNIGHT_PUB_TOOLKIT_JS_PATH required in native intent mode"
            );
            let mut cmd = toolkit_cmd(cfg);
            cmd.env("COMPACTC_VERSION", &cfg.compactc_version)
                .env("SIGNER_SECRET_KEY", &cfg.signer_secret_key);
            cmd.args([
                "generate-intent",
                "circuit",
                "--toolkit-js-path",
                &cfg.toolkit_js_path,
                "--config",
                &cfg.work_dir.join("signer.config.ts").display().to_string(),
                "--src-url",
                &cfg.node_url,
                "--coin-public",
                &cfg.coin_public,
                "--input-onchain-state",
                &run_dir.join("state.mn").display().to_string(),
                "--input-private-state",
                &private_state.display().to_string(),
                "--output-intent",
                &run_dir.join("publish.intent").display().to_string(),
                "--output-private-state",
                &private_state.display().to_string(),
                "--output-zswap-state",
                &run_dir.join("publish.zswap.json").display().to_string(),
                "--output-result",
                &run_dir.join("publish-result.json").display().to_string(),
                "--contract-address",
                &req.contract_address,
                &req.circuit,
            ]);
            cmd.args(&args);
            cmd
        }
    };
    run(intent, "toolkit generate-intent")?;

    // 3. Build + prove + fund + submit.
    let mut send = toolkit_cmd(cfg);
    send.args([
        "send-intent",
        "--src-url",
        &cfg.node_url,
        "--dest-url",
        &cfg.node_url,
        "--funding-seed",
        &cfg.funding_seed,
        "--intent-file",
        &run_dir.join("publish.intent").display().to_string(),
        "--compiled-contract-dir",
        &cfg.work_dir.join(".run/resolver").display().to_string(),
    ]);
    run(send, "toolkit send-intent")?;
    Ok(())
}

// ---- GET /state: anchored contract-state read ----------------------------

#[derive(Debug, serde::Serialize)]
struct Anchor {
    height: u64,
    /// Finalized block hash, bare lowercase hex (no `0x`) to match this
    /// integration's address/atom convention; re-add `0x` for substrate RPCs.
    hash: String,
}

#[derive(Debug, serde::Serialize)]
struct StateResponse {
    anchor: Option<Anchor>,
    tree: crate::state::Node,
}

/// The toolkit's `--src-url` is a `ws://` endpoint; one-shot JSON-RPC reads go
/// over the paired HTTP endpoint.
fn http_rpc_url(node_url: &str) -> String {
    if let Some(rest) = node_url.strip_prefix("ws://") {
        format!("http://{rest}")
    } else if let Some(rest) = node_url.strip_prefix("wss://") {
        format!("https://{rest}")
    } else {
        node_url.to_string()
    }
}

/// One-shot JSON-RPC call via the `curl` subprocess (no async HTTP stack in this
/// nested workspace — same shell-out design as the toolkit steps).
fn rpc_call(
    cfg: &Config,
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        .to_string();
    let mut cmd = Command::new(&cfg.curl_bin);
    cmd.args([
        "-s",
        "-S",
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "-d",
        &body,
        &http_rpc_url(&cfg.node_url),
    ]);
    let output = cmd
        .output()
        .with_context(|| format!("spawning curl for {method}"))?;
    anyhow::ensure!(
        output.status.success(),
        "curl {method} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let resp: serde_json::Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parsing {method} JSON-RPC response"))?;
    if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
        anyhow::bail!("rpc {method} error: {err}");
    }
    resp.get("result")
        .cloned()
        .with_context(|| format!("rpc {method}: response has no result"))
}

/// Value of a `?key=value&...` query-string parameter in a request URL.
fn query_param<'a>(url: &'a str, key: &str) -> Option<&'a str> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// Fetch the contract state anchored to the finalized head, decode it, and
/// serialize the `{anchor, tree}` response. Task 0 proved
/// `midnight_contractState(addr, at)` honors a finalized-block-hash `at`; the
/// blob carries no embedded anchor, so we pin it ourselves.
fn fetch_state_response(cfg: &Config, address: &str) -> anyhow::Result<String> {
    let head = rpc_call(cfg, "chain_getFinalizedHead", serde_json::json!([]))?;
    let head_hash = head
        .as_str()
        .context("finalized head is not a string")?
        .to_string();

    let header = rpc_call(cfg, "chain_getHeader", serde_json::json!([&head_hash]))?;
    let number = header
        .get("number")
        .and_then(serde_json::Value::as_str)
        .context("header has no `number`")?;
    let height = u64::from_str_radix(number.trim_start_matches("0x"), 16)
        .context("parsing header.number")?;

    // Address = raw 64-hex, no `0x`; `at` = the 0x-prefixed finalized hash.
    let blob = rpc_call(
        cfg,
        "midnight_contractState",
        serde_json::json!([address, &head_hash]),
    )?;
    let blob = blob
        .as_str()
        .context("contractState result is not a string")?;
    let raw =
        hex::decode(blob.trim_start_matches("0x")).context("hex-decoding contract-state blob")?;
    let tree = crate::state::decode_contract_state(&raw)?;

    let response = StateResponse {
        anchor: Some(Anchor {
            height,
            hash: head_hash.trim_start_matches("0x").to_string(),
        }),
        tree,
    };
    Ok(serde_json::to_string(&response)?)
}

/// `GET /state?address=<64hex>` → 200 `{anchor,tree}` / 400 bad address / 502
/// fetch or decode failure.
fn handle_state(cfg: &Config, url: &str) -> (u16, String) {
    let address = match query_param(url, "address") {
        Some(a) if is_hex(a, 32) => a,
        Some(_) => return (400, "address must be 64 lowercase hex".into()),
        None => return (400, "missing `address` query param".into()),
    };
    match fetch_state_response(cfg, address) {
        Ok(body) => (200, body),
        Err(e) => (502, format!("{e:#}")),
    }
}

pub fn serve(cfg: Config) -> anyhow::Result<()> {
    let server = tiny_http::Server::http(("0.0.0.0", cfg.port))
        .map_err(|e| anyhow::anyhow!("bind :{}: {e}", cfg.port))?;
    println!(
        "midnight-publisher listening on :{} (work dir {})",
        cfg.port,
        cfg.work_dir.display()
    );
    fn respond(request: tiny_http::Request, code: u16, body: String) {
        let response = tiny_http::Response::from_string(body).with_status_code(code);
        let _ = request.respond(response);
    }
    // Sequential by design: respond proving peaks ~11.5 GiB RSS.
    for mut request in server.incoming_requests() {
        let url = request.url().to_string();
        let method = request.method().as_str().to_string();
        let path = url.split('?').next().unwrap_or(&url);
        match (method.as_str(), path) {
            ("GET", "/health") => respond(request, 200, "ok".into()),
            ("GET", "/state") => {
                let (code, body) = handle_state(&cfg, &url);
                respond(request, code, body);
            }
            ("POST", "/respond") => {
                let mut body = String::new();
                if request.as_reader().read_to_string(&mut body).is_err() {
                    respond(request, 400, "unreadable body".into());
                    continue;
                }
                let parsed: Result<RespondRequest, _> = serde_json::from_str(&body);
                let req = match parsed {
                    Ok(req) => req,
                    Err(e) => {
                        respond(request, 400, format!("invalid JSON: {e}"));
                        continue;
                    }
                };
                if let Err(e) = validate(&req) {
                    respond(request, 400, e.to_string());
                    continue;
                }
                println!("respond: circuit={} rid={}", req.circuit, req.request_id);
                match run_respond_flow(&cfg, &req) {
                    Ok(()) => respond(request, 200, r#"{"status":"ok"}"#.into()),
                    Err(e) => {
                        eprintln!("respond failed: {e:#}");
                        respond(request, 502, format!("{e:#}"));
                    }
                }
            }
            _ => respond(request, 404, "not found".into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serializes env-mutating RPC handler tests (shared FAKE_RPC_* vars).
    static RPC_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn post_respond() -> RespondRequest {
        RespondRequest {
            contract_address: "ab".repeat(32),
            circuit: "postRespond".into(),
            request_id: "11".repeat(32),
            big_r_x: Some("22".repeat(32)),
            big_r_y: Some("33".repeat(32)),
            s: Some("44".repeat(32)),
            recovery_id: Some(1),
            output_hash: None,
            sig_r: None,
            sig_s: None,
        }
    }

    fn post_respond_bidirectional() -> RespondRequest {
        RespondRequest {
            contract_address: "ab".repeat(32),
            circuit: "postRespondBidirectional".into(),
            request_id: "11".repeat(32),
            big_r_x: None,
            big_r_y: None,
            s: None,
            recovery_id: None,
            output_hash: Some("55".repeat(32)),
            sig_r: Some("66".repeat(32)),
            sig_s: Some("77".repeat(32)),
        }
    }

    fn state_config(curl_bin: PathBuf) -> Config {
        Config {
            port: 0,
            work_dir: std::env::temp_dir(),
            node_url: "ws://node:9944".into(),
            node_url_docker: "ws://node:9944".into(),
            toolkit_bin: PathBuf::from("toolkit"),
            intent_mode: IntentMode::Native,
            toolkit_image: String::new(),
            docker_network: String::new(),
            toolkit_js_path: String::new(),
            funding_seed: String::new(),
            coin_public: String::new(),
            signer_secret_key: String::new(),
            compactc_version: String::new(),
            curl_bin,
        }
    }

    /// The `/respond` JSON seam. Both circuit bodies must stay byte-identical to
    /// the node-side `mpc_chain_midnight` client fixture — the two duplicated
    /// `RespondRequest` structs are pinned by these exact strings on both sides.
    #[test]
    fn respond_request_json_seam_is_stable() {
        let expected_post_respond = format!(
            r#"{{"contract_address":"{ab}","circuit":"postRespond","request_id":"{r1}","big_r_x":"{r2}","big_r_y":"{r3}","s":"{r4}","recovery_id":1}}"#,
            ab = "ab".repeat(32),
            r1 = "11".repeat(32),
            r2 = "22".repeat(32),
            r3 = "33".repeat(32),
            r4 = "44".repeat(32),
        );
        assert_eq!(
            serde_json::to_string(&post_respond()).unwrap(),
            expected_post_respond
        );

        let expected_bidirectional = format!(
            r#"{{"contract_address":"{ab}","circuit":"postRespondBidirectional","request_id":"{r1}","output_hash":"{h}","sig_r":"{sr}","sig_s":"{ss}"}}"#,
            ab = "ab".repeat(32),
            r1 = "11".repeat(32),
            h = "55".repeat(32),
            sr = "66".repeat(32),
            ss = "77".repeat(32),
        );
        assert_eq!(
            serde_json::to_string(&post_respond_bidirectional()).unwrap(),
            expected_bidirectional
        );
    }

    #[test]
    fn validation_rules() {
        assert!(validate(&post_respond()).is_ok());
        assert!(validate(&post_respond_bidirectional()).is_ok());

        // postRespond: recovery must be 0|1, all three scalars present, no bidi.
        let mut bad = post_respond();
        bad.recovery_id = Some(2);
        assert!(validate(&bad).is_err());
        let mut bad = post_respond();
        bad.recovery_id = None;
        assert!(validate(&bad).is_err());
        let mut bad = post_respond();
        bad.big_r_x = None;
        assert!(validate(&bad).is_err());
        let mut bad = post_respond();
        bad.output_hash = Some("55".repeat(32));
        assert!(
            validate(&bad).is_err(),
            "postRespond must reject bidirectional fields"
        );

        // postRespondBidirectional: needs the three 64-hex fields, no post fields.
        let mut bad = post_respond_bidirectional();
        bad.sig_r = None;
        assert!(validate(&bad).is_err());
        let mut bad = post_respond_bidirectional();
        bad.output_hash = Some("55".repeat(31)); // 62 hex — wrong length
        assert!(validate(&bad).is_err());
        let mut bad = post_respond_bidirectional();
        bad.recovery_id = Some(0);
        assert!(
            validate(&bad).is_err(),
            "postRespondBidirectional must reject postRespond fields"
        );

        // Uppercase hex rejected; the old circuit names are gone.
        let mut bad = post_respond();
        bad.s = Some("AA".repeat(32));
        assert!(validate(&bad).is_err());
        let mut bad = post_respond();
        bad.circuit = "respond".into();
        assert!(validate(&bad).is_err(), "old circuit name removed");
    }

    #[test]
    fn circuit_args_order() {
        assert_eq!(
            circuit_args(&post_respond()),
            vec![
                "11".repeat(32),
                "22".repeat(32),
                "33".repeat(32),
                "44".repeat(32),
                "1".to_string(),
            ]
        );
        assert_eq!(
            circuit_args(&post_respond_bidirectional()),
            vec![
                "11".repeat(32),
                "55".repeat(32),
                "66".repeat(32),
                "77".repeat(32),
            ]
        );
    }

    /// Runs the full flow against a fake toolkit that records its argv; pins
    /// the exact command sequence the Phase-3 drivers validated.
    #[test]
    fn respond_flow_invokes_toolkit_in_driver_order() {
        let tmp = std::env::temp_dir().join(format!("mn-pub-test-{}", std::process::id()));
        let work = tmp.join("work");
        std::fs::create_dir_all(work.join(".run")).unwrap();
        std::fs::write(work.join(".run/private-state.json"), "{}").unwrap();
        let log = tmp.join("calls.log");
        let fake = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fake-toolkit.sh");

        let cfg = Config {
            port: 0,
            work_dir: work.clone(),
            node_url: "ws://node:9944".into(),
            node_url_docker: "ws://node:9944".into(),
            toolkit_bin: fake,
            intent_mode: IntentMode::Native,
            toolkit_image: String::new(),
            docker_network: String::new(),
            toolkit_js_path: "/toolkit-js".into(),
            funding_seed: "00".repeat(31) + "01",
            coin_public: "aa".repeat(32),
            signer_secret_key: "11".repeat(32),
            compactc_version: "0.33.0".into(),
            curl_bin: PathBuf::from("curl"),
        };
        std::env::set_var("FAKE_TOOLKIT_LOG", &log);
        run_respond_flow(&cfg, &post_respond()).unwrap();

        let calls = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = calls.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("contract-state "));
        assert!(lines[0].contains("--contract-address abab"));
        assert!(lines[1].starts_with("generate-intent circuit "));
        assert!(lines[1].contains("--config"));
        assert!(lines[1].ends_with(&format!(
            "postRespond {} {} {} {} 1",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32)
        )));
        assert!(lines[2].starts_with("send-intent "));
        assert!(lines[2].contains("--compiled-contract-dir"));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn query_param_parses_address() {
        assert_eq!(query_param("/state?address=abc", "address"), Some("abc"));
        assert_eq!(
            query_param("/state?foo=1&address=de&bar=2", "address"),
            Some("de")
        );
        assert_eq!(query_param("/state", "address"), None);
        assert_eq!(query_param("/state?foo=1", "address"), None);
    }

    #[test]
    fn state_rejects_bad_address() {
        // Validation happens before any RPC, so curl is never invoked.
        let cfg = state_config(PathBuf::from("/bin/false"));
        assert_eq!(handle_state(&cfg, "/state").0, 400, "missing address");
        assert_eq!(handle_state(&cfg, "/state?address=xyz").0, 400, "not hex");
        assert_eq!(
            handle_state(&cfg, &format!("/state?address={}", "AB".repeat(32))).0,
            400,
            "uppercase hex rejected"
        );
    }

    #[test]
    fn state_fetches_decodes_and_anchors_via_fake_rpc() {
        let _guard = RPC_ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("mn-pub-state-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let log = tmp.join("rpc.log");
        let fake = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fake-rpc.sh");
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/reference-state.mn");

        let head = "a".repeat(64);
        std::env::set_var("FAKE_RPC_LOG", &log);
        std::env::set_var("FAKE_RPC_HEAD", &head);
        std::env::set_var("FAKE_RPC_NUMBER", "0x2a");
        std::env::set_var("FAKE_RPC_STATE_MN", &fixture);

        let addr = "2b".repeat(32);
        let (code, body) = handle_state(&state_config(fake), &format!("/state?address={addr}"));
        assert_eq!(code, 200, "body: {body}");

        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["anchor"]["height"].as_u64(), Some(42));
        assert_eq!(v["anchor"]["hash"].as_str(), Some(head.as_str()));
        assert_eq!(v["tree"]["kind"], "array");
        assert_eq!(
            v["tree"]["children"][0]["atoms"][0],
            "1ff6b01828eaff69181037f78de6ef97fb4e179c082302633f6f99c39790c476"
        );

        // Driver order: finalized head, then its header, then the anchored read.
        let calls = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = calls.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("chain_getFinalizedHead"));
        assert!(lines[1].contains("chain_getHeader"));
        assert!(lines[2].contains("midnight_contractState"));
        assert!(
            lines[2].contains(&addr),
            "read the requested contract address"
        );
        assert!(
            lines[2].contains(&format!("0x{head}")),
            "read anchored at the finalized head"
        );
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn state_decode_failure_is_502() {
        let _guard = RPC_ENV_LOCK.lock().unwrap();
        let tmp = std::env::temp_dir().join(format!("mn-pub-state502-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let bad = tmp.join("bad.mn");
        std::fs::write(&bad, b"not a valid contract-state blob").unwrap();
        let fake = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fake-rpc.sh");

        std::env::set_var("FAKE_RPC_LOG", tmp.join("rpc.log"));
        std::env::set_var("FAKE_RPC_HEAD", "b".repeat(64));
        std::env::set_var("FAKE_RPC_NUMBER", "0x1");
        std::env::set_var("FAKE_RPC_STATE_MN", &bad);

        let (code, _) = handle_state(
            &state_config(fake),
            &format!("/state?address={}", "2b".repeat(32)),
        );
        assert_eq!(code, 502, "undecodable blob is a 502");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
