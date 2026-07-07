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
    pub big_r_x: String,
    pub big_r_y: String,
    pub s: String,
    pub recovery_id: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serialized_output: Option<String>,
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
    anyhow::ensure!(
        is_hex(&req.big_r_x, 32) && is_hex(&req.big_r_y, 32) && is_hex(&req.s, 32),
        "signature scalars must be 64 hex each"
    );
    anyhow::ensure!(req.recovery_id <= 1, "recovery_id must be 0|1");
    match req.circuit.as_str() {
        "respond" => anyhow::ensure!(req.serialized_output.is_none(), "respond takes no output"),
        "respond_bidirectional" => {
            let out = req.serialized_output.as_deref().unwrap_or("");
            anyhow::ensure!(
                !out.is_empty()
                    && out.len() % 2 == 0
                    && out.len() <= 256
                    && out.bytes().all(|b| b.is_ascii_hexdigit()),
                "serialized_output must be 1..=128 bytes of hex"
            );
        }
        other => anyhow::bail!("unknown circuit {other}"),
    }
    Ok(())
}

/// Circuit CLI args in the toolkit-js codec: Bytes<N> = full zero-padded hex,
/// Uint<N> = decimal.
pub fn circuit_args(req: &RespondRequest) -> Vec<String> {
    match req.circuit.as_str() {
        "respond" => vec![
            req.request_id.clone(),
            req.big_r_x.clone(),
            req.big_r_y.clone(),
            req.s.clone(),
            req.recovery_id.to_string(),
        ],
        "respond_bidirectional" => {
            let out = req.serialized_output.as_deref().expect("validated");
            let output_len = out.len() / 2;
            let padded = format!("{out}{}", "0".repeat(256 - out.len()));
            vec![
                req.request_id.clone(),
                padded,
                output_len.to_string(),
                req.big_r_x.clone(),
                req.big_r_y.clone(),
                req.s.clone(),
                req.recovery_id.to_string(),
            ]
        }
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
        match (method.as_str(), url.as_str()) {
            ("GET", "/health") => respond(request, 200, "ok".into()),
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

    fn sample(circuit: &str, output: Option<&str>) -> RespondRequest {
        RespondRequest {
            contract_address: "ab".repeat(32),
            circuit: circuit.into(),
            request_id: "11".repeat(32),
            big_r_x: "22".repeat(32),
            big_r_y: "33".repeat(32),
            s: "44".repeat(32),
            recovery_id: 1,
            serialized_output: output.map(Into::into),
        }
    }

    /// Must be byte-identical to the fixture in mpc-chain-midnight's
    /// client tests — the seam contract.
    #[test]
    fn respond_request_json_contract_is_stable() {
        let req = sample("respond_bidirectional", Some("00000001"));
        let expected = format!(
            r#"{{"contract_address":"{}","circuit":"respond_bidirectional","request_id":"{}","big_r_x":"{}","big_r_y":"{}","s":"{}","recovery_id":1,"serialized_output":"00000001"}}"#,
            "ab".repeat(32),
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
        );
        assert_eq!(serde_json::to_string(&req).unwrap(), expected);
    }

    #[test]
    fn validation_rules() {
        assert!(validate(&sample("respond", None)).is_ok());
        assert!(validate(&sample("respond", Some("00"))).is_err());
        assert!(validate(&sample("respond_bidirectional", Some("00000001"))).is_ok());
        assert!(validate(&sample("respond_bidirectional", None)).is_err());
        assert!(validate(&sample("respond_bidirectional", Some(&"00".repeat(129)))).is_err());
        assert!(validate(&sample("bogus", None)).is_err());
        let mut bad = sample("respond", None);
        bad.recovery_id = 2;
        assert!(validate(&bad).is_err());
    }

    #[test]
    fn circuit_args_pad_and_order() {
        let args = circuit_args(&sample("respond", None));
        assert_eq!(args.len(), 5);
        assert_eq!(args[4], "1");

        let args = circuit_args(&sample("respond_bidirectional", Some("00000001")));
        assert_eq!(args.len(), 7);
        assert_eq!(args[1].len(), 256, "output zero-padded to Bytes<128>");
        assert!(args[1].starts_with("00000001"));
        assert_eq!(args[2], "4", "outputLen = meaningful byte count");
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
        };
        std::env::set_var("FAKE_TOOLKIT_LOG", &log);
        run_respond_flow(&cfg, &sample("respond", None)).unwrap();

        let calls = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = calls.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("contract-state "));
        assert!(lines[0].contains("--contract-address abab"));
        assert!(lines[1].starts_with("generate-intent circuit "));
        assert!(lines[1].contains("--config"));
        assert!(lines[1].ends_with(&format!(
            "respond {} {} {} {} 1",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32)
        )));
        assert!(lines[2].starts_with("send-intent "));
        assert!(lines[2].contains("--compiled-contract-dir"));
        std::fs::remove_dir_all(&tmp).ok();
    }
}
