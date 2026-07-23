//! Respond-publishing flow: the exact Phase-3 driver-script sequence
//! (contract-state → generate-intent circuit → send-intent) as subprocesses.
//! generate-intent inherently needs node/toolkit-js, so docker mode runs it in
//! the pinned toolkit-033 image; everything else uses the native toolkit
//! binary built from this workspace's seeded lockfile.
//!
//! WHY subprocesses when the toolkit is already a library dependency: its commands
//! ARE callable in-process (`commands::{contract_state, generate_intent,
//! send_intent}::execute`, each taking typed args), so the argv assembled below is
//! a deliberate choice rather than ignorance of that API. Two reasons keep it. The
//! CLI is the toolkit's stable public contract, whereas its internal command types
//! churn between release candidates of an alpha dependency. And proving peaks
//! around 11.5 GiB RSS: as a child process an OOM kills the prover and this service
//! answers 502, while in-process it would take the whole sidecar and every other
//! seam down with it.

use anyhow::Context as _;
use std::io::Read as _;
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
    // `postRespond` -> `SignatureRespondedEvent { bigRx, bigRy, s, recoveryId }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub big_r_x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub big_r_y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,
    // `postRespondBidirectional` -> `RespondBidirectionalEvent { serializedOutput,
    // outputLen, r, s, recoveryId }`. The event stores the WHOLE ABI-encoded
    // return data (`Bytes<128>`, zero-padded, so 256 hex) plus its meaningful
    // byte count, NOT a digest of it.
    //
    // `sig_r`/`sig_s` are LITTLE-ENDIAN, the byte order the record's `Bytes<32>`
    // fields store (the node-side client byte-reverses k256's big-endian
    // scalars before POSTing). The central contract does NOT check any of this:
    // both post circuits are blind appends (counter increment + map insert, no
    // assert), so consumers verify on claim and validity is the caller's
    // responsibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serialized_output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_len: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_r: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_s: Option<String>,
    /// Parity of R.y, carried by BOTH events for off-chain key recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    /// Interface to bind the HTTP server to. Defaults to 127.0.0.1 (a
    /// co-located sidecar; never 0.0.0.0). Overridable for tests.
    pub bind_host: String,
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
    /// Proof server to offload circuit proving to, or `None` to prove locally
    /// in-process.
    ///
    /// Not merely an optimisation for the signet contracts: they are compiled
    /// with `--feature-zkir-v3` (the toolchain floor for in-circuit
    /// `secp256k1EcdsaVerify`), and the ledger this toolkit links pins
    /// `midnight-zkir` 2.2.0, which accepts only `ir-source[v2]`/`[v2-generic]`.
    /// Proving such a contract locally therefore cannot work at all — it aborts
    /// with "expected one of 'ir-source[v2-generic]' or 'ir-source[v2]', got
    /// 'ir-source[v3-generic]'" — while the 9.x proof server handles v3. So for
    /// any zkir-v3 contract this is required, not optional.
    pub proof_server: Option<String>,
    /// JSON-RPC client for the `GET /state` read path (finalized head, header,
    /// `midnight_contractState`). Overridable for tests.
    ///
    /// Still a subprocess, but the original reason ("no async HTTP stack in this
    /// nested workspace") no longer holds: `/block` already links subxt + tokio
    /// in-process. This is un-consolidated rather than justified, and folding it
    /// into an in-process call would drop this config, the fake-rpc harness, and a
    /// spawn per read. It is NOT duplicating the toolkit's own `get_contract_state`,
    /// which requires a fully replayed `LedgerContext`; a single
    /// `midnight_contractState` RPC answers the same question far more cheaply.
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
        let intent_mode = match env_or("MIDNIGHT_PUB_INTENT_MODE", "native").as_str() {
            "docker" => IntentMode::Docker,
            "native" => IntentMode::Native,
            other => anyhow::bail!("MIDNIGHT_PUB_INTENT_MODE must be docker|native, got {other}"),
        };
        let node_url = env_required("MIDNIGHT_PUB_NODE_URL")?;

        // The loopback boundary IS this service's access control: it has no
        // authentication of any kind and it holds a funding wallet. Binding it
        // somewhere reachable must be a deliberate, spelled-out act behind an
        // external authenticated boundary, never a typo in an env var.
        let bind_host = env_or("MIDNIGHT_PUB_BIND_HOST", "127.0.0.1");
        let is_loopback = bind_host == "localhost"
            || bind_host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        anyhow::ensure!(
            is_loopback || env_or("MIDNIGHT_PUB_ALLOW_NON_LOOPBACK", "0") == "1",
            "MIDNIGHT_PUB_BIND_HOST={bind_host} is not a loopback address. This service has \
             no authentication and holds a funding wallet; set \
             MIDNIGHT_PUB_ALLOW_NON_LOOPBACK=1 only when an authenticated boundary fronts it."
        );

        Ok(Self {
            port: env_or("MIDNIGHT_PUB_PORT", "8790").parse()?,
            bind_host,
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
            // Required, never defaulted: a baked-in fallback is a real signing
            // key that ships in the binary and silently works in production.
            signer_secret_key: env_required("MIDNIGHT_PUB_SIGNER_SECRET_KEY")?,
            compactc_version: env_or("MIDNIGHT_PUB_COMPACTC_VERSION", "0.33.0"),
            proof_server: Some(env_or("MIDNIGHT_PUB_PROOF_SERVER_URL", ""))
                .filter(|url| !url.is_empty()),
            curl_bin: PathBuf::from(env_or("MIDNIGHT_PUB_CURL_BIN", "curl")),
        })
    }

    fn run_dir(&self) -> PathBuf {
        // Own subdir: never collide with the driver scripts' .run/ files.
        self.work_dir.join(".run/publisher")
    }

    /// The values that must never reach a log line or an HTTP response body.
    /// Both are passed to the toolkit on its argv, so its stderr can echo them.
    fn secrets(&self) -> [&str; 2] {
        [self.funding_seed.as_str(), self.signer_secret_key.as_str()]
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
                req.serialized_output.is_none()
                    && req.output_len.is_none()
                    && req.sig_r.is_none()
                    && req.sig_s.is_none(),
                "postRespond takes no bidirectional fields"
            );
        }
        "postRespondBidirectional" => {
            // serializedOutput is Bytes<128>: the whole zero-padded ABI return
            // data, not a digest of it.
            anyhow::ensure!(
                req.serialized_output
                    .as_deref()
                    .is_some_and(|v| is_hex(v, 128)),
                "postRespondBidirectional needs serialized_output as 256 lowercase hex (Bytes<128>)"
            );
            anyhow::ensure!(
                req.output_len.is_some_and(|len| len as usize <= 128),
                "postRespondBidirectional output_len must be 0..=128"
            );
            anyhow::ensure!(
                is_hex32(&req.sig_r) && is_hex32(&req.sig_s),
                "postRespondBidirectional needs sig_r/sig_s as 64 lowercase hex each"
            );
            anyhow::ensure!(
                req.recovery_id.is_some_and(|r| r <= 1),
                "postRespondBidirectional recovery_id must be 0|1"
            );
            anyhow::ensure!(
                req.big_r_x.is_none() && req.big_r_y.is_none() && req.s.is_none(),
                "postRespondBidirectional takes no postRespond fields"
            );
        }
        other => anyhow::bail!("unknown circuit {other}"),
    }
    Ok(())
}

/// Circuit CLI args in the toolkit-js codec.
///
/// The toolkit reflects over the Compact-generated `contract/index.d.ts`
/// (`ImpureCircuits`) and parses each argv entry as JSON5 against the declared
/// parameter type, so the arity and shape below are dictated by the contract,
/// not chosen: BOTH circuits take exactly two arguments — the request id, then
/// the whole event struct as ONE JSON object. Passing the struct's fields as
/// separate argv entries fails the toolkit's arity check before proving.
///
/// - `Bytes<N>` is declared `Uint8Array` and takes bare lowercase hex.
/// - `Uint<N>` is declared `bigint` and must be a JSON *number*: struct members
///   are re-serialized before conversion, so a quoted `"1"` would reach
///   `BigInt("'1'")` and throw.
///
/// `sig_r`/`sig_s` are already the little-endian byte order the hub circuit's
/// `Bytes<32> as Secp256k1Scalar` cast expects — the node-side client
/// byte-reverses k256's big-endian scalars before POSTing.
pub fn circuit_args(req: &RespondRequest) -> Vec<String> {
    let field = |f: &Option<String>| f.clone().expect("validated");
    match req.circuit.as_str() {
        // requestId + SignatureRespondedEvent{bigRx, bigRy, s, recoveryId}
        "postRespond" => vec![
            req.request_id.clone(),
            format!(
                r#"{{"bigRx":"{}","bigRy":"{}","s":"{}","recoveryId":{}}}"#,
                field(&req.big_r_x),
                field(&req.big_r_y),
                field(&req.s),
                req.recovery_id.expect("validated"),
            ),
        ],
        // requestId + RespondBidirectionalEvent{serializedOutput, outputLen, r, s, recoveryId}
        "postRespondBidirectional" => vec![
            req.request_id.clone(),
            format!(
                r#"{{"serializedOutput":"{}","outputLen":{},"r":"{}","s":"{}","recoveryId":{}}}"#,
                field(&req.serialized_output),
                req.output_len.expect("validated"),
                field(&req.sig_r),
                field(&req.sig_s),
                req.recovery_id.expect("validated"),
            ),
        ],
        _ => unreachable!("validated"),
    }
}

/// Replace every occurrence of a secret with a placeholder.
///
/// The toolkit takes `--funding-seed` on its argv and several of its failures
/// echo the invocation back, so raw stderr can carry the funding wallet's seed.
/// That stderr becomes an HTTP 502 body and a log line, so it is redacted at the
/// source: every later consumer is then safe by construction.
fn redact(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_string();
    for secret in secrets {
        if !secret.is_empty() {
            out = out.replace(secret, "<redacted>");
        }
    }
    out
}

fn run(mut cmd: Command, what: &str, secrets: &[&str]) -> anyhow::Result<()> {
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
        anyhow::bail!(
            "{what} failed ({}): {}",
            output.status,
            redact(&tail, secrets)
        );
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
    run(fetch, "toolkit contract-state", &cfg.secrets())?;

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
    run(intent, "toolkit generate-intent", &cfg.secrets())?;

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
        // The toolkit's Resolver reads `<dir>/keys/<circuit>.{prover,verifier}`
        // and `<dir>/zkir/<circuit>.bzkir`, so this is the compiled-contract
        // asset root — the same `managed/` the toolkit-js binding names in its
        // `withCompiledFileAssets`, not a separate directory. Point it anywhere
        // else and the resolver finds no circuit data: proving then panics
        // inside the toolkit ("prover key not created") rather than erroring.
        "--compiled-contract-dir",
        &cfg.work_dir.join("managed").display().to_string(),
    ]);
    if let Some(url) = &cfg.proof_server {
        send.args(["--proof-server", url]);
    }
    run(send, "toolkit send-intent", &cfg.secrets())?;
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

/// Fetch a contract's state at a given block (default: the finalized head),
/// decode it, and serialize the `{anchor, tree}` response.
/// `midnight_contractState(addr, at)` honors a block-hash `at`; the blob carries
/// no embedded anchor, so we pin it ourselves.
///
/// `at` is what lets a caller ask "what did block N write to this contract?":
/// read the contract at N and at N's parent and diff the two trees. An indexer
/// walking blocks in order already holds the parent's tree, so that costs one
/// read per block. See `block.rs` for why this replaces trying to recover writes
/// out of a transaction's transcript.
fn fetch_state_response(cfg: &Config, address: &str, at: Option<&str>) -> anyhow::Result<String> {
    let block_hash = match at {
        Some(hash) => hash.to_string(),
        None => rpc_call(cfg, "chain_getFinalizedHead", serde_json::json!([]))?
            .as_str()
            .context("finalized head is not a string")?
            .to_string(),
    };

    let header = rpc_call(cfg, "chain_getHeader", serde_json::json!([&block_hash]))?;
    let number = header
        .get("number")
        .and_then(serde_json::Value::as_str)
        .context("header has no `number`")?;
    let height = u64::from_str_radix(number.trim_start_matches("0x"), 16)
        .context("parsing header.number")?;

    // Address = raw 64-hex, no `0x`; `at` = the 0x-prefixed block hash.
    let blob = rpc_call(
        cfg,
        "midnight_contractState",
        serde_json::json!([address, &block_hash]),
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
            hash: block_hash.trim_start_matches("0x").to_string(),
        }),
        tree,
    };
    Ok(serde_json::to_string(&response)?)
}

/// `GET /state?address=<64hex>[&at=<0xblockhash>]` → 200 `{anchor,tree}` / 400
/// bad address or `at` / 502 fetch or decode failure. Without `at`, reads the
/// finalized head; with it, reads that block, so two reads either side of a
/// block reveal exactly what that block wrote.
fn handle_state(cfg: &Config, url: &str) -> (u16, String) {
    let address = match query_param(url, "address") {
        Some(a) if is_hex(a, 32) => a,
        Some(_) => return (400, "address must be 64 lowercase hex".into()),
        None => return (400, "missing `address` query param".into()),
    };
    let at = match query_param(url, "at") {
        Some(h) if h.starts_with("0x") && is_hex(&h[2..], 32) => Some(h),
        Some(_) => return (400, "at must be `0x` followed by 64 lowercase hex".into()),
        None => None,
    };
    match fetch_state_response(cfg, address, at) {
        Ok(body) => (200, body),
        Err(e) => (502, format!("{e:#}")),
    }
}

// ---- GET /block: finalized-block decode ----------------------------------

/// Fetch a finalized block by hash and decode its per-transaction
/// cross-contract-call provenance. Unwrapping extrinsics into ledger
/// `Transaction` bytes is metadata-aware SCALE decoding, so it drives the
/// toolkit's fetcher lib in-process (not the curl RPC path `/state` uses);
/// `block.rs` then reads each transaction's claimed calls and commitments.
///
/// This seam answers "which transaction called whom", not "what was written":
/// for writes, read `/state?at=` either side of the block and diff.
fn fetch_block_response(cfg: &Config, hash_hex: &str) -> anyhow::Result<String> {
    use midnight_node_toolkit::client::MidnightNodeClient;
    use midnight_node_toolkit::fetcher::{fetch_single_block, fetch_storage::InMemory};
    use subxt::utils::H256;

    let hash_bytes = hex::decode(hash_hex).context("decoding block hash")?;
    anyhow::ensure!(hash_bytes.len() == 32, "block hash must be 32 bytes");
    let block_hash = H256::from_slice(&hash_bytes);

    // The toolkit fetcher is async; drive it from this sync handler on a
    // throwaway single-threaded runtime (one block fetch per request).
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime for block fetch")?;

    let raw = runtime.block_on(async {
        let client = MidnightNodeClient::new(&cfg.node_url, None)
            .await
            .map_err(|e| anyhow::anyhow!("connect to node {}: {e}", cfg.node_url))?;
        // chain_id and block_number are only cache keys for this per-request,
        // discarded InMemory store; the block itself is fetched purely by hash.
        fetch_single_block(
            H256::zero(),
            0,
            block_hash,
            Some(&client),
            &InMemory::default(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("fetch block 0x{hash_hex}: {e}"))
    })?;

    let response = crate::block::decode_block(&raw.transactions)?;
    Ok(serde_json::to_string(&response)?)
}

/// `GET /block?hash=<0xhash>` → 200 `{calls}` / 400 bad hash / 502 fetch or
/// decode failure.
fn handle_block(cfg: &Config, url: &str) -> (u16, String) {
    let hash = match query_param(url, "hash") {
        Some(h) if h.starts_with("0x") && is_hex(&h[2..], 32) => &h[2..],
        Some(_) => return (400, "hash must be `0x` followed by 64 lowercase hex".into()),
        None => return (400, "missing `hash` query param".into()),
    };
    match fetch_block_response(cfg, hash) {
        Ok(body) => (200, body),
        Err(e) => (502, format!("{e:#}")),
    }
}

/// Upper bound on a `POST /respond` body. The payload is a handful of 64-hex
/// fields; anything beyond this is a bug or an attack, not a real request.
const MAX_RESPOND_BODY_BYTES: u64 = 64 * 1024;

pub fn serve(cfg: Config) -> anyhow::Result<()> {
    let server = tiny_http::Server::http((cfg.bind_host.as_str(), cfg.port))
        .map_err(|e| anyhow::anyhow!("bind {}:{}: {e}", cfg.bind_host, cfg.port))?;
    println!(
        "midnight-publisher listening on {}:{} (work dir {})",
        cfg.bind_host,
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
            ("GET", "/block") => {
                let (code, body) = handle_block(&cfg, &url);
                respond(request, code, body);
            }
            ("POST", "/respond") => {
                // Bounded read: a respond payload is a handful of 64-hex fields,
                // and this server is sequential, so one oversized body would
                // otherwise pin the whole service's memory and stall every seam.
                let mut body = String::new();
                if request
                    .as_reader()
                    .take(MAX_RESPOND_BODY_BYTES)
                    .read_to_string(&mut body)
                    .is_err()
                {
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
            serialized_output: None,
            output_len: None,
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
            recovery_id: Some(0),
            serialized_output: Some("55".repeat(128)),
            output_len: Some(64),
            sig_r: Some("66".repeat(32)),
            sig_s: Some("77".repeat(32)),
        }
    }

    fn state_config(curl_bin: PathBuf) -> Config {
        Config {
            port: 0,
            bind_host: "127.0.0.1".into(),
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
            proof_server: None,
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
            r#"{{"contract_address":"{ab}","circuit":"postRespondBidirectional","request_id":"{r1}","serialized_output":"{o}","output_len":64,"sig_r":"{sr}","sig_s":"{ss}","recovery_id":0}}"#,
            ab = "ab".repeat(32),
            r1 = "11".repeat(32),
            o = "55".repeat(128),
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
        bad.serialized_output = Some("55".repeat(128));
        assert!(
            validate(&bad).is_err(),
            "postRespond must reject bidirectional fields"
        );

        // postRespondBidirectional: the whole event, and no postRespond fields.
        let mut bad = post_respond_bidirectional();
        bad.sig_r = None;
        assert!(validate(&bad).is_err());
        let mut bad = post_respond_bidirectional();
        bad.serialized_output = Some("55".repeat(127)); // 254 hex, wrong length
        assert!(validate(&bad).is_err());
        let mut bad = post_respond_bidirectional();
        bad.output_len = None;
        assert!(validate(&bad).is_err(), "outputLen is part of the event");
        let mut bad = post_respond_bidirectional();
        bad.recovery_id = None;
        assert!(validate(&bad).is_err(), "recoveryId is part of the event");
        let mut bad = post_respond_bidirectional();
        bad.big_r_x = Some("22".repeat(32));
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

    /// Both circuits take two arguments: the request id, then the event struct
    /// as one JSON object whose keys are the Compact struct's field names. The
    /// arity is the toolkit's own precondition — it compares argv against the
    /// generated `ImpureCircuits` declaration and refuses to prove on mismatch.
    #[test]
    fn circuit_args_are_request_id_plus_one_event_object() {
        assert_eq!(
            circuit_args(&post_respond()),
            vec![
                "11".repeat(32),
                format!(
                    r#"{{"bigRx":"{}","bigRy":"{}","s":"{}","recoveryId":1}}"#,
                    "22".repeat(32),
                    "33".repeat(32),
                    "44".repeat(32),
                ),
            ]
        );
        assert_eq!(
            circuit_args(&post_respond_bidirectional()),
            vec![
                "11".repeat(32),
                format!(
                    r#"{{"serializedOutput":"{}","outputLen":64,"r":"{}","s":"{}","recoveryId":0}}"#,
                    "55".repeat(128),
                    "66".repeat(32),
                    "77".repeat(32),
                ),
            ]
        );
    }

    /// The event argument must survive the toolkit's JSON5 parse with the exact
    /// key set and JS types the declaration names: hex strings for the
    /// `Uint8Array` fields, and bare numbers for the `bigint` fields (a quoted
    /// number would reach `BigInt("'64'")` inside the toolkit and throw).
    #[test]
    fn event_argument_is_json_with_the_declared_field_types() {
        let args = circuit_args(&post_respond_bidirectional());
        let event: serde_json::Value = serde_json::from_str(&args[1]).unwrap();
        let obj = event.as_object().unwrap();

        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["outputLen", "r", "recoveryId", "s", "serializedOutput"]
        );

        assert_eq!(
            event["serializedOutput"],
            serde_json::json!("55".repeat(128))
        );
        assert_eq!(event["outputLen"], serde_json::json!(64));
        assert_eq!(event["recoveryId"], serde_json::json!(0));
        assert!(event["outputLen"].is_number() && event["recoveryId"].is_number());
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
            bind_host: "127.0.0.1".into(),
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
            proof_server: Some("http://127.0.0.1:6300".into()),
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
            r#"postRespond {} {{"bigRx":"{}","bigRy":"{}","s":"{}","recoveryId":1}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32)
        )));
        assert!(lines[2].starts_with("send-intent "));
        // The resolver root is the compiled-contract asset dir itself: the
        // toolkit reads keys/<circuit>.prover and zkir/<circuit>.bzkir under it.
        assert!(lines[2].contains(&format!(
            "--compiled-contract-dir {}",
            work.join("managed").display()
        )));
        // Proving is offloaded when a proof server is configured — mandatory for
        // the zkir-v3 signet contracts, which the linked ledger cannot prove.
        assert!(lines[2].contains("--proof-server http://127.0.0.1:6300"));
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
    fn block_rejects_bad_hash() {
        // Hash validation happens before any fetch, so no node is contacted.
        let cfg = state_config(PathBuf::from("/bin/false"));
        assert_eq!(handle_block(&cfg, "/block").0, 400, "missing hash");
        assert_eq!(
            handle_block(&cfg, "/block?hash=abc").0,
            400,
            "missing 0x prefix"
        );
        assert_eq!(
            handle_block(&cfg, &format!("/block?hash=0x{}", "ab".repeat(31))).0,
            400,
            "too short (62 hex)"
        );
        assert_eq!(
            handle_block(&cfg, &format!("/block?hash=0x{}", "AB".repeat(32))).0,
            400,
            "uppercase hex rejected"
        );
        // A well-formed hash would proceed to the node fetch, which needs a live
        // node, so it is exercised only in integration, not here.
    }

    #[test]
    fn state_fetches_decodes_and_anchors_via_fake_rpc() {
        let _guard = RPC_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        let _guard = RPC_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    #[test]
    fn config_defaults_localhost_bind_and_native_intent() {
        let _guard = RPC_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (k, v) in [
            ("MIDNIGHT_PUB_NODE_URL", "ws://node:9944"),
            ("MIDNIGHT_PUB_WORK_DIR", "/tmp"),
            ("MIDNIGHT_PUB_TOOLKIT_BIN", "toolkit"),
            ("MIDNIGHT_PUB_FUNDING_SEED", "00"),
            ("MIDNIGHT_PUB_COIN_PUBLIC", "aa"),
            ("MIDNIGHT_PUB_SIGNER_SECRET_KEY", "11"),
        ] {
            std::env::set_var(k, v);
        }
        std::env::remove_var("MIDNIGHT_PUB_BIND_HOST");
        std::env::remove_var("MIDNIGHT_PUB_INTENT_MODE");
        std::env::remove_var("MIDNIGHT_PUB_ALLOW_NON_LOOPBACK");
        let cfg = Config::from_env().expect("from_env with required vars set");
        assert_eq!(cfg.bind_host, "127.0.0.1", "defaults to localhost bind");
        assert!(
            matches!(cfg.intent_mode, IntentMode::Native),
            "defaults to native intent"
        );

        // The signing key is required, never defaulted: a baked-in fallback is a
        // real key shipped in the binary that silently works in production.
        std::env::remove_var("MIDNIGHT_PUB_SIGNER_SECRET_KEY");
        assert!(
            Config::from_env().is_err(),
            "a missing signer secret key must fail startup, not fall back to a baked-in default"
        );
        std::env::set_var("MIDNIGHT_PUB_SIGNER_SECRET_KEY", "11");

        // Loopback is the entire access control, so a reachable bind has to be
        // opted into explicitly and can never be reached by a typo.
        std::env::set_var("MIDNIGHT_PUB_BIND_HOST", "0.0.0.0");
        assert!(
            Config::from_env().is_err(),
            "a non-loopback bind must be refused without an explicit opt-in"
        );
        std::env::set_var("MIDNIGHT_PUB_ALLOW_NON_LOOPBACK", "1");
        assert_eq!(
            Config::from_env()
                .expect("the explicit opt-in permits a reachable bind")
                .bind_host,
            "0.0.0.0"
        );
        std::env::remove_var("MIDNIGHT_PUB_BIND_HOST");
        std::env::remove_var("MIDNIGHT_PUB_ALLOW_NON_LOOPBACK");
    }

    /// Secrets reach the toolkit on its argv, and several of its failures echo
    /// the invocation back. That stderr becomes a 502 body and a log line, so
    /// the seed must never survive the trip.
    #[test]
    fn subprocess_stderr_is_redacted_before_it_escapes() {
        let seed = "c0ffee00c0ffee00c0ffee00c0ffee00";
        let leaked = format!("toolkit: invoked with --funding-seed {seed} and it blew up");
        let safe = redact(&leaked, &[seed, "unused"]);
        assert!(
            !safe.contains(seed),
            "the funding seed must not survive redaction: {safe}"
        );
        assert!(safe.contains("<redacted>"), "{safe}");
    }
}
