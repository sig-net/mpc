//! Bootstrap and exercise the local MPC cluster defined by `localnet/docker-compose.yaml`.
//!
//! `bootstrap` prepares both chains the cluster depends on: it creates the NEAR accounts,
//! deploys and initialises the MPC contract that holds the participant set, installs the
//! Solana signet program and creates its state account. It also writes a dealt stock of
//! triples and presignatures into Redis, so every node starts from the same material on every
//! run. `sign` submits a signature request through that program and waits for the cluster to
//! answer.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::signer::Signer;

mod keygen;
mod keyshare;
mod near;
mod nodes;
mod request_id;
mod solana;
mod stockpile;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Prepare both chains: NEAR accounts and contract, Solana program and state.
    Bootstrap(BootstrapArgs),
    /// Prepare only the NEAR side.
    BootstrapNear(BootstrapArgs),
    /// Prepare only the Solana side.
    BootstrapSolana(BootstrapArgs),
    /// Preload only the triples and presignatures.
    Stockpile(BootstrapArgs),
    /// Submit a signature request and wait for the cluster to answer it.
    Sign(SignArgs),
    /// Write a fresh set of per-node env files. Run this to rotate the localnet's keys.
    Keygen(KeygenArgs),
}

#[derive(clap::Args, Debug)]
struct KeygenArgs {
    /// Where to write the `node<N>.env` files.
    #[arg(long, default_value = "localnet/nodes")]
    out_dir: PathBuf,
    /// How many nodes to generate. Committed key shares exist for 3 and 5.
    #[arg(long, default_value_t = 3)]
    nodes: usize,
    /// NEAR account each node uses, formatted with its index.
    #[arg(long, default_value = "mpc{i}.test.near")]
    account_template: String,
    /// URL peers reach each node on. `{i}` is the node index, `{port}` its web port.
    ///
    /// Every node runs inside one container, so peers reach each other over loopback and
    /// each needs a port of its own.
    #[arg(long, default_value = "http://127.0.0.1:{port}")]
    address_template: String,
    /// Port of node 0. Each subsequent node takes the next one.
    #[arg(long, default_value_t = 3000)]
    base_port: u16,
}

#[derive(clap::Args, Debug)]
struct BootstrapArgs {
    /// Directory holding the per-node `node<N>.env` files.
    #[arg(long, env = "LOCALNET_NODES_DIR", default_value = "/localnet/nodes")]
    nodes_dir: PathBuf,
    /// Directory holding the committed key shares, named after their owning account.
    #[arg(long, env = "LOCALNET_KEYSHARES_DIR", default_value = "/localnet/keyshares")]
    keyshares_dir: PathBuf,
    /// Compiled MPC contract to deploy on the NEAR sandbox.
    #[arg(long, env = "LOCALNET_CONTRACT_WASM", default_value = "/artifacts/mpc_contract.wasm")]
    contract_wasm: PathBuf,
    /// Compiled Solana signet program to install.
    #[arg(long, env = "LOCALNET_PROGRAM_SO", default_value = "/artifacts/chain_signatures.so")]
    program_so: PathBuf,

    #[arg(long, env = "LOCALNET_NEAR_RPC", default_value = "http://near-sandbox:3030")]
    near_rpc: String,
    /// Root account baked into the near-sandbox image's genesis.
    #[arg(long, env = "LOCALNET_NEAR_ROOT_ACCOUNT", default_value = "test.near")]
    near_root_account: String,
    /// Validator key of the sandbox's root account.
    ///
    /// Derived from the root account name when omitted, matching the `--test-seed` the
    /// sandbox image initialises with. Set this only when pointing the localnet at a sandbox
    /// someone else initialised.
    #[arg(long, env = "LOCALNET_NEAR_ROOT_SK")]
    near_root_sk: Option<String>,
    /// Account the MPC contract is deployed to.
    #[arg(long, env = "LOCALNET_CONTRACT_ACCOUNT", default_value = "mpc.test.near")]
    contract_account: String,
    /// Number of participants required to produce a signature.
    #[arg(long, env = "LOCALNET_THRESHOLD", default_value_t = 2)]
    threshold: usize,

    #[arg(long, env = "LOCALNET_SOLANA_RPC", default_value = "http://surfpool:8899")]
    solana_rpc: String,
    /// Deposit the signet program charges per signature request, in lamports.
    #[arg(long, env = "LOCALNET_SIGNATURE_DEPOSIT", default_value_t = 1_000_000)]
    signature_deposit: u64,
    /// CAIP-2 chain id the signet program reports in its events.
    #[arg(long, env = "LOCALNET_SOLANA_CHAIN_ID", default_value = "solana:localnet")]
    solana_chain_id: String,
    /// Balance to top the requester and each node's Solana account up to, in lamports.
    #[arg(long, env = "LOCALNET_ACCOUNT_LAMPORTS", default_value_t = 10_000_000_000)]
    account_lamports: u64,

    #[arg(long, env = "LOCALNET_REDIS_URL", default_value = "redis://redis:6379")]
    redis_url: String,
    /// Dealt triples and presignatures to preload, from the integration test fixture.
    #[arg(long, env = "LOCALNET_FIXTURE", default_value = "/artifacts/mpc_fixture.json")]
    fixture: PathBuf,
    /// Preload triples and presignatures at all.
    ///
    /// Turn this off to have the cluster generate its own, the way a deployed network does.
    /// On this profile that costs nothing measurable: see `AGENTS.md`.
    #[arg(
        long,
        env = "LOCALNET_STOCKPILE",
        default_value_t = true,
        action = clap::ArgAction::Set,
    )]
    stockpile: bool,
}

#[derive(clap::Args, Debug)]
struct SignArgs {
    #[arg(long, env = "LOCALNET_SOLANA_RPC", default_value = "http://surfpool:8899")]
    solana_rpc: String,
    /// 32 byte payload to sign, as hex. Randomised when omitted.
    #[arg(long)]
    payload: Option<String>,
    /// Derivation path for the requested key.
    #[arg(long, default_value = "test")]
    path: String,
    #[arg(long, default_value_t = 0)]
    key_version: u32,
    #[arg(long, default_value = "")]
    algo: String,
    #[arg(long, default_value = "")]
    dest: String,
    #[arg(long, default_value = "")]
    params: String,
    /// How long to wait for the cluster to answer, in seconds.
    #[arg(long, default_value_t = 180)]
    timeout: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mpc_localnet=info".into()),
        )
        .init();

    match Cli::parse().command {
        Command::Bootstrap(args) => {
            bootstrap_near(&args).await?;
            bootstrap_solana(&args).await?;
            stockpile(&args).await?;
            println!("localnet is bootstrapped");
        }
        Command::BootstrapNear(args) => bootstrap_near(&args).await?,
        Command::BootstrapSolana(args) => bootstrap_solana(&args).await?,
        Command::Stockpile(args) => stockpile(&args).await?,
        Command::Sign(args) => sign(&args).await?,
        Command::Keygen(args) => {
            keygen::write_all(
                &args.out_dir,
                args.nodes,
                &args.account_template,
                &args.address_template,
                args.base_port,
            )?;
        }
    }
    Ok(())
}

async fn bootstrap_near(args: &BootstrapArgs) -> anyhow::Result<()> {
    let nodes = nodes::load_all(&args.nodes_dir)?;
    let shares = keyshare::load_all(&args.keyshares_dir, &nodes)?;
    let public_key = keyshare::shared_public_key(&shares)?;
    tracing::info!(nodes = nodes.len(), "loaded node specs and key shares");

    near::wait_until_healthy(&args.near_rpc, HEALTH_TIMEOUT).await?;

    let config = near::NearConfig {
        rpc_url: args.near_rpc.clone(),
        root_account_id: args.near_root_account.parse().context("root account id")?,
        root_sk: match &args.near_root_sk {
            Some(secret_key) => secret_key.parse().map_err(|err| {
                anyhow::anyhow!("LOCALNET_NEAR_ROOT_SK is not a valid secret key: {err:?}")
            })?,
            // The sandbox image runs `init --test-seed <root account>`, so the root key is a
            // function of the account name. Deriving it here rather than copying the literal
            // keeps the two from drifting when the image is rebuilt.
            None => near_workspaces::types::SecretKey::from_seed(
                near_workspaces::types::KeyType::ED25519,
                &args.near_root_account,
            ),
        },
        contract_account_id: args.contract_account.parse().context("contract account id")?,
        threshold: args.threshold,
    };
    near::bootstrap(&config, &nodes, &args.contract_wasm, public_key).await
}

async fn bootstrap_solana(args: &BootstrapArgs) -> anyhow::Result<()> {
    let nodes = nodes::load_all(&args.nodes_dir)?;
    let rpc = RpcClient::new_with_commitment(args.solana_rpc.clone(), CommitmentConfig::confirmed());
    solana::wait_until_healthy(&rpc, HEALTH_TIMEOUT).await?;

    let program_id = solana::program_id()?;
    if solana::is_program_installed(&rpc, &program_id).await? {
        tracing::info!(%program_id, "solana program is already installed");
    } else {
        let binary = std::fs::read(&args.program_so)
            .with_context(|| format!("reading {}", args.program_so.display()))?;
        solana::install_program(&rpc, &args.solana_rpc, &program_id, &binary).await?;
    }

    let requester = solana::requester_keypair()?;
    solana::ensure_funded(&rpc, &requester.pubkey(), args.account_lamports).await?;
    for node in &nodes {
        solana::ensure_funded(&rpc, &node.solana_pubkey(), args.account_lamports).await?;
    }

    if solana::is_program_initialized(&rpc, &program_id).await? {
        tracing::info!("solana program state already exists");
    } else {
        solana::initialize(
            &rpc,
            &requester,
            &program_id,
            args.signature_deposit,
            &args.solana_chain_id,
        )
        .await?;
    }

    tracing::info!(
        requester = %requester.pubkey(),
        responders = ?nodes.iter().map(|node| node.solana_pubkey().to_string()).collect::<Vec<_>>(),
        "solana side is ready",
    );
    Ok(())
}

/// Fill Redis with dealt triples and presignatures, so every node starts from the same known
/// stock on every run.
///
/// This runs before any node starts, since the compose file makes them wait for the bootstrap
/// to exit. Writing into a live cluster's storage would race its own generation.
async fn stockpile(args: &BootstrapArgs) -> anyhow::Result<()> {
    if !args.stockpile {
        tracing::info!("stockpiling is off, the cluster will generate its own material");
        return Ok(());
    }

    let nodes = nodes::load_all(&args.nodes_dir)?;
    if let Some(loaded) =
        stockpile::run(&args.fixture, &args.redis_url, &nodes, args.threshold).await?
    {
        tracing::info!(
            triple_pairs = loaded.triple_pairs,
            presignatures = loaded.presignatures,
            nodes = nodes.len(),
            "preloaded triples and presignatures for every node",
        );
    }
    Ok(())
}

async fn sign(args: &SignArgs) -> anyhow::Result<()> {
    let payload: [u8; 32] = match &args.payload {
        Some(hex_payload) => hex::decode(hex_payload)
            .context("--payload is not valid hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("--payload must be exactly 32 bytes"))?,
        None => rand_payload(),
    };

    let rpc = RpcClient::new_with_commitment(args.solana_rpc.clone(), CommitmentConfig::confirmed());
    let program_id = solana::program_id()?;
    let requester = solana::requester_keypair()?;

    let signature = solana::sign(
        &rpc,
        &requester,
        &program_id,
        payload,
        &args.path,
        args.key_version,
        &args.algo,
        &args.dest,
        &args.params,
    )
    .await?;

    let events = solana::decode_events(&rpc, &signature, &program_id).await?;
    let requested = events
        .into_iter()
        .find_map(|event| match event {
            solana::DecodedEvent::SignatureRequested(requested) => Some(requested),
            _ => None,
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the sign transaction emitted no SignatureRequestedEvent. The validator did not \
                 return the anchor CPI event in the transaction's inner instructions, so the MPC \
                 nodes cannot see this request either."
            )
        })?;

    let request_id = request_id::for_signature_request(&requested);
    println!("request id: {}", hex::encode(request_id));
    println!("waiting for the cluster to respond...");

    let responded = solana::await_response(
        &rpc,
        &program_id,
        request_id,
        Duration::from_secs(args.timeout),
    )
    .await?;

    println!("big_r.x:     {}", hex::encode(responded.signature.big_r.x));
    println!("big_r.y:     {}", hex::encode(responded.signature.big_r.y));
    println!("s:           {}", hex::encode(responded.signature.s));
    println!("recovery_id: {}", responded.signature.recovery_id);
    Ok(())
}

/// A payload with no meaning, for when the caller did not supply one.
fn rand_payload() -> [u8; 32] {
    use solana_sdk::signature::Signer as _;
    // Reuse a fresh keypair's public key as 32 bytes of entropy, which avoids taking a
    // dependency on a random number generator just for this.
    solana_sdk::signature::Keypair::new().pubkey().to_bytes()
}
