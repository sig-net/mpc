//! Live-network gate for the wire layer: assemble, sign, broadcast, and
//! settle a `TriggerSmartContract` transaction against a configured
//! endpoint, plus duplicate-broadcast and codeless-address probes.
//! The recorded-response replay runs in CI; live legs are opt-in via
//! env vars (see README).

use anyhow::{bail, Context};
use k256::ecdsa::SigningKey;
use mpc_chain_integration_core::{ChainIndexer, MockStateManager, StateManager};
use mpc_chain_tron::{
    BroadcastOutcome, TronConfig, TronExecutionResult, TronHttp, TronReceipt, TronWatcher,
};
use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, Chain, ChainEvent, ExecutionOutcome, SignId,
};
use mpc_tron_wire::{
    parse_hex,
    pb::{Contract, ContractType, Message, RawTransaction, TriggerSmartContract},
    NowBlock, TronAddress,
};
use prost_types::Any;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use url::Url;

use alloy::primitives::{Address, B256, U256};
use alloy::sol_types::SolCall;

fn env_secs(name: &str, default: u64) -> anyhow::Result<Duration> {
    Ok(Duration::from_secs(match std::env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("{name}: not a number of seconds"))?,
        Err(_) => default,
    }))
}

/// Nile USDT; verified by `triggerconstantcontract name()` = "Tether USD".
const DEFAULT_CONTRACT: &str = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf";

/// Tron's 3 s slot — also the expiry leg's window length.
const SLOT_MS: i64 = 3_000;

alloy::sol! {
    interface Trc20 {
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

/// `transfer(address,uint256)` calldata: selector plus two padded words —
/// the exact shape of the recorded mainnet USDT transfers.
fn usdt_transfer_calldata(to: &TronAddress, amount: u64) -> Vec<u8> {
    Trc20::transferCall {
        to: Address::from_slice(&to.as_bytes()[1..]),
        amount: U256::from(amount),
    }
    .abi_encode()
}

fn transfer_topic() -> B256 {
    alloy::primitives::keccak256(b"Transfer(address,address,uint256)")
}

/// Validity window and energy-fee cap; observed on recorded transfers.
const EXPIRATION_MS: i64 = 300_000;
const FEE_LIMIT_SUN: i64 = 50_000_000;
const TRIGGER_SMART_CONTRACT_TYPE_URL: &str = "type.googleapis.com/protocol.TriggerSmartContract";

/// Minimal watcher-leg backlog entry: identity and bytes, `request_id`
/// mirroring the flat id, Nile-targeted.
fn bidirectional_tx(
    id: [u8; 32],
    serialized_transaction: Vec<u8>,
    source_chain: Chain,
) -> Arc<BidirectionalTx> {
    Arc::new(BidirectionalTx {
        id: BidirectionalTxId(id),
        sender: [0u8; 32],
        serialized_transaction,
        source_chain,
        target_chain: Chain::Tron,
        caip2_id: "tron:nile".to_string(),
        key_version: 0,
        deposit: 0,
        path: String::new(),
        algo: "secp256k1".to_string(),
        dest: "tron:nile".to_string(),
        params: String::new(),
        output_deserialization_schema: vec![],
        respond_serialization_schema: vec![],
        request_id: id,
        from_address: [0u8; 20],
        nonce: 0,
    })
}

/// Test-local assembly of raw transactions from structured parameters,
/// with the standard 5-minute validity window.
fn build_raw(
    owner: &TronAddress,
    contract: &TronAddress,
    call_data: &[u8],
    reference: &NowBlock,
    now_ms: i64,
) -> RawTransaction {
    build_raw_expiring(
        owner,
        contract,
        call_data,
        reference,
        now_ms,
        now_ms + EXPIRATION_MS,
    )
}

/// As [`build_raw`] with an explicit expiration — the live expiry gate
/// needs a window shorter than any realistic confirmation.
fn build_raw_expiring(
    owner: &TronAddress,
    contract: &TronAddress,
    call_data: &[u8],
    reference: &NowBlock,
    now_ms: i64,
    expiration: i64,
) -> RawTransaction {
    let trigger = TriggerSmartContract {
        owner_address: owner.as_bytes().to_vec(),
        contract_address: contract.as_bytes().to_vec(),
        call_value: 0,
        data: call_data.to_vec(),
        call_token_value: 0,
        token_id: 0,
    };
    let contract = Contract {
        r#type: ContractType::TriggerSmartContract as i32,
        parameter: Some(Any {
            type_url: TRIGGER_SMART_CONTRACT_TYPE_URL.to_string(),
            value: trigger.encode_to_vec(),
        }),
        permission_id: 0,
    };
    let (ref_block_bytes, ref_block_hash) = reference.reference_fields();
    RawTransaction {
        ref_block_bytes,
        ref_block_num: 0,
        ref_block_hash,
        expiration,
        timestamp: now_ms,
        fee_limit: FEE_LIMIT_SUN,
        contract: vec![contract],
    }
}

/// A spawned [`TronWatcher`] over a mock backlog: its event channel,
/// plus the task to join on stop.
struct WatcherRun {
    cancel: CancellationToken,
    events: tokio::sync::mpsc::Receiver<ChainEvent>,
    done: tokio::task::JoinHandle<anyhow::Result<()>>,
}

fn spawn_watcher(config: TronConfig, state: MockStateManager) -> anyhow::Result<WatcherRun> {
    let watcher = TronWatcher::new(
        config,
        state,
        mpc_chain_integration_core::NoopChainTelemetry,
    )?;
    let (events_tx, events) = tokio::sync::mpsc::channel(64);
    let cancel = CancellationToken::new();
    let done = tokio::spawn({
        let cancel = cancel.clone();
        async move { watcher.run(events_tx, cancel).await }
    });
    Ok(WatcherRun {
        cancel,
        events,
        done,
    })
}

impl WatcherRun {
    async fn stop(self) -> anyhow::Result<()> {
        self.cancel.cancel();
        self.done.await?
    }
}

/// One gate run: connection, signer, and timing.
struct Gate {
    client: TronHttp,
    endpoint: Url,
    api_key: Option<secrecy::SecretString>,
    key: SigningKey,
    owner: TronAddress,
    contract: TronAddress,
    poll: Duration,
    deadline: Duration,
}

/// What the later probes reuse from the acceptance broadcast.
struct Broadcast {
    signed: Vec<u8>,
    reference: NowBlock,
    txid: [u8; 32],
    receipt: TronReceipt,
}

/// The node's `deploycontract` build: unsigned raw bytes, their txID,
/// and the pre-computed contract address.
#[derive(serde::Deserialize)]
struct DeployBuild {
    #[serde(rename = "raw_data_hex")]
    raw_data_hex: String,
    #[serde(rename = "txID")]
    tx_id: String,
    contract_address: String,
}

/// keccak256 of the uncompressed public key, last 20 bytes — the EVM
/// form Tron prefixes with 0x41. Parity-checked against tronWeb.
fn derive_address(key: &SigningKey) -> Address {
    let public = key.verifying_key().to_encoded_point(false);
    let hash = alloy::primitives::keccak256(&public.as_bytes()[1..]);
    Address::from_slice(&hash[12..])
}

/// Signs the raw bytes: sha256 prehash, 65-byte `[r ‖ s ‖ v]` with the
/// recovery-id parity, returning the signed transaction and its txID.
fn sign(key: &SigningKey, raw_bytes: &[u8]) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    sign_raw(key, RawTransaction::parse(raw_bytes)?)
}

/// For `CreateSmartContract` raw data which the admission-pinned `parse` rejects by design.
fn sign_unchecked(key: &SigningKey, raw_bytes: &[u8]) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let raw = RawTransaction::decode(raw_bytes).context("decoding raw transaction")?;
    sign_raw(key, raw)
}

/// sha256-prehash ECDSA, 65-byte `[r ‖ s ‖ v]`, wrapped in a
/// `Transaction` envelope.
fn sign_raw(key: &SigningKey, raw: RawTransaction) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let digest = Sha256::digest(raw.encode_to_vec());
    let (signature, recovery) = key.sign_prehash_recoverable(&digest)?;
    let (r, s) = signature.split_bytes();
    let r: [u8; 32] = r.into();
    let s: [u8; 32] = s.into();
    raw.sign_and_hash(&r, &s, u8::from(recovery.is_y_odd()))
}

impl Gate {
    /// Assembles the live gate from env vars (see README); a key with no
    /// TRX stops the run with its address to fund at the faucet.
    async fn from_env() -> anyhow::Result<Self> {
        let endpoint: Url = std::env::var("TRON_ENDPOINT")
            .context("TRON_ENDPOINT")?
            .parse()
            .context("TRON_ENDPOINT must be a url")?;
        let key_hex = std::env::var("TRON_PRIVATE_KEY").context("TRON_PRIVATE_KEY")?;
        let key_bytes: [u8; 32] = hex::decode(key_hex.trim_start_matches("0x"))?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                anyhow::anyhow!("TRON_PRIVATE_KEY: {} bytes, want 32", bytes.len())
            })?;
        let key = SigningKey::from_bytes(&k256::FieldBytes::from(key_bytes))?;
        let contract = match std::env::var("TRON_CONTRACT") {
            Ok(value) => value
                .parse()
                .or_else(|_| parse_hex(&value).map(TronAddress::from_evm))
                .context("TRON_CONTRACT must be a base58 or hex address")?,
            Err(_) => DEFAULT_CONTRACT.parse().expect("pinned default contract"),
        };

        let poll = env_secs("TRON_POLL_SECS", 3)?;
        let deadline = env_secs("TRON_DEADLINE_SECS", 180)?;
        let config = TronConfig {
            endpoint: endpoint.clone(),
            api_key: std::env::var("TRON_API_KEY").ok().map(Into::into),
            poll_interval: poll,
            ..Default::default()
        };
        let owner = TronAddress::from_evm(derive_address(&key));
        let client = TronHttp::new(&config)?;
        anyhow::ensure!(
            client.get_account_balance(&owner).await? > 0,
            "owner {owner} holds no TRX — fund it at the testnet faucet \
             (Nile: https://nileex.io), then re-run"
        );
        let gate = Self {
            client,
            endpoint,
            api_key: config.api_key.clone(),
            key,
            owner,
            contract,
            poll,
            deadline,
        };
        match std::env::var("TRON_TOKEN_ARTIFACT") {
            Ok(artifact) => gate.with_deployed_token(&artifact).await,
            Err(_) => Ok(gate),
        }
    }

    /// Returns a gate targeting a token freshly deployed from the
    /// artifact via the node's `deploycontract` builder (raw bytes +
    /// pre-computed address), settled like any other broadcast.
    async fn with_deployed_token(self, artifact: &str) -> anyhow::Result<Self> {
        let artifact = std::fs::read_to_string(artifact)
            .with_context(|| format!("token artifact {artifact}"))?;
        let artifact: serde_json::Value = serde_json::from_str(&artifact)?;
        let name = artifact["name"].as_str().context("artifact name")?;
        let abi = serde_json::to_string(artifact["abi"].as_array().context("artifact abi")?)?;

        let build: DeployBuild = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("deploy http client")?
            .post(
                self.endpoint
                    .join("wallet/deploycontract")
                    .context("joining deploy path")?,
            )
            .json(&serde_json::json!({
                "owner_address": self.owner.to_hex(),
                "name": name,
                "abi": abi,
                "bytecode": artifact["bytecode"].as_str().context("artifact bytecode")?,
                "parameter": "",
                "call_value": 0,
                "fee_limit": 1_000_000_000,
                "consume_user_resource_percent": 100,
                "origin_energy_limit": 10_000_000,
                "visible": false
            }))
            .send()
            .await
            .context("deploycontract request")?
            .error_for_status()
            .context("deploycontract status")?
            .json()
            .await
            .context("deploycontract response")?;
        let raw_bytes = hex::decode(&build.raw_data_hex).context("decoding raw_data_hex")?;
        let build_txid: [u8; 32] = build.tx_id.parse::<B256>().context("deploy txID")?.into();
        let deployed = TronAddress::from_evm(
            parse_hex(&build.contract_address).context("deploy contract_address")?,
        );

        let (signed, txid) = sign_unchecked(&self.key, &raw_bytes)?;
        anyhow::ensure!(
            txid == build_txid,
            "deploy txID must be sha256 of the raw bytes"
        );
        match self.client.broadcast_transaction(&signed).await? {
            BroadcastOutcome::Accepted => {}
            other => bail!("[deploy] {other:?}"),
        }
        let receipt = self.settle(&txid).await?;
        let result = receipt
            .result
            .as_deref()
            .or(receipt.receipt_result.as_deref());
        anyhow::ensure!(result == Some("SUCCESS"), "deploy executed {result:?}");
        println!("[deploy] {name} at {deployed}");
        Ok(Self {
            contract: deployed,
            ..self
        })
    }

    /// Runs the sequence: acceptance, watcher, duplicate, codeless.
    async fn run(&self) -> anyhow::Result<()> {
        println!("[gate] owner {} -> contract {}", self.owner, self.contract);
        let accepted = self.acceptance().await?;
        self.watcher(&accepted).await?;
        self.duplicate(&accepted.signed).await?;
        self.codeless(&accepted).await
    }

    /// Watcher config matching this gate's connection and cadence.
    fn watcher_config(&self) -> TronConfig {
        TronConfig {
            endpoint: self.endpoint.clone(),
            api_key: self.api_key.clone(),
            poll_interval: self.poll,
            ..TronConfig::default()
        }
    }

    /// Watcher leg: run [`TronWatcher`] on the settled tx; the event
    /// must match the receipt's own classification.
    async fn watcher(&self, accepted: &Broadcast) -> anyhow::Result<()> {
        let tx = bidirectional_tx(accepted.txid, vec![], Chain::Ethereum);
        let expected = accepted
            .receipt
            .execution_outcome(&tx.output_deserialization_schema)?;

        let state = MockStateManager::new();
        state.watch_execution(Chain::Tron, tx).await;
        let mut run = spawn_watcher(self.watcher_config(), state)?;
        let deadline = Instant::now() + self.deadline;
        let confirmation = loop {
            let event = tokio::time::timeout_at(deadline.into(), run.events.recv())
                .await
                .context("watcher produced no event before the deadline")?
                .context("watcher channel closed")?;
            if let ChainEvent::ExecutionConfirmed { .. } = event {
                break event;
            }
        };
        run.stop().await?;

        let ChainEvent::ExecutionConfirmed {
            tx_id,
            sign_id,
            block_height,
            result,
            ..
        } = confirmation
        else {
            unreachable!()
        };
        anyhow::ensure!(tx_id.0 == accepted.txid, "watcher confirmed {tx_id:?}");
        anyhow::ensure!(sign_id == SignId::new(accepted.txid));
        anyhow::ensure!(
            block_height == accepted.receipt.block_number,
            "watcher height {block_height} != receipt {}",
            accepted.receipt.block_number
        );

        let agrees = match (&expected, &result) {
            (ExecutionOutcome::Failed, ExecutionOutcome::Failed)
            | (ExecutionOutcome::ExtractionFailed, ExecutionOutcome::ExtractionFailed) => true,
            (ExecutionOutcome::Success { output: want }, ExecutionOutcome::Success { output }) => {
                want == output
            }
            _ => false,
        };
        anyhow::ensure!(
            agrees,
            "watcher classified {result:?}, receipt says {expected:?}"
        );
        println!("[watcher] confirmed at block {block_height} as {result:?}");
        Ok(())
    }

    /// Acceptance probe: broadcast a USDT transfer, settle it, and check
    /// the txID and receipt classification. A zero-token balance reverts
    /// instead of settling successfully — both classify the receipt.
    async fn acceptance(&self) -> anyhow::Result<Broadcast> {
        let reference = self.client.get_now_block().await?;
        let now_ms = reference.timestamp as i64;
        let raw = build_raw(
            &self.owner,
            &self.contract,
            &usdt_transfer_calldata(&self.owner, 1),
            &reference,
            now_ms,
        );
        let raw_bytes = raw.encode_to_vec();
        let local_txid: [u8; 32] = Sha256::digest(&raw_bytes).into();
        let (signed, txid) = sign(&self.key, &raw_bytes)?;
        anyhow::ensure!(
            txid == local_txid,
            "txID must be sha256 of the raw bytes, signature aside"
        );
        println!(
            "[broadcast] reference block {}, txid {}",
            reference.number,
            hex::encode(txid)
        );
        match self.client.broadcast_transaction(&signed).await? {
            BroadcastOutcome::Accepted => println!("[broadcast] accepted"),
            other => bail!("[broadcast] {other:?}"),
        }
        let receipt = self.settle(&txid).await?;
        anyhow::ensure!(
            receipt.id == B256::from(txid),
            "receipt id must equal the txID"
        );
        match receipt.execution_result()? {
            TronExecutionResult::Succeeded => {
                anyhow::ensure!(
                    receipt
                        .logs
                        .first()
                        .is_some_and(|log| log.topics().first() == Some(&transfer_topic())),
                    "expected the Transfer event"
                );
                println!(
                    "[broadcast] settled, fee {} sun, {} log(s)",
                    receipt.fee,
                    receipt.logs.len()
                );
            }
            TronExecutionResult::Failed => println!(
                "[broadcast] failed, fee {} sun, resMessage {:?}",
                receipt.fee, receipt.res_message
            ),
        }
        Ok(Broadcast {
            signed,
            reference,
            txid,
            receipt,
        })
    }

    /// Broadcasts a transfer so a demand-driven chain (TRE) produces
    /// a block; settled chains (Nile) produce on their own.
    async fn push_block(&self) -> anyhow::Result<()> {
        let reference = self.client.get_now_block().await?;
        let raw = build_raw(
            &self.owner,
            &self.contract,
            &usdt_transfer_calldata(&self.owner, 1),
            &reference,
            reference.timestamp as i64,
        );
        let (signed, _) = sign(&self.key, &raw.encode_to_vec())?;
        self.client.broadcast_transaction(&signed).await?;
        Ok(())
    }

    /// M6 from a refused broadcast — the reproducible never-included
    /// id (accepted broadcasts pack within their window). The entry
    /// registers with no watch: the backlog scan resolves it.
    async fn expiry(&self) -> anyhow::Result<()> {
        let reference = self.client.get_now_block().await?;
        let expiration = reference.timestamp as i64 + SLOT_MS;
        let raw = build_raw_expiring(
            &self.owner,
            &self.contract,
            &usdt_transfer_calldata(&self.owner, 1),
            &reference,
            reference.timestamp as i64,
            expiration,
        );
        let raw_bytes = raw.encode_to_vec();
        let (signed, txid) = sign(&self.key, &raw_bytes)?;
        // The refusal comes from the chain's clock, not the wall's:
        // advance the served head one slot past the window, pushing a
        // block whenever a demand-driven chain stalls.
        let start = Instant::now();
        let mut last_live = 0;
        loop {
            let live = self.client.get_now_block().await?;
            if live.timestamp as i64 > expiration + SLOT_MS {
                break;
            }
            anyhow::ensure!(
                start.elapsed() < self.deadline,
                "live head did not pass the window within {:?}",
                self.deadline
            );
            self.push_if_stalled(live.timestamp, &mut last_live).await?;
            tokio::time::sleep(self.poll).await;
        }
        match self.client.broadcast_transaction(&signed).await? {
            BroadcastOutcome::Rejected { code, .. } => {
                println!("[expiry] refused as expected: {code}")
            }
            other => bail!("[expiry] wanted the expiry refusal, got {other:?}"),
        }

        let state = MockStateManager::new();
        state
            .add_pending_execution(bidirectional_tx(txid, raw_bytes, Chain::Midnight))
            .await;
        let mut run = spawn_watcher(self.watcher_config(), state)?;
        let mut last_live = 0;
        let confirmation = loop {
            tokio::select! {
                event = run.events.recv() => {
                    let event = event.context("watcher channel closed")?;
                    if let ChainEvent::ExecutionConfirmed { .. } = event {
                        break event;
                    }
                }
                _ = tokio::time::sleep(self.poll) => {
                    anyhow::ensure!(
                        start.elapsed() < self.deadline,
                        "no attestation within {:?}",
                        self.deadline
                    );
                    let live = self.client.get_now_block().await?;
                    self.push_if_stalled(live.timestamp, &mut last_live).await?;
                }
            }
        };
        run.stop().await?;

        let ChainEvent::ExecutionConfirmed {
            tx_id,
            sign_id,
            block_height,
            result,
            ..
        } = confirmation
        else {
            unreachable!()
        };
        anyhow::ensure!(tx_id.0 == txid, "[expiry] attested {tx_id:?}");
        anyhow::ensure!(sign_id == SignId::new(txid));
        anyhow::ensure!(
            matches!(result, ExecutionOutcome::Unviable),
            "[expiry] attested {result:?}, want Unviable"
        );
        // Independent oracle for the deterministic height: a linear
        // scan for the first solidified block at or past the window's
        // end.
        let mut boundary = reference.number + 1;
        loop {
            let block = self
                .client
                .get_block_solidity(boundary)
                .await?
                .with_context(|| format!("[expiry] solidified block {boundary} absent"))?;
            if block.timestamp >= expiration {
                break;
            }
            boundary += 1;
        }
        anyhow::ensure!(
            block_height == boundary,
            "[expiry] attested at {block_height}, want the boundary {boundary}"
        );
        println!(
            "[expiry] attested Unviable at the boundary {block_height} \
             (broadcast reference {}, {:.1?} after the refusal)",
            reference.number,
            start.elapsed()
        );
        Ok(())
    }

    /// Duplicate probe: the identical signed bytes again, rejected by
    /// txID — replay protection without a nonce, and an id the network
    /// never derives from the signature.
    async fn duplicate(&self, signed: &[u8]) -> anyhow::Result<()> {
        match self.client.broadcast_transaction(signed).await? {
            BroadcastOutcome::AlreadyKnown => {
                println!("[duplicate] rejected as DUP_TRANSACTION_ERROR")
            }
            other => bail!("[duplicate] expected the rejection, got {other:?}"),
        }
        Ok(())
    }

    /// Codeless-address probe: a call to an address with no code must
    /// come back `CONTRACT_VALIDATE_ERROR` — the classification recorded
    /// on Nile and mainnet.
    async fn codeless(&self, accepted: &Broadcast) -> anyhow::Result<()> {
        let codeless = TronAddress::from_evm(Address::repeat_byte(0x33));
        let void = build_raw(
            &self.owner,
            &codeless,
            &[0u8; 4],
            &accepted.reference,
            accepted.reference.timestamp as i64,
        );
        let (void_signed, _) = sign(&self.key, &void.encode_to_vec())?;
        let probe = self.client.broadcast_transaction(&void_signed).await?;
        match &probe {
            BroadcastOutcome::Rejected { code, message } => {
                println!("[codeless] rejected {code}: {message}")
            }
            other => println!("[codeless] probe outcome: {other:?}"),
        }
        anyhow::ensure!(
            matches!(&probe, BroadcastOutcome::Rejected { code, .. }
                if code == "CONTRACT_VALIDATE_ERROR"),
            "codeless address: expected CONTRACT_VALIDATE_ERROR, got {probe:?}"
        );
        Ok(())
    }

    /// Pushes a block while the served head stays stalled, tracking
    /// the last-seen timestamp.
    async fn push_if_stalled(&self, live_ts: u64, last_live: &mut u64) -> anyhow::Result<()> {
        if live_ts != *last_live {
            *last_live = live_ts;
            return Ok(());
        }
        self.push_block().await
    }

    /// Polls the solidity router until the receipt appears (solidified);
    /// absence is pending, not an error.
    async fn settle(&self, txid: &[u8; 32]) -> anyhow::Result<TronReceipt> {
        let start = Instant::now();
        loop {
            if let Some(receipt) = self
                .client
                .get_transaction_info_solidity(&B256::from(*txid))
                .await?
            {
                println!(
                    "[settle] solidified in {:.1?} at block {}",
                    start.elapsed(),
                    receipt.block_number
                );
                return Ok(receipt);
            }
            anyhow::ensure!(
                start.elapsed() < self.deadline,
                "not solidified within {:?}",
                self.deadline
            );
            tokio::time::sleep(self.poll).await;
        }
    }
}

fn mock_config(endpoint: Url) -> TronConfig {
    TronConfig {
        endpoint,
        poll_interval: Duration::from_millis(10),
        request_timeout: Duration::from_secs(2),
        ..Default::default()
    }
}

/// One `broadcasthex` stub answering a specific signed transaction;
/// `expect` bounds its hits — mockito hands overflow to the next
/// matching stub.
async fn broadcast_stub(
    server: &mut mockito::ServerGuard,
    signed: &[u8],
    body: String,
    expect: Option<usize>,
) {
    let mut mock = server
        .mock("POST", "/wallet/broadcasthex")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "transaction": hex::encode(signed)
        })))
        .with_body(body);
    if let Some(hits) = expect {
        mock = mock.expect(hits);
    }
    mock.create_async().await;
}

/// One `gettransactioninfobyid` stub answering this txid.
async fn receipt_stub(
    server: &mut mockito::ServerGuard,
    txid: &[u8; 32],
    body: String,
    expect: Option<usize>,
) {
    let mut mock = server
        .mock("POST", "/walletsolidity/gettransactioninfobyid")
        .match_body(mockito::Matcher::PartialJson(serde_json::json!({
            "value": hex::encode(txid)
        })))
        .with_body(body);
    if let Some(hits) = expect {
        mock = mock.expect(hits);
    }
    mock.create_async().await;
}

/// A raw response body recorded from nile.trongrid.io; the mock below
/// serves these verbatim.
fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/nile/{name}.json"))
        .unwrap_or_else(|err| panic!("fixture {name}: {err}"))
}

/// The recorded now block, as body to serve and reference to build
/// against — the signed bytes answer to the recorded responses.
fn recorded_nowblock() -> (String, NowBlock) {
    let body = fixture("nowblock");
    let now: serde_json::Value = serde_json::from_str(&body).unwrap();
    let reference = NowBlock {
        block_id: now["blockID"].as_str().unwrap().parse().unwrap(),
        number: now["block_header"]["raw_data"]["number"].as_u64().unwrap(),
        timestamp: now["block_header"]["raw_data"]["timestamp"]
            .as_u64()
            .unwrap(),
    };
    (body, reference)
}

/// The recorded success receipt with its id patched to this run's txid
/// — the recording's key differs from the replay key.
fn patched_receipt(txid: &[u8; 32]) -> String {
    let body = fixture("receipt-success");
    let recorded_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    body.replace(&recorded_id, &hex::encode(txid))
}

#[tokio::test]
async fn relay_sequence_runs_against_recorded_nile_responses() -> anyhow::Result<()> {
    let (nowblock, reference) = recorded_nowblock();

    let mut key_bytes = [0u8; 32];
    key_bytes[31] = 1;
    let key = SigningKey::from_bytes(&k256::FieldBytes::from(key_bytes)).unwrap();
    let owner = TronAddress::from_evm(derive_address(&key));
    let contract = DEFAULT_CONTRACT.parse().expect("pinned default contract");

    let calldata = usdt_transfer_calldata(&owner, 1);
    // A truncated amount word zero-pads on load to amount·2¹⁹² — always
    // reverting.
    assert_eq!(calldata.len(), 4 + 32 + 32);
    assert_eq!(
        calldata[..4],
        alloy::primitives::keccak256(b"transfer(address,uint256)")[..4]
    );

    let raw = build_raw(
        &owner,
        &contract,
        &calldata,
        &reference,
        reference.timestamp as i64,
    );
    let (signed, txid) = sign(&key, &raw.encode_to_vec()).unwrap();
    let codeless = TronAddress::from_evm(Address::repeat_byte(0x33));
    let void = build_raw(
        &owner,
        &codeless,
        &[0u8; 4],
        &reference,
        reference.timestamp as i64,
    );
    let (void_signed, _) = sign(&key, &void.encode_to_vec()).unwrap();

    let mut server = mockito::Server::new_async().await;
    let endpoint: Url = server.url().parse().unwrap();
    // Mockito answers the first stub whose expectation is still unmet:
    // accept's one-hit stub hands the second identical broadcast to
    // dup, and the pending `{}` stub hands the first poll to the
    // receipt.
    server
        .mock("POST", "/wallet/getnowblock")
        .with_body(nowblock)
        .create_async()
        .await;

    broadcast_stub(
        &mut server,
        &void_signed,
        fixture("broadcast-codeless"),
        None,
    )
    .await;
    broadcast_stub(&mut server, &signed, fixture("broadcast-accept"), Some(1)).await;
    broadcast_stub(&mut server, &signed, fixture("broadcast-dup"), None).await;
    receipt_stub(&mut server, &txid, fixture("receipt-pending"), Some(1)).await;
    receipt_stub(&mut server, &txid, patched_receipt(&txid), None).await;

    let gate = Gate {
        client: TronHttp::new(&mock_config(endpoint.clone())).unwrap(),
        endpoint,
        api_key: None,
        key,
        owner,
        contract,
        poll: Duration::from_millis(10),
        deadline: Duration::from_secs(2),
    };
    gate.run().await?;
    Ok(())
}

/// The expiry leg against recorded Nile responses (refusal captured
/// 2026-10-31, api.nileex.io): refused broadcast, `Unviable` at the
/// first solidified block at or past the window's end.
#[tokio::test]
async fn expiry_leg_runs_against_recorded_nile_responses() -> anyhow::Result<()> {
    let (nowblock, reference) = recorded_nowblock();
    let solidified: serde_json::Value = serde_json::from_str(&fixture("nowblock-solidity"))?;
    let solid_height = solidified["block_header"]["raw_data"]["number"]
        .as_u64()
        .context("solidity head number")?;

    let mut key_bytes = [0u8; 32];
    key_bytes[31] = 1;
    let key = SigningKey::from_bytes(&k256::FieldBytes::from(key_bytes))?;
    let owner = TronAddress::from_evm(derive_address(&key));
    let contract: TronAddress = DEFAULT_CONTRACT.parse().unwrap();

    // A one-slot window the recorded solidified head is long past.
    let expiration = reference.timestamp as i64 + SLOT_MS;
    anyhow::ensure!(
        solidified["block_header"]["raw_data"]["timestamp"]
            .as_i64()
            .context("solidity head timestamp")?
            > expiration,
        "head must be past the window"
    );
    let raw = build_raw_expiring(
        &owner,
        &contract,
        &usdt_transfer_calldata(&owner, 1),
        &reference,
        reference.timestamp as i64,
        expiration,
    );
    let raw_bytes = raw.encode_to_vec();
    let (signed, txid) = sign(&key, &raw_bytes)?;

    let mut server = mockito::Server::new_async().await;
    let endpoint: Url = server.url().parse().unwrap();
    server
        .mock("POST", "/wallet/getnowblock")
        .with_body(nowblock)
        .create_async()
        .await;
    broadcast_stub(&mut server, &signed, fixture("broadcast-expired"), None).await;
    server
        .mock("POST", "/walletsolidity/getnowblock")
        .with_body(fixture("nowblock-solidity"))
        .create_async()
        .await;
    receipt_stub(&mut server, &txid, fixture("receipt-pending"), None).await;

    // The recorded chain anchors at the boundary — reference + 1, its
    // timestamp exactly the window's end; synthesized search mids ride
    // a 3 s clock through it, so any probe that is not a recorded
    // block reads a consistent timestamp.
    let boundary = reference.number + 1;
    let clock = |n: u64| expiration + (n as i64 - boundary as i64) * SLOT_MS;
    let recorded = |n: u64| n == reference.number || n == boundary;
    let stub_mid = |server: &mut mockito::ServerGuard, n: u64| {
        server
            .mock("POST", "/walletsolidity/getblockbynum")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "num": n
            })))
            .with_header("content-type", "application/json")
            .with_body(format!(
                r#"{{ "block_header": {{ "raw_data": {{ "number": {n}, "timestamp": {} }} }}, "transactions": [] }}"#,
                clock(n)
            ))
            .create();
    };
    for target in [reference.timestamp as i64, expiration] {
        let (mut lo, mut hi) = (0u64, solid_height);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if !recorded(mid) {
                stub_mid(&mut server, mid);
            }
            if clock(mid) >= target {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        if !recorded(lo) {
            stub_mid(&mut server, lo);
        }
    }
    for n in [reference.number, boundary] {
        server
            .mock("POST", "/walletsolidity/getblockbynum")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "num": n
            })))
            .with_header("content-type", "application/json")
            .with_body(fixture(&format!("solid-block-{n}")))
            .create_async()
            .await;
    }

    let client = TronHttp::new(&mock_config(endpoint.clone()))?;
    match client.broadcast_transaction(&signed).await? {
        BroadcastOutcome::Rejected { code, .. } => {
            anyhow::ensure!(code == "TRANSACTION_EXPIRATION_ERROR", "refused as {code}");
        }
        other => bail!("wanted the recorded expiry refusal, got {other:?}"),
    }

    let state = MockStateManager::new();
    state
        .add_pending_execution(bidirectional_tx(txid, raw_bytes, Chain::Midnight))
        .await;
    let mut run = spawn_watcher(mock_config(endpoint), state)?;
    let confirmation = loop {
        let event = tokio::time::timeout(Duration::from_secs(5), run.events.recv())
            .await
            .context("watcher produced no event before the deadline")?
            .context("watcher channel closed")?;
        if let ChainEvent::ExecutionConfirmed { .. } = event {
            break event;
        }
    };
    run.stop().await?;

    let ChainEvent::ExecutionConfirmed {
        tx_id,
        block_height,
        result,
        ..
    } = confirmation
    else {
        unreachable!()
    };
    anyhow::ensure!(tx_id.0 == txid, "attested {tx_id:?}");
    anyhow::ensure!(
        block_height == boundary,
        "attested at {block_height}, want the boundary {boundary}"
    );
    anyhow::ensure!(
        matches!(result, ExecutionOutcome::Unviable),
        "attested {result:?}, want Unviable"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "live network: TRON_ENDPOINT, TRON_PRIVATE_KEY"]
async fn live_gate() -> anyhow::Result<()> {
    Gate::from_env().await?.run().await
}

#[tokio::test]
#[ignore = "live network: TRON_ENDPOINT, TRON_PRIVATE_KEY"]
async fn live_gate_expiry() -> anyhow::Result<()> {
    Gate::from_env().await?.expiry().await
}
