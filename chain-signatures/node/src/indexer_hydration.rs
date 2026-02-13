use crate::backlog::Backlog;
use crate::indexer_sol::MAX_SECP256K1_SCALAR;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::{Chain, IndexedSignRequest, Sign, SignRequestType};
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::hash_rlp_data;
use crate::stream::ops::SignatureEvent;
use crate::stream::ChainStream;
use alloy_sol_types::SolValue;
use anyhow::{anyhow, Result};
use ethabi::{encode, Token};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, FieldBytes, Scalar};
use mpc_crypto::ScalarExt as _;
use mpc_primitives::Signature;
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use sha3::{Digest, Keccak256};
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58AddressFormatRegistry, Ss58Codec};
use sp_core::{twox_128, H256};
use sp_runtime::traits::BlakeTwo256;
use sp_state_machine::read_proof_check;
use sp_trie::StorageProof;
use std::convert::TryInto;
use std::fmt;
use std::time::Duration;
use std::time::Instant;
use subxt::backend::{legacy::LegacyRpcMethods, rpc::RpcClient};
use subxt::config::HashFor;
use subxt::events::EventDetails;
use subxt::ext::scale_value::{Composite, Value, ValueDef};
use subxt::{client::OnlineClient, SubstrateConfig};
use tokio::sync::mpsc;
use tokio::sync::watch;

/// Configures Hydration indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_hydration_options")]
pub struct HydrationArgs {
    /// Hydration RPC ws URL
    #[clap(long = "hydration-rpc-ws-url", env("MPC_HYDRATION_RPC_WS_URL"))]
    pub rpc_ws_url: Option<String>,
    /// Hydration signer URI
    #[clap(long = "hydration-signer-uri", env("MPC_HYDRATION_SIGNER_URI"))]
    pub signer_uri: Option<String>,
    #[clap(
        long = "hydration-total-timeout",
        env("MPC_HYDRATION_TOTAL_TIMEOUT"),
        default_value = "200"
    )]
    pub total_timeout: Option<u64>,
}

impl HydrationArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(2);
        if let Some(rpc_ws_url) = self.rpc_ws_url {
            args.extend(["--hydration-rpc-ws-url".to_string(), rpc_ws_url]);
        }
        if let Some(signer_uri) = self.signer_uri {
            args.extend(["--hydration-signer-uri".to_string(), signer_uri]);
        }
        if let Some(total_timeout) = self.total_timeout {
            args.extend([
                "--hydration-total-timeout".to_string(),
                total_timeout.to_string(),
            ]);
        }
        args
    }

    pub fn into_config(self) -> Option<HydrationConfig> {
        Some(HydrationConfig {
            rpc_ws_url: self.rpc_ws_url?,
            signer_uri: self.signer_uri?,
            total_timeout: self.total_timeout?,
        })
    }

    pub fn from_config(config: Option<HydrationConfig>) -> Self {
        match config {
            Some(config) => HydrationArgs {
                rpc_ws_url: Some(config.rpc_ws_url),
                signer_uri: Some(config.signer_uri),
                total_timeout: Some(config.total_timeout),
            },
            None => HydrationArgs {
                rpc_ws_url: None,
                signer_uri: None,
                total_timeout: None,
            },
        }
    }
}

#[derive(Clone)]
pub struct HydrationConfig {
    /// Hydration RPC ws URL
    pub rpc_ws_url: String,
    /// Hydration signer URI
    pub signer_uri: String,
    /// total timeout for a sign request starting from indexed time in seconds
    pub total_timeout: u64,
}

impl fmt::Debug for HydrationConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HydrationConfig")
            .field("rpc_ws_url", &self.rpc_ws_url)
            .field("signer_uri", &"<hidden>")
            .field("total_timeout", &self.total_timeout)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HydrationSignatureRequestedEvent {
    pub sender: [u8; 32],
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
    pub deposit: u64,
    pub chain_id: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
}

impl SignatureEvent for HydrationSignatureRequestedEvent {
    fn generate_request_id(&self) -> [u8; 32] {
        // Encode the event data in ABI format
        let encoded = encode(&[
            Token::String(self.sender_string()),
            Token::Bytes(self.payload.to_vec()),
            Token::String(self.path.clone()),
            Token::Uint(self.key_version.into()),
            Token::String(self.chain_id.clone()),
            Token::String(self.algo.clone()),
            Token::String(self.dest.clone()),
            Token::String(self.params.clone()),
        ]);
        // Calculate keccak256 hash
        let mut hasher = Keccak256::new();
        hasher.update(&encoded);
        hasher.finalize().into()
    }

    fn generate_sign_request(
        &self,
        entropy: [u8; 32],
        total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("found hydration event: {:?}", self);
        if self.deposit == 0 {
            tracing::warn!("deposit is 0, skipping sign request");
            anyhow::bail!("deposit is 0");
        }

        if self.key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!("unsupported key version: {}", self.key_version);
            anyhow::bail!("unsupported key version");
        }

        let Some(payload) = Scalar::from_bytes(self.payload) else {
            tracing::warn!(
                "hydration `sign` did not produce payload hash correctly: {:?}",
                self.payload,
            );
            anyhow::bail!("failed to convert event payload hash to scalar");
        };

        if payload > *MAX_SECP256K1_SCALAR {
            tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
            anyhow::bail!("payload exceeds secp256k1 curve order");
        }

        let epsilon = mpc_crypto::kdf::derive_epsilon_hydration(
            self.key_version,
            &self.sender_string(),
            &self.path,
        );

        let sign_id = SignId::new(self.generate_request_id());
        tracing::info!(?sign_id, "hydration signature requested");

        Ok(IndexedSignRequest {
            id: sign_id,
            args: SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            chain: Chain::Hydration,
            timestamp_created: Instant::now(),
            unix_timestamp_indexed: crate::util::current_unix_timestamp(),
            total_timeout,
            sign_request_type: SignRequestType::Sign,
        })
    }

    fn source_chain(&self) -> Chain {
        Chain::Hydration
    }

    fn sender_string(&self) -> String {
        ss58_address_from_account32(self.sender)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HydrationSignBidirectionalRequestedEvent {
    pub sender: [u8; 32],
    pub serialized_transaction: Vec<u8>,
    pub caip2_id: String,
    pub key_version: u32,
    pub deposit: u64,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub output_deserialization_schema: Vec<u8>,
    pub respond_serialization_schema: Vec<u8>,
}

impl SignatureEvent for HydrationSignBidirectionalRequestedEvent {
    fn generate_request_id(&self) -> [u8; 32] {
        // Match TypeScript implementation using ABI encoding
        let encoded = (
            self.sender_string(),
            self.serialized_transaction.clone(),
            self.caip2_id.clone(),
            self.key_version,
            self.path.clone(),
            self.algo.clone(),
            self.dest.clone(),
            self.params.clone(),
        )
            .abi_encode_packed();

        alloy::primitives::keccak256(encoded).into()
    }

    fn generate_sign_request(
        &self,
        entropy: [u8; 32],
        total_timeout: Duration,
    ) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("found hydration event: {:?}", self);
        if self.deposit == 0 {
            tracing::warn!("deposit is 0, skipping sign request");
            anyhow::bail!("deposit is 0");
        }

        if self.key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!("unsupported key version: {}", self.key_version);
            anyhow::bail!("unsupported key version");
        }

        let request_id = self.generate_request_id();
        let rlp_encoded_tx = self.serialized_transaction.clone();

        // Call the existing derive_epsilon_sol function with the correct parameters
        // to match the TypeScript implementation
        let epsilon = mpc_crypto::kdf::derive_epsilon_hydration(
            self.key_version,
            &self.sender_string(),
            &self.path,
        );

        let sign_id = SignId::new(request_id);
        tracing::info!(?sign_id, "hydration signature requested");
        let unsigned_tx_hash = hash_rlp_data(rlp_encoded_tx);
        let Some(payload) = Scalar::from_bytes(unsigned_tx_hash) else {
            anyhow::bail!("Failed to convert unsigned_tx_hash to scalar: {unsigned_tx_hash:?}");
        };

        if payload > *MAX_SECP256K1_SCALAR {
            tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
            anyhow::bail!("payload exceeds secp256k1 curve order");
        }

        Ok(IndexedSignRequest {
            id: sign_id,
            args: SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            chain: Chain::Hydration,
            timestamp_created: Instant::now(),
            unix_timestamp_indexed: crate::util::current_unix_timestamp(),
            total_timeout,
            sign_request_type: SignRequestType::SignBidirectional(
                crate::stream::ops::SignBidirectionalEvent::Hydration(self.clone()),
            ),
        })
    }

    fn source_chain(&self) -> Chain {
        Chain::Hydration
    }

    fn sender_string(&self) -> String {
        ss58_address_from_account32(self.sender)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydrationRespondBidirectionalEvent {
    pub request_id: [u8; 32],
    pub responder: [u8; 32],
    pub serialized_output: Vec<u8>,
    pub signature: Signature,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydrationSignatureRespondedEvent {
    pub request_id: [u8; 32],
    pub responder: [u8; 32],
    pub signature: Signature,
}

/// Storage key for `frame_system::Events`.
fn system_events_key() -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(&twox_128(b"System"));
    key.extend_from_slice(&twox_128(b"Events"));
    key
}

/// Fetch and *verify* the SCALE‑encoded `System::Events` bytes at a given block.
///
/// - Uses `state_get_read_proof` via `LegacyRpcMethods`.
/// - Verifies the proof against `state_root` using `read_proof_check`.
/// - Returns the proven SCALE bytes for `System::Events`.
async fn fetch_proven_system_events_bytes(
    legacy_rpc: &LegacyRpcMethods<SubstrateConfig>,
    state_root: H256,
    block_hash: HashFor<SubstrateConfig>,
) -> Result<Vec<u8>> {
    let events_key = system_events_key();

    // 1. Get storage proof for System::Events at this block.
    let read_proof = legacy_rpc
        .state_get_read_proof([events_key.as_slice()], Some(block_hash))
        .await
        .map_err(|e| anyhow!("state_get_read_proof failed: {e}"))?;

    // read_proof.proof is Vec<Bytes>; Bytes wraps Vec<u8>.
    let sp_proof = StorageProof::new(read_proof.proof.into_iter().map(|bytes| bytes.0));

    // 2. Verify the proof against the block's state_root using Blake2 trie layout.
    let values_by_key =
        read_proof_check::<BlakeTwo256, _>(state_root, sp_proof, vec![events_key.clone()])
            .map_err(|e| anyhow!("read_proof_check failed: {e}"))?;

    // 3. Extract the SCALE‑encoded System::Events bytes.
    let events_bytes = values_by_key
        .get(&events_key)
        .and_then(|opt| opt.as_ref())
        .ok_or_else(|| anyhow!("System::Events missing from verified proof"))?
        .to_vec();

    Ok(events_bytes)
}

pub(crate) fn ss58_address_from_account32(sender: [u8; 32]) -> String {
    let acc = SpAccountId32::from(sender);
    acc.to_ss58check_with_version(Ss58AddressFormatRegistry::PolkadotAccount.into())
}

pub struct HydrationStream {
    rx: mpsc::Receiver<crate::stream::ChainEvent>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

/// Spawn a long-running task that connects to a Hydration node, verifies
/// Merkle proofs and emits canonical `ChainEvent`s into `events_tx`.
async fn hydration_event_producer(
    hydration: HydrationConfig,
    events_tx: mpsc::Sender<crate::stream::ChainEvent>,
) {
    let ws_url = hydration.rpc_ws_url.clone();
    let total_timeout = Duration::from_secs(hydration.total_timeout);

    // Connect to Subxt (high-level) and RPC (legacy) clients.
    let api = match OnlineClient::<SubstrateConfig>::from_url(ws_url.as_str()).await {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("hydration producer: failed to connect to hydration rpc: {e}");
            return;
        }
    };

    let rpc_client = match RpcClient::from_url(ws_url.as_str()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("hydration producer: failed to create rpc client: {e}");
            return;
        }
    };
    let legacy_rpc = LegacyRpcMethods::<SubstrateConfig>::new(rpc_client);

    // runtime updater
    spawn_runtime_updater(api.clone());

    // Subscribe to finalized blocks and emit ChainEvent into channel.
    loop {
        let mut blocks = match api.blocks().subscribe_finalized().await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("hydration producer: failed to subscribe to finalized blocks: {e}");
                // backoff then retry
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        while let Some(block_res) = blocks.next().await {
            let block = match block_res {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("hydration producer: failed to get block: {e}");
                    break; // reconnect subscription
                }
            };

            let number = block.number();
            let hash = block.hash();
            let header = block.header().clone();
            tracing::debug!("hydration producer: received block {number} ({hash:?})");

            // verify proven System::Events bytes
            let state_root: H256 = header.state_root;
            let events = match block.events().await {
                Ok(ev) => ev,
                Err(e) => {
                    tracing::error!("hydration producer: failed to get events: {e}");
                    continue;
                }
            };
            let events_bytes_unproven = events.bytes().to_vec();
            let events_bytes_proven =
                match fetch_proven_system_events_bytes(&legacy_rpc, state_root, hash).await {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(
                            "hydration producer: failed to fetch proven system events bytes: {e}"
                        );
                        continue;
                    }
                };

            if events_bytes_unproven != events_bytes_proven {
                tracing::error!(
                    "hydration producer: mismatch between rpc and proven events for block {number}"
                );
                continue;
            }

            // Emit Block checkpoint event
            let _ = events_tx
                .send(crate::stream::ChainEvent::Block(number as u64))
                .await;

            // Iterate decoded events and forward as ChainEvent variants.
            for ev in events.iter() {
                let ev = match ev {
                    Ok(ev) => ev,
                    Err(e) => {
                        tracing::error!("hydration producer: failed to decode event: {e}");
                        continue;
                    }
                };

                // SignatureRequested
                if ev.pallet_name() == PALLET_SIGNET
                    && ev.variant_name() == EVENT_SIGNATURE_REQUESTED
                {
                    match decode_signature_requested(&ev) {
                        Ok(event) => {
                            match event.generate_sign_request(
                                sp_core::hashing::blake2_256(ev.bytes()),
                                total_timeout,
                            ) {
                                Ok(req) => {
                                    let _ = events_tx
                                        .send(crate::stream::ChainEvent::SignRequest(req))
                                        .await;
                                }
                                Err(e) => tracing::error!(
                                    "hydration producer: failed to generate sign request: {e}"
                                ),
                            }
                        }
                        Err(e) => tracing::error!(
                            "hydration producer: failed to decode signature requested event: {e}"
                        ),
                    }
                }

                // SignatureResponded
                if ev.pallet_name() == PALLET_SIGNET
                    && ev.variant_name() == EVENT_SIGNATURE_RESPONDED
                {
                    match decode_signature_responded(&ev) {
                        Ok(event) => {
                            let _ = events_tx
                                .send(crate::stream::ChainEvent::Respond(
                                    crate::stream::ops::SignatureRespondedEvent::Hydration(event),
                                ))
                                .await;
                        }
                        Err(e) => tracing::error!(
                            "hydration producer: failed to decode signature responded event: {e}"
                        ),
                    }
                }

                // SignBidirectionalRequested
                if ev.pallet_name() == PALLET_SIGNET
                    && ev.variant_name() == EVENT_SIGN_BIDIRECTIONAL_REQUESTED
                {
                    match decode_sign_bidirectional_requested(&ev) {
                        Ok(event) => {
                            // Create IndexedSignRequest via SignatureEvent impl
                            match event.generate_sign_request(sp_core::hashing::blake2_256(ev.bytes()), total_timeout) {
                                Ok(req) => { let _ = events_tx.send(crate::stream::ChainEvent::SignRequest(req)).await; }
                                Err(e) => tracing::error!("hydration producer: failed to generate sign request: {e}"),
                            }
                        }
                        Err(e) => tracing::error!("hydration producer: failed to decode sign bidirectional requested event: {e}"),
                    }
                }

                // RespondBidirectionalEvent
                if ev.pallet_name() == PALLET_SIGNET
                    && ev.variant_name() == EVENT_RESPOND_BIDIRECTIONAL
                {
                    match decode_respond_bidirectional(&ev) {
                        Ok(event) => {
                            let _ = events_tx
                                .send(crate::stream::ChainEvent::RespondBidirectional(
                                    crate::stream::ops::RespondBidirectionalEvent::Hydration(event),
                                ))
                                .await;
                        }
                        Err(e) => tracing::error!(
                            "hydration producer: failed to decode respond bidirectional event: {e}"
                        ),
                    }
                }
            }

            crate::metrics::indexers::LATEST_BLOCK_NUMBER
                .with_label_values(&[crate::protocol::Chain::Hydration.as_str(), "indexed"])
                .set(number as i64);
        }

        // brief backoff before attempting to recreate subscription
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

impl HydrationStream {
    /// Create a HydrationStream that emits `ChainEvent`s into an internal channel.
    /// Returns `None` if `hydration` is `None` (indexer disabled).
    pub fn new(hydration: Option<HydrationConfig>) -> Option<Self> {
        let Some(hydration) = hydration else {
            tracing::warn!("hydration indexer is disabled");
            return None;
        };

        let (tx, rx) = crate::stream::channel();
        let producer_cfg = hydration.clone();
        let producer_tx = tx.clone();
        let t =
            tokio::spawn(async move { hydration_event_producer(producer_cfg, producer_tx).await });

        Some(HydrationStream { rx, tasks: vec![t] })
    }
}

impl Drop for HydrationStream {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl ChainStream for HydrationStream {
    const CHAIN: crate::protocol::Chain = crate::protocol::Chain::Hydration;
    async fn next_event(&mut self) -> Option<crate::stream::ChainEvent> {
        self.rx.recv().await
    }
}

pub async fn run(
    hydration: Option<HydrationConfig>,
    sign_tx: mpsc::Sender<Sign>,
    backlog: Backlog,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
) {
    let Some(hydration) = hydration else {
        tracing::warn!("hydration indexer is disabled");
        return;
    };
    let total_timeout = Duration::from_secs(hydration.total_timeout);

    let ws_url: &str = hydration.rpc_ws_url.as_str();

    tracing::info!("connecting to hydration rpc at {}", ws_url);

    // High‑level Subxt client for blocks + events.
    let hydration_api = OnlineClient::<SubstrateConfig>::from_url(ws_url).await;
    let hydration_api = match hydration_api {
        Ok(api) => api,
        Err(e) => {
            tracing::error!("failed to connect to hydration rpc: {e}");
            return;
        }
    };
    // Low‑level RPC client for legacy methods like state_get_read_proof.
    let rpc_client = RpcClient::from_url(ws_url).await;
    let rpc_client = match rpc_client {
        Ok(client) => client,
        Err(e) => {
            tracing::error!("failed to connect to hydration rpc: {e}");
            return;
        }
    };
    let legacy_rpc = LegacyRpcMethods::<SubstrateConfig>::new(rpc_client);

    // Wait for threshold to be available
    crate::stream::ops::recover_backlog(
        &backlog,
        &mut contract_watcher,
        &mut mesh_state,
        &node_client,
        Chain::Hydration,
        sign_tx.clone(),
        total_timeout,
    )
    .await;

    // Use the shared event producer and consume `ChainEvent`s from a channel so
    // the same subscription/decoding logic is reused by `HydrationStream`.
    let (events_tx, mut events_rx) = crate::stream::channel();
    // spawn producer that verifies proofs & emits ChainEvent
    let producer_cfg = hydration.clone();
    let _producer_handle =
        tokio::spawn(async move { hydration_event_producer(producer_cfg, events_tx).await });

    while let Some(event) = events_rx.recv().await {
        match event {
            crate::stream::ChainEvent::SignRequest(req) => {
                if let Err(err) =
                    crate::stream::ops::process_sign_request(req, sign_tx.clone(), backlog.clone())
                        .await
                {
                    tracing::error!(?err, chain = %Chain::Hydration, "failed to process sign request");
                }
            }
            crate::stream::ChainEvent::Respond(ev) => {
                if let Err(err) = crate::stream::ops::process_respond_event(
                    ev,
                    sign_tx.clone(),
                    &mut contract_watcher,
                    &backlog,
                )
                .await
                {
                    tracing::error!(?err, chain = %Chain::Hydration, "failed to process respond event");
                }
            }
            crate::stream::ChainEvent::RespondBidirectional(ev) => {
                if let Err(err) = crate::stream::ops::process_respond_bidirectional_event(
                    ev,
                    sign_tx.clone(),
                    &backlog,
                )
                .await
                {
                    tracing::error!(?err, chain = %Chain::Hydration, "failed to process respond bidirectional event");
                }
            }
            crate::stream::ChainEvent::Block(block) => {
                if let Some(checkpoint) = backlog.set_processed_block(Chain::Hydration, block).await
                {
                    tracing::info!(block, ?checkpoint, chain = %Chain::Hydration, "created checkpoint");
                }
                crate::metrics::indexers::LATEST_BLOCK_NUMBER
                    .with_label_values(&[crate::protocol::Chain::Hydration.as_str(), "indexed"])
                    .set(block as i64);
            }
            other => tracing::warn!(?other, "unexpected event from hydration producer"),
        }
    }
}

const PALLET_SIGNET: &str = "Signet";
const EVENT_SIGNATURE_REQUESTED: &str = "SignatureRequested";
const EVENT_SIGNATURE_RESPONDED: &str = "SignatureResponded";
const EVENT_SIGN_BIDIRECTIONAL_REQUESTED: &str = "SignBidirectionalRequested";
const EVENT_RESPOND_BIDIRECTIONAL: &str = "RespondBidirectionalEvent";

pub fn spawn_runtime_updater(api: OnlineClient<SubstrateConfig>) {
    let updater = api.updater();
    tokio::spawn(async move {
        if let Err(e) = updater.perform_runtime_updates().await {
            tracing::error!("runtime updater stopped: {e}");
        }
    });
}

fn decode_signature_requested(
    ev: &EventDetails<SubstrateConfig>,
) -> anyhow::Result<HydrationSignatureRequestedEvent> {
    let fields = ev.field_values()?;

    let sender = get_named_bytes32(&fields, "sender")?;
    let payload = get_named_bytes32(&fields, "payload")?;

    let path = get_named_utf8(&fields, "path")?;
    let chain_id = get_named_utf8(&fields, "chain_id")?;
    let algo = get_named_utf8(&fields, "algo")?;
    let dest = get_named_utf8(&fields, "dest")?;
    let params = get_named_utf8(&fields, "params")?;

    let key_version = get_named_u32(&fields, "key_version")?;
    let deposit = get_named_u64(&fields, "deposit")?;

    Ok(HydrationSignatureRequestedEvent {
        sender,
        payload,
        path,
        key_version,
        deposit,
        chain_id,
        algo,
        dest,
        params,
    })
}

fn decode_signature_responded(
    ev: &EventDetails<SubstrateConfig>,
) -> anyhow::Result<HydrationSignatureRespondedEvent> {
    let fields = ev.field_values()?;

    let request_id = get_named_bytes32(&fields, "request_id")?;
    let responder = get_named_bytes32(&fields, "responder")?; // Hydration 一般是 AccountId32

    // signature: pallet 的 Signature 结构（嵌套）
    let sig_value = get_named(&fields, "signature")?;
    let mpc_sig = parse_signature(sig_value)?;

    Ok(HydrationSignatureRespondedEvent {
        request_id,
        responder,
        signature: mpc_sig,
    })
}

fn decode_sign_bidirectional_requested(
    ev: &EventDetails<SubstrateConfig>,
) -> anyhow::Result<HydrationSignBidirectionalRequestedEvent> {
    let fields = ev.field_values()?;

    let sender = get_named_bytes32(&fields, "sender")?;
    let serialized_transaction = get_named_vec_u8(&fields, "serialized_transaction")?;

    let caip2_id = get_named_utf8(&fields, "caip2_id")?;
    let key_version = get_named_u32(&fields, "key_version")?;
    let deposit = get_named_u64(&fields, "deposit")?;

    let path = get_named_utf8(&fields, "path")?;
    let algo = get_named_utf8(&fields, "algo")?;
    let dest = get_named_utf8(&fields, "dest")?;
    let params = get_named_utf8(&fields, "params")?;

    let output_deserialization_schema = get_named_vec_u8(&fields, "output_deserialization_schema")?;
    let respond_serialization_schema = get_named_vec_u8(&fields, "respond_serialization_schema")?;

    Ok(HydrationSignBidirectionalRequestedEvent {
        sender,
        serialized_transaction,
        caip2_id,
        key_version,
        deposit,
        path,
        algo,
        dest,
        params,
        output_deserialization_schema,
        respond_serialization_schema,
    })
}

fn decode_respond_bidirectional(
    ev: &EventDetails<SubstrateConfig>,
) -> anyhow::Result<HydrationRespondBidirectionalEvent> {
    let fields = ev.field_values()?;

    let request_id = get_named_bytes32(&fields, "request_id")?;
    let responder = get_named_bytes32(&fields, "responder")?;
    let serialized_output = get_named_vec_u8(&fields, "serialized_output")?;

    let sig_val = get_named(&fields, "signature")?;
    let mpc_sig = parse_signature(sig_val)?;

    Ok(HydrationRespondBidirectionalEvent {
        request_id,
        responder,
        serialized_output,
        signature: mpc_sig,
    })
}

fn parse_signature(v: &Value<u32>) -> Result<Signature> {
    let sig_c = as_composite(v).ok_or_else(|| anyhow!("signature is not composite: {v}"))?;

    // Signature { big_r, s, recovery_id }
    let big_r_v = get_named(sig_c, "big_r")?;
    let big_r_c = as_composite(big_r_v).ok_or_else(|| anyhow!("big_r is not composite"))?;

    // AffinePoint { x, y }
    let x = get_named_bytes32(big_r_c, "x")?;
    let y = get_named_bytes32(big_r_c, "y")?;

    // s: [u8;32]
    let s_v = get_named(sig_c, "s")?;
    let s_bytes_vec = value_to_vec_u8(s_v)?;
    if s_bytes_vec.len() != 32 {
        return Err(anyhow!(
            "signature.s expected 32 bytes, got {}",
            s_bytes_vec.len()
        ));
    }
    let s_arr: [u8; 32] = s_bytes_vec.try_into().unwrap();

    // recovery_id: u8
    let rec_v = get_named(sig_c, "recovery_id")?;
    let recovery_id_u8 = rec_v
        .as_u128()
        .ok_or_else(|| anyhow!("recovery_id expected int, got: {rec_v}"))?;
    let recovery_id = recovery_id_u8 as u8;

    let x_bytes: FieldBytes = x.into();
    let y_bytes: FieldBytes = y.into();
    let enc = EncodedPoint::from_affine_coordinates(&x_bytes, &y_bytes, false);

    let big_r = AffinePoint::from_encoded_point(&enc)
        .into_option()
        .ok_or_else(|| anyhow!("invalid affine point in Signature.big_r"))?;

    let s_scalar =
        Scalar::from_bytes(s_arr).ok_or_else(|| anyhow!("invalid scalar in Signature.s"))?;

    Ok(Signature::new(big_r, s_scalar, recovery_id))
}

fn get_named_vec_u8(fields: &Composite<u32>, name: &str) -> Result<Vec<u8>> {
    let v = get_named(fields, name)?;
    value_to_vec_u8(v)
}

fn get_named_bytes32(fields: &Composite<u32>, name: &str) -> Result<[u8; 32]> {
    let v = get_named(fields, name)?;
    let bytes = value_to_vec_u8(v)?;
    let len = bytes.len();
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{name} expected 32 bytes, got {}", len))?;
    Ok(arr)
}

fn get_named_utf8(fields: &Composite<u32>, name: &str) -> Result<String> {
    let v = get_named(fields, name)?;
    let bytes = value_to_vec_u8(v)?;
    Ok(String::from_utf8(bytes)?)
}

fn get_named_u32(fields: &Composite<u32>, name: &str) -> Result<u32> {
    let v = get_named(fields, name)?;
    let n = v
        .as_u128()
        .ok_or_else(|| anyhow!("field {name} expected integer, got: {v}"))?;
    Ok(n.try_into()?)
}

fn get_named_u64(fields: &Composite<u32>, name: &str) -> Result<u64> {
    let v = get_named(fields, name)?;
    let n = v
        .as_u128()
        .ok_or_else(|| anyhow!("field {name} expected integer, got: {v}"))?;
    Ok(n.try_into()?)
}

fn as_composite(v: &Value<u32>) -> Option<&Composite<u32>> {
    match &v.value {
        ValueDef::Composite(c) => Some(c),
        _ => None,
    }
}

fn get_named<'a>(fields: &'a Composite<u32>, name: &str) -> Result<&'a Value<u32>> {
    match fields {
        Composite::Named(kvs) => kvs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v)
            .ok_or_else(|| anyhow!("missing field: {name}")),
        Composite::Unnamed(_) => Err(anyhow!("fields are unnamed; can't lookup '{name}'")),
    }
}

fn value_to_vec_u8(v: &Value<u32>) -> Result<Vec<u8>> {
    if let Some(s) = v.as_str() {
        if let Some(hex_str) = s.strip_prefix("0x") {
            return hex::decode(hex_str).map_err(|e| anyhow!("bad 0x hex string: {e}; s={s}"));
        }
        return Ok(s.as_bytes().to_vec());
    }

    match &v.value {
        ValueDef::Composite(Composite::Unnamed(vals)) => {
            if vals.len() == 1 {
                // if single element and element is Primitive, then Vec<u8> has only one byte
                if let ValueDef::Primitive(_) = vals[0].value {
                    let n = vals[0].as_u128().ok_or_else(|| {
                        anyhow!("expected int-like primitive byte, got: {}", vals[0])
                    })?;
                    if n > 255 {
                        return Err(anyhow!("byte out of range: {n}"));
                    }
                    return Ok(vec![n as u8]);
                }

                //newtype wrapper unwrap (e.g. AccountId32([u8;32]))
                return value_to_vec_u8(&vals[0]);
            }
            let mut out = Vec::with_capacity(vals.len());
            for x in vals {
                let n = x
                    .as_u128()
                    .ok_or_else(|| anyhow!("expected u8-like number in Vec<u8>, got: {x}"))?;
                if n > 255 {
                    return Err(anyhow!("byte out of range: {n}"));
                }
                out.push(n as u8);
            }
            Ok(out)
        }
        other => Err(anyhow!("unsupported Vec<u8> shape: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Scalar;
    use mpc_primitives::LATEST_MPC_KEY_VERSION;
    use std::time::Duration;

    #[test]
    fn test_hydration_signature_requested_generate_sign_request_success() {
        let event = HydrationSignatureRequestedEvent {
            sender: [1u8; 32],
            payload: Scalar::from(2u64).to_bytes().into(),
            path: "m/0/0".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 1u64,
            chain_id: "hydration:local".to_string(),
            algo: "secp256k1".to_string(),
            dest: "".to_string(),
            params: "".to_string(),
        };

        let entropy = [0u8; 32];
        let req = event
            .generate_sign_request(entropy, Duration::from_secs(60))
            .expect("generate_sign_request should succeed");

        assert_eq!(req.chain, Chain::Hydration);
        assert_eq!(req.args.path, "m/0/0");
        assert_eq!(req.args.key_version, LATEST_MPC_KEY_VERSION);
    }

    #[test]
    fn test_hydration_signature_requested_deposit_zero_errors() {
        let mut event = HydrationSignatureRequestedEvent {
            sender: [1u8; 32],
            payload: Scalar::from(2u64).to_bytes().into(),
            path: "m/0/0".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0u64,
            chain_id: "hydration:local".to_string(),
            algo: "secp256k1".to_string(),
            dest: "".to_string(),
            params: "".to_string(),
        };

        let entropy = [0u8; 32];
        assert!(event
            .generate_sign_request(entropy, Duration::from_secs(60))
            .is_err());
    }

    #[test]
    fn test_hydration_sign_bidir_generate_sign_request_success() {
        let event = HydrationSignBidirectionalRequestedEvent {
            sender: [2u8; 32],
            serialized_transaction: vec![1u8, 2u8, 3u8],
            caip2_id: "eip155:1".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 1u64,
            path: "m/0/1".to_string(),
            algo: "secp256k1".to_string(),
            dest: "".to_string(),
            params: "".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
        };

        let entropy = [0u8; 32];
        let req = event
            .generate_sign_request(entropy, Duration::from_secs(60))
            .expect("generate_sign_request should succeed");

        assert_eq!(req.chain, Chain::Hydration);
        match req.sign_request_type {
            SignRequestType::SignBidirectional(
                crate::stream::ops::SignBidirectionalEvent::Hydration(_),
            ) => {}
            other => panic!("expected SignBidirectional, got: {other:?}"),
        }
    }

    #[test]
    fn test_hydration_sign_bidir_deposit_zero_errors() {
        let mut event = HydrationSignBidirectionalRequestedEvent {
            sender: [2u8; 32],
            serialized_transaction: vec![1u8, 2u8, 3u8],
            caip2_id: "eip155:1".to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0u64,
            path: "m/0/1".to_string(),
            algo: "secp256k1".to_string(),
            dest: "".to_string(),
            params: "".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
        };

        let entropy = [0u8; 32];
        assert!(event
            .generate_sign_request(entropy, Duration::from_secs(60))
            .is_err());
    }

    #[test]
    fn test_hydration_stream_new_none_disabled() {
        assert!(HydrationStream::new(None).is_none());
    }
}
