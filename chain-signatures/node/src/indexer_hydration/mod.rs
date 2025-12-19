#![allow(missing_docs)]

use crate::backlog::Backlog;
use crate::indexer_common::SignatureEvent;
use crate::indexer_sol::MAX_SECP256K1_SCALAR;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::{Chain, IndexedSignRequest, Sign, SignRequestType};
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::hash_rlp_data;
use alloy_sol_types::SolValue;
use anyhow::{anyhow, Result};
use ethabi::{encode, Token};
use hydration::runtime_types::pallet_signet::pallet::Signature as HydrationSignature;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, FieldBytes, Scalar};
use mpc_crypto::ScalarExt as _;
use mpc_primitives::Signature;
use mpc_primitives::{SignArgs, SignId, LATEST_MPC_KEY_VERSION};
use near_account_id::AccountId;
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

impl HydrationSignatureRequestedEvent {
    fn from(event: hydration::signet::events::SignatureRequested) -> anyhow::Result<Self> {
        let mut sender = [0u8; 32];
        let sender_array: &[u8; 32] =
            <subxt::utils::AccountId32 as AsRef<[u8; 32]>>::as_ref(&event.sender);
        sender.copy_from_slice(sender_array);
        Ok(Self {
            sender,
            payload: event.payload,
            path: String::from_utf8(event.path)?,
            key_version: event.key_version,
            deposit: event.deposit.try_into()?,
            chain_id: String::from_utf8(event.chain_id)?,
            algo: String::from_utf8(event.algo)?,
            dest: String::from_utf8(event.dest)?,
            params: String::from_utf8(event.params)?,
        })
    }
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
            timestamp_sign_queue: Instant::now(),
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
    pub program_id: [u8; 32],
    pub output_deserialization_schema: Vec<u8>,
    pub respond_serialization_schema: Vec<u8>,
}

impl HydrationSignBidirectionalRequestedEvent {
    fn from(event: hydration::signet::events::SignBidirectionalRequested) -> anyhow::Result<Self> {
        let mut sender = [0u8; 32];
        let sender_array: &[u8; 32] =
            <subxt::utils::AccountId32 as AsRef<[u8; 32]>>::as_ref(&event.sender);
        sender.copy_from_slice(sender_array);
        let mut program_id = [0u8; 32];
        let program_id_array: &[u8; 32] =
            <subxt::utils::AccountId32 as AsRef<[u8; 32]>>::as_ref(&event.program_id);
        program_id.copy_from_slice(program_id_array);
        Ok(Self {
            sender,
            serialized_transaction: event.serialized_transaction,
            caip2_id: String::from_utf8(event.caip2_id)?,
            path: String::from_utf8(event.path)?,
            key_version: event.key_version,
            deposit: event.deposit.try_into()?,
            algo: String::from_utf8(event.algo)?,
            dest: String::from_utf8(event.dest)?,
            params: String::from_utf8(event.params)?,
            program_id,
            output_deserialization_schema: event.output_deserialization_schema,
            respond_serialization_schema: event.respond_serialization_schema,
        })
    }
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
            timestamp_sign_queue: Instant::now(),
            unix_timestamp_indexed: crate::util::current_unix_timestamp(),
            total_timeout,
            sign_request_type: SignRequestType::SignBidirectional(
                crate::indexer_common::SignBidirectionalEvent::Hydration(self.clone()),
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

impl HydrationRespondBidirectionalEvent {
    fn from(event: hydration::signet::events::RespondBidirectionalEvent) -> anyhow::Result<Self> {
        let signature = to_mpc_signature(event.signature)?;
        let responder = account32_to_bytes(&event.responder);
        Ok(Self {
            request_id: event.request_id,
            responder,
            serialized_output: event.serialized_output,
            signature,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HydrationSignatureRespondedEvent {
    pub request_id: [u8; 32],
    pub responder: [u8; 32],
    pub signature: Signature,
}

impl HydrationSignatureRespondedEvent {
    fn from(event: hydration::signet::events::SignatureResponded) -> anyhow::Result<Self> {
        let signature = to_mpc_signature(event.signature)?;
        let responder = account32_to_bytes(&event.responder);
        Ok(Self {
            request_id: event.request_id,
            responder,
            signature,
        })
    }
}

fn to_mpc_signature(sig: HydrationSignature) -> anyhow::Result<Signature> {
    let x_bytes: FieldBytes = sig.big_r.x.into();
    let y_bytes: FieldBytes = sig.big_r.y.into();
    let enc = EncodedPoint::from_affine_coordinates(&x_bytes, &y_bytes, false);

    let big_r = AffinePoint::from_encoded_point(&enc)
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("invalid affine point in HydrationSignature"))?;

    let s = Scalar::from_bytes(sig.s)
        .ok_or_else(|| anyhow::anyhow!("invalid scalar in HydrationSignature"))?;

    Ok(Signature::new(big_r, s, sig.recovery_id))
}

fn account32_to_bytes(account: &subxt::utils::AccountId32) -> [u8; 32] {
    let mut result = [0u8; 32];
    let account_array: &[u8; 32] = <subxt::utils::AccountId32 as AsRef<[u8; 32]>>::as_ref(account);
    result.copy_from_slice(account_array);
    result
}

#[subxt::subxt(runtime_metadata_path = "src/indexer_hydration/artifacts/hydration_metadata.scale")]
pub mod hydration {}

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

pub async fn run(
    hydration: Option<HydrationConfig>,
    sign_tx: mpsc::Sender<Sign>,
    node_near_account_id: AccountId,
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
    crate::indexer_common::recover_backlog(
        &backlog,
        &mut contract_watcher,
        &mut mesh_state,
        &node_client,
        Chain::Hydration,
    )
    .await;

    // Subscribe to finalized Hydration blocks.
    let mut blocks = match hydration_api.blocks().subscribe_finalized().await {
        Ok(blocks) => blocks,
        Err(e) => {
            tracing::error!("failed to subscribe to finalized blocks: {e}");
            return;
        }
    };

    while let Some(block_res) = blocks.next().await {
        let block = match block_res {
            Ok(block) => block,
            Err(e) => {
                tracing::error!("failed to get block: {e}");
                continue;
            }
        };
        let number = block.number();
        let hash = block.hash();
        let header = block.header().clone();
        tracing::info!("received block from hydration rpc: block number {number}, hash {hash:?}");

        // Subxt's Substrate header uses H256 as state root (BlakeTwo256 hash).
        let state_root: H256 = header.state_root;

        // Events as decoded by Subxt (unproven bytes).
        let events = match block.events().await {
            Ok(events) => events,
            Err(e) => {
                tracing::error!("failed to get events: {e}");
                continue;
            }
        };
        // Raw SCALE bytes for `System::Events` that Subxt decoded.
        let events_bytes_unproven = events.bytes().to_vec();

        // Events bytes proven via storage proof under state_root.
        let events_bytes_proven =
            match fetch_proven_system_events_bytes(&legacy_rpc, state_root, hash).await {
                Ok(events_bytes_proven) => events_bytes_proven,
                Err(e) => {
                    tracing::error!("failed to fetch proven system events bytes: {e}");
                    continue;
                }
            };

        // Sanity check: bytes that Subxt decoded must match the Merkle‑proven bytes.
        if events_bytes_unproven != events_bytes_proven {
            tracing::error!(
                "Mismatch between RPC events and Merkle‑proven System::Events \
                 in block #{number} ({hash:?})"
            );
            continue;
        }

        // At this point:
        //  - Block is finalized (subscribe_finalized)
        //  - System::Events is Merkle‑proven under state_root
        //  - The bytes Subxt decoded match the proven bytes
        //
        // → Safe to trust individual decoded events.

        let sign_tx = sign_tx.clone();
        let node_near_account_id = node_near_account_id.clone();
        let backlog = backlog.clone();

        for ev in events.iter() {
            let ev = match ev {
                Ok(ev) => ev,
                Err(e) => {
                    tracing::error!("failed to get event: {e}");
                    continue;
                }
            };

            // SignatureRequested
            if let Ok(Some(req)) = ev.as_event::<hydration::signet::events::SignatureRequested>() {
                let event = match HydrationSignatureRequestedEvent::from(req) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::error!(
                            "failed to convert event to HydrationSignatureRequestedEvent: {e}"
                        );
                        continue;
                    }
                };
                tracing::info!(
                    "Hydration::Signet::SignatureRequested in block #{number} ({hash:?}): {:?}",
                    event
                );

                let entropy = match entropy_from_event(&ev) {
                    Ok(entropy) => entropy,
                    Err(e) => {
                        tracing::error!("failed to extract entropy from event: {e}");
                        continue;
                    }
                };

                if let Err(e) = crate::indexer_common::process_sign_event(
                    Box::new(event),
                    entropy,
                    sign_tx.clone(),
                    node_near_account_id.clone(),
                    total_timeout,
                    backlog.clone(),
                )
                .await
                {
                    tracing::error!("failed to process sign event: {e}");
                }
            }

            // SignatureResponded
            if let Ok(Some(resp)) = ev.as_event::<hydration::signet::events::SignatureResponded>() {
                let event = match HydrationSignatureRespondedEvent::from(resp) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::error!(
                            "failed to convert event to HydrationSignatureRespondedEvent: {e}"
                        );
                        continue;
                    }
                };
                tracing::info!(
                    "Hydration::Signet::SignatureResponded in block #{number} ({hash:?}): {:?}",
                    event
                );
                if let Err(e) = crate::indexer_common::process_respond_event(
                    crate::indexer_common::SignatureRespondedEvent::Hydration(event),
                    sign_tx.clone(),
                    &mut contract_watcher,
                    &backlog,
                )
                .await
                {
                    tracing::error!("failed to process respond event: {e}");
                }
            }

            // Bidirectional request
            if let Ok(Some(req_bi)) =
                ev.as_event::<hydration::signet::events::SignBidirectionalRequested>()
            {
                let event = match HydrationSignBidirectionalRequestedEvent::from(req_bi) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::error!("failed to convert event to HydrationSignBidirectionalRequestedEvent: {e}");
                        continue;
                    }
                };
                tracing::info!(
                    "Hydration::Signet::SignBidirectionalRequested in block #{number} ({hash:?}): {:?}",
                    event
                );

                let entropy = match entropy_from_event(&ev) {
                    Ok(entropy) => entropy,
                    Err(e) => {
                        tracing::error!("failed to extract entropy from event: {e}");
                        continue;
                    }
                };

                if let Err(e) = crate::indexer_common::process_sign_event(
                    Box::new(event),
                    entropy,
                    sign_tx.clone(),
                    node_near_account_id.clone(),
                    total_timeout,
                    backlog.clone(),
                )
                .await
                {
                    tracing::error!("failed to process sign event: {e}");
                }
            }

            // Bidirectional response
            if let Ok(Some(resp_bi)) =
                ev.as_event::<hydration::signet::events::RespondBidirectionalEvent>()
            {
                let event = match HydrationRespondBidirectionalEvent::from(resp_bi) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::error!(
                            "failed to convert event to HydrationRespondBidirectionalEvent: {e}"
                        );
                        continue;
                    }
                };
                tracing::info!(
                    "Hydration::Signet::RespondBidirectionalEvent in block #{number} ({hash:?}): {:?}",
                    event
                );
                if let Err(e) = crate::indexer_common::process_respond_bidirectional_event(
                    crate::indexer_common::RespondBidirectionalEvent::Hydration(event),
                    sign_tx.clone(),
                    &backlog,
                )
                .await
                {
                    tracing::error!("failed to process respond bidirectional event: {e}");
                }
            }
        }
    }
}

fn entropy_from_event(
    ev: &subxt::events::EventDetails<SubstrateConfig>,
) -> anyhow::Result<[u8; 32]> {
    ev.bytes().to_vec()[..32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("failed to convert event bytes to [u8; 32]"))
}
