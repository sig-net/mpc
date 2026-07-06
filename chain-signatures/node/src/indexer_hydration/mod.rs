mod config;

use crate::backlog::Backlog;
use crate::mesh::MeshState;
use crate::node_client::NodeClient;
use crate::protocol::{Chain, Sign};
use crate::rpc::ContractStateWatcher;
use crate::sign_bidirectional::hash_rlp_data;
pub use config::HydrationConfig;

use crate::util::ethabi_request_id;
use alloy_sol_types::SolValue;
use anyhow::{anyhow, Result};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{AffinePoint, EncodedPoint, FieldBytes, Scalar};
use mpc_crypto::ScalarExt as _;
use mpc_indexer_core::ChainTelemetry;
use mpc_primitives::{
    CheckpointDigest, IndexedSignRequest, RespondBidirectionalEvent, SignArgs,
    SignBidirectionalEvent, SignId, Signature, SignatureRespondedEvent, LATEST_MPC_KEY_VERSION,
    MAX_SECP256K1_SCALAR,
};
use sp_core::crypto::{AccountId32 as SpAccountId32, Ss58AddressFormatRegistry, Ss58Codec};
use sp_core::{twox_128, H256};
use sp_runtime::traits::BlakeTwo256;
use sp_state_machine::read_proof_check;
use sp_trie::StorageProof;
use std::convert::TryInto;
use subxt::backend::{legacy::LegacyRpcMethods, rpc::RpcClient};
use subxt::config::HashFor;
use subxt::events::EventDetails;
use subxt::ext::scale_value::{Composite, Value, ValueDef};
use subxt::{client::OnlineClient, SubstrateConfig};
use tokio::sync::mpsc;
use tokio::sync::watch;

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
    fn generate_request_id(&self) -> [u8; 32] {
        ethabi_request_id(
            &self.sender_string(),
            self.payload,
            &self.path,
            self.key_version,
            &self.chain_id,
            &self.algo,
            &self.dest,
            &self.params,
        )
    }

    fn generate_sign_request(&self, entropy: [u8; 32]) -> Option<IndexedSignRequest> {
        tracing::info!("found hydration event: {:?}", self);
        if self.deposit == 0 {
            tracing::warn!("deposit is 0, skipping sign request");
            return None;
        }

        if self.key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!("unsupported key version: {}", self.key_version);
            return None;
        }

        let payload = Scalar::from_bytes(self.payload).or_else(|| {
            tracing::warn!(
                "hydration `sign` did not produce payload hash correctly: {:?}",
                self.payload,
            );
            None
        })?;

        if payload > *MAX_SECP256K1_SCALAR {
            tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
            return None;
        }

        let epsilon = mpc_crypto::kdf::derive_epsilon_hydration(
            self.key_version,
            &self.sender_string(),
            &self.path,
        );

        let sign_id = SignId::new(self.generate_request_id());
        tracing::info!(?sign_id, "hydration signature requested");

        Some(IndexedSignRequest::sign(
            sign_id,
            SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            Chain::Hydration,
            crate::util::current_unix_timestamp(),
        ))
    }

    pub fn source_chain(&self) -> Chain {
        Chain::Hydration
    }

    pub fn sender_string(&self) -> String {
        ss58_address_from_account32(self.sender)
    }
}

/// The deserialized representation of a bidirectional signing request
/// event emitted from the Hydration chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct HydrationSignBidirectionalRequestedEvent {
    /// The 32-byte identifier of the sender.
    pub sender: [u8; 32],

    /// The serialized transaction payload to be signed.
    pub serialized_transaction: Vec<u8>,

    /// CAIP-2 chain ID of the *target chain* where the signed transaction will be sent.
    ///
    /// Note: This is NOT the chain where `respond()` or `respond_bidirectional()` is executed.
    pub caip2_id: String,

    /// Version of the key to be used for signing.
    pub key_version: u32,

    /// Deposit associated with the request.
    pub deposit: u64,

    /// Derivation path used for signing.
    pub path: String,

    /// Signing algorithm identifier.
    ///
    /// If empty (`""`), ECDSA will be used by default.
    pub algo: String,

    /// Destination field (currently unused).
    ///
    /// Should be left empty (`""`).
    pub dest: String,

    /// Additional parameters encoded as a string (currently unused).
    ///
    /// Should be left empty (`""`).
    pub params: String,

    /// Schema used to deserialize the output of the signed transaction.
    ///
    /// MUST be provided.
    pub output_deserialization_schema: Vec<u8>,

    /// Schema used to serialize the `respond_bidirectional` payload.
    ///
    /// MUST be provided.
    pub respond_serialization_schema: Vec<u8>,
}

impl HydrationSignBidirectionalRequestedEvent {
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

    pub fn generate_sign_request(&self, entropy: [u8; 32]) -> Option<IndexedSignRequest> {
        tracing::info!("found hydration event: {:?}", self);
        if self.deposit == 0 {
            tracing::warn!("deposit is 0, skipping sign request");
            return None;
        }

        if self.key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!("unsupported key version: {}", self.key_version);
            return None;
        }

        let request_id = self.generate_request_id();

        // Call the existing derive_epsilon_sol function with the correct parameters
        // to match the TypeScript implementation
        let epsilon = mpc_crypto::kdf::derive_epsilon_hydration(
            self.key_version,
            &self.sender_string(),
            &self.path,
        );

        let sign_id = SignId::new(request_id);
        tracing::info!(?sign_id, "hydration signature requested");
        let unsigned_tx_hash = hash_rlp_data(&self.serialized_transaction);
        let payload = Scalar::from_bytes(unsigned_tx_hash).or_else(|| {
            tracing::warn!("failed to convert unsigned_tx_hash to scalar: {unsigned_tx_hash:?}");
            None
        })?;

        if payload > *MAX_SECP256K1_SCALAR {
            tracing::warn!("payload exceeds secp256k1 curve order: {payload:?}");
            return None;
        }

        Some(IndexedSignRequest::sign_bidirectional(
            sign_id,
            SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            Chain::Hydration,
            crate::util::current_unix_timestamp(),
            SignBidirectionalEvent {
                sender: self.sender,
                serialized_transaction: self.serialized_transaction.clone(),
                caip2_id: self.caip2_id.clone(),
                key_version: self.key_version,
                deposit: self.deposit,
                path: self.path.clone(),
                algo: self.algo.clone(),
                dest: self.dest.clone(),
                params: self.params.clone(),
                output_deserialization_schema: self.output_deserialization_schema.clone(),
                respond_serialization_schema: self.respond_serialization_schema.clone(),
                chain: Chain::Hydration,
                chain_ctx: None,
            },
        ))
    }

    pub fn source_chain(&self) -> Chain {
        Chain::Hydration
    }

    pub fn sender_string(&self) -> String {
        ss58_address_from_account32(self.sender)
    }
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

#[allow(clippy::too_many_arguments)]
pub async fn run<T: ChainTelemetry>(
    hydration: Option<HydrationConfig>,
    sign_tx: mpsc::Sender<Sign>,
    backlog: Backlog,
    telemetry: T,
    mut contract_watcher: ContractStateWatcher,
    mut mesh_state: watch::Receiver<MeshState>,
    node_client: NodeClient,
    mut checkpoints_rx: watch::Receiver<CheckpointDigest>,
) {
    let Some(hydration) = hydration else {
        tracing::warn!("hydration indexer is disabled");
        return;
    };

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

    let threshold = contract_watcher.wait_threshold().await;
    crate::mesh::wait_threshold_active(&mut mesh_state, threshold).await;

    // Load local checkpoint from storage first
    match backlog.storage.load_latest(Chain::Hydration).await {
        Ok(Some(checkpoint)) => {
            tracing::info!(
                chain = ?Chain::Hydration,
                height = checkpoint.block_height,
                "loaded local checkpoint"
            );
            if let Err(err) = backlog.recover_by_checkpoint(checkpoint).await {
                tracing::warn!(chain = ?Chain::Hydration, %err, "failed to recover from local checkpoint");
            }
        }
        Ok(None) => {
            tracing::info!(chain = ?Chain::Hydration, "no local checkpoint found");
        }
        Err(err) => {
            tracing::warn!(chain = ?Chain::Hydration, %err, "failed to load local checkpoint");
        }
    }

    // Load historical checkpoints from storage
    match backlog.storage.load_history(Chain::Hydration).await {
        Ok(history) => {
            for checkpoint in history {
                backlog.remember_checkpoint(checkpoint).await;
            }
        }
        Err(err) => {
            tracing::warn!(chain = ?Chain::Hydration, %err, "failed to load historical checkpoints");
        }
    }

    // Align with consensus
    crate::backlog::consensus::align_backlog_with_consensus(
        Chain::Hydration,
        &backlog,
        &mut checkpoints_rx,
        &mut mesh_state,
        &node_client,
        contract_watcher.account_id(),
    )
    .await;

    spawn_runtime_updater(hydration_api.clone());

    let root_pk = contract_watcher.wait_public_key().await;

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
            if ev.pallet_name() == PALLET_SIGNET && ev.variant_name() == EVENT_SIGNATURE_REQUESTED {
                let event = match decode_signature_requested(&ev) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::error!("failed to decode signature requested event: {e}");
                        continue;
                    }
                };
                tracing::info!(
                    "Hydration::Signet::SignatureRequested in block #{number} ({hash:?}): {:?}",
                    event
                );

                let entropy = sp_core::hashing::blake2_256(ev.bytes());

                let Some(sign_request) = event.generate_sign_request(entropy) else {
                    continue;
                };

                if let Err(e) = crate::stream::ops::process_sign_request(
                    sign_request,
                    sign_tx.clone(),
                    backlog.clone(),
                    true,
                )
                .await
                {
                    tracing::error!("failed to process sign event: {e}");
                }
            }
            // SignatureResponded
            if ev.pallet_name() == PALLET_SIGNET && ev.variant_name() == EVENT_SIGNATURE_RESPONDED {
                let event = match decode_signature_responded(&ev) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::error!("failed to decode signature responded event: {e}");
                        continue;
                    }
                };
                tracing::info!(
                    "Hydration::Signet::SignatureResponded in block #{number} ({hash:?})"
                );
                if let Err(e) = crate::stream::ops::process_respond_event(
                    event,
                    sign_tx.clone(),
                    root_pk,
                    &backlog,
                    true,
                )
                .await
                {
                    tracing::error!("failed to process respond event: {e}");
                }
            }

            // Bidirectional request
            if ev.pallet_name() == PALLET_SIGNET
                && ev.variant_name() == EVENT_SIGN_BIDIRECTIONAL_REQUESTED
            {
                let event = match decode_sign_bidirectional_requested(&ev) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::error!("failed to decode sign bidirectional requested event: {e}");
                        continue;
                    }
                };
                tracing::info!(
                    "Hydration::Signet::SignBidirectionalRequested in block #{number} ({hash:?}): {:?}",
                event
                );

                let entropy = sp_core::hashing::blake2_256(ev.bytes());

                let Some(sign_request) = event.generate_sign_request(entropy) else {
                    continue;
                };

                if let Err(e) = crate::stream::ops::process_sign_request(
                    sign_request,
                    sign_tx.clone(),
                    backlog.clone(),
                    true,
                )
                .await
                {
                    tracing::error!("failed to process sign event: {e}");
                }
            }

            // Bidirectional response
            if ev.pallet_name() == PALLET_SIGNET && ev.variant_name() == EVENT_RESPOND_BIDIRECTIONAL
            {
                let fields = match ev.field_values() {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!("failed to get fields for respond bidirectional: {e}");
                        continue;
                    }
                };
                let request_id = match get_named_bytes32(&fields, "request_id") {
                    Ok(id) => id,
                    Err(e) => {
                        tracing::error!("failed to get request_id: {e}");
                        continue;
                    }
                };
                let signature = match get_named(&fields, "signature").and_then(parse_signature) {
                    Ok(sig) => sig,
                    Err(e) => {
                        tracing::error!(?e, "failed to parse signature");
                        continue;
                    }
                };
                tracing::info!(
                    "Hydration::Signet::RespondBidirectionalEvent in block #{number} ({hash:?})"
                );
                if let Err(e) = crate::stream::ops::process_respond_bidirectional_event(
                    RespondBidirectionalEvent {
                        request_id,
                        signature,
                        chain: crate::protocol::Chain::Hydration,
                    },
                    sign_tx.clone(),
                    root_pk,
                    &backlog,
                    true,
                )
                .await
                {
                    tracing::error!("failed to process respond bidirectional event: {e}");
                }
            }
        }

        // Update Prometheus metrics
        telemetry.block_indexed(number.into());
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
) -> anyhow::Result<SignatureRespondedEvent> {
    let fields = ev.field_values()?;

    let request_id = get_named_bytes32(&fields, "request_id")?;

    // signature: pallet 的 Signature 结构（嵌套）
    let sig_value = get_named(&fields, "signature")?;
    let mpc_sig = parse_signature(sig_value)?;

    Ok(SignatureRespondedEvent {
        request_id,
        signature: mpc_sig,
        chain: Chain::Hydration,
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

    Chain::from_caip2_chain_id(&caip2_id)
        .map_err(|e| anyhow!("invalid caip2 chain id in sign bidirectional event: {e:?}"))?;

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

    #[test]
    fn request_id_matches_ethabi() {
        let event = HydrationSignatureRequestedEvent {
            sender: [0xAA; 32],
            payload: [0xBB; 32],
            path: "m/44'/60'/0'/0/0".to_string(),
            key_version: 3,
            deposit: 999,
            chain_id: "hydration-testnet".to_string(),
            algo: "secp256k1".to_string(),
            dest: "dest-address".to_string(),
            params: "payload-params".to_string(),
        };

        assert_eq!(
            hex::encode(event.generate_request_id()),
            "67a3a9bf9d424d85bef21cf9780a0634c6a06061265ce9d1063f30f1eec84821"
        );
    }
}
