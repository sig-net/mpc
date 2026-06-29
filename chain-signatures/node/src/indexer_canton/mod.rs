mod auth;
mod config;
pub mod contracts;
pub mod ledger_api;
mod request_id;
mod signature;
mod stream;

pub use auth::{CantonAuthConfig, CantonAuthProvider};
pub use request_id::compute_request_id;
pub use signature::der_encode_signature;
pub use stream::{parse_canton_signature, CantonStream};

use alloy::consensus::{SignableTransaction, TxEip1559};
use borsh::{BorshDeserialize, BorshSerialize};
pub use config::CantonConfig;
use contracts::TxParams as CantonTxParams;
use k256::Scalar;
use mpc_indexer_core::utils::hashing::hash_payload;
use mpc_primitives::{
    Chain, IndexedSignRequest, ScalarExt, SignArgs, SignBidirectionalEvent, SignId,
    LATEST_MPC_KEY_VERSION,
};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(crate = "borsh")]
pub struct CantonChainCtx {
    pub sign_event_contract_id: String,
}

/// Node-facing Canton sign event.
///
/// The raw Daml payload uses Canton-native shapes such as `Text` schemas and
/// transaction params. This type is created at the indexer boundary and carries
/// the byte fields expected by the shared bidirectional signing flow.
///
/// `RequestSignature` charges the Canton Coin fee atomically on-ledger (fail-closed),
/// so the indexer only sees already-charged requests. The fee never enters the event
/// payload, request id, KDF epsilon, or signed tx — the MPC neither sees nor verifies
/// it — so the bidirectional flow carries no Canton deposit (deposit = zero).
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct CantonSignBidirectionalRequestedEvent {
    pub sign_event_contract_id: String,
    pub sender: [u8; 32],
    pub request_id: [u8; 32],
    pub serialized_transaction: Vec<u8>,
    pub caip2_id: String,
    pub key_version: u32,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub output_deserialization_schema: Vec<u8>,
    pub respond_serialization_schema: Vec<u8>,
}

impl CantonSignBidirectionalRequestedEvent {
    pub fn from_created(
        contract_id: String,
        raw: contracts::SignBidirectionalRequestedEvent,
    ) -> anyhow::Result<Self> {
        let request_id = compute_request_id(&raw)?;
        let serialized_transaction = match &raw.tx_params {
            CantonTxParams::EvmType2TxParams(params) => {
                TxEip1559::try_from(params)?.encoded_for_signing()
            }
        };
        let mut sender = [0u8; 32];
        hex::decode_to_slice(&raw.sender, &mut sender)
            .map_err(|e| anyhow::anyhow!("invalid hex in sender: {e}"))?;

        Ok(Self {
            sign_event_contract_id: contract_id,
            sender,
            request_id,
            serialized_transaction,
            caip2_id: raw.caip2_id,
            key_version: raw.key_version,
            path: raw.path,
            algo: raw.algo,
            dest: raw.dest,
            params: raw.params,
            output_deserialization_schema: raw.output_deserialization_schema.into_bytes(),
            respond_serialization_schema: raw.respond_serialization_schema.into_bytes(),
        })
    }
}

impl CantonSignBidirectionalRequestedEvent {
    pub fn generate_request_id(&self) -> [u8; 32] {
        self.request_id
    }

    pub fn generate_sign_request(&self, entropy: [u8; 32]) -> anyhow::Result<IndexedSignRequest> {
        tracing::info!("found canton event: {:?}", self);

        if self.key_version > LATEST_MPC_KEY_VERSION {
            tracing::warn!("unsupported key version: {}", self.key_version);
            anyhow::bail!("unsupported key version");
        }

        let request_id = self.request_id;

        let epsilon = mpc_crypto::kdf::derive_epsilon_canton(
            self.key_version,
            &self.sender_string(),
            &self.path,
        );

        let unsigned_tx_hash = hash_payload(&self.serialized_transaction);

        let Some(payload) = Scalar::from_bytes(unsigned_tx_hash) else {
            anyhow::bail!("failed to convert unsigned_tx_hash to scalar: {unsigned_tx_hash:?}");
        };

        let sign_id = SignId::new(request_id);
        tracing::info!(?sign_id, "canton signature requested");

        let ctx = CantonChainCtx {
            sign_event_contract_id: self.sign_event_contract_id.clone(),
        };
        let chain_ctx =
            Some(borsh::to_vec(&ctx).expect("CantonChainCtx Borsh serialization is infallible"));

        Ok(IndexedSignRequest::sign_bidirectional(
            sign_id,
            SignArgs {
                entropy,
                epsilon,
                payload,
                path: self.path.clone(),
                key_version: self.key_version,
            },
            Chain::Canton,
            crate::util::current_unix_timestamp(),
            SignBidirectionalEvent {
                sender: self.sender,
                serialized_transaction: self.serialized_transaction.clone(),
                caip2_id: self.caip2_id.clone(),
                key_version: self.key_version,
                deposit: 0,
                path: self.path.clone(),
                algo: self.algo.clone(),
                dest: self.dest.clone(),
                params: self.params.clone(),
                output_deserialization_schema: self.output_deserialization_schema.clone(),
                respond_serialization_schema: self.respond_serialization_schema.clone(),
                chain: Chain::Canton,
                chain_ctx,
            },
        ))
    }

    pub fn source_chain(&self) -> Chain {
        Chain::Canton
    }

    pub fn sender_string(&self) -> String {
        hex::encode(self.sender)
    }
}
