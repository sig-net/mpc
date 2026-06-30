use std::sync::Arc;

use crate::indexer_hydration::HydrationConfig;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use mpc_chain_integration_core::{ChainPublisher, PublishAction, PublisherTelemetry};
use mpc_primitives::{SignId, SignKind, Signature};
use parity_scale_codec::{Decode, Encode};
use sp_core::{sr25519, Pair as _};
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    MultiSignature as SpMultiSignature,
};
use subxt::config::substrate::{
    AccountId32, BlakeTwo256, MultiSignature, SubstrateConfig, SubstrateExtrinsicParams,
    SubstrateHeader,
};
use subxt::tx::Payload;
use subxt::Config as SubxtConfig;
use subxt::OnlineClient;

enum HydradxConfig {}

impl SubxtConfig for HydradxConfig {
    type AccountId = <SubstrateConfig as SubxtConfig>::AccountId;
    type Address = <SubstrateConfig as SubxtConfig>::AccountId;
    type Signature = <SubstrateConfig as SubxtConfig>::Signature;
    type Hasher = BlakeTwo256;
    type Header = SubstrateHeader<u32, BlakeTwo256>;
    type ExtrinsicParams = SubstrateExtrinsicParams<Self>;
    type AssetId = <SubstrateConfig as SubxtConfig>::AssetId;
}

#[derive(Clone)]
struct HydrationSigner {
    account_id: AccountId32,
    signer: sr25519::Pair,
}

impl HydrationSigner {
    fn from_uri(uri: &str) -> anyhow::Result<Self> {
        let signer = sr25519::Pair::from_string(uri, None)?;
        let account_id = <SpMultiSignature as Verify>::Signer::from(signer.public()).into_account();

        Ok(Self {
            account_id: AccountId32(account_id.into()),
            signer,
        })
    }
}

impl subxt::tx::Signer<HydradxConfig> for HydrationSigner {
    fn account_id(&self) -> <HydradxConfig as SubxtConfig>::AccountId {
        self.account_id.clone()
    }

    fn sign(&self, signer_payload: &[u8]) -> <HydradxConfig as SubxtConfig>::Signature {
        MultiSignature::Sr25519(self.signer.sign(signer_payload).0)
    }
}

#[derive(Clone)]
pub struct HydrationClient {
    api: OnlineClient<HydradxConfig>,
    signer: HydrationSigner,
    telemetry: Arc<dyn PublisherTelemetry>,
}

const PALLET_SIGNET: &str = "Signet";

/// This type mirrors the on-chain representation of an affine point
#[derive(Clone, Debug, Encode, Decode)]
struct HydrationAffinePoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// This type mirrors the on-chain signature format
#[derive(Clone, Debug, Encode, Decode)]
struct HydrationSignature {
    pub big_r: HydrationAffinePoint,
    pub s: [u8; 32],
    pub recovery_id: u8,
}

/// A thin wrapper used to mirror the on-chain `BoundedVec` type for SCALE
/// encoding/decoding. This type does **not** enforce any length bounds; it
/// is effectively just a `Vec<T>` on the client side.
///
/// Callers are responsible for ensuring that the inner `Vec` length respects
/// the maximum length enforced by the on-chain pallet, otherwise the
/// resulting transaction may be rejected on-chain.
#[derive(Clone, Debug, Encode, Decode)]
struct BoundedVec<T>(pub Vec<T>);

/// this type is used to construct tx to call respond() on pallet
struct HydrationRespondTx {
    pub request_ids: BoundedVec<[u8; 32]>,
    pub signatures: BoundedVec<HydrationSignature>,
}

impl Payload for HydrationRespondTx {
    fn encode_call_data_to(
        &self,
        metadata: &subxt::Metadata,
        out: &mut Vec<u8>,
    ) -> std::result::Result<(), subxt::ext::subxt_core::Error> {
        let pallet = metadata.pallet_by_name(PALLET_SIGNET).ok_or_else(|| {
            subxt::ext::subxt_core::Error::Metadata(
                subxt::error::MetadataError::PalletNameNotFound(PALLET_SIGNET.to_string()),
            )
        })?;

        let respond_call_index = pallet
            .call_variant_by_name("respond")
            .ok_or_else(|| {
                subxt::ext::subxt_core::Error::Metadata(
                    subxt::error::MetadataError::CallNameNotFound("respond".to_string()),
                )
            })?
            .index;

        let pallet_index: u8 = pallet.index();

        out.push(pallet_index);
        out.push(respond_call_index);

        (&self.request_ids, &self.signatures).encode_to(out);
        Ok(())
    }
}

/// this type is used to construct tx to call respond_bidirectional() on pallet
struct HydrationRespondBidirectionalTx {
    pub request_id: [u8; 32],
    pub serialized_output: BoundedVec<u8>,
    pub signature: HydrationSignature,
}

impl Payload for HydrationRespondBidirectionalTx {
    fn encode_call_data_to(
        &self,
        metadata: &subxt::Metadata,
        out: &mut Vec<u8>,
    ) -> std::result::Result<(), subxt::ext::subxt_core::Error> {
        let pallet = metadata.pallet_by_name(PALLET_SIGNET).ok_or_else(|| {
            subxt::ext::subxt_core::Error::Metadata(
                subxt::error::MetadataError::PalletNameNotFound(PALLET_SIGNET.to_string()),
            )
        })?;

        let pallet_index: u8 = pallet.index();

        let respond_bidirectional_call_index = pallet
            .call_variant_by_name("respond_bidirectional")
            .ok_or_else(|| {
                subxt::ext::subxt_core::Error::Metadata(
                    subxt::error::MetadataError::CallNameNotFound(
                        "respond_bidirectional".to_string(),
                    ),
                )
            })?
            .index;

        out.push(pallet_index);
        out.push(respond_bidirectional_call_index);

        // respond_bidirectional(origin, request_id, serialized_output, signature)
        (&self.request_id, &self.serialized_output, &self.signature).encode_to(out);
        Ok(())
    }
}

impl HydrationClient {
    pub async fn new(
        config: &HydrationConfig,
        telemetry: Arc<dyn PublisherTelemetry>,
    ) -> anyhow::Result<Self> {
        let api = OnlineClient::<HydradxConfig>::from_url(&config.rpc_ws_url).await?;
        let signer = HydrationSigner::from_uri(&config.signer_uri)?;
        Ok(Self {
            api,
            signer,
            telemetry,
        })
    }

    fn to_hydration_signature(sig: &Signature) -> anyhow::Result<HydrationSignature> {
        let enc = sig.big_r.to_encoded_point(false);

        let x: [u8; 32] = enc
            .x()
            .ok_or_else(|| anyhow::anyhow!("missing x"))?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("x must be 32 bytes"))?;

        let y: [u8; 32] = enc
            .y()
            .ok_or_else(|| anyhow::anyhow!("missing y"))?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("y must be 32 bytes"))?;

        let s: [u8; 32] = sig.s.to_bytes().into();

        Ok(HydrationSignature {
            big_r: HydrationAffinePoint { x, y },
            s,
            recovery_id: sig.recovery_id,
        })
    }

    async fn call_respond(&self, id: &SignId, response: &Signature) -> anyhow::Result<()> {
        let tx = HydrationRespondTx {
            request_ids: BoundedVec(vec![id.request_id]),
            signatures: BoundedVec(vec![Self::to_hydration_signature(response)?]),
        };

        let progress = self
            .api
            .tx()
            .sign_and_submit_then_watch_default(&tx, &self.signer)
            .await?;

        progress.wait_for_finalized_success().await?;
        Ok(())
    }

    async fn call_respond_bidirectional(
        &self,
        id: &SignId,
        serialized_output: Vec<u8>,
        response: &Signature,
    ) -> anyhow::Result<subxt::config::HashFor<HydradxConfig>> {
        let tx = HydrationRespondBidirectionalTx {
            request_id: id.request_id,
            serialized_output: BoundedVec(serialized_output),
            signature: Self::to_hydration_signature(response)?,
        };

        let progress = self
            .api
            .tx()
            .sign_and_submit_then_watch_default(&tx, &self.signer)
            .await?;

        let events = progress.wait_for_finalized_success().await?;
        Ok(events.extrinsic_hash())
    }
}

#[async_trait::async_trait]
impl ChainPublisher for HydrationClient {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let timestamp = action.timestamp;
        let signature = &action.signature;
        let chain = action.indexed.chain;
        let sign_id = action.indexed.id;
        let request_ids = [action.indexed.id.request_id];

        tracing::info!(
            ?sign_id,
            ?chain,
            elapsed = ?timestamp.elapsed(),
            request_id = ?request_ids[0],
            "Hydration: publishing signature"
        );

        match &action.indexed.kind {
            SignKind::Sign | SignKind::SignBidirectional(_) => {
                self.call_respond(&action.indexed.id, signature)
                    .await
                    .inspect_err(|e| {
                        tracing::error!(?sign_id, ?e, "Hydration: failed to publish signature")
                    })?;

                tracing::info!(
                    ?sign_id,
                    elapsed = ?timestamp.elapsed(),
                    "published hydration signature successfully"
                );
            }
            SignKind::RespondBidirectional(respond_bidirectional_tx) => {
                let serialized_output = respond_bidirectional_tx.output.clone();
                tracing::debug!(
                    ?sign_id,
                    request_id = ?request_ids[0],
                    serialized_output_len = serialized_output.len(),
                    "Hydration publish signature: entering RespondBidirectional arm"
                );
                let tx_hash = self
                    .call_respond_bidirectional(&action.indexed.id, serialized_output, signature)
                    .await
                    .inspect_err(|e| {
                        tracing::error!(
                            ?sign_id,
                            ?e,
                            "Hydration publish signature: failed to publish respond bidirectional signature"
                        );
                    })?;

                tracing::info!(
                    ?sign_id,
                    tx_hash = ?tx_hash,
                    elapsed = ?timestamp.elapsed(),
                    "Hydration publish signature: published respond bidirectional signature successfully"
                );
            }
            SignKind::Checkpoint(_) => {
                tracing::error!(?sign_id, "Hydration: checkpoint publishing not supported");
                anyhow::bail!("checkpoint publishing not supported on Hydration");
            }
        }

        self.telemetry.record_publish_metrics(action);

        Ok(())
    }
}

// TODO: add unit tests
