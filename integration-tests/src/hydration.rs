use anyhow::{anyhow, Result};
use serde::Deserialize;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use std::env;

/// Minimal Hydration sandbox handle for integration-tests.
///
/// Two ways to enable in your test environment:
/// 1. Provide `HYDRATION_RPC_WS_URL` pointing at a running Hydration node (recommended for CI).
/// 2. Provide `HYDRATION_BINARY` (path) and `HYDRATION_RPC_WS_URL` (where it will bind) so the harness
///    can detect readiness. Starting the binary is intentionally left to the operator since command
///    line args for Hydration node vary between releases.
#[derive(Clone, Debug, Deserialize)]
pub struct HydrationHandle {
    /// websocket RPC endpoint (ws://...)
    pub rpc_ws_url: String,
    /// optional signer URI to be passed to indexer config (may be empty)
    pub signer_uri: Option<String>,
}

impl HydrationHandle {
    /// Try to construct a handle from environment. Returns Err if the environment
    /// does not contain `HYDRATION_RPC_WS_URL`.
    pub async fn from_env() -> Result<Self> {
        if let Ok(ws) = env::var("HYDRATION_RPC_WS_URL") {
            let signer = env::var("HYDRATION_SIGNER_URI").ok();
            // basic readiness probe: try to connect to the ws URL using a timeout
            let ok = tokio::time::timeout(std::time::Duration::from_secs(3), async {
                // simple TCP connect for ws host:port
                if let Ok(url) = url::Url::parse(&ws) {
                    if let Some(host) = url.host_str() {
                        let port = url.port().unwrap_or(80);
                        let addr = format!("{}:{}", host, port);
                        tokio::net::TcpStream::connect(addr).await.is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .await
            .unwrap_or(false);

            if !ok {
                return Err(anyhow!(
                    "HYDRATION_RPC_WS_URL is set but not reachable: {}",
                    ws
                ));
            }

            Ok(HydrationHandle {
                rpc_ws_url: ws,
                signer_uri: signer,
            })
        } else {
            Err(anyhow!("no HYDRATION_RPC_WS_URL in environment"))
        }
    }

    /// Convert to `mpc_node::indexer_hydration::HydrationConfig` for indexer tests.
    pub fn into_indexer_config(self) -> mpc_node::indexer_hydration::HydrationConfig {
        mpc_node::indexer_hydration::HydrationConfig {
            rpc_ws_url: self.rpc_ws_url,
            signer_uri: self
                .signer_uri
                .unwrap_or_else(|| String::from("http://127.0.0.1:0")),
            total_timeout: 60,
        }
    }

    /// Submit a `respond` extrinsic (SignatureResponded) to the Signet pallet using Subxt.
    /// Accepts a `cait_sith::FullSignature<Secp256k1>` and a `recovery_id`.
    /// Skips/returns error if `HYDRATION_SIGNER_URI` is not set on the handle.
    pub async fn submit_respond(
        &self,
        request_id: [u8; 32],
        signature: cait_sith::FullSignature<k256::Secp256k1>,
        recovery_id: u8,
    ) -> anyhow::Result<()> {
        use parity_scale_codec::Encode;
        use std::str::FromStr;
        use subxt::tx::Payload;
        use subxt::OnlineClient;
        use subxt::config::substrate::SubstrateConfig;
        use subxt_signer::{sr25519, SecretUri};

        let signer_uri = match &self.signer_uri {
            Some(s) if !s.is_empty() => s.clone(),
            _ => anyhow::bail!("HYDRATION_SIGNER_URI is not set; cannot submit extrinsic"),
        };

        // Mirror on-chain HydrationRespondTx: (Vec<[u8;32]>, Vec<HydrationSignature>)
        struct HydrationRespondTx {
            request_ids: Vec<[u8; 32]>,
            signatures: Vec<( [u8;32], [u8;32], [u8;32], u8 )>, // (big_r.x, big_r.y, s, recovery_id)
        }

        impl Payload for HydrationRespondTx {
            fn encode_call_data_to(
                &self,
                metadata: &subxt::Metadata,
                out: &mut Vec<u8>,
            ) -> std::result::Result<(), subxt::ext::subxt_core::Error> {
                let pallet = metadata
                    .pallet_by_name("Signet")
                    .ok_or_else(|| subxt::ext::subxt_core::Error::Metadata(subxt::error::MetadataError::PalletNameNotFound("Signet".to_string())))?;
                let pallet_index: u8 = pallet.index();
                let call_index = pallet
                    .call_variant_by_name("respond")
                    .ok_or_else(|| subxt::ext::subxt_core::Error::Metadata(subxt::error::MetadataError::CallNameNotFound("respond".to_string())))?
                    .index;

                out.push(pallet_index);
                out.push(call_index);

                // encode as (BoundedVec<[u8;32]>, BoundedVec<HydrationSignature>)
                (&self.request_ids, &self.signatures).encode_to(out);
                Ok(())
            }
        }

        // Prepare payload pieces from FullSignature
        let enc = signature.big_r.to_encoded_point(false);
        let x = enc
            .x()
            .ok_or_else(|| anyhow::anyhow!("missing x"))?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("x must be 32 bytes"))?;
        let y = enc
            .y()
            .ok_or_else(|| anyhow::anyhow!("missing y"))?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("y must be 32 bytes"))?;
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(signature.s.to_bytes().as_slice());

        let tx = HydrationRespondTx {
            request_ids: vec![request_id],
            signatures: vec![(x, y, s_bytes, recovery_id)],
        };

        let api = OnlineClient::<SubstrateConfig>::from_url(&self.rpc_ws_url).await?;
        let uri = SecretUri::from_str(&signer_uri)?;
        let signer = sr25519::Keypair::from_uri(&uri)?;

        let progress = api.tx().sign_and_submit_then_watch_default(&tx, &signer).await?;
        progress.wait_for_finalized_success().await?;
        Ok(())
    }
    /// Submit a `sign` extrinsic to the Signet pallet using Subxt.
    ///
    /// Requires `HYDRATION_SIGNER_URI` to be set in the environment (or the
    /// `HydrationHandle` must contain a `signer_uri`). Returns an error when
    /// the signer is not available or the extrinsic fails.
    pub async fn submit_sign_request(
        &self,
        payload: [u8; 32],
        path: &str,
    ) -> anyhow::Result<()> {
        use parity_scale_codec::Encode;
        use std::str::FromStr;
        use subxt::tx::Payload;
        use subxt::OnlineClient;
        use subxt::config::substrate::SubstrateConfig;
        use subxt_signer::{sr25519, SecretUri};

        // Must have a signer URI to submit transactions.
        let signer_uri = match &self.signer_uri {
            Some(s) if !s.is_empty() => s.clone(),
            _ => anyhow::bail!("HYDRATION_SIGNER_URI is not set; cannot submit extrinsic"),
        };

        // Simple payload type that encodes the call to Signet::sign
        struct HydrationSignTx {
            payload: [u8; 32],
            key_version: u32,
            path: String,
            algo: String,
            dest: String,
            params: String,
        }

        impl Payload for HydrationSignTx {
            fn encode_call_data_to(
                &self,
                metadata: &subxt::Metadata,
                out: &mut Vec<u8>,
            ) -> std::result::Result<(), subxt::ext::subxt_core::Error> {
                let pallet = metadata
                    .pallet_by_name("Signet")
                    .ok_or_else(|| subxt::ext::subxt_core::Error::Metadata(subxt::error::MetadataError::PalletNameNotFound("Signet".to_string())))?;
                let pallet_index: u8 = pallet.index();
                let call_index = pallet
                    .call_variant_by_name("sign")
                    .ok_or_else(|| subxt::ext::subxt_core::Error::Metadata(subxt::error::MetadataError::CallNameNotFound("sign".to_string())))?
                    .index;

                out.push(pallet_index);
                out.push(call_index);

                // Encode arguments: (payload, key_version, path, algo, dest, params)
                (&self.payload, &self.key_version, &self.path, &self.algo, &self.dest, &self.params)
                    .encode_to(out);
                Ok(())
            }
        }

        // connect and submit
        let api = OnlineClient::<SubstrateConfig>::from_url(&self.rpc_ws_url).await?;
        let uri = SecretUri::from_str(&signer_uri)?;
        let signer = sr25519::Keypair::from_uri(&uri)?;

        let tx = HydrationSignTx {
            payload,
            key_version: 0,
            path: path.to_string(),
            algo: "secp256k1".to_string(),
            dest: "".to_string(),
            params: "".to_string(),
        };

        let progress = api.tx().sign_and_submit_then_watch_default(&tx, &signer).await?;
        progress.wait_for_finalized_success().await?;
        Ok(())
    }

    /// Submit a `sign_bidirectional` extrinsic to the Signet pallet using Subxt.
    ///
    /// The argument list mirrors the Signet pallet's `sign_bidirectional` call.
    pub async fn submit_sign_bidirectional_request(
        &self,
        serialized_transaction: Vec<u8>,
        caip2_id: &str,
        key_version: u32,
        path: &str,
        algo: &str,
        dest: &str,
        params: &str,
        callback_program_id: [u8; 32],
        output_deserialization_schema: Vec<u8>,
        respond_serialization_schema: Vec<u8>,
    ) -> anyhow::Result<()> {
        use parity_scale_codec::Encode;
        use std::str::FromStr;
        use subxt::tx::Payload;
        use subxt::OnlineClient;
        use subxt::config::substrate::SubstrateConfig;
        use subxt_signer::{sr25519, SecretUri};

        let signer_uri = match &self.signer_uri {
            Some(s) if !s.is_empty() => s.clone(),
            _ => anyhow::bail!("HYDRATION_SIGNER_URI is not set; cannot submit extrinsic"),
        };

        struct HydrationSignBidirectionalTx {
            serialized_transaction: Vec<u8>,
            caip2_id: String,
            key_version: u32,
            path: String,
            algo: String,
            dest: String,
            params: String,
            program_id: [u8; 32],
            output_deserialization_schema: Vec<u8>,
            respond_serialization_schema: Vec<u8>,
        }

        impl Payload for HydrationSignBidirectionalTx {
            fn encode_call_data_to(
                &self,
                metadata: &subxt::Metadata,
                out: &mut Vec<u8>,
            ) -> std::result::Result<(), subxt::ext::subxt_core::Error> {
                let pallet = metadata
                    .pallet_by_name("Signet")
                    .ok_or_else(|| subxt::ext::subxt_core::Error::Metadata(subxt::error::MetadataError::PalletNameNotFound("Signet".to_string())))?;
                let pallet_index: u8 = pallet.index();
                let call_index = pallet
                    .call_variant_by_name("sign_bidirectional")
                    .ok_or_else(|| subxt::ext::subxt_core::Error::Metadata(subxt::error::MetadataError::CallNameNotFound("sign_bidirectional".to_string())))?
                    .index;

                out.push(pallet_index);
                out.push(call_index);

                (&self.serialized_transaction,
                 &self.caip2_id,
                 &self.key_version,
                 &self.path,
                 &self.algo,
                 &self.dest,
                 &self.params,
                 &self.program_id,
                 &self.output_deserialization_schema,
                 &self.respond_serialization_schema)
                    .encode_to(out);
                Ok(())
            }
        }

        let api = OnlineClient::<SubstrateConfig>::from_url(&self.rpc_ws_url).await?;
        let uri = SecretUri::from_str(&signer_uri)?;
        let signer = sr25519::Keypair::from_uri(&uri)?;

        let tx = HydrationSignBidirectionalTx {
            serialized_transaction,
            caip2_id: caip2_id.to_string(),
            key_version,
            path: path.to_string(),
            algo: algo.to_string(),
            dest: dest.to_string(),
            params: params.to_string(),
            program_id: callback_program_id,
            output_deserialization_schema,
            respond_serialization_schema,
        };

        let progress = api.tx().sign_and_submit_then_watch_default(&tx, &signer).await?;
        progress.wait_for_finalized_success().await?;
        Ok(())
    }
}
