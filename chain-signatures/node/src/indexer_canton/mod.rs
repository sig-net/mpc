mod auth;
pub mod contracts;
pub mod ledger_api;
mod request_id;
mod signature;
mod stream;

pub use auth::{CantonAuthConfig, CantonAuthProvider};
pub use request_id::compute_request_id;
pub use signature::der_encode_signature;
pub use stream::{parse_canton_signature, CantonStream};

use crate::protocol::Chain;
use crate::sign_bidirectional::hash_rlp_data;
use alloy::consensus::{SignableTransaction, TxEip1559};
use borsh::{BorshDeserialize, BorshSerialize};
use k256::Scalar;
use mpc_primitives::{ScalarExt, SignArgs, SignBidirectionalEvent, SignId, LATEST_MPC_KEY_VERSION};
use std::fmt;

use contracts::TxParams as CantonTxParams;

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

    pub fn generate_sign_request(
        &self,
        entropy: [u8; 32],
    ) -> anyhow::Result<crate::protocol::IndexedSignRequest> {
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

        let unsigned_tx_hash = hash_rlp_data(&self.serialized_transaction);

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

        Ok(crate::protocol::IndexedSignRequest::sign_bidirectional(
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

/// Canton JSON Ledger API configuration.
#[derive(Clone)]
pub struct CantonConfig {
    pub json_api_url: String,
    pub json_api_ws_url: String,
    pub auth: CantonAuthConfig,
    pub ledger_api_user: String,
    pub party_id: String,
    /// The Signer contract ID on the Canton ledger. Changes on every DAR
    /// redeployment — requires MPC node restart with the new value.
    pub signer_contract_id: String,
    /// Template ID of the Signer contract, in package-name form
    /// (`#signet-signer-v1:Signer:Signer`) — stable across DAR upgrades.
    pub signer_template_id: String,
}

impl fmt::Debug for CantonConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CantonConfig")
            .field("json_api_url", &self.json_api_url)
            .field("json_api_ws_url", &self.json_api_ws_url)
            .field("auth", &self.auth.kind())
            .field("ledger_api_user", &self.ledger_api_user)
            .field("party_id", &self.party_id)
            .field("signer_contract_id", &self.signer_contract_id)
            .field("signer_template_id", &self.signer_template_id)
            .finish()
    }
}

/// CLI arguments for the Canton indexer.
#[derive(Debug, Clone, clap::Parser)]
#[group(id = "indexer_canton_options")]
pub struct CantonArgs {
    #[arg(
        long,
        env("MPC_CANTON_JSON_API_URL"),
        requires_all = [
            "canton_json_api_ws_url",
            "canton_ledger_api_user",
            "canton_oidc_token_url",
            "canton_oidc_client_id",
            "canton_oidc_client_secret",
            "canton_oidc_audience",
            "canton_party_id",
            "canton_signer_contract_id",
            "canton_signer_template_id",
        ]
    )]
    pub canton_json_api_url: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_JSON_API_WS_URL"),
        requires = "canton_json_api_url"
    )]
    pub canton_json_api_ws_url: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_LEDGER_API_USER"),
        requires = "canton_json_api_url"
    )]
    pub canton_ledger_api_user: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_OIDC_TOKEN_URL"),
        requires = "canton_json_api_url"
    )]
    pub canton_oidc_token_url: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_OIDC_CLIENT_ID"),
        requires = "canton_json_api_url"
    )]
    pub canton_oidc_client_id: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_OIDC_CLIENT_SECRET"),
        requires = "canton_json_api_url"
    )]
    pub canton_oidc_client_secret: Option<String>,
    #[arg(
        long,
        env("MPC_CANTON_OIDC_AUDIENCE"),
        requires = "canton_json_api_url"
    )]
    pub canton_oidc_audience: Option<String>,
    #[arg(long, env("MPC_CANTON_OIDC_SCOPE"), requires = "canton_json_api_url")]
    pub canton_oidc_scope: Option<String>,
    #[arg(long, env("MPC_CANTON_PARTY_ID"), requires = "canton_json_api_url")]
    pub canton_party_id: Option<String>,
    /// The Signer contract ID on the Canton ledger. Must be updated if the contract is re-deployed.
    #[arg(
        long,
        env("MPC_CANTON_SIGNER_CONTRACT_ID"),
        requires = "canton_json_api_url"
    )]
    pub canton_signer_contract_id: Option<String>,
    /// Template ID of the Signer contract, in package-name form
    /// (`#signet-signer-v1:Signer:Signer`).
    #[arg(
        long,
        env("MPC_CANTON_SIGNER_TEMPLATE_ID"),
        requires = "canton_json_api_url"
    )]
    pub canton_signer_template_id: Option<String>,
}

impl CantonArgs {
    pub fn into_str_args(self) -> Vec<String> {
        let mut args = Vec::with_capacity(16);
        if let Some(v) = self.canton_json_api_url {
            args.extend(["--canton-json-api-url".to_string(), v]);
        }
        if let Some(v) = self.canton_json_api_ws_url {
            args.extend(["--canton-json-api-ws-url".to_string(), v]);
        }
        if let Some(v) = self.canton_ledger_api_user {
            args.extend(["--canton-ledger-api-user".to_string(), v]);
        }
        if let Some(v) = self.canton_oidc_token_url {
            args.extend(["--canton-oidc-token-url".to_string(), v]);
        }
        if let Some(v) = self.canton_oidc_client_id {
            args.extend(["--canton-oidc-client-id".to_string(), v]);
        }
        if let Some(v) = self.canton_oidc_client_secret {
            args.extend(["--canton-oidc-client-secret".to_string(), v]);
        }
        if let Some(v) = self.canton_oidc_audience {
            args.extend(["--canton-oidc-audience".to_string(), v]);
        }
        if let Some(v) = self.canton_oidc_scope {
            args.extend(["--canton-oidc-scope".to_string(), v]);
        }
        if let Some(v) = self.canton_party_id {
            args.extend(["--canton-party-id".to_string(), v]);
        }
        if let Some(v) = self.canton_signer_contract_id {
            args.extend(["--canton-signer-contract-id".to_string(), v]);
        }
        if let Some(v) = self.canton_signer_template_id {
            args.extend(["--canton-signer-template-id".to_string(), v]);
        }
        args
    }

    pub fn into_config(self) -> Option<CantonConfig> {
        let auth = CantonAuthConfig {
            token_url: self.canton_oidc_token_url?,
            client_id: self.canton_oidc_client_id?,
            client_secret: self.canton_oidc_client_secret?,
            audience: self.canton_oidc_audience?,
            scope: self.canton_oidc_scope,
        };
        Some(CantonConfig {
            json_api_url: self.canton_json_api_url?,
            json_api_ws_url: self.canton_json_api_ws_url?,
            auth,
            ledger_api_user: self.canton_ledger_api_user?,
            party_id: self.canton_party_id?,
            signer_contract_id: self.canton_signer_contract_id?,
            signer_template_id: self.canton_signer_template_id?,
        })
    }

    pub fn from_config(config: Option<CantonConfig>) -> Self {
        match config {
            Some(c) => {
                let CantonAuthConfig {
                    token_url,
                    client_id,
                    client_secret,
                    audience,
                    scope,
                } = c.auth;
                CantonArgs {
                    canton_json_api_url: Some(c.json_api_url),
                    canton_json_api_ws_url: Some(c.json_api_ws_url),
                    canton_ledger_api_user: Some(c.ledger_api_user),
                    canton_oidc_token_url: Some(token_url),
                    canton_oidc_client_id: Some(client_id),
                    canton_oidc_client_secret: Some(client_secret),
                    canton_oidc_audience: Some(audience),
                    canton_oidc_scope: scope,
                    canton_party_id: Some(c.party_id),

                    canton_signer_contract_id: Some(c.signer_contract_id),
                    canton_signer_template_id: Some(c.signer_template_id),
                }
            }
            None => CantonArgs {
                canton_json_api_url: None,
                canton_json_api_ws_url: None,
                canton_ledger_api_user: None,
                canton_oidc_token_url: None,
                canton_oidc_client_id: None,
                canton_oidc_client_secret: None,
                canton_oidc_audience: None,
                canton_oidc_scope: None,
                canton_party_id: None,

                canton_signer_contract_id: None,
                canton_signer_template_id: None,
            },
        }
    }
}
