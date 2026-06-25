use super::PublishAction;
use crate::indexer_canton::ledger_api::{
    ActiveContractEntry, CumulativeFilter, EventFormat, GetActiveContractsRequest,
    IdentifierFilter, JsCommands, LedgerEndResponse, PartyFilter,
    SubmitAndWaitForTransactionRequest, SubmitAndWaitForTransactionResponse, TemplateFilterValue,
};
use crate::indexer_canton::{
    contracts::{CantonSignature, EcdsaSigData},
    CantonAuthProvider, CantonConfig,
};
use crate::indexer_canton::{der_encode_signature, CantonChainCtx};
use mpc_primitives::{Chain, SignKind, Signature};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct CantonClient {
    pub(crate) config: CantonConfig,
    http_client: reqwest::Client,
    auth_provider: CantonAuthProvider,
}

impl std::fmt::Debug for CantonClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CantonClient")
            .field("config", &self.config)
            .field("auth_provider", &"<hidden>")
            .finish()
    }
}

impl CantonClient {
    pub async fn new(config: &CantonConfig) -> anyhow::Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;

        let auth_provider = CantonAuthProvider::new(config.auth.clone())?;

        if !config.signer_contract_id.is_empty() || !config.signer_template_id.is_empty() {
            tracing::info!(
                signer_cid = %config.signer_contract_id,
                signer_template_id = %config.signer_template_id,
                "canton Signer contract configured"
            );
        }

        Ok(Self {
            config: config.clone(),
            http_client,
            auth_provider,
        })
    }

    pub fn ledger_api_user(&self) -> &str {
        &self.config.ledger_api_user
    }

    pub async fn bearer_token(&self) -> anyhow::Result<String> {
        self.auth_provider.bearer_token().await
    }

    fn json_api_endpoint(&self, path: &str) -> String {
        format!("{}{}", self.config.json_api_url, path)
    }

    pub async fn auth_post(&self, path: &str) -> anyhow::Result<reqwest::RequestBuilder> {
        let token = self.bearer_token().await?;
        Ok(self
            .http_client
            .post(self.json_api_endpoint(path))
            .bearer_auth(token))
    }

    pub async fn auth_get(&self, path: &str) -> anyhow::Result<reqwest::RequestBuilder> {
        let token = self.bearer_token().await?;
        Ok(self
            .http_client
            .get(self.json_api_endpoint(path))
            .bearer_auth(token))
    }

    pub async fn fetch_ledger_end(&self) -> anyhow::Result<u64> {
        let resp = self.auth_get("/v2/state/ledger-end").await?.send().await?;
        let resp = check_response(resp, "ledger-end").await?;
        let body: LedgerEndResponse = resp.json().await?;
        Ok(body.offset)
    }

    pub async fn fetch_active_contracts(
        &self,
        parties: &[&str],
        template_id: Option<&str>,
        include_blob: bool,
    ) -> anyhow::Result<Vec<ActiveContractEntry>> {
        let offset = self.fetch_ledger_end().await?;

        let mut filters = serde_json::Map::new();
        for party in parties {
            let value = match template_id {
                Some(tid) => serde_json::to_value(PartyFilter {
                    cumulative: vec![CumulativeFilter {
                        identifier_filter: IdentifierFilter::TemplateFilter {
                            value: TemplateFilterValue {
                                template_id: tid.to_string(),
                                include_created_event_blob: include_blob,
                            },
                        },
                    }],
                })?,
                None => serde_json::json!({}),
            };
            filters.insert(party.to_string(), value);
        }

        let req = GetActiveContractsRequest {
            active_at_offset: offset,
            event_format: EventFormat {
                filters_by_party: filters,
                verbose: true,
            },
        };

        let resp = self
            .auth_post("/v2/state/active-contracts")
            .await?
            .json(&req)
            .send()
            .await?;

        let resp = check_response(resp, "active-contracts query").await?;
        Ok(resp.json().await?)
    }

    pub async fn submit_and_wait(
        &self,
        commands: JsCommands,
        context: &str,
    ) -> anyhow::Result<SubmitAndWaitForTransactionResponse> {
        let resp = self
            .auth_post("/v2/commands/submit-and-wait-for-transaction")
            .await?
            .json(&SubmitAndWaitForTransactionRequest { commands })
            .send()
            .await?;
        let resp = check_response(resp, context).await?;
        Ok(resp.json().await?)
    }

    pub async fn exercise_choice(
        &self,
        command_id: &str,
        choice: &str,
        choice_argument: serde_json::Value,
    ) -> anyhow::Result<()> {
        use crate::indexer_canton::ledger_api::{Command, JsCommands};
        let commands = JsCommands {
            command_id: command_id.to_string(),
            user_id: self.config.ledger_api_user.clone(),
            act_as: vec![self.config.party_id.clone()],
            read_as: vec![self.config.party_id.clone()],
            commands: vec![Command::ExerciseCommand {
                template_id: self.config.signer_template_id.clone(),
                contract_id: self.config.signer_contract_id.clone(),
                choice: choice.to_string(),
                choice_argument,
            }],
            disclosed_contracts: vec![],
        };
        self.submit_and_wait(commands, &format!("canton {choice}"))
            .await?;
        Ok(())
    }
}

async fn check_response(
    resp: reqwest::Response,
    context: &str,
) -> anyhow::Result<reqwest::Response> {
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("{context} failed: {status} {text}");
    }
    Ok(resp)
}

pub async fn try_publish_canton(
    canton: &CantonClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> anyhow::Result<()> {
    let sign_id = action.indexed.id;
    let request_id_hex = hex::encode(action.indexed.id.request_id);

    tracing::info!(
        ?sign_id,
        chain = ?action.indexed.chain,
        elapsed = ?timestamp.elapsed(),
        request_id = %request_id_hex,
        "canton: publishing signature"
    );

    let der_sig = hex::encode(der_encode_signature(signature)?);
    let canton_signature = serde_json::to_value(CantonSignature::EcdsaSig(EcdsaSigData {
        der: der_sig,
        recovery_id: signature.recovery_id,
    }))?;
    let (choice, command_id, choice_argument) = match &action.indexed.kind {
        SignKind::SignBidirectional(event) if event.chain == Chain::Canton => {
            let chain_ctx_bytes = event
                .chain_ctx
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing chain_ctx on Canton sign request"))?;
            let ctx: CantonChainCtx = borsh::from_slice(chain_ctx_bytes)
                .map_err(|e| anyhow::anyhow!("failed to deserialize CantonChainCtx: {e}"))?;
            (
                "Respond",
                format!("mpc-respond-{request_id_hex}"),
                serde_json::json!({
                    "signEventCid": ctx.sign_event_contract_id,
                    "requestId": request_id_hex,
                    "signature": canton_signature,
                }),
            )
        }
        SignKind::RespondBidirectional(respond_tx) => {
            let chain_ctx_bytes = respond_tx
                .chain_ctx
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing chain_ctx on Canton response"))?;
            let ctx: CantonChainCtx = borsh::from_slice(chain_ctx_bytes)
                .map_err(|e| anyhow::anyhow!("failed to deserialize CantonChainCtx: {e}"))?;
            (
                "RespondBidirectional",
                format!("mpc-respond-bidir-{request_id_hex}"),
                serde_json::json!({
                    "signEventCid": ctx.sign_event_contract_id,
                    "requestId": request_id_hex,
                    "serializedOutput": hex::encode(&respond_tx.output),
                    "signature": canton_signature,
                }),
            )
        }
        _ => anyhow::bail!("Canton supports only Canton SignBidirectional or RespondBidirectional"),
    };

    canton
        .exercise_choice(&command_id, choice, choice_argument)
        .await
        .inspect_err(|err| {
            tracing::error!(
                ?sign_id,
                choice,
                request_id = %request_id_hex,
                error = %err,
                "canton: failed to publish signature"
            );
        })?;

    tracing::info!(
        ?sign_id,
        choice,
        elapsed = ?timestamp.elapsed(),
        "published canton {choice} successfully"
    );

    Ok(())
}
