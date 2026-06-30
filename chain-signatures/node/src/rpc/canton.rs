use crate::indexer_canton::{
    contracts::{CantonSignature, EcdsaSigData},
    der_encode_signature,
    ledger_api::{
        ActiveContractEntry, CumulativeFilter, EventFormat, GetActiveContractsRequest,
        IdentifierFilter, JsCommands, LedgerEndResponse, PartyFilter,
        SubmitAndWaitForTransactionRequest, SubmitAndWaitForTransactionResponse,
        TemplateFilterValue,
    },
    CantonAuthProvider, CantonChainCtx, CantonConfig,
};
use mpc_chain_integration_core::{ChainPublisher, PublishAction, PublisherTelemetry};
use mpc_primitives::{Chain, SignKind};
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct CantonClient {
    pub(crate) config: CantonConfig,
    http_client: reqwest::Client,
    auth_provider: CantonAuthProvider,
    telemetry: Arc<dyn PublisherTelemetry>,
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
    pub async fn new(
        config: &CantonConfig,
        telemetry: Arc<dyn PublisherTelemetry>,
    ) -> anyhow::Result<Self> {
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
            telemetry,
        })
    }

    // TODO: this method is only used in integration tests, cosider hiding it behind a feature flag or get api user from config directly
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

    // TODO: this method is only used in integration tests, cosider hiding it behind a feature flag
    async fn auth_get(&self, path: &str) -> anyhow::Result<reqwest::RequestBuilder> {
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

    // TODO: this method is only used in integration tests, cosider hiding it behind a feature flag
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

    // TODO: this method is only used in integration tests, cosider hiding it behind a feature flag
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

    async fn exercise_choice(
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

#[async_trait::async_trait]
impl ChainPublisher for CantonClient {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let sign_id = action.indexed.id;
        let request_id_hex = hex::encode(action.indexed.id.request_id);
        let timestamp = action.timestamp;
        let signature = &action.signature;

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
            _ => anyhow::bail!(
                "Canton supports only Canton SignBidirectional or RespondBidirectional"
            ),
        };

        self.exercise_choice(&command_id, choice, choice_argument)
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

        self.telemetry.record_publish_metrics(action);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer_canton::{CantonAuthConfig, CantonChainCtx};
    use crate::rpc::test_utils::make_publish_action;
    use mockito::{Matcher, Server, ServerGuard};
    use mpc_chain_integration_core::NoopPublisherTelemetry;
    use mpc_primitives::{Chain, RespondBidirectionalTx, SignBidirectionalEvent, SignKind};
    use serde_json::json;

    fn mock_canton_config(url: &str) -> CantonConfig {
        CantonConfig {
            json_api_url: url.to_string(),
            json_api_ws_url: url.replace("http", "ws"),
            auth: CantonAuthConfig {
                token_url: format!("{url}/token"),
                client_id: "test-client".to_string(),
                client_secret: "test-secret".to_string(),
                audience: "test-audience".to_string(),
                scope: None,
            },
            ledger_api_user: "test-user".to_string(),
            party_id: "test-party".to_string(),
            signer_contract_id: "test-contract-id".to_string(),
            signer_template_id: "test-template-id".to_string(),
        }
    }

    async fn setup_mock_server_with_auth() -> ServerGuard {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({"access_token": "mock-token", "token_type": "Bearer", "expires_in": 3600})
                    .to_string(),
            )
            .expect_at_least(0)
            .create_async()
            .await;
        server
    }

    #[tokio::test]
    async fn test_publish_canton_sign_bidirectional_success() {
        let mut server = setup_mock_server_with_auth().await;
        let submit_mock = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
            .match_body(Matcher::Regex("Respond".to_string())) // Robust matcher
            .with_status(200)
            .with_body(json!({"transaction": {"offset": 1, "events": []}}).to_string())
            .expect(1)
            .create_async()
            .await;

        let client = CantonClient::new(
            &mock_canton_config(&server.url()),
            Arc::new(NoopPublisherTelemetry),
        )
        .await
        .unwrap();
        let chain_ctx = borsh::to_vec(&CantonChainCtx {
            sign_event_contract_id: "cid".to_string(),
        })
        .unwrap();

        let event = SignBidirectionalEvent {
            sender: [0; 32],
            serialized_transaction: vec![],
            caip2_id: "canton:global".to_string(),
            key_version: 1,
            deposit: 0,
            path: "".to_string(),
            algo: "".to_string(),
            dest: "".to_string(),
            params: "".to_string(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            chain: Chain::Canton,
            chain_ctx: Some(chain_ctx),
        };

        let action = make_publish_action(Chain::Canton, SignKind::SignBidirectional(event));
        assert!(client.publish_signature(&action).await.is_ok());
        submit_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_publish_canton_respond_bidirectional_success() {
        let mut server = setup_mock_server_with_auth().await;
        let submit_mock = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
            .match_body(Matcher::Regex("RespondBidirectional".to_string())) // Robust matcher
            .with_status(200)
            .with_body(json!({"transaction": {"offset": 1, "events": []}}).to_string())
            .expect(1)
            .create_async()
            .await;

        let client = CantonClient::new(
            &mock_canton_config(&server.url()),
            Arc::new(NoopPublisherTelemetry),
        )
        .await
        .unwrap();
        let chain_ctx = borsh::to_vec(&CantonChainCtx {
            sign_event_contract_id: "cid".to_string(),
        })
        .unwrap();

        let tx = RespondBidirectionalTx {
            tx_id: mpc_primitives::BidirectionalTxId([0; 32]),
            output: vec![1, 2, 3],
            chain_ctx: Some(chain_ctx),
        };

        let action = make_publish_action(Chain::Canton, SignKind::RespondBidirectional(tx));
        assert!(client.publish_signature(&action).await.is_ok());
        submit_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_publish_canton_missing_chain_ctx_fails() {
        let server = setup_mock_server_with_auth().await;
        let client = CantonClient::new(
            &mock_canton_config(&server.url()),
            Arc::new(NoopPublisherTelemetry),
        )
        .await
        .unwrap();

        let tx = RespondBidirectionalTx {
            tx_id: mpc_primitives::BidirectionalTxId([0; 32]),
            output: vec![],
            chain_ctx: None, // Missing
        };

        let action = make_publish_action(Chain::Canton, SignKind::RespondBidirectional(tx));
        let err = client.publish_signature(&action).await.unwrap_err();
        assert!(err.to_string().contains("missing chain_ctx"));
    }

    #[tokio::test]
    async fn test_publish_canton_api_error() {
        let mut server = setup_mock_server_with_auth().await;
        let submit_mock = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
            .with_status(500)
            .with_body("Internal Server Error")
            .expect(1)
            .create_async()
            .await;

        let client = CantonClient::new(
            &mock_canton_config(&server.url()),
            Arc::new(NoopPublisherTelemetry),
        )
        .await
        .unwrap();
        let chain_ctx = borsh::to_vec(&CantonChainCtx {
            sign_event_contract_id: "cid".to_string(),
        })
        .unwrap();
        let tx = RespondBidirectionalTx {
            tx_id: mpc_primitives::BidirectionalTxId([0; 32]),
            output: vec![],
            chain_ctx: Some(chain_ctx),
        };
        let action = make_publish_action(Chain::Canton, SignKind::RespondBidirectional(tx));

        let err = client.publish_signature(&action).await.unwrap_err();
        assert!(err.to_string().contains("500"));
        submit_mock.assert_async().await;
    }
}
