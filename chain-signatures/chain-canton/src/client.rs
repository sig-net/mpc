use crate::{
    auth::CantonAuthProvider,
    config::CantonConfig,
    daml::{CantonSignature, EcdsaSigData},
    ledger_api::{
        ActiveContractEntry, Command, CumulativeFilter, EventFormat, GetActiveContractsRequest,
        IdentifierFilter, JsCantonError, JsCommands, LedgerEndResponse, PartyFilter,
        SubmitAndWaitForTransactionRequest, SubmitAndWaitForTransactionResponse,
        TemplateFilterValue,
    },
    signing::der_encode_signature,
    CantonChainCtx,
};
use mpc_chain_integration_core::utils::retry::{retry_rpc, RetryConfig};
use mpc_chain_integration_core::{ChainPublisher, PublishAction, PublisherTelemetry};
use mpc_primitives::{Chain, SignKind};
use std::{sync::Arc, time::Duration};

// Constants for Canton JSON Ledger API RPC retry behavior.
const CANTON_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const CANTON_RPC_MIN_DELAY: Duration = Duration::from_millis(500);
const CANTON_RPC_MAX_DELAY: Duration = Duration::from_secs(10);
const CANTON_RPC_MAX_RETRIES: usize = 5;

enum SubmissionOutcome {
    Transaction(SubmitAndWaitForTransactionResponse),
    AlreadyAccepted,
}

/// Default retry strategy for Canton JSON Ledger API RPC calls.
fn default_canton_rpc_retry_strategy() -> RetryConfig {
    RetryConfig {
        min_delay: CANTON_RPC_MIN_DELAY,
        max_delay: CANTON_RPC_MAX_DELAY,
        max_times: CANTON_RPC_MAX_RETRIES,
        jitter: true,
    }
}

#[derive(Clone)]
pub struct CantonClient {
    pub(crate) config: CantonConfig,
    http_client: reqwest::Client,
    auth_provider: CantonAuthProvider,
    telemetry: Arc<dyn PublisherTelemetry>,
    retry_strategy: RetryConfig,
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

        Ok(Self::new_with_strategy(
            config,
            telemetry,
            default_canton_rpc_retry_strategy(),
            http_client,
            auth_provider,
        ))
    }

    /// Sets a custom retry strategy. Used in tests to swap in a fast retry policy.
    #[cfg(test)]
    pub(crate) fn with_retry_strategy(mut self, retry_strategy: RetryConfig) -> Self {
        self.retry_strategy = retry_strategy;
        self
    }

    /// Creates a new Canton client with an explicit retry strategy for the JSON
    /// Ledger API RPC calls.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_strategy(
        config: &CantonConfig,
        telemetry: Arc<dyn PublisherTelemetry>,
        retry_strategy: RetryConfig,
        http_client: reqwest::Client,
        auth_provider: CantonAuthProvider,
    ) -> Self {
        Self {
            config: config.clone(),
            http_client,
            auth_provider,
            telemetry,
            retry_strategy,
        }
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
        retry_rpc!(
            CANTON_RPC_TIMEOUT,
            self.retry_strategy,
            "fetch_ledger_end",
            {
                let resp = self.auth_get("/v2/state/ledger-end").await?.send().await?;
                let resp = check_response(resp, "ledger-end").await?;
                let body: LedgerEndResponse = resp.json().await?;
                Ok(body.offset)
            }
        )
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

        retry_rpc!(
            CANTON_RPC_TIMEOUT,
            self.retry_strategy,
            "fetch_active_contracts",
            {
                let resp = self
                    .auth_post("/v2/state/active-contracts")
                    .await?
                    .json(&req)
                    .send()
                    .await?;
                let resp = check_response(resp, "active-contracts query").await?;
                Ok::<Vec<ActiveContractEntry>, anyhow::Error>(resp.json().await?)
            }
        )
    }

    // TODO: this method is only used in integration tests, cosider hiding it behind a feature flag
    pub async fn submit_and_wait(
        &self,
        commands: JsCommands,
        context: &str,
    ) -> anyhow::Result<SubmitAndWaitForTransactionResponse> {
        match self.submit_and_wait_outcome(commands, context).await? {
            SubmissionOutcome::Transaction(transaction) => Ok(transaction),
            SubmissionOutcome::AlreadyAccepted => {
                anyhow::bail!("{context} already accepted; transaction response unavailable")
            }
        }
    }

    async fn submit_and_wait_outcome(
        &self,
        commands: JsCommands,
        context: &str,
    ) -> anyhow::Result<SubmissionOutcome> {
        let max_attempts = self.retry_strategy.max_times;
        retry_rpc!(
            CANTON_RPC_TIMEOUT,
            self.retry_strategy,
            |attempt, err, sleep| {
                tracing::warn!(
                    context,
                    attempt,
                    max_attempts,
                    error = %err,
                    retry_in = ?sleep,
                    "canton submit_and_wait failed, retrying"
                );
            },
            {
                let resp = self
                    .auth_post("/v2/commands/submit-and-wait-for-transaction")
                    .await?
                    .json(&SubmitAndWaitForTransactionRequest {
                        commands: commands.clone(),
                    })
                    .send()
                    .await?;
                let status = resp.status();
                if !status.is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    if status == reqwest::StatusCode::CONFLICT
                        && serde_json::from_str::<JsCantonError>(&body)
                            .is_ok_and(|error| error.code == "DUPLICATE_COMMAND")
                    {
                        // Acceptance ends submission retries; verified ledger events still settle the request.
                        return Ok(SubmissionOutcome::AlreadyAccepted);
                    }
                    anyhow::bail!("{context} failed: {status} {body}");
                }
                Ok(SubmissionOutcome::Transaction(resp.json().await?))
            }
        )
    }

    async fn exercise_choice(
        &self,
        command_id: &str,
        choice: &str,
        choice_argument: serde_json::Value,
    ) -> anyhow::Result<SubmissionOutcome> {
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
        self.submit_and_wait_outcome(commands, &format!("canton {choice}"))
            .await
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
        let sign_id = action.request.id;
        let request_id_hex = hex::encode(action.request.id.request_id);
        let timestamp = action.timestamp;
        let signature = &action.signature;

        tracing::info!(
            ?sign_id,
            chain = ?action.request.chain,
            elapsed = ?timestamp.elapsed(),
            request_id = %request_id_hex,
            "canton: publishing signature"
        );

        let der_sig = hex::encode(der_encode_signature(signature)?);
        let canton_signature = serde_json::to_value(CantonSignature::EcdsaSig(EcdsaSigData {
            der: der_sig,
            recovery_id: signature.recovery_id,
        }))?;

        let (choice, command_id, choice_argument) = match &action.request.kind {
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

        let outcome = self
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

        match outcome {
            SubmissionOutcome::Transaction(_) => {
                tracing::info!(
                    ?sign_id,
                    choice,
                    elapsed = ?timestamp.elapsed(),
                    "published canton {choice} successfully"
                );
                self.telemetry.record_publish_metrics(action);
            }
            SubmissionOutcome::AlreadyAccepted => {
                tracing::info!(
                    ?sign_id,
                    choice,
                    "canton {choice} already accepted; stopped submission retries"
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CantonAuthConfig, CantonConfig};
    use mockito::{Matcher, Server, ServerGuard};
    use mpc_chain_integration_core::{utils::test::make_publish_action, NoopPublisherTelemetry};
    use mpc_primitives::{Chain, RespondBidirectionalTx, SignBidirectionalEvent, SignId, SignKind};
    use serde_json::json;

    /// Fast retry strategy for testing
    fn fast_retry_strategy() -> RetryConfig {
        RetryConfig {
            min_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            max_times: 2,
            jitter: false,
        }
    }

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

    const DUPLICATE_COMMAND: &str = include_str!("testdata/duplicate_command.json");

    #[derive(Default)]
    struct PublishCounter(std::sync::atomic::AtomicUsize);

    impl PublisherTelemetry for PublishCounter {
        fn record_publish_metrics(&self, _action: &PublishAction) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn final_response_action() -> PublishAction {
        make_publish_action(
            Chain::Canton,
            SignKind::RespondBidirectional(RespondBidirectionalTx {
                tx_id: mpc_primitives::BidirectionalTxId([0; 32]),
                output: vec![1, 2, 3],
                chain_ctx: Some(
                    borsh::to_vec(&CantonChainCtx {
                        sign_event_contract_id: "cid".to_string(),
                    })
                    .unwrap(),
                ),
            }),
            SignId::new([0; 32]),
        )
    }

    fn initial_response_action() -> PublishAction {
        make_publish_action(
            Chain::Canton,
            SignKind::SignBidirectional(SignBidirectionalEvent {
                sender: [0; 32],
                serialized_transaction: vec![],
                caip2_id: "canton:global".to_string(),
                key_version: 1,
                deposit: 0,
                path: String::new(),
                algo: String::new(),
                dest: String::new(),
                params: String::new(),
                output_deserialization_schema: vec![],
                respond_serialization_schema: vec![],
                chain: Chain::Canton,
                chain_ctx: Some(
                    borsh::to_vec(&CantonChainCtx {
                        sign_event_contract_id: "cid".to_string(),
                    })
                    .unwrap(),
                ),
            }),
            SignId::new([0; 32]),
        )
    }

    #[tokio::test]
    async fn test_publish_canton_duplicate_command_stops_retrying() {
        for (action, prefix, choice) in [
            (initial_response_action(), "mpc-respond-", "Respond"),
            (
                final_response_action(),
                "mpc-respond-bidir-",
                "RespondBidirectional",
            ),
        ] {
            let mut server = setup_mock_server_with_auth().await;
            let duplicate = server
                .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
                .match_body(Matcher::PartialJson(json!({"commands": {
                    "commandId": format!("{prefix}{}", hex::encode(action.request.id.request_id)),
                    "userId": "test-user",
                    "actAs": ["test-party"],
                    "commands": [{"ExerciseCommand": {"choice": choice}}],
                }})))
                .with_status(409)
                .with_body(DUPLICATE_COMMAND)
                .expect(1)
                .create_async()
                .await;
            let telemetry = Arc::new(PublishCounter::default());
            let client = CantonClient::new(&mock_canton_config(&server.url()), telemetry.clone())
                .await
                .unwrap()
                .with_retry_strategy(fast_retry_strategy());

            let result = client.publish_signature(&action).await;

            assert!(result.is_ok(), "already accepted command: {result:?}");
            duplicate.assert_async().await;
            assert_eq!(telemetry.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn test_publish_canton_timeout_then_duplicate_stops_both_retry_layers() {
        let mut server = setup_mock_server_with_auth().await;
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let first_requests = requests.clone();
        let retry_requests = requests.clone();
        let (release, held_response) = std::sync::mpsc::channel::<()>();
        let held_response = std::sync::Mutex::new(held_response);
        let timeout = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
            .match_request(move |request| {
                first_requests
                    .lock()
                    .unwrap()
                    .push(request.body().unwrap().to_vec());
                true
            })
            .with_status(200)
            .with_chunked_body(move |writer| {
                // Outlast the RPC deadline; mockito joins this writer when the client disconnects.
                let _ = held_response
                    .lock()
                    .unwrap()
                    .recv_timeout(CANTON_RPC_TIMEOUT + Duration::from_secs(1));
                writer.write_all(br#"{"transaction":{"offset":1,"events":[]}}"#)
            })
            .expect(1)
            .create_async()
            .await;
        let duplicate = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
            .match_request(move |request| {
                retry_requests
                    .lock()
                    .unwrap()
                    .push(request.body().unwrap().to_vec());
                true
            })
            .with_status(409)
            .with_body(DUPLICATE_COMMAND)
            .expect(1)
            .create_async()
            .await;
        let archived = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
            .with_status(404)
            .with_body(r#"{"code":"CONTRACT_NOT_FOUND"}"#)
            .expect(0)
            .create_async()
            .await;
        let telemetry = Arc::new(PublishCounter::default());
        let client = CantonClient::new(&mock_canton_config(&server.url()), telemetry.clone())
            .await
            .unwrap()
            .with_retry_strategy(fast_retry_strategy());
        let action = final_response_action();

        let result = retry_rpc!(Duration::MAX, fast_retry_strategy(), "publish", {
            client.publish_signature(&action).await
        });
        drop(release);

        assert!(result.is_ok(), "accepted retry: {result:?}");
        timeout.assert_async().await;
        duplicate.assert_async().await;
        archived.assert_async().await;
        let requests = requests.lock().unwrap();
        assert!(requests.len() >= 2);
        assert!(requests.iter().all(|request| request == &requests[0]));
        assert_eq!(telemetry.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_publish_canton_does_not_accept_other_errors() {
        for (status, body) in [
            (409, r#"{"code":"SUBMISSION_ALREADY_IN_FLIGHT"}"#),
            (409, r#"{"code":"DUPLICATE_CONTRACT_KEY"}"#),
            (409, r#"{"context":{"accepted":"true"}}"#),
            (409, r#"{"code":"OTHER","cause":"DUPLICATE_COMMAND"}"#),
            (409, "DUPLICATE_COMMAND"),
            (404, DUPLICATE_COMMAND),
            (500, DUPLICATE_COMMAND),
            (200, "{}"),
        ] {
            let mut server = setup_mock_server_with_auth().await;
            let response = server
                .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
                .with_status(status)
                .with_body(body)
                .expect(1)
                .create_async()
                .await;
            let client = CantonClient::new(
                &mock_canton_config(&server.url()),
                Arc::new(NoopPublisherTelemetry),
            )
            .await
            .unwrap()
            .with_retry_strategy(RetryConfig {
                max_times: 0,
                ..fast_retry_strategy()
            });

            assert!(
                client
                    .publish_signature(&final_response_action())
                    .await
                    .is_err(),
                "must not accept status {status}: {body}"
            );
            response.assert_async().await;
        }
    }

    #[tokio::test]
    async fn test_submit_and_wait_duplicate_cannot_fabricate_transaction() {
        let mut server = setup_mock_server_with_auth().await;
        let response = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
            .with_status(409)
            .with_body(DUPLICATE_COMMAND)
            .expect(1)
            .create_async()
            .await;
        let client = CantonClient::new(
            &mock_canton_config(&server.url()),
            Arc::new(NoopPublisherTelemetry),
        )
        .await
        .unwrap()
        .with_retry_strategy(fast_retry_strategy());

        assert!(client
            .submit_and_wait(
                JsCommands {
                    command_id: "command".to_string(),
                    user_id: "test-user".to_string(),
                    act_as: vec!["test-party".to_string()],
                    read_as: vec![],
                    commands: vec![],
                    disclosed_contracts: vec![],
                },
                "command"
            )
            .await
            .is_err());
        response.assert_async().await;
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

        let telemetry = Arc::new(PublishCounter::default());
        let client = CantonClient::new(&mock_canton_config(&server.url()), telemetry.clone())
            .await
            .unwrap()
            .with_retry_strategy(fast_retry_strategy());
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

        let action = make_publish_action(
            Chain::Canton,
            SignKind::SignBidirectional(event),
            SignId::new([0u8; 32]),
        );
        assert!(client.publish_signature(&action).await.is_ok());
        submit_mock.assert_async().await;
        assert_eq!(telemetry.0.load(std::sync::atomic::Ordering::SeqCst), 1);
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
        .unwrap()
        .with_retry_strategy(fast_retry_strategy());
        let chain_ctx = borsh::to_vec(&CantonChainCtx {
            sign_event_contract_id: "cid".to_string(),
        })
        .unwrap();

        let tx = RespondBidirectionalTx {
            tx_id: mpc_primitives::BidirectionalTxId([0; 32]),
            output: vec![1, 2, 3],
            chain_ctx: Some(chain_ctx),
        };

        let action = make_publish_action(
            Chain::Canton,
            SignKind::RespondBidirectional(tx),
            SignId::new([0u8; 32]),
        );
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
        .unwrap()
        .with_retry_strategy(fast_retry_strategy());

        let tx = RespondBidirectionalTx {
            tx_id: mpc_primitives::BidirectionalTxId([0; 32]),
            output: vec![],
            chain_ctx: None, // Missing
        };

        let action = make_publish_action(
            Chain::Canton,
            SignKind::RespondBidirectional(tx),
            SignId::new([0u8; 32]),
        );
        let err = client.publish_signature(&action).await.unwrap_err();
        assert!(err.to_string().contains("missing chain_ctx"));
    }

    #[tokio::test]
    async fn test_publish_canton_api_error() {
        let mut server = setup_mock_server_with_auth().await;
        // Fast retry strategy uses max_times: 2 → 3 total attempts on a persistent 500.
        let submit_mock = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
            .with_status(500)
            .with_body("Internal Server Error")
            .expect(3) // 1 attempt + 2 retries
            .create_async()
            .await;

        let client = CantonClient::new(
            &mock_canton_config(&server.url()),
            Arc::new(NoopPublisherTelemetry),
        )
        .await
        .unwrap()
        .with_retry_strategy(fast_retry_strategy());
        let chain_ctx = borsh::to_vec(&CantonChainCtx {
            sign_event_contract_id: "cid".to_string(),
        })
        .unwrap();
        let tx = RespondBidirectionalTx {
            tx_id: mpc_primitives::BidirectionalTxId([0; 32]),
            output: vec![],
            chain_ctx: Some(chain_ctx),
        };
        let action = make_publish_action(
            Chain::Canton,
            SignKind::RespondBidirectional(tx),
            SignId::new([0u8; 32]),
        );

        let err = client.publish_signature(&action).await.unwrap_err();
        assert!(err.to_string().contains("500"));
        assert!(err.to_string().contains("exhausted"));
        submit_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_publish_canton_retries_on_500_then_succeeds() {
        let mut server = setup_mock_server_with_auth().await;
        // First submit attempt → 500, second → success. The retry_rpc! wrapper
        // should transparently retry the failing call and recover.
        let _fail = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
            .with_status(500)
            .with_body("Internal Server Error")
            .expect(1)
            .create_async()
            .await;
        let ok = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
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
        .unwrap()
        .with_retry_strategy(fast_retry_strategy());
        let chain_ctx = borsh::to_vec(&CantonChainCtx {
            sign_event_contract_id: "cid".to_string(),
        })
        .unwrap();
        let tx = RespondBidirectionalTx {
            tx_id: mpc_primitives::BidirectionalTxId([0; 32]),
            output: vec![],
            chain_ctx: Some(chain_ctx),
        };
        let action = make_publish_action(
            Chain::Canton,
            SignKind::RespondBidirectional(tx),
            SignId::new([0u8; 32]),
        );

        assert!(client.publish_signature(&action).await.is_ok());
        ok.assert_async().await;
    }

    #[tokio::test]
    async fn test_publish_canton_does_not_retry_on_4xx() {
        let mut server = setup_mock_server_with_auth().await;
        // A 4xx client error is terminal — should not be retried.
        let submit_mock = server
            .mock("POST", "/v2/commands/submit-and-wait-for-transaction")
            .with_status(400)
            .with_body("Bad Request")
            .expect(1) // should not retry
            .create_async()
            .await;

        let client = CantonClient::new(
            &mock_canton_config(&server.url()),
            Arc::new(NoopPublisherTelemetry),
        )
        .await
        .unwrap()
        .with_retry_strategy(fast_retry_strategy());
        let chain_ctx = borsh::to_vec(&CantonChainCtx {
            sign_event_contract_id: "cid".to_string(),
        })
        .unwrap();
        let tx = RespondBidirectionalTx {
            tx_id: mpc_primitives::BidirectionalTxId([0; 32]),
            output: vec![],
            chain_ctx: Some(chain_ctx),
        };
        let action = make_publish_action(
            Chain::Canton,
            SignKind::RespondBidirectional(tx),
            SignId::new([0u8; 32]),
        );

        let err = client.publish_signature(&action).await.unwrap_err();
        assert!(err.to_string().contains("400"));
        submit_mock.assert_async().await;
    }
}
