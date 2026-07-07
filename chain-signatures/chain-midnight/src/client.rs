//! Midnight `ChainPublisher`: a thin HTTP client to the isolated
//! midnight-publisher service, which owns the toolkit dependency universe and
//! does build → prove → submit for respond circuits. Structurally the Canton
//! client with an HTTP seam instead of the JSON Ledger API.

use crate::config::MidnightConfig;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use mpc_chain_integration_core::{ChainPublisher, PublishAction, PublisherTelemetry};
use mpc_primitives::{Chain, SignKind};
use std::sync::Arc;
use std::time::Duration;

/// Proving `respond_bidirectional` takes ~5–6 minutes (Phase-3 measurement);
/// the request must outlive it.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(900);
/// The contract field is `Bytes<128>`.
const MAX_OUTPUT_LEN: usize = 128;

/// JSON body POSTed to `{publisher_url}/respond`. The midnight-publisher
/// service defines the mirror struct — keep the two in lockstep (both sides
/// pin the same fixture in tests).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MidnightRespondRequest {
    pub contract_address: String,
    pub circuit: String,
    pub request_id: String,
    pub big_r_x: String,
    pub big_r_y: String,
    pub s: String,
    pub recovery_id: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serialized_output: Option<String>,
}

pub struct MidnightClient {
    config: MidnightConfig,
    http: reqwest::Client,
    telemetry: Arc<dyn PublisherTelemetry>,
}

impl MidnightClient {
    pub fn new(config: &MidnightConfig, telemetry: Arc<dyn PublisherTelemetry>) -> Self {
        Self {
            config: config.clone(),
            http: reqwest::Client::builder()
                .timeout(PUBLISH_TIMEOUT)
                .build()
                .expect("reqwest client"),
            telemetry,
        }
    }
}

#[async_trait::async_trait]
impl ChainPublisher for MidnightClient {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        let sign_id = action.request.id;
        let request_id_hex = hex::encode(action.request.id.request_id);

        let (circuit, serialized_output) = match &action.request.kind {
            SignKind::Sign => ("respond", None),
            SignKind::SignBidirectional(event) if event.chain == Chain::Midnight => {
                ("respond", None)
            }
            SignKind::RespondBidirectional(tx) => {
                anyhow::ensure!(
                    tx.output.len() <= MAX_OUTPUT_LEN,
                    "respond output {} bytes exceeds Bytes<128>",
                    tx.output.len()
                );
                ("respond_bidirectional", Some(hex::encode(&tx.output)))
            }
            other => anyhow::bail!("unsupported sign kind for midnight publisher: {other:?}"),
        };

        let point = action.signature.big_r.to_encoded_point(false);
        let body = MidnightRespondRequest {
            contract_address: self.config.contract_address.clone(),
            circuit: circuit.to_string(),
            request_id: request_id_hex.clone(),
            big_r_x: hex::encode(&point.as_bytes()[1..33]),
            big_r_y: hex::encode(&point.as_bytes()[33..65]),
            s: hex::encode(action.signature.s.to_bytes()),
            recovery_id: action.signature.recovery_id,
            serialized_output,
        };

        tracing::info!(?sign_id, circuit, request_id = %request_id_hex, "midnight: publishing signature");
        let resp = self
            .http
            .post(format!("{}/respond", self.config.publisher_url))
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("midnight publisher {circuit} failed: {status} {text}");
        }

        tracing::info!(?sign_id, circuit, elapsed = ?action.timestamp.elapsed(), "midnight: published successfully");
        self.telemetry.record_publish_metrics(action);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Matcher;
    use mpc_chain_integration_core::utils::test::make_publish_action;
    use mpc_chain_integration_core::NoopPublisherTelemetry;
    use mpc_primitives::{BidirectionalTxId, RespondBidirectionalTx, SignBidirectionalEvent};
    use serde_json::json;

    fn config(url: &str) -> MidnightConfig {
        MidnightConfig {
            indexer_graphql_url: "http://unused.invalid".into(),
            indexer_graphql_ws_url: "ws://unused.invalid".into(),
            node_rpc_url: "http://unused.invalid".into(),
            publisher_url: url.trim_end_matches('/').to_string(),
            contract_address: "ab".repeat(32),
            network_id: "undeployed".into(),
        }
    }

    /// The seam fixture: identical text lives in midnight-publisher's tests.
    #[test]
    fn respond_request_json_contract_is_stable() {
        let req = MidnightRespondRequest {
            contract_address: "ab".repeat(32),
            circuit: "respond_bidirectional".into(),
            request_id: "11".repeat(32),
            big_r_x: "22".repeat(32),
            big_r_y: "33".repeat(32),
            s: "44".repeat(32),
            recovery_id: 1,
            serialized_output: Some("00000001".into()),
        };
        let expected = format!(
            r#"{{"contract_address":"{}","circuit":"respond_bidirectional","request_id":"{}","big_r_x":"{}","big_r_y":"{}","s":"{}","recovery_id":1,"serialized_output":"00000001"}}"#,
            "ab".repeat(32),
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
        );
        assert_eq!(serde_json::to_string(&req).unwrap(), expected);
    }

    #[tokio::test]
    async fn publishes_sign_as_respond_circuit() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/respond")
            .match_body(Matcher::Regex(r#""circuit":"respond""#.into()))
            .with_status(200)
            .with_body(json!({"status": "ok"}).to_string())
            .expect(1)
            .create_async()
            .await;

        let client = MidnightClient::new(&config(&server.url()), Arc::new(NoopPublisherTelemetry));
        let action = make_publish_action(Chain::Midnight, SignKind::Sign);
        client.publish_signature(&action).await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn publishes_bidirectional_phase1_and_phase2() {
        let mut server = mockito::Server::new_async().await;
        let phase1 = server
            .mock("POST", "/respond")
            .match_body(Matcher::Regex(r#""circuit":"respond""#.into()))
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        let client = MidnightClient::new(&config(&server.url()), Arc::new(NoopPublisherTelemetry));
        let event = SignBidirectionalEvent {
            sender: [0xab; 32],
            serialized_transaction: vec![2, 0],
            caip2_id: "eip155:1".into(),
            key_version: 1,
            deposit: 1,
            path: "p".into(),
            algo: String::new(),
            dest: "ethereum".into(),
            params: String::new(),
            output_deserialization_schema: br#"["bool"]"#.to_vec(),
            respond_serialization_schema: br#"["bool"]"#.to_vec(),
            chain: Chain::Midnight,
            chain_ctx: None,
        };
        let action = make_publish_action(Chain::Midnight, SignKind::SignBidirectional(event));
        client.publish_signature(&action).await.unwrap();
        phase1.assert_async().await;

        let phase2 = server
            .mock("POST", "/respond")
            .match_body(Matcher::AllOf(vec![
                Matcher::Regex(r#""circuit":"respond_bidirectional""#.into()),
                Matcher::Regex(r#""serialized_output":"01020304""#.into()),
            ]))
            .with_status(200)
            .expect(1)
            .create_async()
            .await;
        let tx = RespondBidirectionalTx {
            tx_id: BidirectionalTxId([0; 32]),
            output: vec![1, 2, 3, 4],
            chain_ctx: None,
        };
        let action = make_publish_action(Chain::Midnight, SignKind::RespondBidirectional(tx));
        client.publish_signature(&action).await.unwrap();
        phase2.assert_async().await;
    }

    #[tokio::test]
    async fn oversized_output_and_http_errors_fail() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("POST", "/respond")
            .with_status(502)
            .with_body("toolkit failed")
            .create_async()
            .await;
        let client = MidnightClient::new(&config(&server.url()), Arc::new(NoopPublisherTelemetry));

        let too_big = RespondBidirectionalTx {
            tx_id: BidirectionalTxId([0; 32]),
            output: vec![0u8; 129],
            chain_ctx: None,
        };
        let err = client
            .publish_signature(&make_publish_action(
                Chain::Midnight,
                SignKind::RespondBidirectional(too_big),
            ))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exceeds Bytes<128>"));

        let err = client
            .publish_signature(&make_publish_action(Chain::Midnight, SignKind::Sign))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("502"));
    }
}
