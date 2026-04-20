use super::ledger_api::{
    ActiveContractEntry, CumulativeFilter, EventFormat, GetActiveContractsRequest,
    IdentifierFilter, JsCommands, LedgerEndResponse, PartyFilter,
    SubmitAndWaitForTransactionRequest, SubmitAndWaitForTransactionResponse, TemplateFilterValue,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

#[derive(serde::Serialize)]
struct JwtClaims {
    sub: String,
    /// Canton supports scope-based OR audience-based tokens, not both.
    /// We use scope-based (the default when no target-audience is configured).
    scope: String,
    iat: u64,
    exp: u64,
    nbf: u64,
}

/// Generate a JWT using a pre-parsed EncodingKey.
pub fn generate_jwt_with_key(key: &EncodingKey, subject: &str) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = JwtClaims {
        sub: subject.to_string(),
        scope: "daml_ledger_api".to_string(),
        iat: now,
        exp: now + 300,
        nbf: now.saturating_sub(60),
    };
    Ok(encode(&Header::new(Algorithm::ES256), &claims, key)?)
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

#[allow(async_fn_in_trait)]
pub trait CantonConn {
    fn http(&self) -> &reqwest::Client;
    fn json_api_url(&self) -> &str;
    fn jwt_encoding_key(&self) -> &EncodingKey;
    fn jwt_subject(&self) -> &str;

    fn generate_jwt(&self) -> anyhow::Result<String> {
        generate_jwt_with_key(self.jwt_encoding_key(), self.jwt_subject())
    }

    async fn fetch_ledger_end(&self) -> anyhow::Result<u64> {
        let resp = self
            .http()
            .get(format!("{}/v2/state/ledger-end", self.json_api_url()))
            .bearer_auth(self.generate_jwt()?)
            .send()
            .await?;
        let resp = check_response(resp, "ledger-end").await?;
        let body: LedgerEndResponse = resp.json().await?;
        Ok(body.offset)
    }

    async fn fetch_active_contracts(
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
            .http()
            .post(format!(
                "{}/v2/state/active-contracts",
                self.json_api_url()
            ))
            .bearer_auth(self.generate_jwt()?)
            .json(&req)
            .send()
            .await?;

        let resp = check_response(resp, "active-contracts query").await?;
        Ok(resp.json().await?)
    }

    async fn submit_and_wait(
        &self,
        commands: JsCommands,
        context: &str,
    ) -> anyhow::Result<SubmitAndWaitForTransactionResponse> {
        let resp = self
            .http()
            .post(format!(
                "{}/v2/commands/submit-and-wait-for-transaction",
                self.json_api_url()
            ))
            .bearer_auth(self.generate_jwt()?)
            .json(&SubmitAndWaitForTransactionRequest { commands })
            .send()
            .await?;
        let resp = check_response(resp, context).await?;
        Ok(resp.json().await?)
    }
}
