use super::ledger_api::{self, JsCommands, SubmitAndWaitForTransactionRequest};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mpc_primitives::Signature;

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
    let header = Header::new(Algorithm::ES256);
    Ok(encode(&header, &claims, key)?)
}

/// DER-encode an ECDSA signature from an MPC Signature (big_r, s).
/// See `contracts.rs` for why we use DER encoding.
pub fn der_encode_signature(signature: &Signature) -> anyhow::Result<Vec<u8>> {
    use mpc_crypto::x_coordinate;

    let r_scalar = x_coordinate(&signature.big_r);
    let ecdsa_sig = k256::ecdsa::Signature::from_scalars(r_scalar, signature.s).map_err(|e| {
        anyhow::anyhow!("failed to create ECDSA signature from (r, s) scalars: {e}")
    })?;
    Ok(ecdsa_sig.to_der().to_bytes().to_vec())
}

/// Check HTTP response status and return an error with body text if not successful.
pub async fn check_response(
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

/// Fetch the current ledger end offset from Canton.
pub async fn fetch_ledger_end(
    http_client: &reqwest::Client,
    json_api_url: &str,
    jwt_token: &str,
) -> anyhow::Result<u64> {
    let resp = http_client
        .get(format!("{json_api_url}/v2/state/ledger-end"))
        .bearer_auth(jwt_token)
        .send()
        .await?;
    let resp = check_response(resp, "ledger-end").await?;
    let body: ledger_api::LedgerEndResponse = resp.json().await?;
    Ok(body.offset)
}

/// Fetch active contracts from Canton, optionally filtered by template.
pub async fn fetch_active_contracts(
    http_client: &reqwest::Client,
    json_api_url: &str,
    jwt_token: &str,
    parties: &[&str],
    template_id: Option<&str>,
    include_blob: bool,
) -> anyhow::Result<Vec<ledger_api::ActiveContractEntry>> {
    let offset = fetch_ledger_end(http_client, json_api_url, jwt_token).await?;

    let mut filters = serde_json::Map::new();
    for party in parties {
        let value = match template_id {
            Some(tid) => serde_json::to_value(ledger_api::PartyFilter {
                cumulative: vec![ledger_api::CumulativeFilter {
                    identifier_filter: ledger_api::IdentifierFilter::TemplateFilter {
                        value: ledger_api::TemplateFilterValue {
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

    let req = ledger_api::GetActiveContractsRequest {
        active_at_offset: offset,
        event_format: ledger_api::EventFormat {
            filters_by_party: filters,
            verbose: true,
        },
    };

    let resp = http_client
        .post(format!("{json_api_url}/v2/state/active-contracts"))
        .bearer_auth(jwt_token)
        .json(&req)
        .send()
        .await?;

    let resp = check_response(resp, "active-contracts query").await?;
    Ok(resp.json().await?)
}

/// Discover the Signer contract ID by querying active contracts.
/// Returns (contractId, templateId) for the unique Signer:Signer contract.
pub async fn discover_signer_cid(
    http_client: &reqwest::Client,
    json_api_url: &str,
    jwt_token: &str,
    party_id: &str,
) -> anyhow::Result<(String, String)> {
    let items = fetch_active_contracts(
        http_client,
        json_api_url,
        jwt_token,
        &[party_id],
        None,
        false,
    )
    .await?;

    let mut signer_contracts: Vec<(String, String)> = Vec::new();
    for item in &items {
        if let Some(ledger_api::ContractEntry::JsActiveContract(active)) = &item.contract_entry {
            let ce = &active.created_event;
            if ledger_api::template_suffix_matches(&ce.template_id, ledger_api::templates::SIGNER) {
                signer_contracts.push((ce.contract_id.clone(), ce.template_id.clone()));
            }
        }
    }

    match signer_contracts.as_slice() {
        [] => anyhow::bail!("no active Signer:Signer contract found"),
        [single] => Ok(single.clone()),
        _ => anyhow::bail!(
            "expected 1 Signer:Signer contract, found {}",
            signer_contracts.len()
        ),
    }
}

/// POST a `submit-and-wait-for-transaction` command and return the parsed response.
pub async fn submit_and_wait(
    http_client: &reqwest::Client,
    json_api_url: &str,
    jwt_token: &str,
    commands: JsCommands,
    context: &str,
) -> anyhow::Result<ledger_api::SubmitAndWaitForTransactionResponse> {
    let resp = http_client
        .post(format!(
            "{json_api_url}/v2/commands/submit-and-wait-for-transaction"
        ))
        .bearer_auth(jwt_token)
        .json(&SubmitAndWaitForTransactionRequest { commands })
        .send()
        .await?;
    let resp = check_response(resp, context).await?;
    Ok(resp.json().await?)
}
