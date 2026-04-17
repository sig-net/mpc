use super::ledger_api::{self, Command, JsCommands, SubmitAndWaitForTransactionRequest};
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

/// Fetch active contracts from Canton, filtered by template.
pub async fn fetch_active_contracts(
    http_client: &reqwest::Client,
    json_api_url: &str,
    jwt_token: &str,
    parties: &[&str],
    template_id: &str,
    include_blob: bool,
) -> anyhow::Result<Vec<ledger_api::ActiveContractEntry>> {
    let offset = fetch_ledger_end(http_client, json_api_url, jwt_token).await?;

    let mut filters = serde_json::Map::new();
    for party in parties {
        let filter = ledger_api::PartyFilter {
            cumulative: vec![ledger_api::CumulativeFilter {
                identifier_filter: ledger_api::IdentifierFilter::TemplateFilter {
                    value: ledger_api::TemplateFilterValue {
                        template_id: template_id.to_string(),
                        include_created_event_blob: include_blob,
                    },
                },
            }],
        };
        filters.insert(party.to_string(), serde_json::to_value(filter)?);
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
    let url = format!("{json_api_url}/v2/state/active-contracts");

    let mut filters_by_party = serde_json::Map::new();
    filters_by_party.insert(party_id.to_string(), serde_json::json!({}));

    let body = ledger_api::GetActiveContractsRequest {
        active_at_offset: 0,
        event_format: ledger_api::EventFormat {
            filters_by_party,
            verbose: false,
        },
    };

    let resp = http_client
        .post(&url)
        .bearer_auth(jwt_token)
        .json(&body)
        .send()
        .await?;

    let resp = check_response(resp, "active-contracts query").await?;
    let items: Vec<ledger_api::ActiveContractEntry> = resp.json().await?;

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

/// Exercise a choice on a Canton contract.
#[allow(clippy::too_many_arguments)]
pub async fn exercise_choice(
    http_client: &reqwest::Client,
    json_api_url: &str,
    jwt_token: &str,
    user_id: &str,
    party_id: &str,
    template_id: &str,
    contract_id: &str,
    command_id: &str,
    choice: &str,
    choice_argument: serde_json::Value,
) -> anyhow::Result<()> {
    let url = format!("{json_api_url}/v2/commands/submit-and-wait-for-transaction");

    let req = SubmitAndWaitForTransactionRequest {
        commands: JsCommands {
            command_id: command_id.to_string(),
            user_id: user_id.to_string(),
            act_as: vec![party_id.to_string()],
            read_as: vec![party_id.to_string()],
            commands: vec![Command::ExerciseCommand {
                template_id: template_id.to_string(),
                contract_id: contract_id.to_string(),
                choice: choice.to_string(),
                choice_argument,
            }],
            disclosed_contracts: vec![],
        },
    };

    let resp = http_client
        .post(&url)
        .bearer_auth(jwt_token)
        .json(&req)
        .send()
        .await?;
    check_response(resp, &format!("canton {choice}")).await?;
    Ok(())
}
