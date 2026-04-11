use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mpc_primitives::Signature;
use canton_types::ledger_api;

// ---------------------------------------------------------------------------
// JWT token generation (ES256)
// ---------------------------------------------------------------------------

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
pub(crate) fn generate_jwt_with_key(key: &EncodingKey, subject: &str) -> anyhow::Result<String> {
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
    Ok(encode(&header, &claims, &key)?)
}

// ---------------------------------------------------------------------------
// DER signature encoding
// ---------------------------------------------------------------------------

/// DER-encode an ECDSA signature from an MPC Signature (big_r, s).
///
/// Canton's native Daml signature verification (`secp256k1WithEcdsaOnly`)
/// only accepts DER-encoded signatures — there is no built-in Daml function
/// to convert from raw `(r, s)` components to DER. We encode on the MPC
/// side so the Daml contracts can verify directly without conversion.
pub fn der_encode_signature(signature: &Signature) -> anyhow::Result<Vec<u8>> {
    use mpc_crypto::x_coordinate;

    let r_scalar = x_coordinate(&signature.big_r);
    let ecdsa_sig = k256::ecdsa::Signature::from_scalars(r_scalar, &signature.s)
        .map_err(|e| anyhow::anyhow!("failed to create ECDSA signature from (r, s) scalars: {e}"))?;
    Ok(ecdsa_sig.to_der().to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Signer CID discovery
// ---------------------------------------------------------------------------

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

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("active-contracts query failed: {status} {text}");
    }

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
        _ => anyhow::bail!("expected 1 Signer:Signer contract, found {}", signer_contracts.len()),
    }
}
