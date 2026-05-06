use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

/// JWT claims accepted by the Canton Ledger API.
/// See https://docs.digitalasset.com/operate/3.5/howtos/secure/apis/jwt.html.
#[derive(serde::Serialize)]
struct JwtClaims {
    /// Participant user id; its `act_as`/`read_as` rights gate commands.
    sub: String,
    /// `daml_ledger_api` unless the participant sets a custom `target-scope`
    /// (mutually exclusive with `target-audience`).
    scope: String,
    /// Issued-at, Unix seconds.
    iat: u64,
    /// Expiration, Unix seconds.
    exp: u64,
    /// Not-before, Unix seconds. Set slightly in the past to absorb clock skew.
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
