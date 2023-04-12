use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::StatusCode;

#[async_trait::async_trait]
pub trait OAuthTokenVerifier {
    async fn verify_token(token: &str) -> Result<String, String>; // TODO: replace String error with custom error type

    /// This function validates JWT (OIDC ID token) by checking the signature received
    /// from the issuer, issuer, audience, and expiration time.
    fn validate_jwt(
        token: &str,
        public_key: &[u8],
        issuer: &str,
        audience: &str,
    ) -> Result<IdTokenClaims, String> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);

        let decoding_key = DecodingKey::from_rsa_der(public_key);

        match decode::<IdTokenClaims>(token, &decoding_key, &validation) {
            Ok(token_data) => Ok(token_data.claims),
            Err(e) => Err(format!("Failed to validate the token: {}", e)),
        }
    }
}

pub enum SupportedTokenVerifiers {
    GoogleTokenVerifier,
    TestTokenVerifier,
}

/* Universal token verifier */
pub struct UniversalTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for UniversalTokenVerifier {
    async fn verify_token(token: &str) -> Result<String, String> {
        // TODO: here we assume that verifier type can be determined from the token
        match get_token_verifier_type(token) {
            SupportedTokenVerifiers::GoogleTokenVerifier => {
                return GoogleTokenVerifier::verify_token(token).await;
            }
            SupportedTokenVerifiers::TestTokenVerifier => {
                return TestTokenVerifier::verify_token(token).await;
            }
        }
    }
}

fn get_token_verifier_type(token: &str) -> SupportedTokenVerifiers {
    match token.len() {
        // TODO: add real token type detection
        0 => {
            tracing::info!("Using GoogleTokenVerifier");
            SupportedTokenVerifiers::GoogleTokenVerifier
        }
        _ => {
            tracing::info!("Using TestTokenVerifier");
            SupportedTokenVerifiers::TestTokenVerifier
        }
    }
}

/* Google verifier */
pub struct GoogleTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for GoogleTokenVerifier {
    // Google specs for ID token verification: https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken
    async fn verify_token(token: &str) -> Result<String, String> {
        let public_key = get_google_public_key().expect("Failed to get Google public key");

        const GOOGLE_ISSUER_ID: &str = "https://accounts.google.com"; // TODO: should be an array, google provides two options
        const GOOGLE_AUDIENCE_ID: &str = "TODO: get audience id from Google (register new project)";

        let claims = Self::validate_jwt(token, &public_key, GOOGLE_ISSUER_ID, GOOGLE_AUDIENCE_ID)
            .expect("Failed to validate JWT");
        let internal_user_identifier = format!("{}:{}", claims.iss, claims.sub);

        Ok(internal_user_identifier)
    }
}

/* Test verifier */
pub struct TestTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for TestTokenVerifier {
    async fn verify_token(token: &str) -> Result<String, String> {
        match token {
            "validToken" => {
                tracing::info!(target: "test-token-verifier", "access token is valid");
                Ok("testAccountId".to_string())
            }
            _ => {
                tracing::info!(target: "test-token-verifier", "access token verification failed");
                Err("Invalid token".to_string())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize,
}

#[derive(Serialize, Deserialize)]
struct OpenIdConfig {
    jwks_uri: String,
}

#[derive(Serialize, Deserialize)]
struct Jwks {
    keys: Vec<Value>,
}

fn get_google_public_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let open_id_config_url = "https://accounts.google.com/.well-known/openid-configuration";
    let client = reqwest::blocking::Client::new();
    let response = client.get(open_id_config_url).send()?;
    if response.status() != StatusCode::OK {
        return Err(format!("Failed to get OpenID config: {}", response.status()).into());
    }
    let body = response.text()?;
    let config: OpenIdConfig = serde_json::from_str(&body)?;
    let jwks_uri = config.jwks_uri;
    let response = client
        .get(&jwks_uri)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .send()?;
    if response.status() != StatusCode::OK {
        return Err(format!("Failed to get JWK set: {}", response.status()).into());
    }
    let body = response.text()?;
    let jwks: Jwks = serde_json::from_str(&body)?;
    let public_key = jwks.keys[0]["n"].as_str().unwrap();
    Ok(public_key.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rand8::rngs::OsRng;
    use rsa::{
        pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
        RsaPrivateKey, RsaPublicKey,
    };

    #[test]
    fn test_get_google_public_key() {
        let pk = get_google_public_key().unwrap();
        assert!(pk.len() > 0);
    }

    #[test]
    fn test_validate_jwt() {
        let (private_key_der, public_key_der): (Vec<u8>, Vec<u8>) = get_rsa_der_key_pair();

        let my_claims = IdTokenClaims {
            iss: "test_issuer".to_string(),
            sub: "test_subject".to_string(),
            aud: "test_audience".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };

        let token = match encode(
            &Header::new(Algorithm::RS256),
            &my_claims,
            &EncodingKey::from_rsa_der(&private_key_der),
        ) {
            Ok(t) => t,
            Err(e) => panic!("Failed to encode token: {}", e),
        };

        // Valid token and claims
        GoogleTokenVerifier::validate_jwt(&token, &public_key_der, &my_claims.iss, &my_claims.aud)
            .unwrap();

        // Invalid public key
        let (invalid_public_key, _invalid_private_key) = get_rsa_der_key_pair();
        match GoogleTokenVerifier::validate_jwt(
            &token,
            &invalid_public_key,
            &my_claims.iss,
            &my_claims.aud,
        ) {
            Ok(_) => panic!("Token validation should fail"),
            Err(e) => assert_eq!(e, "Failed to validate the token: InvalidSignature"),
        }

        // Invalid issuer
        match GoogleTokenVerifier::validate_jwt(
            &token,
            &public_key_der,
            "invalid_issuer",
            &my_claims.aud,
        ) {
            Ok(_) => panic!("Token validation should fail"),
            Err(e) => assert_eq!(e, "Failed to validate the token: InvalidIssuer"),
        }

        // Invalid audience
        match GoogleTokenVerifier::validate_jwt(
            &token,
            &public_key_der,
            &my_claims.iss,
            "invalid_audience",
        ) {
            Ok(_) => panic!("Token validation should fail"),
            Err(e) => assert_eq!(e, "Failed to validate the token: InvalidAudience"),
        }
    }

    #[tokio::test]
    async fn test_verify_token_valid() {
        let token = "validToken";
        let account_id = TestTokenVerifier::verify_token(token).await.unwrap();
        assert_eq!(account_id, "testAccountId");
    }

    #[tokio::test]
    async fn test_verify_token_invalid_with_test_verifier() {
        let token = "invalid";
        let account_id = TestTokenVerifier::verify_token(token).await;
        assert_eq!(account_id, Err("Invalid token".to_string()));
    }

    #[tokio::test]
    async fn test_verify_token_valid_with_test_verifier() {
        let token = "validToken";
        let account_id = TestTokenVerifier::verify_token(token).await.unwrap();
        assert_eq!(account_id, "testAccountId");
    }

    #[tokio::test]
    async fn test_verify_token_invalid_with_universal_verifier() {
        let token = "invalid";
        let account_id = UniversalTokenVerifier::verify_token(token).await;
        assert_eq!(account_id, Err("Invalid token".to_string()));
    }

    #[tokio::test]
    async fn test_verify_token_valid_with_universal_verifier() {
        let token = "validToken";
        let account_id = UniversalTokenVerifier::verify_token(token).await.unwrap();
        assert_eq!(account_id, "testAccountId");
    }

    pub fn get_rsa_der_key_pair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let bits: usize = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let private_key_der = private_key
            .to_pkcs1_der()
            .expect("Failed to encode private key")
            .as_bytes()
            .to_vec();
        let public_key_der = public_key
            .to_pkcs1_der()
            .expect("Failed to encode public key")
            .as_bytes()
            .to_vec();

        (private_key_der, public_key_der)
    }
}
