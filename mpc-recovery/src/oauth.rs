use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

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

        let decoding_key = DecodingKey::from_rsa_pem(public_key).unwrap();

        match decode::<IdTokenClaims>(token, &decoding_key, &validation) {
            Ok(token_data) => Ok(token_data.claims),
            Err(e) => Err(format!("Failed to validate the token: {}", e)),
        }
    }
}

pub enum SupportedTokenVerifiers {
    PagodaFirebaseTokenVerifier,
    TestTokenVerifier,
}

/* Universal token verifier */
pub struct UniversalTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for UniversalTokenVerifier {
    async fn verify_token(token: &str) -> Result<String, String> {
        // TODO: here we assume that verifier type can be determined from the token
        match get_token_verifier_type(token) {
            SupportedTokenVerifiers::PagodaFirebaseTokenVerifier => {
                return PagodaFirebaseTokenVerifier::verify_token(token).await;
            }
            SupportedTokenVerifiers::TestTokenVerifier => {
                return TestTokenVerifier::verify_token(token).await;
            }
        }
    }
}

fn get_token_verifier_type(token: &str) -> SupportedTokenVerifiers {
    match token.len() > 30 {
        // TODO: add real token type detection, now the system can be bypassed by passing a short token
        true => {
            tracing::info!("Using PagodaFirebaseTokenVerifier");
            SupportedTokenVerifiers::PagodaFirebaseTokenVerifier
        }
        false => {
            tracing::info!("Using TestTokenVerifier");
            SupportedTokenVerifiers::TestTokenVerifier
        }
    }
}

/* Pagoda/Firebase verifier */
pub struct PagodaFirebaseTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for PagodaFirebaseTokenVerifier {
    // Specs for ID token verification:
    // Google: https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken
    // Firebase: https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
    async fn verify_token(token: &str) -> Result<String, String> {
        let public_key = get_pagoda_firebase_public_key().expect("Failed to get Google public key");

        // this is a tmp Project ID, the real one is: pagoda-onboarding-dev
        let pagoda_firebase_audience_id: String = "pagoda-fast-auth-441fe".to_string();
        let pagoda_firebase_issuer_id: String = format!(
            "https://securetoken.google.com/{}",
            pagoda_firebase_audience_id
        );

        let claims = Self::validate_jwt(
            token,
            public_key.as_bytes(),
            &pagoda_firebase_issuer_id,
            &pagoda_firebase_audience_id,
        )
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

fn get_pagoda_firebase_public_key() -> Result<String, reqwest::Error> {
    // TODO: handle errors
    let url =
        "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
    let client = reqwest::blocking::Client::new();
    let response = client.get(url).send()?;
    let json: HashMap<String, Value> = response.json()?;
    let key = json.iter().next().unwrap().1.as_str().unwrap().to_string();
    Ok(key)
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
    fn test_get_pagoda_firebase_public_key() {
        let pk = get_pagoda_firebase_public_key().unwrap();
        assert!(!pk.is_empty());
    }

    #[test]
    fn test_validate_jwt() {
        let (private_key_der, public_key_der): (Vec<u8>, Vec<u8>) = get_rsa_pem_key_pair();

        let my_claims = IdTokenClaims {
            iss: "test_issuer".to_string(),
            sub: "test_subject".to_string(),
            aud: "test_audience".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };

        let token = match encode(
            &Header::new(Algorithm::RS256),
            &my_claims,
            &EncodingKey::from_rsa_pem(&private_key_der).unwrap(),
        ) {
            Ok(t) => t,
            Err(e) => panic!("Failed to encode token: {}", e),
        };

        // Valid token and claims
        PagodaFirebaseTokenVerifier::validate_jwt(
            &token,
            &public_key_der,
            &my_claims.iss,
            &my_claims.aud,
        )
        .unwrap();

        // Invalid public key
        let (invalid_public_key, _invalid_private_key) = get_rsa_pem_key_pair();
        match PagodaFirebaseTokenVerifier::validate_jwt(
            &token,
            &invalid_public_key,
            &my_claims.iss,
            &my_claims.aud,
        ) {
            Ok(_) => panic!("Token validation should fail"),
            Err(e) => assert_eq!(e, "Failed to validate the token: InvalidSignature"),
        }

        // Invalid issuer
        match PagodaFirebaseTokenVerifier::validate_jwt(
            &token,
            &public_key_der,
            "invalid_issuer",
            &my_claims.aud,
        ) {
            Ok(_) => panic!("Token validation should fail"),
            Err(e) => assert_eq!(e, "Failed to validate the token: InvalidIssuer"),
        }

        // Invalid audience
        match PagodaFirebaseTokenVerifier::validate_jwt(
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

    pub fn get_rsa_pem_key_pair() -> (Vec<u8>, Vec<u8>) {
        let mut rng = OsRng;
        let bits: usize = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        let private_key_der = private_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode private key")
            .as_bytes()
            .to_vec();
        let public_key_der = public_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("Failed to encode public key")
            .as_bytes()
            .to_vec();

        (private_key_der, public_key_der)
    }
}
