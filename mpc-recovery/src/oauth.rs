use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand8::rngs::OsRng;
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};

#[async_trait::async_trait]
pub trait OAuthTokenVerifier {
    async fn verify_token(token: &str) -> Option<&str>;
}

pub enum SupportedTokenVerifiers {
    GoogleTokenVerifier,
    TestTokenVerifier,
}

/* Universal token verifier */
pub struct UniversalTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for UniversalTokenVerifier {
    async fn verify_token(token: &str) -> Option<&str> {
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
    async fn verify_token(token: &str) -> Option<&str> {
        /*
        Expected steps:
        1. Extract the public key of the authorization server from the OpenID Connect discovery endpoint or other configuration sources.
            - https://accounts.google.com/.well-known/openid-configuration
            - get certs from jwks_uri
        2. Parse the ID token to extract the JWT header, payload, and signature.
        3. Verify the signature of the ID token using the public key of the authorization server.
        4. Check the issuer and audience claims in the ID token to ensure that the token was issued by the expected authorization server and intended for your client application.
            - check iss (https://accounts.google.com or accounts.google.com)
            - check aud (shou be equal to app's client ID)
        5. Check the expiration time and signature timestamp to ensure that the token is not expired or used before its time.
            - check exp
        6. Optionally, you can check other claims in the ID token, such as the nonce or subject claim, to provide additional security checks.
        */

        match token {
            "validToken" => {
                tracing::info!("GoogleTokenVerifier: access token is valid");
                Some("testAccountId")
            }
            _ => {
                tracing::info!("GoogleTokenVerifier: access token verification failed");
                None
            }
        }
    }
}

/* Test verifier */
pub struct TestTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for TestTokenVerifier {
    async fn verify_token(token: &str) -> Option<&str> {
        match token {
            "validToken" => {
                tracing::info!("TestTokenVerifier: access token is valid");
                Some("testAccountId")
            }
            _ => {
                tracing::info!("TestTokenVerifier: access token verification failed");
                None
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize, //TODO: should we delete last two fields? Looks like we do not need them.
}

pub fn validate_jwt(
    token: &str,
    public_key: &[u8],
    issuer: &str,
    audience: &str,
) -> Result<IdTokenClaims, String> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);

    let decoding_key = DecodingKey::from_rsa_der(public_key);

    match decode::<IdTokenClaims>(&token, &decoding_key, &validation) {
        Ok(token_data) => Ok(token_data.claims),
        Err(e) => Err(format!("Failed to validate the token: {}", e)),
    }
}

fn get_rsa_der_key_pair() -> (Vec<u8>, Vec<u8>) {
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

#[test]
fn test_validate_jwt() {
    let (private_key_der, public_key_der) = get_rsa_der_key_pair();

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
    validate_jwt(&token, &public_key_der, &my_claims.iss, &my_claims.aud).unwrap();

    // Invalid public key
    let (invalid_public_key, _invalid_private_key) = get_rsa_der_key_pair();
    match validate_jwt(&token, &invalid_public_key, &my_claims.iss, &my_claims.aud) {
        Ok(_) => panic!("Token validation should fail"),
        Err(e) => assert_eq!(e, "Failed to validate the token: InvalidSignature"),
    }

    // Invalid issuer
    match validate_jwt(&token, &public_key_der, "invalid_issuer", &my_claims.aud) {
        Ok(_) => panic!("Token validation should fail"),
        Err(e) => assert_eq!(e, "Failed to validate the token: InvalidIssuer"),
    }

    // Invalid audience
    match validate_jwt(&token, &public_key_der, &my_claims.iss, "invalid_audience") {
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
    assert_eq!(account_id, None);
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
    assert_eq!(account_id, None);
}

#[tokio::test]
async fn test_verify_token_valid_with_universal_verifier() {
    let token = "validToken";
    let account_id = UniversalTokenVerifier::verify_token(token).await.unwrap();
    assert_eq!(account_id, "testAccountId");
}
