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
    // TODO: replace with real implementation
    async fn verify_token(token: &str) -> Option<&str> {
        // Google specs for ID token verification: https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken

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
