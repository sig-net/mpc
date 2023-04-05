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
        0 => SupportedTokenVerifiers::GoogleTokenVerifier,
        _ => SupportedTokenVerifiers::TestTokenVerifier,
    }
}

/* Google verifier */
pub struct GoogleTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for GoogleTokenVerifier {
    // TODO: replace with real implementation
    async fn verify_token(token: &str) -> Option<&str> {
        match token {
            "validToken" => Some("testAccountId"),
            _ => None,
        }
    }
}

/* Test verifier */
pub struct TestTokenVerifier {}

#[async_trait::async_trait]
impl OAuthTokenVerifier for TestTokenVerifier {
    async fn verify_token(token: &str) -> Option<&str> {
        match token {
            "validToken" => Some("testAccountId"),
            _ => None,
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
