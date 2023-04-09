
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{AuthUrl, ClientId, ClientSecret, Scope, TokenUrl};

#[test]
fn test_get_and_verify_google_access_token() -> anyhow::Result<()> {
    // In order to get ID token, we need to use the "Authorization Code" grant type? What grant type is used for OIDC?
    // What flow should we use? Authorization Code Flow (response_type=code), the Implicit Flow (response_type=id_token token or response_type=id_token), or the Hybrid Flow?
    // Flows are decribed in the main spec, but it's llong, TODO: read it, if needed
    const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
    const GOOGLE_TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v3/token";

    let client = BasicClient::new(
        ClientId::new("client_id".to_string()),
        Some(ClientSecret::new("client_secret".to_string())),
        AuthUrl::new(GOOGLE_AUTH_URL.to_string()).expect("Invalid authorization endpoint URL"),
        Some(TokenUrl::new(GOOGLE_TOKEN_URL.to_string()).expect("Invalid token endpoint URL")),
    );

    let _token_result = client
        .exchange_client_credentials()
        .add_scope(Scope::new("read".to_string()))
        .request(http_client)
        .expect("Failed to get token");

    // TODO: add google token verification
    Ok(())
}
