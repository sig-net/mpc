use anyhow;
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, ResourceOwnerPassword,
    ResourceOwnerUsername, Scope, TokenUrl,
};

#[test]
fn get_and_verify_google_access_token() -> anyhow::Result<()> {
    // TODO: adde google urls
    let client = BasicClient::new(
        ClientId::new("client_id".to_string()),
        Some(ClientSecret::new("client_secret".to_string())),
        AuthUrl::new("http://authorize".to_string())?,
        Some(TokenUrl::new("http://token".to_string())?),
    );

    let token_result = client
        .exchange_password(
            &ResourceOwnerUsername::new("user".to_string()),
            &ResourceOwnerPassword::new("pass".to_string()),
        )
        .add_scope(Scope::new("read".to_string()))
        .request(http_client)?;
    
    // TODO: add google token verification

    Ok(())
}
