use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{AccessToken, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenResponse, TokenUrl};
use std::error::Error;

pub trait OAuthTokenVerifier {
    fn verify_token(&self, token: &str) -> Option<ClientId>;
}

/* Google verifier */
pub struct GoogleTokenVerifier {
    client_id: ClientId, // TODO: do we need this field?
}

impl GoogleTokenVerifier {
    pub fn new(client_id: &str) -> GoogleTokenVerifier { // TODO: do we need this function?
        GoogleTokenVerifier {
            client_id: ClientId::new(client_id.to_owned()),
        }
    }

    pub fn verify_token(&self, token: &str) -> Result<String, Box<dyn Error>> {
        let client_secret = ClientSecret::new("".to_owned());
        let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_owned())?;
        let token_url = TokenUrl::new("https://accounts.google.com/o/oauth2/token".to_owned())?;
        let redirect_url = RedirectUrl::new("http://localhost:8080".to_owned())?;
        let client = BasicClient::new(
            self.client_id.clone(),
            Some(client_secret),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(redirect_url);

        let token = AccessToken::new(token.to_owned());
        let token_info_url = "https://www.googleapis.com/oauth2/v3/tokeninfo".parse()?;
        let token_info_request =
            client.request::<_, TokenResponse>(http_client, reqwest::Method::GET, token_info_url)
                .unwrap()
                .bearer_auth(token.secret());
        let token_info = token_info_request.send()?.json::<serde_json::Value>()?;

        if let Some(aud) = token_info.get("aud") {
            if let Some(client_id) = aud.as_str() {
                if client_id == self.client_id.secret() {
                    if let Some(sub) = token_info.get("sub") {
                        if let Some(account_id) = sub.as_str() {
                            return Ok(account_id.to_owned());
                        }
                    }
                }
            }
        }

        Err("Invalid token".into())
    }
}

/* Test verifier */
pub struct TestTokenVerifier {
    client_id: String,
}

impl TestTokenVerifier {
    pub fn new(client_id: String) -> Self {
        Self {
            client_id,
        }
    }

    fn verify_test_token(&self, token: &str) -> Option<ClientId> {
        match token {
            "valid" => Some(ClientId::new("testAccountId".to_owned())), // TODO: add prefix?
            _ => None,
        }
    }
}

impl OAuthTokenVerifier for TestTokenVerifier {
    fn verify_token(&self, token: &str) -> Option<ClientId> {
        self.verify_test_token(token)
    }
}
