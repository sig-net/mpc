use near_crypto::SecretKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: usize,
}

pub struct UserSession {
    pub jwt_token: String,
    pub fa_sk: SecretKey,
    pub la_sk: SecretKey,
}
