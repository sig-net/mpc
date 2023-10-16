use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use near_primitives::utils::generate_random_string;

use crate::primitives::IdTokenClaims;

// TODO: try using existing function
pub fn create_jwt_token(
    secret_rsa_pem_key: &str,
    aud: &str,
    iss: &str,
    sub: Option<&str>,
) -> String {
    let rnd_sub = generate_random_string(10);
    let sub = sub.unwrap_or_else(|| &rnd_sub);

    let my_claims = IdTokenClaims {
        iss: iss.to_owned(),
        sub: sub.to_owned(),
        aud: aud.to_owned(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
    };

    let private_key_der = secret_rsa_pem_key.as_bytes().to_vec();

    let token = encode(
        &Header::new(Algorithm::RS256),
        &my_claims,
        &EncodingKey::from_rsa_pem(&private_key_der).unwrap(),
    )
    .expect("Failed to encode jwt token");

    token.to_string()
}
