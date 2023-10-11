use std::collections::HashMap;

use borsh::{self, BorshDeserialize, BorshSerialize};
use chrono::{Duration, Utc};
use google_datastore1::api::{Key, PathElement};
use hex::FromHex;
use jsonwebtoken as jwt;
use jwt::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use near_primitives::utils::generate_random_string;
use serde::{Deserialize, Serialize};

use near_crypto::PublicKey;

use crate::{
    error::MpcError,
    gcp::{
        error::ConvertError,
        value::{FromValue, IntoValue, Value},
        KeyKind,
    },
    oauth::IdTokenClaims,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct OidcHash([u8; 32]);

impl AsRef<[u8]> for OidcHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl FromHex for OidcHash {
    type Error = anyhow::Error;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> anyhow::Result<Self> {
        let bytes = <[u8; 32]>::from_hex(hex)?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(transparent)]
pub struct OidcToken {
    data: String,
}

impl OidcToken {
    pub fn new(data: &str) -> Self {
        Self { data: data.into() }
    }

    pub fn digest_hash(&self) -> OidcHash {
        let hasher = sha2::Digest::chain(sha2::Sha256::default(), self.data.as_bytes());
        let hash = <[u8; 32]>::try_from(sha2::Digest::finalize(hasher).as_slice())
            .expect("Hash is the wrong size");
        OidcHash(hash)
    }

    pub fn random() -> Self {
        let rsa_pem_key = "-----BEGIN RSA PRIVATE KEY-----
        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
        -----END RSA PRIVATE KEY-----";

        let private_key_der = rsa_pem_key.as_bytes().to_vec();

        let aud = "test_audience".to_string();

        let my_claims = IdTokenClaims {
            iss: format!("https://securetoken.google.com/{}", aud),
            sub: generate_random_string(7),
            aud,
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        };

        let token = match encode(
            &Header::new(Algorithm::RS256),
            &my_claims,
            &EncodingKey::from_rsa_pem(&private_key_der).unwrap(),
        ) {
            Ok(t) => OidcToken::new(t.as_str()),
            Err(e) => panic!("Failed to encode token: {}", e),
        };

        Self {
            data: token.to_string(),
        }
    }

    pub fn invalid() -> Self {
        Self {
            data: "invalid_token".to_string(),
        }
    }

    // NOTE: code taken directly from jsonwebtoken::verify_signature and modified to suit
    // our needs (i.e. not knowing audience and issuer ahead of time).
    pub fn decode(
        &self,
        key: &DecodingKey,
    ) -> anyhow::Result<(jwt::Header, IdTokenClaims, String)> {
        let mut parts = self.as_ref().rsplitn(2, '.');
        let (Some(signature), Some(message)) = (parts.next(), parts.next()) else {
            anyhow::bail!("could not split into signature and message for OIDC token");
        };
        let mut parts = message.rsplitn(2, '.');
        let (Some(payload), Some(header)) = (parts.next(), parts.next()) else {
            anyhow::bail!("could not split into payload and header for OIDC token");
        };
        let header: jwt::Header = serde_json::from_slice(&b64_decode(header)?)?;
        let claims: IdTokenClaims = serde_json::from_slice(&b64_decode(payload)?)?;

        if !jwt::crypto::verify(signature, message.as_bytes(), key, header.alg)? {
            anyhow::bail!("InvalidSignature");
        }

        Ok((header, claims, signature.into()))
    }
}

fn b64_decode<T: AsRef<[u8]>>(input: T) -> anyhow::Result<Vec<u8>> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, input)
        .map_err(Into::into)
}

impl std::str::FromStr for OidcToken {
    type Err = MpcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl std::fmt::Display for OidcToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.data)
    }
}

impl AsRef<str> for OidcToken {
    fn as_ref(&self) -> &str {
        &self.data
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OidcDigest {
    pub node_id: usize,
    pub digest: OidcHash,
    pub public_key: PublicKey,
}

impl KeyKind for OidcDigest {
    fn kind() -> String {
        "OidcDigest".to_string()
    }
}

impl IntoValue for OidcDigest {
    fn into_value(self) -> Value {
        let mut properties = HashMap::new();
        properties.insert(
            "node_id".to_string(),
            Value::IntegerValue(self.node_id as i64),
        );
        properties.insert(
            "digest".to_string(),
            Value::StringValue(hex::encode(&self.digest)),
        );
        properties.insert(
            "public_key".to_string(),
            Value::StringValue(serde_json::to_string(&self.public_key).unwrap()),
        );

        Value::EntityValue {
            key: Key {
                path: Some(vec![PathElement {
                    kind: Some(Self::kind()),
                    name: Some(self.to_name()),
                    id: None,
                }]),
                partition_id: None,
            },
            properties,
        }
    }
}

impl FromValue for OidcDigest {
    fn from_value(value: Value) -> Result<Self, ConvertError> {
        match value {
            Value::EntityValue { mut properties, .. } => {
                let (_, node_id) = properties
                    .remove_entry("node_id")
                    .ok_or_else(|| ConvertError::MissingProperty("node_id".to_string()))?;
                let node_id = i64::from_value(node_id)? as usize;
                let (_, digest) = properties
                    .remove_entry("digest")
                    .ok_or_else(|| ConvertError::MissingProperty("digest".to_string()))?;
                let digest = hex::decode(String::from_value(digest)?)
                    .map_err(|_| ConvertError::MalformedProperty("digest".to_string()))?;
                let digest = <[u8; 32]>::try_from(digest)
                    .map_err(|_| ConvertError::MalformedProperty("digest".to_string()))?;
                let digest = OidcHash(digest);

                let (_, public_key) = properties
                    .remove_entry("public_key")
                    .ok_or_else(|| ConvertError::MissingProperty("public_key".to_string()))?;
                let public_key = String::from_value(public_key)?;
                let public_key = serde_json::from_str(&public_key)
                    .map_err(|_| ConvertError::MalformedProperty("public_key".to_string()))?;

                Ok(Self {
                    node_id,
                    digest,
                    public_key,
                })
            }
            error => Err(ConvertError::UnexpectedPropertyType {
                expected: "entity".to_string(),
                got: format!("{:?}", error),
            }),
        }
    }
}

impl OidcDigest {
    pub fn to_name(&self) -> String {
        format!("{}/{}", self.node_id, hex::encode(&self.digest))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::utils::claim_oidc_request_digest;

    use super::*;

    #[test]
    fn test_oidc_digest_from_and_to_value() {
        let oidc_token = OidcToken::random();
        let oidc_token_hash = oidc_token.digest_hash();
        let user_pk =
            PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae").unwrap();

        let oidc_request_digest = match claim_oidc_request_digest(&oidc_token_hash, &user_pk) {
            Ok(digest) => digest,
            Err(err) => panic!("Failed to create digest: {:?}", err),
        };

        let digest = <[u8; 32]>::try_from(oidc_request_digest).expect("Hash was wrong size");
        let digest = OidcHash(digest);

        let oidc_digest = OidcDigest {
            node_id: 1,
            digest: digest.clone(),
            public_key: user_pk,
        };

        let val = oidc_digest.clone().into_value();

        let reconstructed_oidc_digest = match OidcDigest::from_value(val) {
            Ok(oidc_digest) => oidc_digest,
            Err(err) => panic!("Failed to reconstruct OidcDigest: {:?}", err),
        };

        // Wrong digest for comparison
        let public_key_2 = "ed25519:EBNJGHctB2LuDsCyMWrfwW87QrAob2kKzoS98PR5vjJn";
        let oidc_digest_2 = OidcDigest {
            node_id: 1,
            digest,
            public_key: public_key_2.parse().expect("Failed to parse public key"),
        };

        assert_eq!(oidc_digest, reconstructed_oidc_digest);
        assert_ne!(oidc_digest_2, reconstructed_oidc_digest);
    }

    #[test]
    fn test_oidc_to_name() {
        let oidc_token = OidcToken::random();
        let user_pk =
            PublicKey::from_str("ed25519:J75xXmF7WUPS3xCm3hy2tgwLCKdYM1iJd4BWF8sWVnae").unwrap();
        let oidc_token_hash = oidc_token.digest_hash();

        let digest = match claim_oidc_request_digest(&oidc_token_hash, &user_pk) {
            Ok(digest) => digest,
            Err(err) => panic!("Failed to create digest: {:?}", err),
        };

        let digest = <[u8; 32]>::try_from(digest).expect("Hash was wrong size");
        let digest = OidcHash(digest);

        let oidc_digest = OidcDigest {
            node_id: 1,
            digest,
            public_key: user_pk,
        };

        let name = oidc_digest.to_name();

        assert_eq!(
            name,
            format!(
                "{}/{}",
                oidc_digest.node_id,
                hex::encode(oidc_digest.digest)
            )
        );
    }
}
