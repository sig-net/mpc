use crate::NodeId;
use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};
use threshold_crypto::{Signature, SignatureShare};

#[derive(Serialize, Deserialize)]
pub struct AddRecoveryMethodRequest {
    pub access_token: String,
    pub account_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AddRecoveryMethodResponse {
    Ok {
        #[serde(with = "hex_public_key")]
        public_key: PublicKey,
    },
    Err {
        msg: String,
    },
}

#[derive(Serialize, Deserialize)]
pub struct RecoverAccountRequest {
    pub access_token: String,
    #[serde(with = "hex_public_key")]
    pub public_key: PublicKey,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum RecoverAccountResponse {
    Ok,
    Err { msg: String },
}

#[derive(Serialize, Deserialize)]
pub struct LeaderRequest {
    pub payload: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum LeaderResponse {
    Ok {
        #[serde(with = "hex_sig_share")]
        signature: Signature,
    },
    Err,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SigShareRequest {
    pub payload: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SigShareResponse {
    Ok {
        node_id: NodeId,
        sig_share: SignatureShare,
    },
    Err,
}

mod hex_sig_share {
    use serde::{Deserialize, Deserializer, Serializer};
    use threshold_crypto::Signature;

    pub fn serialize<S>(sig_share: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = hex::encode(sig_share.to_bytes());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature::from_bytes(
            <[u8; 96]>::try_from(hex::decode(s).map_err(serde::de::Error::custom)?).map_err(
                |v: Vec<u8>| {
                    serde::de::Error::custom(format!(
                        "signature has incorrect length: expected 96 bytes, but got {}",
                        v.len()
                    ))
                },
            )?,
        )
        .map_err(serde::de::Error::custom)
    }
}

mod hex_public_key {
    use ed25519_dalek::PublicKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig_share: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = hex::encode(sig_share.to_bytes());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PublicKey::from_bytes(&hex::decode(s).map_err(serde::de::Error::custom)?)
            .map_err(serde::de::Error::custom)
    }
}
