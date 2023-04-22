use crate::NodeId;
use multi_party_eddsa::protocols::Signature;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct NewAccountRequest {
    pub public_key: String,
    pub near_account_id: String,
    pub oidc_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NewAccountResponse {
    Ok,
    Err { msg: String },
}

impl NewAccountResponse {
    pub fn err(msg: String) -> Self {
        NewAccountResponse::Err { msg }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddKeyRequest {
    pub near_account_id: Option<String>,
    pub public_key: String,
    pub oidc_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum AddKeyResponse {
    Ok,
    Err { msg: String },
}

impl AddKeyResponse {
    pub fn err(msg: String) -> Self {
        AddKeyResponse::Err { msg }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LeaderRequest {
    pub payload: String,
}

#[derive(Serialize, Deserialize, Debug)]
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
    pub payload: Vec<u8>,
}

// #[derive(Serialize, Deserialize, Debug)]
// #[allow(clippy::large_enum_variant)]
// pub enum SigShareResponse {
//     Ok {
//         node_id: NodeId,
//         sig_share: SignatureShare,
//     },
//     Err,
// }

mod hex_sig_share {
    use std::ops::Deref;

    use curv::elliptic::curves::{Point, Scalar};
    use multi_party_eddsa::protocols::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(sig_share: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = hex::encode(to_bytes(sig_share));
        serializer.serialize_str(&s)
    }

    fn to_bytes(sig: &Signature) -> Vec<u8> {
        [sig.R.to_bytes(false).deref(), sig.s.to_bytes().deref()].concat()
    }

    fn from_bytes(sig: [u8; 96]) -> Result<Signature, String> {
        Ok(Signature {
            R: Point::from_bytes(&sig.as_ref()[..32]).map_err(|e| e.to_string())?,
            s: Scalar::from_bytes(&sig.as_ref()[32..]).map_err(|e| e.to_string())?,
        })
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        from_bytes(
            // This is the length of a BLS sig not an Ed25519 I think?
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
