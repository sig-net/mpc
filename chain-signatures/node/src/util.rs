use chrono::{DateTime, LocalResult, TimeZone, Utc};
use crypto_shared::{near_public_key_to_affine_point, PublicKey};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};
use std::time::Duration;

pub trait NearPublicKeyExt {
    fn into_affine_point(self) -> PublicKey;
}

impl NearPublicKeyExt for String {
    fn into_affine_point(self) -> PublicKey {
        let public_key_value = serde_json::json!(self);
        serde_json::from_value(public_key_value).expect("Failed to deserialize struct")
    }
}

impl NearPublicKeyExt for near_sdk::PublicKey {
    fn into_affine_point(self) -> PublicKey {
        near_public_key_to_affine_point(self)
    }
}

impl NearPublicKeyExt for near_crypto::Secp256K1PublicKey {
    fn into_affine_point(self) -> PublicKey {
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(self.as_ref());
        let point = EncodedPoint::from_bytes(bytes).unwrap();
        PublicKey::from_encoded_point(&point).unwrap()
    }
}

impl NearPublicKeyExt for near_crypto::PublicKey {
    fn into_affine_point(self) -> PublicKey {
        match self {
            near_crypto::PublicKey::SECP256K1(public_key) => public_key.into_affine_point(),
            near_crypto::PublicKey::ED25519(_) => panic!("unsupported key type"),
        }
    }
}

pub trait AffinePointExt {
    fn into_near_public_key(self) -> near_crypto::PublicKey;
    fn to_base58(&self) -> String;
}

impl AffinePointExt for AffinePoint {
    fn into_near_public_key(self) -> near_crypto::PublicKey {
        near_crypto::PublicKey::SECP256K1(
            near_crypto::Secp256K1PublicKey::try_from(
                &self.to_encoded_point(false).as_bytes()[1..65],
            )
            .unwrap(),
        )
    }

    fn to_base58(&self) -> String {
        let key = near_crypto::Secp256K1PublicKey::try_from(
            &self.to_encoded_point(false).as_bytes()[1..65],
        )
        .unwrap();
        format!("{:?}", key)
    }
}

pub fn is_elapsed_longer_than_timeout(timestamp_sec: u64, timeout: u64) -> bool {
    if let LocalResult::Single(msg_timestamp) = Utc.timestamp_opt(timestamp_sec as i64, 0) {
        let timeout = Duration::from_millis(timeout);
        let now_datetime: DateTime<Utc> = Utc::now();
        // Calculate the difference in seconds
        let elapsed_duration = now_datetime.signed_duration_since(msg_timestamp);
        let timeout = chrono::Duration::seconds(timeout.as_secs() as i64)
            + chrono::Duration::nanoseconds(timeout.subsec_nanos() as i64);
        elapsed_duration > timeout
    } else {
        false
    }
}
