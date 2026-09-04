use mpc_crypto::{near_public_key_to_affine_point, PublicKey};

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};

pub trait NearPublicKeyExt {
    fn into_affine_point(self) -> PublicKey;
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
            near_crypto::PublicKey::MLDSA65(_) => panic!("unsupported key type"),
        }
    }
}

/// Convert a secp256k1 `AffinePoint` into a NEAR public key.
pub trait NearPublicKeyFromAffineExt {
    fn into_near_public_key(self) -> near_crypto::PublicKey;
}

impl NearPublicKeyFromAffineExt for AffinePoint {
    fn into_near_public_key(self) -> near_crypto::PublicKey {
        near_crypto::PublicKey::SECP256K1(
            near_crypto::Secp256K1PublicKey::try_from(
                &self.to_encoded_point(false).as_bytes()[1..65],
            )
            .unwrap(),
        )
    }
}

pub const fn first_8_bytes(input: [u8; 32]) -> [u8; 8] {
    let mut output = [0u8; 8];
    let mut i = 0;
    while i < 8 {
        output[i] = input[i];
        i += 1;
    }
    output
}

pub fn channel_len(tx: &tokio::sync::mpsc::Sender<impl Sized>) -> usize {
    tx.max_capacity() - tx.capacity()
}
