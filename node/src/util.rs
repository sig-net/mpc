use crate::kdf::{derive_epsilon, derive_key};
use crate::types::PublicKey;
use cait_sith::FullSignature;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::scalar::FromUintUnchecked;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::subtle::ConditionallySelectable;
use k256::Secp256k1;
use k256::{AffinePoint, EncodedPoint, Scalar, U256};
use near_primitives::types::AccountId;
use sha2::digest::generic_array::sequence::{Concat, Lengthen};

pub trait NearPublicKeyExt {
    fn into_affine_point(self) -> PublicKey;
}

pub trait NearCryptoPkExt {
    fn into_near_crypto_pk(self) -> near_crypto::PublicKey;
}

impl NearPublicKeyExt for near_sdk::PublicKey {
    fn into_affine_point(self) -> PublicKey {
        let mut bytes = self.into_bytes();
        bytes[0] = 0x04;
        let point = EncodedPoint::from_bytes(bytes).unwrap();
        PublicKey::from_encoded_point(&point).unwrap()
    }
}

impl NearCryptoPkExt for near_sdk::PublicKey {
    fn into_near_crypto_pk(self) -> near_crypto::PublicKey {
        match self.curve_type() {
            near_sdk::CurveType::ED25519 => near_crypto::PublicKey::ED25519(
                near_crypto::ED25519PublicKey::try_from(self.as_bytes()).unwrap(),
            ),
            near_sdk::CurveType::SECP256K1 => near_crypto::PublicKey::SECP256K1(
                near_crypto::Secp256K1PublicKey::try_from(self.as_bytes()).unwrap(),
            ),
        }
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

pub trait ScalarExt {
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl ScalarExt for Scalar {
    fn from_bytes(bytes: &[u8]) -> Self {
        Scalar::from_uint_unchecked(U256::from_le_slice(bytes))
    }
}

pub trait FullSignatureExt {
    fn into_near_signature(self) -> near_crypto::Signature;
}

impl FullSignatureExt for FullSignature<Secp256k1> {
    fn into_near_signature(self) -> near_crypto::Signature {
        let r_s = self.big_r.x().concat(self.s.to_bytes());
        let tag = ConditionallySelectable::conditional_select(&2u8, &3u8, self.big_r.y_is_odd());
        let signature = r_s.append(tag);
        let signature = near_crypto::Secp256K1Signature::try_from(signature.as_slice()).unwrap();
        near_crypto::Signature::SECP256K1(signature)
    }
}

pub fn derive_near_key(
    public_key: &near_crypto::PublicKey,
    account_id: &AccountId,
    path: &str,
) -> near_crypto::PublicKey {
    let point: AffinePoint = public_key.clone().into_affine_point();
    let epsilon = derive_epsilon(account_id, path);
    let cait_sith_pk = derive_key(point, epsilon);
    cait_sith_pk.into_near_public_key()
}
