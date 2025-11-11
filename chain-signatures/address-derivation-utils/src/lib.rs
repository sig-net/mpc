use alloy_primitives::Address;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::AffinePoint;
use k256::Scalar;

pub type PublicKey = <k256::Secp256k1 as k256::elliptic_curve::CurveArithmetic>::AffinePoint;

pub fn derive_key(public_key: PublicKey, epsilon: Scalar) -> PublicKey {
    (<k256::Secp256k1 as k256::elliptic_curve::CurveArithmetic>::ProjectivePoint::GENERATOR
        * epsilon
        + public_key)
        .to_affine()
}

fn public_key_to_address_from_affine(user_pk: &AffinePoint) -> Address {
    // false => uncompressed (65 bytes, 0x04 || X || Y)
    let enc = user_pk.to_encoded_point(false);
    let bytes = enc.as_bytes();
    debug_assert!(!enc.is_compressed());
    debug_assert_eq!(bytes[0], 0x04);

    // keccak256 over X||Y (skip the 0x04)
    let hash: [u8; 32] = *alloy_primitives::keccak256(&bytes[1..]);
    Address::from_slice(&hash[12..]) // last 20 bytes
}

pub fn derive_user_address(mpc_pk: PublicKey, derivation_epsilon: Scalar) -> Address {
    let user_pk: AffinePoint = derive_key(mpc_pk, derivation_epsilon);
    public_key_to_address_from_affine(&user_pk)
}
