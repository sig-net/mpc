pub mod kdf;
pub mod types;

use k256::EncodedPoint;
use k256::elliptic_curve::sec1::FromEncodedPoint;
pub use kdf::{derive_epsilon_near, derive_key, x_coordinate};
pub use types::{PublicKey, ScalarExt};

// Our wasm runtime doesn't support good syncronous entropy.
// We could use something VRF + pseudorandom here, but someone would likely shoot themselves in the foot with it.
// Our crypto libraries should definately panic, because they normally expect randomness to be private
#[cfg(target_arch = "wasm32")]
use getrandom::{Error, register_custom_getrandom};
#[cfg(target_arch = "wasm32")]
pub fn randomness_unsupported(_: &mut [u8]) -> Result<(), Error> {
    Err(Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
register_custom_getrandom!(randomness_unsupported);

pub fn near_public_key_to_affine_point(pk: near_sdk::PublicKey) -> PublicKey {
    let mut bytes = pk.into_bytes();
    bytes[0] = 0x04;
    let point = EncodedPoint::from_bytes(bytes).unwrap();
    PublicKey::from_encoded_point(&point).unwrap()
}
