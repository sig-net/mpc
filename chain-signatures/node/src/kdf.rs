use hkdf::Hkdf;
use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint, Scalar};
use mpc_crypto::ScalarExt;
use near_primitives::hash::CryptoHash;
use sha3::Sha3_256;

// Constant prefix that ensures delta derivation values are used specifically for
// near-mpc-recovery with key derivation protocol vX.Y.Z.
const DELTA_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 delta derivation:";

// TODO: move to mpc_crypto::kdf once updated
// In case there are multiple requests in the same block (hence same entropy), we need to ensure
// that we generate different random scalars as delta tweaks.
// Receipt ID should be unique inside of a block, so it serves us as the request identifier.
pub fn derive_delta(
    request_id: [u8; 32],
    entropy: [u8; 32],
    presignature_big_r: AffinePoint,
) -> Scalar {
    let hk = Hkdf::<Sha3_256>::new(None, &entropy);
    let info = format!("{DELTA_DERIVATION_PREFIX}:{}", CryptoHash(request_id));
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm).unwrap();
    hk.expand(
        presignature_big_r.to_encoded_point(true).as_bytes(),
        &mut okm,
    )
    .unwrap();
    Scalar::from_non_biased(okm)
}
