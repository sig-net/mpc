use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint};

// TODO: add unit tests
/// Format an `AffinePoint` as a NEAR secp256k1 public key in base58, for logging.
///
/// This mirrors `AffinePointExt::to_base58` in the node's `util` module; it is the only
/// piece of that trait used by the NEAR publisher.
pub fn affine_point_to_base58(point: &AffinePoint) -> String {
    let key =
        near_crypto::Secp256K1PublicKey::try_from(&point.to_encoded_point(false).as_bytes()[1..65])
            .unwrap();
    format!("{key:?}")
}

/// Current time in seconds since the UNIX epoch.
pub fn current_unix_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
