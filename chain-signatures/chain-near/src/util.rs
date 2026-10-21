use k256::{elliptic_curve::sec1::ToEncodedPoint, AffinePoint};

/// Extension trait for formatting a secp256k1 `AffinePoint` as a NEAR public key.
pub trait AffinePointExt {
    /// Format the point as a NEAR secp256k1 public key in base58 (the body of
    /// `secp256k1:<base58>`), for logging.
    fn to_base58(&self) -> String;
}

impl AffinePointExt for AffinePoint {
    fn to_base58(&self) -> String {
        let key = near_crypto::Secp256K1PublicKey::try_from(
            &self.to_encoded_point(false).as_bytes()[1..65],
        )
        .unwrap();
        format!("{key:?}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::ProjectivePoint;
    use near_crypto::PublicKey;
    use std::str::FromStr;

    /// Helper to reconstruct an `AffinePoint` from a NEAR secp256k1 public-key string.
    fn point_from_near_str(s: &str) -> AffinePoint {
        let PublicKey::SECP256K1(pk) = PublicKey::from_str(s).unwrap() else {
            panic!("expected a secp256k1 public key, got {s}");
        };
        let mut bytes = vec![0x04];
        bytes.extend_from_slice(pk.as_ref());
        let encoded = k256::EncodedPoint::from_bytes(&bytes).unwrap();
        AffinePoint::from_encoded_point(&encoded).unwrap()
    }

    #[test]
    fn roundtrips_known_near_public_key() {
        let full = "secp256k1:4tY4qMzusmgX5wYdG35663Y3Qar3CTbpApotwk9ZKLoF79XA4DjG8XoByaKdNHKQX9Lz5hd7iJqsWdTKyA7dKa6Z";
        let body = &full["secp256k1:".len()..];
        let point = point_from_near_str(full);

        assert_eq!(point.to_base58(), body);
    }

    #[test]
    fn encodes_arbitrary_point() {
        let g2 = ProjectivePoint::GENERATOR * k256::Scalar::from(2u32);
        let point = g2.to_affine();

        let body = point.to_base58();
        let full = format!("secp256k1:{body}");

        assert_eq!(point_from_near_str(&full), point);
    }
}
