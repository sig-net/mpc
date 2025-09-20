use k256::{
    Scalar, Secp256k1, U256,
    elliptic_curve::{CurveArithmetic, PrimeField, bigint::ArrayEncoding},
};

pub type PublicKey = <Secp256k1 as CurveArithmetic>::AffinePoint;

pub trait ScalarExt: Sized {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
    fn from_non_biased(bytes: [u8; 32]) -> Self;
}

impl ScalarExt for Scalar {
    /// Returns nothing if the bytes are greater than the field size of Secp256k1.
    /// This will be very rare with random bytes as the field size is 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let bytes = U256::from_be_slice(bytes.as_slice());
        Scalar::from_repr(bytes.to_be_byte_array()).into_option()
    }

    /// When the user can't directly select the value, this will always work
    /// Use cases are things that we know have been hashed
    fn from_non_biased(hash: [u8; 32]) -> Self {
        // This should never happen.
        // The space of inputs is 2^256, the space of the field is ~2^256 - 2^129.
        // This mean that you'd have to run 2^127 hashes to find a value that causes this to fail.
        Scalar::from_bytes(hash).expect("Derived epsilon value falls outside of the field")
    }
}

#[test]
fn scalar_fails_as_expected() {
    let too_high = [0xFF; 32];
    assert!(Scalar::from_bytes(too_high).is_none());

    let mut not_too_high = [0xFF; 32];
    // Order is of k256 is FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    //                                                  [15]
    not_too_high[15] = 0xFD;
    assert!(Scalar::from_bytes(not_too_high).is_some());
}
