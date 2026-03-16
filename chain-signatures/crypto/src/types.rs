pub use mpc_primitives::{PublicKey, ScalarExt};

#[test]
fn scalar_fails_as_expected() {
    use k256::Scalar;

    let too_high = [0xFF; 32];
    assert!(Scalar::from_bytes(too_high).is_none());

    let mut not_too_high = [0xFF; 32];
    // Order is of k256 is FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    //                                                  [15]
    not_too_high[15] = 0xFD;
    assert!(Scalar::from_bytes(not_too_high).is_some());
}
