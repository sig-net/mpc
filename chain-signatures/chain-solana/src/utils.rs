pub fn mpc_to_sol_signature(
    signature: &mpc_primitives::Signature,
    big_r: k256::EncodedPoint,
) -> signet_program::Signature {
    signet_program::Signature {
        big_r: signet_program::AffinePoint {
            x: big_r.as_bytes()[1..33].try_into().unwrap(),
            y: big_r.as_bytes()[33..65].try_into().unwrap(),
        },
        s: signature.s.to_bytes().into(),
        recovery_id: signature.recovery_id,
    }
}
