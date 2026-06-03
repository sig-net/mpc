use mpc_crypto::x_coordinate;
use mpc_primitives::Signature;

pub fn der_encode_signature(signature: &Signature) -> anyhow::Result<Vec<u8>> {
    let r_scalar = x_coordinate(&signature.big_r);
    let ecdsa_sig = k256::ecdsa::Signature::from_scalars(r_scalar, signature.s).map_err(|e| {
        anyhow::anyhow!("failed to create ECDSA signature from (r, s) scalars: {e}")
    })?;
    Ok(ecdsa_sig.to_der().to_bytes().to_vec())
}
