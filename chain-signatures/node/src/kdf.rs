use anyhow::Context;
use k256::{ecdsa::RecoveryId, elliptic_curve::sec1::ToEncodedPoint, Scalar};
use mpc_crypto::{kdf::recover, x_coordinate};
use mpc_primitives::Signature;

// try to get the correct recovery id for this signature by brute force.
pub fn into_signature(
    public_key: &k256::AffinePoint,
    big_r: &k256::AffinePoint,
    s: &k256::Scalar,
    msg_hash: Scalar,
) -> anyhow::Result<Signature> {
    let public_key = public_key.to_encoded_point(false);
    let signature = k256::ecdsa::Signature::from_scalars(x_coordinate(big_r), s)
        .context("cannot create signature from threshold-signatures signature")?;
    let pk0 = recover(
        &msg_hash.to_bytes()[..],
        &signature,
        RecoveryId::try_from(0).context("cannot create recovery_id=0")?,
    )
    .context("unable to use 0 as recovery_id to recover public key")?
    .to_encoded_point(false);
    if public_key == pk0 {
        return Ok(Signature::new(*big_r, *s, 0));
    }

    let pk1 = recover(
        &msg_hash.to_bytes()[..],
        &signature,
        RecoveryId::try_from(1).context("cannot create recovery_id=1")?,
    )
    .context("unable to use 1 as recovery_id to recover public key")?
    .to_encoded_point(false);
    if public_key == pk1 {
        return Ok(Signature::new(*big_r, *s, 1));
    }

    anyhow::bail!("cannot use either recovery id (0 or 1) to recover pubic key")
}
