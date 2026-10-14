//! Chain-dispatched validation and signing of unsigned transactions:
//! admission and respond processing share one path per target chain.

use crate::protocol::Chain;
use k256::elliptic_curve::point::AffineCoordinates as _;
use k256::elliptic_curve::scalar::IsHigh as _;
use mpc_chain_tron::pb::RawTransaction;
use mpc_primitives::Signature;
use rlp::Rlp;

use super::eth_tx::{sign_and_hash_eip1559_from_unsigned, sign_and_hash_legacy_from_unsigned};

/// Checks the unsigned bytes against the target chain's signing rules.
/// Admission calls this so a transaction that cannot be signed at respond
/// time is rejected before it enters the backlog; running the actual
/// signing path is what keeps admission structurally equal to respond
/// processing.
pub(crate) fn validate_unsigned_transaction(target: Chain, unsigned: &[u8]) -> anyhow::Result<()> {
    match target {
        Chain::Ethereum => validate_unsigned_ethereum(unsigned),
        Chain::Tron => RawTransaction::parse(unsigned).map(|_| ()),
        _ => anyhow::bail!("unsupported target chain {target}"),
    }
}

fn validate_unsigned_ethereum(unsigned_rlp: &[u8]) -> anyhow::Result<()> {
    // The placeholder's recovery id is 1, the strict case: the legacy `v`
    // computation adds `y_parity`, so validating with 0 would admit the one
    // chain id whose `v` only overflows when the real signature draws parity 1.
    let placeholder = Signature::new(
        k256::ProjectivePoint::GENERATOR.to_affine(),
        k256::Scalar::ONE,
        1,
    );
    sign_and_hash_ethereum(unsigned_rlp, placeholder).map(|_| ())
}

/// Signs `unsigned` for `target`, returning the transaction id the target
/// chain records it under and the account-sequence field: Ethereum's nonce,
/// or 0 for Tron, which has none (ref-block fields in the raw data serve
/// that role).
pub fn sign_and_hash_transaction(
    target: Chain,
    unsigned: &[u8],
    signature: Signature,
) -> anyhow::Result<([u8; 32], u64)> {
    match target {
        Chain::Ethereum => sign_and_hash_ethereum(unsigned, signature),
        Chain::Tron => sign_and_hash_tron(unsigned, signature),
        _ => anyhow::bail!("unsupported target chain {target}"),
    }
}

/// Low-s normalized `(r, s, v)`: a chain includes only the low-s encoding,
/// and negating s negates the recovered point, so the recovery id flips
/// with it.
fn normalized_rs_v(signature: &Signature) -> ([u8; 32], [u8; 32], u8) {
    let negate = bool::from(signature.s.is_high());
    let s_scalar = if negate { -signature.s } else { signature.s };
    let v = ((signature.recovery_id == 1) ^ negate) as u8;
    let mut r = [0u8; 32];
    r.copy_from_slice(signature.big_r.x().as_slice());
    let mut s = [0u8; 32];
    s.copy_from_slice(s_scalar.to_bytes().as_slice());
    (r, s, v)
}

fn sign_and_hash_tron(unsigned: &[u8], signature: Signature) -> anyhow::Result<([u8; 32], u64)> {
    let (r, s, v) = normalized_rs_v(&signature);
    let (_signed, txid) = RawTransaction::parse(unsigned)?.sign_and_hash(&r, &s, v)?;
    Ok((txid, 0))
}

fn sign_and_hash_ethereum(
    unsigned_rlp: &[u8],
    signature: Signature,
) -> anyhow::Result<([u8; 32], u64)> {
    let (r, s, v) = normalized_rs_v(&signature);
    let y_parity = v == 1;

    if is_eip1559(unsigned_rlp) {
        sign_and_hash_eip1559_from_unsigned(unsigned_rlp, &r, &s, y_parity)
    } else {
        // Extract chain_id from the unsigned RLP (it's the 7th field in legacy transactions)
        // In legacy Ethereum transactions with EIP-155, there are 9 fields:
        // [nonce, gasPrice, gasLimit, to, value, data, chain_id, 0, 0]
        // The chain_id is the 7th field (index 6, 0-based).
        // We check for at least 9 fields to ensure chain_id is present.
        let rlp = Rlp::new(unsigned_rlp);
        let chain_id = if rlp.item_count().unwrap_or(0) >= 9 {
            rlp.val_at::<u64>(6).ok()
        } else {
            None
        };
        sign_and_hash_legacy_from_unsigned(unsigned_rlp, chain_id, &r, &s, y_parity)
    }
}

fn is_eip1559(unsigned_rlp: &[u8]) -> bool {
    unsigned_rlp[0] == 0x02
}

#[cfg(test)]
mod tests {
    use super::super::eth_tx::legacy_tx;
    use super::{sign_and_hash_transaction, validate_unsigned_transaction};
    use mpc_primitives::Chain;

    /// The negated signature verifies too, so it has to name the transaction a
    /// chain will actually include.
    #[test]
    fn a_high_s_signature_names_the_same_transaction_as_its_low_s_form() {
        use k256::elliptic_curve::point::AffineCoordinates as _;
        use k256::elliptic_curve::scalar::IsHigh as _;

        let unsigned = legacy_tx(31_337);

        let big_r = k256::ProjectivePoint::GENERATOR.to_affine();
        let low = k256::Scalar::from(5u64);
        let high = -low;
        assert!(!bool::from(low.is_high()) && bool::from(high.is_high()));

        let id_of = |s, recovery_id| {
            sign_and_hash_transaction(
                Chain::Ethereum,
                &unsigned,
                mpc_primitives::Signature::new(big_r, s, recovery_id),
            )
            .unwrap()
            .0
        };

        assert_eq!(id_of(low, 1), id_of(high, 0));

        // The ids would also agree if we normalised the wrong way, so compare
        // against the low-s encoding directly.
        let expected = super::super::eth_tx::sign_and_hash_legacy_from_unsigned(
            &unsigned,
            Some(31_337),
            big_r.x().as_slice(),
            low.to_bytes().as_slice(),
            false,
        )
        .unwrap()
        .0;
        assert_eq!(id_of(high, 1), expected);
    }

    /// At `chain_id = (u64::MAX - 35) / 2` the legacy `v = 2c + 35 + y_parity`
    /// overflows only for parity 1. Admission must reject it, not admit a request
    /// that then fails at respond time whenever the signature draws parity 1.
    #[test]
    fn validate_rejects_the_legacy_chain_id_that_only_overflows_on_parity_one() {
        let boundary = (u64::MAX - 35) / 2;
        let chain = Chain::Ethereum;
        assert!(validate_unsigned_transaction(chain, &legacy_tx(boundary)).is_err());
        assert!(validate_unsigned_transaction(chain, &legacy_tx(boundary - 1)).is_ok());
    }

    #[test]
    fn sign_and_hash_rejects_an_unsupported_target() {
        let unsigned = legacy_tx(1);
        let sig = mpc_primitives::Signature::new(
            k256::ProjectivePoint::GENERATOR.to_affine(),
            k256::Scalar::ONE,
            1,
        );
        assert!(sign_and_hash_transaction(Chain::Solana, &unsigned, sig).is_err());
    }
}
