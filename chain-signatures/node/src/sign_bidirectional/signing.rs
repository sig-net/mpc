//! Chain-dispatched validation and signing of unsigned transactions:
//! admission and respond processing share one path per target chain.

use crate::protocol::Chain;
use k256::elliptic_curve::point::AffineCoordinates as _;
use k256::elliptic_curve::scalar::IsHigh as _;
use mpc_primitives::{BidirectionalTxId, SignBidirectionalEvent, Signature};
use mpc_tron_wire::{pb::RawTransaction, TronAddress};
use rlp::Rlp;

use super::eth_tx::{
    derive_user_address, sign_and_hash_eip1559_from_unsigned, sign_and_hash_legacy_from_unsigned,
};
use super::SignBidirectionalEventExt as _;

/// Checks the unsigned bytes against the target chain's signing rules,
/// returning the Ethereum calldata when the target runs schema checks.
/// Admission calls this so a transaction that cannot be signed at respond
/// time is rejected before it enters the backlog; running the actual
/// signing path is what keeps admission structurally equal to respond
/// processing.
pub(crate) fn validate_unsigned_transaction(
    target: Chain,
    unsigned: &[u8],
) -> anyhow::Result<Option<&[u8]>> {
    match target {
        Chain::Ethereum => validate_unsigned_ethereum(unsigned).map(Some),
        // Tron's receipt-based output extraction defines no schemas yet;
        // admission requires them empty (see `validate`).
        Chain::Tron => RawTransaction::parse(unsigned).map(|_| None),
        _ => anyhow::bail!("unsupported target chain {target}"),
    }
}

/// The destination id before signing, when the target defines one without
/// the signature: Tron's txID is sha256 of the raw bytes, flat across
/// requests with identical bytes; Ethereum's id hashes the signed
/// transaction, so there is nothing to compare until a signature exists.
pub(crate) fn pending_destination_id(
    target: Chain,
    unsigned: &[u8],
) -> anyhow::Result<Option<BidirectionalTxId>> {
    match target {
        Chain::Tron => Ok(Some(BidirectionalTxId(
            RawTransaction::parse(unsigned)?.txid(),
        ))),
        _ => Ok(None),
    }
}

/// Returns `true` if the event's serialized transaction names the requester's derived key as owner.
/// For Tron, this checks the trigger's `owner_address`. Other chains are assumed to recover the sender from the signature.
pub(crate) fn owned_by_requester(
    event: &SignBidirectionalEvent,
    root_pk: mpc_primitives::PublicKey,
) -> bool {
    if event.target_chain() != Ok(Chain::Tron) {
        return true;
    }
    let owner = match RawTransaction::parse(&event.serialized_transaction)
        .and_then(|raw| raw.owner_address())
    {
        Ok(owner) => owner,
        // `validate` already rejected undecodable bytes.
        Err(_) => return true,
    };
    let Some(epsilon) = event.epsilon().ok() else {
        return true;
    };
    owner == TronAddress::from_evm(derive_user_address(root_pk, epsilon)).as_bytes()
}

/// Unsigned integer fields per transaction type, `(field index, max bytes)`,
/// in consensus order. Legacy signs r and s as empty strings — EIP-155 hashes
/// them empty, so anything else names another hash.
const EIP1559_UINTS: &[(usize, usize)] = &[
    (0, 32), // chain id
    (1, 8),  // nonce
    (2, 32), // max priority fee
    (3, 32), // max fee
    (4, 8),  // gas limit
    (6, 32), // value
];
const LEGACY_UINTS: &[(usize, usize)] = &[
    (0, 8),  // nonce
    (1, 32), // gas price
    (2, 8),  // gas limit
    (4, 32), // value
    (6, 32), // chain id
    (7, 0),  // r
    (8, 0),  // s
];

fn validate_unsigned_ethereum(unsigned_rlp: &[u8]) -> anyhow::Result<&[u8]> {
    // The placeholder's recovery id is 1, the strict case: the legacy `v`
    // computation adds `y_parity`, so validating with 0 would admit the one
    // chain id whose `v` only overflows when the real signature draws parity 1.
    let placeholder = Signature::new(
        k256::ProjectivePoint::GENERATOR.to_affine(),
        k256::Scalar::ONE,
        1,
    );
    sign_and_hash_ethereum(unsigned_rlp, placeholder)?;
    let eip1559 = is_eip1559(unsigned_rlp);
    let body = if eip1559 {
        &unsigned_rlp[1..]
    } else {
        unsigned_rlp
    };
    let fields = Rlp::new(body);
    // The signature covers these exact bytes while Ethereum recovers the sender
    // from the hash of what it decodes, so bytes after the list sign a hash
    // Ethereum never computes.
    anyhow::ensure!(
        fields.payload_info()?.total() == body.len(),
        "bytes after the transaction"
    );
    anyhow::ensure!(
        fields.item_count()? == 9,
        "transaction has {} fields, not 9",
        fields.item_count()?
    );
    // Signing copies these fields as they are, so each must already be what
    // Ethereum decodes for its type.
    let (uints, gas_limit_index, to_index, data_index) = if eip1559 {
        (EIP1559_UINTS, 4, 5, 7)
    } else {
        (LEGACY_UINTS, 2, 3, 5)
    };
    for &(index, max_bytes) in uints {
        uint_field(&fields, index, max_bytes)?;
    }
    let mut access_list_gas = 0;
    if eip1559 {
        let priority_fee = uint_field(&fields, 2, 32)?;
        let max_fee = uint_field(&fields, 3, 32)?;
        // Length first, bytes second: the numeric order of canonical
        // big-endian integers.
        anyhow::ensure!(
            (priority_fee.len(), priority_fee) <= (max_fee.len(), max_fee),
            "max priority fee above max fee"
        );
        access_list_gas = validate_access_list(&fields.at(8)?)?;
    }
    // An empty `to` creates a contract, which extraction refuses, and Ethereum
    // rejects any other length.
    let to = string_field(&fields, to_index)?;
    anyhow::ensure!(
        to.len() == 20,
        "`to` is {} bytes, not a 20-byte call target",
        to.len()
    );
    let data = string_field(&fields, data_index)?;
    let gas_limit: u64 = fields.val_at(gas_limit_index)?;
    let min_gas = min_gas_limit(data, access_list_gas);
    anyhow::ensure!(
        gas_limit >= min_gas,
        "gas limit {gas_limit} below the minimum {min_gas}"
    );
    Ok(data)
}

/// The least gas limit a call is valid with on every watched network, all of
/// which run Prague: its intrinsic gas (EIP-2028 calldata, EIP-2930 access
/// list) or the EIP-7623 calldata floor, whichever is higher.
fn min_gas_limit(data: &[u8], access_list_gas: u64) -> u64 {
    let zeros = data.iter().filter(|byte| **byte == 0).count() as u64;
    let tokens = zeros + 4 * (data.len() as u64 - zeros);
    (21_000 + 4 * tokens + access_list_gas).max(21_000 + 10 * tokens)
}

/// `Rlp::data` also returns a list's payload and accepts a one-byte string
/// below 0x80 behind a prefix; Ethereum decodes neither as a string.
fn string_atom<'a>(field: &Rlp<'a>) -> anyhow::Result<&'a [u8]> {
    anyhow::ensure!(field.is_data(), "RLP list, not a string");
    let data = field.data()?;
    anyhow::ensure!(
        !(field.as_raw().first() == Some(&0x81) && data.first().is_some_and(|b| *b < 0x80)),
        "not canonical RLP"
    );
    Ok(data)
}

fn string_field<'a>(fields: &Rlp<'a>, index: usize) -> anyhow::Result<&'a [u8]> {
    string_atom(&fields.at(index)?)
        .map_err(|error| error.context(format!("transaction field {index}")))
}

/// An unsigned integer of at most `max_bytes` bytes, without leading zeros.
fn uint_field<'a>(fields: &Rlp<'a>, index: usize, max_bytes: usize) -> anyhow::Result<&'a [u8]> {
    let data = string_field(fields, index)?;
    anyhow::ensure!(
        data.first() != Some(&0),
        "transaction field {index} has a leading zero"
    );
    anyhow::ensure!(
        data.len() <= max_bytes,
        "transaction field {index} has {} bytes, more than {max_bytes}",
        data.len()
    );
    Ok(data)
}

/// A list of `[20-byte address, list of 32-byte storage keys]`. Returns its
/// intrinsic gas (EIP-2930).
fn validate_access_list(access_list: &Rlp) -> anyhow::Result<u64> {
    let mut gas = 0;
    anyhow::ensure!(access_list.is_list(), "access list is not an RLP list");
    for (i, entry) in access_list.iter().enumerate() {
        anyhow::ensure!(
            entry.is_list() && entry.item_count()? == 2,
            "access list entry {i} is not [address, storage keys]"
        );
        let address = string_atom(&entry.at(0)?)
            .map_err(|error| error.context(format!("access list entry {i} address")))?;
        anyhow::ensure!(
            address.len() == 20,
            "access list entry {i} has no 20-byte address"
        );
        let keys = entry.at(1)?;
        anyhow::ensure!(
            keys.is_list(),
            "access list entry {i} storage keys are not an RLP list"
        );
        gas += 2_400 + 1_900 * keys.item_count()? as u64;
        for (k, key) in keys.iter().enumerate() {
            let key = string_atom(&key)
                .map_err(|error| error.context(format!("access list entry {i} storage key {k}")))?;
            anyhow::ensure!(
                key.len() == 32,
                "access list entry {i} storage key {k} is not 32 bytes"
            );
        }
    }
    Ok(gas)
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
        // The txID is sha256(raw_data) — signature-independent by construction.
        Chain::Tron => Ok((RawTransaction::parse(unsigned)?.txid(), 0)),
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

fn sign_and_hash_ethereum(
    unsigned_rlp: &[u8],
    signature: Signature,
) -> anyhow::Result<([u8; 32], u64)> {
    let (r, s, v) = normalized_rs_v(&signature);
    let y_parity = v == 1;

    if is_eip1559(unsigned_rlp) {
        sign_and_hash_eip1559_from_unsigned(unsigned_rlp, &r, &s, y_parity)
    } else {
        let chain_id = transaction_chain_id(unsigned_rlp);
        sign_and_hash_legacy_from_unsigned(unsigned_rlp, chain_id, &r, &s, y_parity)
    }
}

/// The EIP-155 chain id of an unsigned EIP-1559 or legacy transaction.
pub(crate) fn transaction_chain_id(unsigned_rlp: &[u8]) -> Option<u64> {
    if let Some(body) = unsigned_rlp.strip_prefix(&[0x02]) {
        return Rlp::new(body).val_at(0).ok();
    }
    // Legacy with EIP-155 has 9 fields:
    // [nonce, gasPrice, gasLimit, to, value, data, chain_id, 0, 0]
    let legacy = Rlp::new(unsigned_rlp);
    match legacy.item_count() {
        Ok(9) => legacy.val_at(6).ok(),
        _ => None,
    }
}

fn is_eip1559(unsigned_rlp: &[u8]) -> bool {
    unsigned_rlp.first() == Some(&0x02)
}

#[cfg(test)]
mod tests {
    use super::super::eth_tx::legacy_tx;
    use super::{sign_and_hash_transaction, validate_unsigned_transaction};
    use alloy::consensus::{SignableTransaction as _, TxEip1559};
    use alloy::primitives::TxKind;
    use mpc_primitives::Chain;

    #[test]
    fn transaction_chain_id_reads_legacy_and_eip1559() {
        assert_eq!(
            super::transaction_chain_id(&legacy_tx(31_337)),
            Some(31_337)
        );
        let eip1559 = TxEip1559 {
            chain_id: 11_155_111,
            ..Default::default()
        };
        let unsigned = eip1559.encoded_for_signing();
        assert_eq!(super::transaction_chain_id(&unsigned), Some(11_155_111));
    }

    #[test]
    fn validate_rejects_contract_creation() {
        let eip1559 = |to| {
            TxEip1559 {
                chain_id: 1,
                gas_limit: 21_000,
                to,
                ..Default::default()
            }
            .encoded_for_signing()
        };
        let call = TxKind::Call(alloy::primitives::Address::repeat_byte(0x11));
        let ok = |bytes: &[u8]| validate_unsigned_transaction(Chain::Ethereum, bytes).is_ok();
        assert!(ok(&eip1559(call)));
        assert!(!ok(&eip1559(TxKind::Create)));

        // nonce, gas price, gas limit, empty `to`, value, data, then EIP-155 chain id 1
        let legacy_create = {
            let mut rlp = super::super::eth_tx::EthereumTxRlp::new_list(9);
            for field in [0, 0, 0, 0, 0, 0, 1, 0, 0] {
                rlp.append_u64(field);
            }
            rlp.into_vec()
        };
        assert!(ok(&legacy_tx(1)));
        assert!(!ok(&legacy_create));
    }

    /// Signing copies fields as they are, so admission must refuse every
    /// encoding Ethereum would not decode as the field's type.
    #[test]
    fn validate_rejects_fields_ethereum_cannot_decode() {
        let string = |bytes: &[u8]| rlp::encode(&bytes.to_vec()).to_vec();
        let uint = |value: u64| rlp::encode(&value).to_vec();
        let list = |items: &[Vec<u8>]| {
            let mut stream = rlp::RlpStream::new_list(items.len());
            for item in items {
                stream.append_raw(item, 1);
            }
            stream.out().to_vec()
        };
        let encode = |eip1559: bool, fields: &[Vec<u8>]| {
            let body = list(fields);
            if eip1559 {
                [&[2u8][..], &body].concat()
            } else {
                body
            }
        };
        let to = string(&[0x11; 20]);
        let data = string(&[1, 2]);
        let pair = list(&[uint(1), uint(2)]);
        // nonce, gas price, gas limit, to, value, data, chain id, r, s
        let legacy = vec![
            uint(0),
            uint(1),
            uint(30_000),
            to.clone(),
            uint(0),
            data.clone(),
            uint(1),
            uint(0),
            uint(0),
        ];
        // chain id, nonce, max priority fee, max fee, gas limit, to, value, data, access list
        let access_list = list(&[list(&[string(&[0x22; 20]), list(&[string(&[0x33; 32])])])]);
        let eip1559_fields = vec![
            uint(1),
            uint(0),
            uint(1),
            uint(2),
            uint(30_000),
            to,
            uint(0),
            data,
            access_list,
        ];
        for (is_1559, valid) in [(false, &legacy), (true, &eip1559_fields)] {
            let validate =
                |bytes: &[u8]| validate_unsigned_transaction(Chain::Ethereum, bytes).is_ok();
            assert!(validate(&encode(is_1559, valid)), "1559: {is_1559}");
            let with = |index: usize, field: Vec<u8>| {
                let mut fields = valid.clone();
                fields[index] = field;
                encode(is_1559, &fields)
            };
            let mut invalid = vec![
                (
                    "trailing byte".to_string(),
                    [encode(is_1559, valid), vec![0]].concat(),
                ),
                (
                    "ten fields".to_string(),
                    encode(is_1559, &[valid.clone(), vec![uint(0)]].concat()),
                ),
            ];
            for index in 0..9 {
                invalid.push((format!("list in field {index}"), with(index, pair.clone())));
            }
            let (uints, data_index) = if is_1559 {
                (vec![0, 1, 2, 3, 4, 6], 7)
            } else {
                (vec![0, 1, 2, 4, 6, 7, 8], 5)
            };
            for index in uints {
                invalid.push((
                    format!("leading zero in field {index}"),
                    with(index, string(&[0, 1])),
                ));
            }
            invalid.push((
                "33-byte uint".to_string(),
                with(if is_1559 { 6 } else { 4 }, string(&[1; 33])),
            ));
            invalid.push((
                "9-byte gas limit".to_string(),
                with(if is_1559 { 4 } else { 2 }, string(&[1; 9])),
            ));
            invalid.push((
                "prefixed single byte".to_string(),
                with(data_index, vec![0x81, 0x05]),
            ));
            if is_1559 {
                invalid.push(("priority fee above max fee".to_string(), with(2, uint(3))));
                invalid.push(("access list as string".to_string(), with(8, string(&[1]))));
                invalid.push((
                    "19-byte access list address".to_string(),
                    with(8, list(&[list(&[string(&[0x22; 19]), list(&[])])])),
                ));
                invalid.push((
                    "31-byte storage key".to_string(),
                    with(
                        8,
                        list(&[list(&[string(&[0x22; 20]), list(&[string(&[0x33; 31])])])]),
                    ),
                ));
            } else {
                invalid.push(("nonzero r".to_string(), with(7, uint(1))));
            }
            for (case, tx) in invalid {
                assert!(!validate(&tx), "1559: {is_1559}, {case}");
            }
        }
    }

    /// Ethereum refuses a transaction whose gas limit is below the larger of
    /// its intrinsic gas (21000, 4 per zero and 16 per other data byte, 2400
    /// per access list address, 1900 per storage key) and the EIP-7623
    /// calldata floor (21000, 10 per zero and 40 per other data byte).
    #[test]
    fn validate_rejects_a_gas_limit_below_the_minimum() {
        use alloy::consensus::TxLegacy;
        use alloy::eips::eip2930::{AccessList, AccessListItem};
        use alloy::primitives::{Address, Bytes, B256};

        let entry = |byte, keys| AccessListItem {
            address: Address::repeat_byte(byte),
            storage_keys: vec![B256::ZERO; keys],
        };
        let tx = |eip1559: bool, input: &[u8], access_list: Vec<AccessListItem>, gas_limit| {
            let to = TxKind::Call(Address::repeat_byte(0x11));
            let input = Bytes::copy_from_slice(input);
            if eip1559 {
                TxEip1559 {
                    chain_id: 1,
                    gas_limit,
                    to,
                    input,
                    access_list: AccessList(access_list),
                    ..Default::default()
                }
                .encoded_for_signing()
            } else {
                TxLegacy {
                    chain_id: Some(1),
                    gas_limit,
                    to,
                    input,
                    ..Default::default()
                }
                .encoded_for_signing()
            }
        };
        let ok = |bytes: &[u8]| validate_unsigned_transaction(Chain::Ethereum, bytes).is_ok();
        let cases = [
            (
                "intrinsic gas",
                true,
                &[0, 0, 1][..],
                vec![entry(0x22, 2), entry(0x33, 1)],
                21_000 + 2 * 4 + 16 + 2 * 2_400 + 3 * 1_900,
            ),
            (
                "calldata floor",
                true,
                &[0xff; 100][..],
                vec![],
                21_000 + 100 * 40,
            ),
            (
                "legacy calldata floor",
                false,
                &[0, 0, 1][..],
                vec![],
                21_000 + 2 * 10 + 40,
            ),
        ];
        for (case, eip1559, input, access_list, min) in cases {
            assert!(ok(&tx(eip1559, input, access_list.clone(), min)), "{case}");
            assert!(!ok(&tx(eip1559, input, access_list, min - 1)), "{case}");
        }
    }

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
        let validate = |bytes: &[u8]| validate_unsigned_transaction(Chain::Ethereum, bytes).is_ok();
        assert!(!validate(&legacy_tx(boundary)));
        assert!(validate(&legacy_tx(boundary - 1)));
    }

    #[test]
    fn validate_rejects_empty_bytes() {
        for chain in [Chain::Ethereum, Chain::Tron] {
            assert!(validate_unsigned_transaction(chain, &[]).is_err());
        }
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
