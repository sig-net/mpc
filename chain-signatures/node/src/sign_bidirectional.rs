use crate::protocol::{Chain, IndexedSignRequest};
use alloy::primitives::{keccak256, Address};
use anyhow::Context as _;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::scalar::IsHigh as _;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use k256::{AffinePoint, Scalar};
use mpc_crypto::derive_key;
use mpc_primitives::ChainConfig as _;
pub use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, ChainFromError, SignBidirectionalEvent, Signature,
};
use rlp::{Rlp, RlpStream};
use serde::{Deserialize, Serialize};

use std::sync::Arc;

use crate::backlog::Publishing;

/// Progress of an active Cait-Sith MPC signing round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignProgress {
    /// Actively running or awaiting MPC signing.
    Generating,
    /// Signature produced; ready to publish or awaiting on-chain inclusion.
    Publishing(Publishing),
}

impl SignProgress {
    pub fn is_generating(&self) -> bool {
        matches!(self, Self::Generating)
    }

    pub fn publishing(&self) -> Option<&Publishing> {
        match self {
            Self::Publishing(publish) => Some(publish),
            Self::Generating => None,
        }
    }
}

/// Lifecycle stages of a two-phase bidirectional transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BidirectionalProgress {
    /// Phase 1: Signing the initial transaction for the source chain.
    Initial(SignProgress),
    /// Awaiting execution on the target chain.
    Executing(Arc<BidirectionalTx>),
    /// Phase 2: Signing the completion/respond transaction for the source chain.
    Final {
        respond_request: Arc<IndexedSignRequest>,
        progress: SignProgress,
    },
    /// Terminal output extraction failure; retained for source checkpoint agreement.
    Parked(Arc<BidirectionalTx>),
}

/// Overall status of any request held in the backlog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignStatus {
    Sign(SignProgress),
    Bidirectional(BidirectionalProgress),
}

impl SignStatus {
    pub fn is_pending_generation(&self) -> bool {
        match self {
            Self::Sign(progress) => progress.is_generating(),
            Self::Bidirectional(BidirectionalProgress::Initial(progress)) => {
                progress.is_generating()
            }
            Self::Bidirectional(BidirectionalProgress::Final { progress, .. }) => {
                progress.is_generating()
            }
            Self::Bidirectional(
                BidirectionalProgress::Executing(_) | BidirectionalProgress::Parked(_),
            ) => false,
        }
    }

    pub fn is_pending_execution(&self) -> bool {
        matches!(
            self,
            Self::Bidirectional(BidirectionalProgress::Executing(_))
        )
    }

    pub fn execution_tx(&self) -> Option<&Arc<BidirectionalTx>> {
        match self {
            Self::Bidirectional(BidirectionalProgress::Executing(tx)) => Some(tx),
            _ => None,
        }
    }

    pub fn publishing(&self) -> Option<&Publishing> {
        match self {
            Self::Sign(progress) => progress.publishing(),
            Self::Bidirectional(BidirectionalProgress::Initial(progress)) => progress.publishing(),
            Self::Bidirectional(BidirectionalProgress::Final { progress, .. }) => {
                progress.publishing()
            }
            Self::Bidirectional(
                BidirectionalProgress::Executing(_) | BidirectionalProgress::Parked(_),
            ) => None,
        }
    }

    /// Project this status onto what is observable at a checkpoint's own chain height.
    ///
    /// * `0` — the initial source-chain phase (standard Sign or initial Bidirectional).
    /// * `1` — the post-initial phase (Bidirectional awaiting target execution, parked, or final response).
    pub fn consensus_tag(&self) -> u8 {
        match self {
            Self::Sign(_) | Self::Bidirectional(BidirectionalProgress::Initial(_)) => 0,
            Self::Bidirectional(
                BidirectionalProgress::Executing(_)
                | BidirectionalProgress::Final { .. }
                | BidirectionalProgress::Parked(_),
            ) => 1,
        }
    }
}

/// Extension trait for `SignBidirectionalEvent` to provide additional helper methods.
pub trait SignBidirectionalEventExt {
    fn sender_string(&self) -> anyhow::Result<String>;
    fn epsilon(&self) -> anyhow::Result<Scalar>;
    fn target_chain(&self) -> Result<Chain, ChainFromError>;

    /// The deterministic derivations respond processing runs for every bidirectional
    /// request, and the schema checks output extraction applies whatever the target
    /// chain returns. Shared between admission (reject before the backlog) and the
    /// respond path's failure handling (quarantine): both must agree on what "can
    /// never advance" means.
    fn validate(&self) -> anyhow::Result<()>;

    /// Construct a [`BidirectionalTx`] from this event, the response signature, and the MPC root key.
    fn to_bidirectional_tx(
        &self,
        request_id: [u8; 32],
        mpc_sig: Signature,
        root_pk: mpc_primitives::PublicKey,
    ) -> anyhow::Result<BidirectionalTx>;
}

impl SignBidirectionalEventExt for SignBidirectionalEvent {
    fn sender_string(&self) -> anyhow::Result<String> {
        match self.chain {
            Chain::Canton | Chain::Midnight => Ok(hex::encode(self.sender)),
            _ => crate::stream::ops::sender_string(self.sender, self.chain),
        }
    }

    fn epsilon(&self) -> anyhow::Result<Scalar> {
        match self.chain {
            Chain::Solana => Ok(mpc_crypto::kdf::derive_epsilon_sol(
                self.key_version,
                &self.sender_string()?,
                &self.path,
            )?),
            Chain::Hydration => Ok(mpc_crypto::kdf::derive_epsilon_hydration(
                self.key_version,
                &self.sender_string()?,
                &self.path,
            )?),
            Chain::Canton => Ok(mpc_crypto::kdf::derive_epsilon_canton(
                self.key_version,
                &self.sender_string()?,
                &self.path,
            )?),
            Chain::Midnight => Ok(mpc_crypto::kdf::derive_epsilon_midnight(
                self.key_version,
                &self.sender_string()?,
                &self.path,
            )?),
            _ => anyhow::bail!("Unsupported chain for epsilon derivation: {:?}", self.chain),
        }
    }

    fn target_chain(&self) -> Result<Chain, mpc_primitives::ChainFromError> {
        Chain::from_caip2_chain_id(&self.caip2_id)
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.serialized_transaction.is_empty(),
            "empty serialized_transaction"
        );
        let target = self
            .target_chain()
            .map_err(|err| anyhow::anyhow!("bad target chain: {err:?}"))?;
        anyhow::ensure!(
            target.has_execution_watcher(),
            "unsupported target chain {target}"
        );
        self.epsilon().context("cannot derive epsilon")?;
        let calldata = validate_unsigned_transaction(&self.serialized_transaction)
            .context("undecodable serialized_transaction")?;
        // Ethereum is the only target with an execution watcher, checked above.
        mpc_chain_ethereum::validate_schemas(
            calldata,
            &self.output_deserialization_schema,
            self.chain.respond_serialization_format(),
            &self.respond_serialization_schema,
        )
        .context("unprocessable output schemas")
    }

    fn to_bidirectional_tx(
        &self,
        request_id: [u8; 32],
        mpc_sig: Signature,
        root_pk: mpc_primitives::PublicKey,
    ) -> anyhow::Result<BidirectionalTx> {
        let target_chain = self.target_chain().with_context(|| {
            format!("failed to determine target chain for request: {request_id:?}")
        })?;
        let epsilon = self.epsilon()?;
        let from_address = derive_user_address(root_pk, epsilon);
        let (signed_tx_hash, nonce) =
            sign_and_hash_transaction(&self.serialized_transaction, mpc_sig)?;

        Ok(BidirectionalTx {
            id: BidirectionalTxId(signed_tx_hash),
            sender: self.sender,
            serialized_transaction: self.serialized_transaction.clone(),
            source_chain: self.chain,
            target_chain,
            caip2_id: self.caip2_id.clone(),
            key_version: self.key_version,
            deposit: self.deposit,
            path: self.path.clone(),
            algo: self.algo.clone(),
            dest: self.dest.clone(),
            params: self.params.clone(),
            output_deserialization_schema: self.output_deserialization_schema.clone(),
            respond_serialization_schema: self.respond_serialization_schema.clone(),
            request_id,
            from_address: **from_address,
            nonce,
        })
    }
}

/// Extension trait for `BidirectionalTx` to provide additional helper methods.
pub trait BidirectionalTxExt {
    fn sender_string(&self) -> anyhow::Result<String>;
    fn epsilon(&self, path: &str) -> anyhow::Result<Scalar>;
}

impl BidirectionalTxExt for BidirectionalTx {
    fn sender_string(&self) -> anyhow::Result<String> {
        if matches!(self.source_chain, Chain::Canton | Chain::Midnight) {
            return Ok(hex::encode(self.sender));
        }
        crate::stream::ops::sender_string(self.sender, self.source_chain)
    }

    fn epsilon(&self, path: &str) -> anyhow::Result<Scalar> {
        match self.source_chain {
            Chain::Solana => Ok(mpc_crypto::kdf::derive_epsilon_sol(
                self.key_version,
                &self.sender_string()?,
                path,
            )?),
            Chain::Hydration => Ok(mpc_crypto::kdf::derive_epsilon_hydration(
                self.key_version,
                &self.sender_string()?,
                path,
            )?),
            Chain::Canton => Ok(mpc_crypto::kdf::derive_epsilon_canton(
                self.key_version,
                &self.sender_string()?,
                path,
            )?),
            Chain::Midnight => Ok(mpc_crypto::kdf::derive_epsilon_midnight(
                self.key_version,
                &self.sender_string()?,
                path,
            )?),
            _ => anyhow::bail!("Unsupported chain: {}", self.source_chain),
        }
    }
}

/// Check that `unsigned_rlp` would survive [`sign_and_hash_transaction`], without a
/// real signature, and return its calldata. Admission calls this so a transaction
/// that cannot be signed at respond time is rejected before it enters the backlog;
/// running the actual function is what keeps admission structurally equal to
/// respond processing. The placeholder's recovery id is 1, the strict case: the
/// legacy `v` computation adds `y_parity`, so validating with 0 would admit the one
/// chain id whose `v` only overflows when the real signature draws parity 1.
fn validate_unsigned_transaction(unsigned_rlp: &[u8]) -> anyhow::Result<&[u8]> {
    let placeholder = Signature::new(
        k256::ProjectivePoint::GENERATOR.to_affine(),
        k256::Scalar::ONE,
        1,
    );
    sign_and_hash_transaction(unsigned_rlp, placeholder)?;
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
    let (to_index, data_index) = if eip1559 {
        uint_field(&fields, 0, 32)?; // chain id
        uint_field(&fields, 1, 8)?; // nonce
        let max_priority_fee = uint_field(&fields, 2, 32)?;
        let max_fee = uint_field(&fields, 3, 32)?;
        anyhow::ensure!(
            (max_priority_fee.len(), max_priority_fee) <= (max_fee.len(), max_fee),
            "max priority fee above max fee"
        );
        uint_field(&fields, 4, 8)?; // gas limit
        uint_field(&fields, 6, 32)?; // value
        validate_access_list(&fields.at(8)?)?;
        (5, 7)
    } else {
        uint_field(&fields, 0, 8)?; // nonce
        uint_field(&fields, 1, 32)?; // gas price
        uint_field(&fields, 2, 8)?; // gas limit
        uint_field(&fields, 4, 32)?; // value
        uint_field(&fields, 6, 32)?; // chain id
                                     // EIP-155 hashes r and s as empty strings; anything else signs another hash.
        uint_field(&fields, 7, 0)?;
        uint_field(&fields, 8, 0)?;
        (3, 5)
    };
    // An empty `to` creates a contract, which extraction refuses, and Ethereum
    // rejects any other length.
    let to = string_field(&fields, to_index)?;
    anyhow::ensure!(
        to.len() == 20,
        "`to` is {} bytes, not a 20-byte call target",
        to.len()
    );
    string_field(&fields, data_index)
}

/// `Rlp::data` also returns a list's payload and accepts a one-byte string
/// below 0x80 behind a prefix; Ethereum decodes neither as a string.
fn string_field<'a>(fields: &Rlp<'a>, index: usize) -> anyhow::Result<&'a [u8]> {
    let field = fields.at(index)?;
    anyhow::ensure!(
        field.is_data(),
        "transaction field {index} is an RLP list, not a string"
    );
    let data = field.data()?;
    anyhow::ensure!(
        !(field.as_raw()[0] == 0x81 && data[0] < 0x80),
        "transaction field {index} is not canonical RLP"
    );
    Ok(data)
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

/// A list of `[20-byte address, list of 32-byte storage keys]`.
fn validate_access_list(access_list: &Rlp) -> anyhow::Result<()> {
    anyhow::ensure!(access_list.is_list(), "access list is not an RLP list");
    for i in 0..access_list.item_count()? {
        let entry = access_list.at(i)?;
        anyhow::ensure!(
            entry.is_list() && entry.item_count()? == 2,
            "access list entry {i} is not [address, storage keys]"
        );
        anyhow::ensure!(
            string_field(&entry, 0)?.len() == 20,
            "access list entry {i} has no 20-byte address"
        );
        let keys = entry.at(1)?;
        anyhow::ensure!(
            keys.is_list(),
            "access list entry {i} storage keys are not an RLP list"
        );
        for k in 0..keys.item_count()? {
            anyhow::ensure!(
                string_field(&keys, k)?.len() == 32,
                "access list entry {i} storage key {k} is not 32 bytes"
            );
        }
    }
    Ok(())
}

pub fn sign_and_hash_transaction(
    unsigned_rlp: &[u8],
    signature: Signature,
) -> anyhow::Result<([u8; 32], u64)> {
    // A chain includes only the low-s encoding, and negating s negates the
    // recovered point, so the recovery id flips with it.
    let negate = bool::from(signature.s.is_high());
    let s_scalar = if negate { -signature.s } else { signature.s };
    let y_parity = (signature.recovery_id == 1) ^ negate;
    let r = signature.big_r.x().as_slice().to_vec();
    let s = s_scalar.to_bytes().as_slice().to_vec();

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
    let rlp = Rlp::new(unsigned_rlp);
    (rlp.item_count().ok()? >= 9).then(|| rlp.val_at(6).ok())?
}

fn is_eip1559(unsigned_rlp: &[u8]) -> bool {
    unsigned_rlp[0] == 0x02
}

pub fn sign_and_hash_eip1559_from_unsigned(
    unsigned: &[u8], // may be 0x02||RLP(body) or just RLP(body)
    r: &[u8],
    s: &[u8],
    y_parity: bool,
) -> anyhow::Result<([u8; 32], u64)> {
    // Strip optional type prefix
    let (_, body) = match unsigned.first().copied() {
        Some(0x02) => (true, &unsigned[1..]),
        _ => (false, unsigned),
    };

    // Decode the 9-field unsigned body
    let rlp = Rlp::new(body);
    anyhow::ensure!(rlp.is_list(), "unsigned 1559 payload must be an RLP list");
    anyhow::ensure!(
        rlp.item_count()? == 9,
        "unexpected 1559 unsigned field count"
    );

    let nonce: u64 = rlp.val_at::<u64>(1)?;

    // Re-encode with signature fields appended
    let mut srlp = EthereumTxRlp::new_list(12);
    for i in 0..9 {
        srlp.append_raw_field(rlp.at(i)?.as_raw());
    }
    let y: u8 = if y_parity { 1 } else { 0 };
    srlp.append_u8(y);
    srlp.append_uint_bytes(r);
    srlp.append_uint_bytes(s);

    let srlp_body = srlp.as_raw(); // &[u8]
    let mut signed_bytes = Vec::with_capacity(1 + srlp_body.len());
    signed_bytes.push(0x02);
    signed_bytes.extend_from_slice(srlp_body);

    let hash = keccak256(&signed_bytes);
    Ok((hash.into(), nonce))
}

pub fn sign_and_hash_legacy_from_unsigned(
    unsigned_rlp: &[u8], // the exact preimage you hashed (… , chainId, 0, 0)
    chain_id: Option<u64>,
    r: &[u8],
    s: &[u8],
    y_parity: bool,
) -> anyhow::Result<([u8; 32], u64)> {
    let rlp = Rlp::new(unsigned_rlp);
    anyhow::ensure!(rlp.is_list(), "unsigned legacy must be an RLP list");
    anyhow::ensure!(
        rlp.item_count()? >= 9,
        "unexpected legacy unsigned field count"
    );

    let nonce: u64 = rlp.val_at::<u64>(0)?;
    let mut out = EthereumTxRlp::new_list(9);
    for i in 0..6 {
        out.append_raw_field(rlp.at(i)?.as_raw());
    }
    // Checked: `chain_id` is attacker-controlled bytes (admission runs this decode
    // on every observed request event), and 35 + 2 * chain_id overflows for ids
    // near u64::MAX.
    let v: u64 = chain_id
        .unwrap_or(0)
        .checked_mul(2)
        .and_then(|doubled| doubled.checked_add(35 + u64::from(y_parity)))
        .ok_or_else(|| anyhow::anyhow!("legacy chain_id too large"))?;
    out.append_u64(v);
    out.append_uint_bytes(r);
    out.append_uint_bytes(s);

    let signed_bytes = out.into_vec();
    let hash = alloy::primitives::keccak256(&signed_bytes);
    Ok((hash.into(), nonce))
}

struct EthereumTxRlp {
    stream: RlpStream,
}

impl EthereumTxRlp {
    fn new_list(len: usize) -> Self {
        Self {
            stream: RlpStream::new_list(len),
        }
    }

    fn append_raw_field(&mut self, raw: &[u8]) {
        self.stream.append_raw(raw, 1);
    }

    fn append_u8(&mut self, value: u8) {
        self.stream.append(&value);
    }

    fn append_u64(&mut self, value: u64) {
        self.stream.append(&value);
    }

    fn append_uint_bytes(&mut self, value: &[u8]) {
        let first_nonzero = value
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(value.len());
        if first_nonzero == value.len() {
            self.stream.append_empty_data();
            return;
        }

        self.stream.append(&value[first_nonzero..].to_vec());
    }

    fn as_raw(&self) -> &[u8] {
        self.stream.as_raw()
    }

    fn into_vec(self) -> Vec<u8> {
        self.stream.out().to_vec()
    }
}

pub fn public_key_to_address(public_key: &[u8]) -> Address {
    debug_assert_eq!(public_key[0], 0x04);
    let hash: [u8; 32] = *alloy::primitives::keccak256(&public_key[1..]);

    Address::from_slice(&hash[12..])
}

pub fn derive_user_address(mpc_pk: mpc_crypto::PublicKey, derivation_epsilon: Scalar) -> Address {
    let user_pk: AffinePoint = derive_key(mpc_pk, derivation_epsilon);

    public_key_to_address(user_pk.to_encoded_point(false).as_bytes())
}

#[cfg(test)]
mod derive_tests {
    use super::derive_user_address;
    use alloy::primitives::Address;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::{AffinePoint, EncodedPoint};
    use mpc_crypto::derive_epsilon_near;
    use mpc_primitives::LEGACY_MPC_KEY_VERSION_0;

    #[test]
    fn derive_user_address_matches_golden() {
        let mpc_key = "045b4fa179e005361fd858f8a6f896d7afc23a53d3f95d6566a88cde954e7b2f1cb77c554705c35d4ffced67aeafbcda46d9d89d6f200c3a3d109f92872863b3dc";
        let account_id = "dev-20250212213501-93636560094065.test.near"
            .parse()
            .unwrap();
        let mpc_pk = hex::decode(mpc_key).unwrap();
        let mpc_pk = EncodedPoint::from_bytes(mpc_pk).unwrap();
        let mpc_pk = AffinePoint::from_encoded_point(&mpc_pk).unwrap();
        let derivation_epsilon =
            derive_epsilon_near(LEGACY_MPC_KEY_VERSION_0, &account_id, "test").unwrap();
        let expected: Address = "0x083c8776b5e447e91bae43b7883a92a9bdb66d1d"
            .parse()
            .unwrap();

        assert_eq!(derive_user_address(mpc_pk, derivation_epsilon), expected);
    }
}

#[cfg(test)]
mod tests {
    use super::sign_and_hash_eip1559_from_unsigned;
    use alloy::consensus::{SignableTransaction, TxEip1559};
    use alloy::eips::eip2718::Encodable2718;
    use alloy::primitives::{Bytes, FixedBytes, Signature, TxKind, U256};
    use std::sync::Arc;

    #[test]
    fn eip1559_hash_matches_alloy_for_create_with_leading_zero_r() {
        let tx = TxEip1559 {
            chain_id: 31_337,
            nonce: 3,
            gas_limit: 100_000,
            max_fee_per_gas: 100_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Create,
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::new(),
        };
        let unsigned = tx.encoded_for_signing();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r[31] = 1;
        s[31] = 2;

        let (hash, nonce) = sign_and_hash_eip1559_from_unsigned(&unsigned, &r, &s, true).unwrap();

        let signed = tx
            .into_signed(Signature::from_scalars_and_parity(
                FixedBytes::from_slice(&r),
                FixedBytes::from_slice(&s),
                true,
            ))
            .encoded_2718();
        let expected_hash: [u8; 32] = alloy::primitives::keccak256(&signed).into();

        assert_eq!(hash, expected_hash);
        assert_eq!(nonce, 3);
    }

    fn legacy_tx(chain_id: u64) -> Vec<u8> {
        let mut rlp = super::EthereumTxRlp::new_list(9);
        // nonce, gas price, gas limit
        for _ in 0..3 {
            rlp.append_u64(0);
        }
        rlp.stream.append(&vec![0x11u8; 20]);
        // value, data
        for _ in 0..2 {
            rlp.append_u64(0);
        }
        rlp.append_u64(chain_id);
        rlp.append_u64(0);
        rlp.append_u64(0);
        rlp.into_vec()
    }

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
            super::sign_and_hash_transaction(
                &unsigned,
                mpc_primitives::Signature::new(big_r, s, recovery_id),
            )
            .unwrap()
            .0
        };

        assert_eq!(id_of(low, 1), id_of(high, 0));

        // The ids would also agree if we normalised the wrong way, so compare
        // against the low-s encoding directly.
        let expected = super::sign_and_hash_legacy_from_unsigned(
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
        assert!(super::validate_unsigned_transaction(&legacy_tx(boundary)).is_err());
        assert!(super::validate_unsigned_transaction(&legacy_tx(boundary - 1)).is_ok());
    }

    #[test]
    fn validate_rejects_contract_creation() {
        let eip1559 = |to| {
            TxEip1559 {
                chain_id: 1,
                to,
                ..Default::default()
            }
            .encoded_for_signing()
        };
        let call = TxKind::Call(alloy::primitives::Address::repeat_byte(0x11));
        assert!(super::validate_unsigned_transaction(&eip1559(call)).is_ok());
        assert!(super::validate_unsigned_transaction(&eip1559(TxKind::Create)).is_err());

        // nonce, gas price, gas limit, empty `to`, value, data, then EIP-155 chain id 1
        let mut legacy_create = super::EthereumTxRlp::new_list(9);
        for field in [0, 0, 0, 0, 0, 0, 1, 0, 0] {
            legacy_create.append_u64(field);
        }
        assert!(super::validate_unsigned_transaction(&legacy_tx(1)).is_ok());
        assert!(super::validate_unsigned_transaction(&legacy_create.into_vec()).is_err());
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
            uint(21_000),
            to.clone(),
            uint(0),
            data.clone(),
            uint(1),
            uint(0),
            uint(0),
        ];
        // chain id, nonce, max priority fee, max fee, gas limit, to, value, data, access list
        let access_list = list(&[list(&[string(&[0x22; 20]), list(&[string(&[0x33; 32])])])]);
        let eip1559 = vec![
            uint(1),
            uint(0),
            uint(1),
            uint(2),
            uint(21_000),
            to,
            uint(0),
            data,
            access_list,
        ];
        for (is_1559, valid) in [(false, &legacy), (true, &eip1559)] {
            assert!(
                super::validate_unsigned_transaction(&encode(is_1559, valid)).is_ok(),
                "1559: {is_1559}"
            );
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
                assert!(
                    super::validate_unsigned_transaction(&tx).is_err(),
                    "1559: {is_1559}, {case}"
                );
            }
        }
    }

    #[test]
    fn validate_rejects_unsupported_target_chain() {
        use super::{SignBidirectionalEvent, SignBidirectionalEventExt as _};
        use crate::protocol::Chain;

        let event = |target: Chain| SignBidirectionalEvent {
            sender: Default::default(),
            serialized_transaction: legacy_tx(1),
            dest: String::new(),
            caip2_id: target.caip2_chain_id().to_string(),
            key_version: 0,
            deposit: 0,
            path: "m/0".to_string(),
            algo: "ECDSA".to_string(),
            params: "{}".to_string(),
            chain: Chain::Solana,
            chain_ctx: None,
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"ok","type":"bool"}]"#.to_vec(),
        };
        assert!(event(Chain::Ethereum).validate().is_ok());
        assert!(event(Chain::Solana).validate().is_err());
    }

    #[test]
    fn test_checkpoint_consensus_bytes_deterministic_across_publish_states() {
        use super::{BidirectionalProgress, SignProgress, SignStatus};
        use crate::backlog::mock::{mock_bidi_response, mock_publishing, mock_tx};

        let dummy_tx = Arc::new(mock_tx(1));
        let dummy_respond_req = mock_bidi_response(&dummy_tx);

        let generation_tag = SignStatus::Sign(SignProgress::Generating).consensus_tag();
        let publish_tag =
            SignStatus::Sign(SignProgress::Publishing(mock_publishing())).consensus_tag();
        assert_eq!(
            generation_tag, publish_tag,
            "Generating and Publishing must produce identical consensus tags"
        );

        // Initial bidirectional phase matches standard sign
        let bidi_initial_gen_tag =
            SignStatus::Bidirectional(BidirectionalProgress::Initial(SignProgress::Generating))
                .consensus_tag();
        assert_eq!(generation_tag, bidi_initial_gen_tag);

        // Post-initial phase: target-chain execution and the final response
        // generation/publish are indistinguishable at the source-chain height.
        let execution_tag =
            SignStatus::Bidirectional(BidirectionalProgress::Executing(dummy_tx)).consensus_tag();
        let gen_bidi_tag = SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request: Arc::clone(&dummy_respond_req),
            progress: SignProgress::Generating,
        })
        .consensus_tag();
        let pub_bidi_tag = SignStatus::Bidirectional(BidirectionalProgress::Final {
            respond_request: dummy_respond_req,
            progress: SignProgress::Publishing(mock_publishing()),
        })
        .consensus_tag();
        assert_eq!(
            execution_tag, gen_bidi_tag,
            "Executing and Final Generating must share a consensus tag \
             (target-chain execution is not observable at the source-chain height)"
        );
        assert_eq!(
            gen_bidi_tag, pub_bidi_tag,
            "Final Generating and Final Publishing must produce identical consensus tags"
        );

        // The initial source-chain phase is observable at this checkpoint's height,
        // so it differs from the post-initial phase (execution / final response).
        assert_ne!(generation_tag, gen_bidi_tag);
    }
}
