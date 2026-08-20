use crate::protocol::{Chain, IndexedSignRequest};
use alloy::primitives::{keccak256, Address, Bytes};
use cait_sith::protocol::Participant;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use k256::{AffinePoint, Scalar};
use mpc_crypto::derive_key;
use mpc_primitives::{BidirectionalTx, ChainFromError, SignBidirectionalEvent, Signature};
use rlp::{Rlp, RlpStream};

pub type RequestId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PublishState {
    pub signature: Signature,
    pub participants: Vec<Participant>,
    pub is_proposer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignStatus {
    PendingGeneration,
    PendingPublish { publish: PublishState },
    PendingExecution { tx: BidirectionalTx },
    PendingGenerationBidirectional,
    PendingPublishBidirectional { publish: PublishState },
}

impl SignStatus {
    pub fn is_pending_generation(&self) -> bool {
        matches!(
            self,
            SignStatus::PendingGeneration | SignStatus::PendingGenerationBidirectional
        )
    }

    pub fn is_pending_execution(&self) -> bool {
        matches!(self, SignStatus::PendingExecution { .. })
    }

    /// Project this status onto what is observable at a checkpoint's own chain height.
    ///
    /// A source-chain checkpoint cannot observe either of the distinguishing axes
    /// below, so the status collapses into one of two phases:
    ///
    /// * `0` — the initial source-chain phase (`PendingGeneration` /
    ///   `PendingPublish`). Generation and publication are local attempts to reach
    ///   the initial on-chain response: only a signature's participants advance to
    ///   publishing, so nodes cannot be required to agree on which of the two a
    ///   request is in.
    /// * `1` — the post-initial phase (`PendingExecution`,
    ///   `PendingGenerationBidirectional`, `PendingPublishBidirectional`). Once the
    ///   initial response has been produced, the remaining progress — awaiting
    ///   target-chain execution and then signing/publishing the final response — is
    ///   not observable at the source-chain checkpoint height. Nodes therefore
    ///   cannot be required to agree on whether a request is still awaiting
    ///   execution or already in the final-response generation/publish step, so all
    ///   of these statuses share a single tag.
    pub fn consensus_tag(&self) -> u8 {
        match self {
            SignStatus::PendingGeneration | SignStatus::PendingPublish { .. } => 0,
            SignStatus::PendingExecution { .. }
            | SignStatus::PendingGenerationBidirectional
            | SignStatus::PendingPublishBidirectional { .. } => 1,
        }
    }

    pub fn execution_tx(&self) -> Option<&BidirectionalTx> {
        match self {
            SignStatus::PendingExecution { tx } => Some(tx),
            _ => None,
        }
    }
}

/// Extension trait for `SignBidirectionalEvent` to provide additional helper methods.
pub trait SignBidirectionalEventExt {
    fn sender_string(&self) -> anyhow::Result<String>;
    fn epsilon(&self) -> anyhow::Result<Scalar>;
    fn target_chain(&self) -> Result<Chain, ChainFromError>;
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
            )),
            Chain::Hydration => Ok(mpc_crypto::kdf::derive_epsilon_hydration(
                self.key_version,
                &self.sender_string()?,
                &self.path,
            )),
            Chain::Canton => Ok(mpc_crypto::kdf::derive_epsilon_canton(
                self.key_version,
                &self.sender_string()?,
                &self.path,
            )),
            Chain::Midnight => Ok(mpc_crypto::kdf::derive_epsilon_midnight(
                self.key_version,
                &self.sender_string()?,
                &self.path,
            )),
            _ => anyhow::bail!("Unsupported chain for epsilon derivation: {:?}", self.chain),
        }
    }

    fn target_chain(&self) -> Result<Chain, mpc_primitives::ChainFromError> {
        Chain::from_caip2_chain_id(&self.caip2_id)
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
            )),
            Chain::Hydration => Ok(mpc_crypto::kdf::derive_epsilon_hydration(
                self.key_version,
                &self.sender_string()?,
                path,
            )),
            Chain::Canton => Ok(mpc_crypto::kdf::derive_epsilon_canton(
                self.key_version,
                &self.sender_string()?,
                path,
            )),
            Chain::Midnight => Ok(mpc_crypto::kdf::derive_epsilon_midnight(
                self.key_version,
                &self.sender_string()?,
                path,
            )),
            _ => anyhow::bail!("Unsupported chain: {}", self.source_chain),
        }
    }
}

pub fn decode_rlp(rlp_data: Vec<u8>, is_eip1559: bool) -> anyhow::Result<Vec<Bytes>> {
    let payload = if is_eip1559 {
        &rlp_data[1..]
    } else {
        &rlp_data
    };

    let rlp = rlp::Rlp::new(payload);

    if !rlp.is_list() {
        anyhow::bail!("Input is not a valid RLP list");
    }

    let mut result = Vec::new();

    for i in 0..rlp.item_count()? {
        let item = rlp.at(i)?;
        result.push(Bytes::copy_from_slice(item.data()?));
    }

    Ok(result)
}

pub fn sign_and_hash_transaction(
    unsigned_rlp: &[u8],
    signature: Signature,
) -> anyhow::Result<([u8; 32], u64)> {
    let r = signature.big_r.x().as_slice().to_vec();
    let s = signature.s.to_bytes().as_slice().to_vec();
    let y_parity = signature.recovery_id == 1;

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
    let v: u64 = 35 + 2 * chain_id.unwrap_or(0) + if y_parity { 1 } else { 0 };
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
        let derivation_epsilon = derive_epsilon_near(LEGACY_MPC_KEY_VERSION_0, &account_id, "test");
        let expected: Address = "0x083c8776b5e447e91bae43b7883a92a9bdb66d1d"
            .parse()
            .unwrap();

        assert_eq!(derive_user_address(mpc_pk, derivation_epsilon), expected);
    }
}

#[derive(Clone)]
pub struct SignBidirectionalSignature {
    pub public_key: mpc_crypto::PublicKey,
    pub request: IndexedSignRequest,
    pub signature: Signature,
}

#[cfg(test)]
mod tests {
    use super::sign_and_hash_eip1559_from_unsigned;
    use alloy::consensus::{SignableTransaction, TxEip1559};
    use alloy::eips::eip2718::Encodable2718;
    use alloy::primitives::{Bytes, FixedBytes, Signature, TxKind, U256};

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

    #[test]
    fn test_checkpoint_consensus_bytes_deterministic_across_publish_states() {
        use super::{PublishState, SignStatus};
        use mpc_primitives::{BidirectionalTx, BidirectionalTxId, Chain, Signature};

        let dummy_sig = Signature {
            big_r: k256::ProjectivePoint::GENERATOR.to_affine(),
            s: k256::Scalar::ONE,
            recovery_id: 0,
        };
        let dummy_tx = BidirectionalTx {
            id: BidirectionalTxId([1u8; 32]),
            sender: [0u8; 32],
            serialized_transaction: vec![],
            source_chain: Chain::Solana,
            target_chain: Chain::Ethereum,
            caip2_id: String::new(),
            key_version: 0,
            deposit: 0,
            path: String::new(),
            algo: String::new(),
            dest: String::new(),
            params: String::new(),
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
            request_id: [1u8; 32],
            from_address: [0u8; 20],
            nonce: 0,
        };
        let publish = || PublishState {
            signature: dummy_sig,
            participants: vec![],
            is_proposer: true,
        };

        let generation_tag = SignStatus::PendingGeneration.consensus_tag();
        let publish_tag = SignStatus::PendingPublish { publish: publish() }.consensus_tag();
        assert_eq!(
            generation_tag, publish_tag,
            "PendingGeneration and PendingPublish must produce identical consensus tags"
        );

        // Post-initial phase: target-chain execution and the final response
        // generation/publish are indistinguishable at the source-chain height.
        let execution_tag = SignStatus::PendingExecution { tx: dummy_tx }.consensus_tag();
        let gen_bidi_tag = SignStatus::PendingGenerationBidirectional.consensus_tag();
        let pub_bidi_tag =
            SignStatus::PendingPublishBidirectional { publish: publish() }.consensus_tag();
        assert_eq!(
            execution_tag, gen_bidi_tag,
            "PendingExecution and PendingGenerationBidirectional must share a consensus tag \
             (target-chain execution is not observable at the source-chain height)"
        );
        assert_eq!(
            gen_bidi_tag, pub_bidi_tag,
            "PendingGenerationBidirectional and PendingPublishBidirectional must produce identical consensus tags"
        );

        // The initial source-chain phase is observable at this checkpoint's height,
        // so it differs from the post-initial phase (execution / final response).
        assert_ne!(generation_tag, gen_bidi_tag);
    }
}
