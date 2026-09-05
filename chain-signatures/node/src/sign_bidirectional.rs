use crate::protocol::{Chain, IndexedSignRequest};
use alloy::primitives::{keccak256, Address};
use anyhow::Context as _;
use k256::elliptic_curve::point::AffineCoordinates;
use k256::elliptic_curve::sec1::ToEncodedPoint as _;
use k256::{AffinePoint, Scalar};
use mpc_crypto::derive_key;
pub use mpc_primitives::{BidirectionalTx, ChainFromError, SignBidirectionalEvent, Signature};
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
            Self::Bidirectional(BidirectionalProgress::Executing(_)) => false,
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
            Self::Bidirectional(BidirectionalProgress::Initial(progress)) => {
                progress.publishing()
            }
            Self::Bidirectional(BidirectionalProgress::Final { progress, .. }) => {
                progress.publishing()
            }
            Self::Bidirectional(BidirectionalProgress::Executing(_)) => None,
        }
    }

    /// Project this status onto what is observable at a checkpoint's own chain height.
    ///
    /// * `0` — the initial source-chain phase (standard Sign or initial Bidirectional).
    /// * `1` — the post-initial phase (Bidirectional awaiting target execution or final response).
    pub fn consensus_tag(&self) -> u8 {
        match self {
            Self::Sign(_) | Self::Bidirectional(BidirectionalProgress::Initial(_)) => 0,
            Self::Bidirectional(
                BidirectionalProgress::Executing(_) | BidirectionalProgress::Final { .. },
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
    /// request. Shared between admission (reject before the backlog) and the respond
    /// path's failure handling (quarantine): both must agree on what "can never
    /// advance" means.
    fn validate(&self) -> anyhow::Result<()>;
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

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.serialized_transaction.is_empty(),
            "empty serialized_transaction"
        );
        self.target_chain()
            .map_err(|err| anyhow::anyhow!("bad target chain: {err:?}"))?;
        self.epsilon().context("cannot derive epsilon")?;
        validate_unsigned_transaction(&self.serialized_transaction)
            .context("undecodable serialized_transaction")?;
        Ok(())
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

/// Check that `unsigned_rlp` would survive [`sign_and_hash_transaction`], without a
/// real signature. Admission calls this so a transaction that cannot be signed at
/// respond time is rejected before it enters the backlog; running the actual
/// function is what keeps admission structurally equal to respond processing. The
/// placeholder's recovery id is 1, the strict case: the legacy `v` computation adds
/// `y_parity`, so validating with 0 would admit the one chain id whose `v` only
/// overflows when the real signature draws parity 1.
fn validate_unsigned_transaction(unsigned_rlp: &[u8]) -> anyhow::Result<()> {
    let placeholder = Signature::new(
        k256::ProjectivePoint::GENERATOR.to_affine(),
        k256::Scalar::ONE,
        1,
    );
    sign_and_hash_transaction(unsigned_rlp, placeholder).map(|_| ())
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
        let derivation_epsilon = derive_epsilon_near(LEGACY_MPC_KEY_VERSION_0, &account_id, "test");
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

    /// At `chain_id = (u64::MAX - 35) / 2` the legacy `v = 2c + 35 + y_parity`
    /// overflows only for parity 1. Admission must reject it, not admit a request
    /// that then fails at respond time whenever the signature draws parity 1.
    #[test]
    fn validate_rejects_the_legacy_chain_id_that_only_overflows_on_parity_one() {
        let legacy_tx = |chain_id: u64| {
            let mut rlp = super::EthereumTxRlp::new_list(9);
            for _ in 0..6 {
                rlp.append_u64(0);
            }
            rlp.append_u64(chain_id);
            rlp.append_u64(0);
            rlp.append_u64(0);
            rlp.into_vec()
        };
        let boundary = (u64::MAX - 35) / 2;
        assert!(super::validate_unsigned_transaction(&legacy_tx(boundary)).is_err());
        assert!(super::validate_unsigned_transaction(&legacy_tx(boundary - 1)).is_ok());
    }

    #[test]
    fn test_checkpoint_consensus_bytes_deterministic_across_publish_states() {
        use crate::backlog::Publishing;
        use super::{BidirectionalProgress, SignProgress, SignStatus};
        use k256::Scalar;
        use mpc_primitives::{
            BidirectionalTx, BidirectionalTxId, Chain, IndexedSignRequest, RespondBidirectionalTx,
            SignArgs, SignId, SignKind, Signature,
        };

        let dummy_sig = Signature {
            big_r: k256::ProjectivePoint::GENERATOR.to_affine(),
            s: k256::Scalar::ONE,
            recovery_id: 0,
        };
        let dummy_tx = Arc::new(BidirectionalTx {
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
        });
        let publish = || Publishing::new(dummy_sig, vec![], true);
        let dummy_respond_req = Arc::new(IndexedSignRequest::new(
            SignId::new([1u8; 32]),
            SignArgs {
                entropy: [0u8; 32],
                epsilon: Scalar::ONE,
                payload: Scalar::ONE,
                path: String::new(),
                key_version: 0,
            },
            Chain::Solana,
            0,
            SignKind::RespondBidirectional(RespondBidirectionalTx {
                tx_id: dummy_tx.id,
                output: vec![],
                chain_ctx: None,
            }),
        ));

        let generation_tag = SignStatus::Sign(SignProgress::Generating).consensus_tag();
        let publish_tag = SignStatus::Sign(SignProgress::Publishing(publish())).consensus_tag();
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
            progress: SignProgress::Publishing(publish()),
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
