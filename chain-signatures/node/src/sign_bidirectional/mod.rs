//! Bidirectional signing: event admission, response construction, and the
//! backlog-facing progress state. Chain-targeted signing lives in `signing`,
//! the Ethereum wire encoding in `eth_tx`.

mod eth_tx;
mod progress;
mod signing;

use crate::protocol::Chain;
use anyhow::Context as _;
use k256::Scalar;
use mpc_primitives::ChainConfig as _;
use mpc_primitives::LATEST_MPC_KEY_VERSION;
pub use mpc_primitives::{
    BidirectionalTx, BidirectionalTxId, ChainFromError, SignBidirectionalEvent, Signature,
};

pub use eth_tx::{derive_user_address, public_key_to_address};
pub use progress::{BidirectionalProgress, SignProgress, SignStatus};
pub use signing::sign_and_hash_transaction;
use signing::validate_unsigned_transaction;
pub(crate) use signing::{owned_by_requester, pending_destination_id, transaction_chain_id};

/// The requester's chain-local identity string: Midnight and Canton senders
/// are 32-byte addresses whose canonical form is the lowercase hex of those
/// bytes; other chains format natively.
fn source_chain_sender_string(sender: [u8; 32], chain: Chain) -> anyhow::Result<String> {
    match chain {
        Chain::Canton | Chain::Midnight => Ok(hex::encode(sender)),
        _ => crate::stream::ops::sender_string(sender, chain),
    }
}

/// Derives the request key's epsilon on the requester's chain.
fn derive_epsilon(
    chain: Chain,
    key_version: u32,
    sender_string: &str,
    path: &str,
) -> anyhow::Result<Scalar> {
    match chain {
        Chain::Solana => Ok(mpc_crypto::kdf::derive_epsilon_sol(
            key_version,
            sender_string,
            path,
        )?),
        Chain::Hydration => Ok(mpc_crypto::kdf::derive_epsilon_hydration(
            key_version,
            sender_string,
            path,
        )?),
        Chain::Canton => Ok(mpc_crypto::kdf::derive_epsilon_canton(
            key_version,
            sender_string,
            path,
        )?),
        Chain::Midnight => Ok(mpc_crypto::kdf::derive_epsilon_midnight(
            key_version,
            sender_string,
            path,
        )?),
        _ => anyhow::bail!("unsupported chain for epsilon derivation: {chain}"),
    }
}

/// The only `(algo, dest, params)` a request may carry (Section 7.1 of
/// doc/bidirectional-calls.md). The node signs ECDSA whatever they say, but they
/// enter the request id, so any other value would give one execution a second
/// request id (G2). `dest` is deprecated: it has no meaning and stays blank until
/// it leaves the request id with the Section 7 format.
pub(crate) const SDK_REQUEST_FIELDS: (&str, &str, &str) = ("ECDSA", "", "");

/// Key version [`LATEST_MPC_KEY_VERSION`] and [`SDK_REQUEST_FIELDS`].
fn check_request_fields(event: &SignBidirectionalEvent) -> anyhow::Result<()> {
    anyhow::ensure!(
        event.key_version == LATEST_MPC_KEY_VERSION,
        "key version must be {LATEST_MPC_KEY_VERSION}, got {}",
        event.key_version
    );
    // Midnight's record holds these fields as enums, and its decoder refuses every
    // value but the one it renders (chain-midnight convert.rs).
    if event.chain == Chain::Midnight {
        return Ok(());
    }
    let fields = (
        event.algo.as_str(),
        event.dest.as_str(),
        event.params.as_str(),
    );
    anyhow::ensure!(
        fields == SDK_REQUEST_FIELDS,
        "(algo, dest, params) must be {SDK_REQUEST_FIELDS:?}, got {fields:?}"
    );
    Ok(())
}

/// Extension trait for `SignBidirectionalEvent` to provide additional helper methods.
pub trait SignBidirectionalEventExt {
    fn sender_string(&self) -> anyhow::Result<String>;
    fn epsilon(&self) -> anyhow::Result<Scalar>;
    fn target_chain(&self) -> Result<Chain, ChainFromError>;
    /// The destination id before signing, when the target defines one without
    /// the signature: Tron's txID is sha256 of the raw bytes, flat across
    /// requests with identical bytes. `None` for Ethereum and any target whose
    /// id covers the signature — there is nothing to compare pre-signing.
    fn flat_destination_id(&self) -> Option<BidirectionalTxId>;

    /// The deterministic derivations respond processing runs for every bidirectional
    /// request, the schema checks output extraction applies to whatever the target
    /// chain returns, and the reserved request fields. Shared between admission (reject before the backlog)
    /// and the respond path's failure handling (quarantine): both must agree on
    /// what "can never advance" means.
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
        source_chain_sender_string(self.sender, self.chain)
    }

    fn epsilon(&self) -> anyhow::Result<Scalar> {
        derive_epsilon(
            self.chain,
            self.key_version,
            &self.sender_string()?,
            &self.path,
        )
    }

    fn target_chain(&self) -> Result<Chain, mpc_primitives::ChainFromError> {
        Chain::from_caip2_chain_id(&self.caip2_id)
    }

    fn flat_destination_id(&self) -> Option<BidirectionalTxId> {
        let target = self.target_chain().ok()?;
        pending_destination_id(target, &self.serialized_transaction)
            .ok()
            .flatten()
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
            target.supports_bidirectional_signing(),
            "unsupported target chain {target}"
        );
        check_request_fields(self)?;
        self.epsilon().context("cannot derive epsilon")?;
        // TODO(tron): once the record carries structured params, admission
        // must enforce §6.1's expiration bound (future, ≤ 24 h past the
        // request's Midnight timestamp); raw bytes carry no request timestamp
        // to check against. Owner binding (`owned_by_requester`) and duplicate
        // destination-id rejection already run at ingestion; the expiry→Unviable
        // scan must cover backlog entries, not just watchers.
        let calldata = validate_unsigned_transaction(target, &self.serialized_transaction)
            .context("undecodable serialized_transaction")?;
        match calldata {
            Some(calldata) => mpc_chain_ethereum::validate_schemas(
                calldata,
                &self.output_deserialization_schema,
                self.chain.respond_serialization_format(),
                &self.respond_serialization_schema,
            )
            .context("unprocessable output schemas"),
            // Tron: receipt-based output extraction arrives with the execution
            // watcher, which also defines its schemas; until then admission
            // requires a Tron target to carry none.
            None => {
                anyhow::ensure!(
                    self.output_deserialization_schema.is_empty()
                        && self.respond_serialization_schema.is_empty(),
                    "Tron targets define no output schemas yet"
                );
                Ok(())
            }
        }
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
        // TODO(tron): `from_address` is EVM-shaped; Tron consumers need the
        // derived key's Tron address (same EVM math, 0x41-prefixed form).
        let (signed_tx_hash, nonce) =
            sign_and_hash_transaction(target_chain, &self.serialized_transaction, mpc_sig)?;

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
        source_chain_sender_string(self.sender, self.source_chain)
    }

    fn epsilon(&self, path: &str) -> anyhow::Result<Scalar> {
        derive_epsilon(
            self.source_chain,
            self.key_version,
            &self.sender_string()?,
            path,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::eth_tx::legacy_tx;
    use super::{
        SignBidirectionalEvent, SignBidirectionalEventExt as _, Signature, LATEST_MPC_KEY_VERSION,
        SDK_REQUEST_FIELDS,
    };
    use crate::protocol::Chain;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::{AffinePoint, EncodedPoint};

    /// Recorded mainnet USDT transfer (chain-tron fixture `usdt-transfer-1.json`)
    const RAW_HEX: &str = "0a02db6f220815ff9c9c504ad4a8409a80f5a491345aae01081f12a9010a31747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e54726967676572536d617274436f6e747261637412740a154120eb85916a10d2c6542613e4c9517b5e99b2dee9121541a614f803b6fd780986a42c78ec9c7f77e6ded13c2244a9059cbb000000000000000000000000d9e02baf48ed306afc63cfa816a2b6be8442036a0000000000000000000000000000000000000000000000000000000008f428f870bad8e2a49134900180e1eb17";
    const TXID_HEX: &str = "d3741faef8cd6594923d7d827b610b12ce9bc80f65822c827c8fd7a612570540";

    fn solana_event(target: Chain) -> SignBidirectionalEvent {
        SignBidirectionalEvent {
            sender: Default::default(),
            serialized_transaction: legacy_tx(1),
            dest: SDK_REQUEST_FIELDS.1.to_string(),
            caip2_id: target.caip2_chain_id().to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: "m/0".to_string(),
            algo: SDK_REQUEST_FIELDS.0.to_string(),
            params: SDK_REQUEST_FIELDS.2.to_string(),
            chain: Chain::Solana,
            chain_ctx: None,
            output_deserialization_schema: vec![],
            respond_serialization_schema: br#"[{"name":"ok","type":"bool"}]"#.to_vec(),
        }
    }

    #[test]
    fn validate_rejects_unsupported_target_chain() {
        assert!(solana_event(Chain::Ethereum).validate().is_ok());
        assert!(solana_event(Chain::Solana).validate().is_err());
    }

    #[test]
    fn validate_accepts_only_key_version_1_and_the_sdk_fields() {
        type Edit = fn(&mut SignBidirectionalEvent);
        let cases: [(&str, Edit, bool); 14] = [
            ("as the SDKs send it", |_| {}, true),
            ("from Hydration", |e| e.chain = Chain::Hydration, true),
            (
                "from Hydration at key version 0",
                |e| {
                    e.chain = Chain::Hydration;
                    e.key_version = 0;
                },
                false,
            ),
            (
                "from Hydration, algo lowercase",
                |e| {
                    e.chain = Chain::Hydration;
                    e.algo = "ecdsa".to_string();
                },
                false,
            ),
            ("from Canton", |e| e.chain = Chain::Canton, true),
            ("key version 0", |e| e.key_version = 0, false),
            ("key version 2", |e| e.key_version = 2, false),
            (
                "algo secp256k1",
                |e| e.algo = "secp256k1".to_string(),
                false,
            ),
            ("algo lowercase", |e| e.algo = "ecdsa".to_string(), false),
            ("dest ethereum", |e| e.dest = "ethereum".to_string(), false),
            ("dest tron", |e| e.dest = "tron".to_string(), false),
            ("params {}", |e| e.params = "{}".to_string(), false),
            (
                "from Midnight, as its decoder renders it",
                |e| {
                    e.chain = Chain::Midnight;
                    e.algo = "ecdsa".to_string();
                },
                true,
            ),
            (
                "from Midnight at key version 0",
                |e| {
                    e.chain = Chain::Midnight;
                    e.key_version = 0;
                },
                false,
            ),
        ];
        for (case, edit, accepted) in cases {
            let mut event = solana_event(Chain::Ethereum);
            edit(&mut event);
            assert_eq!(event.validate().is_ok(), accepted, "{case}");
        }
    }

    fn tron_event(bytes: Vec<u8>) -> SignBidirectionalEvent {
        SignBidirectionalEvent {
            sender: Default::default(),
            serialized_transaction: bytes,
            dest: String::new(),
            caip2_id: Chain::Tron.caip2_chain_id().to_string(),
            key_version: 1,
            deposit: 0,
            path: "m/0".to_string(),
            algo: "ECDSA".to_string(),
            params: "{}".to_string(),
            chain: Chain::Midnight,
            chain_ctx: None,
            output_deserialization_schema: vec![],
            respond_serialization_schema: vec![],
        }
    }

    #[test]
    fn validate_rejects_bytes_that_are_not_tron_raw() {
        // Ethereum RLP routed to a Tron target.
        assert!(tron_event(legacy_tx(1)).validate().is_err());

        // Truncated Tron raw bytes.
        assert!(tron_event(vec![0x0a, 0x02, 0xdb]).validate().is_err());
    }

    #[test]
    fn validate_and_sign_accept_a_tron_target() {
        let unsigned = hex::decode(RAW_HEX).unwrap();

        let event = tron_event(unsigned.clone());
        assert!(event.validate().is_ok());

        // The txID is sha256(raw_data): independent of the signature, so any
        // (low-s normalized) signature names the same transaction.
        let big_r = k256::ProjectivePoint::GENERATOR.to_affine();
        let id_of = |s, recovery_id| {
            super::sign_and_hash_transaction(
                Chain::Tron,
                &unsigned,
                mpc_primitives::Signature::new(big_r, s, recovery_id),
            )
            .unwrap()
        };
        let low = k256::Scalar::from(5u64);
        let (id_low, nonce) = id_of(low, 1);
        let (id_high, _) = id_of(-low, 0);
        assert_eq!(id_low, id_high);
        assert_eq!(nonce, 0);
        assert_eq!(hex::encode(id_low), TXID_HEX);
    }

    #[test]
    fn pending_destination_id_is_flat_only_for_tron() {
        let raw = hex::decode(RAW_HEX).unwrap();
        let id = super::pending_destination_id(Chain::Tron, &raw)
            .unwrap()
            .expect("tron ids exist before signing");
        assert_eq!(hex::encode(id.0), TXID_HEX);
        // Ethereum's id hashes the signed transaction: nothing to compare
        // pre-signing.
        assert!(super::pending_destination_id(Chain::Ethereum, &raw)
            .unwrap()
            .is_none());
    }

    #[test]
    fn flat_destination_id_reads_the_event() {
        let mut event = tron_event(hex::decode(RAW_HEX).unwrap());
        assert_eq!(
            hex::encode(event.flat_destination_id().unwrap().0),
            TXID_HEX
        );
        event.dest = Chain::Ethereum.to_string();
        event.caip2_id = Chain::Ethereum.caip2_chain_id().to_string();
        assert!(event.flat_destination_id().is_none());
    }

    #[test]
    fn to_bidirectional_tx_pins_the_tron_placeholder() {
        const FROM_ADDRESS_HEX: &str = "f0e7701dff7663ad180b34ff9f32b937a166f481";

        let mpc_key = hex::decode("045b4fa179e005361fd858f8a6f896d7afc23a53d3f95d6566a88cde954e7b2f1cb77c554705c35d4ffced67aeafbcda46d9d89d6f200c3a3d109f92872863b3dc").unwrap();
        let encoded = EncodedPoint::from_bytes(mpc_key).unwrap();
        let root_pk = AffinePoint::from_encoded_point(&encoded).unwrap();

        let event = SignBidirectionalEvent {
            sender: [0u8; 32],
            serialized_transaction: hex::decode(RAW_HEX).unwrap(),
            ..tron_event(Vec::new())
        };
        let sig = Signature::new(
            k256::ProjectivePoint::GENERATOR.to_affine(),
            k256::Scalar::ONE,
            1,
        );

        let tx = event.to_bidirectional_tx([7u8; 32], sig, root_pk).unwrap();

        assert_eq!(tx.target_chain, Chain::Tron);
        assert_eq!(tx.source_chain, Chain::Midnight);
        assert_eq!(hex::encode(tx.id.0), TXID_HEX);
        assert_eq!(tx.nonce, 0);
        assert_eq!(hex::encode(tx.from_address), FROM_ADDRESS_HEX);
        assert_eq!(tx.serialized_transaction, hex::decode(RAW_HEX).unwrap());
    }
}
