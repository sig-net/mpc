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
use mpc_primitives::{IndexedSignRequest, SignKind};

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

/// The only `algo`, `dest` and `params` a request may carry (Section 7.1 of
/// doc/bidirectional-calls.md). The node signs ECDSA whatever they say, but they
/// enter the request id, so any other value would give one execution a second
/// request id (G2). `dest` is deprecated: it has no meaning and stays blank until
/// it leaves the request id with the Section 7 format.
pub(crate) const SDK_ALGO: &str = "ECDSA";
pub(crate) const SDK_DEST: &str = "";
pub(crate) const SDK_PARAMS: &str = "";

/// Key version 0 predates bidirectional signing.
const MIN_BIDIRECTIONAL_KEY_VERSION: u32 = 1;

/// Reserved for bidirectional paths where plain `sign` shares their keys, so plain
/// sign cannot use up a bidirectional request's nonce.
pub(crate) const BIDIRECTIONAL_PATH_PREFIX: &str = "bidirectional/";

/// The prefix bidirectional paths on `chain` must start with, where plain `sign`
/// derives the same key from the same sender, path and key version.
fn bidirectional_namespace(chain: Chain) -> Option<&'static str> {
    matches!(chain, Chain::Solana | Chain::Hydration).then_some(BIDIRECTIONAL_PATH_PREFIX)
}

/// Whether `request` is a plain sign request naming a path reserved for bidirectional
/// requests.
pub(crate) fn claims_bidirectional_namespace(request: &IndexedSignRequest) -> bool {
    matches!(request.kind, SignKind::Sign)
        && bidirectional_namespace(request.chain)
            .is_some_and(|prefix| request.args.path.starts_with(prefix))
}

/// Whether `event`'s path lies in its chain's namespace. True where there is none.
fn path_in_namespace(event: &SignBidirectionalEvent) -> bool {
    bidirectional_namespace(event.chain).is_none_or(|prefix| event.path.starts_with(prefix))
}

/// Key version in `MIN_BIDIRECTIONAL_KEY_VERSION..=LATEST_MPC_KEY_VERSION`, and
/// [`SDK_ALGO`], [`SDK_DEST`] and [`SDK_PARAMS`].
fn check_request_fields(event: &SignBidirectionalEvent) -> anyhow::Result<()> {
    anyhow::ensure!(
        event.key_version >= MIN_BIDIRECTIONAL_KEY_VERSION,
        "key version must be at least {MIN_BIDIRECTIONAL_KEY_VERSION}, got {}",
        event.key_version
    );
    anyhow::ensure!(
        event.key_version <= LATEST_MPC_KEY_VERSION,
        "key version must be at most {LATEST_MPC_KEY_VERSION}, got {}",
        event.key_version
    );
    let fields = (
        event.algo.as_str(),
        event.dest.as_str(),
        event.params.as_str(),
    );
    let expected = (SDK_ALGO, SDK_DEST, SDK_PARAMS);
    anyhow::ensure!(
        fields == expected,
        "(algo, dest, params) must be {expected:?}, got {fields:?}"
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
    /// request, and the schema checks output extraction applies to whatever the
    /// target chain returns. Shared between admission (reject before the backlog)
    /// and the respond path's failure handling (quarantine): both must agree on
    /// what "can never advance" means. Off-spec reserved request fields are only
    /// logged for now.
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
        // Only warns until the applications send these fields; refusing them
        // follows once the warnings stop.
        if let Err(err) = check_request_fields(self) {
            tracing::warn!(
                source_chain = ?self.chain,
                sender = ?self.sender_string().ok(),
                "accepting off-spec bidirectional request fields: {err:#}"
            );
        }
        // Only warns until the senders move their paths into the namespace.
        if !path_in_namespace(self) {
            tracing::warn!(
                source_chain = ?self.chain,
                sender = ?self.sender_string().ok(),
                path = %self.path,
                "accepting a bidirectional path outside {BIDIRECTIONAL_PATH_PREFIX:?}"
            );
        }
        self.epsilon().context("cannot derive epsilon")?;
        // TODO(tron): enforce §4.3's bound t_src < expiration ≤ t_src +
        // 24 h. The raw bytes carry `expiration`; the missing pipe is the
        // source time (event has none, Midnight reports block_timestamp:
        // None) — thread indexed_ts into validate or expose block time.
        // The expiry→Unviable scan must cover backlog entries, not just
        // watchers.
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
        // EVM-shaped; Tron consumers wrap it with `TronAddress::from_evm`.
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
        SignBidirectionalEvent, SignBidirectionalEventExt as _, Signature,
        BIDIRECTIONAL_PATH_PREFIX, LATEST_MPC_KEY_VERSION, SDK_ALGO, SDK_DEST, SDK_PARAMS,
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
            dest: SDK_DEST.to_string(),
            caip2_id: target.caip2_chain_id().to_string(),
            key_version: LATEST_MPC_KEY_VERSION,
            deposit: 0,
            path: format!("{BIDIRECTIONAL_PATH_PREFIX}m/0"),
            algo: SDK_ALGO.to_string(),
            params: SDK_PARAMS.to_string(),
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
    fn validate_accepts_off_spec_fields_for_now() {
        let mut event = solana_event(Chain::Ethereum);
        event.algo = "ecdsa".to_string();
        event.dest = "ethereum".to_string();
        event.params = "{}".to_string();
        event.path = "m/0".to_string();
        assert!(super::check_request_fields(&event).is_err());
        assert!(!super::path_in_namespace(&event));
        assert!(event.validate().is_ok());
    }

    #[test]
    fn check_request_fields_accepts_only_key_version_1_and_the_sdk_fields() {
        type Edit = fn(&mut SignBidirectionalEvent);
        let cases: [(&str, Edit, bool); 15] = [
            ("on spec", |_| {}, true),
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
            ("from Midnight", |e| e.chain = Chain::Midnight, true),
            (
                "from Midnight, algo lowercase",
                |e| {
                    e.chain = Chain::Midnight;
                    e.algo = "ecdsa".to_string();
                },
                false,
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
            assert_eq!(
                super::check_request_fields(&event).is_ok(),
                accepted,
                "{case}"
            );
        }
    }

    #[test]
    fn path_in_namespace_only_where_plain_sign_shares_keys() {
        let cases = [
            (Chain::Solana, "bidirectional/m/0", true),
            (Chain::Solana, "bidirectional/", true),
            (Chain::Solana, "m/0", false),
            (Chain::Solana, "bidirectional", false),
            (Chain::Hydration, "bidirectional/m/0", true),
            (Chain::Hydration, "m/0", false),
            (Chain::Canton, "m/0", true),
            (Chain::Midnight, "m/0", true),
        ];
        for (chain, path, inside) in cases {
            let mut event = solana_event(Chain::Ethereum);
            event.chain = chain;
            event.path = path.to_string();
            assert_eq!(super::path_in_namespace(&event), inside, "{chain} {path}");
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
            params: String::new(),
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
