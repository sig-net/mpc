use std::time::Instant;

use cait_sith::protocol::Participant;
use cait_sith::FullSignature;
use k256::Secp256k1;
use mpc_crypto::PublicKey;
use mpc_primitives::{IndexedSignRequest, Signature};

/// Trait for publishing signatures to different blockchains (single attempt, caller handles retries).
#[async_trait::async_trait]
pub trait ChainPublisher: Send + Sync + 'static {
    /// Accepts a publish action. The publisher encapsulates how this is executed
    /// (e.g., immediate spawn, or pushing to an internal batching queue).
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()>;
}

/// Represents a signature that is ready to be published to a blockchain.
#[derive(Clone)]
pub struct PublishAction {
    /// The public key associated with the signature.
    pub public_key: PublicKey,
    /// The indexed sign request that this signature corresponds to.
    pub indexed: IndexedSignRequest,
    /// The actual signature to be published.
    pub signature: Signature,
    /// The participants involved in the signing process.
    pub participants: Vec<Participant>,
    /// The timestamp when the publish action was created.
    pub timestamp: Instant,
}

impl PublishAction {
    pub fn new(
        public_key: PublicKey,
        indexed: IndexedSignRequest,
        output: FullSignature<Secp256k1>,
        participants: Vec<Participant>,
    ) -> Option<Self> {
        let expected_public_key = mpc_crypto::derive_key(public_key, indexed.args.epsilon);
        let signature = mpc_crypto::reconstruct_signature(
            &expected_public_key,
            &output.big_r,
            &output.s,
            indexed.args.payload,
        )
        .ok()?;
        Some(Self {
            public_key,
            indexed,
            signature,
            participants,
            timestamp: Instant::now(),
        })
    }
}
