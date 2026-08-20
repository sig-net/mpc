use std::sync::Arc;
use std::time::Instant;

use cait_sith::FullSignature;
use k256::Secp256k1;
use mpc_crypto::PublicKey;
use mpc_primitives::{IndexedSignRequest, Participant, Signature};

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
    pub request: Arc<IndexedSignRequest>,
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
        request: Arc<IndexedSignRequest>,
        output: FullSignature<Secp256k1>,
        participants: Vec<Participant>,
    ) -> Option<Self> {
        let expected_public_key = mpc_crypto::derive_key(public_key, request.args.epsilon);
        let signature = mpc_crypto::reconstruct_signature(
            &expected_public_key,
            &output.big_r,
            &output.s,
            request.args.payload,
        )
        .ok()?;
        Some(Self {
            public_key,
            request,
            signature,
            participants,
            timestamp: Instant::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test::{make_indexed, make_signature, scalar};
    use k256::AffinePoint;
    use mpc_primitives::{Chain, SignId, SignKind};

    #[test]
    fn publish_action_accepts_valid_signature() {
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk: AffinePoint = sk.public_key().into();
        let epsilon = scalar(&[1u8; 32]);
        let payload = scalar(&[42u8; 32]);

        let output = make_signature(&sk, epsilon, payload);
        let request = make_indexed(
            Chain::NEAR,
            epsilon,
            payload,
            SignKind::Sign,
            SignId::new([0u8; 32]),
        );

        assert!(PublishAction::new(pk, Arc::new(request), output, vec![]).is_some());
    }

    #[test]
    fn publish_action_rejects_invalid_signature() {
        let sk = k256::SecretKey::random(&mut rand::thread_rng());
        let pk: AffinePoint = sk.public_key().into();
        let epsilon = scalar(&[1u8; 32]);
        let payload = scalar(&[42u8; 32]);

        let mut output = make_signature(&sk, epsilon, payload);
        output.s += k256::Scalar::ONE;
        let request = make_indexed(
            Chain::NEAR,
            epsilon,
            payload,
            SignKind::Sign,
            SignId::new([0u8; 32]),
        );

        assert!(PublishAction::new(pk, Arc::new(request), output, vec![]).is_none());
    }
}
