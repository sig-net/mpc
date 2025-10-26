//! Wrapper crate for `near/threshold-signatures` implementing the `ThresholdSigner` trait.

use async_trait::async_trait;
use cait_sith::protocol::{Participant, Protocol as CaitSithProtocol};
use k256::{AffinePoint, Scalar, Secp256k1};
use mpc_crypto::signing::{
    Action, ProtocolError, SigningError, ThresholdProtocol, ThresholdSigner,
};
use mpc_crypto::ScalarExt;
use serde_json;
use threshold_signatures;

/// Implementation of `ThresholdSigner` using `cait-sith` (existing backend).
pub struct CaitSithAdapter;

impl CaitSithAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ThresholdSigner for CaitSithAdapter {
    fn keygen_protocol(
        &self,
        participants: &[Participant],
        me: Participant,
        threshold: usize,
    ) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError> {
        // cait_sith only supports ECDSA
        let protocol = cait_sith::keygen::<Secp256k1>(participants, me, threshold)
            .map_err(|e| SigningError::ProtocolError(format!("keygen failed: {:?}", e)))?;
        Ok(Box::new(CaitSithProtocolWrapper(protocol)))
    }

    fn presign_protocol(
        &self,
        _participants: &[Participant],
        _me: Participant,
        _keygen_output: &[u8],
    ) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError> {
        // CaitSith requires pre-computed triples for presign, which are not available
        // in this abstraction layer. The existing MPC system handles presignatures
        // through a separate workflow that manages triples internally.
        Err(SigningError::ProtocolError(
            "presign protocol not supported in ThresholdSigner abstraction - use existing presignature system".to_string(),
        ))
    }

    fn sign_protocol(
        &self,
        participants: &[Participant],
        me: Participant,
        keygen_output: &[u8],
        presign_output: &[u8],
        message: &[u8],
    ) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError> {
        // Deserialize inputs
        let keygen_result: cait_sith::KeygenOutput<Secp256k1> =
            serde_json::from_slice(keygen_output).map_err(|e| {
                SigningError::ProtocolError(format!("failed to deserialize keygen output: {}", e))
            })?;

        // Manually deserialize PresignOutput like Presignature does
        #[derive(serde::Deserialize)]
        struct PresignFields {
            output_big_r: AffinePoint,
            output_k: Scalar,
            output_sigma: Scalar,
        }

        let fields: PresignFields = serde_json::from_slice(presign_output).map_err(|e| {
            SigningError::ProtocolError(format!("failed to deserialize presign output: {}", e))
        })?;

        let presign_result = cait_sith::PresignOutput {
            big_r: fields.output_big_r,
            k: fields.output_k,
            sigma: fields.output_sigma,
        };

        // Convert message from &[u8] to Scalar (assuming it's a 32-byte big-endian representation)
        if message.len() != 32 {
            return Err(SigningError::ProtocolError(format!(
                "message must be 32 bytes, got {}",
                message.len()
            )));
        }
        let message_scalar = Scalar::from_bytes(message.try_into().unwrap())
            .ok_or_else(|| SigningError::ProtocolError("invalid message scalar".to_string()))?;

        // Create sign protocol using cait_sith
        let protocol = cait_sith::sign::<Secp256k1>(
            participants,
            me,
            keygen_result.public_key, // Remove the borrow
            presign_result,
            message_scalar, // Use the converted scalar
        )
        .map_err(|e| SigningError::ProtocolError(format!("sign failed: {:?}", e)))?;

        Ok(Box::new(CaitSithProtocolWrapper(protocol)))
    }
}

/// Wrapper to adapt cait_sith protocols to the ThresholdProtocol interface.
pub struct CaitSithProtocolWrapper<P>(pub P);

impl<P> ThresholdProtocol for CaitSithProtocolWrapper<P>
where
    P: CaitSithProtocol,
    P::Output: 'static,
{
    fn poke(&mut self) -> Result<Action, ProtocolError> {
        match self.0.poke() {
            Ok(cait_sith::protocol::Action::Wait) => Ok(Action::Wait),
            Ok(cait_sith::protocol::Action::SendMany(data)) => Ok(Action::SendMany(data)),
            Ok(cait_sith::protocol::Action::SendPrivate(to, data)) => {
                Ok(Action::SendPrivate(to, data))
            }
            Ok(cait_sith::protocol::Action::Return(output)) => {
                // Manually serialize cait_sith output types since they don't implement Serialize
                use std::any::Any;
                let data = if let Some(keygen_output) =
                    (&output as &dyn Any).downcast_ref::<cait_sith::KeygenOutput<Secp256k1>>()
                {
                    serde_json::to_vec(&serde_json::json!({
                        "private_share": keygen_output.private_share,
                        "public_key": keygen_output.public_key
                    }))
                } else if let Some(presign_output) =
                    (&output as &dyn Any).downcast_ref::<cait_sith::PresignOutput<Secp256k1>>()
                {
                    serde_json::to_vec(&serde_json::json!({
                        "big_r": presign_output.big_r,
                        "k": presign_output.k,
                        "sigma": presign_output.sigma
                    }))
                } else if let Some(full_sig) =
                    (&output as &dyn Any).downcast_ref::<cait_sith::FullSignature<Secp256k1>>()
                {
                    serde_json::to_vec(&serde_json::json!({
                        "big_r": full_sig.big_r,
                        "s": full_sig.s
                    }))
                } else {
                    return Err(ProtocolError::ProtocolError(
                        "unknown output type".to_string(),
                    ));
                }
                .map_err(|e| {
                    ProtocolError::ProtocolError(format!("serialization failed: {}", e))
                })?;
                Ok(Action::Success(data))
            }
            Err(e) => Err(ProtocolError::ProtocolError(format!(
                "protocol error: {:?}",
                e
            ))),
        }
    }

    fn message(&mut self, from: Participant, data: Vec<u8>) {
        self.0.message(from, data);
    }
}

/// Implementation of `ThresholdSigner` using `near/threshold-signatures`.
pub struct NearThresholdSigner;

impl NearThresholdSigner {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ThresholdSigner for NearThresholdSigner {
    fn keygen_protocol(
        &self,
        participants: &[Participant],
        me: Participant,
        threshold: usize,
    ) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError> {
        // For now, use cait_sith for ECDSA. In the future, this could use near/threshold-signatures
        // for EdDSA support.
        let protocol = cait_sith::keygen::<Secp256k1>(participants, me, threshold)
            .map_err(|e| SigningError::ProtocolError(format!("keygen failed: {:?}", e)))?;
        Ok(Box::new(CaitSithProtocolWrapper(protocol)))
    }

    fn presign_protocol(
        &self,
        _participants: &[Participant],
        _me: Participant,
        _keygen_output: &[u8],
    ) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError> {
        // NearThresholdSigner does not support presign optimization
        // It performs signing directly without pre-computed presignatures
        Err(SigningError::ProtocolError(
            "presign protocol not supported - NearThresholdSigner performs direct signing"
                .to_string(),
        ))
    }

    fn sign_protocol(
        &self,
        _participants: &[Participant],
        _me: Participant,
        _keygen_output: &[u8],
        _presign_output: &[u8],
        _message: &[u8],
    ) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError> {
        // TODO: Implement using near/threshold-signatures EdDSA sign function
        // Need to research the exact API and create a protocol wrapper
        Err(SigningError::ProtocolError(
            "sign protocol not yet implemented for NearThresholdSigner".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cait_sith_adapter_creation() {
        let _adapter = CaitSithAdapter::new();
        // Basic creation test
    }

    #[tokio::test]
    async fn test_near_threshold_signer_creation() {
        let _signer = NearThresholdSigner::new();
        // Basic creation test - more comprehensive tests when implementation is complete
    }
}
