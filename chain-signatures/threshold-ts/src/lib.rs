//! Wrapper crate for `near/threshold-signatures` implementing the `ThresholdSigner` trait.

use async_trait::async_trait;
use cait_sith::protocol::{Participant, Protocol as CaitSithProtocol};
use k256::Secp256k1;
use mpc_crypto::signing::{
    Action, ProtocolError, SigningError, ThresholdProtocol, ThresholdSigner,
};
use serde_json;

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
        // TODO: Implement presign protocol for cait_sith
        // This requires understanding the cait_sith presign API
        Err(SigningError::ProtocolError(
            "presign protocol not implemented for cait_sith".to_string(),
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
        // TODO: Implement sign protocol for cait_sith
        // This requires understanding the cait_sith sign API
        Err(SigningError::ProtocolError(
            "sign protocol not implemented for cait_sith".to_string(),
        ))
    }
}

/// Wrapper to adapt cait_sith protocols to the ThresholdProtocol interface.
pub struct CaitSithProtocolWrapper<P>(pub P);

impl<P> ThresholdProtocol for CaitSithProtocolWrapper<P>
where
    P: CaitSithProtocol,
    P::Output: serde::Serialize,
{
    fn poke(&mut self) -> Result<Action, ProtocolError> {
        match self.0.poke() {
            Ok(cait_sith::protocol::Action::Wait) => Ok(Action::Wait),
            Ok(cait_sith::protocol::Action::SendMany(data)) => Ok(Action::SendMany(data)),
            Ok(cait_sith::protocol::Action::SendPrivate(to, data)) => {
                Ok(Action::SendPrivate(to, data))
            }
            Ok(cait_sith::protocol::Action::Return(output)) => {
                let data = serde_json::to_vec(&output).map_err(|e| {
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
        // TODO: Implement using near/threshold-signatures for EdDSA support
        Err(SigningError::ProtocolError("x".to_string()))
    }

    fn sign_protocol(
        &self,
        _participants: &[Participant],
        _me: Participant,
        _keygen_output: &[u8],
        _presign_output: &[u8],
        _message: &[u8],
    ) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError> {
        // TODO: Implement using near/threshold-signatures for EdDSA support
        Err(SigningError::ProtocolError("x".to_string()))
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
