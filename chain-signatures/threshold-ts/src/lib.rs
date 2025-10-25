//! Wrapper crate for `near/threshold-signatures` implementing the `ThresholdSigner` trait.

use async_trait::async_trait;
use cait_sith::protocol::Participant;
use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use mpc_crypto::signing::{
    CurveType, KeyId, KeyMeta, SignMetadata, SignRequest, SignResult, SigningError, ThresholdSigner,
};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::RwLock;

/// Implementation of `ThresholdSigner` using `cait-sith` (existing backend).
pub struct CaitSithAdapter {
    keys: RwLock<HashMap<KeyId, KeyMeta>>,
    // For cait-sith, we don't store actual keys - they're managed by the MPC protocol
}

impl CaitSithAdapter {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ThresholdSigner for CaitSithAdapter {
    async fn generate_key(
        &self,
        participants: &[Participant],
        me: Participant,
        threshold: usize,
        curve: CurveType,
    ) -> Result<KeyMeta, SigningError> {
        match curve {
            CurveType::Ecdsa => {
                // Generate a unique key ID
                let key_id = KeyId(format!(
                    "cait-sith-ecdsa-{}-{}",
                    participants.len(),
                    threshold
                ));

                // For cait-sith, we don't actually generate keys here
                // This is just metadata - actual key generation happens in the MPC protocol
                let key_meta = KeyMeta {
                    curve,
                    key_id: key_id.clone(),
                    public_key: vec![], // Will be filled by MPC protocol
                    participants: participants.to_vec(),
                    threshold,
                };

                self.keys.write().unwrap().insert(key_id, key_meta.clone());
                Ok(key_meta)
            }
            CurveType::Eddsa => {
                // cait-sith doesn't support EdDSA
                Err(SigningError::UnsupportedCurve(CurveType::Eddsa))
            }
        }
    }

    async fn reshare_key(
        &self,
        _key_id: KeyId,
        _old_participants: &[Participant],
        _new_participants: &[Participant],
        _me: Participant,
        _threshold: usize,
    ) -> Result<KeyMeta, SigningError> {
        // Not implemented for cait-sith adapter
        Err(SigningError::ProtocolError("reshare not supported".to_string()))
    }

    async fn sign(&self, _request: SignRequest) -> Result<SignResult, SigningError> {
        // Signing is handled by the MPC protocol, not individual operations
        Err(SigningError::ProtocolError("individual signing not supported - use MPC protocol".to_string()))
    }

    async fn verify(
        &self,
        _key_meta: &KeyMeta,
        _message: &[u8],
        _signature: &[u8],
        _metadata: &SignMetadata,
    ) -> Result<bool, SigningError> {
        // Verification would need to be implemented if needed
        Err(SigningError::ProtocolError("verification not implemented".to_string()))
    }
}

/// Implementation of `ThresholdSigner` using `near/threshold-signatures`.
pub struct NearThresholdSigner {
    keys: RwLock<HashMap<KeyId, KeyMeta>>,
    ecdsa_keys: RwLock<HashMap<KeyId, SigningKey>>,
    eddsa_keys: RwLock<HashMap<KeyId, Ed25519SigningKey>>,
}

impl NearThresholdSigner {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            ecdsa_keys: RwLock::new(HashMap::new()),
            eddsa_keys: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ThresholdSigner for NearThresholdSigner {
    async fn generate_key(
        &self,
        participants: &[Participant],
        me: Participant,
        threshold: usize,
        curve: CurveType,
    ) -> Result<KeyMeta, SigningError> {
        match curve {
            CurveType::Ecdsa => {
                // Generate a unique key ID
                let key_id = KeyId(format!(
                    "near-ts-ecdsa-{}-{}",
                    participants.len(),
                    threshold
                ));

                // Generate a real ECDSA key pair for testing
                let signing_key = SigningKey::random(&mut OsRng);
                let verifying_key = VerifyingKey::from(&signing_key);
                let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

                let key_meta = KeyMeta {
                    curve,
                    key_id: key_id.clone(),
                    public_key: public_key_bytes,
                    participants: participants.to_vec(),
                    threshold,
                };

                // Store the key (in a real implementation, this would be distributed)
                self.ecdsa_keys
                    .write()
                    .unwrap()
                    .insert(key_id.clone(), signing_key);
                self.keys.write().unwrap().insert(key_id, key_meta.clone());

                Ok(key_meta)
            }
            CurveType::Eddsa => {
                // Generate a unique key ID
                let key_id = KeyId(format!(
                    "near-ts-eddsa-{}-{}",
                    participants.len(),
                    threshold
                ));

                // Generate a real EdDSA key pair for testing
                let signing_key = Ed25519SigningKey::generate(&mut OsRng);
                let verifying_key = Ed25519VerifyingKey::from(&signing_key);
                let public_key_bytes = verifying_key.to_bytes().to_vec();

                let key_meta = KeyMeta {
                    curve,
                    key_id: key_id.clone(),
                    public_key: public_key_bytes,
                    participants: participants.to_vec(),
                    threshold,
                };

                // Store the key
                self.eddsa_keys
                    .write()
                    .unwrap()
                    .insert(key_id.clone(), signing_key);
                self.keys.write().unwrap().insert(key_id, key_meta.clone());

                Ok(key_meta)
            }
        }
    }

    async fn reshare_key(
        &self,
        _key_id: KeyId,
        _old_participants: &[Participant],
        _new_participants: &[Participant],
        _me: Participant,
        _threshold: usize,
    ) -> Result<KeyMeta, SigningError> {
        // TODO: implement resharing
        todo!("Implement key resharing")
    }

    async fn sign(&self, request: SignRequest) -> Result<SignResult, SigningError> {
        // Check that we have the key
        let key_meta = self
            .keys
            .read()
            .unwrap()
            .get(&request.key_id)
            .ok_or_else(|| SigningError::KeyNotFound(request.key_id.clone()))?
            .clone();

        match key_meta.curve {
            CurveType::Ecdsa => {
                let signing_key = self
                    .ecdsa_keys
                    .read()
                    .unwrap()
                    .get(&request.key_id)
                    .ok_or_else(|| SigningError::KeyNotFound(request.key_id.clone()))?
                    .clone();

                // Sign the message using ECDSA
                let signature: Signature = signing_key.sign(&request.message);
                let signature_bytes = signature.to_vec();

                // For ECDSA, we need a recovery ID (stub value for now)
                let metadata = SignMetadata::Ecdsa { recovery_id: 0 };

                Ok(SignResult {
                    signature: signature_bytes,
                    metadata,
                })
            }
            CurveType::Eddsa => {
                let signing_key = self
                    .eddsa_keys
                    .read()
                    .unwrap()
                    .get(&request.key_id)
                    .ok_or_else(|| SigningError::KeyNotFound(request.key_id.clone()))?
                    .clone();

                // Sign the message using EdDSA
                let signature: Ed25519Signature = signing_key.sign(&request.message);
                let signature_bytes = signature.to_bytes().to_vec();

                // EdDSA signatures don't need extra metadata
                let metadata = SignMetadata::Eddsa;

                Ok(SignResult {
                    signature: signature_bytes,
                    metadata,
                })
            }
        }
    }

    async fn verify(
        &self,
        key_meta: &KeyMeta,
        message: &[u8],
        signature: &[u8],
        metadata: &SignMetadata,
    ) -> Result<bool, SigningError> {
        match key_meta.curve {
            CurveType::Ecdsa => {
                if let SignMetadata::Ecdsa { recovery_id: _ } = metadata {
                    // Parse the verifying key from the public key bytes
                    let verifying_key = VerifyingKey::from_sec1_bytes(&key_meta.public_key)
                        .map_err(|_| {
                            SigningError::SerializationError("Invalid public key".to_string())
                        })?;

                    // Parse the signature
                    let signature = Signature::from_slice(signature).map_err(|_| {
                        SigningError::SerializationError("Invalid signature".to_string())
                    })?;

                    // Verify the signature
                    Ok(verifying_key.verify(message, &signature).is_ok())
                } else {
                    Err(SigningError::ProtocolError(
                        "Invalid metadata for ECDSA".to_string(),
                    ))
                }
            }
            CurveType::Eddsa => {
                if let SignMetadata::Eddsa = metadata {
                    // Parse the verifying key from the public key bytes
                    let public_key_bytes: [u8; 32] =
                        key_meta.public_key.as_slice().try_into().map_err(|_| {
                            SigningError::SerializationError(
                                "Invalid public key length".to_string(),
                            )
                        })?;
                    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_key_bytes)
                        .map_err(|_| {
                            SigningError::SerializationError("Invalid public key".to_string())
                        })?;

                    // Parse the signature
                    let signature_bytes: [u8; 64] = signature.try_into().map_err(|_| {
                        SigningError::SerializationError("Invalid signature length".to_string())
                    })?;
                    let signature = Ed25519Signature::from_bytes(&signature_bytes);

                    // Verify the signature
                    Ok(verifying_key.verify(message, &signature).is_ok())
                } else {
                    Err(SigningError::ProtocolError(
                        "Invalid metadata for EdDSA".to_string(),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cait_sith::protocol::Participant;

    #[tokio::test]
    async fn test_cait_sith_adapter_key_generation() {
        let adapter = CaitSithAdapter::new();
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let me = Participant::from(0u32);
        let threshold = 2;

        let result = adapter
            .generate_key(&participants, me, threshold, CurveType::Ecdsa)
            .await;
        assert!(result.is_ok());

        let key_meta = result.unwrap();
        assert_eq!(key_meta.curve, CurveType::Ecdsa);
        assert_eq!(key_meta.participants, participants);
        assert_eq!(key_meta.threshold, threshold);
    }

    #[tokio::test]
    async fn test_cait_sith_adapter_unsupported_curve() {
        let adapter = CaitSithAdapter::new();
        let participants = vec![Participant::from(0u32)];
        let me = Participant::from(0u32);

        let result = adapter
            .generate_key(&participants, me, 1, CurveType::Eddsa)
            .await;
        assert!(matches!(
            result,
            Err(SigningError::UnsupportedCurve(CurveType::Eddsa))
        ));
    }

    #[tokio::test]
    async fn test_cait_sith_adapter_signing() {
        let mut adapter = CaitSithAdapter::new();

        // First generate a key
        let participants = vec![Participant::from(0u32)];
        let me = Participant::from(0u32);
        let key_meta = adapter
            .generate_key(&participants, me, 1, CurveType::Ecdsa)
            .await
            .unwrap();

        // Store the key
        let key_id = key_meta.key_id.clone();
        adapter.keys.write().unwrap().insert(key_id.clone(), key_meta);

        // Now sign
        let request = SignRequest {
            key_id,
            message: b"test message".to_vec(),
            chain: "eth".to_string(),
        };

        let result = adapter.sign(request).await;
        assert!(result.is_ok());

        let sign_result = result.unwrap();
        assert_eq!(sign_result.signature.len(), 64); // ECDSA signature size
        assert!(matches!(
            sign_result.metadata,
            SignMetadata::Ecdsa { recovery_id: 0 }
        ));
    }

    #[tokio::test]
    async fn test_near_threshold_signer_creation() {
        let _signer = NearThresholdSigner::new();
        // Basic creation test - more comprehensive tests when implementation is complete
    }
}
