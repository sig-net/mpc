//! Abstraction layer for threshold signing backends.
//!
//! This module defines the core interfaces and types for threshold signing,
//! decoupling the rest of the codebase from specific implementations like
//! `cait-sith` or `near/threshold-signatures`.

use async_trait::async_trait;
use cait_sith::protocol::Participant;

/// Supported elliptic curves for threshold signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CurveType {
    /// ECDSA over Secp256k1 (compatible with Ethereum, etc.)
    Ecdsa,
    /// EdDSA over Curve25519 (Ed25519, compatible with NEAR, Solana, etc.)
    Eddsa,
}

/// Unique identifier for a threshold key.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyId(pub String);

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Metadata about a generated threshold key.
#[derive(Debug, Clone)]
pub struct KeyMeta {
    pub curve: CurveType,
    pub key_id: KeyId,
    pub public_key: Vec<u8>, // Serialized public key bytes
    pub participants: Vec<Participant>,
    pub threshold: usize,
}

/// Request to sign a message with a threshold key.
#[derive(Debug, Clone)]
pub struct SignRequest {
    pub key_id: KeyId,
    pub message: Vec<u8>,
    pub chain: String, // e.g., "eth", "sol", "near" - for chain-specific formatting
}

/// Algorithm-specific metadata included with signatures.
#[derive(Debug, Clone)]
pub enum SignMetadata {
    /// ECDSA signature includes recovery ID for public key recovery.
    Ecdsa { recovery_id: u8 },
    /// EdDSA signatures are self-contained (no extra metadata needed).
    Eddsa,
}

/// Result of a threshold signing operation.
#[derive(Debug, Clone)]
pub struct SignResult {
    pub signature: Vec<u8>, // Serialized signature bytes
    pub metadata: SignMetadata,
}

/// Errors that can occur during threshold signing operations.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("key not found: {0}")]
    KeyNotFound(KeyId),
    #[error("unsupported curve: {0:?}")]
    UnsupportedCurve(CurveType),
    #[error("insufficient participants")]
    InsufficientParticipants,
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Trait for threshold signing backends.
///
/// Implementations should handle the full lifecycle of threshold protocols
/// (key generation, signing, etc.) and provide a unified interface.
#[async_trait::async_trait]
pub trait ThresholdSigner: Send + Sync {
    /// Generate a new threshold key.
    async fn generate_key(
        &self,
        participants: &[Participant],
        me: Participant,
        threshold: usize,
        curve: CurveType,
    ) -> Result<KeyMeta, SigningError>;

    /// Reshare an existing key to new participants.
    async fn reshare_key(
        &self,
        key_id: KeyId,
        old_participants: &[Participant],
        new_participants: &[Participant],
        me: Participant,
        threshold: usize,
    ) -> Result<KeyMeta, SigningError>;

    /// Sign a message using a threshold key.
    async fn sign(&self, request: SignRequest) -> Result<SignResult, SigningError>;

    /// Verify a signature (for testing/debugging).
    async fn verify(
        &self,
        key_meta: &KeyMeta,
        message: &[u8],
        signature: &[u8],
        metadata: &SignMetadata,
    ) -> Result<bool, SigningError>;
}