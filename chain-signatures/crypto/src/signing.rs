//! Abstraction layer for threshold signing backends.
//!
//! This module defines the core interfaces and types for threshold signing,
//! decoupling the rest of the codebase from specific implementations like
//! `cait-sith` or `near/threshold-signatures`.

use async_trait::async_trait;
use cait_sith::protocol::Participant;

/// Available signing backends for threshold operations
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigningBackend {
    /// Use cait-sith for ECDSA operations (legacy, default)
    CaitSith,
    /// Use near/threshold-signatures for both ECDSA and EdDSA operations
    NearThresholdSignatures,
}

impl Default for SigningBackend {
    fn default() -> Self {
        SigningBackend::CaitSith
    }
}

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

/// Common interface for threshold signing protocols.
/// This matches the cait_sith protocol interface.
pub trait ThresholdProtocol {
    /// Advance the protocol and return the next action.
    fn poke(&mut self) -> Result<Action, ProtocolError>;

    /// Receive a message from another participant.
    fn message(&mut self, from: Participant, data: Vec<u8>);
}

/// Actions that a threshold protocol can take.
#[derive(Debug, Clone)]
pub enum Action {
    /// Wait for messages from other participants.
    Wait,
    /// Send data to all other participants.
    SendMany(Vec<u8>),
    /// Send data to a specific participant.
    SendPrivate(Participant, Vec<u8>),
    /// Protocol completed successfully with result.
    Success(Vec<u8>),
}

/// Errors that can occur in threshold protocols.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("initialization error: {0}")]
    InitializationError(String),
    #[error("protocol error: {0}")]
    ProtocolError(String),
}

/// Trait for threshold signing backends.
///
/// Implementations should provide the full lifecycle of threshold protocols
/// (key generation, signing, etc.) and provide a unified interface.
#[async_trait::async_trait]
pub trait ThresholdSigner: Send + Sync {
    /// Create a key generation protocol.
    fn keygen_protocol(
        &self,
        participants: &[Participant],
        me: Participant,
        threshold: usize,
    ) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError>;

    /// Create a presignature generation protocol.
    fn presign_protocol(
        &self,
        participants: &[Participant],
        me: Participant,
        keygen_output: &[u8], // Serialized keygen output
    ) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError>;

    /// Create a signature generation protocol.
    fn sign_protocol(
        &self,
        participants: &[Participant],
        me: Participant,
        keygen_output: &[u8],  // Serialized keygen output
        presign_output: &[u8], // Serialized presign output
        message: &[u8],
    ) -> Result<Box<dyn ThresholdProtocol + Send>, SigningError>;

    /// Generate a new threshold key.
    async fn generate_key(
        &self,
        participants: &[Participant],
        me: Participant,
        threshold: usize,
        curve: CurveType,
    ) -> Result<KeyMeta, SigningError>;

    /// Sign a message using a threshold key.
    async fn sign(&self, request: SignRequest) -> Result<SignResult, SigningError>;

    /// Verify a signature.
    async fn verify(
        &self,
        key_meta: &KeyMeta,
        message: &[u8],
        signature: &[u8],
        metadata: &SignMetadata,
    ) -> Result<bool, SigningError>;
}
