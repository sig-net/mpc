//! Outcome metadata shared by response signing, persistence and Midnight events.

/// Marks node-internal context admitted under the canonical Midnight SDK contract.
/// Legacy checkpoints lack it and cannot safely acquire new attestation semantics.
pub const MIDNIGHT_ATTESTATION_CONTEXT: &[u8] = b"midnight-canonical-v1";

/// Variant indices of the SDK Compact `OutputKind` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum AttestationOutcomeKind {
    Executed = 0,
    Failed = 1,
    Unviable = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationError {
    InvalidOutcome(u8),
    NonemptyFailureOutput,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOutcome(kind) => write!(f, "invalid attestation outcome kind {kind}"),
            Self::NonemptyFailureOutput => {
                f.write_str("Failed and Unviable attestations require empty output")
            }
        }
    }
}

impl std::error::Error for AttestationError {}

impl TryFrom<u8> for AttestationOutcomeKind {
    type Error = AttestationError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Executed),
            1 => Ok(Self::Failed),
            2 => Ok(Self::Unviable),
            other => Err(AttestationError::InvalidOutcome(other)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct AttestationMetadata {
    /// Selects the signing key; the SDK digest binds this through the request ID.
    pub key_version: u32,
    pub block_height: u64,
    pub outcome: AttestationOutcomeKind,
}

impl AttestationMetadata {
    pub fn validate_output(&self, output: &[u8]) -> Result<(), AttestationError> {
        if self.outcome != AttestationOutcomeKind::Executed && !output.is_empty() {
            return Err(AttestationError::NonemptyFailureOutput);
        }
        Ok(())
    }
}

/// Metadata carried by Midnight's canonical `RespondBidirectionalEvent`.
/// The output itself travels through the cache; its length and digest travel here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedAttestation {
    pub block_height: u64,
    pub outcome: AttestationOutcomeKind,
    pub serialized_output_length: u64,
    pub digest: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_tags_match_the_sdk_enum() {
        for (kind, tag) in [
            (AttestationOutcomeKind::Executed, 0),
            (AttestationOutcomeKind::Failed, 1),
            (AttestationOutcomeKind::Unviable, 2),
        ] {
            assert_eq!(kind as u8, tag);
            assert_eq!(AttestationOutcomeKind::try_from(tag), Ok(kind));
        }
        for tag in 3..=255 {
            assert_eq!(
                AttestationOutcomeKind::try_from(tag),
                Err(AttestationError::InvalidOutcome(tag))
            );
        }
    }

    #[test]
    fn only_executed_can_carry_output() {
        for outcome in [
            AttestationOutcomeKind::Executed,
            AttestationOutcomeKind::Failed,
            AttestationOutcomeKind::Unviable,
        ] {
            let metadata = AttestationMetadata {
                key_version: 1,
                block_height: 42,
                outcome,
            };
            assert!(metadata.validate_output(&[]).is_ok());
            assert_eq!(
                metadata.validate_output(&[1]).is_ok(),
                outcome == AttestationOutcomeKind::Executed
            );
        }
    }
}
