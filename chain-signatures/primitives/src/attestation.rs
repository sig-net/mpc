//! Outcome metadata shared by response signing, persistence and Midnight events.

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
    /// Checkpoints encode this field as `outcome`.
    #[serde(rename = "outcome")]
    pub outcome_kind: AttestationOutcomeKind,
}

impl AttestationMetadata {
    pub fn validate_output(&self, output: &[u8]) -> Result<(), AttestationError> {
        if self.outcome_kind != AttestationOutcomeKind::Executed && !output.is_empty() {
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
    pub outcome_kind: AttestationOutcomeKind,
    pub serialized_output_length: u64,
    pub digest: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_metadata_preserves_checkpoint_encoding() {
        for (outcome, fixture) in [
            (AttestationOutcomeKind::Executed, "a36b6b65795f76657273696f6e016c626c6f636b5f686569676874182a676f7574636f6d65684578656375746564"),
            (AttestationOutcomeKind::Failed, "a36b6b65795f76657273696f6e016c626c6f636b5f686569676874182a676f7574636f6d65664661696c6564"),
            (AttestationOutcomeKind::Unviable, "a36b6b65795f76657273696f6e016c626c6f636b5f686569676874182a676f7574636f6d6568556e766961626c65"),
        ] {
            let metadata = AttestationMetadata {
                key_version: 1,
                block_height: 42,
                outcome_kind: outcome,
            };
            let fixture = hex::decode(fixture).unwrap();
            let mut encoded = Vec::new();
            ciborium::into_writer(&metadata, &mut encoded).unwrap();
            assert_eq!(encoded, fixture);
            let recovered: AttestationMetadata = ciborium::from_reader(fixture.as_slice()).unwrap();
            assert_eq!(recovered, metadata);
        }
    }

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
                outcome_kind: outcome,
            };
            assert!(metadata.validate_output(&[]).is_ok());
            assert_eq!(
                metadata.validate_output(&[1]).is_ok(),
                outcome == AttestationOutcomeKind::Executed
            );
        }
    }
}
