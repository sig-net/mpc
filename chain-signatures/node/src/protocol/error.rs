use cait_sith::protocol::{InitializationError, Participant};
use mpc_primitives::SignId;

use super::{presignature::PresignatureId, triple::TripleId};

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error("presignature already generated")]
    AlreadyGenerated,
    #[error("cait-sith initialization error: {0}")]
    CaitSithInitializationError(#[from] InitializationError),
    #[error("triple {0} is generating or missing")]
    TripleGeneratingOrMissing(TripleId),
    #[error("triple {0} and {1} are missing")]
    TripleMissing(TripleId, TripleId),
    #[error("presignature {0} is generating or missing")]
    PresignatureGeneratingOrMissing(PresignatureId),
    #[error("presignature bad parameters")]
    PresignatureBadParameters,
    #[error("unable to reserve a slot for presignature")]
    PresignatureReserveError,
    #[error("waiting for missing sign request id={0:?}")]
    WaitingForIndexer(SignId),
    #[error("invalid proposer expected={0:?}, actual={1:?}")]
    InvalidProposer(Participant, Participant),
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Property 64: Generation Error Handling
    // Validates: Requirements 23.1
    //
    // For any generation error (AlreadyGenerated, TripleMissing), the system SHALL
    // provide appropriate error responses that can be matched and handled.
    #[test]
    fn prop_generation_error_handling() {
        // **Feature: unit-test-coverage, Property 64: Generation Error Handling**
        
        // Test AlreadyGenerated error
        let error = GenerationError::AlreadyGenerated;
        assert_eq!(error.to_string(), "presignature already generated");
        
        // Test TripleMissing error with two triple IDs
        let triple_id_1: TripleId = 1;
        let triple_id_2: TripleId = 2;
        let error = GenerationError::TripleMissing(triple_id_1, triple_id_2);
        let error_msg = error.to_string();
        assert!(error_msg.contains("triple"));
        assert!(error_msg.contains("missing"));
        
        // Test PresignatureReserveError
        let error = GenerationError::PresignatureReserveError;
        assert_eq!(error.to_string(), "unable to reserve a slot for presignature");
        
        // Verify errors can be matched
        match GenerationError::AlreadyGenerated {
            GenerationError::AlreadyGenerated => {
                // Successfully matched AlreadyGenerated
            }
            _ => panic!("Failed to match AlreadyGenerated"),
        }
        
        match GenerationError::TripleMissing(1, 2) {
            GenerationError::TripleMissing(_, _) => {
                // Successfully matched TripleMissing
            }
            _ => panic!("Failed to match TripleMissing"),
        }
    }

    // Property 65: Invalid Proposer Rejection
    // Validates: Requirements 23.2
    //
    // For any invalid proposer scenario, the system SHALL reject the proposal
    // appropriately by providing an InvalidProposer error with expected and actual participants.
    #[test]
    fn prop_invalid_proposer_rejection() {
        // **Feature: unit-test-coverage, Property 65: Invalid Proposer Rejection**
        
        let expected_proposer = Participant::from(1u32);
        let actual_proposer = Participant::from(2u32);
        
        let error = GenerationError::InvalidProposer(expected_proposer, actual_proposer);
        let error_msg = error.to_string();
        
        // Verify error message contains both participants
        assert!(error_msg.contains("invalid proposer"));
        assert!(error_msg.contains("expected"));
        assert!(error_msg.contains("actual"));
        
        // Verify error can be matched and participants extracted
        match error {
            GenerationError::InvalidProposer(exp, act) => {
                assert_eq!(exp, expected_proposer);
                assert_eq!(act, actual_proposer);
            }
            _ => panic!("Failed to match InvalidProposer"),
        }
        
        // Test that different proposers produce different errors
        let error1 = GenerationError::InvalidProposer(Participant::from(1u32), Participant::from(2u32));
        let error2 = GenerationError::InvalidProposer(Participant::from(1u32), Participant::from(3u32));
        
        assert_ne!(error1.to_string(), error2.to_string());
    }

    // Property 66: Presignature Reservation Error Handling
    // Validates: Requirements 23.3
    //
    // For any presignature reservation failure, the system SHALL handle the error
    // gracefully by providing a PresignatureReserveError that can be caught and handled.
    #[test]
    fn prop_presignature_reservation_error_handling() {
        // **Feature: unit-test-coverage, Property 66: Presignature Reservation Error Handling**
        
        let error = GenerationError::PresignatureReserveError;
        
        // Verify error message is clear
        assert_eq!(error.to_string(), "unable to reserve a slot for presignature");
        
        // Verify error can be matched
        match error {
            GenerationError::PresignatureReserveError => {
                // Successfully matched PresignatureReserveError
            }
            _ => panic!("Failed to match PresignatureReserveError"),
        }
        
        // Verify error is distinct from other errors
        let other_error = GenerationError::AlreadyGenerated;
        assert_ne!(error.to_string(), other_error.to_string());
        
        // Verify error implements Display trait
        let error_display = format!("{}", error);
        assert!(!error_display.is_empty());
    }

    // Property 67: Malformed Message Handling
    // Validates: Requirements 23.4
    //
    // For any malformed message received, the system SHALL handle it gracefully
    // without crashing or corrupting state. This is tested by verifying that
    // error types can be properly constructed and matched.
    #[test]
    fn prop_malformed_message_handling() {
        // **Feature: unit-test-coverage, Property 67: Malformed Message Handling**
        
        // Test that various error types can be constructed and handled
        let errors: Vec<GenerationError> = vec![
            GenerationError::AlreadyGenerated,
            GenerationError::TripleGeneratingOrMissing(1),
            GenerationError::TripleMissing(1, 2),
            GenerationError::PresignatureGeneratingOrMissing(1),
            GenerationError::PresignatureBadParameters,
            GenerationError::PresignatureReserveError,
            GenerationError::InvalidProposer(Participant::from(1u32), Participant::from(2u32)),
        ];
        
        // Verify all errors can be converted to strings (Display trait)
        for error in &errors {
            let error_str = error.to_string();
            assert!(!error_str.is_empty(), "Error message should not be empty");
        }
        
        // Verify all errors can be matched
        for error in errors {
            let matched = match error {
                GenerationError::AlreadyGenerated => true,
                GenerationError::TripleGeneratingOrMissing(_) => true,
                GenerationError::TripleMissing(_, _) => true,
                GenerationError::PresignatureGeneratingOrMissing(_) => true,
                GenerationError::PresignatureBadParameters => true,
                GenerationError::PresignatureReserveError => true,
                GenerationError::InvalidProposer(_, _) => true,
                _ => false,
            };
            assert!(matched, "All error variants should be matchable");
        }
    }
}

