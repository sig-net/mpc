use near_sdk::Gas;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("Signature request has timed out.")]
    Timeout,
    #[error("Signature request has already been submitted. Please try again later.")]
    PayloadCollision,
    #[error("Malformed payload: {0}")]
    MalformedPayload(String),
    #[error(
        "This key version is not supported. Call latest_key_version() to get the latest supported version."
    )]
    UnsupportedKeyVersion,
    #[error("Attached deposit is lower than required. Attached: {0}, Required: {1}.")]
    InsufficientDeposit(u128, u128),
    #[error("Provided gas is lower than required. Provided: {0}, required {1}.")]
    InsufficientGas(Gas, Gas),
    #[error("Too many pending requests. Please try again later.")]
    RequestLimitExceeded,
    #[error("This sign request has timed out, was completed, or never existed.")]
    RequestNotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum RespondError {
    #[error("This sign request has timed out, was completed, or never existed.")]
    RequestNotFound,
    #[error("The provided signature is invalid.")]
    InvalidSignature,
    #[error("The protocol is not Running.")]
    ProtocolNotInRunningState,
}

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("The protocol is not Running.")]
    ProtocolStateNotRunning,
    #[error("Account to join is already in the participant set.")]
    JoinAlreadyParticipant,
}

#[derive(Debug, thiserror::Error)]
pub enum PublicKeyError {
    #[error("Protocol state is not running or resharing.")]
    ProtocolStateNotRunningOrResharing,
    #[error("Derived key conversion failed.")]
    DerivedKeyConversionFailed,
}

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("Threshold cannot be greater than the number of candidates")]
    ThresholdTooHigh,
    #[error("Cannot load in contract due to missing state")]
    ContractStateIsMissing,
}

#[derive(Debug, thiserror::Error)]
pub enum VoteError {
    #[error("Voting account is not in the participant set.")]
    VoterNotParticipant,
    #[error("Account to be kicked is not in the participant set.")]
    KickNotParticipant,
    #[error("Account to join is not in the candidate set.")]
    JoinNotCandidate,
    #[error("Mismatched epoch.")]
    EpochMismatch,
    #[error("Number of participants cannot go below threshold.")]
    ParticipantsBelowThreshold,
    #[error("Update not found.")]
    UpdateNotFound,
    #[error("Attached deposit is lower than required. Attached: {0}, Required: {1}.")]
    InsufficientDeposit(u128, u128),
    #[error("Unexpected protocol state: {0}")]
    UnexpectedProtocolState(String),
    #[error("Unexpected: {0}")]
    Unexpected(String),
}

// Macro to implement near_sdk::FunctionError
macro_rules! impl_function_error {
    ($($error_type:ty),*) => {
        $(
            impl near_sdk::FunctionError for $error_type {
                fn panic(&self) -> ! {
                    crate::env::panic_str(&self.to_string())
                }
            }
        )*
    };
}

impl_function_error!(
    SignError,
    RespondError,
    JoinError,
    PublicKeyError,
    InitError,
    VoteError
);
