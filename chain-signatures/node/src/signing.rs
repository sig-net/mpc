//! Re-export of the signing abstraction layer from mpc-crypto.

pub use mpc_crypto::signing::*;

/// Factory function to create the appropriate ThresholdSigner implementation
/// based on the configured backend.
#[cfg(feature = "near-threshold-signatures")]
pub fn create_threshold_signer(backend: &SigningBackend) -> Box<dyn ThresholdSigner + Send + Sync> {
    match backend {
        SigningBackend::CaitSith => Box::new(threshold_ts::CaitSithAdapter::new()),
        SigningBackend::NearThresholdSignatures => {
            Box::new(threshold_ts::NearThresholdSigner::new())
        }
    }
}

/// Stub implementation when the feature is not enabled
#[cfg(not(feature = "near-threshold-signatures"))]
pub fn create_threshold_signer(
    _backend: &SigningBackend,
) -> Box<dyn ThresholdSigner + Send + Sync> {
    // Return a stub that panics - this should not be called if the feature is not enabled
    panic!("near-threshold-signatures feature not enabled")
}
