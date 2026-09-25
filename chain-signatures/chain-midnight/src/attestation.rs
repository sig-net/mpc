//! Consistency checks for canonical Midnight response requests at external boundaries.

use anyhow::Context as _;
use mpc_primitives::{IndexedSignRequest, PublishedAttestation, SignKind};

/// Derive the published metadata after checking a final response against its signed payload.
/// Callers route Midnight requests here; initial signature responses have no attestation.
pub fn validate_attestation_response(
    request: &IndexedSignRequest,
) -> anyhow::Result<PublishedAttestation> {
    let SignKind::RespondBidirectional(response) = &request.kind else {
        anyhow::bail!("Midnight attestation requires a RespondBidirectional request");
    };
    let metadata = response
        .attestation
        .as_ref()
        .context("Midnight attestation metadata is missing")?;
    anyhow::ensure!(
        metadata.key_version == request.args.key_version,
        "Midnight attestation key version does not match the signing request"
    );
    let digest = mpc_compact_hashing::compute_attestation_hash(
        &request.id.request_id,
        metadata,
        &response.output,
    )?;
    anyhow::ensure!(
        request.args.payload.to_bytes().as_slice() == digest,
        "Midnight attestation digest does not match the signed payload"
    );
    Ok(PublishedAttestation {
        block_height: metadata.block_height,
        outcome: metadata.outcome,
        serialized_output_length: response.output.len() as u64,
        digest,
    })
}
