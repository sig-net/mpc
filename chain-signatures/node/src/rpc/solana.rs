use super::PublishAction;
use crate::indexer_sol::SolanaClient;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use mpc_primitives::{SignKind, Signature};
use signet_program::accounts::Respond as SolanaRespondAccount;
use signet_program::accounts::RespondBidirectional as SolanaRespondBidirectionalAccount;
use signet_program::instruction::Respond as SolanaRespond;
use signet_program::instruction::RespondBidirectional as SolanaRespondBidirectional;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer as SolanaSigner;
use std::time::Instant;

pub async fn try_publish_sol(
    sol: &SolanaClient,
    action: &PublishAction,
    timestamp: &Instant,
    signature: &Signature,
) -> Result<(), ()> {
    let program = sol.client.program(sol.program_id).map_err(|_| ())?;

    let sign_id = action.indexed.id;
    let request_ids = vec![action.indexed.id.request_id];
    let big_r = signature.big_r.to_encoded_point(false);
    let signature = crate::util::mpc_to_sol_signature(signature, big_r);

    tracing::debug!(
        ?sign_id,
        request_type = ?action.indexed.kind,
        "try_publish_sol: dispatching request"
    );

    match &action.indexed.kind {
        SignKind::Sign | SignKind::SignBidirectional(_) => {
            let (event_authority, _) =
                Pubkey::find_program_address(&[b"__event_authority"], &sol.program_id);
            let tx = program
                .request()
                .signer(sol.payer.clone())
                .accounts(SolanaRespondAccount {
                    responder: sol.payer.pubkey(),
                    event_authority,
                    program: sol.program_id,
                })
                .args(SolanaRespond {
                    request_ids,
                    signatures: vec![signature.clone()],
                })
                .send()
                .await
                .map_err(|err| {
                    tracing::error!(
                        sign_id = ?action.indexed.id,
                        error = ?err,
                        "failed to publish solana signature"
                    );
                })?;

            tracing::info!(
                ?sign_id,
                tx_hash = ?tx,
                elapsed = ?timestamp.elapsed(),
                "published solana signature successfully"
            );
        }
        SignKind::RespondBidirectional(respond_bidirectional_tx) => {
            tracing::debug!(
                ?sign_id,
                request_id = ?request_ids[0],
                serialized_output_len = respond_bidirectional_tx.output.len(),
                "try_publish_sol: entering RespondBidirectional arm"
            );
            let respond_bidirectional_serialized_output = respond_bidirectional_tx.output.clone();
            let tx = program
                .request()
                .signer(sol.payer.clone())
                .accounts(SolanaRespondBidirectionalAccount {
                    responder: sol.payer.clone().try_pubkey().unwrap(),
                })
                .args(SolanaRespondBidirectional {
                    request_id: request_ids[0],
                    serialized_output: respond_bidirectional_serialized_output.clone(),
                    signature: signature.clone(),
                })
                .send()
                .await
                .map_err(|err| {
                    tracing::error!(
                        ?sign_id,
                        error = ?err,
                        "failed to publish respond bidirectional solana signature"
                    );
                })?;

            tracing::info!(
                ?sign_id,
                tx_hash = ?tx,
                elapsed = ?timestamp.elapsed(),
                "published respond bidirectional solana signature successfully"
            );
        }
        SignKind::Checkpoint(_) => {
            tracing::error!(
                ?sign_id,
                "try_publish_sol: checkpoint signature publishing not supported on Solana"
            );
            return Err(());
        }
    }

    Ok(())
}
