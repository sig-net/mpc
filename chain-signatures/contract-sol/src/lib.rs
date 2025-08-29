#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

// fake address
declare_id!("CMGYAEsqXw5z52R8fmMZwPYQARHPEkGbefJA2FmeHLMh");

#[program]
pub mod signet_program {
    use super::*;

    // we need minimal implementation of the contract in order to import all the primitives
    pub fn respond(
        ctx: Context<Respond>,
        request_ids: Vec<[u8; 32]>,
        signatures: Vec<Signature>,
    ) -> Result<()> {
        // Minimal implementation - just emit the event
        for i in 0..request_ids.len() {
            emit!(SignatureRespondedEvent {
                request_id: request_ids[i],
                responder: *ctx.accounts.responder.key,
                signature: signatures[i].clone(),
            });
        }

        Ok(())
    }

    pub fn read_respond(
        ctx: Context<ReadRespond>,
        request_id: [u8; 32],
        serialized_output: Vec<u8>,
        signature: Signature,
    ) -> Result<()> {
        // The signature should be an ECDSA signature over keccak256(request_id || serialized_output)

        // only possible error responses // (this tx could never happen):
        // - nonce too low
        // - balance too low
        // - literal on chain error

        emit!(ReadRespondedEvent {
            request_id,
            responder: *ctx.accounts.responder.key,
            serialized_output,
            signature,
        });

        Ok(())
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct AffinePoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct Signature {
    pub big_r: AffinePoint,
    pub s: [u8; 32],
    pub recovery_id: u8,
}

#[derive(Accounts)]
pub struct Respond<'info> {
    pub responder: Signer<'info>,
}

#[derive(Accounts)]
pub struct ReadRespond<'info> {
    pub responder: Signer<'info>,
}

#[event]
pub struct SignatureRespondedEvent {
    pub request_id: [u8; 32],
    pub responder: Pubkey,
    pub signature: Signature,
}

#[event]
pub struct ReadRespondedEvent {
    pub request_id: [u8; 32],
    pub responder: Pubkey,
    pub serialized_output: Vec<u8>,
    pub signature: Signature,
}
