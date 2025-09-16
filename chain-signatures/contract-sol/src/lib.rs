#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

// fake address
declare_id!("CMGYAEsqXw5z52R8fmMZwPYQARHPEkGbefJA2FmeHLMh");

#[program]
pub mod signet_program {
    use super::*;

    /// Initialize the program state
    pub fn initialize(
        ctx: Context<Initialize>,
        signature_deposit: u64,
        chain_id: String,
    ) -> Result<()> {
        let program_state = &mut ctx.accounts.program_state;
        program_state.admin = ctx.accounts.admin.key();
        program_state.signature_deposit = signature_deposit;
        program_state.chain_id = chain_id;

        Ok(())
    }

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

#[account]
pub struct ProgramState {
    pub admin: Pubkey,
    pub signature_deposit: u64,
    pub chain_id: String,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 8 + 4 + 128, // discriminator + admin + deposit + string length + max chain_id length
        seeds = [b"program-state"],
        bump
    )]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
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
