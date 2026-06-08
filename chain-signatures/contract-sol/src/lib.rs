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
            emit_cpi!(SignatureRespondedEvent {
                request_id: request_ids[i],
                responder: *ctx.accounts.responder.key,
                signature: signatures[i].clone(),
            });
        }

        Ok(())
    }

    pub fn respond_bidirectional(
        ctx: Context<RespondBidirectional>,
        request_id: [u8; 32],
        serialized_output: Vec<u8>,
        signature: Signature,
    ) -> Result<()> {
        // only possible error responses // (this tx could never happen):
        // - nonce too low
        // - balance too low
        // - literal on chain error
        emit!(RespondBidirectionalEvent {
            request_id,
            responder: *ctx.accounts.responder.key,
            serialized_output,
            signature,
        });

        Ok(())
    }

    pub fn sign(
        ctx: Context<Sign>,
        payload: [u8; 32],
        key_version: u32,
        path: String,
        algo: String,
        dest: String,
        params: String,
    ) -> Result<()> {
        // Emit a sign request event that matches the MPC node's expected structure
        emit!(SignatureRequestedEvent {
            sender: *ctx.accounts.requester.key,
            payload,
            key_version,
            deposit: ctx.accounts.program_state.signature_deposit,
            chain_id: "solana".to_string(),
            path,
            algo,
            dest,
            params,
            fee_payer: Some(*ctx.accounts.requester.key),
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_bidirectional(
        ctx: Context<SignBidirectional>,
        serialized_transaction: Vec<u8>,
        // the mainnet caip2_id of the target chain where the signed transaction will be sent
        caip2_id: String,
        key_version: u32,
        path: String,
        algo: String,
        dest: String,
        params: String,
        program_id: Pubkey,
        output_deserialization_schema: Vec<u8>,
        respond_serialization_schema: Vec<u8>,
    ) -> Result<()> {
        emit!(SignBidirectionalEvent {
            sender: *ctx.accounts.requester.key,
            serialized_transaction,
            caip2_id,
            key_version,
            deposit: ctx.accounts.program_state.signature_deposit,
            path,
            algo,
            dest,
            params,
            program_id,
            output_deserialization_schema,
            respond_serialization_schema,
        });

        Ok(())
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
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

#[event_cpi]
#[derive(Accounts)]
pub struct Respond<'info> {
    pub responder: Signer<'info>,
}

#[derive(Accounts)]
pub struct RespondBidirectional<'info> {
    pub responder: Signer<'info>,
}

#[event_cpi]
#[derive(Accounts)]
pub struct Sign<'info> {
    #[account(mut, seeds = [b"program-state"], bump)]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub requester: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SignBidirectional<'info> {
    #[account(mut, seeds = [b"program-state"], bump)]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub requester: Signer<'info>,
    #[account(mut)]
    pub fee_payer: Option<Signer<'info>>,
    pub system_program: Program<'info, System>,
    pub instructions: Option<AccountInfo<'info>>,
}

#[event]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureRespondedEvent {
    pub request_id: [u8; 32],
    pub responder: Pubkey,
    pub signature: Signature,
}

#[event]
#[derive(Clone)]
pub struct RespondBidirectionalEvent {
    pub request_id: [u8; 32],
    pub responder: Pubkey,
    pub serialized_output: Vec<u8>,
    pub signature: Signature,
}

#[event]
#[derive(Clone, Debug)]
pub struct SignatureRequestedEvent {
    pub sender: Pubkey,
    pub payload: [u8; 32],
    pub key_version: u32,
    pub deposit: u64,
    pub chain_id: String,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub fee_payer: Option<Pubkey>,
}

/// Event emitted when a bidirectional signing request is initiated
/// via the `sign_bidirectional` instruction on the Solana program.
#[event]
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SignBidirectionalEvent {
    /// The public key of the sender initiating the request.
    pub sender: Pubkey,

    /// The serialized transaction payload to be signed.
    pub serialized_transaction: Vec<u8>,

    /// mainnet CAIP-2 chain ID of the *target chain* where the signed transaction will be sent.
    ///
    /// Note: This is NOT the chain where `respond()` or `respond_bidirectional()` is executed.
    pub caip2_id: String,

    /// Version of the key to be used for signing.
    pub key_version: u32,

    /// Deposit associated with the request.
    pub deposit: u64,

    /// Derivation path used for signing.
    pub path: String,

    /// Signing algorithm identifier.
    ///
    /// If empty (`""`), ECDSA will be used by default.
    pub algo: String,

    /// Destination field (currently unused).
    ///
    /// Should be left empty (`""`).
    pub dest: String,

    /// Additional parameters encoded as a string (currently unused).
    ///
    /// Should be left empty (`""`).
    pub params: String,

    /// The program ID of the Solana program that emitted this event.
    ///
    /// Used by MPC service to filter and verify events from the correct program.
    ///
    /// MUST match the deployed program ID.
    pub program_id: Pubkey,

    /// Schema used to deserialize the output of the signed transaction.
    pub output_deserialization_schema: Vec<u8>,

    /// Schema used to serialize the `respond_bidirectional` payload.
    pub respond_serialization_schema: Vec<u8>,
}
