#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("CMGYAEsqXw5z52R8fmMZwPYQARHPEkGbefJA2FmeHLMh");

#[program]
pub mod chain_signatures_project {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, signature_deposit: u64) -> Result<()> {
        let program_state = &mut ctx.accounts.program_state;
        program_state.admin = ctx.accounts.admin.key();
        program_state.signature_deposit = signature_deposit;

        Ok(())
    }

    pub fn update_deposit(ctx: Context<AdminOnly>, new_deposit: u64) -> Result<()> {
        let program_state = &mut ctx.accounts.program_state;
        program_state.signature_deposit = new_deposit;

        emit!(DepositUpdatedEvent {
            old_deposit: program_state.signature_deposit,
            new_deposit,
        });

        Ok(())
    }

    pub fn withdraw_funds(ctx: Context<WithdrawFunds>, amount: u64) -> Result<()> {
        let program_state = &ctx.accounts.program_state;
        let recipient = &ctx.accounts.recipient;

        let program_state_info = program_state.to_account_info();
        require!(
            program_state_info.lamports() >= amount,
            ChainSignaturesError::InsufficientFunds
        );

        require!(
            recipient.key() != Pubkey::default(),
            ChainSignaturesError::InvalidRecipient
        );

        // Transfer funds from program_state to recipient
        **program_state_info.try_borrow_mut_lamports()? -= amount;
        **recipient.try_borrow_mut_lamports()? += amount;

        emit!(FundsWithdrawnEvent {
            amount,
            recipient: recipient.key(),
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
        let program_state = &ctx.accounts.program_state;
        let requester = &ctx.accounts.requester;
        let system_program = &ctx.accounts.system_program;

        let payer = match &ctx.accounts.fee_payer {
            Some(fee_payer) => fee_payer.to_account_info(),
            None => requester.to_account_info(),
        };

        require!(
            payer.lamports() >= program_state.signature_deposit,
            ChainSignaturesError::InsufficientDeposit
        );

        let transfer_instruction = anchor_lang::system_program::Transfer {
            from: payer,
            to: program_state.to_account_info(),
        };

        anchor_lang::system_program::transfer(
            CpiContext::new(system_program.to_account_info(), transfer_instruction),
            program_state.signature_deposit,
        )?;

        emit!(SignatureRequestedEvent {
            sender: *requester.key,
            payload,
            key_version,
            deposit: program_state.signature_deposit,
            chain_id: 0,
            path,
            algo,
            dest,
            params,
            fee_payer: ctx.accounts.fee_payer.as_ref().map(|payer| *payer.key),
        });

        Ok(())
    }

    pub fn respond(
        ctx: Context<Respond>,
        request_ids: Vec<[u8; 32]>,
        signatures: Vec<Signature>,
    ) -> Result<()> {
        require!(
            request_ids.len() == signatures.len(),
            ChainSignaturesError::InvalidInputLength
        );

        for i in 0..request_ids.len() {
            emit!(SignatureRespondedEvent {
                request_id: request_ids[i],
                responder: *ctx.accounts.responder.key,
                signature: signatures[i].clone(),
            });
        }

        Ok(())
    }
}

#[account]
pub struct ProgramState {
    pub admin: Pubkey,
    pub signature_deposit: u64,
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
pub struct Initialize<'info> {
    #[account(
        init,
        payer = admin,
        space = 8 + 32 + 8,
        seeds = [b"program-state"],
        bump
    )]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(
        mut,
        seeds = [b"program-state"],
        bump,
        has_one = admin @ ChainSignaturesError::Unauthorized
    )]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub admin: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawFunds<'info> {
    #[account(
        mut,
        seeds = [b"program-state"],
        bump,
        has_one = admin @ ChainSignaturesError::Unauthorized
    )]
    pub program_state: Account<'info, ProgramState>,

    #[account(mut)]
    pub admin: Signer<'info>,

    /// CHECK: The safety check is performed in the withdraw_funds
    /// function by checking it is not the zero address.
    #[account(mut)]
    pub recipient: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Sign<'info> {
    #[account(mut, seeds = [b"program-state"], bump)]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub requester: Signer<'info>,
    #[account(mut)]
    pub fee_payer: Option<Signer<'info>>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Respond<'info> {
    pub responder: Signer<'info>,
}

#[event]
pub struct SignatureRequestedEvent {
    pub sender: Pubkey,
    pub payload: [u8; 32],
    pub key_version: u32,
    pub deposit: u64,
    pub chain_id: u64,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub fee_payer: Option<Pubkey>,
}

#[event]
pub struct SignatureRespondedEvent {
    pub request_id: [u8; 32],
    pub responder: Pubkey,
    pub signature: Signature,
}

#[event]
pub struct DepositUpdatedEvent {
    pub old_deposit: u64,
    pub new_deposit: u64,
}

#[event]
pub struct FundsWithdrawnEvent {
    pub amount: u64,
    pub recipient: Pubkey,
}

#[error_code]
pub enum ChainSignaturesError {
    #[msg("Insufficient deposit amount")]
    InsufficientDeposit,
    #[msg("Arrays must have the same length")]
    InvalidInputLength,
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Insufficient funds for withdrawal")]
    InsufficientFunds,
    #[msg("Invalid recipient address")]
    InvalidRecipient,
}
