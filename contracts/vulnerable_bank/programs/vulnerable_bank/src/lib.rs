use anchor_lang::prelude::*;

declare_id!("675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8");

#[program]
pub mod pseudo_source {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> ProgramResult {
        let bank = &mut ctx.accounts.bank;
        require!(bank.owner == ctx.accounts.owner.key(), ErrorCode::Unauthorized);
        bank.bump = bump;
        Ok(())
    }

    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> ProgramResult {
        let from_bank = &mut ctx.accounts.from_bank;
        let to_bank = &mut ctx.accounts.to_bank;

        require!(from_bank.owner == ctx.accounts.owner.key(), ErrorCode::Unauthorized);
        require!(to_bank.owner == ctx.accounts.owner.key(), ErrorCode::Unauthorized);

        from_bank.balance = from_bank.balance.checked_sub(amount).ok_or(error!(ErrorCode::Underflow))?;
        to_bank.balance = to_bank.balance.checked_add(amount).ok_or(error!(ErrorCode::Overflow))?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = owner, space = 8 + 32 + 1)]
    pub bank: Account<'info, Bank>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from_bank: Account<'info, Bank>,
    #[account(mut)]
    pub to_bank: Account<'info, Bank>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[account]
pub struct Bank {
    bump: u8,
    owner: Pubkey,
    balance: u64,
}
#[error_code]
pub enum ErrorCode {
    #[msg("Duplicate account")]
    DuplicateAccount,
    #[msg("Invalid program")]
    InvalidProgram,
    #[msg("Account already initialized")]
    AlreadyInitialized,
    #[msg("Account not initialized")]
    NotInitialized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Same account transfer")]
    SameAccountTransfer,
    #[msg("Account locked")]
    AccountLocked,
    #[msg("Invalid owner")]
    InvalidOwner,
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Underflow")]
    Underflow,
}
