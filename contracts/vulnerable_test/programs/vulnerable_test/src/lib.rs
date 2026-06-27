use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod vulnerable_test {
    use super::*;

    // VULNERABILITY 1: No signer check
    pub fn initialize(ctx: Context<Initialize>, amount: u64) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance = amount;
        // MISSING: require!(ctx.accounts.authority.is_signer, ErrorCode::Unauthorized);
        Ok(())
    }

    // VULNERABILITY 2: Unchecked arithmetic (overflow)
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        // VULNERABLE: unchecked addition
        bank.balance = bank.balance + amount; // Should use checked_add
        Ok(())
    }

    // VULNERABILITY 3: Unchecked arithmetic (underflow)
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        // VULNERABLE: unchecked subtraction
        bank.balance = bank.balance - amount; // Should use checked_sub
        // MISSING: require!(bank.balance >= amount, ErrorCode::InsufficientFunds);
        Ok(())
    }

    // VULNERABILITY 4: No owner validation
    pub fn transfer_ownership(ctx: Context<TransferOwnership>) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        // MISSING: require!(bank.owner == ctx.accounts.authority.key(), ErrorCode::Unauthorized);
        bank.owner = ctx.accounts.new_owner.key();
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 40)]
    pub bank: Account<'info, Bank>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub bank: Account<'info, Bank>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub bank: Account<'info, Bank>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct TransferOwnership<'info> {
    #[account(mut)]
    pub bank: Account<'info, Bank>,
    pub authority: Signer<'info>,
    /// CHECK: No validation on new owner
    pub new_owner: AccountInfo<'info>,
}

#[account]
pub struct Bank {
    pub balance: u64,
    pub owner: Pubkey,
    pub authority: Pubkey,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
    #[msg("Arithmetic underflow")]
    ArithmeticUnderflow,
}
