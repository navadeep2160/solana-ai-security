use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWxTWqkY6W2BeZ7FEfcYkg476zPF");

#[program]
pub mod vulnerable_bank {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.owner = ctx.accounts.owner.key();
        bank.balance = amount;
        Ok(())
    }

    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;

        require!(ctx.accounts.user.key() == bank.owner, ErrorCode::Unauthorized);
        require!(bank.balance >= amount, ErrorCode::InsufficientFunds);

        bank.balance = bank.balance.checked_sub(amount).ok_or(error!(ErrorCode::InsufficientFunds))?;

        Ok(())
    }

    pub fn deposit(
        ctx: Context<Deposit>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance = bank.balance.checked_add(amount).ok_or(error!(ErrorCode::Overflow))?;
        Ok(())
    }

    pub fn close_account(
        ctx: Context<CloseAccount>,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        require!(ctx.accounts.caller.key() == bank.owner, ErrorCode::Unauthorized);
        // The `close = caller` attribute on the `bank` account in the `CloseAccount` struct
        // handles the transfer of remaining SOL and closing of the account.
        // No explicit `bank.balance = 0;` is needed here.
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = owner,
        space = 8 + 32 + 8
    )]
    pub bank: Account<'info, BankAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub bank: Account<'info, BankAccount>,

    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub bank: Account<'info, BankAccount>,

    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(mut, close = caller)]
    pub bank: Account<'info, BankAccount>,

    #[account(mut)]
    pub caller: Signer<'info>,
}

#[account]
pub struct BankAccount {
    pub owner: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized access.")]
    Unauthorized,
    #[msg("Insufficient funds.")]
    InsufficientFunds,
    #[msg("Arithmetic overflow.")]
    Overflow,
}