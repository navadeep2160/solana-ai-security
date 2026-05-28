use anchor_lang::prelude::*;

declare_id!("7v4a7AxxpkGEs6YX6wefijkD3Qm6K3AjcngGNvkC4VeW");

#[program]
pub mod vulnerable_bank {
    use super::*;

    pub fn initialize(
        ctx: Context<Initialize>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.owner = *ctx.accounts.owner.key;
        bank.balance = amount;
        Ok(())
    }

    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance = bank.balance.checked_sub(amount).ok_or(BankError::Underflow)?;
        Ok(())
    }

    pub fn deposit(
        ctx: Context<Deposit>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance = bank.balance.checked_add(amount).ok_or(BankError::Overflow)?;
        Ok(())
    }

    pub fn close_account(
        _ctx: Context<CloseAccount>,
    ) -> Result<()> {
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
    #[account(mut, has_one = owner)]
    pub bank: Account<'info, BankAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, has_one = owner)]
    pub bank: Account<'info, BankAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,
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
pub enum BankError {
    #[msg("Unauthorized access.")]
    Unauthorized,
    #[msg("Account balance underflow.")]
    Underflow,
    #[msg("Account balance overflow.")]
    Overflow,
}