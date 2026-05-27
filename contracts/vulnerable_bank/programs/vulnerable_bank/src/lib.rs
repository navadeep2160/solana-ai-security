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

        // VULNERABILITY 2: No owner verification - Fixed by `has_one = user` constraint
        // VULNERABILITY 3: No underflow check - Fixed by `checked_sub`
        bank.balance = bank.balance.checked_sub(amount).ok_or(ProgramError::ArithmeticOverflow)?;

        Ok(())
    }

    pub fn deposit(
        ctx: Context<Deposit>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        // VULNERABILITY 4: No overflow check on deposit - Fixed by `checked_add`
        bank.balance = bank.balance.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;
        Ok(())
    }

    pub fn close_account(
        _ctx: Context<CloseAccount>,
    ) -> Result<()> {
        // VULNERABILITY 5: Admin function with no authority check - Fixed by `has_one = owner` and `close = owner` constraints
        // The account is closed and lamports transferred by the `close = owner` constraint.
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
    #[account(mut, has_one = owner)] // VULNERABILITY 2: Owner verification added
    pub bank: Account<'info, BankAccount>,

    // VULNERABILITY 1: user is not a Signer - Fixed
    #[account(mut)] // user needs to be mutable to receive lamports
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, has_one = owner)]
    pub bank: Account<'info, BankAccount>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseAccount<'info> {
    // VULNERABILITY 5: no constraint that caller is owner - Fixed by `has_one = owner` and `close = owner`
    #[account(mut, close = owner, has_one = owner)]
    pub bank: Account<'info, BankAccount>,

    // The owner of the bank account, who is also the signer and recipient of funds
    #[account(mut)] // owner needs to be mutable to receive lamports
    pub owner: Signer<'info>,
}

#[account]
pub struct BankAccount {
    pub owner: Pubkey,
    pub balance: u64,
}