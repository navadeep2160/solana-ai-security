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

    // VULNERABILITY 1: No signer check — anyone can withdraw
    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;

        // VULNERABILITY 2: No owner verification
        // VULNERABILITY 3: No underflow check
        bank.balance -= amount;

        Ok(())
    }

    // VULNERABILITY 4: No overflow check on deposit
    pub fn deposit(
        ctx: Context<Deposit>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance += amount;
        Ok(())
    }

    // VULNERABILITY 5: Admin function with no authority check
    pub fn close_account(
        ctx: Context<CloseAccount>,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance = 0;
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

    // VULNERABILITY: user is not a Signer
    /// CHECK: unsafe, no validation
    pub user: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub bank: Account<'info, BankAccount>,

    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(mut)]
    pub bank: Account<'info, BankAccount>,

    // VULNERABILITY: no constraint that caller is owner
    /// CHECK: unsafe, no authority check
    pub caller: AccountInfo<'info>,
}

#[account]
pub struct BankAccount {
    pub owner: Pubkey,
    pub balance: u64,
}
