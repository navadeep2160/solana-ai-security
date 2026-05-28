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
        let owner = &ctx.accounts.owner;
        let system_program = &ctx.accounts.system_program;

        if amount == 0 {
            return Err(ErrorCode::WithdrawAmountZero.into());
        }
        
        bank.balance = bank.balance.checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;

        anchor_lang::system_program::transfer(
            CpiContext::new(
                system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: bank.to_account_info(),
                    to: owner.to_account_info(),
                },
            ),
            amount,
        )?;

        Ok(())
    }

    pub fn deposit(
        ctx: Context<Deposit>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        let user = &ctx.accounts.user;
        let system_program = &ctx.accounts.system_program;

        if amount == 0 {
            return Err(ErrorCode::DepositAmountZero.into());
        }

        bank.balance = bank.balance.checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;

        anchor_lang::system_program::transfer(
            CpiContext::new(
                system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: user.to_account_info(),
                    to: bank.to_account_info(),
                },
            ),
            amount,
        )?;

        Ok(())
    }

    pub fn close_account(
        ctx: Context<CloseAccount>,
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

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub bank: Account<'info, BankAccount>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(mut, close = owner, has_one = owner)]
    pub bank: Account<'info, BankAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,
}

#[account]
pub struct BankAccount {
    pub owner: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Insufficient funds in the bank account.")]
    InsufficientFunds,
    #[msg("Account balance overflowed.")]
    Overflow,
    #[msg("Withdraw amount cannot be zero.")]
    WithdrawAmountZero,
    #[msg("Deposit amount cannot be zero.")]
    DepositAmountZero,
}