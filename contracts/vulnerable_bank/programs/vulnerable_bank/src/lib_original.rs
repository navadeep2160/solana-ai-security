use anchor_lang::prelude::*;

declare_id!("Ak49KJAr32qbxt3whtzpLB69Xz1mTT4MGDSXNuaF6AL");

#[program]
pub mod vulnerable_bank {
    use super::*;

    // ── INIT ─────────────────────────────────────────────────
    pub fn initialize(
        ctx: Context<Initialize>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.owner   = *ctx.accounts.owner.key;
        bank.balance = amount;
        bank.admin   = *ctx.accounts.owner.key;
        bank.locked  = false;
        Ok(())
    }

    // VULN 1: No signer check — anyone can withdraw
    // VULN 2: No owner verification
    // VULN 3: No underflow check
    pub fn withdraw(
        ctx: Context<Withdraw>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance -= amount;
        Ok(())
    }

    // VULN 4: No overflow check
    pub fn deposit(
        ctx: Context<Deposit>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance += amount;
        Ok(())
    }

    // VULN 5: No authority check on close
    pub fn close_account(
        ctx: Context<CloseAccount>,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance = 0;
        Ok(())
    }

    // VULN 6: Reinitialization — no check if already initialized
    pub fn reinitialize(
        ctx: Context<Reinitialize>,
        new_owner: Pubkey,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.owner = new_owner;
        bank.admin = new_owner;
        Ok(())
    }

    // VULN 7: Admin action with no admin check
    pub fn set_locked(
        ctx: Context<SetLocked>,
        locked: bool,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        // anyone can lock/unlock the bank
        bank.locked = locked;
        Ok(())
    }

    // VULN 8: Arithmetic — multiply before divide missing,
    //         loss of precision, no overflow guard
    pub fn calculate_fee(
        ctx: Context<CalculateFee>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        // divides before multiply — precision loss
        let fee = (amount / 100) * 3;
        bank.balance -= fee;
        Ok(())
    }

    // VULN 9: CPI to arbitrary program — no program ID check
    pub fn cpi_transfer(
        ctx: Context<CpiTransfer>,
        amount: u64,
    ) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance -= amount;
        // no verification that target_program is a trusted program
        Ok(())
    }

    // VULN 10: Duplicate mutable accounts — no uniqueness check
    pub fn transfer(
        ctx: Context<Transfer>,
        amount: u64,
    ) -> Result<()> {
        let from = &mut ctx.accounts.from;
        let to   = &mut ctx.accounts.to;
        from.balance -= amount;
        to.balance   += amount;
        Ok(())
    }
}

// ── Account structs ───────────────────────────────────────────

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = owner, space = 8 + 32 + 32 + 8 + 1)]
    pub bank: Account<'info, BankAccount>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub bank: Account<'info, BankAccount>,
    // VULN 1: AccountInfo not Signer
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
    // VULN 5: no constraint that caller is owner
    /// CHECK: unsafe, no authority check
    pub caller: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Reinitialize<'info> {
    #[account(mut)]
    pub bank: Account<'info, BankAccount>,
    // VULN 6: any signer can reinitialize
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetLocked<'info> {
    #[account(mut)]
    pub bank: Account<'info, BankAccount>,
    // VULN 7: any signer can lock — no admin check
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct CalculateFee<'info> {
    #[account(mut)]
    pub bank: Account<'info, BankAccount>,
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
pub struct CpiTransfer<'info> {
    #[account(mut)]
    pub bank: Account<'info, BankAccount>,
    pub caller: Signer<'info>,
    // VULN 9: target_program not validated
    /// CHECK: arbitrary program, no ID check
    pub target_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, BankAccount>,
    // VULN 10: from and to can be the same account
    #[account(mut)]
    pub to: Account<'info, BankAccount>,
    pub caller: Signer<'info>,
}

#[account]
pub struct BankAccount {
    pub owner:   Pubkey,
    pub admin:   Pubkey,
    pub balance: u64,
    pub locked:  bool,
}
