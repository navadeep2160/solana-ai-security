// AUTO-GENERATED from bytecode analysis
// Program: 675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8
// Patterns detected: 111
// This is pseudo-source for patch generation only

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

#[error_code]
pub enum ErrorCode {
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
}

#[derive(Accounts)]
pub struct ProcessInstruction<'info> {
    pub authority: Signer<'info>,
    pub token_account: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

    pub fn entrypoint(ctx: Context<ProcessInstruction>, amount: u64) -> Result<()> {
        let account = &ctx.accounts.authority;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        Ok(())
    }

    pub fn custom_panic(ctx: Context<ProcessInstruction>, amount: u64) -> Result<()> {
        let account = &ctx.accounts.authority;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        // VULNERABLE: Unchecked arithmetic
        let new_balance = old_balance + amount;
        // Should use: old_balance.checked_add(amount).ok_or(ErrorCode::ArithmeticOverflow)?;
        Ok(())
    }