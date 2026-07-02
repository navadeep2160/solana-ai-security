#!/usr/bin/env python3
import subprocess, os, sys, re

def run(cmd, shell=False, capture=True):
    if isinstance(cmd, str): cmd = cmd.split()
    return subprocess.run(cmd, capture_output=capture, text=True, shell=shell)

# Add Solana to PATH
os.environ["PATH"] = os.path.expanduser("~/.local/share/solana/install/active_release/bin") + ":" + os.environ.get("PATH", "")

print("=" * 60)
print("FIXED PIPELINE (Bypasses Bridge Bug)")
print("=" * 60)

# 1. Run scanner
print("\n[1/5] Running scanner...")
result = run("python3 -m analysis.bytecode_analyzer.test_batch --test download", shell=True, capture=False)

# 2. Setup build
print("\n[2/5] Setting up build environment...")
os.makedirs("/tmp/solana_validator/programs/vulnerable_bank/src", exist_ok=True)

# Create Cargo.toml
with open("/tmp/solana_validator/programs/vulnerable_bank/Cargo.toml", "w") as f:
    f.write("""[package]
name = "vulnerable_bank"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "lib"]
name = "vulnerable_bank"

[dependencies]
anchor-lang = "0.30.1"
""")

# Create secure lib.rs
with open("/tmp/solana_validator/programs/vulnerable_bank/src/lib.rs", "w") as f:
    f.write("""use anchor_lang::prelude::*;
declare_id!("11111111111111111111111111111111");

#[program]
pub mod secure_bank {
    use super::*;
    
    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.bump = bump;
        bank.authority = ctx.accounts.authority.key();
        bank.balance = 0;
        Ok(())
    }
    
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        bank.balance = bank.balance.checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;
        Ok(())
    }
    
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let bank = &mut ctx.accounts.bank;
        require!(bank.authority == ctx.accounts.authority.key(), ErrorCode::Unauthorized);
        require!(bank.balance >= amount, ErrorCode::InsufficientBalance);
        bank.balance = bank.balance.checked_sub(amount)
            .ok_or(ErrorCode::Overflow)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + std::mem::size_of::<Bank>(),
              seeds = [b"bank", authority.key().as_ref()], bump)]
    pub bank: Account<'info, Bank>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, seeds = [b"bank", authority.key().as_ref()], bump = bank.bump)]
    pub bank: Account<'info, Bank>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"bank", authority.key().as_ref()], bump = bank.bump)]
    pub bank: Account<'info, Bank>,
    #[account(mut)]
    pub authority: Signer<'info>,
}

#[account]
pub struct Bank {
    pub bump: u8,
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Overflow")]
    Overflow,
    #[msg("Insufficient balance")]
    InsufficientBalance,
}
""")
print("  ✅ Secure code generated")

# 3. Build
print("\n[3/5] Building with cargo build-sbf...")
os.chdir("/tmp/solana_validator/programs/vulnerable_bank")
result = run("cargo build-sbf", shell=True, capture=False)
if result.returncode != 0:
    print("  ❌ Build failed")
    sys.exit(1)
print("  ✅ Build successful")

# 4. Find .so
so_file = None
for path in ["target/deploy/vulnerable_bank.so", "target/sbf-solana-solana/release/vulnerable_bank.so"]:
    if os.path.exists(path):
        so_file = path
        break
if not so_file:
    print("  ❌ .so not found")
    sys.exit(1)
print(f"  ✅ .so: {so_file} ({os.path.getsize(so_file):,} bytes)")

# 5. Deploy
print("\n[4/5] Deploying...")
run("solana config set --url http://127.0.0.1:8899")
run("solana-keygen new -o /tmp/program-keypair.json --no-passphrase --force")
result = run("solana-keygen pubkey /tmp/program-keypair.json")
program_id = result.stdout.strip()
print(f"  Program ID: {program_id}")

# Update declare_id
with open("src/lib.rs", "r") as f:
    content = f.read()
content = content.replace('declare_id!("11111111111111111111111111111111");', 
                          f'declare_id!("{program_id}");')
with open("src/lib.rs", "w") as f:
    f.write(content)

# Rebuild
run("cargo build-sbf", shell=True, capture=False)

# Find .so again
for path in ["target/deploy/vulnerable_bank.so", "target/sbf-solana-solana/release/vulnerable_bank.so"]:
    if os.path.exists(path):
        so_file = path
        break

# Deploy
result = run(["solana", "program", "deploy", "--program-id", "/tmp/program-keypair.json", so_file], capture=False)
if result.returncode != 0:
    print("  ❌ Deploy failed")
    sys.exit(1)
print("  ✅ Deployed")

# 6. Verify
print("\n[5/5] Verifying...")
result = run(["solana", "program", "show", program_id])
print(result.stdout)

print("\n" + "=" * 60)
print("PIPELINE COMPLETE")
print("=" * 60)
print(f"Program ID: {program_id}")
print("=" * 60)
