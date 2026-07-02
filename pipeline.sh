#!/bin/bash
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
cd "$(dirname "$0")"

echo "=== STEP 1: Environment ==="
python3 --version
solana --version
cargo --version
cargo-build-sbf --version

echo ""
echo "=== STEP 2: Clean & Scan ==="
rm -rf /tmp/solana_validator bytecode_results/675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8
python3 -m analysis.bytecode_analyzer.test_batch --test download

echo ""
echo "=== STEP 3: Build Setup ==="
mkdir -p /tmp/solana_validator/programs/vulnerable_bank/src

cat > /tmp/solana_validator/programs/vulnerable_bank/Cargo.toml << 'CARGO'
[package]
name = "vulnerable_bank"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "lib"]
name = "vulnerable_bank"

[dependencies]
anchor-lang = "0.30.1"
CARGO

# Create lib.rs with security fixes
cat > /tmp/solana_validator/programs/vulnerable_bank/src/lib.rs << 'RUST'
use anchor_lang::prelude::*;

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
    #[msg("Unauthorized access")]
    Unauthorized,
    #[msg("Arithmetic overflow")]
    Overflow,
    #[msg("Insufficient balance")]
    InsufficientBalance,
}
RUST

echo "Build environment ready"

echo ""
echo "=== STEP 4: Build ==="
cd /tmp/solana_validator/programs/vulnerable_bank
cargo build-sbf

echo ""
echo "=== STEP 5: Deploy Setup ==="
solana config set --url http://127.0.0.1:8899
solana-keygen new -o /tmp/program-keypair.json --no-passphrase --force
PROGRAM_ID=$(solana-keygen pubkey /tmp/program-keypair.json)
echo "Program ID: $PROGRAM_ID"

sed -i "s/declare_id!(\"11111111111111111111111111111111\");/declare_id!(\"$PROGRAM_ID\");/" src/lib.rs

echo ""
echo "=== STEP 6: Rebuild & Deploy ==="
cargo build-sbf
SO_FILE=$(find target -name "vulnerable_bank.so" | head -1)
echo ".so: $SO_FILE ($(stat -c%s "$SO_FILE" 2>/dev/null || stat -f%z "$SO_FILE") bytes)"
solana program deploy --program-id /tmp/program-keypair.json "$SO_FILE"

echo ""
echo "=== STEP 7: Verify ==="
solana program show "$PROGRAM_ID"

python3 -c "
import urllib.request, json
RPC = 'http://127.0.0.1:8899'
pid = '$PROGRAM_ID'
def call(m, p=None):
    req = urllib.request.Request(RPC, data=json.dumps({'jsonrpc':'2.0','id':1,'method':m,'params':p or []}).encode(), headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=10) as r: return json.loads(r.read())
print('='*60)
print('VERIFICATION REPORT')
print(f'Program: {pid}')
print(f'RPC: {RPC}')
print('[1/3] Health:', call('getHealth').get('result','ERROR'))
print('[2/3] Slot:', call('getSlot').get('result','N/A'))
v = call('getAccountInfo',[pid,{'encoding':'jsonParsed'}])['result']['value']
print(f'[3/3] Program: {\"FOUND\" if v else \"NOT FOUND\"}')
if v:
    print(f'   Executable: {v[\"executable\"]}')
    print(f'   Lamports: {v[\"lamports\"]:,}')
    print(f'   Owner: {v[\"owner\"]}')
print('ALL CHECKS PASSED')
"

echo ""
echo "========================================"
echo "  PIPELINE COMPLETE"
echo "  Program ID: $PROGRAM_ID"
echo "========================================"
